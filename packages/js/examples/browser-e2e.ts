/**
 * Real-browser test: headless Chrome with a CDP virtual WebAuthn authenticator.
 *   1. `kith passkey enroll` → enrollment page → create + confirm a real passkey
 *   2. Relying party (openid-client) → hub login page → passkey → back, signed in
 *   3. SSO (no login page), prompt=login, acr_values step-up, logout
 * Env: KITH_HOME, KITH_BIN, KITH_ISSUER, RP (default http://localhost:3000), SHOTS (dir)
 */
import { spawn } from "node:child_process";
import { chromium, type Page } from "playwright-core";
import assert from "node:assert/strict";

const RP = process.env.RP ?? "http://localhost:3000";
const ISSUER = process.env.KITH_ISSUER!;
const SHOTS = process.env.SHOTS;
const step = (s: string) => console.log(`  • ${s}`);
const shot = async (page: Page, name: string) => SHOTS && (await page.screenshot({ path: `${SHOTS}/${name}.png` }));

const browser = await chromium.launch({ channel: "chrome", headless: true });
try {
  const context = await browser.newContext({ colorScheme: "light", viewport: { width: 520, height: 640 } });
  const page = await context.newPage();
  const cdp = await context.newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  await cdp.send("WebAuthn.addVirtualAuthenticator", {
    options: { protocol: "ctap2", transport: "internal", hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true },
  });

  // 1. Enroll a passkey through the browser, approved by the CLI's manage key.
  const cli = spawn(process.env.KITH_BIN!, ["passkey", "enroll", "--no-open", "--name", "Chrome passkey"], { env: process.env });
  let cliErr = "";
  cli.stderr.on("data", (d) => (cliErr += d));
  const url: string = await new Promise((resolve, reject) => {
    cli.stdout.once("data", (d) => resolve(String(d).trim()));
    cli.once("exit", (c) => reject(new Error(`enroll exited ${c}: ${cliErr}`)));
  });
  const cliDone = new Promise<number>((r) => cli.once("exit", (c) => r(c ?? 1)));
  await page.goto(url);
  await shot(page, "1-enroll");
  await page.click("#create");
  await page.waitForSelector("#confirm:not(.hidden)", { timeout: 15000 });
  await page.click("#confirm");
  await page.waitForFunction(() => document.getElementById("status")!.textContent!.startsWith("Done"));
  assert.equal(await cliDone, 0, cliErr);
  step("passkey created in Chrome, approved by the CLI, proof of possession verified, KEL published");

  // 2. Sign in to the relying party.
  await page.goto(`${RP}/login`);
  await page.waitForSelector("#passkey");
  assert.ok(page.url().startsWith(`${ISSUER}/oauth/authorize`));
  await shot(page, "2-login");
  await page.click("#passkey");
  await page.waitForURL(`${RP}/`);
  const me = await (await page.request.get(`${RP}/me.json`)).json();
  assert.match(me.claims.sub, /^did:kith:/);
  assert.equal(me.claims.acr, "urn:kith:acr:aal2");
  assert.equal(me.claims.email, "ada@acme.test");
  assert.ok(me.claims.roles.includes("billing-admin"), JSON.stringify(me.claims));
  assert.equal(me.userinfo.sub, me.claims.sub);
  assert.equal(me.refreshed, true);
  await shot(page, "3-signed-in");
  step(`signed in: sub ${me.claims.sub.slice(0, 24)}…, acr ${me.claims.acr}, roles ${me.claims.roles.join(", ")}; userinfo + refresh OK`);

  // 3a. SSO: a second sign-in never shows the login page.
  const seen: string[] = [];
  page.on("framenavigated", (f) => f === page.mainFrame() && seen.push(f.url()));
  await page.goto(`${RP}/login`);
  await page.waitForURL(`${RP}/`);
  assert.ok(!(await page.$("#passkey")), "no login page on SSO");
  assert.ok(seen.every((u) => !u.startsWith(ISSUER) || !u.includes("/oauth/login")));
  step("SSO: second sign-in went straight through the hub");

  // 3b. prompt=login forces a fresh passkey assertion.
  await page.goto(`${RP}/login?prompt=login`);
  await page.waitForSelector("#passkey");
  await page.click("#passkey");
  await page.waitForURL(`${RP}/`);
  step("prompt=login: re-authenticated with the passkey");

  // 3c. acr_values=aal3 cannot be met by an AAL2 passkey: the page asks for more.
  await page.goto(`${RP}/login?acr=aal3`);
  await page.waitForSelector("#passkey");
  await page.click("#passkey");
  await page.waitForFunction(() => document.getElementById("status")!.textContent!.includes("hardware security key (assurance level 3)"));
  await shot(page, "4-step-up");
  step("acr_values=aal3: the AAL2 passkey was refused and the page asked for a hardware security key");

  // 3d. Logout ends the hub session.
  await page.goto(`${RP}/logout`);
  await page.waitForURL(`${RP}/`);
  await page.goto(`${RP}/login`);
  await page.waitForSelector("#passkey");
  step("logout: hub session cleared, next sign-in shows the login page");
} finally {
  await browser.close();
}
