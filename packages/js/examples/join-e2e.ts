/**
 * Real-browser test of joining devices (spec §7.13): headless Chrome with CDP virtual
 * WebAuthn authenticators, the real `kith` binary, against a hub started with `--signup`.
 *   1. An account made at /signup (passkey + downloaded recovery key)
 *   2. `kith device join` on a "Mac": the browser signs in on the join page, claims it,
 *      and approves it with the passkey; the terminal confirms and keeps the log
 *   3. A "phone" (its own browser and authenticator) joins by the account page's QR link:
 *      it makes a passkey and proves it, and the account page approves it
 *   4. `kith manage set 2 passkey mac phone --recovery-key …` on the Mac
 *   5. A third device needs two approvals: the browser's passkey, then
 *      `kith device approve` on the Mac
 * Env: KITH_ISSUER, KITH_BIN, DEMO (dir for homes and files), SHOTS (dir)
 */
import { spawn, execFileSync, type ChildProcess } from "node:child_process";
import { readFile, writeFile } from "node:fs/promises";
import { chromium, type BrowserContext, type Page } from "playwright-core";
import assert from "node:assert/strict";

const ISSUER = process.env.KITH_ISSUER!;
const K = process.env.KITH_BIN!;
const DEMO = process.env.DEMO!;
const SHOTS = process.env.SHOTS;
const step = (s: string) => console.log(`  • ${s}`);
const shot = async (page: Page, name: string) => SHOTS && (await page.screenshot({ path: `${SHOTS}/${name}.png`, fullPage: true }));
const kith = (home: string, ...args: string[]) => execFileSync(K, ["--home", `${DEMO}/${home}`, ...args], { encoding: "utf8" });

async function passkeyPage(context: BrowserContext) {
  const page = await context.newPage();
  const cdp = await context.newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  await cdp.send("WebAuthn.addVirtualAuthenticator", {
    options: { protocol: "ctap2", transport: "internal", hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true },
  });
  const errors: string[] = [];
  page.on("pageerror", (e) => errors.push(e.message));
  return { page, errors };
}

/** `kith device join` in the background; resolves the join link once it is printed. */
function startJoin(home: string, name: string) {
  const child: ChildProcess = spawn(K, ["--home", `${DEMO}/${home}`, "device", "join", "--hub", ISSUER, "--name", name, "--keystore", "file", "--no-open", "--yes"], { stdio: ["ignore", "pipe", "pipe"] });
  let out = "", err = "";
  child.stdout!.on("data", (d) => (out += d));
  child.stderr!.on("data", (d) => (err += d));
  const link = new Promise<string>((resolve, reject) => {
    child.stderr!.on("data", () => {
      // The code line comes after the link and the QR code.
      const m = err.match(new RegExp(`${ISSUER}/join/[A-Za-z0-9_-]+`));
      if (m && /code is [0-9a-f-]{14}/.test(err)) resolve(m[0]);
    });
    child.on("exit", () => reject(new Error(`kith device join exited early:\n${err}`)));
  });
  const exit = new Promise<{ code: number | null; out: string; err: string }>((resolve) => child.on("exit", (code) => resolve({ code, out, err })));
  return { link, exit, stderr: () => err };
}

async function waitFor(page: Page, selector: string, what: string) {
  await page.waitForSelector(selector, { timeout: 20000 }).catch(async (e) => {
    throw new Error(`${what}: ${e.message}\ntitle: ${await page.textContent("#title").catch(() => "")}\nstatus: ${await page.textContent("#status").catch(() => "")}`);
  });
}

const browser = await chromium.launch({ channel: "chrome", headless: true });
try {
  // 1. The account.
  const macBrowser = await browser.newContext({ colorScheme: "light", viewport: { width: 520, height: 820 }, acceptDownloads: true });
  const { page, errors } = await passkeyPage(macBrowser);
  await page.goto(`${ISSUER}/signup`);
  await page.click("#start");
  await page.waitForSelector("#step-recovery:not(.hidden)");
  const [download] = await Promise.all([page.waitForEvent("download"), page.click("#download")]);
  const recoveryFile = `${DEMO}/kith-recovery-key.json`;
  await writeFile(recoveryFile, await readFile((await download.path())!));
  await page.check("#saved");
  await page.click("#create");
  await page.waitForSelector("#step-done:not(.hidden)", { timeout: 20000 });
  const did = (await page.textContent("#did"))!.trim();
  step(`account ${did.slice(0, 24)}… with a passkey and a downloaded recovery key`);

  // 2. The Mac joins from its terminal; the browser signs in, claims and approves.
  const mac = startJoin("mac", "mac");
  const macLink = await mac.link;
  assert.match(mac.stderr(), /▀|▄|█/, "the terminal shows a QR code");
  const code = mac.stderr().match(/code is ([0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4})/)![1];
  await page.goto(macLink);
  await waitFor(page, "#signin:not(.hidden)", "a signed-out browser is asked to sign in");
  await shot(page, "j1-sign-in");
  await page.click("#signin");
  await waitFor(page, "#claim:not(.hidden)", "after signing in, the claim");
  assert.ok((await page.textContent("#items"))!.includes(code), "the page shows the terminal's code");
  await shot(page, "j2-claim");
  await page.click("#claim");
  await waitFor(page, "#approve:not(.hidden)", "after claiming, the approval");
  await shot(page, "j3-approve");
  await page.click("#approve");
  const macDone = await mac.exit;
  assert.equal(macDone.code, 0, macDone.err);
  assert.equal(macDone.out.trim(), did);
  await waitFor(page, "text=Device added", "the page reports the device");
  await shot(page, "j4-added");
  const macStatus = JSON.parse(kith("mac", "status"));
  assert.equal(macStatus.did, did);
  assert.equal(macStatus.devices.length, 2);
  step(`kith device join: the Mac joined as ${macStatus.this_device}, code ${code} shown on both sides`);

  // 3. The phone joins by the account page's QR code.
  await page.goto(`${ISSUER}/whoami`);
  await page.click("#add");
  await waitFor(page, "#qr-box:not(.hidden)", "the account page shows a QR code");
  const phoneLink = (await page.textContent("#link"))!.trim();
  assert.match(phoneLink, new RegExp(`^${ISSUER}/join/`));
  const qr = await page.request.get(`${phoneLink}/qr.svg`);
  assert.equal(qr.headers()["content-type"], "image/svg+xml");
  assert.ok(await page.evaluate(() => (document.getElementById("qr") as HTMLImageElement).naturalWidth > 0), "the QR image loads");
  await shot(page, "j5-qr");

  const phoneBrowser = await browser.newContext({ colorScheme: "light", viewport: { width: 390, height: 780 }, isMobile: true, hasTouch: true });
  const phone = await passkeyPage(phoneBrowser);
  await phone.page.goto(phoneLink); // what the camera opens
  await waitFor(phone.page, "#create:not(.hidden)", "the phone is offered a passkey");
  assert.ok((await phone.page.textContent("#items"))!.includes(did), "the phone names the identity");
  await shot(phone.page, "j6-phone");
  await phone.page.fill("#name", "phone");
  await phone.page.click("#create");
  await waitFor(phone.page, "#confirm:not(.hidden)", "the phone confirms its passkey");
  await phone.page.click("#confirm");
  await waitFor(phone.page, "text=Waiting for approval", "the phone waits");
  const phoneCode = (await phone.page.textContent("#items"))!.match(/[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}/)![0];
  await shot(phone.page, "j7-phone-waiting");
  await waitFor(page, "#approve:not(.hidden)", "the account page sees the phone");
  assert.ok((await page.textContent("#items"))!.includes(phoneCode), "both screens show the same code");
  await shot(page, "j8-approve-phone");
  await page.click("#approve");
  await waitFor(page, "text=Device added", "the account page adds the phone");
  await waitFor(phone.page, "text=Device added", "the phone hears it was added");
  await shot(phone.page, "j9-phone-added");
  step(`the phone joined by QR link with its own passkey (code ${phoneCode})`);

  // 4. 2 of [passkey, mac, phone], signed with the recovery key.
  const set = execFileSync(K, ["--home", `${DEMO}/mac`, "manage", "set", "2", "passkey", "mac", "phone", "--recovery-key", recoveryFile, "--next-out", `${DEMO}/kith-recovery-key-2.json`, "--yes"], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
  void set;
  const shown = JSON.parse(kith("mac", "manage", "show"));
  assert.equal(shown.manage, "2 of [passkey, mac, phone]");
  assert.equal(shown.signers.filter((s: { this_device: boolean }) => s.this_device).length, 1);
  const next = JSON.parse(await readFile(`${DEMO}/kith-recovery-key-2.json`, "utf8"));
  assert.equal(next.kith, "recovery-key");
  // The old recovery key is spent: it can't rotate again.
  let refused = "";
  try {
    execFileSync(K, ["--home", `${DEMO}/mac`, "manage", "set", "1", "passkey", "--recovery-key", recoveryFile, "--next-out", `${DEMO}/x.json`, "--yes"], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
  } catch (e) {
    refused = String((e as { stderr: string }).stderr);
  }
  assert.match(refused, /not the recovery key/);
  step(`kith manage set: ${shown.manage}; a new recovery key saved, the old one refused`);

  // 5. A third device needs two approvals.
  const laptop = startJoin("laptop", "laptop");
  const laptopLink = await laptop.link;
  await page.goto(laptopLink);
  await waitFor(page, "#claim:not(.hidden)", "the laptop's claim");
  await page.click("#claim");
  await waitFor(page, "#approve:not(.hidden)", "the laptop's approval");
  await page.click("#approve");
  await waitFor(page, "text=One more approval needed", "one approval is not enough");
  await shot(page, "j10-one-more");
  const id = laptopLink.split("/").pop()!;
  const approved = execFileSync(K, ["--home", `${DEMO}/mac`, "device", "approve", id, "--yes"], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
  void approved;
  const laptopDone = await laptop.exit;
  assert.equal(laptopDone.code, 0, laptopDone.err);
  await waitFor(page, "text=Device added", "the page sees the second approval");
  await shot(page, "j11-added-2of3");
  const devices = JSON.parse(kith("laptop", "status")).devices.map((d: { name: string }) => d.name).sort();
  assert.deepEqual(devices, ["laptop", "mac", "passkey", "phone"]);
  step("a third device took two approvals: the browser's passkey, then `kith device approve` on the Mac");

  // Sign-in is unchanged: the joined Mac gets a token on its own.
  const token = kith("mac", "token").trim();
  assert.ok(token.split(".").length === 3, "the Mac signs in alone");
  step("the Mac still signs in on its own (kith token)");

  assert.deepEqual([...errors, ...phone.errors], [], "no page errors");
} finally {
  await browser.close();
}
