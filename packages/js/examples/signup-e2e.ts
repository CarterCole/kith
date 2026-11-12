/**
 * Real-browser test of browser sign-up: headless Chrome with a CDP virtual
 * WebAuthn authenticator, against a hub started with `--signup`.
 *   1. Relying party → hub login page → "Create one" → sign-up page
 *   2. Recovery key made in the browser and downloaded; passkey created and confirmed
 *   3. Back to the sign-in, passkey → consent → relying party, as the new identity
 *   4. A fresh sign-in (no SSO cookie) finds the account again from the passkey alone
 *   5. The page mines proof of work for the new account; the hub's record checks out here
 *   6. "Continue with" a provider that has no identity yet: a passkey is made, the provider
 *      account is linked, and the app's sign-in finishes; next time the provider alone works
 *   7. Recovery key from secret words (checked against an independent derivation here),
 *      and from a public key brought from outside (Ed25519)
 * Env: KITH_ISSUER, RP (default http://localhost:3000), SHOTS (dir)
 */
import { readFile } from "node:fs/promises";
import { createECDH, createHash, generateKeyPairSync, pbkdf2Sync } from "node:crypto";
import { chromium, type Page } from "playwright-core";
import assert from "node:assert/strict";

const RP = process.env.RP ?? "http://localhost:3000";
const ISSUER = process.env.KITH_ISSUER!;
const SHOTS = process.env.SHOTS;
const step = (s: string) => console.log(`  • ${s}`);
const shot = async (page: Page, name: string) => SHOTS && (await page.screenshot({ path: `${SHOTS}/${name}.png` }));


const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
function base58(bytes: Uint8Array) {
  let n = BigInt("0x" + Buffer.from(bytes).toString("hex"));
  let out = "";
  for (; n > 0n; n /= 58n) out = B58[Number(n % 58n)] + out;
  for (const b of bytes) { if (b) break; out = "1" + out; }
  return out;
}
/** Leading zero bits of SHA-256("kith/work/v1\0" ‖ did ‖ "\0" ‖ nonce), spec §7.12. */
function workBits(did: string, nonce: number) {
  const n = Buffer.alloc(8);
  n.writeBigUInt64BE(BigInt(nonce));
  const h = createHash("sha256").update("kith/work/v1\0" + did + "\0").update(n).digest();
  let bits = 0;
  for (const b of h) { if (b) return bits + Math.clz32(b) - 24; bits += 8; }
  return bits;
}
/** The derivation in spec §7.11, written separately from the page's. */
function deriveRecovery(phrase: string) {
  const normal = phrase.normalize("NFKD").toLowerCase().split(/\s+/).filter(Boolean).join(" ");
  const seed = pbkdf2Sync(normal, "kith/recovery/p256/v1", 600000, 64, "sha256");
  const n = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
  const d = (BigInt("0x" + seed.toString("hex")) % (n - 1n)) + 1n;
  const ecdh = createECDH("prime256v1");
  ecdh.setPrivateKey(Buffer.from(d.toString(16).padStart(64, "0"), "hex"));
  return "did:key:z" + base58(new Uint8Array([0x80, 0x24, ...ecdh.getPublicKey(null, "compressed")]));
}

const browser = await chromium.launch({ channel: "chrome", headless: true });
try {
  const context = await browser.newContext({ colorScheme: "light", viewport: { width: 520, height: 720 }, acceptDownloads: true });
  const page = await context.newPage();
  const cdp = await context.newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  const { authenticatorId } = await cdp.send("WebAuthn.addVirtualAuthenticator", {
    options: { protocol: "ctap2", transport: "internal", hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true },
  });
  const errors: string[] = [];
  page.on("pageerror", (e) => errors.push(e.message));

  // 1. From an app's sign-in to the sign-up page.
  await page.goto(`${RP}/login`);
  await page.waitForSelector("#passkey");
  assert.ok(page.url().startsWith(`${ISSUER}/oauth/authorize`));
  assert.ok(await page.isVisible("#signup"), "the login page offers to create an account");
  await shot(page, "s1-login");
  await page.click("#signup-link");
  await page.waitForURL(`${ISSUER}/signup?return=*`);
  await shot(page, "s2-signup");
  step("login page links to sign-up and remembers where to come back to");

  // 2. A recovery key, saved before the passkey exists.
  await page.click("#start");
  await page.waitForSelector("#step-recovery:not(.hidden)");
  assert.ok(await page.isDisabled("#create"), "the passkey can't be made before the recovery key is acknowledged");
  const [download] = await Promise.all([page.waitForEvent("download"), page.click("#download")]);
  assert.equal(download.suggestedFilename(), "kith-recovery-key.json");
  const file = JSON.parse(await readFile((await download.path())!, "utf8"));
  assert.equal(file.kith, "recovery-key");
  assert.match(file.signer, /^did:key:zDn/, "a P-256 did:key");
  assert.equal(file.private_key_jwk.kty, "EC");
  assert.equal(file.private_key_jwk.crv, "P-256");
  assert.ok(file.private_key_jwk.d, "the file holds the private half");
  await shot(page, "s3-recovery");
  await page.check("#saved");
  assert.ok(await page.isEnabled("#create"));
  step(`recovery key downloaded (${file.signer.slice(0, 20)}…)`);

  await page.click("#create");
  await page.waitForSelector("#step-done:not(.hidden)", { timeout: 20000 });
  const did = (await page.textContent("#did"))!.trim();
  assert.match(did, /^did:kith:[a-z2-7]+$/);
  await shot(page, "s4-done");
  step(`account created: ${did.slice(0, 24)}…`);

  // The hub holds a log it can verify, and none of the private material.
  const kel = await (await page.request.get(`${ISSUER}/v1/kel/${did}`)).json();
  assert.equal(kel.length ?? kel.events?.length ?? 1, 1);
  const body = JSON.stringify(kel);
  assert.ok(!body.includes(file.private_key_jwk.d), "the recovery key's private half never reached the hub");
  assert.ok(body.includes(file.signer) === false, "only a digest of the recovery key is committed");


  // 5. Proof of work: the page spends compute, the hub keeps the best proof, and the
  //    record is checkable with one hash done here.
  assert.equal((await (await page.request.get(`${ISSUER}/v1/work/${did}`)).json()).work, 0);
  await page.click("#work-toggle");
  await page.waitForFunction(() => Number(document.getElementById("work-bits")!.textContent) >= 16, null, { timeout: 60000 });
  await shot(page, "s4b-work");
  await page.click("#work-toggle");
  await page.waitForFunction(() => document.getElementById("work-toggle")!.textContent === "Resume");
  const rec = await (await page.request.get(`${ISSUER}/v1/work/${did}`)).json();
  assert.ok(rec.work >= 16, `the hub recorded ${rec.work} bits`);
  assert.equal(workBits(did, rec.nonce), rec.work, "the recorded nonce really has that much work for this did");
  assert.equal(Number(await page.textContent("#work-bits")), rec.work, "the page and the hub agree");
  step(`proof of work: ${rec.work} bits, verified independently`);

  // 3. Back to the app's sign-in, as the new identity.
  await page.click("#continue");
  await page.waitForSelector("#passkey");
  await page.click("#passkey");
  await page.waitForSelector("#allow");
  await page.click("#allow");
  await page.waitForURL(`${RP}/`);
  let me = await (await page.request.get(`${RP}/me.json`)).json();
  assert.equal(me.claims.sub, did);
  assert.equal(me.claims.acr, "urn:kith:acr:aal2");
  await shot(page, "s5-signed-in");
  step("signed in to the app as the new identity (AAL2)");

  // 4. No SSO cookie: the passkey alone leads back to the account.
  await context.clearCookies();
  await page.goto(`${RP}/login`);
  await page.waitForSelector("#passkey");
  await page.click("#passkey");
  await page.waitForURL(`${RP}/`);
  me = await (await page.request.get(`${RP}/me.json`)).json();
  assert.equal(me.claims.sub, did);
  step("fresh sign-in: the passkey found the account again");

  // 7. Secret words, and a key brought from outside. Each makes a working account.
  async function signUpWith(pick: (p: Page) => Promise<string>) {
    const p = page; // the virtual authenticator is attached to this page only
    const errs: string[] = [];
    const onError = (e: Error) => errs.push(e.message);
    p.on("pageerror", onError);
    await p.goto(`${ISSUER}/signup`);
    await p.click("#start");
    await p.waitForSelector("#step-recovery:not(.hidden)");
    const key = await pick(p);
    assert.equal((await p.textContent("#chosen-key"))!.trim(), key);
    await p.check("#saved");
    await p.click("#create");
    await p.waitForSelector("#step-done:not(.hidden)", { timeout: 20000 }).catch(async (e) => {
      throw new Error(`${e.message}\nstatus: ${await p.textContent("#status")}\npage errors: ${errs.join("; ")}`);
    });
    const id = (await p.textContent("#did"))!.trim();
    const log = JSON.stringify(await (await p.request.get(`${ISSUER}/v1/kel/${id}`)).json());
    assert.ok(!log.includes(key), "only a digest of the recovery key is committed");
    p.off("pageerror", onError);
    assert.deepEqual(errs, []);
    return id;
  }

  const phrase = "Correct  horse battery STAPLE velvet orbit";
  const expected = deriveRecovery(phrase);
  await signUpWith(async (p) => {
    await p.check('input[value="words"]');
    await p.fill("#words", "only four words here");
    await p.fill("#words2", "only four words here");
    await p.click("#derive");
    assert.match((await p.textContent("#status"))!, /at least 5/);
    await p.fill("#words", phrase);
    await p.fill("#words2", "something else entirely different words");
    await p.click("#derive");
    assert.match((await p.textContent("#status"))!, /don't match/);
    assert.ok(await p.isDisabled("#saved"), "no key yet, nothing to acknowledge");
    await p.fill("#words2", "correct horse battery staple velvet orbit");
    await p.click("#derive");
    await p.waitForSelector("#chosen:not(.hidden)", { timeout: 30000 });
    return expected;
  });
  step("secret words: the page derived exactly the key the written-out recipe gives");

  const pub = generateKeyPairSync("ed25519").publicKey.export({ format: "jwk" }).x!;
  const ed = "did:key:z" + base58(new Uint8Array([0xed, 0x01, ...Buffer.from(pub, "base64url")]));
  await signUpWith(async (p) => {
    await p.check('input[value="own"]');
    await p.fill("#own", "did:key:zNotAKey0OIl");
    await p.click("#check-own");
    assert.match((await p.textContent("#status"))!, /isn't a did:key|isn't usable/);
    await p.fill("#own", ed);
    await p.click("#check-own");
    await p.waitForSelector("#chosen:not(.hidden)");
    return ed;
  });
  step("own key: an Ed25519 public key made elsewhere is accepted and committed");

  // Chrome's virtual authenticator refuses a fourth new passkey ("NotAllowedError" from
  // create()) while holding three; the earlier accounts are not needed from here on.
  await cdp.send("WebAuthn.clearCredentials", { authenticatorId });
  // 6. Sign up through a provider. The mock signs in the same account every time.
  await context.clearCookies();
  await page.goto(`${RP}/login`);
  await page.waitForSelector("#upstreams button");
  assert.match((await page.textContent("#upstreams button"))!, /Mock ID/);
  await page.click("#upstreams button");
  await page.waitForURL(`${ISSUER}/signup?ticket=*`);
  assert.ok(await page.isVisible("#provider-note"), "the page says a provider account is being set up");
  assert.match((await page.textContent("#provider-note"))!, /Mock ID/);
  await shot(page, "s6-provider-signup");
  await page.click("#start");
  await page.waitForSelector("#step-recovery:not(.hidden)");
  await page.check("#saved");
  await page.click("#create");
  // The hub finishes the app's sign-in; a new identity has not granted consent yet.
  await page.waitForSelector("#allow", { timeout: 30000 }).catch(async (e) => {
    throw new Error(`${e.message}\nat ${page.url()}\nstatus: ${await page.textContent("#status")}`);
  });
  await page.click("#allow");
  await page.waitForURL(`${RP}/`, { timeout: 30000 }).catch(async (e) => {
    throw new Error(`${e.message}\nat ${page.url()}\n${(await page.textContent("body"))?.slice(0, 400)}`);
  });
  me = await (await page.request.get(`${RP}/me.json`)).json();
  assert.match(me.claims.sub, /^did:kith:/);
  assert.notEqual(me.claims.sub, did, "a provider account makes its own identity");
  assert.equal(me.claims.acr, "urn:kith:acr:aal1");
  assert.deepEqual(me.claims.amr, ["fed"]);
  const viaProvider = me.claims.sub;
  step(`provider sign-up: new identity ${viaProvider.slice(0, 24)}…, signed in at AAL1`);

  await context.clearCookies();
  await page.goto(`${RP}/login`);
  await page.waitForSelector("#upstreams button");
  await page.click("#upstreams button");
  await page.waitForURL(`${RP}/`);
  me = await (await page.request.get(`${RP}/me.json`)).json();
  assert.equal(me.claims.sub, viaProvider, "the provider account now signs in to that identity");
  step("next time the provider alone signs in to the same identity");

  assert.deepEqual(errors, [], "no script errors on the pages");
} finally {
  await browser.close();
}
