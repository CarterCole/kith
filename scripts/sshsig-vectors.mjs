#!/usr/bin/env node
// Regenerates spec/test-vectors/sshsig.json (spec §1.3.1) with the system's ssh-keygen.
//
// Every signature comes from `ssh-keygen -Y sign` with fresh throwaway keys. Negative
// cases are real signatures with one thing changed. `ssh_keygen` records what
// `ssh-keygen -Y check-novalidate -n kith` says about each case, so any difference
// from Kith's verdict is explicit.
//
//   node scripts/sshsig-vectors.mjs
import { execFileSync, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const OUT = join(dirname(fileURLToPath(import.meta.url)), "../spec/test-vectors/sshsig.json");
const dir = mkdtempSync(join(tmpdir(), "kith-sshsig-"));

function keygen(name, type, bits) {
  const file = join(dir, name);
  execFileSync("ssh-keygen", ["-q", "-t", type, ...(bits ? ["-b", String(bits)] : []), "-N", "", "-C", `kith-vector-${name}`, "-f", file]);
  return { file, pub: readFileSync(`${file}.pub`, "utf8").trim() };
}

function sign(key, message, { namespace = "kith", hash } = {}) {
  const args = ["-Y", "sign", "-f", key.file, "-n", namespace, ...(hash ? ["-O", `hashalg=${hash}`] : [])];
  return dearmor(execFileSync("ssh-keygen", args, { input: message, stdio: ["pipe", "pipe", "ignore"] }).toString());
}

function sshKeygenAccepts(blob, message) {
  const file = join(dir, "check.sig");
  writeFileSync(file, armor(blob));
  const r = spawnSync("ssh-keygen", ["-Y", "check-novalidate", "-n", "kith", "-s", file], { input: message });
  return r.status === 0;
}

function dearmor(text) {
  const body = text.replace("-----BEGIN SSH SIGNATURE-----", "").replace("-----END SSH SIGNATURE-----", "");
  return Buffer.from(body.replace(/\s+/g, ""), "base64");
}

function armor(blob) {
  const lines = blob.toString("base64").match(/.{1,70}/g);
  return ["-----BEGIN SSH SIGNATURE-----", ...lines, "-----END SSH SIGNATURE-----", ""].join("\n");
}

// SSH wire-format strings, back to back.
function strings(buf) {
  const out = [];
  for (let i = 0; i < buf.length; ) {
    const n = buf.readUInt32BE(i);
    out.push(buf.subarray(i + 4, i + 4 + n));
    i += 4 + n;
  }
  return out;
}

const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
function base58(bytes) {
  let n = 0n;
  for (const b of bytes) n = n * 256n + BigInt(b);
  let s = "";
  while (n > 0n) {
    s = B58[Number(n % 58n)] + s;
    n /= 58n;
  }
  for (const b of bytes) {
    if (b !== 0) break;
    s = "1" + s;
  }
  return s;
}

// did:key of an OpenSSH public key line. EC points are compressed, as did:key wants.
function didKey(pubLine) {
  const [type, a, b] = strings(Buffer.from(pubLine.split(" ")[1], "base64"));
  if (type.toString() === "ssh-ed25519") return "did:key:z" + base58(Buffer.concat([Buffer.from([0xed, 0x01]), a]));
  const codec = { nistp256: [0x80, 0x24], nistp384: [0x81, 0x24] }[a.toString()];
  const len = (b.length - 1) / 2;
  const x = b.subarray(1, 1 + len);
  const yOdd = b[b.length - 1] & 1;
  return "did:key:z" + base58(Buffer.concat([Buffer.from(codec), Buffer.from([yOdd ? 3 : 2]), x]));
}

const digest = (s) => createHash("sha256").update(s).digest("base64url");
const event = `kith identity event v1\ndid: new\nseq: 0\nkind: inception\ndigest: ${digest("sshsig vector inception")}`;
const revocation = `kith revocation v1\norg: did:kith:example-org\nseq: 9\ndigest: ${digest("sshsig vector revocation")}`;

const ed = keygen("ed25519", "ed25519");
const edOther = keygen("ed25519-other", "ed25519");
const p256 = keygen("p256", "ecdsa", 256);
const p384 = keygen("p384", "ecdsa", 384);

const edEvent = sign(ed, event);
const flipped = Buffer.from(edEvent);
flipped[flipped.length - 10] ^= 0x01;

const cases = [
  { name: "ed25519-sha512", why: "ssh-keygen's default hash", key: ed, message: event, blob: edEvent, valid: true },
  { name: "ed25519-sha256", key: ed, message: event, blob: sign(ed, event, { hash: "sha256" }), valid: true },
  { name: "ed25519-revocation", why: "any Kith message, not just key events", key: ed, message: revocation, blob: sign(ed, revocation), valid: true },
  { name: "p256-sha512", key: p256, message: event, blob: sign(p256, event), valid: true },
  { name: "p256-sha256", key: p256, message: revocation, blob: sign(p256, revocation, { hash: "sha256" }), valid: true },
  { name: "wrong-namespace", why: "signed with -n git; the namespace must be kith", key: ed, message: event, blob: sign(ed, event, { namespace: "git" }), valid: false },
  { name: "wrong-message", why: "a valid signature over a different message", key: ed, message: revocation, blob: edEvent, valid: false },
  { name: "wrong-signer", why: "valid signature, but the signer id names another key", key: ed, signer: didKey(edOther.pub), message: event, blob: edEvent, valid: false },
  { name: "tampered-signature", why: "one bit of the Ed25519 signature flipped", key: ed, message: event, blob: flipped, valid: false },
  { name: "trailing-data", why: "a zero byte after the blob", key: ed, message: event, blob: Buffer.concat([edEvent, Buffer.from([0])]), valid: false },
  { name: "p384-unsupported", why: "ecdsa-sha2-nistp384 is not a Kith SSHSIG key type", key: p384, message: event, blob: sign(p384, event), valid: false },
];

const version = spawnSync("ssh", ["-V"], { encoding: "utf8" }).stderr.trim();
const out = {
  description:
    "SSHSIG vectors (spec §1.3.1), signed by ssh-keygen -Y sign with throwaway keys. For each case, verify " +
    "{signer, alg: \"SSHSIG\", sig} over the UTF-8 bytes of message; the result must equal valid. sig is " +
    "base64url of the blob inside armored, which is what ssh-keygen wrote. public_key is the OpenSSH public " +
    "key that signed. ssh_keygen is what `ssh-keygen -Y check-novalidate -n kith` said; it checks structure " +
    "and the signature, not who the signer is. Regenerate with scripts/sshsig-vectors.mjs.",
  generated_with: version,
  cases: cases.map((c) => ({
    name: c.name,
    ...(c.why ? { why: c.why } : {}),
    signer: c.signer ?? didKey(c.key.pub),
    message: c.message,
    sig: c.blob.toString("base64url"),
    armored: armor(c.blob),
    public_key: c.key.pub,
    valid: c.valid,
    ssh_keygen: sshKeygenAccepts(c.blob, c.message),
  })),
};

writeFileSync(OUT, JSON.stringify(out, null, 2) + "\n");
rmSync(dir, { recursive: true, force: true });
console.log(`wrote ${out.cases.length} cases to ${OUT}`);
