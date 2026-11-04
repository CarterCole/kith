const D = JSON.parse(document.getElementById("kith-data").textContent);
const $ = (id) => document.getElementById(id);
const b64u = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const b64uDecode = (s) => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4)), (c) => c.charCodeAt(0));
const sha256 = async (s) => new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s)));
function status(text, kind = "") {
  const el = $("status");
  el.textContent = text;
  el.className = "status " + kind;
}
async function postJSON(url, body) {
  const r = await fetch(url, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
  const j = await r.json().catch(() => ({}));
  return { ok: r.ok, status: r.status, body: j };
}
const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
function base58(bytes) {
  let n = 0n;
  for (const b of bytes) n = n * 256n + BigInt(b);
  let out = "";
  while (n > 0n) { out = B58[Number(n % 58n)] + out; n /= 58n; }
  for (const b of bytes) { if (b !== 0) break; out = "1" + out; }
  return out;
}
// A P-256 public key (SPKI, as WebAuthn and WebCrypto export it) as a did:key.
function p256DidKey(spki) {
  const b = new Uint8Array(spki);
  const pt = b.slice(b.length - 65);
  const compressed = [pt[64] & 1 ? 3 : 2, ...pt.slice(1, 33)];
  return "did:key:z" + base58(new Uint8Array([0x80, 0x24, ...compressed]));
}
function webauthnSupported() {
  return !!(window.PublicKeyCredential && navigator.credentials);
}
