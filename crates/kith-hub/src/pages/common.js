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
function webauthnSupported() {
  return !!(window.PublicKeyCredential && navigator.credentials);
}
