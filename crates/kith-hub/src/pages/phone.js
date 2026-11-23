// Sign in with a phone (spec §7.14). This page shows a QR code of a handoff, the phone
// that scans it signs in with its passkey, and this page finishes the sign-in with the
// secret only it holds. Needs #phone-box, #phone-qr, #phone-note and #phone-again.
let phoneX = null;
let phoneTimer = null;

function phoneNote(text, error = false) {
  $("phone-note").textContent = text;
  $("phone-note").classList.toggle("error", error);
}

function phoneStop(text, error = false) {
  clearTimeout(phoneTimer);
  phoneX = null;
  $("phone-qr").classList.add("faded");
  $("phone-again").classList.remove("hidden");
  phoneNote(text, error);
}

// `requestId` is the app's sign-in request, or null on the account page. `onDone`
// gets where to go once this browser is signed in.
async function phoneStart(requestId, onDone) {
  clearTimeout(phoneTimer);
  phoneX = null;
  $("phone-box").classList.remove("hidden");
  $("phone-again").classList.add("hidden");
  $("phone-again").onclick = () => phoneStart(requestId, onDone);
  phoneNote("Making a code…");
  const r = await postJSON("/v1/handoff", requestId ? { request_id: requestId } : {});
  if (!r.ok) return phoneStop(r.body.error_description || "Couldn't make a code.", true);
  const x = { ...r.body, until: Date.now() + r.body.expires_in * 1000 };
  phoneX = x;
  $("phone-qr").src = `/handoff/${x.id}/qr.svg`;
  $("phone-qr").classList.remove("hidden", "faded");
  phoneNote("Scan with your phone's camera, then sign in there with its passkey.");

  const poll = async () => {
    if (phoneX !== x) return;
    if (Date.now() > x.until) return phoneStop("The code expired.");
    let s = null;
    try {
      const res = await fetch(`/v1/handoff/${x.id}`, { cache: "no-store" });
      if (res.status === 404) return phoneX === x && phoneStop("The code expired.");
      if (res.ok) s = (await res.json()).state;
    } catch {}
    if (phoneX !== x) return;
    if (s === "scanned") {
      $("phone-qr").classList.add("faded");
      phoneNote("Scanned. Approve on your phone.");
    } else if (s === "denied") {
      return phoneStop("Declined on the phone.");
    } else if (s === "approved") {
      phoneNote("Approved on your phone. Signing in…");
      const f = await postJSON(`/v1/handoff/${x.id}/finish`, { secret: x.secret });
      if (f.ok) return onDone(f.body.redirect);
      return phoneStop(f.body.error_description || "Couldn't finish signing in.", true);
    }
    phoneTimer = setTimeout(poll, 1500);
  };
  phoneTimer = setTimeout(poll, 1500);
}

// A screen you'd scan from: a mouse or trackpad, not a phone's touchscreen.
const phoneByDefault = window.matchMedia("(pointer: fine)").matches;
