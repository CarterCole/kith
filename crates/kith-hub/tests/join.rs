//! Joining a device (spec §7.13): a terminal's request claimed and approved in a browser,
//! a phone's passkey added by QR invite, and approvals collected until a 2-of-3 manage
//! policy is met. Real WebAuthn assertions come from the software authenticator.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;

use kith_core::kel::{next_event, verify_log, Event, EventBody, KeyState};
use kith_core::keys::{KeyType, LocalSigner, VerifyOptions};
use kith_core::policy::SignerPolicy;
use kith_core::util::{b64u, random_id, sha256};
use kith_core::webauthn;
use kith_hub::{Hub, HubConfig, RateLimit};

const ISSUER: &str = "http://localhost:7777";

struct World {
    app: Router,
    hub: Arc<Hub>,
}

fn world(configure: impl FnOnce(&mut HubConfig)) -> World {
    let dir = std::env::temp_dir().join(format!("kith-join-{}", random_id()));
    let mut cfg = HubConfig::new(ISSUER, dir);
    cfg.signup = true;
    configure(&mut cfg);
    let hub = Hub::open(cfg).unwrap();
    World {
        app: kith_hub::router(hub.clone()),
        hub,
    }
}

struct Resp {
    status: StatusCode,
    body: Vec<u8>,
    headers: axum::http::HeaderMap,
}

impl Resp {
    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or(Value::Null)
    }
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

async fn send(app: &Router, req: Request<Body>) -> Resp {
    let r = app.clone().oneshot(req).await.unwrap();
    let (parts, body) = r.into_parts();
    Resp {
        status: parts.status,
        headers: parts.headers,
        body: body.collect().await.unwrap().to_bytes().to_vec(),
    }
}

async fn get(app: &Router, uri: &str, cookie: Option<&str>) -> Resp {
    let mut r = Request::get(uri);
    if let Some(c) = cookie {
        r = r.header(header::COOKIE, c);
    }
    send(app, r.body(Body::empty()).unwrap()).await
}

async fn post(app: &Router, uri: &str, body: Value, cookie: Option<&str>) -> Resp {
    let mut r = Request::post(uri).header(header::CONTENT_TYPE, "application/json");
    if let Some(c) = cookie {
        r = r.header(header::COOKIE, c);
    }
    send(app, r.body(Body::from(body.to_string())).unwrap()).await
}

fn page_data(html: &str) -> Value {
    let start = html
        .find(r#"<script id="kith-data" type="application/json">"#)
        .unwrap()
        + 47;
    let end = start + html[start..].find("</script>").unwrap();
    serde_json::from_str(&html[start..end]).unwrap()
}

/// What a browser's passkey sends for a message: the assertion, without its key.
fn assertion(passkey: &LocalSigner, message: &str, origin: &str) -> Value {
    let (data, sig) = webauthn::soft_assert(
        &passkey.secret,
        "localhost",
        origin,
        &sha256(message.as_bytes()),
        true,
        1,
    )
    .unwrap();
    json!({"authenticator_data": data.authenticator_data, "client_data_json": data.client_data_json, "signature": b64u(sig)})
}

/// An account made at /signup, signed in on the account page.
struct Account {
    did: String,
    passkey: LocalSigner,
    recovery: LocalSigner,
    cookie: String,
}

async fn sign_up(w: &World) -> Account {
    let passkey = LocalSigner::generate(KeyType::P256);
    let recovery = LocalSigner::generate(KeyType::P256);
    let begun = post(&w.app, "/v1/signup", json!({}), None).await.json();
    let id = begun["id"].as_str().unwrap();
    let handle = begun["handle"].as_str().unwrap();
    let proposed = post(
        &w.app,
        &format!("/v1/signup/{id}/key"),
        json!({"key": passkey.id, "recovery_key": recovery.id}),
        None,
    )
    .await
    .json();
    let sig = webauthn::soft_sign_message(
        &passkey,
        "localhost",
        ISSUER,
        proposed["message"].as_str().unwrap().as_bytes(),
    )
    .unwrap();
    let done = post(
        &w.app,
        &format!("/v1/signup/{id}/sig"),
        json!({"sig": sig}),
        None,
    )
    .await;
    assert_eq!(done.status, StatusCode::OK, "{}", done.text());
    let did = done.json()["did"].as_str().unwrap().to_string();

    let page = get(&w.app, "/whoami", None).await;
    let d = page_data(&page.text());
    let mut factor = assertion(&passkey, d["message"].as_str().unwrap(), ISSUER);
    factor["type"] = json!("webauthn");
    let login = post(
        &w.app,
        "/whoami",
        json!({"challenge_id": d["challenge_id"], "did": handle, "factors": [factor]}),
        None,
    )
    .await;
    assert_eq!(login.status, StatusCode::OK, "{}", login.text());
    let cookie = login.headers[header::SET_COOKIE]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();
    Account {
        did,
        passkey,
        recovery,
        cookie,
    }
}

fn state(w: &World, did: &str) -> KeyState {
    verify_log(&w.hub.get_kel(did).unwrap(), &VerifyOptions::default()).unwrap()
}

/// A terminal opens a request for its key.
async fn terminal_request(w: &World, key: &LocalSigner, name: &str) -> String {
    let r = post(
        &w.app,
        "/v1/join",
        json!({"device": {"key": key.id, "name": name, "kind": "software", "aal": 1}}),
        None,
    )
    .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    let j = r.json();
    assert_eq!(
        j["url"],
        format!("{ISSUER}/join/{}", j["id"].as_str().unwrap())
    );
    j["id"].as_str().unwrap().to_string()
}

/// The terminal's proof of possession: its key over the event's message.
async fn terminal_pop(w: &World, id: &str, key: &LocalSigner) -> Resp {
    let s = get(&w.app, &format!("/v1/join/{id}"), None).await.json();
    let sig = key.sign(s["message"].as_str().unwrap().as_bytes()).unwrap();
    post(
        &w.app,
        &format!("/v1/join/{id}/pop"),
        json!({"sig": sig}),
        None,
    )
    .await
}

async fn approve_with_passkey(w: &World, id: &str, passkey: &LocalSigner) -> Resp {
    let s = get(&w.app, &format!("/v1/join/{id}"), None).await.json();
    let a = assertion(passkey, s["message"].as_str().unwrap(), ISSUER);
    post(
        &w.app,
        &format!("/v1/join/{id}/approve"),
        json!({"webauthn": a}),
        None,
    )
    .await
}

#[tokio::test]
async fn a_terminal_joins_once_the_browser_claims_and_the_passkey_approves() {
    let w = world(|_| {});
    let acct = sign_up(&w).await;
    let mac = LocalSigner::generate(KeyType::Ed25519);
    let id = terminal_request(&w, &mac, "mac").await;

    let s = get(&w.app, &format!("/v1/join/{id}"), None).await.json();
    assert_eq!(s["state"], "waiting_for_identity");
    assert!(s["did"].is_null() && s["event"].is_null());
    assert_eq!(
        s["device"]["fingerprint"],
        kith_core::util::key_fingerprint(&mac.id)
    );

    // Nothing to sign or approve until someone signed in claims it.
    let early = post(
        &w.app,
        &format!("/v1/join/{id}/pop"),
        json!({"sig": mac.sign(b"anything").unwrap()}),
        None,
    )
    .await;
    assert_eq!(early.status, StatusCode::BAD_REQUEST);
    let anon = post(&w.app, &format!("/v1/join/{id}/claim"), json!({}), None).await;
    assert_eq!(anon.status, StatusCode::UNAUTHORIZED);

    // The page offers a signed-out browser a sign-in, and a signed-in one the claim.
    let page = get(&w.app, &format!("/join/{id}"), None).await;
    let d = page_data(&page.text());
    assert!(d["session_did"].is_null() && d["challenge_id"].is_string());
    let page = get(&w.app, &format!("/join/{id}"), Some(&acct.cookie)).await;
    let d = page_data(&page.text());
    assert_eq!(d["session_did"], acct.did);
    assert!(d.get("challenge_id").is_none());

    let claimed = post(
        &w.app,
        &format!("/v1/join/{id}/claim"),
        json!({}),
        Some(&acct.cookie),
    )
    .await;
    assert_eq!(claimed.status, StatusCode::OK, "{}", claimed.text());
    let c = claimed.json();
    assert_eq!(c["state"], "waiting_for_approval");
    assert_eq!(c["did"], acct.did);
    let ev: Event = serde_json::from_value(c["event"].clone()).unwrap();
    assert_eq!(ev.seq, 1);
    let EventBody::AddDevice { device } = &ev.body else {
        panic!("not add_device")
    };
    assert_eq!(device.key, mac.id);
    assert_eq!(device.caps, ["session", "alias"]);
    assert_eq!(
        c["message"].as_str().unwrap().as_bytes(),
        &ev.signing_message().unwrap()[..]
    );
    let again = post(
        &w.app,
        &format!("/v1/join/{id}/claim"),
        json!({}),
        Some(&acct.cookie),
    )
    .await;
    assert_eq!(again.status, StatusCode::CONFLICT, "claimed once only");

    // Approval first, proof second: either order works, and the event lands on the second.
    let approved = approve_with_passkey(&w, &id, &acct.passkey).await;
    assert_eq!(approved.status, StatusCode::OK, "{}", approved.text());
    let a = approved.json();
    assert_eq!(a["approved"], true);
    assert_eq!(a["approvals"], json!([acct.passkey.id]));
    assert_eq!(
        a["state"], "waiting_for_approval",
        "still waiting for the proof"
    );
    assert_eq!(state(&w, &acct.did).devices.len(), 1);

    let other = LocalSigner::generate(KeyType::Ed25519);
    let s = get(&w.app, &format!("/v1/join/{id}"), None).await.json();
    let forged = other
        .sign(s["message"].as_str().unwrap().as_bytes())
        .unwrap();
    let r = post(
        &w.app,
        &format!("/v1/join/{id}/pop"),
        json!({"sig": forged}),
        None,
    )
    .await;
    assert_eq!(
        r.status,
        StatusCode::UNAUTHORIZED,
        "only the joining key proves"
    );

    let done = terminal_pop(&w, &id, &mac).await;
    assert_eq!(done.status, StatusCode::OK, "{}", done.text());
    assert_eq!(done.json()["state"], "done");
    let st = state(&w, &acct.did);
    assert_eq!(st.seq, 1);
    let dev = st.devices.values().find(|d| d.key == mac.id).unwrap();
    assert_eq!(dev.name, "mac");

    let late = approve_with_passkey(&w, &id, &acct.passkey).await;
    assert_eq!(
        late.status,
        StatusCode::CONFLICT,
        "a finished request takes nothing more"
    );
}

#[tokio::test]
async fn a_phone_joins_by_invite_with_its_own_passkey() {
    let w = world(|_| {});
    let acct = sign_up(&w).await;
    let anon = post(&w.app, "/v1/join/invite", json!({}), None).await;
    assert_eq!(
        anon.status,
        StatusCode::UNAUTHORIZED,
        "an invite needs a session"
    );
    let inv = post(&w.app, "/v1/join/invite", json!({}), Some(&acct.cookie)).await;
    assert_eq!(inv.status, StatusCode::OK, "{}", inv.text());
    let id = inv.json()["id"].as_str().unwrap().to_string();

    let s = get(&w.app, &format!("/v1/join/{id}"), None).await.json();
    assert_eq!(s["state"], "waiting_for_device");
    assert_eq!(s["did"], acct.did, "the phone's page names the identity");

    // The QR code of the link.
    let qr = get(&w.app, &format!("/join/{id}/qr.svg"), None).await;
    assert_eq!(qr.status, StatusCode::OK);
    assert_eq!(qr.headers[header::CONTENT_TYPE], "image/svg+xml");
    assert!(qr.text().contains("<svg"));
    assert_eq!(
        get(&w.app, "/join/nope/qr.svg", None).await.status,
        StatusCode::NOT_FOUND
    );

    // A terminal's claim doesn't apply to an invite, and a non-P-256 key is refused.
    let claim = post(
        &w.app,
        &format!("/v1/join/{id}/claim"),
        json!({}),
        Some(&acct.cookie),
    )
    .await;
    assert_eq!(claim.status, StatusCode::CONFLICT);
    let ed = LocalSigner::generate(KeyType::Ed25519);
    let r = post(
        &w.app,
        &format!("/v1/join/{id}/device"),
        json!({"key": ed.id}),
        None,
    )
    .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    let r = post(
        &w.app,
        &format!("/v1/join/{id}/device"),
        json!({"key": LocalSigner::generate(KeyType::P256).id, "name": "x".repeat(41)}),
        None,
    )
    .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST, "names are short");

    let phone = LocalSigner::generate(KeyType::P256);
    let r = post(
        &w.app,
        &format!("/v1/join/{id}/device"),
        json!({"key": phone.id, "name": "phone"}),
        None,
    )
    .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    let j = r.json();
    assert_eq!(j["state"], "waiting_for_approval");
    assert_eq!(j["device"]["kind"], "passkey");
    assert_eq!(j["device"]["rp_id"], "localhost");
    let message = j["message"].as_str().unwrap().to_string();

    // The phone's proof is checked as a login: this hub's origins only.
    let wrong = assertion(&phone, &message, "https://evil.example");
    let r = post(
        &w.app,
        &format!("/v1/join/{id}/pop"),
        json!({"webauthn": wrong}),
        None,
    )
    .await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    let r = post(
        &w.app,
        &format!("/v1/join/{id}/pop"),
        json!({"webauthn": assertion(&phone, &message, ISSUER)}),
        None,
    )
    .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    assert_eq!(r.json()["pop"], true);

    // The new passkey can't approve itself: it doesn't manage the identity.
    let r = approve_with_passkey(&w, &id, &phone).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    let r = approve_with_passkey(&w, &id, &acct.passkey).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    assert_eq!(r.json()["state"], "done");
    let st = state(&w, &acct.did);
    let dev = st.devices.values().find(|d| d.key == phone.id).unwrap();
    assert_eq!(
        (dev.name.as_str(), dev.aal, dev.caps.clone()),
        ("phone", 2, vec!["session".to_string()])
    );
}

#[tokio::test]
async fn with_a_2_of_3_manage_policy_one_approval_is_not_enough() {
    let w = world(|_| {});
    let acct = sign_up(&w).await;

    // Join a terminal and a phone, approved by the passkey alone.
    let mac = LocalSigner::generate(KeyType::P256);
    let id = terminal_request(&w, &mac, "mac").await;
    post(
        &w.app,
        &format!("/v1/join/{id}/claim"),
        json!({}),
        Some(&acct.cookie),
    )
    .await;
    approve_with_passkey(&w, &id, &acct.passkey).await;
    assert_eq!(terminal_pop(&w, &id, &mac).await.json()["state"], "done");

    let phone = LocalSigner::generate(KeyType::P256);
    let id = post(&w.app, "/v1/join/invite", json!({}), Some(&acct.cookie))
        .await
        .json()["id"]
        .as_str()
        .unwrap()
        .to_string();
    let j = post(
        &w.app,
        &format!("/v1/join/{id}/device"),
        json!({"key": phone.id}),
        None,
    )
    .await
    .json();
    let message = j["message"].as_str().unwrap();
    post(
        &w.app,
        &format!("/v1/join/{id}/pop"),
        json!({"webauthn": assertion(&phone, message, ISSUER)}),
        None,
    )
    .await;
    assert_eq!(
        approve_with_passkey(&w, &id, &acct.passkey).await.json()["state"],
        "done"
    );

    // The recovery key rotates the manage policy to 2 of the three, as `kith manage set` does.
    let st = state(&w, &acct.did);
    let next = LocalSigner::generate(KeyType::P256);
    let manage = SignerPolicy::threshold(
        2,
        [&acct.passkey.id, &mac.id, &phone.id]
            .into_iter()
            .map(SignerPolicy::single)
            .collect(),
    );
    let mut rot = next_event(
        &st,
        EventBody::Rotate {
            rotation: SignerPolicy::single(&acct.recovery.id),
            manage,
            next: SignerPolicy::single(&next.id).digest(),
            revoke_devices: false,
        },
    );
    rot.sign(&acct.recovery).unwrap();
    let mut kel = w.hub.get_kel(&acct.did).unwrap();
    kel.push(rot);
    w.hub.put_kel(&acct.did, kel).unwrap();

    // A third device now needs two approvals.
    let laptop = LocalSigner::generate(KeyType::Ed25519);
    let id = terminal_request(&w, &laptop, "laptop").await;
    let c = post(
        &w.app,
        &format!("/v1/join/{id}/claim"),
        json!({}),
        Some(&acct.cookie),
    )
    .await;
    assert_eq!(c.status, StatusCode::OK, "{}", c.text());
    assert_eq!(terminal_pop(&w, &id, &laptop).await.json()["pop"], true);
    let one = approve_with_passkey(&w, &id, &acct.passkey).await.json();
    assert_eq!(one["approved"], false);
    assert_eq!(one["state"], "waiting_for_approval");
    // The same signer twice still counts once.
    let twice = approve_with_passkey(&w, &id, &acct.passkey).await.json();
    assert_eq!(twice["approvals"].as_array().unwrap().len(), 1);
    // A key outside the policy can't fill the second seat.
    let message = one["message"].as_str().unwrap();
    let outsider = LocalSigner::generate(KeyType::P256);
    let r = post(
        &w.app,
        &format!("/v1/join/{id}/approve"),
        json!({"sig": outsider.sign(message.as_bytes()).unwrap()}),
        None,
    )
    .await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    // The terminal's key is a manage signer now: `kith device approve` signs plainly.
    let r = post(
        &w.app,
        &format!("/v1/join/{id}/approve"),
        json!({"sig": mac.sign(message.as_bytes()).unwrap()}),
        None,
    )
    .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    assert_eq!(r.json()["state"], "done");
    let st = state(&w, &acct.did);
    assert_eq!(st.devices.len(), 4);
    assert!(st.devices.values().any(|d| d.key == laptop.id));
}

#[tokio::test]
async fn a_request_fails_if_the_log_moves_under_it() {
    let w = world(|_| {});
    let acct = sign_up(&w).await;
    let a = LocalSigner::generate(KeyType::Ed25519);
    let b = LocalSigner::generate(KeyType::Ed25519);
    let ida = terminal_request(&w, &a, "a").await;
    let idb = terminal_request(&w, &b, "b").await;
    for id in [&ida, &idb] {
        post(
            &w.app,
            &format!("/v1/join/{id}/claim"),
            json!({}),
            Some(&acct.cookie),
        )
        .await;
        approve_with_passkey(&w, id, &acct.passkey).await;
    }
    // Both were built on seq 0; the first to finish wins, the second must start again.
    assert_eq!(terminal_pop(&w, &ida, &a).await.json()["state"], "done");
    let r = terminal_pop(&w, &idb, &b).await.json();
    assert_eq!(r["state"], "failed");
    assert!(r["error"].is_string());
    assert_eq!(state(&w, &acct.did).devices.len(), 2);
}

#[tokio::test]
async fn terminal_requests_are_checked_and_rate_limited() {
    let w = world(|c| {
        c.join_limit = RateLimit {
            max: 4,
            window_secs: 3600,
        }
    });
    let key = LocalSigner::generate(KeyType::Ed25519).id;
    for (device, why) in [
        (
            json!({"key": key, "name": "x", "kind": "software", "aal": 2}),
            "software is aal 1",
        ),
        (
            json!({"key": key, "name": "x", "kind": "passkey", "aal": 2}),
            "passkeys join by invite",
        ),
        (
            json!({"key": "nope", "name": "x", "kind": "hardware", "aal": 1}),
            "a did:key",
        ),
        (
            json!({"key": key, "name": "x", "kind": "hardware", "aal": 1, "xkey": "did:key:zbad"}),
            "an X25519 xkey",
        ),
    ] {
        let r = post(&w.app, "/v1/join", json!({"device": device}), None).await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "{why}: {}", r.text());
    }
    // The fifth attempt from one address in the hour: four above, and this.
    let r = post(
        &w.app,
        "/v1/join",
        json!({"device": {"key": key, "name": "x", "kind": "hardware", "aal": 3}}),
        None,
    )
    .await;
    assert_eq!(r.status, StatusCode::TOO_MANY_REQUESTS, "{}", r.text());
    assert_eq!(
        get(&w.app, "/v1/join/unknown", None).await.status,
        StatusCode::NOT_FOUND
    );
    let page = get(&w.app, "/join/unknown", None).await;
    assert_eq!(page.status, StatusCode::NOT_FOUND);
    assert!(page.text().contains("Link expired"));
}

#[tokio::test]
async fn the_account_page_offers_to_add_a_device() {
    let w = world(|_| {});
    let acct = sign_up(&w).await;
    let page = get(&w.app, "/whoami", Some(&acct.cookie)).await;
    assert!(page.text().contains(r#"id="add""#));
    assert!(page.text().contains("/v1/join/invite"));
}
