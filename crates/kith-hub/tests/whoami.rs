//! `GET /v1/whoami` and `GET /v1/profile/{did}`: one identity's key event log, devices,
//! sessions and recovery state, as the owner sees it and as anyone sees it.
//!
//! Anything derived from the KEL is already public (`GET /v1/kel/{did}`), so the public
//! profile shows exactly that. What only the hub holds (sessions, the authenticator, the
//! co-signer) is for the owner alone.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{header, Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;

use kith_core::kel::{new_inception, next_event, verify_log, Device, DeviceKind, EventBody, KeyState};
use kith_core::keys::{KeyType, LocalSigner, VerifyOptions};
use kith_core::policy::SignerPolicy;
use kith_core::session::{DeviceSigner, SessionKey};
use kith_core::util::{b64u, now, random_id, sha256};
use kith_core::{totp, webauthn};
use kith_hub::oidc::{Client, Consent};
use kith_hub::{Hub, HubConfig, TT_SESSION};

const ISSUER: &str = "http://localhost:7777";
const ORIGIN: &str = "http://localhost:7777";
const APP_CB: &str = "http://localhost:3000/cb";

struct Person {
    st: KeyState,
    laptop: LocalSigner,
    passkey: LocalSigner,
    recovery: Vec<LocalSigner>,
}

struct World {
    app: Router,
    hub: Arc<Hub>,
}

fn device(id: &str, key: &LocalSigner, kind: DeviceKind, caps: &[&str]) -> Device {
    Device {
        id: id.into(),
        key: key.id.clone(),
        name: id.into(),
        kind,
        aal: if kind == DeviceKind::Passkey { 2 } else { 1 },
        caps: caps.iter().map(|c| c.to_string()).collect(),
        rp_id: (kind == DeviceKind::Passkey).then(|| "localhost".into()),
        xkey: None,
    }
}

/// An identity with three devices, a 2-of-3 recovery policy committed in `next`, and a
/// history: the tablet is revoked, then the recovery keys rotate the manage key.
fn person(hub: &Hub) -> Person {
    let root = LocalSigner::generate(KeyType::Ed25519);
    let laptop = LocalSigner::generate(KeyType::Ed25519);
    let tablet = LocalSigner::generate(KeyType::Ed25519);
    let passkey = LocalSigner::generate(KeyType::P256);
    let recovery: Vec<LocalSigner> = (0..3).map(|_| LocalSigner::generate(KeyType::Ed25519)).collect();
    let rotation = SignerPolicy::threshold(2, recovery.iter().map(|s| SignerPolicy::single(&s.id)).collect());

    let mut inc = new_inception(
        SignerPolicy::single(&root.id),
        &rotation,
        vec![
            device("laptop", &laptop, DeviceKind::Software, &["session", "alias"]),
            device("tablet", &tablet, DeviceKind::Software, &["session"]),
            device("phone", &passkey, DeviceKind::Passkey, &["session"]),
        ],
    );
    inc.sign(&root).unwrap();
    inc.sign(&laptop).unwrap();
    inc.sign(&tablet).unwrap();
    let msg = inc.signing_message().unwrap();
    inc.add_sig(webauthn::soft_sign_message(&passkey, "localhost", ORIGIN, &msg).unwrap());
    let mut log = vec![inc];

    let st = verify_log(&log, &VerifyOptions::default()).unwrap();
    let mut revoke = next_event(&st, EventBody::RevokeDevice { device_id: "tablet".into(), reason: Some("lost".into()) });
    revoke.sign(&root).unwrap();
    log.push(revoke);

    let st = verify_log(&log, &VerifyOptions::default()).unwrap();
    let new_root = LocalSigner::generate(KeyType::Ed25519);
    let new_next = SignerPolicy::single(LocalSigner::generate(KeyType::Ed25519).id);
    let mut rotate = next_event(&st, EventBody::Rotate { rotation, manage: SignerPolicy::single(&new_root.id), next: new_next.digest(), revoke_devices: false });
    rotate.sign(&recovery[0]).unwrap();
    rotate.sign(&recovery[2]).unwrap();
    log.push(rotate);

    let st = verify_log(&log, &VerifyOptions::default()).unwrap();
    hub.put_kel(&st.did, log).unwrap();
    Person { st, laptop, passkey, recovery }
}

fn world() -> World {
    let dir = std::env::temp_dir().join(format!("kith-whoami-{}", random_id()));
    let mut cfg = HubConfig::new(ISSUER, dir.join("data"));
    cfg.clients = vec![Client { client_id: "app".into(), redirect_uris: vec![APP_CB.into()], name: Some("Demo App".into()), consent: Consent::Implied, ..Default::default() }];
    let hub = Hub::open(cfg).unwrap();
    World { app: kith_hub::router(hub.clone()), hub }
}

struct Resp {
    status: StatusCode,
    body: Vec<u8>,
}

impl Resp {
    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or(Value::Null)
    }
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

async fn call(app: &Router, method: &str, uri: &str, auth: Option<&str>, body: Option<Value>) -> Resp {
    let mut b = Request::builder().method(method).uri(uri).extension(ConnectInfo(SocketAddr::new("10.0.0.1".parse().unwrap(), 4000)));
    if let Some(a) = auth {
        b = b.header(header::AUTHORIZATION, a);
    }
    let body = match body {
        Some(v) => {
            b = b.header(header::CONTENT_TYPE, "application/json");
            Body::from(v.to_string())
        }
        None => Body::empty(),
    };
    let r = app.clone().oneshot(b.body(body).unwrap()).await.unwrap();
    let status = r.status();
    Resp { status, body: r.into_body().collect().await.unwrap().to_bytes().to_vec() }
}

async fn post_form(app: &Router, uri: &str, form: &[(&str, &str)]) -> Resp {
    let body = form.iter().map(|(k, v)| format!("{k}={}", enc(v))).collect::<Vec<_>>().join("&");
    let req = Request::post(uri).header(header::CONTENT_TYPE, "application/x-www-form-urlencoded").body(Body::from(body)).unwrap();
    let r = app.clone().oneshot(req).await.unwrap();
    let status = r.status();
    Resp { status, body: r.into_body().collect().await.unwrap().to_bytes().to_vec() }
}

fn enc(s: &str) -> String {
    s.bytes().map(|b| if b.is_ascii_alphanumeric() || b"-._~".contains(&b) { (b as char).to_string() } else { format!("%{b:02X}") }).collect()
}

/// A hub token from the laptop's device key, as the CLI gets one.
async fn bearer(w: &World, p: &Person) -> String {
    let dev = p.st.device("laptop").unwrap().clone();
    let sk = SessionKey::create(&p.st.did, &dev, DeviceSigner::Key(&p.laptop.secret), 3600).unwrap();
    let st_tok = sk.session_token(ISSUER, json!({})).unwrap();
    let tok = post_form(&w.app, "/oauth/token", &[("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange"), ("subject_token", &st_tok), ("subject_token_type", TT_SESSION)]).await.json();
    format!("Bearer {}", tok["access_token"].as_str().expect("access token"))
}

fn page_data(html: &str) -> Value {
    let start = html.find(r#"<script id="kith-data" type="application/json">"#).unwrap() + 47;
    let end = start + html[start..].find("</script>").unwrap();
    serde_json::from_str(&html[start..end]).unwrap()
}

/// Sign in to the `app` client with the passkey, which starts a hub session.
async fn sign_in(w: &World, p: &Person) {
    let verifier = format!("{}{}", random_id(), random_id());
    let challenge = b64u(sha256(verifier.as_bytes()));
    let url = format!("/oauth/authorize?response_type=code&client_id=app&redirect_uri={}&scope=openid&state=s&nonce=n&code_challenge={challenge}&code_challenge_method=S256", enc(APP_CB));
    let page = call(&w.app, "GET", &url, None, None).await;
    let d = page_data(&page.text());
    let message = d["message"].as_str().unwrap();
    let (data, sig) = webauthn::soft_assert(&p.passkey.secret, "localhost", ORIGIN, &sha256(message.as_bytes()), true, 1).unwrap();
    let factor = json!({"type": "webauthn", "authenticator_data": data.authenticator_data, "client_data_json": data.client_data_json, "signature": b64u(sig)});
    let r = call(&w.app, "POST", "/oauth/login", None, Some(json!({"request_id": d["request_id"], "challenge_id": d["challenge_id"], "did": p.st.did, "factors": [factor]}))).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
}

fn strings(v: &Value) -> Vec<String> {
    let mut out: Vec<String> = v.as_array().expect("an array").iter().map(|s| s.as_str().expect("a string").to_string()).collect();
    out.sort();
    out
}

#[tokio::test]
async fn whoami_needs_a_hub_token() {
    let w = world();
    person(&w.hub);
    assert_eq!(call(&w.app, "GET", "/v1/whoami", None, None).await.status, StatusCode::UNAUTHORIZED);
    assert_eq!(call(&w.app, "GET", "/v1/whoami", Some("Bearer nonsense"), None).await.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn whoami_shows_the_log_the_devices_and_the_recovery_commitment() {
    let w = world();
    let p = person(&w.hub);
    let auth = bearer(&w, &p).await;
    let r = call(&w.app, "GET", "/v1/whoami", Some(&auth), None).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    let v = r.json();
    assert_eq!(v["did"], p.st.did);

    // The log, oldest first, with who signed each event.
    let events = v["events"].as_array().unwrap();
    assert_eq!(events.iter().map(|e| e["kind"].as_str().unwrap()).collect::<Vec<_>>(), ["inception", "revoke_device", "rotate"]);
    assert_eq!(events.iter().map(|e| e["seq"].as_u64().unwrap()).collect::<Vec<_>>(), (0..=p.st.seq).collect::<Vec<_>>());
    assert_eq!(events[2]["digest"], p.st.digest);
    assert_eq!(events[1]["detail"]["device_id"], "tablet");
    assert_eq!(events[1]["detail"]["reason"], "lost");
    assert_eq!(events[0]["signers"].as_array().unwrap().len(), 4, "the root and each device sign an inception");

    // Devices as they stand now: the revoked tablet is gone and listed as revoked.
    let devices = v["state"]["devices"].as_object().unwrap();
    assert_eq!(devices.keys().cloned().collect::<Vec<_>>(), ["laptop", "phone"]);
    assert_eq!(strings(&v["state"]["revoked"]), ["tablet"]);

    // Recovery: the hub sees what is committed and which rotations revealed their signers.
    assert_eq!(v["recovery"]["next"], p.st.next);
    let rotations = v["recovery"]["rotations"].as_array().unwrap();
    assert_eq!(rotations.len(), 1);
    assert_eq!(rotations[0]["seq"], 2);
    let mut expected = vec![p.recovery[0].id.clone(), p.recovery[2].id.clone()];
    expected.sort();
    assert_eq!(strings(&rotations[0]["signers"]), expected);
    assert_eq!(rotations[0]["revoked_devices"], false);
    assert_eq!(v["recovery"]["totp"]["enrolled"], false);
    assert_eq!(v["recovery"]["cosigner"], Value::Null);

    // The token that asked.
    assert_eq!(v["token"]["dev"], "laptop");
    assert!(v["token"]["exp"].as_i64().unwrap() > now());
}

#[tokio::test]
async fn whoami_lists_only_your_own_sessions() {
    let w = world();
    let (a, b) = (person(&w.hub), person(&w.hub));
    let auth = bearer(&w, &a).await;
    assert_eq!(call(&w.app, "GET", "/v1/whoami", Some(&auth), None).await.json()["sessions"], json!([]));

    sign_in(&w, &a).await;
    sign_in(&w, &b).await;
    let v = call(&w.app, "GET", "/v1/whoami", Some(&auth), None).await.json();
    let sessions = v["sessions"].as_array().unwrap();
    assert_eq!(sessions.len(), 1, "{sessions:?}");
    assert_eq!(sessions[0]["did"], a.st.did);
    assert_eq!(sessions[0]["device"], "phone");
    assert_eq!(sessions[0]["aal"], 2);
    assert_eq!(sessions[0]["clients"], json!(["app"]));
    assert!(sessions[0].get("cookie").is_none() && sessions[0].get("secret").is_none());
}

#[tokio::test]
async fn whoami_reports_the_authenticator_and_the_cosigner_without_creating_them() {
    let w = world();
    let p = person(&w.hub);
    let auth = bearer(&w, &p).await;
    // Looking does not make a co-signer.
    for _ in 0..2 {
        assert_eq!(call(&w.app, "GET", "/v1/whoami", Some(&auth), None).await.json()["recovery"]["cosigner"], Value::Null);
    }

    let enrolled = call(&w.app, "POST", "/v1/totp/enroll", Some(&auth), None).await.json();
    let secret = totp::from_base32(enrolled["secret"].as_str().unwrap()).unwrap();
    let pending = call(&w.app, "GET", "/v1/whoami", Some(&auth), None).await.json();
    assert_eq!(pending["recovery"]["totp"]["enrolled"], false, "enrolled but not confirmed");
    assert_eq!(call(&w.app, "POST", "/v1/totp/confirm", Some(&auth), Some(json!({"code": totp::code_at(&secret, now())}))).await.status, StatusCode::OK);
    let signer = call(&w.app, "POST", "/v1/cosigner", Some(&auth), None).await.json()["signer"].clone();

    let v = call(&w.app, "GET", "/v1/whoami", Some(&auth), None).await.json();
    assert_eq!(v["recovery"]["totp"]["enrolled"], true);
    assert_eq!(v["recovery"]["cosigner"], signer);
    assert!(!v.to_string().contains(enrolled["secret"].as_str().unwrap()), "the seed never leaves the hub");
}

#[tokio::test]
async fn profile_is_public_and_holds_only_what_the_log_makes_public() {
    let w = world();
    let p = person(&w.hub);
    let auth = bearer(&w, &p).await;
    sign_in(&w, &p).await;
    call(&w.app, "POST", "/v1/cosigner", Some(&auth), None).await;

    let r = call(&w.app, "GET", &format!("/v1/profile/{}", p.st.did), None, None).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    let v = r.json();
    assert_eq!(v["did"], p.st.did);
    assert_eq!(v["events"].as_array().unwrap().len(), 3);
    assert_eq!(v["state"]["devices"].as_object().unwrap().len(), 2);
    assert_eq!(v["recovery"]["next"], p.st.next);
    assert_eq!(v["recovery"]["rotations"].as_array().unwrap().len(), 1);

    // Nothing the hub alone knows.
    for private in ["sessions", "token"] {
        assert!(v.get(private).is_none(), "{private} is for the owner");
    }
    assert!(v["recovery"].get("totp").is_none() && v["recovery"].get("cosigner").is_none());

    // The events are the stored log's, so a mirror can check them against `/v1/kel`.
    let kel = call(&w.app, "GET", &format!("/v1/kel/{}", p.st.did), None, None).await.json();
    assert_eq!(v["events"].as_array().unwrap().len(), kel.as_array().unwrap().len());

    assert_eq!(call(&w.app, "GET", "/v1/profile/did:kith:nobody", None, None).await.status, StatusCode::NOT_FOUND);
}
