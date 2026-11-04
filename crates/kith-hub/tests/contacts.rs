//! Verified contacts (spec 7.8.2): proving an email address or phone number to the hub,
//! keeping it private, publishing it, and checking it again. Messages go to an outbox
//! file instead of AWS.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{header, Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;

use kith_core::kel::{new_inception, verify_log, Device, DeviceKind, KeyState};
use kith_core::keys::{KeyType, LocalSigner, VerifyOptions};
use kith_core::policy::SignerPolicy;
use kith_core::session::{DeviceSigner, SessionKey};
use kith_core::token::verify_account_attestation;
use kith_core::util::{b64u, random_id, sha256};
use kith_core::webauthn;
use kith_hub::contacts::{Delivery, PUBLIC_AUDIENCE};
use kith_hub::oidc::{Client, Consent};
use kith_hub::{Hub, HubConfig, RateLimit, TT_SESSION};

const ISSUER: &str = "http://localhost:7777";
const ORIGIN: &str = "http://localhost:7777";
const APP_CB: &str = "http://localhost:3000/cb";
const ADA_MAIL: &str = "mailto:ada@example.com";
const ADA_PHONE: &str = "tel:+15555550100";

struct Person {
    st: KeyState,
    laptop: LocalSigner,
    tablet: LocalSigner,
    passkey: LocalSigner,
}

struct World {
    app: Router,
    hub: Arc<Hub>,
    outbox: PathBuf,
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

/// An identity with a laptop that may link aliases, a tablet that may only sign in,
/// and a passkey for the browser.
fn person(hub: &Hub) -> Person {
    let root = LocalSigner::generate(KeyType::Ed25519);
    let laptop = LocalSigner::generate(KeyType::Ed25519);
    let tablet = LocalSigner::generate(KeyType::Ed25519);
    let passkey = LocalSigner::generate(KeyType::P256);
    let next = SignerPolicy::single(LocalSigner::generate(KeyType::Ed25519).id);
    let mut inc = new_inception(
        SignerPolicy::single(&root.id),
        &next,
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
    let log = vec![inc];
    let st = verify_log(&log, &VerifyOptions::default()).unwrap();
    hub.put_kel(&st.did, log).unwrap();
    Person { st, laptop, tablet, passkey }
}

fn world_with(configure: impl FnOnce(&mut HubConfig)) -> World {
    let dir = std::env::temp_dir().join(format!("kith-contacts-{}", random_id()));
    let outbox = dir.join("outbox.jsonl");
    let mut cfg = HubConfig::new(ISSUER, dir.join("data"));
    cfg.contacts.delivery = Delivery::Outbox(outbox.clone());
    cfg.clients = vec![Client { client_id: "app".into(), redirect_uris: vec![APP_CB.into()], name: Some("Demo App".into()), consent: Consent::Implied, ..Default::default() }];
    configure(&mut cfg);
    let hub = Hub::open(cfg).unwrap();
    World { app: kith_hub::router(hub.clone()), hub, outbox }
}

fn world() -> World {
    world_with(|_| {})
}

struct Resp {
    status: StatusCode,
    body: Vec<u8>,
    cookie: Option<String>,
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
    call_from(app, "10.0.0.1", method, uri, auth, body).await
}

async fn call_from(app: &Router, ip: &str, method: &str, uri: &str, auth: Option<&str>, body: Option<Value>) -> Resp {
    call_with(app, ip, method, uri, auth.map(|a| (header::AUTHORIZATION, a)), body).await
}

async fn call_with(app: &Router, ip: &str, method: &str, uri: &str, extra: Option<(header::HeaderName, &str)>, body: Option<Value>) -> Resp {
    let mut b = Request::builder().method(method).uri(uri).extension(ConnectInfo(SocketAddr::new(ip.parse().unwrap(), 4000)));
    if let Some((k, v)) = extra {
        b = b.header(k, v);
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
    let cookie = r.headers().get(header::SET_COOKIE).map(|v| v.to_str().unwrap().split(';').next().unwrap().to_string());
    Resp { status, cookie, body: r.into_body().collect().await.unwrap().to_bytes().to_vec() }
}

async fn post_form(app: &Router, uri: &str, form: &[(&str, &str)]) -> Resp {
    let body = form.iter().map(|(k, v)| format!("{k}={}", enc(v))).collect::<Vec<_>>().join("&");
    let req = Request::post(uri).header(header::CONTENT_TYPE, "application/x-www-form-urlencoded").body(Body::from(body)).unwrap();
    let r = app.clone().oneshot(req).await.unwrap();
    let status = r.status();
    let location = r.headers().get(header::LOCATION).map(|v| v.to_str().unwrap().to_string());
    let mut body = r.into_body().collect().await.unwrap().to_bytes().to_vec();
    if let Some(l) = location {
        body = l.into_bytes();
    }
    Resp { status, body, cookie: None }
}

fn enc(s: &str) -> String {
    s.bytes().map(|b| if b.is_ascii_alphanumeric() || b"-._~".contains(&b) { (b as char).to_string() } else { format!("%{b:02X}") }).collect()
}

/// A hub token from one of the person's device keys, as the CLI gets one.
async fn bearer(w: &World, p: &Person, device: &str) -> String {
    let key = if device == "laptop" { &p.laptop } else { &p.tablet };
    let dev = p.st.device(device).unwrap().clone();
    let sk = SessionKey::create(&p.st.did, &dev, DeviceSigner::Key(&key.secret), 3600).unwrap();
    let st_tok = sk.session_token(ISSUER, json!({})).unwrap();
    let tok = post_form(&w.app, "/oauth/token", &[("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange"), ("subject_token", &st_tok), ("subject_token_type", TT_SESSION)]).await.json();
    format!("Bearer {}", tok["access_token"].as_str().expect("access token"))
}

/// Every message the hub sent to `to`, oldest first.
fn sent_to(w: &World, to: &str) -> Vec<Value> {
    std::fs::read_to_string(&w.outbox).unwrap_or_default().lines().map(|l| serde_json::from_str::<Value>(l).unwrap()).filter(|m| m["to"] == to).collect()
}

/// The code in the last message to `to`.
fn last_code(w: &World, to: &str) -> String {
    let m = sent_to(w, to).pop().unwrap_or_else(|| panic!("nothing was sent to {to}"));
    let body = m["body"].as_str().unwrap();
    body.split(|c: char| !c.is_ascii_digit()).find(|t| t.len() == 6).expect("a six-digit code").to_string()
}

async fn verify_contact(w: &World, auth: &str, address: &str) -> Value {
    let r = call(&w.app, "POST", "/v1/contacts", Some(auth), Some(json!({"address": address}))).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    let normal = r.json()["address"].as_str().unwrap().to_string();
    let r = call(&w.app, "POST", "/v1/contacts/confirm", Some(auth), Some(json!({"address": address, "code": last_code(w, &normal)}))).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    r.json()
}

async fn list(w: &World, auth: &str) -> Vec<Value> {
    let r = call(&w.app, "GET", "/v1/contacts", Some(auth), None).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    r.json()["contacts"].as_array().unwrap().clone()
}

async fn lookup(w: &World, address: &str) -> Resp {
    call(&w.app, "GET", &format!("/v1/contacts/lookup?address={}", enc(address)), None, None).await
}

fn query(url: &str) -> HashMap<String, String> {
    url.split_once('?').map(|(_, q)| q).unwrap_or_default().split('&').filter_map(|kv| kv.split_once('=')).map(|(k, v)| (k.to_string(), v.to_string())).collect()
}

fn page_data(html: &str) -> Value {
    let start = html.find(r#"<script id="kith-data" type="application/json">"#).unwrap() + 47;
    let end = start + html[start..].find("</script>").unwrap();
    serde_json::from_str(&html[start..end]).unwrap()
}

/// Sign in to the `app` client with the passkey and redeem the code.
async fn sign_in(w: &World, p: &Person, scope: &str) -> Value {
    let verifier = format!("{}{}", random_id(), random_id());
    let challenge = b64u(sha256(verifier.as_bytes()));
    let url = format!("/oauth/authorize?response_type=code&client_id=app&redirect_uri={}&scope={}&state=s&nonce=n&code_challenge={challenge}&code_challenge_method=S256", enc(APP_CB), enc(scope));
    let page = call(&w.app, "GET", &url, None, None).await;
    let d = page_data(&page.text());
    let message = d["message"].as_str().unwrap();
    let (data, sig) = webauthn::soft_assert(&p.passkey.secret, "localhost", ORIGIN, &sha256(message.as_bytes()), true, 1).unwrap();
    let factor = json!({"type": "webauthn", "authenticator_data": data.authenticator_data, "client_data_json": data.client_data_json, "signature": b64u(sig)});
    let r = call(&w.app, "POST", "/oauth/login", None, Some(json!({"request_id": d["request_id"], "challenge_id": d["challenge_id"], "did": p.st.did, "factors": [factor]}))).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    let redirect = r.json()["redirect"].as_str().unwrap().to_string();
    let code = query(&redirect)["code"].clone();
    let r = post_form(&w.app, "/oauth/token", &[("grant_type", "authorization_code"), ("code", &code), ("redirect_uri", APP_CB), ("code_verifier", &verifier), ("client_id", "app")]).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    r.json()
}

fn id_claims(tokens: &Value) -> Value {
    kith_core::jws::decode(tokens["id_token"].as_str().unwrap()).unwrap().claims
}

/// Each attestation in the token response, verified as the app would.
fn attestations(w: &World, tokens: &Value) -> Vec<kith_core::token::AccountAttestation> {
    tokens["contact_attestations"]
        .as_array()
        .map(|a| a.iter().map(|t| verify_account_attestation(t.as_str().unwrap(), &w.hub.jwks(), ISSUER, "app", kith_core::util::now()).unwrap()).collect())
        .unwrap_or_default()
}

#[tokio::test]
async fn a_verified_email_goes_only_to_apps_the_user_agreed_with() {
    let w = world();
    let ada = person(&w.hub);
    let auth = bearer(&w, &ada, "laptop").await;

    let r = call(&w.app, "POST", "/v1/contacts", Some(&auth), Some(json!({"address": "Ada@Example.COM"}))).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    assert_eq!(r.json()["address"], ADA_MAIL, "addresses are normalised");
    let mail = sent_to(&w, ADA_MAIL);
    assert_eq!(mail.len(), 1);
    assert!(mail[0]["body"].as_str().unwrap().contains("localhost"), "the message names the hub");

    // Not verified yet: listed nowhere, released nowhere.
    assert!(list(&w, &auth).await.is_empty());
    let r = call(&w.app, "POST", "/v1/contacts/confirm", Some(&auth), Some(json!({"address": ADA_MAIL, "code": last_code(&w, ADA_MAIL)}))).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    let contacts = list(&w, &auth).await;
    assert_eq!(contacts.len(), 1);
    assert_eq!(contacts[0]["address"], ADA_MAIL);
    assert_eq!(contacts[0]["kind"], "email");
    assert_eq!(contacts[0]["public"], false, "private by default");
    assert_eq!(contacts[0]["fresh"], true);

    // Nothing public, and the DID document says nothing either.
    assert_eq!(lookup(&w, ADA_MAIL).await.status, StatusCode::NOT_FOUND);
    let doc = call(&w.app, "GET", &format!("/v1/did/{}", ada.st.did), None, None).await.text();
    assert!(!doc.contains("ada@example.com"));

    // An app without the email scope gets nothing about it.
    let t = sign_in(&w, &ada, "openid profile").await;
    assert!(id_claims(&t).get("email").is_none());
    assert!(t.get("contact_attestations").is_none());
    assert!(!kith_core::jws::decode(t["access_token"].as_str().unwrap()).unwrap().claims.to_string().contains("ada@example.com"), "never in an access token");

    // With it: the claim and a signed attestation.
    let t = sign_in(&w, &ada, "openid email").await;
    let id = id_claims(&t);
    assert_eq!(id["email"], "ada@example.com");
    assert_eq!(id["email_verified"], true);
    let atts = attestations(&w, &t);
    assert_eq!(atts.len(), 1);
    assert_eq!(atts[0].provider, "email");
    assert_eq!(atts[0].provider_iss, ISSUER);
    assert_eq!(atts[0].account, ADA_MAIL);
    assert_eq!(atts[0].sub, ada.st.did);
    assert_eq!(atts[0].verified_at, contacts[0]["verified_at"].as_i64().unwrap());

    // Userinfo agrees with the ID token.
    let ui = call(&w.app, "GET", "/oauth/userinfo", Some(&format!("Bearer {}", t["access_token"].as_str().unwrap())), None).await.json();
    assert_eq!(ui["email"], "ada@example.com");
}

#[tokio::test]
async fn a_phone_number_is_normalised_and_released_with_the_phone_scope() {
    let w = world();
    let ada = person(&w.hub);
    let auth = bearer(&w, &ada, "laptop").await;
    let c = verify_contact(&w, &auth, "+1 (555) 555-0100").await;
    assert_eq!(c["address"], ADA_PHONE);
    let text = sent_to(&w, ADA_PHONE)[0]["body"].as_str().unwrap().to_string();
    let code = last_code(&w, ADA_PHONE);
    assert!(text.trim_end().ends_with(&format!("@localhost #{code}")), "origin-bound code line: {text}");

    for bad in ["555-0100", "+1 555", "tel:15555550100", "+1234567890123456", "ada@", "@example.com", "ada@localhost", "ada example@example.com"] {
        let r = call(&w.app, "POST", "/v1/contacts", Some(&auth), Some(json!({"address": bad}))).await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "{bad}: {}", r.text());
    }

    let t = sign_in(&w, &ada, "openid phone").await;
    let id = id_claims(&t);
    assert_eq!(id["phone_number"], "+15555550100");
    assert_eq!(id["phone_number_verified"], true);
    let atts = attestations(&w, &t);
    assert_eq!(atts.len(), 1);
    assert_eq!((atts[0].provider.as_str(), atts[0].account.as_str()), ("phone", ADA_PHONE));
}

#[tokio::test]
async fn phone_numbers_can_be_limited_to_some_countries() {
    let w = world_with(|c| c.contacts.phone_prefixes = vec!["+1".into()]);
    let ada = person(&w.hub);
    let auth = bearer(&w, &ada, "laptop").await;
    let r = call(&w.app, "POST", "/v1/contacts", Some(&auth), Some(json!({"address": "+44 20 7946 0000"}))).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST, "{}", r.text());
    assert!(sent_to(&w, "tel:+442079460000").is_empty(), "nothing was sent");
    verify_contact(&w, &auth, ADA_PHONE).await;
}

#[tokio::test]
async fn codes_are_single_use_and_give_out_after_five_wrong_tries() {
    let w = world();
    let ada = person(&w.hub);
    let auth = bearer(&w, &ada, "laptop").await;
    call(&w.app, "POST", "/v1/contacts", Some(&auth), Some(json!({"address": ADA_MAIL}))).await;
    let code = last_code(&w, ADA_MAIL);
    let wrong = if code == "000000" { "000001" } else { "000000" };
    for _ in 0..5 {
        let r = call(&w.app, "POST", "/v1/contacts/confirm", Some(&auth), Some(json!({"address": ADA_MAIL, "code": wrong}))).await;
        assert_eq!(r.status, StatusCode::UNAUTHORIZED, "{}", r.text());
    }
    let r = call(&w.app, "POST", "/v1/contacts/confirm", Some(&auth), Some(json!({"address": ADA_MAIL, "code": code}))).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED, "the code is gone after five wrong tries: {}", r.text());

    // A new code works, once.
    call(&w.app, "POST", "/v1/contacts", Some(&auth), Some(json!({"address": ADA_MAIL}))).await;
    let code = last_code(&w, ADA_MAIL);
    let confirm = || call(&w.app, "POST", "/v1/contacts/confirm", Some(&auth), Some(json!({"address": ADA_MAIL, "code": code})));
    assert_eq!(confirm().await.status, StatusCode::OK);
    assert_eq!(confirm().await.status, StatusCode::UNAUTHORIZED);

    // Someone else's code is not yours.
    let bob = person(&w.hub);
    let bob_auth = bearer(&w, &bob, "laptop").await;
    call(&w.app, "POST", "/v1/contacts", Some(&auth), Some(json!({"address": "mailto:ada2@example.com"}))).await;
    let code = last_code(&w, "mailto:ada2@example.com");
    let r = call(&w.app, "POST", "/v1/contacts/confirm", Some(&bob_auth), Some(json!({"address": "mailto:ada2@example.com", "code": code}))).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn sending_is_rate_limited_per_identity_address_and_client() {
    let w = world_with(|c| c.contacts.send_limit = RateLimit { max: 2, window_secs: 3600 });
    let ada = person(&w.hub);
    let auth = bearer(&w, &ada, "laptop").await;
    let send = |ip: &'static str, addr: &'static str| call_from(&w.app, ip, "POST", "/v1/contacts", Some(&auth), Some(json!({"address": addr})));
    assert_eq!(send("10.0.0.1", "mailto:a@example.com").await.status, StatusCode::OK);
    assert_eq!(send("10.0.0.2", "mailto:a@example.com").await.status, StatusCode::OK);
    assert_eq!(send("10.0.0.3", "mailto:a@example.com").await.status, StatusCode::TOO_MANY_REQUESTS, "per address");
    let bob = person(&w.hub);
    let bob_auth = bearer(&w, &bob, "laptop").await;
    let r = call_from(&w.app, "10.0.0.4", "POST", "/v1/contacts", Some(&bob_auth), Some(json!({"address": "mailto:a@example.com"}))).await;
    assert_eq!(r.status, StatusCode::TOO_MANY_REQUESTS, "per address, whoever asks");
    assert_eq!(sent_to(&w, "mailto:a@example.com").len(), 2);
}

#[tokio::test]
async fn a_published_contact_can_be_looked_up_and_withdrawn() {
    let w = world();
    let ada = person(&w.hub);
    let laptop = bearer(&w, &ada, "laptop").await;
    let tablet = bearer(&w, &ada, "tablet").await;
    verify_contact(&w, &laptop, ADA_MAIL).await;

    let publish = |auth: String, public: bool| {
        let app = w.app.clone();
        async move { call(&app, "PUT", "/v1/contacts/public", Some(&auth), Some(json!({"address": ADA_MAIL, "public": public}))).await }
    };
    let r = publish(tablet.clone(), true).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN, "a device without the alias cap cannot publish: {}", r.text());
    assert_eq!(lookup(&w, ADA_MAIL).await.status, StatusCode::NOT_FOUND);

    assert_eq!(publish(laptop.clone(), true).await.status, StatusCode::OK);
    let r = lookup(&w, "Ada@Example.com").await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    let found = r.json();
    assert_eq!(found["did"], ada.st.did);
    assert_eq!(found["address"], ADA_MAIL);
    let att = verify_account_attestation(found["attestation"].as_str().unwrap(), &w.hub.jwks(), ISSUER, PUBLIC_AUDIENCE, kith_core::util::now()).unwrap();
    assert_eq!((att.sub.as_str(), att.account.as_str(), att.provider.as_str()), (ada.st.did.as_str(), ADA_MAIL, "email"));
    assert!(verify_account_attestation(found["attestation"].as_str().unwrap(), &w.hub.jwks(), ISSUER, "app", kith_core::util::now()).is_err(), "a public attestation is not an app's");
    assert!(list(&w, &laptop).await[0]["public"].as_bool().unwrap());

    assert_eq!(publish(laptop.clone(), false).await.status, StatusCode::OK);
    assert_eq!(lookup(&w, ADA_MAIL).await.status, StatusCode::NOT_FOUND, "withdrawn");

    // Forgetting it ends everything.
    publish(laptop.clone(), true).await;
    let r = call(&w.app, "DELETE", "/v1/contacts", Some(&laptop), Some(json!({"address": ADA_MAIL}))).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    assert_eq!(lookup(&w, ADA_MAIL).await.status, StatusCode::NOT_FOUND);
    assert!(list(&w, &laptop).await.is_empty());
    assert!(sign_in(&w, &ada, "openid email").await.get("contact_attestations").is_none());
}

#[tokio::test]
async fn whoever_proves_control_last_holds_the_address() {
    let w = world();
    let ada = person(&w.hub);
    let bob = person(&w.hub);
    let ada_auth = bearer(&w, &ada, "laptop").await;
    let bob_auth = bearer(&w, &bob, "laptop").await;
    verify_contact(&w, &ada_auth, ADA_PHONE).await;
    call(&w.app, "PUT", "/v1/contacts/public", Some(&ada_auth), Some(json!({"address": ADA_PHONE, "public": true}))).await;
    // Ada's sign-in from before, with a refresh token.
    let before = sign_in(&w, &ada, "openid phone offline_access").await;
    assert_eq!(attestations(&w, &before).len(), 1);

    // The carrier gives the number to Bob, who verifies it.
    verify_contact(&w, &bob_auth, ADA_PHONE).await;
    assert!(list(&w, &ada_auth).await.is_empty(), "Ada no longer holds it");
    assert_eq!(lookup(&w, ADA_PHONE).await.status, StatusCode::NOT_FOUND, "Bob has not published it");
    let bobs = list(&w, &bob_auth).await;
    assert_eq!((bobs[0]["address"].as_str(), bobs[0]["public"].as_bool()), (Some(ADA_PHONE), Some(false)));

    // Ada's app learns it at the next refresh.
    let r = post_form(&w.app, "/oauth/token", &[("grant_type", "refresh_token"), ("refresh_token", before["refresh_token"].as_str().unwrap()), ("client_id", "app")]).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    let after = r.json();
    assert!(after.get("contact_attestations").is_none(), "{after}");
    assert!(id_claims(&after).get("phone_number").is_none());
}

#[tokio::test]
async fn a_stale_contact_is_kept_but_not_attested_until_checked_again() {
    let w = world_with(|c| c.contacts.email_max_age = 1);
    let ada = person(&w.hub);
    let auth = bearer(&w, &ada, "laptop").await;
    let first = verify_contact(&w, &auth, ADA_MAIL).await;
    call(&w.app, "PUT", "/v1/contacts/public", Some(&auth), Some(json!({"address": ADA_MAIL, "public": true}))).await;
    assert_eq!(lookup(&w, ADA_MAIL).await.status, StatusCode::OK);

    tokio::time::sleep(std::time::Duration::from_millis(2100)).await;
    let c = list(&w, &auth).await;
    assert_eq!((c[0]["fresh"].as_bool(), c[0]["public"].as_bool()), (Some(false), Some(true)), "kept, still marked public");
    assert_eq!(lookup(&w, ADA_MAIL).await.status, StatusCode::NOT_FOUND, "stale: not looked up");
    let t = sign_in(&w, &ada, "openid email").await;
    assert!(t.get("contact_attestations").is_none());
    assert!(id_claims(&t).get("email").is_none());
    let r = call(&w.app, "PUT", "/v1/contacts/public", Some(&auth), Some(json!({"address": ADA_MAIL, "public": true}))).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST, "a stale contact cannot be published: {}", r.text());

    // Checking again: a new code, a new verified_at, and it is public again.
    let again = verify_contact(&w, &auth, ADA_MAIL).await;
    assert!(again["verified_at"].as_i64() > first["verified_at"].as_i64());
    assert_eq!(lookup(&w, ADA_MAIL).await.status, StatusCode::OK);
    assert_eq!(attestations(&w, &sign_in(&w, &ada, "openid email").await)[0].verified_at, again["verified_at"].as_i64().unwrap());
}

#[tokio::test]
async fn the_consent_page_shows_the_contact_before_it_is_released() {
    let w = world_with(|c| c.clients.push(Client { client_id: "ask".into(), redirect_uris: vec![APP_CB.into()], name: Some("Asking App".into()), ..Default::default() }));
    let ada = person(&w.hub);
    let auth = bearer(&w, &ada, "laptop").await;
    verify_contact(&w, &auth, ADA_PHONE).await;
    let verifier = format!("{}{}", random_id(), random_id());
    let challenge = b64u(sha256(verifier.as_bytes()));
    let url = format!("/oauth/authorize?response_type=code&client_id=ask&redirect_uri={}&scope={}&state=s&nonce=n&code_challenge={challenge}&code_challenge_method=S256", enc(APP_CB), enc("openid phone"));
    let page = call(&w.app, "GET", &url, None, None).await;
    let d = page_data(&page.text());
    let message = d["message"].as_str().unwrap();
    let (data, sig) = webauthn::soft_assert(&ada.passkey.secret, "localhost", ORIGIN, &sha256(message.as_bytes()), true, 1).unwrap();
    let factor = json!({"type": "webauthn", "authenticator_data": data.authenticator_data, "client_data_json": data.client_data_json, "signature": b64u(sig)});
    let r = call(&w.app, "POST", "/oauth/login", None, Some(json!({"request_id": d["request_id"], "challenge_id": d["challenge_id"], "did": ada.st.did, "factors": [factor]}))).await;
    let consent_url = r.json()["redirect"].as_str().unwrap().to_string();
    assert!(consent_url.starts_with("/oauth/consent"), "{consent_url}");
    let cookie = r.cookie.expect("session cookie");
    let page = call_with(&w.app, "10.0.0.1", "GET", &consent_url, Some((header::COOKIE, &cookie)), None).await;
    assert_eq!(page.status, StatusCode::OK, "{}", page.text());
    let d = page_data(&page.text());
    assert_eq!(d["claims"]["phone_number"], "+15555550100");
    assert_eq!(d["claims"]["contact_attestations"], json!([ADA_PHONE]), "and that a signed attestation goes with it");
}

#[tokio::test]
async fn without_a_delivery_method_the_endpoints_say_so() {
    let w = world_with(|c| c.contacts.delivery = Delivery::None);
    let ada = person(&w.hub);
    let auth = bearer(&w, &ada, "laptop").await;
    let r = call(&w.app, "POST", "/v1/contacts", Some(&auth), Some(json!({"address": ADA_MAIL}))).await;
    assert_eq!(r.status, StatusCode::NOT_IMPLEMENTED, "{}", r.text());
}

#[tokio::test]
async fn contact_endpoints_need_a_hub_token() {
    let w = world();
    for (method, uri) in [("POST", "/v1/contacts"), ("POST", "/v1/contacts/confirm"), ("GET", "/v1/contacts"), ("PUT", "/v1/contacts/public"), ("DELETE", "/v1/contacts")] {
        let r = call(&w.app, method, uri, None, Some(json!({"address": ADA_MAIL, "code": "123456", "public": true}))).await;
        assert_eq!(r.status, StatusCode::UNAUTHORIZED, "{method} {uri}");
    }
}
