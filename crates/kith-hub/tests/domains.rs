//! Verified domains (spec 7.8.3): proving that an identity, a person or an org, controls a
//! domain by a TXT record, a CNAME or an HTML file that names its DID, and the signed
//! attestations that follow. DNS and HTTP are a fake, so nothing touches the network.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

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
use kith_hub::contacts::PUBLIC_AUDIENCE;
use kith_hub::domains::{DomainProbe, Probe};
use kith_core::domain::{self, Method};
use kith_hub::oidc::{Client, Consent};
use kith_hub::{Hub, HubConfig, TT_SESSION};

const ISSUER: &str = "http://localhost:7777";
const ORIGIN: &str = "http://localhost:7777";
const APP_CB: &str = "http://localhost:3000/cb";
const EXAMPLE: &str = "dns:example.com";

/// The DNS and web of the test: only what a test published exists.
#[derive(Debug, Default)]
struct Net {
    txt: Mutex<HashMap<String, Vec<String>>>,
    cname: Mutex<HashMap<String, Vec<String>>>,
    files: Mutex<HashMap<(String, String), String>>,
    lookups: Mutex<Vec<String>>,
}

impl Net {
    fn txt(&self, name: &str, value: &str) {
        self.txt.lock().unwrap().entry(name.into()).or_default().push(value.into());
    }
    fn cname(&self, name: &str, target: &str) {
        self.cname.lock().unwrap().entry(name.into()).or_default().push(target.into());
    }
    fn file(&self, host: &str, path: &str, body: &str) {
        self.files.lock().unwrap().insert((host.into(), path.into()), body.into());
    }
    fn lookups(&self) -> usize {
        self.lookups.lock().unwrap().len()
    }
}

impl DomainProbe for Net {
    fn txt<'a>(&'a self, name: &'a str) -> Probe<'a, Vec<String>> {
        self.lookups.lock().unwrap().push(format!("txt {name}"));
        let out = self.txt.lock().unwrap().get(name).cloned().unwrap_or_default();
        Box::pin(async move { Ok(out) })
    }
    fn cname<'a>(&'a self, name: &'a str) -> Probe<'a, Vec<String>> {
        self.lookups.lock().unwrap().push(format!("cname {name}"));
        let out = self.cname.lock().unwrap().get(name).cloned().unwrap_or_default();
        Box::pin(async move { Ok(out) })
    }
    fn fetch<'a>(&'a self, host: &'a str, path: &'a str) -> Probe<'a, String> {
        self.lookups.lock().unwrap().push(format!("get {host}{path}"));
        let out = self.files.lock().unwrap().get(&(host.to_string(), path.to_string())).cloned();
        Box::pin(async move { out.ok_or_else(|| anyhow::anyhow!("HTTP 404")) })
    }
}

struct Person {
    st: KeyState,
    laptop: LocalSigner,
    tablet: LocalSigner,
    passkey: LocalSigner,
}

struct World {
    app: Router,
    hub: Arc<Hub>,
    net: Arc<Net>,
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
    let dir = std::env::temp_dir().join(format!("kith-domains-{}", random_id()));
    let net = Arc::new(Net::default());
    let mut cfg = HubConfig::new(ISSUER, dir.join("data"));
    cfg.domains.probe = net.clone();
    cfg.clients = vec![Client { client_id: "app".into(), redirect_uris: vec![APP_CB.into()], name: Some("Demo App".into()), consent: Consent::Implied, ..Default::default() }];
    configure(&mut cfg);
    let hub = Hub::open(cfg).unwrap();
    World { app: kith_hub::router(hub.clone()), hub, net }
}

fn world() -> World {
    world_with(|_| {})
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
    Resp { status, body: r.into_body().collect().await.unwrap().to_bytes().to_vec() }
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
    Resp { status, body }
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

/// Each attestation in the token response, verified as the app would.
fn attestations(w: &World, tokens: &Value) -> Vec<kith_core::token::AccountAttestation> {
    tokens["contact_attestations"]
        .as_array()
        .map(|a| a.iter().map(|t| verify_account_attestation(t.as_str().unwrap(), &w.hub.jwks(), ISSUER, "app", kith_core::util::now()).unwrap()).collect())
        .unwrap_or_default()
}

// ---------------------------------------------------------------- helpers

fn publish_txt(w: &World, domain: &str, did: &str) {
    let r = domain::records(domain, did);
    w.net.txt(&r.txt_name, &r.txt_value);
}

fn publish_cname(w: &World, domain: &str, did: &str) {
    let r = domain::records(domain, did);
    w.net.cname(&r.cname_name, &format!("{}.", r.cname_target));
}

fn publish_html(w: &World, domain: &str, did: &str) {
    w.net.file(domain, &domain::html_path(did), &format!("<html><body>{}</body></html>", domain::value(did)));
}

async fn verify(w: &World, auth: &str, domain: &str, method: Option<&str>) -> Resp {
    let mut body = json!({"domain": domain});
    if let Some(m) = method {
        body["method"] = json!(m);
    }
    call(&w.app, "POST", "/v1/domains/verify", Some(auth), Some(body)).await
}

async fn witness(w: &World, domain: &str, did: &str) -> Resp {
    call(&w.app, "GET", &format!("/v1/domains/attest?domain={}&did={}", enc(domain), enc(did)), None, None).await
}

async fn set_public(w: &World, auth: &str, public: bool) -> Resp {
    call(&w.app, "PUT", "/v1/contacts/public", Some(auth), Some(json!({"address": EXAMPLE, "public": public}))).await
}

// ---------------------------------------------------------------- tests

#[tokio::test]
async fn the_hub_says_what_to_publish_for_the_callers_own_did() {
    let w = world();
    let ada = person(&w.hub);
    let auth = bearer(&w, &ada, "laptop").await;
    for input in ["example.com", "Example.COM", "dns:example.com"] {
        let r = call(&w.app, "POST", "/v1/domains", Some(&auth), Some(json!({"domain": input}))).await;
        assert_eq!(r.status, StatusCode::OK, "{input}: {}", r.text());
        let j = r.json();
        let want = domain::records("example.com", &ada.st.did);
        assert_eq!(j["domain"], EXAMPLE);
        assert_eq!(j["did"], ada.st.did);
        assert_eq!(j["methods"]["txt"], json!({"type": "TXT", "name": want.txt_name, "value": want.txt_value}));
        assert_eq!(j["methods"]["cname"], json!({"type": "CNAME", "name": want.cname_name, "value": want.cname_target}));
        assert_eq!(j["methods"]["html"], json!({"url": want.html_url, "body": want.html_body}));
    }
    for bad in ["localhost", "com", "1.2.3.4", "intranet.local", "example.com/x", "bücher.de", ""] {
        let r = call(&w.app, "POST", "/v1/domains", Some(&auth), Some(json!({"domain": bad}))).await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "{bad:?}: {}", r.text());
    }
    assert_eq!(call(&w.app, "POST", "/v1/domains", None, Some(json!({"domain": "example.com"}))).await.status, StatusCode::UNAUTHORIZED);
    assert_eq!(w.net.lookups(), 0, "telling someone what to publish asks no one");
}

#[tokio::test]
async fn nothing_published_means_nothing_verified() {
    let w = world();
    let ada = person(&w.hub);
    let auth = bearer(&w, &ada, "laptop").await;
    let r = verify(&w, &auth, "example.com", None).await;
    assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY, "{}", r.text());
    assert_eq!(r.json()["error"], "verification_failed");
    let checked = r.json()["checked"].as_array().unwrap().clone();
    assert_eq!(checked.iter().map(|c| c["method"].as_str().unwrap()).collect::<Vec<_>>(), ["txt", "cname", "html"], "every method was tried and says why it failed");
    assert!(checked.iter().all(|c| c["ok"] == false && c["why"].is_string()));
    assert!(call(&w.app, "GET", "/v1/contacts", Some(&auth), None).await.json()["contacts"].as_array().unwrap().is_empty());
    assert_eq!(lookup(&w, EXAMPLE).await.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn each_method_alone_proves_the_domain() {
    for (method, publish) in [("txt", publish_txt as fn(&World, &str, &str)), ("cname", publish_cname), ("html", publish_html)] {
        let w = world();
        let ada = person(&w.hub);
        let auth = bearer(&w, &ada, "laptop").await;
        publish(&w, "example.com", &ada.st.did);
        // Naming a different method finds nothing.
        let other = if method == "txt" { "html" } else { "txt" };
        assert_eq!(verify(&w, &auth, "example.com", Some(other)).await.status, StatusCode::UNPROCESSABLE_ENTITY, "{method} published, {other} asked");
        let r = verify(&w, &auth, "example.com", Some(method)).await;
        assert_eq!(r.status, StatusCode::OK, "{method}: {}", r.text());
        let j = r.json();
        assert_eq!((j["address"].as_str(), j["kind"].as_str(), j["method"].as_str()), (Some(EXAMPLE), Some("domain"), Some(method)));
        assert_eq!((j["public"].clone(), j["fresh"].clone()), (json!(false), json!(true)), "private by default");
        // And without naming one, whichever is there is found.
        let r = verify(&w, &auth, "dns:EXAMPLE.com", None).await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.text());
        assert_eq!(r.json()["method"], method);
    }
}

#[tokio::test]
async fn a_record_that_names_someone_else_proves_nothing() {
    let w = world();
    let ada = person(&w.hub);
    let bob = person(&w.hub);
    let auth = bearer(&w, &ada, "laptop").await;
    // Bob's proofs are all there; Ada's are not.
    publish_txt(&w, "example.com", &bob.st.did);
    publish_cname(&w, "example.com", &bob.st.did);
    publish_html(&w, "example.com", &bob.st.did);
    // A longer DID that begins with Ada's, in a TXT record and in a page at Ada's path.
    w.net.txt("_kith-challenge.example.com", &format!("{}x", domain::value(&ada.st.did)));
    w.net.file("example.com", &domain::html_path(&ada.st.did), &format!("{}x", domain::value(&ada.st.did)));
    // A page that merely echoes the path (a soft 404) proves nothing either.
    w.net.file("example.org", &domain::html_path(&ada.st.did), &format!("not found: {}", domain::html_path(&ada.st.did)));
    for d in ["example.com", "example.org"] {
        assert_eq!(verify(&w, &auth, d, None).await.status, StatusCode::UNPROCESSABLE_ENTITY, "{d}");
    }
    assert_eq!(witness(&w, "example.com", &ada.st.did).await.status, StatusCode::UNPROCESSABLE_ENTITY);
    // Bob can, with his own.
    let bauth = bearer(&w, &bob, "laptop").await;
    assert_eq!(verify(&w, &bauth, "example.com", None).await.status, StatusCode::OK);
}

#[tokio::test]
async fn an_operator_can_allow_only_some_methods() {
    let w = world_with(|c| c.domains.methods = vec![Method::Txt, Method::Cname]);
    let ada = person(&w.hub);
    let auth = bearer(&w, &ada, "laptop").await;
    publish_html(&w, "example.com", &ada.st.did);
    assert_eq!(verify(&w, &auth, "example.com", None).await.status, StatusCode::UNPROCESSABLE_ENTITY, "a page proves nothing here");
    assert_eq!(verify(&w, &auth, "example.com", Some("html")).await.status, StatusCode::BAD_REQUEST);
    assert!(!w.net.lookups.lock().unwrap().iter().any(|l| l.starts_with("get ")), "no page was fetched");
    let r = call(&w.app, "POST", "/v1/domains", Some(&auth), Some(json!({"domain": "example.com"}))).await.json();
    assert!(r["methods"].get("html").is_none() && r["methods"].get("txt").is_some());
    publish_txt(&w, "example.com", &ada.st.did);
    assert_eq!(verify(&w, &auth, "example.com", None).await.status, StatusCode::OK);
}

#[tokio::test]
async fn a_verified_domain_is_published_with_a_signed_attestation() {
    let w = world();
    let ada = person(&w.hub);
    let laptop = bearer(&w, &ada, "laptop").await;
    let tablet = bearer(&w, &ada, "tablet").await;
    publish_txt(&w, "example.com", &ada.st.did);
    let verified = verify(&w, &laptop, "example.com", None).await.json();

    // Private until published, and publishing takes the alias cap.
    assert_eq!(lookup(&w, EXAMPLE).await.status, StatusCode::NOT_FOUND);
    assert_eq!(set_public(&w, &tablet, true).await.status, StatusCode::FORBIDDEN);
    assert_eq!(set_public(&w, &laptop, true).await.status, StatusCode::OK);

    let r = lookup(&w, EXAMPLE).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    let j = r.json();
    assert_eq!((j["address"].as_str(), j["did"].as_str()), (Some(EXAMPLE), Some(ada.st.did.as_str())));
    let att = verify_account_attestation(j["attestation"].as_str().unwrap(), &w.hub.jwks(), ISSUER, PUBLIC_AUDIENCE, kith_core::util::now()).unwrap();
    assert_eq!((att.provider.as_str(), att.account.as_str(), att.sub.as_str()), ("domain", EXAMPLE, ada.st.did.as_str()));
    assert_eq!(att.verified_at, verified["verified_at"].as_i64().unwrap());

    // Withdrawing ends it, and forgetting removes it.
    assert_eq!(set_public(&w, &laptop, false).await.status, StatusCode::OK);
    assert_eq!(lookup(&w, EXAMPLE).await.status, StatusCode::NOT_FOUND);
    let gone = call(&w.app, "DELETE", "/v1/contacts", Some(&laptop), Some(json!({"address": EXAMPLE}))).await;
    assert_eq!(gone.json()["removed"], true);
}

#[tokio::test]
async fn proving_a_domain_last_takes_it_and_its_publicity() {
    let w = world();
    let ada = person(&w.hub);
    let bob = person(&w.hub);
    let (a, b) = (bearer(&w, &ada, "laptop").await, bearer(&w, &bob, "laptop").await);
    publish_txt(&w, "example.com", &ada.st.did);
    verify(&w, &a, "example.com", None).await;
    call(&w.app, "PUT", "/v1/contacts/public", Some(&a), Some(json!({"address": EXAMPLE, "public": true}))).await;
    assert_eq!(lookup(&w, EXAMPLE).await.json()["did"], ada.st.did);

    // The domain changes hands: the new owner publishes Bob's record and proves it.
    publish_txt(&w, "example.com", &bob.st.did);
    assert_eq!(verify(&w, &b, "example.com", None).await.status, StatusCode::OK);
    assert_eq!(lookup(&w, EXAMPLE).await.status, StatusCode::NOT_FOUND, "Bob has not published it, and Ada's publication does not carry over");
    let ada_contacts = call(&w.app, "GET", "/v1/contacts", Some(&a), None).await.json();
    assert!(ada_contacts["contacts"].as_array().unwrap().is_empty(), "Ada no longer holds it");
}

#[tokio::test]
async fn an_app_gets_the_domain_only_with_the_domain_scope() {
    let w = world();
    let ada = person(&w.hub);
    let auth = bearer(&w, &ada, "laptop").await;
    publish_txt(&w, "example.com", &ada.st.did);
    publish_txt(&w, "example.net", &ada.st.did);
    verify(&w, &auth, "example.com", None).await;
    verify(&w, &auth, "example.net", None).await;
    let t = sign_in(&w, &ada, "openid email phone").await;
    assert!(t.get("contact_attestations").is_none(), "the email and phone scopes do not release domains");
    let t = sign_in(&w, &ada, "openid domain").await;
    let mut atts: Vec<_> = attestations(&w, &t).into_iter().map(|a| (a.provider, a.account, a.sub)).collect();
    atts.sort();
    assert_eq!(atts, [("domain".into(), "dns:example.com".into(), ada.st.did.clone()), ("domain".into(), "dns:example.net".into(), ada.st.did.clone())]);
    assert!(!kith_core::jws::decode(t["access_token"].as_str().unwrap()).unwrap().claims.to_string().contains("example.com"), "never in an access token");
}

#[tokio::test]
async fn a_stale_domain_is_kept_but_not_attested_until_checked_again() {
    let w = world_with(|c| c.domains.max_age = 1);
    let ada = person(&w.hub);
    let auth = bearer(&w, &ada, "laptop").await;
    publish_txt(&w, "example.com", &ada.st.did);
    verify(&w, &auth, "example.com", None).await;
    call(&w.app, "PUT", "/v1/contacts/public", Some(&auth), Some(json!({"address": EXAMPLE, "public": true}))).await;
    tokio::time::sleep(std::time::Duration::from_millis(2100)).await;
    assert_eq!(lookup(&w, EXAMPLE).await.status, StatusCode::NOT_FOUND, "stale: not looked up");
    let listed = call(&w.app, "GET", "/v1/contacts", Some(&auth), None).await.json();
    assert_eq!(listed["contacts"][0]["fresh"], false);
    // The DNS record is still there, so checking again makes it fresh.
    assert_eq!(verify(&w, &auth, "example.com", None).await.status, StatusCode::OK);
    let listed = call(&w.app, "GET", "/v1/contacts", Some(&auth), None).await.json();
    assert_eq!((listed["contacts"][0]["fresh"].clone(), listed["contacts"][0]["public"].clone()), (json!(true), json!(true)), "the same holder keeps their publication");
}

#[tokio::test]
async fn a_record_that_is_taken_down_stops_the_next_check() {
    let w = world();
    let ada = person(&w.hub);
    let auth = bearer(&w, &ada, "laptop").await;
    publish_txt(&w, "example.com", &ada.st.did);
    assert_eq!(verify(&w, &auth, "example.com", None).await.status, StatusCode::OK);
    w.net.txt.lock().unwrap().clear();
    assert_eq!(verify(&w, &auth, "example.com", None).await.status, StatusCode::UNPROCESSABLE_ENTITY);
}

/// Anyone running a hub can look for themselves and sign what they saw: the DID need not
/// have an account there, and it may be an org's.
#[tokio::test]
async fn any_hub_can_witness_a_domain_for_any_did() {
    let w = world();
    let acme = "did:kith:acme-org";
    assert_eq!(witness(&w, "example.com", acme).await.status, StatusCode::UNPROCESSABLE_ENTITY, "nothing published yet");

    publish_cname(&w, "example.com", acme);
    let r = witness(&w, "dns:Example.com", acme).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    let j = r.json();
    assert_eq!((j["domain"].as_str(), j["did"].as_str(), j["method"].as_str()), (Some(EXAMPLE), Some(acme), Some("cname")));
    let att = verify_account_attestation(j["attestation"].as_str().unwrap(), &w.hub.jwks(), ISSUER, PUBLIC_AUDIENCE, kith_core::util::now()).unwrap();
    assert_eq!((att.provider.as_str(), att.provider_iss.as_str(), att.account.as_str(), att.sub.as_str()), ("domain", ISSUER, EXAMPLE, acme));
    assert!((kith_core::util::now() - att.verified_at).abs() <= 2, "it says when this hub looked");
    assert!(att.exp - att.iat <= 3600, "a witness statement is short-lived: look again, don't keep copies");

    // Nothing was stored: the hub remembers no one's domain from a witness call.
    assert_eq!(lookup(&w, EXAMPLE).await.status, StatusCode::NOT_FOUND);

    // A second hub sees the same records and signs on its own key.
    let other = world();
    other.net.cname.lock().unwrap().clone_from(&w.net.cname.lock().unwrap());
    let r2 = witness(&other, "example.com", acme).await;
    assert_eq!(r2.status, StatusCode::OK);
    assert_ne!(other.hub.jwks().to_string(), w.hub.jwks().to_string(), "different hubs, different keys");
    assert!(verify_account_attestation(r2.json()["attestation"].as_str().unwrap(), &w.hub.jwks(), ISSUER, PUBLIC_AUDIENCE, kith_core::util::now()).is_err(), "each is checked against its own hub's keys");

    // Garbage in is refused before anything is looked up.
    let before = w.net.lookups();
    for (d, did) in [("localhost", acme), ("example.com", "not-a-did"), ("example.com", "did:kith:a\"b"), ("example.com", "")] {
        assert_eq!(witness(&w, d, did).await.status, StatusCode::BAD_REQUEST, "{d} {did}");
    }
    assert_eq!(w.net.lookups(), before);
}

#[tokio::test]
async fn checking_a_domain_is_rate_limited() {
    let w = world_with(|c| c.domains.verify_limit = kith_hub::RateLimit { max: 3, window_secs: 3600 });
    let ada = person(&w.hub);
    let auth = bearer(&w, &ada, "laptop").await;
    for _ in 0..3 {
        assert_eq!(verify(&w, &auth, "example.com", None).await.status, StatusCode::UNPROCESSABLE_ENTITY);
    }
    let r = verify(&w, &auth, "example.com", None).await;
    assert_eq!(r.status, StatusCode::TOO_MANY_REQUESTS, "{}", r.text());
    // The witness endpoint has its own bucket, per client address.
    for _ in 0..3 {
        assert_eq!(witness(&w, "example.com", "did:kith:acme-org").await.status, StatusCode::UNPROCESSABLE_ENTITY);
    }
    assert_eq!(witness(&w, "example.com", "did:kith:acme-org").await.status, StatusCode::TOO_MANY_REQUESTS);
    let calls = w.net.lookups();
    let _ = verify(&w, &auth, "example.com", None).await;
    assert_eq!(w.net.lookups(), calls, "a limited call looks nothing up");
}

#[tokio::test]
async fn domains_cannot_be_proved_with_a_code() {
    let w = world();
    let ada = person(&w.hub);
    let auth = bearer(&w, &ada, "laptop").await;
    let r = call(&w.app, "POST", "/v1/contacts", Some(&auth), Some(json!({"address": EXAMPLE}))).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST, "{}", r.text());
    assert!(r.text().contains("/v1/domains"), "it says where to go: {}", r.text());
}
