//! End-to-end OpenID Connect tests against the hub router (in process), using real
//! WebAuthn assertions from the software authenticator.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{header, HeaderMap, Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use rsa::pkcs1v15::{Signature, VerifyingKey};
use rsa::signature::Verifier;
use rsa::{BigUint, RsaPublicKey};
use serde_json::{json, Value};
use sha2::Sha256;
use tower::ServiceExt;

use kith_core::kel::{new_inception, next_event, verify_log, Device, DeviceKind, EventBody, KeyState};
use kith_core::keys::{KeyType, LocalSigner, PublicKey, VerifyOptions};
use kith_core::policy::SignerPolicy;
use kith_core::session::{DeviceSigner, SessionKey};
use kith_core::util::{b64u, b64u_decode, now, sha256};
use kith_core::{jws, totp, webauthn};
use kith_hub::oidc::{Client, Consent, SubjectType, BACKCHANNEL_LOGOUT_EVENT};
use kith_hub::jwe;
use kith_hub::{Hub, HubConfig, RateLimit, TT_SESSION};

const ISSUER: &str = "http://localhost:7777";
const ORIGIN: &str = "http://localhost:7777";
const APP_CB: &str = "http://localhost:3000/cb";
const PW_CB: &str = "https://pw.example/cb";

struct World {
    dir: std::path::PathBuf,
    cfg: HubConfig,
    app: Router,
    hub: Arc<Hub>,
    root: LocalSigner,
    passkey: LocalSigner,
    laptop: LocalSigner,
    st: KeyState,
    log: Vec<kith_core::kel::Event>,
}

fn device(id: &str, key: &LocalSigner, kind: DeviceKind, aal: u8) -> Device {
    Device {
        id: id.into(),
        key: key.id.clone(),
        name: id.into(),
        kind,
        aal,
        caps: vec!["session".into()],
        rp_id: (kind == DeviceKind::Passkey).then(|| "localhost".into()),
        xkey: None,
    }
}

fn world() -> World {
    world_with(|_| {})
}

/// A hub with one identity and the two standard clients; `configure` can add more.
fn world_with(configure: impl FnOnce(&mut HubConfig)) -> World {
    let dir = std::env::temp_dir().join(format!("kith-oidc-{}", kith_core::util::random_id()));
    let root = LocalSigner::generate(KeyType::Ed25519);
    let passkey = LocalSigner::generate(KeyType::P256);
    let laptop = LocalSigner::generate(KeyType::Ed25519);
    let next = SignerPolicy::single(LocalSigner::generate(KeyType::Ed25519).id);
    let mut inc = new_inception(
        SignerPolicy::single(&root.id),
        &next,
        vec![device("phone", &passkey, DeviceKind::Passkey, 2), device("laptop", &laptop, DeviceKind::Software, 1)],
    );
    inc.sign(&root).unwrap();
    let msg = inc.signing_message().unwrap();
    inc.add_sig(webauthn::soft_sign_message(&passkey, "localhost", ORIGIN, &msg).unwrap());
    inc.sign(&laptop).unwrap();
    let log = vec![inc];
    let st = verify_log(&log, &VerifyOptions::default()).unwrap();

    std::fs::create_dir_all(&dir).unwrap();
    let bundle = json!({
        "version": 1,
        "groups": {
            "staff": {"rule": "principal has email && principal.email like \"*@acme.test\""},
            "strong": {"rule": "principal.aal >= 2"}
        },
        "roles": {"admin": {"members": ["group:strong"]}},
        "directory": {(st.did.clone()): {"attrs": {"email": "ada@acme.test", "name": "Ada"}}},
        "policies": ""
    });
    std::fs::write(dir.join("bundle.json"), bundle.to_string()).unwrap();

    let mut cfg = HubConfig::new(ISSUER, dir.join("data"));
    cfg.bundle_path = Some(dir.join("bundle.json"));
    cfg.clients = vec![
        Client {
            client_id: "app".into(),
            client_secret: None,
            redirect_uris: vec![APP_CB.into()],
            name: Some("Demo App".into()),
            audience: Some("api://demo".into()),
            post_logout_redirect_uris: vec!["http://localhost:3000/".into()],
            consent: Consent::Implied,
            ..Default::default()
        },
        // The same app, but the user is asked before anything is shared.
        Client { client_id: "ask".into(), redirect_uris: vec![APP_CB.into()], name: Some("Asking App".into()), ..Default::default() },
        Client {
            client_id: "pw".into(),
            client_secret: Some("s3cret".into()),
            redirect_uris: vec![PW_CB.into()],
            name: None,
            audience: None,
            subject_type: SubjectType::Pairwise,
            id_token_signed_response_alg: "EdDSA".into(),
            consent: Consent::Implied,
            ..Default::default()
        },
    ];
    configure(&mut cfg);
    let hub = Hub::open(cfg.clone()).unwrap();
    hub.put_kel(&st.did, log.clone()).unwrap();
    World { dir, cfg, app: kith_hub::router(hub.clone()), hub, root, passkey, laptop, st, log }
}

impl World {
    /// Open the same data directory again, as a restart of the hub process would.
    fn restart(&mut self) {
        self.hub = Hub::open(self.cfg.clone()).unwrap();
        self.app = kith_hub::router(self.hub.clone());
    }
}

struct Resp {
    status: StatusCode,
    headers: HeaderMap,
    body: Vec<u8>,
}

impl Resp {
    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or(Value::Null)
    }
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
    fn location(&self) -> String {
        self.headers[header::LOCATION].to_str().unwrap().to_string()
    }
    fn cookie(&self) -> Option<String> {
        self.headers.get(header::SET_COOKIE).map(|v| v.to_str().unwrap().split(';').next().unwrap().to_string())
    }
}

async fn send(app: &Router, req: Request<Body>) -> Resp {
    let r = app.clone().oneshot(req).await.unwrap();
    let status = r.status();
    let headers = r.headers().clone();
    let body = r.into_body().collect().await.unwrap().to_bytes().to_vec();
    Resp { status, headers, body }
}

async fn get(app: &Router, uri: &str, cookie: Option<&str>) -> Resp {
    let mut b = Request::get(uri);
    if let Some(c) = cookie {
        b = b.header(header::COOKIE, c);
    }
    send(app, b.body(Body::empty()).unwrap()).await
}

async fn post_json(app: &Router, uri: &str, body: Value) -> Resp {
    post_json_with(app, uri, body, &[]).await
}

async fn post_json_with(app: &Router, uri: &str, body: Value, headers: &[(header::HeaderName, &str)]) -> Resp {
    let mut b = Request::post(uri).header(header::CONTENT_TYPE, "application/json");
    for (k, v) in headers {
        b = b.header(k, *v);
    }
    send(app, b.body(Body::from(body.to_string())).unwrap()).await
}

async fn post_form(app: &Router, uri: &str, form: &[(&str, &str)], basic: Option<&str>) -> Resp {
    let body = form.iter().map(|(k, v)| format!("{k}={}", enc(v))).collect::<Vec<_>>().join("&");
    let mut b = Request::post(uri).header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
    if let Some(basic) = basic {
        use base64::Engine;
        b = b.header(header::AUTHORIZATION, format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(basic)));
    }
    send(app, b.body(Body::from(body)).unwrap()).await
}

/// Any request: method, headers, the client address the server would see, a JSON body.
async fn call(app: &Router, method: &str, uri: &str, headers: &[(header::HeaderName, &str)], ip: Option<&str>, body: Option<Value>) -> Resp {
    let mut b = Request::builder().method(method).uri(uri);
    for (k, v) in headers {
        b = b.header(k, *v);
    }
    if let Some(ip) = ip {
        b = b.extension(ConnectInfo(SocketAddr::new(ip.parse().unwrap(), 4000)));
    }
    let body = match body {
        Some(v) => {
            b = b.header(header::CONTENT_TYPE, "application/json");
            Body::from(v.to_string())
        }
        None => Body::empty(),
    };
    send(app, b.body(body).unwrap()).await
}

/// A hub (aud = issuer) access token, the way the CLI gets one: a session chain
/// from a device key, exchanged at the token endpoint.
async fn hub_bearer(w: &World, device: &str, key: &LocalSigner) -> String {
    let dev = w.st.device(device).unwrap().clone();
    let sk = SessionKey::create(&w.st.did, &dev, DeviceSigner::Key(&key.secret), 3600).unwrap();
    let st_tok = sk.session_token(ISSUER, json!({})).unwrap();
    let tok = post_form(&w.app, "/oauth/token", &[("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange"), ("subject_token", &st_tok), ("subject_token_type", TT_SESSION)], None).await.json();
    format!("Bearer {}", tok["access_token"].as_str().expect("access token"))
}

fn enc(s: &str) -> String {
    s.bytes()
        .map(|b| if b.is_ascii_alphanumeric() || b"-._~".contains(&b) { (b as char).to_string() } else { format!("%{b:02X}") })
        .collect()
}

fn query(url: &str) -> HashMap<String, String> {
    url.split_once('?')
        .map(|(_, q)| q)
        .unwrap_or_default()
        .split('&')
        .filter_map(|kv| kv.split_once('='))
        .map(|(k, v)| (k.to_string(), v.replace("%3A", ":").replace("%2F", "/").replace("%20", " ")))
        .collect()
}

fn page_data(html: &str) -> Value {
    let start = html.find(r#"<script id="kith-data" type="application/json">"#).unwrap() + 47;
    let end = start + html[start..].find("</script>").unwrap();
    serde_json::from_str(&html[start..end]).unwrap()
}

fn pkce() -> (String, String) {
    let verifier = format!("{}{}", kith_core::util::random_id(), kith_core::util::random_id());
    let challenge = b64u(sha256(verifier.as_bytes()));
    (verifier, challenge)
}

fn authorize_url(client: &str, cb: &str, challenge: &str, extra: &str) -> String {
    authorize_scoped(client, cb, challenge, "openid profile email groups offline_access", extra)
}

fn authorize_scoped(client: &str, cb: &str, challenge: &str, scope: &str, extra: &str) -> String {
    format!(
        "/oauth/authorize?response_type=code&client_id={client}&redirect_uri={}&scope={}&state=st8&nonce=n0nce&code_challenge={challenge}&code_challenge_method=S256{extra}",
        enc(cb),
        enc(scope)
    )
}

async fn redeem(w: &World, client: &str, redirect: &str, verifier: &str, basic: Option<&str>) -> Value {
    let code = query(redirect)["code"].clone();
    let mut form = vec![("grant_type", "authorization_code"), ("code", code.as_str()), ("redirect_uri", APP_CB), ("code_verifier", verifier)];
    if basic.is_none() {
        form.push(("client_id", client));
    }
    let r = post_form(&w.app, "/oauth/token", &form, basic).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    r.json()
}

/// Answer the login page's challenge with the passkey (username-less: no device id).
fn passkey_factor(passkey: &LocalSigner, message: &str, origin: &str) -> Value {
    let (data, sig) = webauthn::soft_assert(&passkey.secret, "localhost", origin, &sha256(message.as_bytes()), true, 1).unwrap();
    json!({"type": "webauthn", "authenticator_data": data.authenticator_data, "client_data_json": data.client_data_json, "signature": b64u(sig)})
}

async fn login_with_passkey(w: &World, page: &Resp, passkey: &LocalSigner) -> Resp {
    let d = page_data(&page.text());
    post_json(
        &w.app,
        "/oauth/login",
        json!({"request_id": d["request_id"], "challenge_id": d["challenge_id"], "did": w.st.did, "factors": [passkey_factor(passkey, d["message"].as_str().unwrap(), ORIGIN)]}),
    )
    .await
}

fn verify_rs256(jwks: &Value, token: &str) -> Value {
    let t = jws::decode(token).unwrap();
    assert_eq!(t.header["alg"], "RS256");
    let k = jwks["keys"].as_array().unwrap().iter().find(|k| k["kid"] == t.header["kid"]).unwrap();
    let n = BigUint::from_bytes_be(&b64u_decode(k["n"].as_str().unwrap()).unwrap());
    let e = BigUint::from_bytes_be(&b64u_decode(k["e"].as_str().unwrap()).unwrap());
    let vk = VerifyingKey::<Sha256>::new(RsaPublicKey::new(n, e).unwrap());
    vk.verify(t.signing_input.as_bytes(), &Signature::try_from(t.signature.as_slice()).unwrap()).unwrap();
    t.claims
}

#[tokio::test]
async fn discovery_advertises_oidc() {
    let w = world();
    let d = get(&w.app, "/.well-known/openid-configuration", None).await.json();
    assert_eq!(d["issuer"], ISSUER);
    assert_eq!(d["authorization_endpoint"], format!("{ISSUER}/oauth/authorize"));
    assert_eq!(d["code_challenge_methods_supported"], json!(["S256"]));
    let jwks = get(&w.app, "/.well-known/jwks.json", None).await.json();
    let kinds: Vec<&str> = jwks["keys"].as_array().unwrap().iter().map(|k| k["kty"].as_str().unwrap()).collect();
    assert_eq!(kinds, vec!["OKP", "RSA"]);
}

#[tokio::test]
async fn code_flow_sso_refresh_and_revocation() {
    let w = world();
    let jwks = get(&w.app, "/.well-known/jwks.json", None).await.json();

    // 1. authorize → login page (with a strict CSP)
    let (verifier, challenge) = pkce();
    let page = get(&w.app, &authorize_url("app", APP_CB, &challenge, ""), None).await;
    assert_eq!(page.status, StatusCode::OK);
    assert!(page.headers[header::CONTENT_SECURITY_POLICY].to_str().unwrap().contains("script-src 'nonce-"));
    let d = page_data(&page.text());
    assert_eq!(d["client_name"], "Demo App");

    // 2. username-less passkey login → redirect with code, SSO cookie
    let r = login_with_passkey(&w, &page, &w.passkey).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    let cookie = r.cookie().expect("session cookie");
    let redirect = r.json()["redirect"].as_str().unwrap().to_string();
    assert!(redirect.starts_with(APP_CB));
    let q = query(&redirect);
    assert_eq!(q["state"], "st8");
    assert_eq!(q["iss"], ISSUER);

    // 3. token: wrong verifier fails and burns nothing else; right verifier succeeds once
    let code = q["code"].clone();
    let bad = post_form(&w.app, "/oauth/token", &[("grant_type", "authorization_code"), ("code", &code), ("redirect_uri", APP_CB), ("code_verifier", "wrong"), ("client_id", "app")], None).await;
    assert_eq!(bad.json()["error"], "invalid_grant");

    let page = get(&w.app, &authorize_url("app", APP_CB, &challenge, ""), Some(&cookie)).await;
    assert_eq!(page.status, StatusCode::SEE_OTHER, "SSO: no login page the second time");
    let code = query(&page.location())["code"].clone();
    let tok = post_form(&w.app, "/oauth/token", &[("grant_type", "authorization_code"), ("code", &code), ("redirect_uri", APP_CB), ("code_verifier", &verifier), ("client_id", "app")], None).await;
    assert_eq!(tok.status, StatusCode::OK, "{}", tok.text());
    assert_eq!(tok.headers[header::CACHE_CONTROL], "no-store");
    let tok = tok.json();
    let replay = post_form(&w.app, "/oauth/token", &[("grant_type", "authorization_code"), ("code", &code), ("redirect_uri", APP_CB), ("code_verifier", &verifier), ("client_id", "app")], None).await;
    assert_eq!(replay.json()["error"], "invalid_grant", "codes are single use");

    // 4. ID token: RS256, audience, nonce, assurance, scoped claims
    let id = verify_rs256(&jwks, tok["id_token"].as_str().unwrap());
    assert_eq!(id["iss"], ISSUER);
    assert_eq!(id["aud"], "app");
    assert_eq!(id["sub"], w.st.did);
    assert_eq!(id["nonce"], "n0nce");
    assert_eq!(id["acr"], "urn:kith:acr:aal2");
    assert_eq!(id["email"], "ada@acme.test");
    assert_eq!(id["name"], "Ada");
    assert_eq!(id["groups"], json!(["staff", "strong"]));
    assert_eq!(id["roles"], json!(["admin"]));

    // 5. access token: RFC 9068, for the client's API audience
    let at = kith_core::token::verify_access_token(tok["access_token"].as_str().unwrap(), &jwks, ISSUER, "api://demo", kith_core::util::now()).unwrap();
    assert_eq!(at.client_id.as_deref(), Some("app"));
    assert_eq!(at.dev.as_deref(), Some("phone"));

    // 6. userinfo
    let ui = send(&w.app, Request::get("/oauth/userinfo").header(header::AUTHORIZATION, format!("Bearer {}", tok["access_token"].as_str().unwrap())).body(Body::empty()).unwrap()).await;
    assert_eq!(ui.json()["email"], "ada@acme.test");

    // 7. refresh rotates; the old refresh token is dead
    let rt = tok["refresh_token"].as_str().unwrap().to_string();
    let r2 = post_form(&w.app, "/oauth/token", &[("grant_type", "refresh_token"), ("refresh_token", &rt), ("client_id", "app")], None).await.json();
    assert!(r2["access_token"].is_string() && r2["refresh_token"].is_string());
    let again = post_form(&w.app, "/oauth/token", &[("grant_type", "refresh_token"), ("refresh_token", &rt), ("client_id", "app")], None).await;
    assert_eq!(again.json()["error"], "invalid_grant");

    // 8. revoke the phone in the KEL: refresh and SSO both stop working
    let mut ev = next_event(&w.st, EventBody::RevokeDevice { device_id: "phone".into(), reason: Some("lost".into()) });
    ev.sign(&w.root).unwrap();
    let mut log = w.log.clone();
    log.push(ev);
    w.hub.put_kel(&w.st.did, log).unwrap();
    let dead = post_form(&w.app, "/oauth/token", &[("grant_type", "refresh_token"), ("refresh_token", r2["refresh_token"].as_str().unwrap()), ("client_id", "app")], None).await;
    assert!(dead.json()["error_description"].as_str().unwrap().contains("revoked"));
    let page = get(&w.app, &authorize_url("app", APP_CB, &challenge, ""), Some(&cookie)).await;
    assert_eq!(page.status, StatusCode::OK, "revoked device's SSO session is not reused");
}

#[tokio::test]
async fn prompt_none_step_up_and_errors() {
    let w = world();
    let (_, challenge) = pkce();

    let r = get(&w.app, &authorize_url("app", APP_CB, &challenge, "&prompt=none"), None).await;
    assert_eq!(query(&r.location())["error"], "login_required");

    let r = get(&w.app, "/oauth/authorize?response_type=code&client_id=app&redirect_uri=http%3A%2F%2Fevil.example%2Fcb&scope=openid&code_challenge=x&code_challenge_method=S256", None).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST, "unregistered redirect_uri never redirects");

    let r = get(&w.app, "/oauth/authorize?response_type=code&client_id=app&redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fcb&scope=openid&state=s", None).await;
    assert_eq!(query(&r.location())["error"], "invalid_request", "PKCE is mandatory");

    // acr_values aal3: the AAL2 passkey is not enough → step_up_required with a fresh challenge
    let page = get(&w.app, &authorize_url("app", APP_CB, &challenge, "&acr_values=urn%3Akith%3Aacr%3Aaal3"), None).await;
    assert_eq!(page_data(&page.text())["min_aal"], 3);
    let r = login_with_passkey(&w, &page, &w.passkey).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    let j = r.json();
    assert_eq!(j["error"], "step_up_required");
    assert_eq!((j["aal"].as_u64(), j["required_aal"].as_u64()), (Some(2), Some(3)));
    assert!(j["challenge_id"].is_string() && j["message"].is_string());

    // A passkey that isn't this identity's is rejected (and gets a retry challenge).
    let page = get(&w.app, &authorize_url("app", APP_CB, &challenge, ""), None).await;
    let r = login_with_passkey(&w, &page, &LocalSigner::generate(KeyType::P256)).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    assert!(r.json()["challenge_id"].is_string());

    // Wrong origin (phishing site relaying the challenge) is rejected.
    let d = page_data(&page.text());
    let evil = post_json(&w.app, "/oauth/login", json!({"request_id": d["request_id"], "challenge_id": r.json()["challenge_id"], "did": w.st.did, "factors": [passkey_factor(&w.passkey, r.json()["message"].as_str().unwrap(), "https://evil.example")]})).await;
    assert_eq!(evil.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn pairwise_confidential_client() {
    let w = world();
    let jwks = get(&w.app, "/.well-known/jwks.json", None).await.json();
    let mut subs = vec![];
    for _ in 0..2 {
        let (verifier, challenge) = pkce();
        let page = get(&w.app, &authorize_url("pw", PW_CB, &challenge, ""), None).await;
        let r = login_with_passkey(&w, &page, &w.passkey).await;
        let code = query(r.json()["redirect"].as_str().unwrap())["code"].clone();
        let form = [("grant_type", "authorization_code"), ("code", code.as_str()), ("redirect_uri", PW_CB), ("code_verifier", verifier.as_str())];
        assert_eq!(post_form(&w.app, "/oauth/token", &form, Some("pw:wrong")).await.status, StatusCode::UNAUTHORIZED);
        let tok = post_form(&w.app, "/oauth/token", &form, Some("pw:s3cret")).await.json();
        let t = jws::decode(tok["id_token"].as_str().unwrap()).unwrap();
        assert_eq!(t.header["alg"], "EdDSA");
        let ed = jwks["keys"].as_array().unwrap().iter().find(|k| k["kid"] == t.header["kid"]).unwrap();
        jws::verify(&t, &PublicKey::from_jwk(ed).unwrap()).unwrap();
        assert_ne!(t.claims["sub"], w.st.did, "pairwise subject hides the DID");
        let at = jws::decode(tok["access_token"].as_str().unwrap()).unwrap();
        assert_eq!(at.claims["sub"], t.claims["sub"]);
        assert!(at.claims["attrs"].get("aliases").is_none());
        subs.push(t.claims["sub"].clone());
    }
    assert_eq!(subs[0], subs[1], "pairwise subject is stable per client");
}

#[tokio::test]
async fn browser_passkey_enrollment() {
    let w = world();
    // The CLI authenticates to the hub with its session chain.
    let dev = w.st.device("laptop").unwrap().clone();
    let sk = SessionKey::create(&w.st.did, &dev, DeviceSigner::Key(&w.laptop.secret), 3600).unwrap();
    let st_tok = sk.session_token(ISSUER, json!({})).unwrap();
    let tok = post_form(&w.app, "/oauth/token", &[("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange"), ("subject_token", &st_tok), ("subject_token_type", TT_SESSION)], None).await.json();
    let bearer = format!("Bearer {}", tok["access_token"].as_str().unwrap());

    let start = send(&w.app, Request::post("/v1/enroll").header(header::AUTHORIZATION, &bearer).header(header::CONTENT_TYPE, "application/json").body(Body::from(r#"{"name":"yubikey"}"#)).unwrap()).await.json();
    let id = start["id"].as_str().unwrap().to_string();
    assert_eq!(start["url"], format!("{ISSUER}/enroll/{id}"));
    let page = get(&w.app, &format!("/enroll/{id}"), None).await;
    assert_eq!(page_data(&page.text())["did"], w.st.did);

    // Browser: create passkey, submit key.
    let new_pk = LocalSigner::generate(KeyType::P256);
    post_json(&w.app, &format!("/v1/enroll/{id}/key"), json!({"key": new_pk.id, "credential_id": "cred1"})).await;

    // CLI: build and sign add_device, hand the message to the browser.
    let device = Device { id: "dev_yk".into(), key: new_pk.id.clone(), name: "yubikey".into(), kind: DeviceKind::Passkey, aal: 2, caps: vec!["session".into()], rp_id: Some("localhost".into()), xkey: None };
    let mut ev = next_event(&w.st, EventBody::AddDevice { device });
    ev.sign(&w.root).unwrap();
    let message = String::from_utf8(ev.signing_message().unwrap()).unwrap();
    let r = send(&w.app, Request::post(format!("/v1/enroll/{id}/event")).header(header::AUTHORIZATION, &bearer).header(header::CONTENT_TYPE, "application/json").body(Body::from(json!({"device_id": "dev_yk", "message": message}).to_string())).unwrap()).await;
    assert_eq!(r.json()["state"], "waiting_for_signature");

    // Browser: a signature from a different key is refused; the real one is accepted.
    let wrong = webauthn::soft_sign_message(&LocalSigner::generate(KeyType::P256), "localhost", ORIGIN, message.as_bytes()).unwrap();
    assert_eq!(post_json(&w.app, &format!("/v1/enroll/{id}/sig"), json!({"sig": wrong})).await.status, StatusCode::BAD_REQUEST);
    let pop = webauthn::soft_sign_message(&new_pk, "localhost", ORIGIN, message.as_bytes()).unwrap();
    assert_eq!(post_json(&w.app, &format!("/v1/enroll/{id}/sig"), json!({"sig": pop})).await.json()["state"], "signed");

    // CLI: append and publish; the new passkey can now sign in through OIDC.
    let status = get(&w.app, &format!("/v1/enroll/{id}"), None).await.json();
    ev.add_sig(serde_json::from_value(status["sig"].clone()).unwrap());
    let mut log = w.log.clone();
    log.push(ev);
    w.hub.put_kel(&w.st.did, log).unwrap();
    let (_, challenge) = pkce();
    let page = get(&w.app, &authorize_url("app", APP_CB, &challenge, ""), None).await;
    let r = login_with_passkey(&w, &page, &new_pk).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
}

#[tokio::test]
async fn consent_is_asked_remembered_and_can_be_refused() {
    let w = world();
    let jwks = get(&w.app, "/.well-known/jwks.json", None).await.json();
    let (verifier, challenge) = pkce();
    let consent = |request_id: &str, allow: bool, cookie: &str| {
        let body = json!({"request_id": request_id, "allow": allow});
        let (app, cookie) = (w.app.clone(), cookie.to_string());
        async move { post_json_with(&app, "/oauth/consent", body, &[(header::COOKIE, &cookie)]).await }
    };

    // Signing in is not enough: the hub stops at the consent page, with no code yet.
    let page = get(&w.app, &authorize_scoped("ask", APP_CB, &challenge, "openid email", ""), None).await;
    let r = login_with_passkey(&w, &page, &w.passkey).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    let cookie = r.cookie().expect("session cookie");
    let next = r.json()["redirect"].as_str().unwrap().to_string();
    assert!(next.starts_with("/oauth/consent?request_id="), "{next}");
    let request_id = query(&next)["request_id"].clone();

    // The page is only for the browser that signed in, and says what would be shared.
    assert_eq!(get(&w.app, &next, None).await.status, StatusCode::BAD_REQUEST);
    assert_eq!(get(&w.app, &next, Some("kith_session=someone-elses")).await.status, StatusCode::BAD_REQUEST);
    let page = get(&w.app, &next, Some(&cookie)).await;
    assert_eq!(page.status, StatusCode::OK, "{}", page.text());
    let d = page_data(&page.text());
    assert_eq!((d["client_name"].as_str(), d["redirect_host"].as_str(), d["did"].as_str()), (Some("Asking App"), Some("localhost"), Some(w.st.did.as_str())));
    assert_eq!(d["scopes"], json!(["openid", "email"]));
    assert_eq!(d["claims"], json!({"email": "ada@acme.test", "email_verified": true}), "only what the scopes release");

    // Knowing the request id is not enough to answer for the user.
    let stolen = post_json(&w.app, "/oauth/consent", json!({"request_id": request_id, "allow": true})).await;
    assert_eq!(stolen.status, StatusCode::BAD_REQUEST);

    // Deny: the app hears access_denied, and the request is spent.
    let denied = consent(&request_id, false, &cookie).await;
    let q = query(denied.json()["redirect"].as_str().unwrap());
    assert_eq!((q["error"].as_str(), q["state"].as_str(), q["iss"].as_str()), ("access_denied", "st8", ISSUER));
    assert!(!q.contains_key("code"));
    assert_eq!(consent(&request_id, true, &cookie).await.status, StatusCode::BAD_REQUEST);

    // SSO skips the login page but not the question; prompt=none cannot ask it.
    let silent = get(&w.app, &authorize_scoped("ask", APP_CB, &challenge, "openid email", "&prompt=none"), Some(&cookie)).await;
    assert_eq!(query(&silent.location())["error"], "consent_required");
    let again = get(&w.app, &authorize_scoped("ask", APP_CB, &challenge, "openid email", ""), Some(&cookie)).await;
    assert_eq!(again.status, StatusCode::SEE_OTHER);
    assert!(again.location().starts_with("/oauth/consent?request_id="));
    let request_id = query(&again.location())["request_id"].clone();

    // Allow: a code, tokens, and the hub session's public id in the ID token.
    let allowed = consent(&request_id, true, &cookie).await;
    assert_eq!(allowed.status, StatusCode::OK, "{}", allowed.text());
    let tok = redeem(&w, "ask", allowed.json()["redirect"].as_str().unwrap(), &verifier, None).await;
    let id = verify_rs256(&jwks, tok["id_token"].as_str().unwrap());
    assert_eq!(id["email"], "ada@acme.test");
    assert!(id.get("name").is_none() && id.get("groups").is_none());
    let sid = id["sid"].as_str().expect("sid");
    assert!(!cookie.contains(sid), "sid must not be the session cookie");

    // Remembered for those scopes, even silently…
    let silent = get(&w.app, &authorize_scoped("ask", APP_CB, &challenge, "openid email", "&prompt=none"), Some(&cookie)).await;
    assert!(query(&silent.location()).contains_key("code"), "{}", silent.location());
    // …but more scopes, or prompt=consent, ask again. Even for a first-party app.
    let wider = get(&w.app, &authorize_scoped("ask", APP_CB, &challenge, "openid email groups", ""), Some(&cookie)).await;
    assert!(wider.location().starts_with("/oauth/consent?"));
    let forced = get(&w.app, &authorize_scoped("ask", APP_CB, &challenge, "openid email", "&prompt=consent"), Some(&cookie)).await;
    assert!(forced.location().starts_with("/oauth/consent?"));
    let first_party = get(&w.app, &authorize_url("app", APP_CB, &challenge, "&prompt=consent"), Some(&cookie)).await;
    assert!(first_party.location().starts_with("/oauth/consent?"));
    let d = get(&w.app, "/.well-known/openid-configuration", None).await.json();
    assert_eq!(d["prompt_values_supported"], json!(["none", "login", "consent"]));
}

#[tokio::test]
async fn dynamic_registration() {
    // Off by default.
    let w = world();
    let meta = json!({"redirect_uris": [APP_CB], "client_name": "Registered App"});
    assert_eq!(post_json(&w.app, "/oauth/register", meta.clone()).await.status, StatusCode::NOT_FOUND);
    assert!(get(&w.app, "/.well-known/openid-configuration", None).await.json().get("registration_endpoint").is_none());

    let w = world_with(|cfg| cfg.registration_token = Some("let-me-in".into()));
    let d = get(&w.app, "/.well-known/openid-configuration", None).await.json();
    assert_eq!(d["registration_endpoint"], format!("{ISSUER}/oauth/register"));
    let register = |meta: Value, token: &'static str| {
        let app = w.app.clone();
        async move { post_json_with(&app, "/oauth/register", meta, &[(header::AUTHORIZATION, token)]).await }
    };

    // Needs the registration token.
    assert_eq!(post_json(&w.app, "/oauth/register", meta.clone()).await.status, StatusCode::UNAUTHORIZED);
    assert_eq!(register(meta.clone(), "Bearer wrong").await.status, StatusCode::UNAUTHORIZED);

    // Metadata the hub will not honour is refused, not silently dropped.
    for (bad, error) in [
        (json!({"redirect_uris": []}), "invalid_redirect_uri"),
        (json!({"redirect_uris": ["http://evil.example/cb"]}), "invalid_redirect_uri"),
        (json!({"redirect_uris": ["https://a.example/cb#frag"]}), "invalid_redirect_uri"),
        (json!({"redirect_uris": [APP_CB], "jwks_uri": "https://a.example/jwks"}), "invalid_client_metadata"),
        (json!({"redirect_uris": [APP_CB], "response_types": ["id_token"]}), "invalid_client_metadata"),
        (json!({"redirect_uris": [APP_CB], "grant_types": ["implicit"]}), "invalid_client_metadata"),
        (json!({"redirect_uris": [APP_CB], "token_endpoint_auth_method": "private_key_jwt"}), "invalid_client_metadata"),
        (json!({"redirect_uris": [APP_CB], "backchannel_logout_uri": "http://internal.example/hook"}), "invalid_client_metadata"),
        (json!({"redirect_uris": [APP_CB], "id_token_encrypted_response_alg": "RSA-OAEP-256"}), "invalid_client_metadata"),
        (json!({"redirect_uris": ["https://a.example/cb", "https://b.example/cb"], "subject_type": "pairwise"}), "invalid_client_metadata"),
    ] {
        let r = register(bad.clone(), "Bearer let-me-in").await;
        assert_eq!((r.status, r.json()["error"].as_str()), (StatusCode::BAD_REQUEST, Some(error)), "{bad}");
    }

    let r = register(meta, "Bearer let-me-in").await;
    assert_eq!(r.status, StatusCode::CREATED, "{}", r.text());
    assert_eq!(r.headers[header::CACHE_CONTROL], "no-store");
    let c = r.json();
    let (id, secret) = (c["client_id"].as_str().unwrap(), c["client_secret"].as_str().unwrap());
    assert_eq!((c["client_name"].as_str(), c["token_endpoint_auth_method"].as_str()), (Some("Registered App"), Some("client_secret_basic")));
    assert_eq!((c["redirect_uris"].clone(), c["client_secret_expires_at"].clone()), (json!([APP_CB]), json!(0)));
    let public = register(json!({"redirect_uris": ["com.example.app:/cb"], "token_endpoint_auth_method": "none"}), "Bearer let-me-in").await.json();
    assert!(public.get("client_secret").is_none(), "{public}");

    // It works like any client, except that it can never skip the consent page.
    let (verifier, challenge) = pkce();
    let page = get(&w.app, &authorize_url(id, APP_CB, &challenge, ""), None).await;
    assert_eq!(page_data(&page.text())["client_name"], "Registered App");
    let r = login_with_passkey(&w, &page, &w.passkey).await;
    let next = r.json()["redirect"].as_str().unwrap().to_string();
    assert!(next.starts_with("/oauth/consent?"), "{next}");
    let cookie = r.cookie().unwrap();
    let allowed = post_json_with(&w.app, "/oauth/consent", json!({"request_id": query(&next)["request_id"], "allow": true}), &[(header::COOKIE, &cookie)]).await;
    let redirect = allowed.json()["redirect"].as_str().unwrap().to_string();
    let code = query(&redirect)["code"].clone();
    let form = [("grant_type", "authorization_code"), ("code", code.as_str()), ("redirect_uri", APP_CB), ("code_verifier", verifier.as_str())];
    assert_eq!(post_form(&w.app, "/oauth/token", &form, Some(&format!("{id}:wrong"))).await.status, StatusCode::UNAUTHORIZED);
    let tok = redeem(&w, id, &redirect, &verifier, Some(&format!("{id}:{secret}"))).await;
    assert_eq!(jws::decode(tok["id_token"].as_str().unwrap()).unwrap().claims["aud"], id);

    // Registrations survive a restart.
    let reopened = Hub::open(HubConfig::new(ISSUER, w.dir.join("data"))).unwrap();
    assert_eq!(reopened.client(id).and_then(|c| c.name).as_deref(), Some("Registered App"));
    assert_eq!(reopened.client(id).map(|c| c.consent), Some(Consent::Explicit));
}

/// A second authorization for a client the session already agreed to: straight to a code.
async fn allowed_redirect_again(w: &World, client: &str, cookie: &str, challenge: &str) -> String {
    let r = get(&w.app, &authorize_url(client, APP_CB, challenge, ""), Some(cookie)).await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
    assert!(r.location().starts_with(APP_CB), "{}", r.location());
    r.location()
}

#[tokio::test]
async fn logout_tells_the_clients() {
    // A relying party that records the logout tokens it is sent.
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<String>();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let rp = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
    let hook = axum::routing::post(move |axum::Form(f): axum::Form<HashMap<String, String>>| {
        let tx = tx.clone();
        async move { tx.send(f["logout_token"].clone()).map(|_| StatusCode::OK).unwrap_or(StatusCode::GONE) }
    });
    tokio::spawn(async move { axum::serve(listener, Router::new().route("/backchannel", hook)).await.unwrap() });

    let w = world_with(|cfg| {
        cfg.clients.push(Client {
            client_id: "notify".into(),
            redirect_uris: vec![APP_CB.into()],
            post_logout_redirect_uris: vec!["http://localhost:3000/".into()],
            consent: Consent::Implied,
            backchannel_logout_uri: Some(format!("{rp}/backchannel")),
            frontchannel_logout_uri: Some(format!("{rp}/frontchannel")),
            ..Default::default()
        })
    });
    let jwks = get(&w.app, "/.well-known/jwks.json", None).await.json();
    let d = get(&w.app, "/.well-known/openid-configuration", None).await.json();
    for k in ["backchannel_logout_supported", "backchannel_logout_session_supported", "frontchannel_logout_supported", "frontchannel_logout_session_supported"] {
        assert_eq!(d[k], true, "{k}");
    }

    // Sign in to both apps in one hub session; only "notify" asked to be told.
    let (verifier, challenge) = pkce();
    let page = get(&w.app, &authorize_url("notify", APP_CB, &challenge, ""), None).await;
    let r = login_with_passkey(&w, &page, &w.passkey).await;
    let cookie = r.cookie().unwrap();
    let tok = redeem(&w, "notify", r.json()["redirect"].as_str().unwrap(), &verifier, None).await;
    let id = verify_rs256(&jwks, tok["id_token"].as_str().unwrap());
    let sid = id["sid"].as_str().unwrap().to_string();
    let unredeemed = allowed_redirect_again(&w, "app", &cookie, &challenge).await;

    // Logout: a page that loads the app's front-channel URL, then goes on to the app.
    let out = get(&w.app, "/oauth/logout?client_id=notify&post_logout_redirect_uri=http%3A%2F%2Flocalhost%3A3000%2F&state=bye", Some(&cookie)).await;
    assert_eq!(out.status, StatusCode::OK, "{}", out.text());
    let page = page_data(&out.text());
    assert_eq!(page["frames"], json!([format!("{rp}/frontchannel?iss={}&sid={sid}", enc(ISSUER))]));
    assert_eq!(page["redirect"], "http://localhost:3000/?state=bye");
    let csp = out.headers[header::CONTENT_SECURITY_POLICY].to_str().unwrap();
    assert!(csp.ends_with(&format!("; frame-src {rp}")), "{csp}");

    // The back channel got a signed logout token for the same session.
    let token = tokio::time::timeout(std::time::Duration::from_secs(5), rx.recv()).await.expect("logout token within 5s").unwrap();
    assert_eq!(jws::decode(&token).unwrap().header["typ"], "logout+jwt");
    let c = verify_rs256(&jwks, &token);
    assert_eq!((c["iss"].as_str(), c["aud"].as_str(), c["sub"].as_str(), c["sid"].as_str()), (Some(ISSUER), Some("notify"), Some(w.st.did.as_str()), Some(sid.as_str())));
    assert!(c["events"][BACKCHANNEL_LOGOUT_EVENT].is_object() && c["jti"].is_string());
    assert!(c.get("nonce").is_none(), "a logout token must not carry a nonce");
    assert!(rx.try_recv().is_err(), "only clients that registered a URI are called");

    // The session is over: no SSO, and its unredeemed code is dead.
    assert_eq!(get(&w.app, &authorize_url("notify", APP_CB, &challenge, ""), Some(&cookie)).await.status, StatusCode::OK);
    let code = query(&unredeemed)["code"].clone();
    let dead = post_form(&w.app, "/oauth/token", &[("grant_type", "authorization_code"), ("code", &code), ("redirect_uri", APP_CB), ("code_verifier", &verifier), ("client_id", "app")], None).await;
    assert_eq!(dead.json()["error"], "invalid_grant");

    // Without a session there is nobody to tell: the plain redirect.
    let out = get(&w.app, "/oauth/logout?client_id=notify&post_logout_redirect_uri=http%3A%2F%2Flocalhost%3A3000%2F", None).await;
    assert_eq!(out.status, StatusCode::SEE_OTHER);
}

#[tokio::test]
async fn encrypted_id_tokens() {
    use rsa::traits::PublicKeyParts;
    let key = rsa::RsaPrivateKey::new(&mut rand::rngs::OsRng, 2048).unwrap();
    let client_jwks = json!({"keys": [{"kty": "RSA", "kid": "rp-enc", "use": "enc", "n": b64u(key.n().to_bytes_be()), "e": b64u(key.e().to_bytes_be())}]});
    let client = Client {
        client_id: "sealed".into(),
        redirect_uris: vec![APP_CB.into()],
        consent: Consent::Implied,
        id_token_encrypted_response_alg: Some("RSA-OAEP-256".into()),
        jwks: Some(client_jwks),
        ..Default::default()
    };
    // Asking for encryption without a usable key is a configuration error.
    assert!(Client { jwks: None, ..client.clone() }.validate().is_err());
    assert!(Client { id_token_encrypted_response_alg: Some("RSA1_5".into()), ..client.clone() }.validate().is_err());

    let w = world_with(|cfg| cfg.clients.push(client));
    let jwks = get(&w.app, "/.well-known/jwks.json", None).await.json();
    let d = get(&w.app, "/.well-known/openid-configuration", None).await.json();
    assert_eq!(d["id_token_encryption_alg_values_supported"], json!(["RSA-OAEP-256", "ECDH-ES"]));
    assert_eq!(d["id_token_encryption_enc_values_supported"], json!(["A256GCM"]));

    let (verifier, challenge) = pkce();
    let page = get(&w.app, &authorize_url("sealed", APP_CB, &challenge, ""), None).await;
    let r = login_with_passkey(&w, &page, &w.passkey).await;
    let tok = redeem(&w, "sealed", r.json()["redirect"].as_str().unwrap(), &verifier, None).await;

    // A JWE around the usual signed ID token: nothing readable without the client's key.
    let sealed = tok["id_token"].as_str().unwrap();
    assert_eq!(sealed.split('.').count(), 5);
    let header: Value = serde_json::from_slice(&b64u_decode(sealed.split('.').next().unwrap()).unwrap()).unwrap();
    assert_eq!(header, json!({"alg": "RSA-OAEP-256", "enc": "A256GCM", "cty": "JWT", "kid": "rp-enc"}));
    assert!(!sealed.contains(&b64u("ada@acme.test")));
    let other = rsa::RsaPrivateKey::new(&mut rand::rngs::OsRng, 2048).unwrap();
    assert!(jwe::decrypt(sealed, &jwe::Secret::Rsa(Box::new(other))).is_err());
    let inner = String::from_utf8(jwe::decrypt(sealed, &jwe::Secret::Rsa(Box::new(key))).unwrap()).unwrap();
    let id = verify_rs256(&jwks, &inner);
    assert_eq!((id["aud"].as_str(), id["email"].as_str(), id["nonce"].as_str()), (Some("sealed"), Some("ada@acme.test"), Some("n0nce")));
}

#[tokio::test]
async fn state_survives_a_restart() {
    let mut w = world();
    let (verifier, challenge) = pkce();

    // The sign-in request outlives a restart. Only the in-memory challenge is lost:
    // the page is handed a fresh one and retries.
    let page = get(&w.app, &authorize_url("ask", APP_CB, &challenge, ""), None).await;
    let d = page_data(&page.text());
    w.restart();
    let r = login_with_passkey(&w, &page, &w.passkey).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED, "{}", r.text());
    let retry = r.json();
    assert!(retry["challenge_id"].is_string() && retry["message"].is_string(), "{retry}");
    let factor = passkey_factor(&w.passkey, retry["message"].as_str().unwrap(), ORIGIN);
    let r = post_json(&w.app, "/oauth/login", json!({"request_id": d["request_id"], "challenge_id": retry["challenge_id"], "did": w.st.did, "factors": [factor]})).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    let cookie = r.cookie().unwrap();
    let next = r.json()["redirect"].as_str().unwrap().to_string();
    assert!(next.starts_with("/oauth/consent?"), "{next}");

    // The consent page still knows the login that is waiting on it.
    w.restart();
    assert_eq!(get(&w.app, &next, Some(&cookie)).await.status, StatusCode::OK);
    let allowed = post_json_with(&w.app, "/oauth/consent", json!({"request_id": query(&next)["request_id"], "allow": true}), &[(header::COOKIE, &cookie)]).await;
    let redirect = allowed.json()["redirect"].as_str().unwrap().to_string();
    assert!(redirect.starts_with(APP_CB), "{redirect}");

    // The code survives, and so does the refresh token it yields.
    w.restart();
    let tok = redeem(&w, "ask", &redirect, &verifier, None).await;
    let rt = tok["refresh_token"].as_str().unwrap().to_string();
    w.restart();
    let r2 = post_form(&w.app, "/oauth/token", &[("grant_type", "refresh_token"), ("refresh_token", &rt), ("client_id", "ask")], None).await;
    assert_eq!(r2.status, StatusCode::OK, "{}", r2.text());

    // SSO and the remembered consent: straight to a code, no login or consent page.
    let r = get(&w.app, &authorize_url("ask", APP_CB, &challenge, ""), Some(&cookie)).await;
    assert_eq!(r.status, StatusCode::SEE_OTHER, "{}", r.text());
    assert!(r.location().starts_with(APP_CB), "{}", r.location());

    // Bearer secrets are stored hashed: the database never holds them in the clear.
    let db = w.dir.join("data").join("hub.sqlite");
    let mut raw = std::fs::read(&db).unwrap();
    raw.extend(std::fs::read(db.with_extension("sqlite-wal")).unwrap_or_default());
    let raw = String::from_utf8_lossy(&raw);
    let cookie_value = cookie.split_once('=').unwrap().1;
    for secret in [cookie_value, rt.as_str(), r2.json()["refresh_token"].as_str().unwrap(), query(&redirect)["code"].as_str()] {
        assert!(!raw.contains(secret), "a bearer secret is in the database in the clear");
    }
    assert!(raw.contains(&w.st.did), "sanity: the file was read");
}

#[tokio::test]
async fn totp_lockout_survives_a_restart() {
    let mut w = world();
    let bearer = hub_bearer(&w, "laptop", &w.laptop).await;
    let auth = [(header::AUTHORIZATION, bearer.as_str())];
    let enrolled = call(&w.app, "POST", "/v1/totp/enroll", &auth, None, Some(json!({}))).await.json();
    let secret = totp::from_base32(enrolled["secret"].as_str().unwrap()).unwrap();
    let confirm = |code: String| {
        let app = w.app.clone();
        let auth = auth.clone();
        async move { call(&app, "POST", "/v1/totp/confirm", &auth, None, Some(json!({"code": code}))).await }
    };
    assert_eq!(confirm(totp::code_at(&secret, now())).await.status, StatusCode::OK);

    // Five wrong codes lock the factor; after that even the right code is refused.
    let wrong = || {
        let valid: Vec<String> = [-30, 0, 30].iter().map(|d| totp::code_at(&secret, now() + d)).collect();
        ["000000", "000001"].iter().find(|c| !valid.iter().any(|v| v == *c)).unwrap().to_string()
    };
    for _ in 0..4 {
        assert_eq!(confirm(wrong()).await.status, StatusCode::UNAUTHORIZED);
    }
    assert_eq!(confirm(wrong()).await.status, StatusCode::UNAUTHORIZED, "the fifth failure locks");
    let locked = confirm(totp::code_at(&secret, now() + 30)).await;
    assert_eq!((locked.status, locked.json()["error"].as_str()), (StatusCode::TOO_MANY_REQUESTS, Some("locked")));
    assert!(locked.json()["retry_after"].as_i64().is_some_and(|s| s > 0 && s <= 900), "{}", locked.text());

    // A restart does not reset it.
    w.restart();
    let still = call(&w.app, "POST", "/v1/totp/confirm", &auth, None, Some(json!({"code": totp::code_at(&secret, now() + 30)}))).await;
    assert_eq!(still.status, StatusCode::TOO_MANY_REQUESTS, "{}", still.text());
}

#[tokio::test]
async fn login_and_registration_are_rate_limited() {
    let w = world_with(|cfg| {
        cfg.login_limit = RateLimit { max: 3, window_secs: 60 };
        cfg.register_limit = RateLimit { max: 1, window_secs: 3600 };
        cfg.registration_token = Some("let-me-in".into());
    });
    let (_, challenge) = pkce();
    let page = get(&w.app, &authorize_url("app", APP_CB, &challenge, ""), None).await;
    let d = page_data(&page.text());
    let bad = json!({"request_id": d["request_id"], "challenge_id": d["challenge_id"], "did": w.st.did, "factors": [{"type": "totp", "code": "000000"}]});
    for _ in 0..3 {
        assert_eq!(call(&w.app, "POST", "/oauth/login", &[], Some("203.0.113.7"), Some(bad.clone())).await.status, StatusCode::UNAUTHORIZED);
    }
    let limited = call(&w.app, "POST", "/oauth/login", &[], Some("203.0.113.7"), Some(bad.clone())).await;
    assert_eq!((limited.status, limited.json()["error"].as_str()), (StatusCode::TOO_MANY_REQUESTS, Some("rate_limited")), "{}", limited.text());
    let retry: i64 = limited.headers[header::RETRY_AFTER].to_str().unwrap().parse().unwrap();
    assert!((1..=60).contains(&retry), "{retry}");
    assert_eq!(limited.json()["retry_after"], retry);

    // Another address is not affected: a real login from it goes through.
    assert_eq!(call(&w.app, "POST", "/oauth/login", &[], Some("203.0.113.8"), Some(bad)).await.status, StatusCode::UNAUTHORIZED);
    let fresh = get(&w.app, &authorize_url("app", APP_CB, &challenge, ""), None).await;
    assert_eq!(login_with_passkey(&w, &fresh, &w.passkey).await.status, StatusCode::OK);

    // Registration: every attempt counts, including ones without the token.
    let meta = json!({"redirect_uris": [APP_CB]});
    assert_eq!(call(&w.app, "POST", "/oauth/register", &[], Some("198.51.100.1"), Some(meta.clone())).await.status, StatusCode::UNAUTHORIZED);
    assert_eq!(call(&w.app, "POST", "/oauth/register", &[(header::AUTHORIZATION, "Bearer let-me-in")], Some("198.51.100.1"), Some(meta.clone())).await.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(call(&w.app, "POST", "/oauth/register", &[(header::AUTHORIZATION, "Bearer let-me-in")], Some("198.51.100.2"), Some(meta.clone())).await.status, StatusCode::CREATED);

    // Behind one reverse proxy, the address is the last X-Forwarded-For entry (the
    // one the proxy appended); whatever the client put in front of it is ignored.
    let w = world_with(|cfg| {
        cfg.behind_proxy = true;
        cfg.register_limit = RateLimit { max: 1, window_secs: 3600 };
        cfg.registration_token = Some("let-me-in".into());
    });
    let via_proxy = |xff: &'static str| {
        let app = w.app.clone();
        let meta = meta.clone();
        async move { call(&app, "POST", "/oauth/register", &[(header::AUTHORIZATION, "Bearer let-me-in"), (header::HeaderName::from_static("x-forwarded-for"), xff)], Some("10.0.0.1"), Some(meta)).await.status }
    };
    assert_eq!(via_proxy("1.1.1.1, 203.0.113.9").await, StatusCode::CREATED);
    assert_eq!(via_proxy("2.2.2.2, 203.0.113.9").await, StatusCode::TOO_MANY_REQUESTS, "same real client, a different claimed origin");
    assert_eq!(via_proxy("203.0.113.10").await, StatusCode::CREATED);
}

#[tokio::test]
async fn admin_api() {
    let w = world_with(|cfg| {
        cfg.admin_token = Some("ops-secret".into());
        // The bundle's "admin" role: members of group "strong" (AAL 2 or better).
        cfg.admin_role = Some("admin".into());
        cfg.registration_token = Some("let-me-in".into());
    });
    let ops = [(header::AUTHORIZATION, "Bearer ops-secret")];
    let admin = |method: &'static str, uri: String| {
        let app = w.app.clone();
        let ops = ops.clone();
        async move { call(&app, method, &uri, &ops, None, None).await }
    };
    assert_eq!(call(&w.app, "GET", "/v1/admin/sessions", &[], None, None).await.status, StatusCode::UNAUTHORIZED);
    assert_eq!(call(&w.app, "GET", "/v1/admin/sessions", &[(header::AUTHORIZATION, "Bearer nope")], None, None).await.status, StatusCode::UNAUTHORIZED);

    // One hub session, two apps; both get refresh tokens, "ask" after consent.
    let (verifier, challenge) = pkce();
    let page = get(&w.app, &authorize_url("app", APP_CB, &challenge, ""), None).await;
    let r = login_with_passkey(&w, &page, &w.passkey).await;
    let cookie = r.cookie().unwrap();
    let app_tok = redeem(&w, "app", r.json()["redirect"].as_str().unwrap(), &verifier, None).await;
    let r = get(&w.app, &authorize_url("ask", APP_CB, &challenge, ""), Some(&cookie)).await;
    let consent = r.location();
    let allowed = post_json_with(&w.app, "/oauth/consent", json!({"request_id": query(&consent)["request_id"], "allow": true}), &[(header::COOKIE, &cookie)]).await;
    let ask_tok = redeem(&w, "ask", allowed.json()["redirect"].as_str().unwrap(), &verifier, None).await;
    let refresh = |client: &'static str, rt: String| {
        let app = w.app.clone();
        async move { post_form(&app, "/oauth/token", &[("grant_type", "refresh_token"), ("refresh_token", &rt), ("client_id", client)], None).await }
    };

    // Stats and sessions. Cookies are never shown.
    let stats = admin("GET", "/v1/admin/stats".into()).await.json();
    assert_eq!((stats["sessions"].as_i64(), stats["refresh_tokens"].as_i64(), stats["configured_clients"].as_i64(), stats["kels"].as_i64()), (Some(1), Some(2), Some(3), Some(1)), "{stats}");
    let sessions = admin("GET", "/v1/admin/sessions".into()).await.json();
    assert_eq!(sessions.as_array().map(Vec::len), Some(1), "{sessions}");
    let s = &sessions[0];
    assert_eq!((s["did"].as_str(), s["device"].as_str(), s["aal"].as_i64()), (Some(w.st.did.as_str()), Some("phone"), Some(2)));
    assert_eq!(s["clients"], json!(["app", "ask"]));
    assert!(!sessions.to_string().contains(cookie.split_once('=').unwrap().1));
    let sid = s["sid"].as_str().unwrap().to_string();
    assert_eq!(jws::decode(app_tok["id_token"].as_str().unwrap()).unwrap().claims["sid"], sid, "the sid clients saw");
    assert_eq!(admin("GET", "/v1/admin/sessions?did=did:kith:nobody".into()).await.json(), json!([]));

    // Consent: list it, withdraw it. The client's offline access ends; it is asked again.
    let grants = admin("GET", format!("/v1/admin/grants/{}", w.st.did)).await.json();
    assert_eq!((grants[0]["client_id"].as_str(), grants[0]["client_name"].as_str()), (Some("ask"), Some("Asking App")), "{grants}");
    assert_eq!(grants[0]["scopes"], json!(["email", "groups", "offline_access", "openid", "profile"]));
    let out = admin("DELETE", format!("/v1/admin/grants/{}/ask", w.st.did)).await.json();
    assert_eq!((out["revoked"].as_bool(), out["refresh_tokens_revoked"].as_i64()), (Some(true), Some(1)), "{out}");
    assert_eq!(refresh("ask", ask_tok["refresh_token"].as_str().unwrap().into()).await.json()["error"], "invalid_grant");
    assert!(get(&w.app, &authorize_url("ask", APP_CB, &challenge, ""), Some(&cookie)).await.location().starts_with("/oauth/consent?"));
    assert_eq!(admin("GET", format!("/v1/admin/grants/{}", w.st.did)).await.json(), json!([]));
    let app_rt = refresh("app", app_tok["refresh_token"].as_str().unwrap().into()).await.json()["refresh_token"].as_str().unwrap().to_string();

    // End the session: no more SSO, and its refresh tokens are gone too.
    let out = admin("DELETE", format!("/v1/admin/sessions/{sid}")).await.json();
    assert_eq!((out["ended"][0]["sid"].as_str(), out["refresh_tokens_revoked"].as_i64()), (Some(sid.as_str()), Some(1)), "{out}");
    assert_eq!(admin("DELETE", format!("/v1/admin/sessions/{sid}")).await.status, StatusCode::NOT_FOUND);
    assert_eq!(get(&w.app, &authorize_url("app", APP_CB, &challenge, ""), Some(&cookie)).await.status, StatusCode::OK, "back to the login page");
    assert_eq!(refresh("app", app_rt).await.json()["error"], "invalid_grant");

    // Sign out everywhere: every session of the identity.
    let mut cookies = vec![];
    for _ in 0..2 {
        let page = get(&w.app, &authorize_url("app", APP_CB, &challenge, ""), None).await;
        cookies.push(login_with_passkey(&w, &page, &w.passkey).await.cookie().unwrap());
    }
    let out = admin("DELETE", format!("/v1/admin/identities/{}/sessions", w.st.did)).await.json();
    assert_eq!(out["ended"].as_array().map(Vec::len), Some(2), "{out}");
    for c in &cookies {
        assert_eq!(get(&w.app, &authorize_url("app", APP_CB, &challenge, ""), Some(c)).await.status, StatusCode::OK);
    }
    assert_eq!(admin("GET", "/v1/admin/stats".into()).await.json()["sessions"], 0);

    // Clients: configured ones are read-only here; registered ones can be removed.
    let clients = admin("GET", "/v1/admin/clients".into()).await.json();
    let listed: Vec<(&str, &str, bool)> = clients.as_array().unwrap().iter().map(|c| (c["client_id"].as_str().unwrap(), c["source"].as_str().unwrap(), c["has_secret"].as_bool().unwrap())).collect();
    assert_eq!(listed, vec![("app", "configured", false), ("ask", "configured", false), ("pw", "configured", true)]);
    assert!(!clients.to_string().contains("s3cret"), "secrets are never listed");
    assert_eq!(admin("DELETE", "/v1/admin/clients/app".into()).await.status, StatusCode::CONFLICT);
    let reg = post_json_with(&w.app, "/oauth/register", json!({"redirect_uris": [APP_CB], "client_name": "Temp"}), &[(header::AUTHORIZATION, "Bearer let-me-in")]).await.json();
    let id = reg["client_id"].as_str().unwrap().to_string();
    let clients = admin("GET", "/v1/admin/clients".into()).await.json();
    assert!(clients.as_array().unwrap().iter().any(|c| c["client_id"] == id && c["source"] == "registered" && c["has_secret"] == true), "{clients}");
    assert_eq!(admin("DELETE", format!("/v1/admin/clients/{id}")).await.json()["deleted"], id);
    assert!(w.hub.client(&id).is_none());
    assert_eq!(admin("DELETE", format!("/v1/admin/clients/{id}")).await.status, StatusCode::NOT_FOUND);

    // The role: a hub token for someone in it works; AAL 1 is not "strong", so the
    // laptop's token is refused; a token for another audience is no hub token at all.
    let ch = post_json(&w.app, "/v1/auth/challenge", json!({"did": w.st.did})).await.json();
    let strong = post_json(&w.app, "/v1/auth/verify", json!({"challenge_id": ch["challenge_id"], "audience": ISSUER, "factors": [passkey_factor(&w.passkey, ch["message"].as_str().unwrap(), ORIGIN)]})).await.json();
    let by_role = call(&w.app, "GET", "/v1/admin/stats", &[(header::AUTHORIZATION, &format!("Bearer {}", strong["access_token"].as_str().unwrap()))], None, None).await;
    assert_eq!(by_role.status, StatusCode::OK, "{}", by_role.text());
    let laptop = hub_bearer(&w, "laptop", &w.laptop).await;
    assert_eq!(call(&w.app, "GET", "/v1/admin/stats", &[(header::AUTHORIZATION, &laptop)], None, None).await.status, StatusCode::FORBIDDEN);
    let ch = post_json(&w.app, "/v1/auth/challenge", json!({"did": w.st.did})).await.json();
    let elsewhere = post_json(&w.app, "/v1/auth/verify", json!({"challenge_id": ch["challenge_id"], "audience": "api://demo", "factors": [passkey_factor(&w.passkey, ch["message"].as_str().unwrap(), ORIGIN)]})).await.json();
    assert_eq!(call(&w.app, "GET", "/v1/admin/stats", &[(header::AUTHORIZATION, &format!("Bearer {}", elsewhere["access_token"].as_str().unwrap()))], None, None).await.status, StatusCode::UNAUTHORIZED);
}
