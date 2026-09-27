//! End-to-end OpenID Connect tests against the hub router (in process), using real
//! WebAuthn assertions from the software authenticator.

use std::collections::HashMap;
use std::sync::Arc;

use axum::body::Body;
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
use kith_core::util::{b64u, b64u_decode, sha256};
use kith_core::{jws, webauthn};
use kith_hub::oidc::{Client, SubjectType};
use kith_hub::{Hub, HubConfig, TT_SESSION};

const ISSUER: &str = "http://localhost:7777";
const ORIGIN: &str = "http://localhost:7777";
const APP_CB: &str = "http://localhost:3000/cb";
const PW_CB: &str = "https://pw.example/cb";

struct World {
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
            subject_type: SubjectType::Public,
            id_token_signed_response_alg: "RS256".into(),
            post_logout_redirect_uris: vec!["http://localhost:3000/".into()],
            min_aal: None,
        },
        Client {
            client_id: "pw".into(),
            client_secret: Some("s3cret".into()),
            redirect_uris: vec![PW_CB.into()],
            name: None,
            audience: None,
            subject_type: SubjectType::Pairwise,
            id_token_signed_response_alg: "EdDSA".into(),
            post_logout_redirect_uris: vec![],
            min_aal: None,
        },
    ];
    let hub = Hub::open(cfg).unwrap();
    hub.put_kel(&st.did, log.clone()).unwrap();
    World { app: kith_hub::router(hub.clone()), hub, root, passkey, laptop, st, log }
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
    send(app, Request::post(uri).header(header::CONTENT_TYPE, "application/json").body(Body::from(body.to_string())).unwrap()).await
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
    format!(
        "/oauth/authorize?response_type=code&client_id={client}&redirect_uri={}&scope={}&state=st8&nonce=n0nce&code_challenge={challenge}&code_challenge_method=S256{extra}",
        enc(cb),
        enc("openid profile email groups offline_access")
    )
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
