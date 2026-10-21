//! Upstream OIDC login ("Sign in with Telegram") end to end: the hub router in
//! process, and a stand-in provider on a loopback port that behaves the way
//! Telegram's documents: discovery, code + PKCE, client_secret_basic, RS256 ID tokens.

#![allow(clippy::result_large_err)]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::extract::State;
use axum::http::{header, HeaderMap, Request, StatusCode};
use axum::routing::{get, post};
use axum::{Form, Json, Router};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;

use kith_core::kel::{new_inception, next_event, verify_log, Device, DeviceKind, Event, EventBody, KeyState};
use kith_core::keys::{KeyType, LocalSigner, SecretKey, VerifyOptions};
use kith_core::policy::SignerPolicy;
use kith_core::session::{DeviceSigner, SessionKey};
use kith_core::util::{b64u, now, random_id, sha256};
use kith_core::{jws, totp};
use kith_hub::oidc::{Consent, Client, RsaSigner, SubjectType};
use kith_hub::upstream::{verify_id_token, Upstream};
use kith_hub::{Hub, HubConfig, TT_SESSION};

const ISSUER: &str = "http://localhost:7777";
const APP_CB: &str = "http://localhost:3000/cb";
const BOT_ID: &str = "7000000001";
const BOT_SECRET: &str = "bot-secret";
const TG_USER: &str = "424242";

/// What the provider remembers about a code it handed out.
struct Issued {
    challenge: String,
    nonce: String,
    sub: String,
}

struct Provider {
    issuer: String,
    key: RsaSigner,
    codes: Mutex<HashMap<String, Issued>>,
    /// What `/userinfo` answers, and how often it was asked.
    userinfo: Mutex<Value>,
    userinfo_calls: std::sync::atomic::AtomicUsize,
}

async fn provider_userinfo(State(p): State<Arc<Provider>>, headers: HeaderMap) -> (StatusCode, Json<Value>) {
    p.userinfo_calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    if headers.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()) != Some("Bearer at") {
        return (StatusCode::UNAUTHORIZED, Json(json!({"error": "invalid_token"})));
    }
    (StatusCode::OK, Json(p.userinfo.lock().unwrap().clone()))
}

async fn provider_token(State(p): State<Arc<Provider>>, headers: HeaderMap, Form(f): Form<HashMap<String, String>>) -> (StatusCode, Json<Value>) {
    use base64::Engine;
    let basic = base64::engine::general_purpose::STANDARD.encode(format!("{BOT_ID}:{BOT_SECRET}"));
    if headers.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()) != Some(&format!("Basic {basic}")) {
        return (StatusCode::UNAUTHORIZED, Json(json!({"error": "invalid_client"})));
    }
    let issued = p.codes.lock().unwrap().remove(f.get("code").map(String::as_str).unwrap_or_default());
    let Some(i) = issued.filter(|i| f.get("code_verifier").is_some_and(|v| b64u(sha256(v.as_bytes())) == i.challenge)) else {
        return (StatusCode::BAD_REQUEST, Json(json!({"error": "invalid_grant"})));
    };
    let t = now();
    let id = json!({"iss": p.issuer, "sub": i.sub, "aud": BOT_ID, "iat": t, "exp": t + 300, "nonce": i.nonce});
    (StatusCode::OK, Json(json!({"access_token": "at", "token_type": "Bearer", "expires_in": 300, "id_token": p.key.sign_jwt(&id).unwrap()})))
}

async fn start_provider() -> Arc<Provider> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let issuer = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
    let p = Arc::new(Provider { issuer: issuer.clone(), key: RsaSigner::generate().unwrap(), codes: Mutex::new(HashMap::new()), userinfo: Mutex::new(json!({"sub": TG_USER})), userinfo_calls: Default::default() });
    let discovery = json!({"issuer": issuer, "authorization_endpoint": format!("{issuer}/auth"), "token_endpoint": format!("{issuer}/token"), "jwks_uri": format!("{issuer}/.well-known/jwks.json"), "userinfo_endpoint": format!("{issuer}/userinfo")});
    let jwks = json!({"keys": [p.key.jwk()]});
    let app = Router::new()
        .route("/.well-known/openid-configuration", get(move || async move { Json(discovery) }))
        .route("/.well-known/jwks.json", get(move || async move { Json(jwks) }))
        .route("/token", post(provider_token))
        .route("/userinfo", get(provider_userinfo))
        .with_state(p.clone());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    p
}

struct World {
    app: Router,
    hub: Arc<Hub>,
    provider: Arc<Provider>,
    root: LocalSigner,
    laptop: LocalSigner,
    did: String,
    log: Vec<Event>,
}

impl World {
    fn state(&self) -> KeyState {
        verify_log(&self.log, &VerifyOptions::default()).unwrap()
    }

    /// Append a manage-signed event and publish the log.
    fn publish(&mut self, body: EventBody) {
        let mut ev = next_event(&self.state(), body);
        ev.sign(&self.root).unwrap();
        self.log.push(ev);
        self.hub.put_kel(&self.did, self.log.clone()).unwrap();
    }

    fn alias(&self, sub: &str) -> String {
        self.hub.upstream("telegram").unwrap().alias(sub)
    }
}

fn identity(dir: &std::path::Path) -> (LocalSigner, LocalSigner, Vec<Event>) {
    std::fs::create_dir_all(dir).unwrap();
    let root = LocalSigner::generate(KeyType::Ed25519);
    let laptop = LocalSigner::generate(KeyType::Ed25519);
    let next = SignerPolicy::single(LocalSigner::generate(KeyType::Ed25519).id);
    let dev = Device { id: "laptop".into(), key: laptop.id.clone(), name: "laptop".into(), kind: DeviceKind::Software, aal: 1, caps: vec!["session".into()], rp_id: None, xkey: None };
    let mut inc = new_inception(SignerPolicy::single(&root.id), &next, vec![dev]);
    inc.sign(&root).unwrap();
    inc.sign(&laptop).unwrap();
    (root, laptop, vec![inc])
}

async fn world() -> World {
    world_with(&[]).await
}

/// `attributes` are the claims the hub trusts the provider for, as (claim, attribute).
async fn world_with(attributes: &[(&str, &str)]) -> World {
    let dir = std::env::temp_dir().join(format!("kith-upstream-{}", random_id()));
    let provider = start_provider().await;
    let (root, laptop, log) = identity(&dir);
    let did = verify_log(&log, &VerifyOptions::default()).unwrap().did;

    // The directory knows this identity's name; a group rule matches on email.
    let bundle = json!({
        "version": 1,
        "groups": {"staff": {"rule": "principal has email && principal.email like \"*@acme.test\""}},
        "roles": {},
        "directory": {(did.clone()): {"attrs": {"name": "Ada"}}},
        "policies": ""
    });
    std::fs::write(dir.join("bundle.json"), bundle.to_string()).unwrap();

    let mut cfg = HubConfig::new(ISSUER, dir.join("data"));
    cfg.bundle_path = Some(dir.join("bundle.json"));
    cfg.clients = vec![Client {
        client_id: "app".into(),
        client_secret: None,
        redirect_uris: vec![APP_CB.into()],
        name: Some("Demo App".into()),
        audience: None,
        subject_type: SubjectType::Public,
        id_token_signed_response_alg: "EdDSA".into(),
        consent: Consent::Implied,
        ..Default::default()
    }];
    // Endpoints are left out, so the hub has to discover them.
    let attributes = attributes.iter().map(|(claim, attr)| (claim.to_string(), attr.to_string())).collect();
    cfg.upstreams = vec![Upstream { issuer: provider.issuer.clone(), authorization_endpoint: None, token_endpoint: None, jwks_uri: None, attributes, ..Upstream::telegram(BOT_ID, BOT_SECRET) }];
    let hub = Hub::open(cfg).unwrap();
    hub.put_kel(&did, log.clone()).unwrap();
    let mut w = World { app: kith_hub::router(hub.clone()), hub, provider, root, laptop, did, log };
    let alias = w.alias(TG_USER);
    w.publish(EventBody::AliasLink { alias });
    w
}

#[derive(Debug)]
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
    fn cookie(&self, name: &str) -> Option<String> {
        self.headers.get_all(header::SET_COOKIE).iter().filter_map(|v| v.to_str().ok()).map(|v| v.split(';').next().unwrap().to_string()).find(|c| c.starts_with(&format!("{name}=")) && !c.ends_with('='))
    }
}

async fn send(app: &Router, req: Request<Body>) -> Resp {
    let r = app.clone().oneshot(req).await.unwrap();
    let (status, headers) = (r.status(), r.headers().clone());
    Resp { status, headers, body: r.into_body().collect().await.unwrap().to_bytes().to_vec() }
}

async fn get_(app: &Router, uri: &str, cookie: Option<&str>) -> Resp {
    let mut b = Request::get(uri);
    if let Some(c) = cookie {
        b = b.header(header::COOKIE, c);
    }
    send(app, b.body(Body::empty()).unwrap()).await
}

async fn post_json(app: &Router, uri: &str, body: Value, bearer: Option<&str>) -> Resp {
    let mut b = Request::post(uri).header(header::CONTENT_TYPE, "application/json");
    if let Some(t) = bearer {
        b = b.header(header::AUTHORIZATION, format!("Bearer {t}"));
    }
    send(app, b.body(Body::from(body.to_string())).unwrap()).await
}

async fn post_form(app: &Router, uri: &str, form: &[(&str, &str)]) -> Resp {
    let body = form.iter().map(|(k, v)| format!("{k}={}", enc(v))).collect::<Vec<_>>().join("&");
    send(app, Request::post(uri).header(header::CONTENT_TYPE, "application/x-www-form-urlencoded").body(Body::from(body)).unwrap()).await
}

fn enc(s: &str) -> String {
    s.bytes().map(|b| if b.is_ascii_alphanumeric() || b"-._~".contains(&b) { (b as char).to_string() } else { format!("%{b:02X}") }).collect()
}

fn dec(s: &str) -> String {
    let mut out = vec![];
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            out.push(u8::from_str_radix(&s[i + 1..i + 3], 16).unwrap());
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).unwrap()
}

fn query(url: &str) -> HashMap<String, String> {
    url.split_once('?').map(|(_, q)| q).unwrap_or_default().split('&').filter_map(|kv| kv.split_once('=')).map(|(k, v)| (k.to_string(), dec(v))).collect()
}

fn page_data(html: &str) -> Value {
    let start = html.find(r#"<script id="kith-data" type="application/json">"#).unwrap() + 47;
    let end = start + html[start..].find("</script>").unwrap();
    serde_json::from_str(&html[start..end]).unwrap()
}

fn authorize_url(challenge: &str, extra: &str) -> String {
    format!(
        "/oauth/authorize?response_type=code&client_id=app&redirect_uri={}&scope={}&state=st8&nonce=n0nce&code_challenge={challenge}&code_challenge_method=S256{extra}",
        enc(APP_CB),
        enc("openid offline_access")
    )
}

fn pkce() -> (String, String) {
    let verifier = format!("{}{}", random_id(), random_id());
    let challenge = b64u(sha256(verifier.as_bytes()));
    (verifier, challenge)
}

/// The browser's trip through the provider: start at the hub, "sign in" as `sub`,
/// and come back to the hub's callback with the provider's code.
struct Trip {
    state: String,
    code: String,
    cookie: String,
}

async fn visit_provider(w: &World, request_id: &str, sub: &str, extra: &str) -> Trip {
    let r = get_(&w.app, &format!("/oauth/upstream/telegram/start?request_id={request_id}{extra}"), None).await;
    assert_eq!(r.status, StatusCode::SEE_OTHER, "{}", r.text());
    let to = r.location();
    assert!(to.starts_with(&format!("{}/auth?", w.provider.issuer)), "{to}");
    let q = query(&to);
    assert_eq!((q["response_type"].as_str(), q["client_id"].as_str(), q["scope"].as_str()), ("code", BOT_ID, "openid"));
    assert_eq!(q["redirect_uri"], format!("{ISSUER}/oauth/upstream/telegram/callback"));
    assert_eq!(q["code_challenge_method"], "S256");
    let code = random_id();
    w.provider.codes.lock().unwrap().insert(code.clone(), Issued { challenge: q["code_challenge"].clone(), nonce: q["nonce"].clone(), sub: sub.into() });
    Trip { state: q["state"].clone(), code, cookie: r.cookie("kith_upstream").expect("state cookie") }
}

async fn come_back(w: &World, t: &Trip) -> Resp {
    get_(&w.app, &format!("/oauth/upstream/telegram/callback?code={}&state={}", t.code, t.state), Some(&t.cookie)).await
}

async fn redeem(w: &World, redirect: &str, verifier: &str) -> Value {
    let q = query(redirect);
    assert_eq!(q["state"], "st8");
    post_form(&w.app, "/oauth/token", &[("grant_type", "authorization_code"), ("code", &q["code"]), ("redirect_uri", APP_CB), ("code_verifier", verifier), ("client_id", "app")]).await.json()
}

#[tokio::test]
async fn telegram_login_and_unlink() {
    let mut w = world().await;
    let (verifier, challenge) = pkce();

    // The login page offers the provider, and discovery lists it.
    let page = get_(&w.app, &authorize_url(&challenge, ""), None).await;
    let d = page_data(&page.text());
    assert_eq!(d["upstreams"], json!([{"id": "telegram", "name": "Telegram", "issuer": w.provider.issuer}]));
    assert!(d["federated"].is_null());
    let disco = get_(&w.app, "/.well-known/openid-configuration", None).await.json();
    assert_eq!(disco["kith"]["upstreams"][0]["id"], "telegram");
    let request_id = d["request_id"].as_str().unwrap();

    // Out to the provider and back: straight to the app, with a hub session.
    let trip = visit_provider(&w, request_id, TG_USER, "").await;
    let r = come_back(&w, &trip).await;
    assert_eq!(r.status, StatusCode::SEE_OTHER, "{}", r.text());
    assert!(r.location().starts_with(APP_CB));
    let session = r.cookie("kith_session").expect("session cookie");

    // Tokens say how weak the evidence was: AAL1, amr fed, no device.
    let tok = redeem(&w, &r.location(), &verifier).await;
    let id = jws::decode(tok["id_token"].as_str().unwrap()).unwrap().claims;
    assert_eq!(id["sub"], w.did);
    assert_eq!(id["acr"], "urn:kith:acr:aal1");
    assert_eq!(id["amr"], json!(["fed"]));
    let at = jws::decode(tok["access_token"].as_str().unwrap()).unwrap().claims;
    assert!(at.get("dev").is_none());
    assert_eq!(at["attrs"]["aliases"], json!([w.alias(TG_USER)]));
    // This provider is not trusted for attributes, so UserInfo is never asked.
    assert_eq!(w.provider.userinfo_calls.load(std::sync::atomic::Ordering::SeqCst), 0);

    // The callback is single use.
    assert_eq!(come_back(&w, &trip).await.status, StatusCode::BAD_REQUEST);

    // SSO works while the alias is linked…
    let again = get_(&w.app, &authorize_url(&challenge, ""), Some(&session)).await;
    assert_eq!(again.status, StatusCode::SEE_OTHER);

    // …and unlinking it ends the session and its refresh token.
    let alias = w.alias(TG_USER);
    w.publish(EventBody::AliasUnlink { alias });
    let again = get_(&w.app, &authorize_url(&challenge, ""), Some(&session)).await;
    assert_eq!(again.status, StatusCode::OK, "unlinked account's SSO session is not reused");
    let dead = post_form(&w.app, "/oauth/token", &[("grant_type", "refresh_token"), ("refresh_token", tok["refresh_token"].as_str().unwrap()), ("client_id", "app")]).await;
    assert!(dead.json()["error_description"].as_str().unwrap().contains("unlinked"), "{}", dead.text());

    // And the account can no longer sign in.
    let request_id = page_data(&again.text())["request_id"].as_str().unwrap().to_string();
    let r = come_back(&w, &visit_provider(&w, &request_id, TG_USER, "").await).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn callback_rejections() {
    let mut w = world().await;
    let (_, challenge) = pkce();
    let page = get_(&w.app, &authorize_url(&challenge, ""), None).await;
    let request_id = page_data(&page.text())["request_id"].as_str().unwrap().to_string();

    // Unknown provider, unknown request.
    assert_eq!(get_(&w.app, &format!("/oauth/upstream/google/start?request_id={request_id}"), None).await.status, StatusCode::NOT_FOUND);
    assert_eq!(get_(&w.app, "/oauth/upstream/telegram/start?request_id=nope", None).await.status, StatusCode::BAD_REQUEST);

    // Login CSRF: the callback only works in the browser that started the flow.
    let trip = visit_provider(&w, &request_id, TG_USER, "").await;
    let r = get_(&w.app, &format!("/oauth/upstream/telegram/callback?code={}&state={}", trip.code, trip.state), None).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    let trip = visit_provider(&w, &request_id, TG_USER, "").await;
    let r = get_(&w.app, &format!("/oauth/upstream/telegram/callback?code={}&state={}", trip.code, trip.state), Some("kith_upstream=someone-elses")).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);

    // A code the provider doesn't honour.
    let mut trip = visit_provider(&w, &request_id, TG_USER, "").await;
    trip.code = "forged".into();
    assert_eq!(come_back(&w, &trip).await.status, StatusCode::BAD_GATEWAY);

    // The user cancelled at the provider.
    let trip = visit_provider(&w, &request_id, TG_USER, "").await;
    let r = get_(&w.app, &format!("/oauth/upstream/telegram/callback?error=access_denied&state={}", trip.state), Some(&trip.cookie)).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);

    // A Telegram account nobody linked: the page says how to link it.
    let r = come_back(&w, &visit_provider(&w, &request_id, "999", "").await).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    assert!(r.text().contains(&w.alias("999")), "{}", r.text());
    assert!(r.cookie("kith_session").is_none());

    // Two identities link the same account: the browser must say which it means.
    let dir = std::env::temp_dir().join(format!("kith-upstream-{}", random_id()));
    let (root2, _, mut log2) = identity(&dir);
    let st2 = verify_log(&log2, &VerifyOptions::default()).unwrap();
    let mut ev = next_event(&st2, EventBody::AliasLink { alias: w.alias(TG_USER) });
    ev.sign(&root2).unwrap();
    log2.push(ev);
    w.hub.put_kel(&st2.did, log2).unwrap();
    let r = come_back(&w, &visit_provider(&w, &request_id, TG_USER, "").await).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    assert!(r.text().contains("More than one"));
    let r = come_back(&w, &visit_provider(&w, &request_id, TG_USER, &format!("&did={}", enc(&st2.did))).await).await;
    assert_eq!(r.status, StatusCode::SEE_OTHER, "{}", r.text());

    // A hint for an identity that never linked the account doesn't help.
    w.publish(EventBody::AliasUnlink { alias: w.alias(TG_USER) });
    let page = get_(&w.app, &authorize_url(&challenge, ""), None).await;
    let request_id = page_data(&page.text())["request_id"].as_str().unwrap().to_string();
    let r = come_back(&w, &visit_provider(&w, &request_id, TG_USER, &format!("&did={}", enc(&w.did))).await).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn step_up_with_totp() {
    let w = world().await;

    // Enroll TOTP from the laptop.
    let dev = w.state().device("laptop").unwrap().clone();
    let sk = SessionKey::create(&w.did, &dev, DeviceSigner::Key(&w.laptop.secret), 3600).unwrap();
    let st_tok = sk.session_token(ISSUER, json!({})).unwrap();
    let tok = post_form(&w.app, "/oauth/token", &[("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange"), ("subject_token", &st_tok), ("subject_token_type", TT_SESSION)]).await.json();
    let bearer = tok["access_token"].as_str().unwrap();
    let enrolled = post_json(&w.app, "/v1/totp/enroll", json!({}), Some(bearer)).await.json();
    let secret = totp::from_base32(enrolled["secret"].as_str().unwrap()).unwrap();
    let confirmed = post_json(&w.app, "/v1/totp/confirm", json!({"code": totp::code_at(&secret, now() - 30)}), Some(bearer)).await;
    assert_eq!(confirmed.status, StatusCode::OK, "{}", confirmed.text());

    // The app asks for AAL2; Telegram alone is AAL1, so the hub shows the login page
    // again, asking only for a one-time code.
    let (verifier, challenge) = pkce();
    let page = get_(&w.app, &authorize_url(&challenge, "&acr_values=urn%3Akith%3Aacr%3Aaal2"), None).await;
    let request_id = page_data(&page.text())["request_id"].as_str().unwrap().to_string();
    let r = come_back(&w, &visit_provider(&w, &request_id, TG_USER, "").await).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    assert!(r.cookie("kith_session").is_none(), "no session before step-up");
    let d = page_data(&r.text());
    assert_eq!(d["request_id"], request_id.as_str());
    assert_eq!((d["federated"]["did"].as_str(), d["federated"]["provider"].as_str()), (Some(w.did.as_str()), Some("Telegram")));
    let token = d["federated"]["token"].as_str().unwrap();
    let code = totp::code_at(&secret, now());

    // Knowing the request id is not enough to borrow the Telegram factor.
    let login = |challenge_id: Value, federated: Value, code: &str| {
        post_json(&w.app, "/oauth/login", json!({"request_id": request_id, "challenge_id": challenge_id, "did": w.did, "factors": [{"type": "totp", "code": code}], "federated": federated}), None)
    };
    let stolen = login(d["challenge_id"].clone(), json!("guess"), "000000").await;
    assert_eq!(stolen.status, StatusCode::UNAUTHORIZED);
    // The factor can't be submitted either.
    let forged = post_json(&w.app, "/oauth/login", json!({"request_id": request_id, "challenge_id": stolen.json()["challenge_id"], "did": w.did, "factors": [{"type": "federated", "provider": "telegram", "alias": w.alias(TG_USER)}]}), None).await;
    assert!(forged.status.is_client_error() && forged.cookie("kith_session").is_none(), "{}", forged.text());

    // Telegram + one-time code reaches AAL2.
    let page = come_back(&w, &visit_provider(&w, &request_id, TG_USER, "").await).await;
    let d = page_data(&page.text());
    assert_ne!(d["federated"]["token"], token, "each trip gets its own token");
    let stale = login(d["challenge_id"].clone(), json!(token), &code).await;
    assert_eq!(stale.status, StatusCode::UNAUTHORIZED, "the earlier trip's token is dead");
    let ok = login(stale.json()["challenge_id"].clone(), d["federated"]["token"].clone(), &code).await;
    assert_eq!(ok.status, StatusCode::OK, "{}", ok.text());
    let tok = redeem(&w, ok.json()["redirect"].as_str().unwrap(), &verifier).await;
    let id = jws::decode(tok["id_token"].as_str().unwrap()).unwrap().claims;
    assert_eq!(id["acr"], "urn:kith:acr:aal2");
    assert_eq!(id["amr"], json!(["otp", "fed", "mfa"]));
}

#[test]
fn id_token_checks() {
    let p = Upstream::telegram(BOT_ID, BOT_SECRET);
    p.validate().unwrap();
    assert_eq!(p.alias("42"), "https://oauth.telegram.org#42");
    assert_eq!(p.alias("a b#c"), "https://oauth.telegram.org#a%20b%23c");
    assert!(Upstream { issuer: "http://oauth.telegram.org".into(), ..p.clone() }.validate().is_err());
    assert!(Upstream { scope: "profile".into(), ..p.clone() }.validate().is_err());
    assert!(Upstream { id: "Tele/gram".into(), ..p.clone() }.validate().is_err());

    let t = now();
    let rsa = RsaSigner::generate().unwrap();
    let good = json!({"iss": p.issuer, "sub": "42", "aud": BOT_ID, "iat": t, "exp": t + 300, "nonce": "n"});
    let jwks = json!({"keys": [rsa.jwk()]});
    let check = |claims: &Value, nonce: &str| verify_id_token(&p, &jwks, &rsa.sign_jwt(claims).unwrap(), nonce, t);
    let with = |k: &str, v: Value| {
        let mut c = good.clone();
        c[k] = v;
        c
    };
    assert_eq!(check(&good, "n").unwrap()["sub"], "42");
    // Telegram's `aud` is the bot id; accept it as a number or in a list too.
    check(&with("aud", json!(7000000001u64)), "n").unwrap();
    check(&with("aud", json!(["other", BOT_ID])), "n").unwrap();
    check(&with("sub", json!(42)), "n").unwrap();
    check(&with("nonce", Value::Null), "n").unwrap();
    assert!(check(&good, "other").is_err(), "nonce");
    assert!(check(&with("aud", json!("another-bot")), "n").is_err(), "audience");
    assert!(check(&with("iss", json!("https://evil.example")), "n").is_err(), "issuer");
    assert!(check(&with("exp", json!(t - 3600)), "n").is_err(), "expiry");
    assert!(check(&with("exp", Value::Null), "n").is_err(), "expiry required");
    assert!(check(&with("iat", json!(t + 3600)), "n").is_err(), "issued in the future");
    assert!(check(&with("sub", json!("")), "n").is_err(), "subject");

    // Signed by a key the provider doesn't publish.
    let other = RsaSigner::generate().unwrap();
    assert!(verify_id_token(&p, &jwks, &other.sign_jwt(&good).unwrap(), "n", t).is_err());
    // Unsigned, and HMAC keyed with a public value.
    let none = format!("{}.{}.", b64u(br#"{"alg":"none"}"#), b64u(good.to_string()));
    assert!(verify_id_token(&p, &jwks, &none, "n", t).is_err());
    let hs = format!("{}.{}.{}", b64u(br#"{"alg":"HS256"}"#), b64u(good.to_string()), b64u(b"sig"));
    assert!(verify_id_token(&p, &jwks, &hs, "n", t).is_err());

    // The other algorithms Telegram can be set to: ES256, EdDSA, ES256K.
    for kty in [KeyType::P256, KeyType::Ed25519, KeyType::Secp256k1] {
        let key = SecretKey::generate(kty);
        let mut jwk = key.public().to_jwk();
        jwk["kid"] = json!("k1");
        let token = jws::sign(json!({"kid": "k1"}), &good, &key).unwrap();
        let set = json!({"keys": [rsa.jwk(), jwk]});
        verify_id_token(&p, &set, &token, "n", t).unwrap_or_else(|e| panic!("{kty:?}: {e:?}"));
        assert!(verify_id_token(&p, &jwks, &token, "n", t).is_err(), "{kty:?} key not in the set");
        // A different key under the same kid.
        let mut swapped = SecretKey::generate(kty).public().to_jwk();
        swapped["kid"] = json!("k1");
        assert!(verify_id_token(&p, &json!({"keys": [swapped]}), &token, "n", t).is_err());
    }
}

/// One trip through the provider for a fresh request, redeemed for tokens.
async fn sign_in(w: &World) -> Result<Value, Resp> {
    let (verifier, challenge) = pkce();
    let page = get_(&w.app, &authorize_url(&challenge, ""), None).await;
    let request_id = page_data(&page.text())["request_id"].as_str().unwrap().to_string();
    let r = come_back(w, &visit_provider(w, &request_id, TG_USER, "").await).await;
    if r.status != StatusCode::SEE_OTHER {
        return Err(r);
    }
    let tok = redeem(w, &r.location(), &verifier).await;
    Ok(jws::decode(tok["access_token"].as_str().unwrap()).unwrap().claims)
}

#[tokio::test]
async fn userinfo_attributes() {
    let w = world_with(&[("name", "name"), ("email", "email"), ("phone_number", "phone"), ("locale", "locale")]).await;
    let answer = |v: Value| *w.provider.userinfo.lock().unwrap() = v;

    // Listed claims become attributes; the directory's own values are not replaced,
    // unlisted claims are dropped, and group rules see the result.
    answer(json!({"sub": TG_USER, "name": "Mallory", "email": "ada@acme.test", "email_verified": true, "phone_number": "+15550100", "nickname": "mal", "locale": {"not": "plain"}}));
    let at = sign_in(&w).await.unwrap_or_else(|r| panic!("{}", r.text()));
    assert_eq!(w.provider.userinfo_calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    let attrs = &at["attrs"];
    assert_eq!((attrs["name"].as_str(), attrs["email"].as_str(), attrs["phone"].as_str()), (Some("Ada"), Some("ada@acme.test"), Some("+15550100")));
    assert!(attrs.get("nickname").is_none() && attrs.get("phone_number").is_none() && attrs.get("locale").is_none(), "{attrs}");
    assert_eq!(at["groups"], json!(["staff"]));
    assert_eq!(at["aal"], 1, "attributes never raise assurance");

    // An address the provider has not verified is not taken, so it opens no group.
    answer(json!({"sub": TG_USER, "email": "ada@acme.test", "email_verified": false, "phone_number": "+15550100", "phone_number_verified": false}));
    let at = sign_in(&w).await.unwrap_or_else(|r| panic!("{}", r.text()));
    assert!(at["attrs"].get("email").is_none() && at["attrs"].get("phone").is_none(), "{}", at["attrs"]);
    assert_eq!(at["groups"], json!([]));
    answer(json!({"sub": TG_USER, "email": "ada@acme.test"}));
    assert!(sign_in(&w).await.unwrap()["attrs"].get("email").is_none(), "email_verified must be present and true");

    // UserInfo about another account is an attack, not a detail: the login fails.
    answer(json!({"sub": "999", "email": "ceo@acme.test", "email_verified": true}));
    let r = sign_in(&w).await.expect_err("sub mismatch");
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    assert!(r.text().contains("another account"), "{}", r.text());

    // A provider can never be trusted for what the KEL or the login decides.
    let p = Upstream::telegram(BOT_ID, BOT_SECRET);
    for reserved in ["aliases", "aal", "email_verified"] {
        assert!(Upstream { attributes: [("x".to_string(), reserved.to_string())].into(), ..p.clone() }.validate().is_err(), "{reserved}");
    }
}
