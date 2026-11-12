//! Browser sign-up (spec §7.11): a passkey and a recovery key make an identity, and
//! the passkey then signs in through OpenID Connect by its handle. Real WebAuthn
//! assertions come from the software authenticator.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;

use kith_core::kel::{verify_log, DeviceKind, EventBody};
use kith_core::keys::{KeyType, LocalSigner, VerifyOptions};
use kith_core::policy::SignerPolicy;
use kith_core::util::{b64u, b64u_decode, random_id, sha256};
use kith_core::webauthn;
use kith_core::work::work_bits;
use kith_hub::oidc::{Client, Consent};
use kith_hub::{Hub, HubConfig, RateLimit};

const ISSUER: &str = "http://localhost:7777";
const CB: &str = "http://localhost:3000/cb";

struct World {
    app: Router,
    hub: Arc<Hub>,
}

fn world(configure: impl FnOnce(&mut HubConfig)) -> World {
    let dir = std::env::temp_dir().join(format!("kith-signup-{}", random_id()));
    let mut cfg = HubConfig::new(ISSUER, dir);
    cfg.clients = vec![Client {
        client_id: "app".into(),
        redirect_uris: vec![CB.into()],
        name: Some("Demo App".into()),
        consent: Consent::Implied,
        ..Default::default()
    }];
    configure(&mut cfg);
    let hub = Hub::open(cfg).unwrap();
    World {
        app: kith_hub::router(hub.clone()),
        hub,
    }
}

fn open() -> World {
    world(|c| c.signup = true)
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

async fn send(app: &Router, req: Request<Body>) -> Resp {
    let r = app.clone().oneshot(req).await.unwrap();
    let status = r.status();
    Resp {
        status,
        body: r.into_body().collect().await.unwrap().to_bytes().to_vec(),
    }
}

async fn get(app: &Router, uri: &str) -> Resp {
    send(app, Request::get(uri).body(Body::empty()).unwrap()).await
}

async fn post(app: &Router, uri: &str, body: Value) -> Resp {
    send(
        app,
        Request::post(uri)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .unwrap(),
    )
    .await
}

fn page_data(html: &str) -> Value {
    let start = html
        .find(r#"<script id="kith-data" type="application/json">"#)
        .unwrap()
        + 47;
    let end = start + html[start..].find("</script>").unwrap();
    serde_json::from_str(&html[start..end]).unwrap()
}

/// What the browser does up to the point of signing: a passkey and a recovery key.
struct Browser {
    passkey: LocalSigner,
    recovery: LocalSigner,
}

impl Browser {
    fn new() -> Self {
        Browser {
            passkey: LocalSigner::generate(KeyType::P256),
            recovery: LocalSigner::generate(KeyType::P256),
        }
    }

    async fn begin(&self, w: &World) -> Value {
        let r = post(&w.app, "/v1/signup", json!({})).await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.text());
        r.json()
    }

    async fn propose(&self, w: &World, id: &str) -> Resp {
        post(
            &w.app,
            &format!("/v1/signup/{id}/key"),
            json!({"key": self.passkey.id, "recovery_key": self.recovery.id}),
        )
        .await
    }

    fn sign(&self, message: &str, origin: &str) -> Value {
        serde_json::to_value(
            webauthn::soft_sign_message(&self.passkey, "localhost", origin, message.as_bytes())
                .unwrap(),
        )
        .unwrap()
    }

    /// The whole flow; returns the new DID and the handle the passkey was made with.
    async fn sign_up(&self, w: &World) -> (String, String) {
        let begun = self.begin(w).await;
        let id = begun["id"].as_str().unwrap();
        let proposed = self.propose(w, id).await;
        assert_eq!(proposed.status, StatusCode::OK, "{}", proposed.text());
        let message = proposed.json()["message"].as_str().unwrap().to_string();
        let done = post(
            &w.app,
            &format!("/v1/signup/{id}/sig"),
            json!({"sig": self.sign(&message, ISSUER)}),
        )
        .await;
        assert_eq!(done.status, StatusCode::OK, "{}", done.text());
        (
            done.json()["did"].as_str().unwrap().to_string(),
            begun["handle"].as_str().unwrap().to_string(),
        )
    }
}

#[tokio::test]
async fn sign_up_makes_an_identity_the_passkey_controls() {
    let w = open();
    let b = Browser::new();
    let (did, _) = b.sign_up(&w).await;

    let log = w.hub.get_kel(&did).expect("the log is stored");
    let st = verify_log(&log, &VerifyOptions::default()).unwrap();
    assert_eq!(st.did, did);
    assert_eq!(
        st.manage,
        SignerPolicy::single(&b.passkey.id),
        "the passkey manages the identity"
    );
    let EventBody::Inception { next, .. } = &log[0].body else {
        panic!("not an inception")
    };
    assert_eq!(
        next,
        &SignerPolicy::single(&b.recovery.id).digest(),
        "the recovery key is the pre-rotation commitment"
    );
    assert_eq!(st.devices.len(), 1);
    let device = st.devices.values().next().unwrap();
    assert_eq!(
        (device.kind, device.aal, device.key.as_str()),
        (DeviceKind::Passkey, 2, b.passkey.id.as_str())
    );
    assert_eq!(device.rp_id.as_deref(), Some("localhost"));
    // The key log is public; nothing about the person goes into it.
    assert_eq!(device.name, "passkey");
}

#[tokio::test]
async fn the_new_passkey_signs_in_by_its_handle() {
    let w = open();
    let b = Browser::new();
    let (did, handle) = b.sign_up(&w).await;
    let (nonce, bits) = mine(&did, 12);
    assert_eq!(
        post(&w.app, "/v1/work", json!({"did": did, "nonce": nonce}))
            .await
            .status,
        StatusCode::OK
    );

    let challenge = b64u(sha256(b"verifier-verifier-verifier-verifier-1234"));
    let url = format!("/oauth/authorize?response_type=code&client_id=app&redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fcb&scope=openid%20work&state=s&nonce=n&code_challenge={challenge}&code_challenge_method=S256");
    let page = get(&w.app, &url).await;
    assert_eq!(page.status, StatusCode::OK);
    let d = page_data(&page.text());
    assert_eq!(
        d["signup"], true,
        "the login page offers to create an account"
    );

    let (data, sig) = webauthn::soft_assert(
        &b.passkey.secret,
        "localhost",
        ISSUER,
        &sha256(d["message"].as_str().unwrap().as_bytes()),
        true,
        1,
    )
    .unwrap();
    let factor = json!({"type": "webauthn", "authenticator_data": data.authenticator_data, "client_data_json": data.client_data_json, "signature": b64u(sig)});

    // The handle is a user handle, not an identity: it's what the browser has.
    assert!(handle.starts_with("h_"));
    let ok = post(&w.app, "/oauth/login", json!({"request_id": d["request_id"], "challenge_id": d["challenge_id"], "did": handle, "factors": [factor]})).await;
    assert_eq!(ok.status, StatusCode::OK, "{}", ok.text());
    let redirect = ok.json()["redirect"].as_str().unwrap().to_string();
    assert!(
        redirect.starts_with(CB) && redirect.contains("code="),
        "{redirect}"
    );

    let code = redirect
        .split("code=")
        .nth(1)
        .unwrap()
        .split('&')
        .next()
        .unwrap();
    let form = format!("grant_type=authorization_code&code={code}&redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fcb&client_id=app&code_verifier=verifier-verifier-verifier-verifier-1234");
    let tok = send(
        &w.app,
        Request::post("/oauth/token")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(form))
            .unwrap(),
    )
    .await;
    assert_eq!(tok.status, StatusCode::OK, "{}", tok.text());
    let id_token = tok.json()["id_token"].as_str().unwrap().to_string();
    let claims: Value =
        serde_json::from_slice(&b64u_decode(id_token.split('.').nth(1).unwrap()).unwrap()).unwrap();
    assert_eq!(claims["sub"], did, "apps see the DID, never the handle");
    assert_eq!(claims["acr"], "urn:kith:acr:aal2");
    assert_eq!(
        claims["work"], bits,
        "the work spent on the account reaches the app"
    );

    // A handle nobody was given is just an unknown identity.
    let page = get(&w.app, &url).await;
    let d = page_data(&page.text());
    let (data, sig) = webauthn::soft_assert(
        &b.passkey.secret,
        "localhost",
        ISSUER,
        &sha256(d["message"].as_str().unwrap().as_bytes()),
        true,
        1,
    )
    .unwrap();
    let factor = json!({"type": "webauthn", "authenticator_data": data.authenticator_data, "client_data_json": data.client_data_json, "signature": b64u(sig)});
    let no = post(&w.app, "/oauth/login", json!({"request_id": d["request_id"], "challenge_id": d["challenge_id"], "did": "h_unknown", "factors": [factor]})).await;
    assert_eq!(no.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn sign_up_is_closed_unless_switched_on() {
    let w = world(|_| {});
    assert_eq!(get(&w.app, "/signup").await.status, StatusCode::NOT_FOUND);
    assert_eq!(
        post(&w.app, "/v1/signup", json!({})).await.status,
        StatusCode::NOT_FOUND
    );
    let page = get(&w.app, "/oauth/authorize?response_type=code&client_id=app&redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fcb&scope=openid&code_challenge=x&code_challenge_method=S256").await;
    assert_eq!(page_data(&page.text())["signup"], false);
}

#[tokio::test]
async fn the_signup_page_is_served_with_a_strict_csp() {
    let w = open();
    let r = w
        .app
        .clone()
        .oneshot(Request::get("/signup").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let csp = r.headers()[header::CONTENT_SECURITY_POLICY]
        .to_str()
        .unwrap()
        .to_string();
    assert!(
        csp.contains("script-src 'nonce-")
            && csp.contains("default-src 'none'")
            && csp.contains("frame-ancestors 'none'"),
        "{csp}"
    );
    let html =
        String::from_utf8(r.into_body().collect().await.unwrap().to_bytes().to_vec()).unwrap();
    assert_eq!(page_data(&html)["rp_id"], "localhost");
}

#[tokio::test]
async fn only_the_new_passkey_can_sign_the_inception() {
    let w = open();
    let b = Browser::new();
    let begun = b.begin(&w).await;
    let id = begun["id"].as_str().unwrap();
    let sig_url = format!("/v1/signup/{id}/sig");

    // Nothing to sign before a passkey is submitted.
    let early = post(&w.app, &sig_url, json!({"sig": b.sign("anything", ISSUER)})).await;
    assert_eq!(early.status, StatusCode::BAD_REQUEST);

    let message = b.propose(&w, id).await.json()["message"]
        .as_str()
        .unwrap()
        .to_string();
    // A passkey can't be submitted twice.
    assert_eq!(b.propose(&w, id).await.status, StatusCode::CONFLICT);

    let other = Browser::new();
    for (what, sig) in [
        ("another passkey", other.sign(&message, ISSUER)),
        ("another origin", b.sign(&message, "https://evil.example")),
        ("another message", b.sign("not the inception", ISSUER)),
    ] {
        let r = post(&w.app, &sig_url, json!({"sig": sig})).await;
        assert!(
            r.status.is_client_error(),
            "{what} was accepted: {}",
            r.text()
        );
    }
    // Still signable by the right passkey after the failed attempts.
    let ok = post(&w.app, &sig_url, json!({"sig": b.sign(&message, ISSUER)})).await;
    assert_eq!(ok.status, StatusCode::OK, "{}", ok.text());
    // And only once.
    assert_eq!(
        post(&w.app, &sig_url, json!({"sig": b.sign(&message, ISSUER)}))
            .await
            .status,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn keys_are_checked_before_an_inception_is_built() {
    let w = open();
    let b = Browser::new();
    let id = b.begin(&w).await["id"].as_str().unwrap().to_string();
    let url = format!("/v1/signup/{id}/key");

    let ed25519 = LocalSigner::generate(KeyType::Ed25519).id;
    assert_eq!(
        post(
            &w.app,
            &url,
            json!({"key": ed25519, "recovery_key": b.recovery.id})
        )
        .await
        .status,
        StatusCode::BAD_REQUEST,
        "a passkey must be P-256"
    );
    assert_eq!(
        post(
            &w.app,
            &url,
            json!({"key": b.passkey.id, "recovery_key": b.passkey.id})
        )
        .await
        .status,
        StatusCode::BAD_REQUEST,
        "the recovery key must differ"
    );
    assert_eq!(
        post(
            &w.app,
            &url,
            json!({"key": b.passkey.id, "recovery_key": "not a key"})
        )
        .await
        .status,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        post(
            &w.app,
            "/v1/signup/unknown/key",
            json!({"key": b.passkey.id, "recovery_key": b.recovery.id})
        )
        .await
        .status,
        StatusCode::NOT_FOUND
    );
    // None of that used up the sign-up.
    assert_eq!(b.propose(&w, &id).await.status, StatusCode::OK);
}

#[tokio::test]
async fn sign_ups_are_rate_limited() {
    let w = world(|c| {
        c.signup = true;
        c.signup_limit = RateLimit {
            max: 2,
            window_secs: 3600,
        };
    });
    for _ in 0..2 {
        assert_eq!(
            post(&w.app, "/v1/signup", json!({})).await.status,
            StatusCode::OK
        );
    }
    let r = post(&w.app, "/v1/signup", json!({})).await;
    assert_eq!(r.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(r.json()["error"], "rate_limited");
}

#[tokio::test]
async fn accounts_survive_a_restart() {
    let dir = std::env::temp_dir().join(format!("kith-signup-{}", random_id()));
    let mut cfg = HubConfig::new(ISSUER, &dir);
    cfg.signup = true;
    cfg.clients = vec![Client {
        client_id: "app".into(),
        redirect_uris: vec![CB.into()],
        consent: Consent::Implied,
        ..Default::default()
    }];
    let hub = Hub::open(cfg.clone()).unwrap();
    let w = World {
        app: kith_hub::router(hub.clone()),
        hub,
    };
    let (did, handle) = Browser::new().sign_up(&w).await;
    drop(w);

    let hub = Hub::open(cfg).unwrap();
    assert!(hub.get_kel(&did).is_some(), "the key log is on disk");
    assert_eq!(
        hub.store.did_for_handle(&handle).unwrap().as_deref(),
        Some(did.as_str())
    );
}

#[tokio::test]
async fn a_bad_recovery_key_is_refused_before_a_passkey_exists() {
    let w = world(|c| c.signup = true);
    for bad in ["", "not a key", "did:key:zQ3", "did:kith:abc"] {
        let r = post(&w.app, "/v1/signup/check", json!({"recovery_key": bad})).await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "{bad}");
        let r = post(&w.app, "/v1/signup", json!({"recovery_key": bad})).await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "{bad}");
    }
    // A refused key doesn't use up a rate-limit slot or leave an attempt behind.
    let good = LocalSigner::generate(KeyType::Ed25519).id;
    let r = post(&w.app, "/v1/signup/check", json!({"recovery_key": good})).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    assert_eq!(
        post(&w.app, "/v1/signup", json!({"recovery_key": good}))
            .await
            .status,
        StatusCode::OK
    );
}

/// The first nonce giving at least `want` bits (what a miner does).
fn mine(did: &str, want: u32) -> (u64, u32) {
    (0..)
        .map(|n| (n, work_bits(did, n)))
        .find(|(_, b)| *b >= want)
        .unwrap()
}

#[tokio::test]
async fn work_only_raises_an_accounts_work_and_belongs_to_one_identity() {
    let w = open();
    let (did, _) = Browser::new().sign_up(&w).await;
    let (other, _) = Browser::new().sign_up(&w).await;
    assert_eq!(
        get(&w.app, &format!("/v1/work/{did}")).await.json()["work"],
        0
    );

    let (n12, b12) = mine(&did, 12);
    let r = post(&w.app, "/v1/work", json!({"did": did, "nonce": n12})).await;
    assert_eq!(
        (r.status, r.json()["work"].as_u64()),
        (StatusCode::OK, Some(b12 as u64)),
        "{}",
        r.text()
    );

    // A better proof raises it; a worse one never lowers it.
    let (n16, b16) = mine(&did, 16);
    assert_eq!(
        post(&w.app, "/v1/work", json!({"did": did, "nonce": n16}))
            .await
            .json()["work"],
        b16
    );
    let r = post(&w.app, "/v1/work", json!({"did": did, "nonce": n12})).await;
    assert_eq!(r.json()["work"], b16, "{}", r.text());
    let on_record = get(&w.app, &format!("/v1/work/{did}")).await.json();
    assert_eq!(
        (on_record["work"].as_u64(), on_record["nonce"].as_u64()),
        (Some(b16 as u64), Some(n16))
    );

    // Too little work, an unknown identity, and another identity's proof all fail.
    assert_eq!(
        post(
            &w.app,
            "/v1/work",
            json!({"did": did, "nonce": (0..).find(|n| work_bits(&did, *n) < 4).unwrap()})
        )
        .await
        .status,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        post(
            &w.app,
            "/v1/work",
            json!({"did": "did:kith:nobody", "nonce": n12})
        )
        .await
        .status,
        StatusCode::NOT_FOUND
    );
    if work_bits(&other, n16) < 12 {
        assert_eq!(
            post(&w.app, "/v1/work", json!({"did": other, "nonce": n16}))
                .await
                .status,
            StatusCode::BAD_REQUEST,
            "a proof is for one identity"
        );
    }
    assert_eq!(
        get(&w.app, &format!("/v1/work/{other}")).await.json()["work"],
        0
    );
}

/// `oneshot` with the response headers kept, for the session cookie.
async fn send_h(app: &Router, req: Request<Body>) -> (Resp, axum::http::HeaderMap) {
    let r = app.clone().oneshot(req).await.unwrap();
    let (parts, body) = r.into_parts();
    let body = body.collect().await.unwrap().to_bytes().to_vec();
    (
        Resp {
            status: parts.status,
            body,
        },
        parts.headers,
    )
}

fn with_cookie(uri: &str, cookie: &str) -> Request<Body> {
    Request::get(uri)
        .header(header::COOKIE, cookie)
        .body(Body::empty())
        .unwrap()
}

/// What the account page posts after the passkey answers its challenge.
fn account_login(b: &Browser, d: &Value, did: &str, message: &str) -> Value {
    let (data, sig) = webauthn::soft_assert(
        &b.passkey.secret,
        "localhost",
        ISSUER,
        &sha256(message.as_bytes()),
        true,
        1,
    )
    .unwrap();
    json!({
        "challenge_id": d["challenge_id"],
        "did": did,
        "factors": [{"type": "webauthn", "authenticator_data": data.authenticator_data, "client_data_json": data.client_data_json, "signature": b64u(sig)}],
    })
}

#[tokio::test]
async fn the_account_page_signs_in_with_the_passkey_and_shows_who_you_are() {
    let w = open();
    let b = Browser::new();
    let (did, handle) = b.sign_up(&w).await;

    let page = get(&w.app, "/whoami").await;
    assert_eq!(page.status, StatusCode::OK);
    let d = page_data(&page.text());
    assert_eq!(d["signed_in"], false);
    assert_eq!(d["signup"], true);
    assert_eq!(d["rp_id"], "localhost");
    assert!(d.get("did").is_none(), "nobody is named before sign-in");

    let body = account_login(&b, &d, &handle, d["message"].as_str().unwrap());
    let (ok, headers) = send_h(
        &w.app,
        Request::post("/whoami")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .unwrap(),
    )
    .await;
    assert_eq!(ok.status, StatusCode::OK, "{}", ok.text());
    assert_eq!(ok.json()["did"], did);
    let set = headers[header::SET_COOKIE].to_str().unwrap();
    assert!(
        set.starts_with("kith_session=") && set.contains("HttpOnly"),
        "{set}"
    );
    let cookie = set.split(';').next().unwrap().to_string();

    let (page, _) = send_h(&w.app, with_cookie("/whoami", &cookie)).await;
    let d = page_data(&page.text());
    assert_eq!(d["signed_in"], true);
    assert_eq!(d["did"], did);
    assert_eq!(d["session"]["aal"], 2, "a user-verified passkey");
    assert_eq!(d["devices"].as_array().unwrap().len(), 1);
    assert_eq!(d["devices"][0]["current"], true);
    assert_eq!(d["devices"][0]["kind"], "passkey");
    assert_eq!(d["work"], 0);
    assert!(
        !page.text().contains(&handle),
        "the handle stays between the passkey and the hub"
    );

    // The home page sends a signed-in visitor here instead of to sign-up.
    let (home, headers) = send_h(&w.app, with_cookie("/", &cookie)).await;
    assert!(home.status.is_redirection());
    assert_eq!(headers[header::LOCATION], "/whoami");
    let (home, headers) = send_h(&w.app, Request::get("/").body(Body::empty()).unwrap()).await;
    assert!(home.status.is_redirection());
    assert_eq!(headers[header::LOCATION], "/signup");

    // It is the hub session apps reuse: an app's sign-in goes straight through.
    let challenge = b64u(sha256(b"verifier-verifier-verifier-verifier-1234"));
    let url = format!("/oauth/authorize?response_type=code&client_id=app&redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fcb&scope=openid&code_challenge={challenge}&code_challenge_method=S256");
    let (sso, headers) = send_h(&w.app, with_cookie(&url, &cookie)).await;
    assert!(sso.status.is_redirection(), "{}", sso.text());
    let to = headers[header::LOCATION].to_str().unwrap();
    assert!(to.starts_with(CB) && to.contains("code="), "{to}");

    // Signing out ends it.
    send_h(&w.app, with_cookie("/oauth/logout", &cookie)).await;
    let (page, _) = send_h(&w.app, with_cookie("/whoami", &cookie)).await;
    assert_eq!(page_data(&page.text())["signed_in"], false);
}

#[tokio::test]
async fn login_sends_you_to_the_account_page() {
    let w = open();
    let (resp, headers) =
        send_h(&w.app, Request::get("/login").body(Body::empty()).unwrap()).await;
    assert!(resp.status.is_redirection(), "{}", resp.status);
    assert_eq!(headers[header::LOCATION], "/whoami");
}

#[tokio::test]
async fn the_account_page_turns_away_a_bad_assertion() {
    let w = open();
    let b = Browser::new();
    let (_, handle) = b.sign_up(&w).await;
    let d = page_data(&get(&w.app, "/whoami").await.text());

    // Signed over something other than the challenge.
    let body = account_login(&b, &d, &handle, "something else");
    let (no, headers) = send_h(
        &w.app,
        Request::post("/whoami")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .unwrap(),
    )
    .await;
    assert_eq!(no.status, StatusCode::UNAUTHORIZED);
    assert!(headers.get(header::SET_COOKIE).is_none());
    let retry = no.json();
    assert!(
        retry["challenge_id"].is_string() && retry["message"].is_string(),
        "a fresh challenge to retry with"
    );

    // Another identity's passkey doesn't sign in as this one.
    let stranger = Browser::new();
    let body = account_login(
        &stranger,
        &retry,
        &handle,
        retry["message"].as_str().unwrap(),
    );
    let no = post(&w.app, "/whoami", body).await;
    assert_eq!(no.status, StatusCode::UNAUTHORIZED);

    // A used challenge doesn't work twice.
    let d = page_data(&get(&w.app, "/whoami").await.text());
    let body = account_login(&b, &d, &handle, d["message"].as_str().unwrap());
    assert_eq!(
        post(&w.app, "/whoami", body.clone()).await.status,
        StatusCode::OK
    );
    assert_eq!(
        post(&w.app, "/whoami", body).await.status,
        StatusCode::UNAUTHORIZED
    );

    // A cookie the hub never issued is just signed out.
    let (page, _) = send_h(&w.app, with_cookie("/whoami", "kith_session=forged")).await;
    assert_eq!(page_data(&page.text())["signed_in"], false);
}
