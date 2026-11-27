//! Signing in with a phone (spec §7.15): the login page shows a QR code, a phone that
//! scans it signs in with its passkey, and the page that showed the code finishes the
//! sign-in with a secret only it holds. Real WebAuthn assertions come from the software
//! authenticator.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;

use kith_core::keys::{KeyType, LocalSigner};
use kith_core::util::{b64u, random_id, sha256};
use kith_core::webauthn;
use kith_hub::oidc::{Client, Consent};
use kith_hub::{Hub, HubConfig};

const ISSUER: &str = "http://localhost:7777";
const CB: &str = "http://localhost:3000/cb";
const LAPTOP: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36";

struct World {
    app: Router,
    _hub: Arc<Hub>,
}

fn world() -> World {
    world_with(|_| {})
}

fn world_with(configure: impl FnOnce(&mut HubConfig)) -> World {
    let dir = std::env::temp_dir().join(format!("kith-handoff-{}", random_id()));
    let mut cfg = HubConfig::new(ISSUER, dir);
    cfg.signup = true;
    cfg.clients = vec![
        Client {
            client_id: "app".into(),
            redirect_uris: vec![CB.into()],
            name: Some("Demo App".into()),
            consent: Consent::Implied,
            ..Default::default()
        },
        // Wants a hardware key on the computer itself.
        Client {
            client_id: "vault".into(),
            redirect_uris: vec![CB.into()],
            name: Some("Vault".into()),
            consent: Consent::Implied,
            min_aal: Some(3),
            ..Default::default()
        },
    ];
    configure(&mut cfg);
    let hub = Hub::open(cfg).unwrap();
    World {
        app: kith_hub::router(hub.clone()),
        _hub: hub,
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
    fn cookie(&self) -> Option<String> {
        let c = self.headers.get(header::SET_COOKIE)?.to_str().ok()?;
        Some(c.split(';').next()?.to_string())
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
    let mut r = Request::get(uri).header(header::USER_AGENT, LAPTOP);
    if let Some(c) = cookie {
        r = r.header(header::COOKIE, c);
    }
    send(app, r.body(Body::empty()).unwrap()).await
}

async fn post(app: &Router, uri: &str, body: Value) -> Resp {
    let r = Request::post(uri)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::USER_AGENT, LAPTOP);
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

/// What a browser's passkey sends for `message`, as a login factor.
fn factor(passkey: &LocalSigner, message: &str) -> Value {
    let (data, sig) = webauthn::soft_assert(
        &passkey.secret,
        "localhost",
        ISSUER,
        &sha256(message.as_bytes()),
        true,
        1,
    )
    .unwrap();
    json!({"type": "webauthn", "authenticator_data": data.authenticator_data, "client_data_json": data.client_data_json, "signature": b64u(sig)})
}

/// An account made at /signup: its DID, the handle its passkey carries, and the passkey.
async fn sign_up(w: &World) -> (String, String, LocalSigner) {
    let passkey = LocalSigner::generate(KeyType::P256);
    let recovery = LocalSigner::generate(KeyType::P256);
    let begun = post(&w.app, "/v1/signup", json!({})).await.json();
    let id = begun["id"].as_str().unwrap();
    let handle = begun["handle"].as_str().unwrap().to_string();
    let proposed = post(
        &w.app,
        &format!("/v1/signup/{id}/key"),
        json!({"key": passkey.id, "recovery_key": recovery.id}),
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
    let done = post(&w.app, &format!("/v1/signup/{id}/sig"), json!({"sig": sig})).await;
    assert_eq!(done.status, StatusCode::OK, "{}", done.text());
    let did = done.json()["did"].as_str().unwrap().to_string();
    (did, handle, passkey)
}

/// The computer opens the login page for `client` and asks for a QR code.
async fn computer(w: &World, client: &str) -> (String, Value) {
    let url = format!("/oauth/authorize?response_type=code&client_id={client}&redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fcb&scope=openid&state=s&code_challenge=x&code_challenge_method=S256");
    let page = get(&w.app, &url, None).await;
    assert_eq!(page.status, StatusCode::OK);
    let request_id = page_data(&page.text())["request_id"]
        .as_str()
        .unwrap()
        .to_string();
    let r = post(&w.app, "/v1/handoff", json!({"request_id": request_id})).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    (request_id, r.json())
}

async fn state(w: &World, id: &str) -> String {
    let s = get(&w.app, &format!("/v1/handoff/{id}"), None).await.json();
    s["state"].as_str().unwrap().to_string()
}

/// The phone opens the link and signs in with its passkey.
async fn phone_approves(w: &World, id: &str, handle: &str, passkey: &LocalSigner) -> Resp {
    let page = get(&w.app, &format!("/handoff/{id}"), None).await;
    assert_eq!(page.status, StatusCode::OK);
    let d = page_data(&page.text());
    let message = d["message"].as_str().unwrap();
    post(
        &w.app,
        &format!("/v1/handoff/{id}/approve"),
        json!({"challenge_id": d["challenge_id"], "did": handle, "factors": [factor(passkey, message)]}),
    )
    .await
}

#[tokio::test]
async fn a_phone_signs_the_computer_in() {
    let w = world();
    let (did, handle, passkey) = sign_up(&w).await;
    let (_, h) = computer(&w, "app").await;
    let id = h["id"].as_str().unwrap();
    assert_eq!(h["url"], format!("{ISSUER}/handoff/{id}"));
    assert!(h["secret"].as_str().unwrap().len() >= 20);
    assert_eq!(state(&w, id).await, "waiting");

    // The QR code is of the link, and only while the handoff is open.
    let qr = get(&w.app, &format!("/handoff/{id}/qr.svg"), None).await;
    assert_eq!(qr.status, StatusCode::OK);
    assert_eq!(qr.headers[header::CONTENT_TYPE], "image/svg+xml");

    // The phone's page names the app and the computer before anything is signed.
    let page = get(&w.app, &format!("/handoff/{id}"), None).await;
    let d = page_data(&page.text());
    assert_eq!(d["client_name"], "Demo App");
    assert_eq!(d["browser"], "Chrome on macOS");
    assert!(d["message"]
        .as_str()
        .unwrap()
        .contains(&format!("/handoff/{id}")));
    assert_eq!(
        state(&w, id).await,
        "scanned",
        "the computer learns the code was scanned"
    );

    let ok = phone_approves(&w, id, &handle, &passkey).await;
    assert_eq!(ok.status, StatusCode::OK, "{}", ok.text());
    assert_eq!(ok.json()["state"], "approved");
    assert!(
        ok.cookie().is_none(),
        "the phone is not signed in by approving"
    );
    assert_eq!(state(&w, id).await, "approved");

    // Only the page that opened the handoff can finish it.
    let wrong = post(
        &w.app,
        &format!("/v1/handoff/{id}/finish"),
        json!({"secret": "guess"}),
    )
    .await;
    assert_eq!(wrong.status, StatusCode::UNAUTHORIZED);

    let done = post(
        &w.app,
        &format!("/v1/handoff/{id}/finish"),
        json!({"secret": h["secret"]}),
    )
    .await;
    assert_eq!(done.status, StatusCode::OK, "{}", done.text());
    let redirect = done.json()["redirect"].as_str().unwrap().to_string();
    assert!(
        redirect.starts_with(CB) && redirect.contains("code="),
        "{redirect}"
    );
    let cookie = done.cookie().expect("a hub session for the computer");

    // The computer's session belongs to the identity, signed in by the phone's passkey.
    let me = get(&w.app, "/whoami", Some(&cookie)).await;
    let m = page_data(&me.text());
    assert_eq!(m["signed_in"], true);
    assert_eq!(m["did"], did);
    assert_eq!(m["session"]["aal"], 2);

    // Once.
    let again = post(
        &w.app,
        &format!("/v1/handoff/{id}/finish"),
        json!({"secret": h["secret"]}),
    )
    .await;
    assert_eq!(again.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn the_computer_waits_until_the_phone_approves() {
    let w = world();
    let (_, h) = computer(&w, "app").await;
    let id = h["id"].as_str().unwrap();
    let early = post(
        &w.app,
        &format!("/v1/handoff/{id}/finish"),
        json!({"secret": h["secret"]}),
    )
    .await;
    assert_eq!(early.status, StatusCode::CONFLICT, "{}", early.text());
    assert_eq!(
        state(&w, id).await,
        "waiting",
        "and it can still be approved"
    );
}

#[tokio::test]
async fn the_phone_can_say_no() {
    let w = world();
    let (_, handle, passkey) = sign_up(&w).await;
    let (_, h) = computer(&w, "app").await;
    let id = h["id"].as_str().unwrap();
    let no = post(&w.app, &format!("/v1/handoff/{id}/deny"), json!({})).await;
    assert_eq!(no.status, StatusCode::OK, "{}", no.text());
    assert_eq!(state(&w, id).await, "denied");

    let late = phone_approves(&w, id, &handle, &passkey).await;
    assert_eq!(late.status, StatusCode::CONFLICT, "{}", late.text());
    let fin = post(
        &w.app,
        &format!("/v1/handoff/{id}/finish"),
        json!({"secret": h["secret"]}),
    )
    .await;
    assert_eq!(fin.status, StatusCode::CONFLICT);
}

#[tokio::test]
async fn an_assertion_for_another_page_does_not_approve() {
    let w = world();
    let (_, handle, passkey) = sign_up(&w).await;
    let (_, first) = computer(&w, "app").await;
    let (_, second) = computer(&w, "app").await;
    let (a, b) = (
        first["id"].as_str().unwrap(),
        second["id"].as_str().unwrap(),
    );

    // Signed for the first handoff's page, sent to the second.
    let d = page_data(&get(&w.app, &format!("/handoff/{a}"), None).await.text());
    let message = d["message"].as_str().unwrap();
    let r = post(
        &w.app,
        &format!("/v1/handoff/{b}/approve"),
        json!({"challenge_id": d["challenge_id"], "did": handle, "factors": [factor(&passkey, message)]}),
    )
    .await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED, "{}", r.text());

    // The login page's own challenge isn't one either.
    let login = get(&w.app, "/oauth/authorize?response_type=code&client_id=app&redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fcb&scope=openid&code_challenge=x&code_challenge_method=S256", None).await;
    let l = page_data(&login.text());
    let r = post(
        &w.app,
        &format!("/v1/handoff/{b}/approve"),
        json!({"challenge_id": l["challenge_id"], "did": handle, "factors": [factor(&passkey, l["message"].as_str().unwrap())]}),
    )
    .await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED, "{}", r.text());
    assert_eq!(state(&w, b).await, "waiting");
}

#[tokio::test]
async fn an_app_that_wants_a_hardware_key_here_is_not_signed_in_by_phone() {
    let w = world();
    let (_, handle, passkey) = sign_up(&w).await;
    let (_, h) = computer(&w, "vault").await;
    let id = h["id"].as_str().unwrap();
    let r = phone_approves(&w, id, &handle, &passkey).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED, "{}", r.text());
    assert_eq!(r.json()["error"], "step_up_required");
    assert_eq!(state(&w, id).await, "scanned");
}

#[tokio::test]
async fn the_account_page_signs_in_by_phone_too() {
    let w = world();
    let (did, handle, passkey) = sign_up(&w).await;
    let r = post(&w.app, "/v1/handoff", json!({})).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    let h = r.json();
    let id = h["id"].as_str().unwrap();
    let d = page_data(&get(&w.app, &format!("/handoff/{id}"), None).await.text());
    assert_eq!(
        d["client_name"],
        Value::Null,
        "no app: the account page itself"
    );

    let ok = phone_approves(&w, id, &handle, &passkey).await;
    assert_eq!(ok.status, StatusCode::OK, "{}", ok.text());
    let done = post(
        &w.app,
        &format!("/v1/handoff/{id}/finish"),
        json!({"secret": h["secret"]}),
    )
    .await;
    assert_eq!(done.status, StatusCode::OK, "{}", done.text());
    assert_eq!(done.json()["redirect"], "/whoami");
    let me = get(&w.app, "/whoami", done.cookie().as_deref()).await;
    assert_eq!(page_data(&me.text())["did"], did);
}

#[tokio::test]
async fn unknown_handoffs_and_requests() {
    let w = world();
    let r = post(&w.app, "/v1/handoff", json!({"request_id": "nope"})).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST, "{}", r.text());
    assert_eq!(
        get(&w.app, "/v1/handoff/nope", None).await.status,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        get(&w.app, "/handoff/nope", None).await.status,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        get(&w.app, "/handoff/nope/qr.svg", None).await.status,
        StatusCode::NOT_FOUND
    );
}

/// Behind CloudFront (spec §7.9) the phone's page shows the computer's address and the
/// phone's own as the visitors', not the edges they came through.
#[tokio::test]
async fn behind_cloudfront_the_page_shows_the_visitors_addresses() {
    const SECRET: &str = "0123456789abcdef0123456789abcdef";
    let w = world_with(|cfg| {
        cfg.behind_proxy = true;
        cfg.cloudfront_secrets = vec![SECRET.into()];
    });
    let through =
        |r: axum::http::request::Builder, secret: Option<&str>, viewer: &str, xff: &str| {
            let r = r
                .header(header::USER_AGENT, LAPTOP)
                .header("cloudfront-viewer-address", viewer)
                .header("x-forwarded-for", xff);
            match secret {
                Some(s) => r.header("kith-origin-secret", s),
                None => r,
            }
        };

    // The computer opens a handoff for the account page through one edge…
    let open = through(
        Request::post("/v1/handoff").header(header::CONTENT_TYPE, "application/json"),
        Some(SECRET),
        "203.0.113.9:46532",
        "203.0.113.9, 15.158.0.1",
    );
    let open = send(&w.app, open.body(Body::from("{}")).unwrap()).await;
    assert_eq!(open.status, StatusCode::OK, "{}", open.text());
    let id = open.json()["id"].as_str().unwrap().to_string();

    // …and the phone opens its link through another.
    let phone = through(
        Request::get(format!("/handoff/{id}")),
        Some(SECRET),
        "2001:db8::20:51000",
        "2001:db8::20, 15.158.0.2",
    );
    let page = send(&w.app, phone.body(Body::empty()).unwrap()).await;
    assert_eq!(page.status, StatusCode::OK);
    let d = page_data(&page.text());
    assert_eq!(d["ip"], "203.0.113.9");
    assert_eq!(d["phone_ip"], "2001:db8::20");

    // Straight to the origin, a claimed viewer address is ignored: the page shows the
    // address the proxy saw.
    let forged = through(
        Request::get(format!("/handoff/{id}")),
        None,
        "203.0.113.9:1",
        "203.0.113.9, 192.0.2.66",
    );
    let page = send(&w.app, forged.body(Body::empty()).unwrap()).await;
    assert_eq!(page_data(&page.text())["phone_ip"], "192.0.2.66");
}
