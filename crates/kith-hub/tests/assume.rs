//! Assumable roles at the hub (spec §4.3.1): a session token exchanged with `role` gets
//! a token that holds the role for no longer than its `max_age`. A role without an
//! `assume` setting, such as `god`, is never assumed, not even by its members.

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;

use kith_core::kel::{new_inception, verify_log, Device, DeviceKind, KeyState};
use kith_core::keys::{KeyType, LocalSigner, VerifyOptions};
use kith_core::policy::SignerPolicy;
use kith_core::session::{DeviceSigner, SessionKey};
use kith_core::token::verify_access_token;
use kith_core::util::{now, random_id};
use kith_hub::{Hub, HubConfig, TT_DELEGATION, TT_SESSION};

const ISSUER: &str = "http://localhost:7777";
const AUD: &str = "api://invoices";

struct Person {
    st: KeyState,
    laptop: LocalSigner,
}

fn person(hub: &Hub) -> Person {
    let root = LocalSigner::generate(KeyType::Ed25519);
    let laptop = LocalSigner::generate(KeyType::Ed25519);
    let next = SignerPolicy::single(LocalSigner::generate(KeyType::Ed25519).id);
    let dev = Device {
        id: "laptop".into(),
        key: laptop.id.clone(),
        name: "laptop".into(),
        kind: DeviceKind::Software,
        aal: 1,
        caps: vec!["session".into()],
        rp_id: None,
        xkey: None,
    };
    let mut inc = new_inception(SignerPolicy::single(&root.id), &next, vec![dev]);
    inc.sign(&root).unwrap();
    inc.sign(&laptop).unwrap();
    let log = vec![inc];
    let st = verify_log(&log, &VerifyOptions::default()).unwrap();
    hub.put_kel(&st.did, log).unwrap();
    Person { st, laptop }
}

struct World {
    app: Router,
    hub: std::sync::Arc<Hub>,
    ada: Person,
    bob: Person,
}

fn world() -> World {
    let dir = std::env::temp_dir().join(format!("kith-assume-{}", random_id()));
    std::fs::create_dir_all(&dir).unwrap();
    let mut cfg = HubConfig::new(ISSUER, dir.join("data"));
    cfg.bundle_path = Some(dir.join("bundle.json"));
    // The hub needs a bundle to open; the real one names the people made below.
    std::fs::write(dir.join("bundle.json"), r#"{"version": 1, "policies": ""}"#).unwrap();
    let hub = Hub::open(cfg).unwrap();
    let (ada, bob) = (person(&hub), person(&hub));
    let bundle = json!({
        "version": 1,
        "groups": {"oncall": {"members": [ada.st.did]}},
        "roles": {
            "god": {"members": [ada.st.did]},
            "break-glass": {"assume": {"members": ["group:oncall"], "max_age": 300}},
            "auditor": {"assume": {"members": [bob.st.did]}}
        },
        "policies": ""
    });
    std::fs::write(dir.join("bundle.json"), bundle.to_string()).unwrap();
    World { app: kith_hub::router(hub.clone()), hub, ada, bob }
}

fn session_token(p: &Person) -> String {
    let dev = p.st.device("laptop").unwrap().clone();
    let sk = SessionKey::create(&p.st.did, &dev, DeviceSigner::Key(&p.laptop.secret), 3600).unwrap();
    sk.session_token(ISSUER, json!({})).unwrap()
}

async fn exchange(w: &World, form: &[(&str, &str)]) -> (StatusCode, Value) {
    let body = form.iter().map(|(k, v)| format!("{k}={}", urlencoding(v))).collect::<Vec<_>>().join("&");
    let req = Request::post("/oauth/token").header(header::CONTENT_TYPE, "application/x-www-form-urlencoded").body(Body::from(body)).unwrap();
    let r = w.app.clone().oneshot(req).await.unwrap();
    let status = r.status();
    let bytes = r.into_body().collect().await.unwrap().to_bytes();
    (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
}

fn urlencoding(s: &str) -> String {
    s.bytes().map(|b| if b.is_ascii_alphanumeric() || b"-._~".contains(&b) { (b as char).to_string() } else { format!("%{b:02X}") }).collect()
}

async fn assume(w: &World, p: &Person, role: &str) -> (StatusCode, Value) {
    let tok = session_token(p);
    exchange(w, &[("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange"), ("subject_token", &tok), ("subject_token_type", TT_SESSION), ("audience", AUD), ("role", role)]).await
}

#[tokio::test]
async fn a_session_assumes_a_role_for_no_longer_than_its_max_age() {
    let w = world();
    let (status, body) = assume(&w, &w.ada, "break-glass").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["expires_in"], 300, "the role's max_age caps the token");
    let c = verify_access_token(body["access_token"].as_str().unwrap(), &w.hub.signer.jwks(), ISSUER, AUD, now()).unwrap();
    assert_eq!(c.assumed.as_deref(), Some("break-glass"));
    assert_eq!(c.roles, ["break-glass", "god"], "added to the roles she holds");
    assert_eq!(c.exp - c.iat, 300);

    let (status, body) = assume(&w, &w.bob, "auditor").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["expires_in"], 900, "no max_age: the hub's own lifetime");
}

#[tokio::test]
async fn god_is_never_assumed_and_others_are_refused_with_a_reason() {
    let w = world();
    for (p, role, refusal) in [(&w.ada, "god", "not_assumable"), (&w.bob, "god", "not_assumable"), (&w.ada, "nosuch", "not_assumable"), (&w.bob, "break-glass", "not_eligible"), (&w.ada, "auditor", "not_eligible")] {
        let (status, body) = assume(&w, p, role).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{role}: {body}");
        assert_eq!(body["error"], "access_denied", "{role}");
        assert_eq!(body["refusal"], refusal, "{role}");
    }
    // Without `role`, nothing is assumed and god is held as before.
    let tok = session_token(&w.ada);
    let (status, body) = exchange(&w, &[("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange"), ("subject_token", &tok), ("subject_token_type", TT_SESSION), ("audience", AUD)]).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let c = verify_access_token(body["access_token"].as_str().unwrap(), &w.hub.signer.jwks(), ISSUER, AUD, now()).unwrap();
    assert_eq!((c.roles, c.assumed), (vec!["god".to_string()], None));
}

#[tokio::test]
async fn a_delegated_session_cannot_assume_a_role() {
    let w = world();
    let (status, body) = exchange(&w, &[("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange"), ("subject_token", "x"), ("subject_token_type", TT_DELEGATION), ("actor_token", "y"), ("role", "auditor")]).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(body["error_description"].as_str().unwrap_or_default().contains("cannot assume"), "{body}");
}
