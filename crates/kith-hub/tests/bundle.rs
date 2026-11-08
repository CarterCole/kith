//! The policy bundle file on a running hub: a file that fails to load leaves the last
//! good one in force, and the admin API reports which is in force and lists the
//! identities an editor can put into groups and roles.

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;

use kith_core::kel::{new_inception, verify_log, Device, DeviceKind, Event, KeyState};
use kith_core::keys::{KeyType, LocalSigner, VerifyOptions};
use kith_core::policy::SignerPolicy;
use kith_core::util::now;
use kith_hub::{Authn, Hub, HubConfig};

const ADMIN: &str = "Bearer ops-secret";

async fn call(app: &Router, uri: &str, auth: Option<&str>) -> (StatusCode, Value) {
    let mut req = Request::builder().uri(uri);
    if let Some(a) = auth {
        req = req.header(header::AUTHORIZATION, a);
    }
    let resp = app
        .clone()
        .oneshot(req.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

/// An identity with one software device, `laptop`.
fn identity() -> (Vec<Event>, KeyState) {
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
    (log, st)
}

fn sign_in(st: &KeyState) -> Authn {
    Authn {
        st: st.clone(),
        dev: Some("laptop".into()),
        aal: 1,
        amr: vec!["swk".into()],
        auth_time: now(),
        alias: None,
        attrs: Default::default(),
    }
}

fn bundle_with(role: &str, did: &str) -> String {
    json!({
        "version": 1,
        "groups": {"org:acme": {"members": [did]}},
        "roles": {(role): {"description": "set by the test", "members": ["group:org:acme"]}},
        "policies": ""
    })
    .to_string()
}

struct World {
    dir: std::path::PathBuf,
    hub: std::sync::Arc<Hub>,
    app: Router,
    ada: KeyState,
}

fn world() -> World {
    let dir = std::env::temp_dir().join(format!("kith-bundle-{}", kith_core::util::random_id()));
    std::fs::create_dir_all(&dir).unwrap();
    let (log, ada) = identity();
    std::fs::write(
        dir.join("bundle.json"),
        bundle_with("carterbox:admin", &ada.did),
    )
    .unwrap();
    let mut cfg = HubConfig::new("http://localhost:7777", dir.join("data"));
    cfg.bundle_path = Some(dir.join("bundle.json"));
    cfg.admin_token = Some("ops-secret".into());
    let hub = Hub::open(cfg).unwrap();
    hub.put_kel(&ada.did, log).unwrap();
    World {
        app: kith_hub::router(hub.clone()),
        dir,
        hub,
        ada,
    }
}

impl World {
    fn roles(&self) -> Vec<String> {
        self.hub
            .access_claims(&sign_in(&self.ada), "api://carterbox", None)
            .expect("a token is still issued")
            .roles
    }

    async fn bundle_status(&self) -> Value {
        let (status, stats) = call(&self.app, "/v1/admin/stats", Some(ADMIN)).await;
        assert_eq!(status, StatusCode::OK, "{stats}");
        stats["bundle"].clone()
    }
}

#[tokio::test]
async fn a_bundle_that_fails_to_load_leaves_the_last_good_one_in_force() {
    let w = world();
    let path = w.dir.join("bundle.json");
    assert_eq!(w.roles(), vec!["carterbox:admin"]);
    let status = w.bundle_status().await;
    assert_eq!(status["error"], Value::Null, "{status}");
    assert_eq!(
        (status["groups"].as_u64(), status["roles"].as_u64()),
        (Some(1), Some(1)),
        "{status}"
    );
    let loaded_at = status["loaded_at"].as_i64().expect("loaded_at");

    // Half a file, as a copy caught mid-write would read.
    let good = std::fs::read_to_string(&path).unwrap();
    std::fs::write(&path, &good[..good.len() / 2]).unwrap();
    assert_eq!(
        w.roles(),
        vec!["carterbox:admin"],
        "the last good bundle stays in force"
    );
    let status = w.bundle_status().await;
    assert!(
        status["error"].as_str().is_some_and(|e| !e.is_empty()),
        "{status}"
    );
    assert_eq!(status["loaded_at"].as_i64(), Some(loaded_at), "{status}");

    // Valid JSON, but a policy Cedar cannot parse.
    let mut broken: Value = serde_json::from_str(&good).unwrap();
    broken["policies"] = json!("permit(principal in Role::\"x\", action, resource) when {");
    std::fs::write(&path, broken.to_string()).unwrap();
    assert_eq!(w.roles(), vec!["carterbox:admin"]);
    assert!(w.bundle_status().await["error"]
        .as_str()
        .is_some_and(|e| e.contains("policies")));

    // The file is gone.
    std::fs::remove_file(&path).unwrap();
    assert_eq!(w.roles(), vec!["carterbox:admin"]);
    assert!(w.bundle_status().await["error"].as_str().is_some());

    // A good file again takes effect at once, and clears the error.
    std::fs::write(&path, bundle_with("carterbox:viewer", &w.ada.did)).unwrap();
    assert_eq!(w.roles(), vec!["carterbox:viewer"]);
    let status = w.bundle_status().await;
    assert_eq!(status["error"], Value::Null, "{status}");
    assert!(status["loaded_at"].as_i64() >= Some(loaded_at), "{status}");
}

#[test]
fn a_bundle_that_fails_to_load_still_stops_the_hub_from_starting() {
    let dir = std::env::temp_dir().join(format!("kith-bundle-{}", kith_core::util::random_id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("bundle.json"), "{\"version\": 1, \"roles\": {").unwrap();
    let mut cfg = HubConfig::new("http://localhost:7777", dir.join("data"));
    cfg.bundle_path = Some(dir.join("bundle.json"));
    assert!(
        Hub::open(cfg).is_err(),
        "there is no last good bundle to fall back on"
    );
}

#[tokio::test]
async fn the_admin_api_lists_identities_with_their_groups_and_roles() {
    let w = world();
    let (bob_log, bob) = identity();
    w.hub.put_kel(&bob.did, bob_log).unwrap();

    assert_eq!(
        call(&w.app, "/v1/admin/identities", None).await.0,
        StatusCode::UNAUTHORIZED
    );
    let (status, list) = call(&w.app, "/v1/admin/identities", Some(ADMIN)).await;
    assert_eq!(status, StatusCode::OK, "{list}");
    let list = list.as_array().expect("a list");
    assert_eq!(list.len(), 2, "{list:?}");
    let find = |did: &str| {
        list.iter()
            .find(|p| p["did"] == did)
            .cloned()
            .expect("listed")
    };

    let ada = find(&w.ada.did);
    assert_eq!(ada["groups"], json!(["org:acme"]), "{ada}");
    assert_eq!(ada["roles"], json!(["carterbox:admin"]), "{ada}");
    assert_eq!(ada["devices"], json!(1), "{ada}");
    assert_eq!(ada["contacts"], json!([]), "{ada}");
    assert_eq!(ada["totp"], json!(false), "{ada}");
    assert_eq!(ada["last_sign_in"], Value::Null, "{ada}");
    assert!(ada["created"].as_i64().is_some(), "{ada}");

    let bob = find(&bob.did);
    assert_eq!(
        (bob["groups"].clone(), bob["roles"].clone()),
        (json!([]), json!([])),
        "{bob}"
    );
}
