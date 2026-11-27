//! Org pages and policy drafts (spec §8.6.1): members see their org, its `god` role saves
//! drafts, and a draft is applied only when the org's manage keys sign its root.

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;

use kith_core::authz::Bundle;
use kith_core::dag::{blocks_to_json, MemStore};
use kith_core::kel::{new_inception, next_event, verify_log, Device, DeviceKind, Event, EventBody, KeyState};
use kith_core::keys::{KeyType, LocalSigner, VerifyOptions};
use kith_core::pdag;
use kith_core::policy::SignerPolicy;
use kith_core::session::{DeviceSigner, SessionKey};
use kith_core::util::random_id;
use kith_hub::{Hub, HubConfig};

const ISSUER: &str = "http://localhost:7777";

struct Person {
    st: KeyState,
    key: LocalSigner,
}

/// An identity with one software device, `dev_main`.
fn person(name: &str) -> (Person, Event) {
    let root = LocalSigner::generate(KeyType::Ed25519);
    let key = LocalSigner::generate(KeyType::Ed25519);
    let recovery = LocalSigner::generate(KeyType::Ed25519);
    let dev = Device {
        id: "dev_main".into(),
        key: key.id.clone(),
        name: name.into(),
        kind: DeviceKind::Software,
        aal: 1,
        caps: vec!["session".into(), "alias".into()],
        rp_id: None,
        xkey: None,
    };
    let mut inc = new_inception(SignerPolicy::single(&root.id), &SignerPolicy::single(&recovery.id), vec![dev]);
    inc.sign(&root).unwrap();
    inc.sign(&key).unwrap();
    let st = verify_log(std::slice::from_ref(&inc), &VerifyOptions::default()).unwrap();
    (Person { st, key }, inc)
}

struct World {
    app: Router,
    hub: Arc<Hub>,
    org: KeyState,
    org_root: LocalSigner,
    org_key: LocalSigner,
    ada: Person,
    carol: Person,
    bob: Person,
}

fn bundle(staff: &[&str], god: &[&str]) -> Bundle {
    serde_json::from_value(json!({
        "version": 1,
        "groups": {"staff": {"description": "Everyone at Acme", "members": staff}},
        "roles": {"god": {"members": god}},
        "policies": ""
    }))
    .unwrap()
}

/// Upload `b`'s blocks and sign its root into the org's log, as `kith org approve` does.
async fn publish(w: &World, b: &Bundle) -> String {
    let store = MemStore::new();
    let root = pdag::build(&store, b).unwrap();
    let r = send(&w.app, "PUT", "/v1/blocks", None, Some(blocks_to_json(&store.blocks()))).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    let mut kel = w.hub.get_kel(&w.org.did).unwrap();
    let st = verify_log(&kel, &VerifyOptions::default()).unwrap();
    let mut ev = next_event(&st, EventBody::PolicyRoot { root: root.clone(), revocations_through: 0 });
    ev.sign(&w.org_root).unwrap();
    kel.push(ev);
    w.hub.put_kel(&w.org.did, kel).unwrap();
    root
}

async fn world() -> World {
    let org_root = LocalSigner::generate(KeyType::Ed25519);
    let org_key = LocalSigner::generate(KeyType::Ed25519);
    let dev = Device {
        id: "dev_server".into(),
        key: org_key.id.clone(),
        name: "server".into(),
        kind: DeviceKind::Software,
        aal: 1,
        caps: vec!["session".into()],
        rp_id: None,
        xkey: None,
    };
    let recovery = LocalSigner::generate(KeyType::Ed25519);
    let mut inc = new_inception(SignerPolicy::single(&org_root.id), &SignerPolicy::single(&recovery.id), vec![dev]);
    inc.sign(&org_root).unwrap();
    inc.sign(&org_key).unwrap();
    let org = verify_log(std::slice::from_ref(&inc), &VerifyOptions::default()).unwrap();

    let dir = std::env::temp_dir().join(format!("kith-orgs-{}", random_id()));
    let mut cfg = HubConfig::new(ISSUER, dir);
    cfg.orgs = BTreeMap::from([("acme".to_string(), org.did.clone())]);
    let hub = Hub::open(cfg).unwrap();
    hub.put_kel(&org.did, vec![inc]).unwrap();
    let mut people = vec![];
    for name in ["ada", "carol", "bob"] {
        let (p, inc) = person(name);
        hub.put_kel(&p.st.did, vec![inc]).unwrap();
        people.push(p);
    }
    let bob = people.pop().unwrap();
    let carol = people.pop().unwrap();
    let ada = people.pop().unwrap();
    let w = World { app: kith_hub::router(hub.clone()), hub, org, org_root, org_key, ada, carol, bob };
    publish(&w, &bundle(&[&w.ada.st.did, &w.carol.st.did], &[&w.carol.st.did])).await;
    w
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
}

async fn send(app: &Router, method: &str, uri: &str, token: Option<&str>, body: Option<Value>) -> Resp {
    let mut r = Request::builder().method(method).uri(uri);
    if let Some(t) = token {
        r = r.header(header::AUTHORIZATION, format!("Bearer {t}"));
    }
    let req = match body {
        Some(b) => r.header(header::CONTENT_TYPE, "application/json").body(Body::from(b.to_string())),
        None => r.body(Body::empty()),
    }
    .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let (parts, body) = resp.into_parts();
    Resp { status: parts.status, headers: parts.headers, body: body.collect().await.unwrap().to_bytes().to_vec() }
}

/// A hub access token, as `kith login` gets one.
async fn token(w: &World, p: &Person) -> String {
    let d = p.st.devices.values().next().unwrap().clone();
    let sk = SessionKey::create(&p.st.did, &d, DeviceSigner::Key(&p.key.secret), 3600).unwrap();
    let body = format!(
        "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange&subject_token={}&subject_token_type={}",
        sk.session_token(ISSUER, json!({})).unwrap(),
        kith_hub::TT_SESSION.replace(':', "%3A"),
    );
    let req = Request::post("/oauth/token")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(body))
        .unwrap();
    let r = w.app.clone().oneshot(req).await.unwrap();
    let v: Value = serde_json::from_slice(&r.into_body().collect().await.unwrap().to_bytes()).unwrap();
    v["access_token"].as_str().unwrap().to_string()
}

#[tokio::test]
async fn members_see_their_org_and_others_do_not() {
    let w = world().await;
    let (ada, bob) = (token(&w, &w.ada).await, token(&w, &w.bob).await);

    assert_eq!(send(&w.app, "GET", "/v1/orgs/acme", None, None).await.status, StatusCode::UNAUTHORIZED);
    assert_eq!(send(&w.app, "GET", "/v1/orgs/nope", Some(&ada), None).await.status, StatusCode::NOT_FOUND);
    let r = send(&w.app, "GET", "/v1/orgs/acme", Some(&bob), None).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN, "{}", r.text());

    let r = send(&w.app, "GET", "/v1/orgs/acme", Some(&ada), None).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    let v = r.json();
    assert_eq!(v["name"], "acme");
    assert_eq!(v["did"], w.org.did);
    assert_eq!(v["devices"][0]["name"], "server");
    assert_eq!(v["policy"]["seq"], 1);
    assert!(v["policy"]["root"].as_str().unwrap().starts_with("bag"));
    assert_eq!(v["policy"]["signers"], json!([w.org_root.id]));
    assert_eq!(v["bundle"]["groups"]["staff"]["members"], json!([w.ada.st.did, w.carol.st.did]));
    assert_eq!(v["viewer"]["did"], w.ada.st.did);
    assert_eq!(v["viewer"]["groups"], json!(["staff"]));
    assert_eq!(v["viewer"]["can_edit"], false);
    assert_eq!(r.headers[header::CACHE_CONTROL], "no-store");

    let list = send(&w.app, "GET", "/v1/orgs", Some(&ada), None).await.json();
    assert_eq!(list["orgs"], json!([{"name": "acme", "did": w.org.did}]));
    assert_eq!(send(&w.app, "GET", "/v1/orgs", Some(&bob), None).await.json()["orgs"], json!([]));

    // The pages are shells that read the API; an unknown org is a 404 page.
    let page = send(&w.app, "GET", "/orgs/acme", None, None).await;
    assert_eq!(page.status, StatusCode::OK);
    assert!(page.text().contains("\"name\":\"acme\""), "the page knows its org");
    assert_eq!(send(&w.app, "GET", "/orgs/nope", None, None).await.status, StatusCode::NOT_FOUND);
    assert_eq!(send(&w.app, "GET", "/orgs", None, None).await.status, StatusCode::OK);
}

#[tokio::test]
async fn the_god_role_drafts_and_only_the_orgs_keys_apply_a_draft() {
    let w = world().await;
    let (ada, carol) = (token(&w, &w.ada).await, token(&w, &w.carol).await);
    let v = send(&w.app, "GET", "/v1/orgs/acme", Some(&carol), None).await.json();
    assert_eq!(v["viewer"]["can_edit"], true);
    let base_root = v["policy"]["root"].as_str().unwrap().to_string();

    let next = bundle(&[&w.ada.st.did, &w.carol.st.did, &w.bob.st.did], &[&w.carol.st.did]);
    let body = json!({"bundle": next});
    let r = send(&w.app, "POST", "/v1/orgs/acme/drafts", Some(&ada), Some(body.clone())).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN, "staff can't draft: {}", r.text());
    let bad = json!({"bundle": {"version": 1, "roles": {"god": {"rule": "principal in"}}, "policies": ""}});
    let r = send(&w.app, "POST", "/v1/orgs/acme/drafts", Some(&carol), Some(bad)).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST, "{}", r.text());

    let r = send(&w.app, "POST", "/v1/orgs/acme/drafts", Some(&carol), Some(body.clone())).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    let d = r.json();
    let id = d["id"].as_str().unwrap().to_string();
    assert_eq!(d["url"], format!("{ISSUER}/orgs/acme/drafts/{id}"));
    assert_eq!(d["root"], pdag::build(&MemStore::new(), &next).unwrap(), "the root anyone rebuilds from the bundle");
    assert_eq!(d["base"]["root"], base_root);
    assert_eq!(d["base"]["seq"], 1);
    assert_eq!(d["state"], "open");
    assert_eq!(d["author"], w.carol.st.did);
    assert_eq!(d["changes"], json!([{"kind": "members", "set": "Group::staff", "added": [w.bob.st.did], "removed": []}]));

    // Members read drafts; the org page lists the open ones.
    let got = send(&w.app, "GET", &format!("/v1/orgs/acme/drafts/{id}"), Some(&ada), None).await;
    assert_eq!(got.status, StatusCode::OK);
    // The org itself reads it too, as `kith org approve` does, though it is in no group.
    let as_org = token(&w, &Person { st: w.org.clone(), key: w.org_key.clone() }).await;
    let got_by_org = send(&w.app, "GET", &format!("/v1/orgs/acme/drafts/{id}"), Some(&as_org), None).await;
    assert_eq!(got_by_org.status, StatusCode::OK, "{}", got_by_org.text());
    assert_eq!(send(&w.app, "POST", "/v1/orgs/acme/drafts", Some(&as_org), Some(body.clone())).await.status, StatusCode::FORBIDDEN, "the org's own sign-in is no god");
    assert_eq!(got.json()["bundle"]["groups"]["staff"]["members"][2], w.bob.st.did);
    let v = send(&w.app, "GET", "/v1/orgs/acme", Some(&ada), None).await.json();
    assert_eq!(v["drafts"][0]["id"], id);
    assert_eq!(send(&w.app, "GET", &format!("/orgs/acme/drafts/{id}"), None, None).await.status, StatusCode::OK);

    // A second draft from the same base goes stale once the first is signed in.
    let other = send(&w.app, "POST", "/v1/orgs/acme/drafts", Some(&carol), Some(json!({"bundle": bundle(&[&w.carol.st.did], &[&w.carol.st.did])}))).await.json();
    let other_id = other["id"].as_str().unwrap().to_string();
    let root = publish(&w, &next).await;
    assert_eq!(root, d["root"]);
    let got = send(&w.app, "GET", &format!("/v1/orgs/acme/drafts/{id}"), Some(&ada), None).await.json();
    assert_eq!(got["state"], "applied");
    let got = send(&w.app, "GET", &format!("/v1/orgs/acme/drafts/{other_id}"), Some(&ada), None).await.json();
    assert_eq!(got["state"], "stale");
    let v = send(&w.app, "GET", "/v1/orgs/acme", Some(&ada), None).await.json();
    assert_eq!(v["policy"]["seq"], 2);
    assert_eq!(v["bundle"]["groups"]["staff"]["members"][2], w.bob.st.did);
    assert_eq!(v["drafts"], json!([]), "only open drafts are listed");

    // Bob is a member now; only the god role discards a draft.
    let bob = token(&w, &w.bob).await;
    assert_eq!(send(&w.app, "GET", "/v1/orgs/acme", Some(&bob), None).await.status, StatusCode::OK);
    assert_eq!(send(&w.app, "DELETE", &format!("/v1/orgs/acme/drafts/{other_id}"), Some(&ada), None).await.status, StatusCode::FORBIDDEN);
    assert_eq!(send(&w.app, "DELETE", &format!("/v1/orgs/acme/drafts/{other_id}"), Some(&carol), None).await.status, StatusCode::NO_CONTENT);
    assert_eq!(send(&w.app, "GET", &format!("/v1/orgs/acme/drafts/{other_id}"), Some(&ada), None).await.status, StatusCode::NOT_FOUND);
}
