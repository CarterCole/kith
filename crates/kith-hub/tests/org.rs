//! Policy DAGs and revocations end to end against the hub router (in process):
//! an org publishes a DAG, a reader checks a slice against the org's KEL, the hub
//! issues tokens from the DAG, and a pushed revocation takes effect everywhere.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;

use kith_core::authz::{Bundle, Principal, Resource};
use kith_core::beacon::NoBeacons;
use kith_core::dag::{blocks_from_json, blocks_to_json, MemStore};
use kith_core::kel::{new_inception, next_event, verify_log, Device, DeviceKind, Event, EventBody, KeyState};
use kith_core::keys::{KeyType, LocalSigner, VerifyOptions};
use kith_core::pdag::{self, Query};
use kith_core::policy::SignerPolicy;
use kith_core::revoke::{self, Entry, FreshnessPolicy, Follower, Heartbeat, Level, Revocation};
use kith_core::util::now;
use kith_hub::{Authn, Hub, HubConfig};

async fn call(app: &Router, method: &str, uri: &str, body: Option<Value>) -> (StatusCode, Value, Vec<u8>) {
    let mut req = Request::builder().method(method).uri(uri);
    let body = match body {
        Some(b) => {
            req = req.header("content-type", "application/json");
            Body::from(b.to_string())
        }
        None => Body::empty(),
    };
    let resp = app.clone().oneshot(req.body(body).unwrap()).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes().to_vec();
    (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null), bytes)
}

fn identity(extra: Vec<Device>, signers: &[&LocalSigner]) -> (LocalSigner, Vec<Event>) {
    let admin = LocalSigner::generate(KeyType::Ed25519);
    let next = SignerPolicy::single(LocalSigner::generate(KeyType::Ed25519).id);
    let mut inc = new_inception(SignerPolicy::single(&admin.id), &next, extra);
    inc.sign(&admin).unwrap();
    for s in signers {
        inc.sign(s).unwrap();
    }
    (admin, vec![inc])
}

fn state(log: &[Event]) -> KeyState {
    verify_log(log, &VerifyOptions::default()).unwrap()
}

#[tokio::test]
async fn publish_slice_issue_revoke() {
    let dir = std::env::temp_dir().join(format!("kith-org-{}", kith_core::util::random_id()));

    // Ada, a person with a laptop.
    let laptop = LocalSigner::generate(KeyType::Ed25519);
    let dev = Device { id: "laptop".into(), key: laptop.id.clone(), name: "laptop".into(), kind: DeviceKind::Software, aal: 1, caps: vec!["session".into()], rp_id: None, xkey: None };
    let (_, ada_log) = identity(vec![dev], &[&laptop]);
    let ada = state(&ada_log);

    // Acme, an org: an ordinary identity.
    let (admin, mut org_log) = identity(vec![], &[]);
    let org = state(&org_log).did;

    let mut cfg = HubConfig::new("http://localhost:7777", &dir);
    cfg.policy_org = Some(org.clone());
    let hub = Hub::open(cfg).unwrap();
    let app = kith_hub::router(hub.clone());
    assert_eq!(call(&app, "PUT", &format!("/v1/kel/{}", ada.did), Some(json!(ada_log))).await.0, StatusCode::OK);
    assert_eq!(call(&app, "PUT", &format!("/v1/kel/{org}"), Some(json!(org_log))).await.0, StatusCode::OK);

    // The conformance bundle, with Ada's real DID.
    let v: Value = serde_json::from_str(include_str!("../../../spec/test-vectors/authz.json")).unwrap();
    let bundle: Bundle = serde_json::from_str(&v["bundle"].to_string().replace("did:kith:ada", &ada.did)).unwrap();
    let store = MemStore::new();
    let root = pdag::build(&store, &bundle).unwrap();

    // Blocks are checked on upload.
    let mut bad = blocks_to_json(&store.blocks());
    let first = bad.as_object().unwrap().keys().next().unwrap().clone();
    bad[&first] = json!("{\"tampered\":true}");
    assert_eq!(call(&app, "PUT", "/v1/blocks", Some(bad)).await.0, StatusCode::BAD_REQUEST);
    assert_eq!(call(&app, "PUT", "/v1/blocks", Some(blocks_to_json(&store.blocks()))).await.0, StatusCode::OK);
    let (s, _, raw) = call(&app, "GET", &format!("/ipfs/{root}"), None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(kith_core::dag::cid_of(&raw), root, "the gateway route serves raw blocks");

    // The org commits the root in its KEL.
    let mut ev = next_event(&state(&org_log), EventBody::PolicyRoot { root: root.clone(), revocations_through: 0 });
    ev.sign(&admin).unwrap();
    org_log.push(ev);
    assert_eq!(call(&app, "PUT", &format!("/v1/kel/{org}"), Some(json!(org_log))).await.0, StatusCode::OK);
    let (_, p, _) = call(&app, "GET", &format!("/v1/policy/{org}"), None).await;
    assert_eq!(p["root"], root);

    // A reader asks for one action and checks the answer against the KEL, not the hub.
    let q = Query::Actions { actions: vec!["Query.invoices".into()], principals: vec![ada.did.clone()] };
    let (_, r, _) = call(&app, "POST", &format!("/v1/policy/{org}/slice"), Some(json!(q))).await;
    let committed = state(&org_log).policy.unwrap().root;
    let slice = pdag::load(&MemStore::from_blocks(blocks_from_json(&r["blocks"]).unwrap()), &committed, &q).unwrap();
    assert_eq!(slice.policy_ids(), vec!["read-invoices"]);

    // The hub issues tokens from the DAG.
    let authn = Authn { st: ada.clone(), dev: Some("laptop".into()), aal: 1, amr: vec!["hwk".into()], auth_time: now() };
    let claims = hub.access_claims(&authn, "api://invoices", None).unwrap();
    assert_eq!(claims.groups, vec!["finance", "staff"]);
    assert_eq!(claims.roles, vec!["billing-reader"]);

    // The org lets the hub sign heartbeats: an add_device for the hub's revoker key,
    // with the hub's proof of possession.
    let (_, info, _) = call(&app, "GET", "/v1/hub", None).await;
    let revoker = Device { id: "hub".into(), key: info["revoker"].as_str().unwrap().into(), name: "hub".into(), kind: DeviceKind::Software, aal: 1, caps: vec!["revoke".into()], rp_id: None, xkey: None };
    let mut ev = next_event(&state(&org_log), EventBody::AddDevice { device: revoker.clone() });
    ev.sign(&admin).unwrap();
    // The hub refuses to vouch for anything but exactly that.
    let mut greedy = ev.clone();
    if let EventBody::AddDevice { device } = &mut greedy.body {
        device.caps.push("session".into());
    }
    assert_eq!(call(&app, "POST", "/v1/hub/revoker", Some(json!(greedy))).await.0, StatusCode::BAD_REQUEST);
    let (_, pop, _) = call(&app, "POST", "/v1/hub/revoker", Some(json!(ev))).await;
    ev.add_sig(serde_json::from_value(pop).unwrap());
    org_log.push(ev);
    assert_eq!(call(&app, "PUT", &format!("/v1/kel/{org}"), Some(json!(org_log))).await.0, StatusCode::OK);
    assert_eq!(hub.served_orgs(), vec![org.clone()]);

    // A forged revocation is refused; a real one is appended and a heartbeat follows.
    let forger = LocalSigner::generate(KeyType::Ed25519);
    let mut forged = Entry::new(&org, None, vec![Revocation::Principal { id: ada.did.clone() }]).unwrap();
    forged.sign(&forger).unwrap();
    assert_eq!(call(&app, "POST", &format!("/v1/revocations/{org}"), Some(json!(forged))).await.0, StatusCode::BAD_REQUEST);
    let mut e1 = Entry::new(&org, None, vec![Revocation::Member { id: ada.did.clone(), set: "Group::finance".into() }]).unwrap();
    e1.sign(&admin).unwrap();
    assert_eq!(call(&app, "POST", &format!("/v1/revocations/{org}"), Some(json!(e1))).await.0, StatusCode::OK);
    assert_eq!(call(&app, "POST", &format!("/v1/revocations/{org}"), Some(json!(e1))).await.0, StatusCode::CONFLICT, "not the next entry");

    // A follower sees the entry and a heartbeat that names it.
    let (_, feed, _) = call(&app, "GET", &format!("/v1/revocations/{org}"), None).await;
    let org_state = state(&org_log);
    let mut f = Follower::new(&org, 0, FreshnessPolicy { require_beacon: false, ..Default::default() });
    let hb: Heartbeat = serde_json::from_value(feed["heartbeat"].clone()).unwrap();
    assert_eq!(hb.seq, 1);
    f.apply_heartbeat(&org_state, &hb, &NoBeacons, now()).unwrap();
    assert_eq!(f.freshness(now()).level, Level::Behind, "heard of entry 1, doesn't hold it");
    for e in feed["entries"].as_array().unwrap() {
        f.apply_entry(&org_state, &serde_json::from_value(e.clone()).unwrap()).unwrap();
    }
    assert_eq!(f.freshness(now()).level, Level::Fresh);
    let mut attrs = serde_json::Map::new();
    attrs.insert("aal".into(), json!(1));
    let p = Principal { id: ada.did.clone(), attrs, groups: claims.groups.clone(), roles: claims.roles.clone(), actor: None, caps: None };
    let op = Resource::new("Operation", "Query.invoices");
    let req = revoke::Request { principal: &p, jti: None, action: "Query.invoices", resource: &op, context: &json!({}) };
    assert!(!revoke::authorize(&slice, &mut f, &req, now()).unwrap().allowed, "her old token's roles don't matter");

    // The hub's own tokens reflect it immediately.
    let claims = hub.access_claims(&authn, "api://invoices", None).unwrap();
    assert_eq!(claims.groups, vec!["staff"]);
    assert!(claims.roles.is_empty());

    // Revoking the principal stops token issuance altogether.
    let mut e2 = Entry::new(&org, Some(&e1), vec![Revocation::Principal { id: ada.did.clone() }]).unwrap();
    e2.sign(&admin).unwrap();
    assert_eq!(call(&app, "POST", &format!("/v1/revocations/{org}"), Some(json!(e2))).await.0, StatusCode::OK);
    assert!(hub.access_claims(&authn, "api://invoices", None).is_err());
}
