//! Generates and checks `spec/test-vectors/policy-dag.json`: a policy DAG, slices
//! of it, and a signed revocation chain with a real drand beacon, with the
//! decisions every implementation must reach. Keys and timestamps are fixed, so
//! the file is reproducible; run with `KITH_WRITE_VECTORS=1` to rewrite it.

use std::collections::BTreeMap;

use serde_json::{json, Value};

use kith_core::authz::{Bundle, Principal, Resource};
use kith_core::beacon::{BeaconValue, Verifiers};
use kith_core::dag::{blocks_to_json, MemStore};
use kith_core::kel::{new_inception, verify_log, Device, DeviceKind, KeyState};
use kith_core::keys::{KeyType, LocalSigner, Scheme, SecretKey, VerifyOptions};
use kith_core::pdag::{self, Query};
use kith_core::policy::SignerPolicy;
use kith_core::revoke::{authorize, Entry, FreshnessPolicy, Follower, Heartbeat, Request, Revocation};

const PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../spec/test-vectors/policy-dag.json");

fn key(seed: u8) -> LocalSigner {
    LocalSigner::from_secret(SecretKey::from_bytes(KeyType::Ed25519, &[seed; 32]).unwrap(), Scheme::Raw, None).unwrap()
}

fn bundle() -> Bundle {
    let v: Value = serde_json::from_str(include_str!("../../../spec/test-vectors/authz.json")).unwrap();
    let mut b: Bundle = serde_json::from_value(v["bundle"].clone()).unwrap();
    b.policies.push_str(
        "\n@id(\"pay-needs-fresh\")\nforbid(principal, action == Action::\"Mutation.payInvoice\", resource) unless { context has kith && context.kith.sync_age < 60 };",
    );
    b
}

fn generate() -> Value {
    // ---- DAG and slices
    let b = bundle();
    let store = MemStore::new();
    let root = pdag::build(&store, &b).unwrap();
    let queries = [
        Query::Actions { actions: vec!["Query.invoices".into()], principals: vec![] },
        Query::Actions { actions: vec!["Mutation.payInvoice".into()], principals: vec!["did:kith:bob".into()] },
        Query::Actions { actions: vec!["Invoice.read".into(), "Query.invoices".into()], principals: vec!["did:kith:ada".into(), "did:kith:bob".into()] },
        Query::Principal { id: "did:kith:ada".into() },
        Query::Principal { id: "did:kith:nobody".into() },
    ];
    let slices: Vec<Value> = queries
        .iter()
        .map(|q| {
            let (s, proof) = pdag::prove(&store, &root, q).unwrap();
            json!({
                "query": q,
                "policies": s.policy_ids(),
                "sets": s.sets.keys().collect::<Vec<_>>(),
                "directory": s.directory.keys().collect::<Vec<_>>(),
                "proof": proof.keys().collect::<Vec<_>>(),
            })
        })
        .collect();

    // ---- an org with an admin key and a revoke-only device
    let admin = key(1);
    let revoker = key(2);
    let dev = Device { id: "revoker".into(), key: revoker.id.clone(), name: "revoker".into(), kind: DeviceKind::Software, aal: 1, caps: vec!["revoke".into()], rp_id: None, xkey: None };
    let mut inc = new_inception(SignerPolicy::single(&admin.id), &SignerPolicy::single(key(3).id), vec![dev]);
    inc.ts = 1692806000;
    inc.sign(&admin).unwrap();
    inc.sign(&revoker).unwrap();
    let kel = vec![inc];
    let org = verify_log(&kel, &VerifyOptions::default()).unwrap();

    let entry = |prev: Option<&Entry>, ts: i64, r: Vec<Revocation>| {
        let mut e = Entry::new(&org.did, prev, r).unwrap();
        e.ts = ts;
        e.sign(&admin).unwrap();
        e
    };
    let e1 = entry(None, 1692806100, vec![Revocation::Member { id: "did:kith:ada".into(), set: "Group::finance".into() }]);
    let e2 = entry(Some(&e1), 1692806110, vec![Revocation::Token { jti: "tok-1".into() }]);
    let e3 = entry(Some(&e2), 1692806120, vec![Revocation::Policy { id: "own-invoice".into() }, Revocation::Policy { id: "no-delegated-pay".into() }]);

    // drand quicknet round 1000, published at 1692806364.
    let beacons: Value = serde_json::from_str(include_str!("../../../spec/test-vectors/beacons.json")).unwrap();
    let round = &beacons["drand"]["cases"][0];
    let beacon = BeaconValue::Drand { chain: beacons["drand"]["chain"].as_str().unwrap().into(), round: 1000, signature: round["signature"].as_str().unwrap().into() };
    let t = round["time"].as_i64().unwrap();
    let mut hb = Heartbeat::new(&org.did, Some(&e3), Some(beacon)).unwrap();
    hb.ts = t + 1;
    hb.sign(&revoker).unwrap();

    let policy = FreshnessPolicy { fresh_for: 60, max_staleness: 600, require_beacon: true };
    let slice = pdag::load(&store, &root, &Query::Actions { actions: vec!["Query.invoices".into(), "Mutation.payInvoice".into(), "Invoice.read".into()], principals: vec!["did:kith:ada".into(), "did:kith:bob".into()] }).unwrap();
    let mut f = Follower::new(&org.did, 0, policy);
    for e in [&e1, &e2, &e3] {
        f.apply_entry(&org, e).unwrap();
    }
    f.apply_heartbeat(&org, &hb, &Verifiers::default(), t + 5).unwrap();

    struct Case {
        name: &'static str,
        principal: &'static str,
        aal: i64,
        action: &'static str,
        resource: Value,
        context: Value,
        jti: Option<&'static str>,
        actor: Option<&'static str>,
        caps: Option<Value>,
        at: i64,
    }
    let op = |a: &str| json!({"type": "Operation", "id": a});
    let c = |name, principal, aal, action: &'static str, at| Case { name, principal, aal, action, resource: op(action), context: json!({}), jti: None, actor: None, caps: None, at };
    let cases = vec![
        c("bob reads invoices", "did:kith:bob", 1, "Query.invoices", t + 10),
        c("ada lost finance, and billing-reader with it", "did:kith:ada", 2, "Query.invoices", t + 10),
        Case { jti: Some("tok-1"), ..c("a revoked token", "did:kith:bob", 1, "Query.invoices", t + 10) },
        Case {
            resource: json!({"type": "Invoice", "id": "inv_1", "attrs": {"ownerEmail": "ada@acme.test"}}),
            ..c("own-invoice was revoked", "did:kith:ada", 1, "Invoice.read", t + 10)
        },
        Case { context: json!({"amount": 5}), ..c("bob pays with a fresh view", "did:kith:bob", 2, "Mutation.payInvoice", t + 10) },
        Case {
            context: json!({"amount": 5}),
            actor: Some("did:kith:assistant"),
            caps: Some(json!([{"action": "Mutation.*"}])),
            ..c("a forbid survives its revocation", "did:kith:bob", 2, "Mutation.payInvoice", t + 10)
        },
        Case { context: json!({"amount": 5}), ..c("degraded: payments need a view under 60 s", "did:kith:bob", 2, "Mutation.payInvoice", t + 300) },
        c("degraded: reads still work", "did:kith:bob", 1, "Query.invoices", t + 300),
        c("stale: everything is denied", "did:kith:bob", 1, "Query.invoices", t + 700),
    ];
    let decisions: Vec<Value> = cases
        .into_iter()
        .map(|c| {
            let mut attrs = serde_json::Map::new();
            attrs.insert("aal".into(), json!(c.aal));
            let p = Principal {
                id: c.principal.into(),
                attrs: attrs.clone(),
                groups: vec![],
                roles: vec![],
                actor: c.actor.map(String::from),
                caps: c.caps.clone().map(|v| serde_json::from_value(v).unwrap()),
            };
            let mut r = Resource::new(c.resource["type"].as_str().unwrap(), c.resource["id"].as_str().unwrap());
            if let Some(a) = c.resource["attrs"].as_object() {
                r.attrs = a.clone();
            }
            let level = f.freshness(c.at).level;
            let d = authorize(&slice, &mut f, &Request { principal: &p, jti: c.jti, action: c.action, resource: &r, context: &c.context }, c.at).unwrap();
            let mut out = json!({
                "name": c.name, "principal": c.principal, "attrs": attrs, "action": c.action,
                "resource": c.resource, "context": c.context, "now": c.at,
                "level": level, "allowed": d.allowed,
            });
            if let Some(j) = c.jti {
                out["jti"] = json!(j);
            }
            if let Some(a) = c.actor {
                out["actor"] = json!(a);
            }
            if let Some(caps) = c.caps {
                out["caps"] = caps;
            }
            if d.reasons.iter().any(|r| r.starts_with("freshness:") || r.starts_with("revoked:")) {
                out["reasons"] = json!(d.reasons);
            }
            out
        })
        .collect();

    json!({
        "description": "Policy DAG and revocation vectors (spec §8). `root` is the DAG of `bundle`; every implementation must build the same root (if it builds), load each slice from `blocks` with exactly the listed policies and sets, and reach every decision in order (the follower's clock only moves forward). Regenerate with KITH_WRITE_VECTORS=1 cargo test -p kith-core --test policy_dag_vectors.",
        "bundle": b,
        "root": root,
        "blocks": blocks_to_json(&store.blocks()),
        "slices": slices,
        "revocations": {
            "org": org_summary(&org),
            "kel": kel,
            "entries": [e1, e2, e3],
            "heartbeat": hb,
            "heartbeat_received_at": t + 5,
            "freshness": policy,
            "slice": {"actions": ["Query.invoices", "Mutation.payInvoice", "Invoice.read"], "principals": ["did:kith:ada", "did:kith:bob"]},
            "decisions": decisions,
        }
    })
}

/// The parts of the key state a revocation verifier needs.
fn org_summary(st: &KeyState) -> Value {
    json!({
        "did": st.did,
        "manage": st.manage,
        "devices": st.devices.values().map(|d| json!({"id": d.id, "key": d.key, "caps": d.caps})).collect::<Vec<_>>(),
    })
}

#[test]
fn policy_dag_vectors() {
    let fresh = generate();
    if std::env::var("KITH_WRITE_VECTORS").is_ok() {
        std::fs::write(PATH, serde_json::to_string_pretty(&fresh).unwrap() + "\n").unwrap();
    }
    let on_disk: Value = serde_json::from_str(&std::fs::read_to_string(PATH).expect("run with KITH_WRITE_VECTORS=1 once")).unwrap();
    // Everything is deterministic: same keys, same timestamps, same bytes.
    let keys: BTreeMap<&str, ()> = fresh.as_object().unwrap().keys().map(|k| (k.as_str(), ())).collect();
    for k in keys.keys() {
        assert_eq!(fresh[*k], on_disk[*k], "policy-dag.json `{k}` is out of date; rerun with KITH_WRITE_VECTORS=1");
    }
}
