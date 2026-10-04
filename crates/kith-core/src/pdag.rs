//! The policy DAG: a bundle stored as content-addressed blocks with indexes, so a
//! reader fetches only the slice it needs and can prove the slice is complete
//! (spec §8.3–8.5).
//!
//! ```text
//! root ── actions     "Query.invoices" | "*"            → [policy links]
//!      ├─ principals  "User::did" | "Group::x" | "*"    → [policy links]
//!      ├─ sets        "Group::x" | "Role::x"            → set link
//!      ├─ members     did                               → ["Group::x", …] (explicit only)
//!      ├─ directory   did                               → {"attrs": {…}}
//!      └─ rules       ["Group::staff", …]                  every set with a rule
//! ```
//!
//! Every policy is filed under each action its scope can match and under the
//! principal its scope names, so "all policies for `Query.invoices`" is exactly two
//! map lookups (the action and `*`), and each lookup proves nothing was left out.

use std::collections::{BTreeMap, BTreeSet};
use std::str::FromStr;

use cedar_policy::{ActionConstraint, Effect, EntityUid, Policy, PolicyId, PolicySet, PrincipalConstraint};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

use crate::authz::{cedar_value, Bundle, DirEntry, Engine, SetDef, MEMBER_ACTION};
use crate::dag::{self, as_link, get_verified, link, map_build, map_get, put_value, BlockGet, BlockPut, Recording};
use crate::{Error, Result};

pub const DAG_VERSION: &str = "kith-policy-dag/1";
/// Key for policies whose action (or principal) scope is unconstrained.
pub const ANY: &str = "*";

/// One Cedar policy as stored in its own block.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyEntry {
    /// The `@id` annotation if present, else Cedar's positional id (`policy0`, …).
    pub id: String,
    pub effect: String,
    /// The policy's Cedar source, including its annotations.
    pub text: String,
    /// Groups and roles the policy mentions anywhere (`Group::x`, `Role::x`).
    pub refs: Vec<String>,
}

/// A group or role as stored in its own block.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SetEntry {
    pub kind: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default)]
    pub members: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule: Option<String>,
    /// Sets this one's membership depends on (nested members and rule references).
    pub deps: Vec<String>,
    /// Sets whose membership depends on this one (the reverse of `deps`).
    pub dependents: Vec<String>,
}

impl SetEntry {
    pub fn key(&self) -> String {
        format!("{}::{}", self.kind, self.name)
    }
}

/// What a reader wants.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Query {
    /// Everything needed to decide these actions, plus directory entries for these
    /// principals. "This JS session only reads `Query.invoices`."
    Actions {
        actions: Vec<String>,
        #[serde(default)]
        principals: Vec<String>,
    },
    /// Every grant that can apply to one principal, across all actions.
    Principal { id: String },
}

/// A verified, complete slice of a policy DAG.
#[derive(Debug, Clone)]
pub struct Slice {
    pub root: String,
    pub version: u32,
    pub sets: BTreeMap<String, SetEntry>,
    pub policies: Vec<PolicyEntry>,
    pub directory: BTreeMap<String, DirEntry>,
}

fn key_of(uid: &EntityUid) -> String {
    format!("{}::{}", uid.type_name(), uid.id().unescaped())
}

fn set_key(member: &str) -> Option<String> {
    member
        .strip_prefix("group:")
        .map(|g| format!("Group::{g}"))
        .or_else(|| member.strip_prefix("role:").map(|r| format!("Role::{r}")))
}

/// Every `Group::…` / `Role::…` entity a policy mentions, in its scope or conditions.
fn refs_of(p: &Policy) -> Result<BTreeSet<String>> {
    fn walk(v: &Value, out: &mut BTreeSet<String>) {
        match v {
            Value::Object(o) => {
                if let (Some(Value::String(t)), Some(Value::String(id))) = (o.get("type"), o.get("id")) {
                    if t == "Group" || t == "Role" {
                        out.insert(format!("{t}::{id}"));
                    }
                }
                o.values().for_each(|x| walk(x, out));
            }
            Value::Array(a) => a.iter().for_each(|x| walk(x, out)),
            _ => {}
        }
    }
    let est = p.to_json().map_err(|e| Error::Authz(format!("policy {}: {e}", p.id())))?;
    let mut out = BTreeSet::new();
    walk(&est, &mut out);
    Ok(out)
}

fn action_keys(p: &Policy) -> Vec<String> {
    let key = |u: &EntityUid| if u.type_name().to_string() == "Action" { u.id().unescaped().to_string() } else { key_of(u) };
    match p.action_constraint() {
        ActionConstraint::Any => vec![ANY.into()],
        ActionConstraint::Eq(u) => vec![key(&u)],
        ActionConstraint::In(us) => us.iter().map(key).collect(),
    }
}

fn principal_key(p: &Policy) -> String {
    match p.principal_constraint() {
        PrincipalConstraint::Any | PrincipalConstraint::Is(_) => ANY.into(),
        PrincipalConstraint::Eq(u) | PrincipalConstraint::In(u) | PrincipalConstraint::IsIn(_, u) => key_of(&u),
    }
}

/// Split a Cedar source file into entries, in source order.
pub fn policy_entries(src: &str) -> Result<Vec<PolicyEntry>> {
    Ok(filed_policies(src)?.into_iter().map(|(e, _, _)| e).collect())
}

/// Entries with the action keys and principal key each is filed under.
fn filed_policies(src: &str) -> Result<Vec<(PolicyEntry, Vec<String>, String)>> {
    let set = PolicySet::from_str(src).map_err(|e| Error::Authz(format!("policies: {e}")))?;
    let mut ps: Vec<&Policy> = set.policies().collect();
    let pos = |p: &Policy| p.id().to_string().strip_prefix("policy").and_then(|n| n.parse::<u64>().ok()).unwrap_or(u64::MAX);
    ps.sort_by_key(|p| pos(p));
    let mut out = vec![];
    let mut seen = BTreeSet::new();
    for p in ps {
        let id = p.annotation("id").map(String::from).unwrap_or_else(|| p.id().to_string());
        if !seen.insert(id.clone()) {
            return Err(Error::Authz(format!("duplicate policy id {id}")));
        }
        let effect = match p.effect() {
            Effect::Permit => "permit",
            Effect::Forbid => "forbid",
        };
        let entry = PolicyEntry { id, effect: effect.into(), text: p.to_string(), refs: refs_of(p)?.into_iter().collect() };
        out.push((entry, action_keys(p), principal_key(p)));
    }
    Ok(out)
}

fn rule_refs(kind: &str, name: &str, rule: &str) -> Result<BTreeSet<String>> {
    let src = format!(
        "permit(principal, action == Action::\"{MEMBER_ACTION}\", resource == {kind}::{}) when {{ {rule} }};",
        serde_json::to_string(name)?
    );
    let p = Policy::parse(Some(PolicyId::new("rule")), src).map_err(|e| Error::Authz(format!("{kind} {name} rule: {e}")))?;
    let mut refs = refs_of(&p)?;
    refs.remove(&format!("{kind}::{name}"));
    Ok(refs)
}

fn links_sorted(mut items: Vec<(String, String)>) -> Value {
    items.sort();
    items.dedup();
    Value::Array(items.into_iter().map(|(_, cid)| link(&cid)).collect())
}

/// Write `bundle` into `store` as a policy DAG. Returns the root CID.
pub fn build(store: &dyn BlockPut, bundle: &Bundle) -> Result<String> {
    // Policies, each in its own block, filed by action and by principal.
    let mut by_action: BTreeMap<String, Vec<(String, String)>> = BTreeMap::new();
    let mut by_principal: BTreeMap<String, Vec<(String, String)>> = BTreeMap::new();
    for (e, actions, principal) in filed_policies(&bundle.policies)? {
        let cid = put_value(store, &serde_json::to_value(&e)?)?;
        for a in actions {
            by_action.entry(a).or_default().push((e.id.clone(), cid.clone()));
        }
        by_principal.entry(principal).or_default().push((e.id.clone(), cid));
    }

    // Groups and roles with their dependency edges in both directions.
    let mut sets: BTreeMap<String, SetEntry> = BTreeMap::new();
    let mut members: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for (kind, defs) in [("Group", &bundle.groups), ("Role", &bundle.roles)] {
        for (name, def) in defs {
            let key = format!("{kind}::{name}");
            let mut deps: BTreeSet<String> = def.members.iter().filter_map(|m| set_key(m)).collect();
            if let Some(rule) = &def.rule {
                deps.extend(rule_refs(kind, name, rule)?);
            }
            for m in def.members.iter().filter(|m| set_key(m).is_none()) {
                members.entry(m.clone()).or_default().insert(key.clone());
            }
            sets.insert(
                key,
                SetEntry {
                    kind: kind.into(),
                    name: name.clone(),
                    description: def.description.clone(),
                    members: def.members.clone(),
                    rule: def.rule.clone(),
                    deps: deps.into_iter().collect(),
                    dependents: vec![],
                },
            );
        }
    }
    let edges: Vec<(String, String)> = sets.values().flat_map(|s| s.deps.iter().map(|d| (d.clone(), s.key()))).collect();
    for (dep, dependent) in edges {
        if let Some(s) = sets.get_mut(&dep) {
            s.dependents.push(dependent);
        }
    }
    let mut set_links = BTreeMap::new();
    for (key, s) in &mut sets {
        s.dependents.sort();
        s.dependents.dedup();
        set_links.insert(key.clone(), link(&put_value(store, &serde_json::to_value(&*s)?)?));
    }

    let directory: BTreeMap<String, Value> = bundle
        .directory
        .iter()
        .map(|(id, d)| (id.clone(), json!({ "attrs": cedar_value(&Value::Object(d.attrs.clone())).unwrap_or(json!({})) })))
        .collect();
    let rules: Vec<String> = sets.values().filter(|s| s.rule.is_some()).map(SetEntry::key).collect();

    let root = json!({
        "kith": DAG_VERSION,
        "version": bundle.version,
        "actions": link(&map_build(store, &by_action.into_iter().map(|(k, v)| (k, links_sorted(v))).collect())?),
        "principals": link(&map_build(store, &by_principal.into_iter().map(|(k, v)| (k, links_sorted(v))).collect())?),
        "sets": link(&map_build(store, &set_links)?),
        "members": link(&map_build(store, &members.into_iter().map(|(k, v)| (k, json!(v))).collect())?),
        "directory": link(&map_build(store, &directory)?),
        "rules": rules,
    });
    put_value(store, &root)
}

struct Reader<'a> {
    store: &'a dyn BlockGet,
    root: Value,
}

impl Reader<'_> {
    fn index(&self, name: &str) -> Result<String> {
        as_link(&self.root[name]).map(String::from).ok_or_else(|| Error::Encoding(format!("policy dag root has no {name} index")))
    }

    fn lookup(&self, index: &str, key: &str) -> Result<Option<Value>> {
        map_get(self.store, &self.index(index)?, key)
    }

    fn policies(&self, index: &str, key: &str, out: &mut BTreeMap<String, PolicyEntry>) -> Result<()> {
        for l in self.lookup(index, key)?.and_then(|v| v.as_array().cloned()).unwrap_or_default() {
            let cid = as_link(&l).ok_or_else(|| Error::Encoding("policy index entry is not a link".into()))?;
            let e: PolicyEntry = serde_json::from_value(get_verified(self.store, cid)?)?;
            out.insert(e.id.clone(), e);
        }
        Ok(())
    }

    fn set(&self, key: &str) -> Result<Option<SetEntry>> {
        match self.lookup("sets", key)? {
            None => Ok(None),
            Some(l) => {
                let cid = as_link(&l).ok_or_else(|| Error::Encoding("set index entry is not a link".into()))?;
                Ok(Some(serde_json::from_value(get_verified(self.store, cid)?)?))
            }
        }
    }

    /// Fetch `start` and everything reachable through `deps` (and `dependents` if `up`).
    fn closure(&self, start: impl IntoIterator<Item = String>, up: bool, out: &mut BTreeMap<String, SetEntry>) -> Result<()> {
        let mut queue: Vec<String> = start.into_iter().collect();
        while let Some(k) = queue.pop() {
            if out.contains_key(&k) {
                continue;
            }
            if let Some(s) = self.set(&k)? {
                queue.extend(if up { s.dependents.clone() } else { s.deps.clone() });
                out.insert(k, s);
            }
        }
        Ok(())
    }
}

/// Read the slice for `query` from the DAG at `root`. Every block is hash-checked,
/// so `store` may be anyone: a hub, an IPFS gateway, a peer, a local cache.
pub fn load(store: &dyn BlockGet, root: &str, query: &Query) -> Result<Slice> {
    let root_v = get_verified(store, root)?;
    if root_v["kith"] != DAG_VERSION {
        return Err(Error::Unsupported(format!("policy dag {}", root_v["kith"])));
    }
    let r = Reader { store, root: root_v };
    let mut policies = BTreeMap::new();
    let mut sets = BTreeMap::new();
    let mut directory = BTreeMap::new();
    let principals: Vec<String> = match query {
        Query::Actions { actions, principals } => {
            for a in actions.iter().map(String::as_str).chain([ANY]) {
                r.policies("actions", a, &mut policies)?;
            }
            principals.clone()
        }
        Query::Principal { id } => {
            // Every set the principal could be in: the ones that list it, every rule
            // set, and everything that depends on those.
            let direct: Vec<String> = r.lookup("members", id)?.and_then(|v| serde_json::from_value(v).ok()).unwrap_or_default();
            let rules: Vec<String> = serde_json::from_value(r.root["rules"].clone()).unwrap_or_default();
            r.closure(direct.into_iter().chain(rules), true, &mut sets)?;
            let candidates: Vec<String> = sets.keys().cloned().collect();
            for key in candidates.iter().map(String::as_str).chain([ANY, format!("User::{id}").as_str()]) {
                r.policies("principals", key, &mut policies)?;
            }
            vec![id.clone()]
        }
    };
    // What those sets and policies need in order to evaluate.
    let wanted: Vec<String> = policies.values().flat_map(|p| p.refs.clone()).chain(sets.values().flat_map(|s| s.deps.clone())).collect();
    r.closure(wanted, false, &mut sets)?;
    for id in principals {
        if let Some(d) = r.lookup("directory", &id)? {
            directory.insert(id, serde_json::from_value(d)?);
        }
    }
    let version = r.root["version"].as_u64().unwrap_or(0) as u32;
    let mut policies: Vec<PolicyEntry> = policies.into_values().collect();
    policies.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(Slice { root: root.to_string(), version, sets, policies, directory })
}

/// Load a slice and return the exact blocks it read: a self-contained proof that
/// anyone holding `root` can check with [`load`] over just those blocks.
pub fn prove(store: &dyn BlockGet, root: &str, query: &Query) -> Result<(Slice, BTreeMap<String, Vec<u8>>)> {
    let rec = Recording::new(store);
    let slice = load(&rec, root, query)?;
    Ok((slice, rec.into_blocks()))
}

impl Slice {
    /// The slice as an ordinary bundle, minus policies (see [`Slice::engine`]).
    pub fn bundle(&self) -> Bundle {
        let mut b = Bundle { version: self.version, directory: self.directory.clone(), ..Default::default() };
        for s in self.sets.values() {
            let def = SetDef { description: s.description.clone(), members: s.members.clone(), rule: s.rule.clone() };
            if s.kind == "Group" {
                b.groups.insert(s.name.clone(), def);
            } else {
                b.roles.insert(s.name.clone(), def);
            }
        }
        b
    }

    /// A policy engine over just this slice, keeping each policy's stored id.
    /// `skip` removes permit policies by id (revocation, §8.7). Forbids are never
    /// removed: revocation may only take access away.
    pub fn engine_without(&self, skip: &BTreeSet<String>) -> Result<Engine> {
        let mut set = PolicySet::new();
        for p in &self.policies {
            if p.effect == "permit" && skip.contains(&p.id) {
                continue;
            }
            let policy = Policy::parse(Some(PolicyId::new(&p.id)), &p.text).map_err(|e| Error::Authz(format!("policy {}: {e}", p.id)))?;
            set.add(policy).map_err(|e| Error::Authz(e.to_string()))?;
        }
        Engine::with_policy_set(self.bundle(), set)
    }

    pub fn engine(&self) -> Result<Engine> {
        self.engine_without(&BTreeSet::new())
    }

    /// Policy ids in this slice.
    pub fn policy_ids(&self) -> Vec<&str> {
        self.policies.iter().map(|p| p.id.as_str()).collect()
    }
}

/// A slice plus its proof blocks, as served over HTTP and stored in test vectors.
pub fn slice_response(root: &str, query: &Query, blocks: &BTreeMap<String, Vec<u8>>) -> Value {
    json!({ "root": root, "query": query, "blocks": dag::blocks_to_json(blocks) })
}

pub fn directory_attrs(slice: &Slice, id: &str) -> Map<String, Value> {
    slice.directory.get(id).map(|d| d.attrs.clone()).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authz::{Principal, Resource};
    use crate::dag::MemStore;

    fn vectors() -> Value {
        serde_json::from_str(include_str!("../../../spec/test-vectors/authz.json")).unwrap()
    }

    fn decide(e: &Engine, d: &Value) -> bool {
        let id = d["principal"].as_str().unwrap();
        let attrs = e.attributes(id, d["attrs"].as_object().unwrap());
        let m = e.memberships(id, &attrs).unwrap();
        let p = Principal {
            id: id.into(),
            attrs,
            groups: m.groups,
            roles: m.roles,
            actor: d["actor"].as_str().map(String::from),
            caps: d.get("caps").map(|c| serde_json::from_value(c.clone()).unwrap()),
        };
        let mut r = Resource::new(d["resource"]["type"].as_str().unwrap(), d["resource"]["id"].as_str().unwrap());
        if let Some(a) = d["resource"]["attrs"].as_object() {
            r.attrs = a.clone();
        }
        e.authorize(&p, d["action"].as_str().unwrap(), &r, &d["context"]).unwrap().allowed
    }

    /// The property the whole design rests on: a slice decides exactly like the
    /// full bundle, for every conformance vector, from its proof blocks alone.
    #[test]
    fn slices_decide_like_the_full_bundle() {
        let v = vectors();
        let bundle: Bundle = serde_json::from_value(v["bundle"].clone()).unwrap();
        let full = Engine::new(bundle.clone()).unwrap();
        let store = MemStore::new();
        let root = build(&store, &bundle).unwrap();
        for d in v["decisions"].as_array().unwrap() {
            let id = d["principal"].as_str().unwrap().to_string();
            for q in [Query::Actions { actions: vec![d["action"].as_str().unwrap().into()], principals: vec![id.clone()] }, Query::Principal { id }] {
                let (_, proof) = prove(&store, &root, &q).unwrap();
                assert!(proof.len() < store.len(), "{q:?} fetched the whole dag");
                let slice = load(&MemStore::from_blocks(proof), &root, &q).unwrap();
                assert_eq!(decide(&slice.engine().unwrap(), d), decide(&full, d), "{} via {q:?}", d["name"]);
                assert_eq!(decide(&full, d), d["allowed"].as_bool().unwrap());
            }
        }
        // A principal slice computes the same memberships as the full bundle.
        for m in v["memberships"].as_array().unwrap() {
            let id = m["id"].as_str().unwrap();
            let slice = load(&store, &root, &Query::Principal { id: id.into() }).unwrap();
            let e = slice.engine().unwrap();
            let got = e.memberships(id, &e.attributes(id, m["attrs"].as_object().unwrap())).unwrap();
            assert_eq!(json!(got.groups), m["groups"], "{id}");
            assert_eq!(json!(got.roles), m["roles"], "{id}");
        }
    }

    #[test]
    fn building_is_deterministic_and_slices_are_narrow() {
        let bundle: Bundle = serde_json::from_value(vectors()["bundle"].clone()).unwrap();
        let a = MemStore::new();
        let b = MemStore::new();
        assert_eq!(build(&a, &bundle).unwrap(), build(&b, &bundle).unwrap());
        let root = build(&a, &bundle).unwrap();
        let s = load(&a, &root, &Query::Actions { actions: vec!["Query.invoices".into()], principals: vec![] }).unwrap();
        assert_eq!(s.policy_ids(), vec!["read-invoices"]);
        // billing-reader needs finance, which needs contractors. Nothing else.
        assert_eq!(s.sets.keys().collect::<Vec<_>>(), vec!["Group::contractors", "Group::finance", "Role::billing-reader"]);
        // Forbids travel with their action: a slice can't silently drop one.
        let pay = load(&a, &root, &Query::Actions { actions: vec!["Mutation.payInvoice".into()], principals: vec![] }).unwrap();
        assert!(pay.policies.iter().any(|p| p.effect == "forbid"));
    }

    #[test]
    fn a_withheld_block_fails_closed() {
        let bundle: Bundle = serde_json::from_value(vectors()["bundle"].clone()).unwrap();
        let store = MemStore::new();
        let root = build(&store, &bundle).unwrap();
        let q = Query::Actions { actions: vec!["Mutation.payInvoice".into()], principals: vec![] };
        let (_, mut proof) = prove(&store, &root, &q).unwrap();
        // Drop the block holding the forbid policy: the load must error, not succeed without it.
        let forbid = proof.iter().find(|(_, b)| String::from_utf8_lossy(b).contains("\"effect\":\"forbid\"")).map(|(c, _)| c.clone()).unwrap();
        proof.remove(&forbid);
        assert!(load(&MemStore::from_blocks(proof), &root, &q).is_err());
    }
}
