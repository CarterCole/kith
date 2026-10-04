//! Authorization: groups (explicit + dynamic), roles, and Cedar policies.
//!
//! A *policy bundle* is the portable unit every Kith implementation loads:
//!
//! ```json
//! {
//!   "version": 1,
//!   "groups": {
//!     "finance":  { "members": ["did:kith:…", "group:finance-contractors"] },
//!     "staff":    { "rule": "principal has email && principal.email like \"*@acme.test\"" },
//!     "strong":   { "rule": "principal.aal >= 2" }
//!   },
//!   "roles": {
//!     "billing-reader": { "members": ["group:finance"] },
//!     "billing-admin":  { "rule": "principal in Group::\"finance\" && principal in Group::\"strong\"" }
//!   },
//!   "directory": { "did:kith:…": { "attrs": { "email": "ada@acme.test", "department": "finance" } } },
//!   "policies": "permit(principal in Role::\"billing-reader\", action == Action::\"Query.invoices\", resource);"
//! }
//! ```
//!
//! Dynamic membership rules are *propositions* written in Cedar's expression
//! language – the same language as policy conditions – evaluated against the
//! principal. Membership is computed to a fixpoint so rules may reference other
//! groups. Each rule compiles to its own Cedar policy
//! (`permit(principal, action == Action::"kith:member", resource == Group::"x") when { rule }`),
//! which means any Cedar binding (Rust, wasm, Python, Go) evaluates it identically.

use std::collections::{BTreeMap, BTreeSet};
use std::str::FromStr;

use cedar_policy::{Authorizer, Context, Decision, Entities, EntityId, EntityTypeName, EntityUid, Policy, PolicyId, PolicySet, Request};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

use crate::session::{caps_allow, Capability};
use crate::{Error, Result};

pub const MEMBER_ACTION: &str = "kith:member";

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct SetDef {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Explicit members: principal ids, `group:<name>` (nested groups).
    #[serde(default)]
    pub members: Vec<String>,
    /// Dynamic membership proposition (Cedar expression over `principal`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct DirEntry {
    #[serde(default)]
    pub attrs: Map<String, Value>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Bundle {
    pub version: u32,
    #[serde(default)]
    pub groups: BTreeMap<String, SetDef>,
    #[serde(default)]
    pub roles: BTreeMap<String, SetDef>,
    #[serde(default)]
    pub directory: BTreeMap<String, DirEntry>,
    #[serde(default)]
    pub policies: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Memberships {
    pub groups: Vec<String>,
    pub roles: Vec<String>,
}

/// The authenticated principal as the policy engine sees it.
#[derive(Debug, Clone, Default)]
pub struct Principal {
    pub id: String,
    pub attrs: Map<String, Value>,
    pub groups: Vec<String>,
    pub roles: Vec<String>,
    /// Present when an actor is exercising a delegation on the principal's behalf.
    pub actor: Option<String>,
    pub caps: Option<Vec<Capability>>,
}

#[derive(Debug, Clone)]
pub struct Resource {
    pub kind: String,
    pub id: String,
    pub attrs: Map<String, Value>,
}

impl Resource {
    pub fn new(kind: impl Into<String>, id: impl Into<String>) -> Self {
        Resource { kind: kind.into(), id: id.into(), attrs: Map::new() }
    }
    pub fn uid_string(&self) -> String {
        format!("{}::{}", self.kind, serde_json::to_string(&self.id).unwrap())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AuthzDecision {
    pub allowed: bool,
    /// Ids of the policies that determined the decision.
    pub reasons: Vec<String>,
    pub errors: Vec<String>,
}

pub struct Engine {
    pub bundle: Bundle,
    policies: PolicySet,
    membership: PolicySet,
    authorizer: Authorizer,
}

fn uid(kind: &str, id: &str) -> Result<EntityUid> {
    let t = EntityTypeName::from_str(kind).map_err(|e| Error::Authz(format!("entity type {kind}: {e}")))?;
    Ok(EntityUid::from_type_name_and_id(t, EntityId::new(id)))
}

/// Cedar has no null or floating point: drop nulls, stringify non-integers.
pub fn cedar_value(v: &Value) -> Option<Value> {
    match v {
        Value::Null => None,
        Value::Number(n) if n.is_f64() => Some(Value::String(n.to_string())),
        Value::Array(a) => Some(Value::Array(a.iter().filter_map(cedar_value).collect())),
        Value::Object(o) => Some(Value::Object(o.iter().filter_map(|(k, v)| cedar_value(v).map(|v| (k.clone(), v))).collect())),
        other => Some(other.clone()),
    }
}

fn cedar_map(m: &Map<String, Value>) -> Value {
    cedar_value(&Value::Object(m.clone())).unwrap_or(json!({}))
}

fn entity(kind: &str, id: &str, attrs: Value, parents: Vec<(&str, &str)>) -> Value {
    json!({
        "uid": {"type": kind, "id": id},
        "attrs": attrs,
        "parents": parents.into_iter().map(|(t, i)| json!({"type": t, "id": i})).collect::<Vec<_>>(),
    })
}

impl Engine {
    pub fn new(bundle: Bundle) -> Result<Self> {
        let policies = PolicySet::from_str(&bundle.policies).map_err(|e| Error::Authz(format!("policies: {e}")))?;
        Self::with_policy_set(bundle, policies)
    }

    /// An engine over `bundle`'s sets and directory with an already-built policy set
    /// (`bundle.policies` is ignored). Used for policy DAG slices.
    pub fn with_policy_set(bundle: Bundle, policies: PolicySet) -> Result<Self> {
        let mut membership = PolicySet::new();
        for (kind, sets) in [("Group", &bundle.groups), ("Role", &bundle.roles)] {
            for (name, def) in sets {
                if let Some(rule) = &def.rule {
                    let id = format!("member:{kind}:{name}");
                    let src = format!(
                        "permit(principal, action == Action::\"{MEMBER_ACTION}\", resource == {kind}::{}) when {{ {rule} }};",
                        serde_json::to_string(name)?
                    );
                    let p = Policy::parse(Some(PolicyId::new(&id)), src).map_err(|e| Error::Authz(format!("{kind} {name} rule: {e}")))?;
                    membership.add(p).map_err(|e| Error::Authz(e.to_string()))?;
                }
            }
        }
        Ok(Engine { bundle, policies, membership, authorizer: Authorizer::new() })
    }

    pub fn from_json(json: &str) -> Result<Self> {
        Self::new(serde_json::from_str(json)?)
    }

    /// Directory attributes for a principal merged with (and overriding) `attrs`.
    pub fn attributes(&self, id: &str, attrs: &Map<String, Value>) -> Map<String, Value> {
        let mut out = self.bundle.directory.get(id).map(|d| d.attrs.clone()).unwrap_or_default();
        for (k, v) in attrs {
            out.insert(k.clone(), v.clone());
        }
        out
    }

    fn set_entities(&self) -> Vec<Value> {
        let mut out = vec![];
        for g in self.bundle.groups.keys() {
            out.push(entity("Group", g, json!({}), vec![]));
        }
        for r in self.bundle.roles.keys() {
            out.push(entity("Role", r, json!({}), vec![]));
        }
        out
    }

    fn principal_entity(&self, id: &str, attrs: &Map<String, Value>, groups: &BTreeSet<String>, roles: &BTreeSet<String>) -> Value {
        let parents = groups.iter().map(|g| ("Group", g.as_str())).chain(roles.iter().map(|r| ("Role", r.as_str()))).collect();
        entity("User", id, cedar_map(attrs), parents)
    }

    /// Compute explicit + nested + dynamic group and role membership.
    pub fn memberships(&self, id: &str, attrs: &Map<String, Value>) -> Result<Memberships> {
        self.memberships_excluding(id, attrs, &BTreeSet::new())
    }

    /// Memberships with some sets (`Group::x`, `Role::x`) ruled out, as revocations
    /// require. An excluded set never joins, so neither do sets that depended on it.
    pub fn memberships_excluding(&self, id: &str, attrs: &Map<String, Value>, excluded: &BTreeSet<String>) -> Result<Memberships> {
        let mut groups = BTreeSet::new();
        let mut roles = BTreeSet::new();
        let limit = self.bundle.groups.len() + self.bundle.roles.len() + 1;
        for _ in 0..limit {
            let mut changed = false;
            let entities = {
                let mut es = self.set_entities();
                es.push(self.principal_entity(id, attrs, &groups, &roles));
                Entities::from_json_value(Value::Array(es), None).map_err(|e| Error::Authz(format!("entities: {e}")))?
            };
            for (kind, defs) in [("Group", &self.bundle.groups), ("Role", &self.bundle.roles)] {
                for (name, def) in defs {
                    let current = if kind == "Group" { &groups } else { &roles };
                    if current.contains(name) || excluded.contains(&format!("{kind}::{name}")) {
                        continue;
                    }
                    let explicit = def.members.iter().any(|m| {
                        m == id || m.strip_prefix("group:").is_some_and(|g| groups.contains(g)) || m.strip_prefix("role:").is_some_and(|r| roles.contains(r))
                    });
                    let dynamic = def.rule.is_some() && {
                        let req = Request::new(uid("User", id)?, uid("Action", MEMBER_ACTION)?, uid(kind, name)?, Context::empty(), None)
                            .map_err(|e| Error::Authz(e.to_string()))?;
                        self.authorizer.is_authorized(&req, &self.membership, &entities).decision() == Decision::Allow
                    };
                    if explicit || dynamic {
                        if kind == "Group" {
                            groups.insert(name.clone());
                        } else {
                            roles.insert(name.clone());
                        }
                        changed = true;
                    }
                }
            }
            if !changed {
                break;
            }
        }
        Ok(Memberships { groups: groups.into_iter().collect(), roles: roles.into_iter().collect() })
    }

    /// Evaluate `action` on `resource` for `principal`. Delegated principals must also
    /// hold a matching capability (attenuation): delegation can only narrow access.
    pub fn authorize(&self, principal: &Principal, action: &str, resource: &Resource, context: &Value) -> Result<AuthzDecision> {
        if let Some(caps) = &principal.caps {
            if !caps_allow(caps, action, &resource.uid_string()) {
                return Ok(AuthzDecision { allowed: false, reasons: vec!["delegation:cap".into()], errors: vec![] });
            }
        }
        let groups: BTreeSet<String> = principal.groups.iter().cloned().collect();
        let roles: BTreeSet<String> = principal.roles.iter().cloned().collect();
        let mut es = self.set_entities();
        es.push(self.principal_entity(&principal.id, &principal.attrs, &groups, &roles));
        es.push(entity(&resource.kind, &resource.id, cedar_map(&resource.attrs), vec![]));
        let entities = Entities::from_json_value(Value::Array(es), None).map_err(|e| Error::Authz(format!("entities: {e}")))?;
        let mut ctx = cedar_value(context).unwrap_or(json!({}));
        if !ctx.is_object() {
            ctx = json!({});
        }
        if let Some(actor) = &principal.actor {
            ctx["actor"] = json!(actor);
        }
        let context = Context::from_json_value(ctx, None).map_err(|e| Error::Authz(format!("context: {e}")))?;
        let req = Request::new(uid("User", &principal.id)?, uid("Action", action)?, uid(&resource.kind, &resource.id)?, context, None)
            .map_err(|e| Error::Authz(e.to_string()))?;
        let resp = self.authorizer.is_authorized(&req, &self.policies, &entities);
        Ok(AuthzDecision {
            allowed: resp.decision() == Decision::Allow,
            reasons: resp.diagnostics().reason().map(|p| p.to_string()).collect(),
            errors: resp.diagnostics().errors().map(|e| e.to_string()).collect(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BUNDLE: &str = r#"{
      "version": 1,
      "groups": {
        "finance": { "members": ["did:kith:ada", "group:contractors"] },
        "contractors": { "members": ["did:kith:bob"] },
        "staff": { "rule": "principal has email && principal.email like \"*@acme.test\"" },
        "strong": { "rule": "principal.aal >= 2" }
      },
      "roles": {
        "billing-reader": { "members": ["group:finance"] },
        "billing-admin": { "rule": "principal in Group::\"finance\" && principal in Group::\"strong\"" }
      },
      "directory": {
        "did:kith:ada": { "attrs": { "email": "ada@acme.test", "department": "finance" } }
      },
      "policies": "@id(\"read-invoices\")\npermit(principal in Role::\"billing-reader\", action == Action::\"Query.invoices\", resource);\n@id(\"pay\")\npermit(principal in Role::\"billing-admin\", action == Action::\"Mutation.payInvoice\", resource) when { context has amount && context.amount < 10000 };\n@id(\"own-invoice\")\npermit(principal, action == Action::\"Invoice.read\", resource) when { resource has ownerId && resource.ownerId == principal.email };\n@id(\"no-delegated-pay\")\nforbid(principal, action == Action::\"Mutation.payInvoice\", resource) when { context has actor };"
    }"#;

    fn principal(e: &Engine, id: &str, aal: i64) -> Principal {
        let mut attrs = e.attributes(id, &Map::new());
        attrs.insert("aal".into(), json!(aal));
        let m = e.memberships(id, &attrs).unwrap();
        Principal { id: id.into(), attrs, groups: m.groups, roles: m.roles, actor: None, caps: None }
    }

    #[test]
    fn explicit_nested_and_dynamic_membership() {
        let e = Engine::from_json(BUNDLE).unwrap();
        let ada = principal(&e, "did:kith:ada", 2);
        assert_eq!(ada.groups, vec!["finance", "staff", "strong"]);
        assert_eq!(ada.roles, vec!["billing-admin", "billing-reader"]);
        let bob = principal(&e, "did:kith:bob", 1);
        assert_eq!(bob.groups, vec!["contractors", "finance"]);
        assert_eq!(bob.roles, vec!["billing-reader"]);
    }

    #[test]
    fn policies_with_context_and_resource_attrs() {
        let e = Engine::from_json(BUNDLE).unwrap();
        let ada = principal(&e, "did:kith:ada", 2);
        let bob = principal(&e, "did:kith:bob", 1);
        let op = Resource::new("Operation", "Query.invoices");
        assert!(e.authorize(&ada, "Query.invoices", &op, &json!({})).unwrap().allowed);
        assert!(e.authorize(&bob, "Query.invoices", &op, &json!({})).unwrap().allowed);
        let pay = Resource::new("Operation", "Mutation.payInvoice");
        assert!(e.authorize(&ada, "Mutation.payInvoice", &pay, &json!({"amount": 500})).unwrap().allowed);
        assert!(!e.authorize(&ada, "Mutation.payInvoice", &pay, &json!({"amount": 50000})).unwrap().allowed);
        assert!(!e.authorize(&bob, "Mutation.payInvoice", &pay, &json!({"amount": 5})).unwrap().allowed);

        let mut inv = Resource::new("Invoice", "inv_1");
        inv.attrs.insert("ownerId".into(), json!("ada@acme.test"));
        inv.attrs.insert("amount".into(), json!(12.5)); // floats are stringified, not rejected
        assert!(e.authorize(&ada, "Invoice.read", &inv, &json!({})).unwrap().allowed);
        assert!(!e.authorize(&bob, "Invoice.read", &inv, &json!({})).unwrap().allowed);
    }

    #[test]
    fn delegation_attenuates() {
        let e = Engine::from_json(BUNDLE).unwrap();
        let mut ada = principal(&e, "did:kith:ada", 2);
        ada.actor = Some("did:kith:assistant".into());
        ada.caps = Some(vec![Capability::new("Query.*"), Capability::new("Mutation.payInvoice")]);
        let op = Resource::new("Operation", "Query.invoices");
        assert!(e.authorize(&ada, "Query.invoices", &op, &json!({})).unwrap().allowed);
        // cap allows it, but the policy forbids delegated payments.
        let pay = Resource::new("Operation", "Mutation.payInvoice");
        assert!(!e.authorize(&ada, "Mutation.payInvoice", &pay, &json!({"amount": 5})).unwrap().allowed);
        // no cap for Invoice.read
        let mut inv = Resource::new("Invoice", "inv_1");
        inv.attrs.insert("ownerId".into(), json!("ada@acme.test"));
        assert!(!e.authorize(&ada, "Invoice.read", &inv, &json!({})).unwrap().allowed);
    }

    /// Shared conformance vectors (also run by the JS and Python packages).
    #[test]
    fn conformance_vectors() {
        let v: Value = serde_json::from_str(include_str!("../../../spec/test-vectors/authz.json")).unwrap();
        let e = Engine::new(serde_json::from_value(v["bundle"].clone()).unwrap()).unwrap();
        for m in v["memberships"].as_array().unwrap() {
            let id = m["id"].as_str().unwrap();
            let attrs = e.attributes(id, m["attrs"].as_object().unwrap());
            let got = e.memberships(id, &attrs).unwrap();
            assert_eq!(json!(got.groups), m["groups"], "groups for {id} {}", m["attrs"]);
            assert_eq!(json!(got.roles), m["roles"], "roles for {id} {}", m["attrs"]);
        }
        for d in v["decisions"].as_array().unwrap() {
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
            let got = e.authorize(&p, d["action"].as_str().unwrap(), &r, &d["context"]).unwrap();
            assert_eq!(got.allowed, d["allowed"].as_bool().unwrap(), "{}: {got:?}", d["name"]);
        }
    }

    #[test]
    fn rule_injection_is_rejected() {
        let bad = r#"{"version":1,"groups":{"x":{"rule":"true }; permit(principal, action, resource) when { true"}},"policies":""}"#;
        assert!(Engine::from_json(bad).is_err());
    }
}
