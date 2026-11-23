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
/// The action an `assume` rule compiles to (spec §4.3.1).
pub const ASSUME_ACTION: &str = "kith:assume";

/// A member that may be left out but not written as `null`: `null` would otherwise read
/// as "absent", and an `"assume": null` would quietly make a role not assumable while
/// the other implementations refuse the bundle (spec §4.3.1).
pub(crate) fn present<'de, D: serde::Deserializer<'de>, T: Deserialize<'de>>(d: D) -> std::result::Result<Option<T>, D::Error> {
    T::deserialize(d).map(Some)
}

/// Who may take on a role for a session, and for how long (spec §4.3.1). A role without
/// this setting is never assumed, whoever asks.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssumeDef {
    /// Principal ids, `group:<name>` and `role:<name>`, as in a set's `members`.
    #[serde(default)]
    pub members: Vec<String>,
    /// A Cedar expression over `principal`, as in a set's `rule`.
    #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "present")]
    pub rule: Option<String>,
    /// The longest an access token carrying the role may live, in seconds.
    #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "present")]
    pub max_age: Option<u64>,
}

/// Why a session may not assume a role (spec §4.3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Refusal {
    /// There is no such role, or it has no `assume` setting.
    NotAssumable,
    /// The role is assumable, but not by this principal now.
    NotEligible,
}

impl Refusal {
    pub fn code(self) -> &'static str {
        match self {
            Refusal::NotAssumable => "not_assumable",
            Refusal::NotEligible => "not_eligible",
        }
    }
}

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
    /// Roles only: who may assume this role. A role with this setting is held only by
    /// assuming it, so it has no `members` and no `rule`.
    #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "present")]
    pub assume: Option<AssumeDef>,
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

/// Why a principal is in a set (spec §4.3, §10.8). The first reason found wins, in the
/// order the evaluation reaches them: listed by id, then through a nested set, then by rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "via", rename_all = "snake_case")]
pub enum Basis {
    /// The principal's id is in the set's `members`.
    Listed,
    /// `group:<name>` (or `role:<name>`) is in `members`, and the principal is in it.
    Nested { set: String },
    /// The set's dynamic rule held.
    Rule,
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
    /// The role this session assumed (spec §4.3.1). It is in `roles` as well.
    pub assumed: Option<String>,
}

/// A reference to an entity: a parent of a resource (spec §4.2.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntityRef {
    #[serde(rename = "type")]
    pub kind: String,
    pub id: String,
}

impl EntityRef {
    pub fn new(kind: impl Into<String>, id: impl Into<String>) -> Self {
        EntityRef { kind: kind.into(), id: id.into() }
    }
}

/// An entity a request describes besides its principal and resource (spec §4.2.1): an
/// ancestor of the resource, or something one of its attributes refers to.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Entity {
    #[serde(rename = "type")]
    pub kind: String,
    pub id: String,
    #[serde(default)]
    pub attrs: Map<String, Value>,
    #[serde(default)]
    pub parents: Vec<EntityRef>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Resource {
    #[serde(rename = "type")]
    pub kind: String,
    pub id: String,
    #[serde(default)]
    pub attrs: Map<String, Value>,
    /// What the resource is directly in. `resource in Folder::"x"` holds when `x` is a
    /// parent, or is reached from one through `related`.
    #[serde(default)]
    pub parents: Vec<EntityRef>,
    /// The other entities policies may walk to from this resource.
    #[serde(default)]
    pub related: Vec<Entity>,
}

impl Resource {
    pub fn new(kind: impl Into<String>, id: impl Into<String>) -> Self {
        Resource { kind: kind.into(), id: id.into(), attrs: Map::new(), parents: vec![], related: vec![] }
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
    assume: PolicySet,
    authorizer: Authorizer,
}

fn uid(kind: &str, id: &str) -> Result<EntityUid> {
    let t = EntityTypeName::from_str(kind).map_err(|e| Error::Authz(format!("entity type {kind}: {e}")))?;
    Ok(EntityUid::from_type_name_and_id(t, EntityId::new(id)))
}

/// Cedar has no null or floating point: drop nulls, stringify non-integers. A float with
/// no fractional part (`2.0`) is the integer it says, as it already is in JavaScript,
/// where the two cannot be told apart.
pub fn cedar_value(v: &Value) -> Option<Value> {
    match v {
        Value::Null => None,
        Value::Number(n) if n.is_f64() => match n.as_f64() {
            Some(f) if f.fract() == 0.0 && f.abs() <= 9_007_199_254_740_991.0 => Some(Value::from(f as i64)),
            _ => Some(Value::String(n.to_string())),
        },
        Value::Array(a) => Some(Value::Array(a.iter().filter_map(cedar_value).collect())),
        Value::Object(o) => Some(Value::Object(o.iter().filter_map(|(k, v)| cedar_value(v).map(|v| (k.clone(), v))).collect())),
        other => Some(other.clone()),
    }
}

fn cedar_map(m: &Map<String, Value>) -> Value {
    cedar_value(&Value::Object(m.clone())).unwrap_or(json!({}))
}

/// The pinned text of a stringified number (spec §4.2): ECMAScript `Number::toString`,
/// the form RFC 8785 §3.2.2.3 uses. It is the shortest digits that read back as `f`,
/// written plainly when the decimal exponent is in −7 < e < 21 and as `d.ddde+N` or
/// `d.ddde-N` otherwise.
pub fn number_text(f: f64) -> String {
    if f == 0.0 {
        return "0".into();
    }
    let sign = if f < 0.0 { "-" } else { "" };
    // serde_json prints the shortest digits, as `ddd.ddd` or `d.ddde[+-]N`. `{:e}` is no
    // substitute: between two equally near candidates it rounds up, where ECMAScript
    // takes the even digit.
    let Some(shortest) = serde_json::Number::from_f64(f.abs()).map(|n| n.to_string()) else {
        return if f.is_nan() { "NaN".into() } else { format!("{sign}Infinity") };
    };
    let (mantissa, exp) = shortest.split_once('e').unwrap_or((&shortest, "0"));
    let (whole, frac) = mantissa.split_once('.').unwrap_or((mantissa, ""));
    let all = format!("{whole}{frac}");
    let digits = all.trim_start_matches('0');
    // The decimal point sits after digit `n` of the `k` digits.
    let n = whole.len() as i32 + exp.parse::<i32>().unwrap() - (all.len() - digits.len()) as i32;
    let digits = digits.trim_end_matches('0');
    let k = digits.len() as i32;
    if (k..=21).contains(&n) {
        format!("{sign}{digits}{}", "0".repeat((n - k) as usize))
    } else if (1..=21).contains(&n) {
        format!("{sign}{}.{}", &digits[..n as usize], &digits[n as usize..])
    } else if (-5..=0).contains(&n) {
        format!("{sign}0.{}{digits}", "0".repeat(-n as usize))
    } else {
        let point = if k > 1 { "." } else { "" };
        format!("{sign}{}{point}{}e{}{}", &digits[..1], &digits[1..], if n > 0 { '+' } else { '-' }, (n - 1).abs())
    }
}

/// A typed value (spec §4.2.2), in the form Cedar's JSON reads. A plain JSON string is
/// always a `String`: an address, a time or a decimal has to say that it is one.
pub mod typed {
    use serde_json::{json, Value};

    fn ext(f: &str, arg: &str) -> Value {
        json!({"__extn": {"fn": f, "arg": arg}})
    }
    /// An IP address or CIDR range: `10.1.2.3`, `10.0.0.0/8`, `::1`.
    pub fn ip(text: &str) -> Value {
        ext("ip", text)
    }
    /// A decimal with at most four fractional digits: `12.50`.
    pub fn decimal(text: &str) -> Value {
        ext("decimal", text)
    }
    /// A date or an instant: `2030-01-01`, `2030-01-01T09:30:00Z`.
    pub fn datetime(text: &str) -> Value {
        ext("datetime", text)
    }
    /// A length of time: `1h30m`, `-2d`.
    pub fn duration(text: &str) -> Value {
        ext("duration", text)
    }
    /// A reference to another entity, such as a document's owner.
    pub fn entity(kind: &str, id: &str) -> Value {
        json!({"__entity": {"type": kind, "id": id}})
    }
}

/// Entity types a request may not describe: the bundle and the engine supply these.
fn reserved_type(kind: &str) -> bool {
    matches!(kind, "Group" | "Role" | "Action") || kind.ends_with("::Action")
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
        let mut assume = PolicySet::new();
        let compile = |set: &mut PolicySet, id: String, action: &str, kind: &str, name: &str, rule: &str| -> Result<()> {
            let src = format!("permit(principal, action == Action::\"{action}\", resource == {kind}::{}) when {{ {rule} }};", serde_json::to_string(name)?);
            let p = Policy::parse(Some(PolicyId::new(&id)), src).map_err(|e| Error::Authz(format!("{kind} {name} rule: {e}")))?;
            set.add(p).map_err(|e| Error::Authz(e.to_string()))
        };
        for (kind, sets) in [("Group", &bundle.groups), ("Role", &bundle.roles)] {
            for (name, def) in sets {
                if let Some(rule) = &def.rule {
                    compile(&mut membership, format!("member:{kind}:{name}"), MEMBER_ACTION, kind, name, rule)?;
                }
                let Some(a) = &def.assume else { continue };
                if kind == "Group" {
                    return Err(Error::Authz(format!("group {name}: only a role can be assumed")));
                }
                if !def.members.is_empty() || def.rule.is_some() {
                    return Err(Error::Authz(format!("role {name} is assumable, so it is held only by assuming it: it has no members and no rule")));
                }
                if a.max_age == Some(0) {
                    return Err(Error::Authz(format!("role {name}: max_age is a positive number of seconds")));
                }
                if let Some(rule) = &a.rule {
                    compile(&mut assume, format!("assume:{name}"), ASSUME_ACTION, kind, name, rule)?;
                }
            }
        }
        Ok(Engine { bundle, policies, membership, assume, authorizer: Authorizer::new() })
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
        Ok(self.explain_memberships(id, attrs, excluded)?.0)
    }

    /// [`Self::memberships_excluding`], and for each set (`Group::x`, `Role::x`) the
    /// reason the principal is in it.
    pub fn explain_memberships(&self, id: &str, attrs: &Map<String, Value>, excluded: &BTreeSet<String>) -> Result<(Memberships, BTreeMap<String, Basis>)> {
        self.fixpoint(id, attrs, excluded, None)
    }

    /// The §4.3 fixpoint. `seed` is an assumed role (§4.3.1): held from the start, so
    /// every set that lists it or whose rule names it is computed with it.
    fn fixpoint(&self, id: &str, attrs: &Map<String, Value>, excluded: &BTreeSet<String>, seed: Option<&str>) -> Result<(Memberships, BTreeMap<String, Basis>)> {
        let mut why = BTreeMap::new();
        let mut groups = BTreeSet::new();
        let mut roles: BTreeSet<String> = seed.map(String::from).into_iter().collect();
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
                    let explicit = def.members.iter().find_map(|m| {
                        if m == id {
                            return Some(Basis::Listed);
                        }
                        let (kind, name) = m.split_once(':')?;
                        let held = match kind {
                            "group" => groups.contains(name),
                            "role" => roles.contains(name),
                            _ => false,
                        };
                        held.then(|| Basis::Nested { set: format!("{}::{name}", if kind == "group" { "Group" } else { "Role" }) })
                    });
                    let dynamic = explicit.is_none() && def.rule.is_some() && {
                        let req = Request::new(uid("User", id)?, uid("Action", MEMBER_ACTION)?, uid(kind, name)?, Context::empty(), None)
                            .map_err(|e| Error::Authz(e.to_string()))?;
                        self.authorizer.is_authorized(&req, &self.membership, &entities).decision() == Decision::Allow
                    };
                    if let Some(basis) = explicit.or(dynamic.then_some(Basis::Rule)) {
                        why.insert(format!("{kind}::{name}"), basis);
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
        Ok((Memberships { groups: groups.into_iter().collect(), roles: roles.into_iter().collect() }, why))
    }

    /// Memberships for a session that assumes `role` (spec §4.3.1): the standing ones,
    /// with the sets in `excluded` revoked, plus the role. The role must have an
    /// `assume` setting that the principal meets, and must not be in `excluded`.
    pub fn assume(&self, id: &str, attrs: &Map<String, Value>, excluded: &BTreeSet<String>, role: &str) -> Result<std::result::Result<Memberships, Refusal>> {
        let Some(a) = self.bundle.roles.get(role).and_then(|d| d.assume.as_ref()) else {
            return Ok(Err(Refusal::NotAssumable));
        };
        let m = self.memberships_excluding(id, attrs, excluded)?;
        if excluded.contains(&format!("Role::{role}")) {
            return Ok(Err(Refusal::NotEligible));
        }
        let listed = a.members.iter().any(|x| {
            x == id
                || x.strip_prefix("group:").is_some_and(|g| m.groups.iter().any(|h| h == g))
                || x.strip_prefix("role:").is_some_and(|r| m.roles.iter().any(|h| h == r))
        });
        let by_rule = !listed && a.rule.is_some() && {
            let (groups, roles) = (m.groups.iter().cloned().collect(), m.roles.iter().cloned().collect());
            let mut es = self.set_entities();
            es.push(self.principal_entity(id, attrs, &groups, &roles));
            let entities = Entities::from_json_value(Value::Array(es), None).map_err(|e| Error::Authz(format!("entities: {e}")))?;
            let req = Request::new(uid("User", id)?, uid("Action", ASSUME_ACTION)?, uid("Role", role)?, Context::empty(), None).map_err(|e| Error::Authz(e.to_string()))?;
            self.authorizer.is_authorized(&req, &self.assume, &entities).decision() == Decision::Allow
        };
        if !listed && !by_rule {
            return Ok(Err(Refusal::NotEligible));
        }
        // Eligibility is decided on what the principal holds standing. What the session
        // holds is computed again with the role in place, so a set that lists the role,
        // and a forbid on that set, apply to it.
        Ok(Ok(self.fixpoint(id, attrs, excluded, Some(role))?.0))
    }

    /// The lowest assurance level, 2 or 3, at which a denied request would be allowed
    /// (spec §4.3.2), so a resource server can ask the user to step up instead of just
    /// refusing. `None` when the request is allowed, when no level would help, or when an
    /// actor holds a delegation (an agent cannot sign in again as the user).
    pub fn step_up(&self, principal: &Principal, action: &str, resource: &Resource, context: &Value) -> Result<Option<u8>> {
        if principal.actor.is_some() || self.authorize(principal, action, resource, context)?.allowed {
            return Ok(None);
        }
        let id = principal.id.as_str();
        let none = BTreeSet::new();
        // What the principal holds at a level: with the assumed role when the role can
        // be assumed there, standing otherwise.
        let sets = |attrs: &Map<String, Value>| -> Result<Memberships> {
            let attrs = self.attributes(id, attrs);
            match &principal.assumed {
                Some(role) => match self.assume(id, &attrs, &none, role)? {
                    Ok(m) => Ok(m),
                    Err(_) => self.memberships(id, &attrs),
                },
                None => self.memberships(id, &attrs),
            }
        };
        let now = sets(&principal.attrs)?;
        let current = principal.attrs.get("aal").and_then(Value::as_f64).unwrap_or(0.0);
        // The session keeps every set it holds and gains only those the higher level adds:
        // a set taken away from it (revoked, excluded) does not come back.
        let gain = |held: &[String], before: &[String], after: &[String]| -> Vec<String> {
            let mut out: BTreeSet<String> = held.iter().cloned().collect();
            out.extend(after.iter().filter(|s| !before.contains(s)).cloned());
            out.into_iter().collect()
        };
        for level in 2u8..=3 {
            if f64::from(level) <= current {
                continue;
            }
            let mut attrs = principal.attrs.clone();
            attrs.insert("aal".into(), json!(level));
            let then = sets(&attrs)?;
            let raised = Principal {
                groups: gain(&principal.groups, &now.groups, &then.groups),
                roles: gain(&principal.roles, &now.roles, &then.roles),
                attrs,
                ..principal.clone()
            };
            if self.authorize(&raised, action, resource, context)?.allowed {
                return Ok(Some(level));
            }
        }
        Ok(None)
    }

    /// The longest an access token may carry `role` as assumed, if the role says.
    pub fn assume_max_age(&self, role: &str) -> Option<u64> {
        self.bundle.roles.get(role)?.assume.as_ref()?.max_age
    }

    /// Evaluate `action` on `resource` for `principal`. Delegated principals must also
    /// hold a matching capability (attenuation): delegation can only narrow access.
    pub fn authorize<'a>(&self, principal: &'a Principal, action: &str, resource: &'a Resource, context: &Value) -> Result<AuthzDecision> {
        if let Some(caps) = &principal.caps {
            if !caps_allow(caps, action, &resource.uid_string()) {
                return Ok(AuthzDecision { allowed: false, reasons: vec!["delegation:cap".into()], errors: vec![] });
            }
        }
        let groups: BTreeSet<String> = principal.groups.iter().cloned().collect();
        let roles: BTreeSet<String> = principal.roles.iter().cloned().collect();
        let mut es = self.set_entities();
        es.push(self.principal_entity(&principal.id, &principal.attrs, &groups, &roles));
        let refs = |ps: &'a [EntityRef]| ps.iter().map(|p| (p.kind.as_str(), p.id.as_str())).collect::<Vec<_>>();
        es.push(entity(&resource.kind, &resource.id, cedar_map(&resource.attrs), refs(&resource.parents)));
        // A related entity describes something new. It never restates the principal, the
        // resource, a set or an action, whose parents decide who is in what.
        let mut seen = BTreeSet::from([("User", principal.id.as_str()), (resource.kind.as_str(), resource.id.as_str())]);
        for r in &resource.related {
            if reserved_type(&r.kind) || !seen.insert((r.kind.as_str(), r.id.as_str())) {
                return Ok(AuthzDecision { allowed: false, reasons: vec!["entities:conflict".into()], errors: vec![] });
            }
            es.push(entity(&r.kind, &r.id, cedar_map(&r.attrs), refs(&r.parents)));
        }
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

    #[test]
    fn memberships_say_why() {
        let e = Engine::from_json(BUNDLE).unwrap();
        let mut attrs = e.attributes("did:kith:bob", &Map::new());
        attrs.insert("aal".into(), json!(2));
        let (m, why) = e.explain_memberships("did:kith:bob", &attrs, &BTreeSet::new()).unwrap();
        assert_eq!(m, e.memberships("did:kith:bob", &attrs).unwrap(), "the same answer");
        assert_eq!(why["Group::contractors"], Basis::Listed);
        assert_eq!(why["Group::finance"], Basis::Nested { set: "Group::contractors".into() });
        assert_eq!(why["Role::billing-reader"], Basis::Nested { set: "Group::finance".into() });
        assert_eq!(why["Group::strong"], Basis::Rule);
        assert_eq!(why["Role::billing-admin"], Basis::Rule);
        assert_eq!(why.len(), m.groups.len() + m.roles.len(), "every membership has a reason");
    }

    fn principal(e: &Engine, id: &str, aal: i64) -> Principal {
        let mut attrs = e.attributes(id, &Map::new());
        attrs.insert("aal".into(), json!(aal));
        let m = e.memberships(id, &attrs).unwrap();
        Principal { id: id.into(), attrs, groups: m.groups, roles: m.roles, actor: None, caps: None, assumed: None }
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
                assumed: None,
            };
            let mut r = Resource::new(d["resource"]["type"].as_str().unwrap(), d["resource"]["id"].as_str().unwrap());
            if let Some(a) = d["resource"]["attrs"].as_object() {
                r.attrs = a.clone();
            }
            let got = e.authorize(&p, d["action"].as_str().unwrap(), &r, &d["context"]).unwrap();
            assert_eq!(got.allowed, d["allowed"].as_bool().unwrap(), "{}: {got:?}", d["name"]);
        }
    }

    /// §4.2.1 and §4.2.2: resource parents, related entities and typed values. A request
    /// that cannot be built is an error here, which the vectors count as a denial.
    #[test]
    fn entity_vectors() {
        let v: Value = serde_json::from_str(include_str!("../../../spec/test-vectors/authz.json")).unwrap();
        let v = &v["entities"];
        let e = Engine::new(serde_json::from_value(v["bundle"].clone()).unwrap()).unwrap();
        let mut failed = vec![];
        for d in v["decisions"].as_array().unwrap() {
            let id = d["principal"].as_str().unwrap();
            let attrs = e.attributes(id, d["attrs"].as_object().unwrap());
            let m = e.memberships(id, &attrs).unwrap();
            let p = Principal { id: id.into(), attrs, groups: m.groups, roles: m.roles, actor: None, caps: None, assumed: None };
            let got = match serde_json::from_value::<Resource>(d["resource"].clone()) {
                Ok(r) => e.authorize(&p, d["action"].as_str().unwrap(), &r, &d["context"]).map(|d| d.allowed).unwrap_or(false),
                Err(_) => false,
            };
            if got != d["allowed"].as_bool().unwrap() {
                failed.push(d["name"].as_str().unwrap());
            }
        }
        assert!(failed.is_empty(), "wrong decisions: {failed:#?}");
    }

    /// §4.3.1: who may assume which role, what the session then holds, and what it may do.
    #[test]
    fn assume_vectors() {
        let v: Value = serde_json::from_str(include_str!("../../../spec/test-vectors/authz.json")).unwrap();
        let v = &v["assume"];
        let e = Engine::new(serde_json::from_value(v["bundle"].clone()).unwrap()).unwrap();
        for a in v["assumptions"].as_array().unwrap() {
            let id = a["id"].as_str().unwrap();
            let attrs = e.attributes(id, a["attrs"].as_object().unwrap());
            let excluded: BTreeSet<String> = serde_json::from_value(a.get("excluded").cloned().unwrap_or(json!([]))).unwrap();
            let got = e.assume(id, &attrs, &excluded, a["role"].as_str().unwrap()).unwrap();
            let want = match a["refused"].as_str() {
                Some(r) => json!({ "refused": r }),
                None => json!({ "groups": a["groups"], "roles": a["roles"] }),
            };
            let got = match got {
                Ok(m) => json!({ "groups": m.groups, "roles": m.roles }),
                Err(r) => json!({ "refused": r.code() }),
            };
            assert_eq!(got, want, "{id} assumes {}", a["role"]);
        }
        for d in v["decisions"].as_array().unwrap() {
            let id = d["principal"].as_str().unwrap();
            let attrs = e.attributes(id, d["attrs"].as_object().unwrap());
            let assumed = d["assume"].as_str().map(String::from);
            let m = match &assumed {
                Some(role) => e.assume(id, &attrs, &BTreeSet::new(), role).unwrap(),
                None => Ok(e.memberships(id, &attrs).unwrap()),
            };
            let allowed = m.is_ok_and(|m| {
                let p = Principal { id: id.into(), attrs, groups: m.groups, roles: m.roles, actor: None, caps: None, assumed };
                let r: Resource = serde_json::from_value(d["resource"].clone()).unwrap();
                e.authorize(&p, d["action"].as_str().unwrap(), &r, &d["context"]).unwrap().allowed
            });
            assert_eq!(allowed, d["allowed"].as_bool().unwrap(), "{}", d["name"]);
        }
        for b in v["invalid"].as_array().unwrap() {
            let loaded = serde_json::from_value::<Bundle>(b["bundle"].clone()).map_err(Error::from).and_then(Engine::new);
            assert!(loaded.is_err(), "loaded: {}", b["note"]);
        }
        assert_eq!(e.assume_max_age("break-glass"), Some(600));
    }

    /// §4.3.2: the lowest level at which a denied request would be allowed.
    #[test]
    fn step_up_vectors() {
        let v: Value = serde_json::from_str(include_str!("../../../spec/test-vectors/authz.json")).unwrap();
        let v = &v["step_up"];
        let e = Engine::new(serde_json::from_value(v["bundle"].clone()).unwrap()).unwrap();
        let mut failed = vec![];
        for d in v["decisions"].as_array().unwrap() {
            let id = d["principal"].as_str().unwrap();
            let attrs = e.attributes(id, d["attrs"].as_object().unwrap());
            let assumed = d["assume"].as_str().map(String::from);
            let m = match (&d.get("groups"), &assumed) {
                (Some(_), _) => Memberships { groups: serde_json::from_value(d["groups"].clone()).unwrap(), roles: serde_json::from_value(d["roles"].clone()).unwrap() },
                (None, Some(role)) => e.assume(id, &attrs, &BTreeSet::new(), role).unwrap().unwrap(),
                (None, None) => e.memberships(id, &attrs).unwrap(),
            };
            let p = Principal {
                id: id.into(),
                attrs,
                groups: m.groups,
                roles: m.roles,
                actor: d["actor"].as_str().map(String::from),
                caps: d.get("caps").map(|c| serde_json::from_value(c.clone()).unwrap()),
                assumed,
            };
            let action = d["action"].as_str().unwrap();
            let r = Resource::new("Operation", action);
            let allowed = e.authorize(&p, action, &r, &d["context"]).unwrap().allowed;
            let step_up = e.step_up(&p, action, &r, &d["context"]).unwrap();
            if allowed != d["allowed"].as_bool().unwrap() || json!(step_up) != d["step_up"] {
                failed.push(format!("{}: allowed {allowed}, step_up {step_up:?}", d["name"].as_str().unwrap()));
            }
        }
        assert!(failed.is_empty(), "wrong answers: {failed:#?}");
    }

    #[test]
    fn rule_injection_is_rejected() {
        let bad = r#"{"version":1,"groups":{"x":{"rule":"true }; permit(principal, action, resource) when { true"}},"policies":""}"#;
        assert!(Engine::from_json(bad).is_err());
    }

    /// §4.2: the text of a stringified number is ECMAScript `Number::toString`.
    #[test]
    // The literals are exact doubles, chosen to sit on ties; truncating them changes the case.
    #[allow(clippy::excessive_precision)]
    fn number_text_is_ecmascript_number_to_string() {
        for (f, text) in [
            (12.5, "12.5"),
            (-12.5, "-12.5"),
            (0.1 + 0.2, "0.30000000000000004"),
            (1e-6, "0.000001"),
            (1.234e-6, "0.000001234"),
            (1e-7, "1e-7"),
            (1.5e-7, "1.5e-7"),
            (5e-324, "5e-324"),
            (1259144888929591.25, "1259144888929591.2"), // two candidates equally near: the even digit
            (9007199254740992.0, "9007199254740992"),
            (123456789012345680000.0, "123456789012345680000"),
            (1e21, "1e+21"),
            (1.5e300, "1.5e+300"),
            (f64::MAX, "1.7976931348623157e+308"),
            (-0.0, "0"),
            (f64::NAN, "NaN"),
            (f64::NEG_INFINITY, "-Infinity"),
        ] {
            assert_eq!(number_text(f), text);
        }
    }
}
