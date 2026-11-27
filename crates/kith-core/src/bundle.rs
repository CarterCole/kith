//! Checks a policy bundle file (spec §4.1) before it is deployed.
//!
//! A hub loads any bundle that parses, and reading JSON forgives a lot: an unknown
//! member is ignored, a key written twice keeps its last value, and `role:x` names a
//! set whether or not `x` exists. Each of those can quietly take access away from
//! someone (or leave it with them), so [`check`] reports them.
//!
//! * **Errors** stop a deploy: the file does not parse, is not a version 1 bundle, has
//!   a policy or rule Cedar refuses, writes a key twice, has a member the hub would
//!   ignore, or lists a `group:` or `role:` that is not defined.
//! * **Warnings** are likely mistakes that still mean something: a member that is not
//!   a DID, a set with no members and no rule, a member listed twice, and a
//!   `Group::"x"` or `Role::"x"` in a rule or policy that names no set.

use std::cell::RefCell;
use std::collections::BTreeSet;

use serde::de::{self, DeserializeSeed, Deserializer, MapAccess, SeqAccess, Visitor};
use serde::Serialize;
use serde_json::Value;

use crate::authz::{Bundle, Engine};

/// What [`check`] found. The bundle may be deployed when [`Report::ok`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Report {
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

impl Report {
    pub fn ok(&self) -> bool {
        self.errors.is_empty()
    }
}

/// Members a bundle may have. `attributes` and `schemas` are spec §9.1 (draft); the
/// hub does not use them yet, but they are not mistakes.
const BUNDLE_KEYS: &[&str] = &[
    "version",
    "groups",
    "roles",
    "directory",
    "policies",
    "attributes",
    "schemas",
];
const SET_KEYS: &[&str] = &["description", "members", "rule", "assume"];
const ASSUME_KEYS: &[&str] = &["members", "rule", "max_age"];
const DIRECTORY_KEYS: &[&str] = &["attrs"];

/// Check the text of a bundle file.
pub fn check(text: &str) -> Report {
    let mut r = Report::default();
    let value: Value = match serde_json::from_str(text) {
        Ok(v) => v,
        Err(e) => {
            r.errors.push(format!("not valid JSON: {e}"));
            return r;
        }
    };
    for path in duplicate_keys(text) {
        r.errors.push(format!(
            "`{path}` is written more than once; only the last one counts"
        ));
    }
    let Some(top) = value.as_object() else {
        r.errors.push("a bundle is a JSON object".into());
        return r;
    };
    unknown_keys(&mut r, top, BUNDLE_KEYS, "the bundle");
    for kind in ["groups", "roles"] {
        for (name, def) in top
            .get(kind)
            .and_then(Value::as_object)
            .into_iter()
            .flatten()
        {
            if let Some(def) = def.as_object() {
                unknown_keys(&mut r, def, SET_KEYS, &format!("{kind}.{name}"));
                if let Some(a) = def.get("assume").and_then(Value::as_object) {
                    unknown_keys(&mut r, a, ASSUME_KEYS, &format!("{kind}.{name}.assume"));
                }
            }
        }
    }
    for (id, entry) in top
        .get("directory")
        .and_then(Value::as_object)
        .into_iter()
        .flatten()
    {
        if let Some(entry) = entry.as_object() {
            unknown_keys(&mut r, entry, DIRECTORY_KEYS, &format!("directory.{id}"));
        }
    }
    let bundle: Bundle = match serde_json::from_value(value) {
        Ok(b) => b,
        Err(e) => {
            r.errors.push(format!("not a policy bundle: {e}"));
            return r;
        }
    };
    if bundle.version != 1 {
        r.errors.push(format!(
            "version is {}; this hub reads version 1",
            bundle.version
        ));
    }
    if let Err(e) = Engine::new(bundle.clone()) {
        r.errors.push(e.to_string());
    }
    for (singular, sets) in [("group", &bundle.groups), ("role", &bundle.roles)] {
        for (name, def) in sets {
            let at = format!("{singular} `{name}`");
            if let Some(a) = &def.assume {
                if a.members.is_empty() && a.rule.is_none() {
                    r.warnings.push(format!("{at} can be assumed by no one: its `assume` has no members and no rule"));
                }
                if let Some(rule) = &a.rule {
                    for missing in undefined_sets(rule, &bundle) {
                        r.warnings.push(format!("{at}'s assume rule names {missing}, which is not defined"));
                    }
                }
            }
            let mut seen = BTreeSet::new();
            for m in def.members.iter().chain(def.assume.iter().flat_map(|a| a.members.iter())) {
                if !seen.insert(m) {
                    r.warnings.push(format!("{at} lists `{m}` twice"));
                }
                if let Some(g) = m.strip_prefix("group:") {
                    if !bundle.groups.contains_key(g) {
                        r.errors
                            .push(format!("{at} lists `{m}`, but there is no group `{g}`"));
                    }
                } else if let Some(x) = m.strip_prefix("role:") {
                    if !bundle.roles.contains_key(x) {
                        r.errors
                            .push(format!("{at} lists `{m}`, but there is no role `{x}`"));
                    }
                } else if !m.starts_with("did:") {
                    r.warnings.push(format!(
                        "{at} lists `{m}`, which is not a DID, `group:…` or `role:…`"
                    ));
                }
            }
            match &def.rule {
                None if def.members.is_empty() && def.assume.is_none() => {
                    r.warnings.push(format!("{at} has no members and no rule"))
                }
                Some(rule) => {
                    for missing in undefined_sets(rule, &bundle) {
                        r.warnings
                            .push(format!("{at}'s rule names {missing}, which is not defined"));
                    }
                }
                None => {}
            }
        }
    }
    for missing in undefined_sets(&bundle.policies, &bundle) {
        r.warnings
            .push(format!("the policies name {missing}, which is not defined"));
    }
    for id in bundle.directory.keys().filter(|id| !id.starts_with("did:")) {
        r.warnings.push(format!(
            "the directory has an entry for `{id}`, which is not a DID"
        ));
    }
    r
}

fn unknown_keys(r: &mut Report, obj: &serde_json::Map<String, Value>, known: &[&str], at: &str) {
    for k in obj.keys().filter(|k| !known.contains(&k.as_str())) {
        r.errors
            .push(format!("unknown member `{k}` in {at}: the hub ignores it"));
    }
}

/// `Group::"x"` and `Role::"x"` in Cedar source whose set the bundle does not define.
fn undefined_sets(src: &str, bundle: &Bundle) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for (kind, sets) in [("Group", &bundle.groups), ("Role", &bundle.roles)] {
        for name in named_sets(src, kind).into_iter().filter(|n| !sets.contains_key(n)) {
            out.insert(format!("{kind}::{}", serde_json::to_string(&name).unwrap_or_default()));
        }
    }
    out
}

/// The names in every `<kind>::"name"` in Cedar source.
fn named_sets(src: &str, kind: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    {
        let opener = format!("{kind}::\"");
        let mut rest = src;
        while let Some(at) = rest.find(&opener) {
            rest = &rest[at + opener.len()..];
            let mut name = String::new();
            let mut end = rest.len();
            let mut chars = rest.char_indices();
            while let Some((i, c)) = chars.next() {
                match c {
                    '"' => {
                        end = i + 1;
                        break;
                    }
                    '\\' => {
                        if let Some((_, escaped)) = chars.next() {
                            name.push(escaped);
                        }
                    }
                    c => name.push(c),
                }
            }
            rest = &rest[end..];
            out.insert(name);
        }
    }
    out
}

/// Paths of object keys that appear twice in the same object, such as `roles.god`.
fn duplicate_keys(text: &str) -> Vec<String> {
    let found = RefCell::new(vec![]);
    let mut de = serde_json::Deserializer::from_str(text);
    let _ = Walk {
        path: String::new(),
        found: &found,
    }
    .deserialize(&mut de);
    found.into_inner()
}

/// Visits a JSON document without building it, noting keys seen twice in one object.
struct Walk<'a> {
    path: String,
    found: &'a RefCell<Vec<String>>,
}

impl<'de> DeserializeSeed<'de> for Walk<'_> {
    type Value = ();
    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<(), D::Error> {
        d.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for Walk<'_> {
    type Value = ();
    fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str("a JSON value")
    }
    fn visit_bool<E: de::Error>(self, _: bool) -> Result<(), E> {
        Ok(())
    }
    fn visit_i64<E: de::Error>(self, _: i64) -> Result<(), E> {
        Ok(())
    }
    fn visit_u64<E: de::Error>(self, _: u64) -> Result<(), E> {
        Ok(())
    }
    fn visit_f64<E: de::Error>(self, _: f64) -> Result<(), E> {
        Ok(())
    }
    fn visit_str<E: de::Error>(self, _: &str) -> Result<(), E> {
        Ok(())
    }
    fn visit_unit<E: de::Error>(self) -> Result<(), E> {
        Ok(())
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<(), A::Error> {
        let mut i = 0;
        while seq
            .next_element_seed(Walk {
                path: format!("{}[{i}]", self.path),
                found: self.found,
            })?
            .is_some()
        {
            i += 1;
        }
        Ok(())
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        let mut seen = BTreeSet::new();
        while let Some(key) = map.next_key::<String>()? {
            let path = if self.path.is_empty() {
                key.clone()
            } else {
                format!("{}.{key}", self.path)
            };
            if !seen.insert(key) {
                self.found.borrow_mut().push(path.clone());
            }
            map.next_value_seed(Walk {
                path,
                found: self.found,
            })?;
        }
        Ok(())
    }
}

/// One difference between two bundles, for a reviewer: a draft's page and `kith org
/// approve` show these before anyone signs (spec §8.6.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Change {
    Version { from: u32, to: u32 },
    SetAdded { set: String },
    SetRemoved { set: String },
    /// Explicit members came or went (`members`; for an assumable role, also `assume.members`).
    Members { set: String, added: Vec<String>, removed: Vec<String> },
    /// Anything else about the set changed: `description`, `rule` or `assume`.
    SetChanged { set: String, fields: Vec<String> },
    PolicyAdded { id: String },
    PolicyRemoved { id: String },
    PolicyChanged { id: String },
    DirectoryAdded { id: String },
    DirectoryRemoved { id: String },
    DirectoryChanged { id: String },
}

/// What changes from `old` to `new`, sets first, then policies (by id, the same way
/// the policy DAG files them), then directory entries. Fails if either bundle's
/// policies don't parse.
pub fn changes(old: &Bundle, new: &Bundle) -> crate::Result<Vec<Change>> {
    use std::collections::BTreeMap;
    let mut out = vec![];
    if old.version != new.version {
        out.push(Change::Version { from: old.version, to: new.version });
    }
    for (kind, a, b) in [("Group", &old.groups, &new.groups), ("Role", &old.roles, &new.roles)] {
        let names: BTreeSet<&String> = a.keys().chain(b.keys()).collect();
        for name in names {
            let set = format!("{kind}::{name}");
            match (a.get(name), b.get(name)) {
                (None, Some(_)) => out.push(Change::SetAdded { set }),
                (Some(_), None) => out.push(Change::SetRemoved { set }),
                (Some(x), Some(y)) => {
                    let all = |d: &crate::authz::SetDef| -> BTreeSet<String> {
                        d.members.iter().chain(d.assume.iter().flat_map(|a| a.members.iter())).cloned().collect()
                    };
                    let (mx, my) = (all(x), all(y));
                    let added: Vec<String> = my.difference(&mx).cloned().collect();
                    let removed: Vec<String> = mx.difference(&my).cloned().collect();
                    if !added.is_empty() || !removed.is_empty() {
                        out.push(Change::Members { set: set.clone(), added, removed });
                    }
                    let mut fields = vec![];
                    if x.description != y.description {
                        fields.push("description".to_string());
                    }
                    if x.rule != y.rule {
                        fields.push("rule".to_string());
                    }
                    let shape = |d: &crate::authz::SetDef| d.assume.as_ref().map(|a| (a.rule.clone(), a.max_age));
                    if x.assume.is_some() != y.assume.is_some() || shape(x) != shape(y) {
                        fields.push("assume".to_string());
                    }
                    if !fields.is_empty() {
                        out.push(Change::SetChanged { set, fields });
                    }
                }
                (None, None) => {}
            }
        }
    }
    let by_id = |b: &Bundle| -> crate::Result<BTreeMap<String, String>> {
        Ok(crate::pdag::policy_entries(&b.policies)?.into_iter().map(|p| (p.id, p.text)).collect())
    };
    let (pa, pb) = (by_id(old)?, by_id(new)?);
    for id in pa.keys().chain(pb.keys()).collect::<BTreeSet<_>>() {
        match (pa.get(id), pb.get(id)) {
            (None, Some(_)) => out.push(Change::PolicyAdded { id: id.clone() }),
            (Some(_), None) => out.push(Change::PolicyRemoved { id: id.clone() }),
            (Some(x), Some(y)) if x != y => out.push(Change::PolicyChanged { id: id.clone() }),
            _ => {}
        }
    }
    for id in old.directory.keys().chain(new.directory.keys()).collect::<BTreeSet<_>>() {
        match (old.directory.get(id), new.directory.get(id)) {
            (None, Some(_)) => out.push(Change::DirectoryAdded { id: id.clone() }),
            (Some(_), None) => out.push(Change::DirectoryRemoved { id: id.clone() }),
            (Some(x), Some(y)) if x.attrs != y.attrs => out.push(Change::DirectoryChanged { id: id.clone() }),
            _ => {}
        }
    }
    Ok(out)
}

#[cfg(test)]
mod change_tests {
    use super::*;

    fn bundle(v: Value) -> Bundle {
        serde_json::from_value(v).unwrap()
    }

    #[test]
    fn changes_name_each_set_member_policy_and_directory_entry() {
        let old = bundle(serde_json::json!({
            "version": 1,
            "groups": {"staff": {"members": ["did:kith:ada", "did:kith:cy"]}, "gone": {"members": ["did:kith:ada"]}},
            "roles": {"god": {"rule": "principal in Group::\"staff\""}},
            "directory": {"did:kith:ada": {"attrs": {"team": "a"}}},
            "policies": "@id(\"read\") permit(principal, action == Action::\"Query.a\", resource);"
        }));
        let new = bundle(serde_json::json!({
            "version": 1,
            "groups": {"staff": {"members": ["did:kith:ada", "did:kith:bob"]}, "ops": {"members": []}},
            "roles": {"god": {"rule": "principal in Group::\"staff\" && principal.aal >= 2"}},
            "directory": {"did:kith:ada": {"attrs": {"team": "b"}}, "did:kith:bob": {}},
            "policies": "@id(\"write\") permit(principal, action == Action::\"Query.b\", resource);"
        }));
        let c = changes(&old, &new).unwrap();
        let has = |want: Change| assert!(c.contains(&want), "{want:?} missing from {c:?}");
        has(Change::Members { set: "Group::staff".into(), added: vec!["did:kith:bob".into()], removed: vec!["did:kith:cy".into()] });
        has(Change::SetAdded { set: "Group::ops".into() });
        has(Change::SetRemoved { set: "Group::gone".into() });
        has(Change::SetChanged { set: "Role::god".into(), fields: vec!["rule".into()] });
        has(Change::DirectoryChanged { id: "did:kith:ada".into() });
        has(Change::DirectoryAdded { id: "did:kith:bob".into() });
        has(Change::PolicyAdded { id: "write".into() });
        has(Change::PolicyRemoved { id: "read".into() });
        assert_eq!(c.len(), 8, "{c:?}");
        assert!(changes(&new, &new).unwrap().is_empty());
    }
}
