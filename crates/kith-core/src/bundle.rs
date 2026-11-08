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
const SET_KEYS: &[&str] = &["description", "members", "rule"];
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
            let mut seen = BTreeSet::new();
            for m in &def.members {
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
                None if def.members.is_empty() => {
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
            if !sets.contains_key(&name) {
                out.insert(format!(
                    "{kind}::{}",
                    serde_json::to_string(&name).unwrap_or_default()
                ));
            }
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
