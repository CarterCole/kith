//! `kith bundle check`: what a bundle file must pass before it is deployed. The hub
//! loads anything that parses; these catch files that parse but don't mean what they say.

use kith_core::bundle::check;

const ADA: &str = "did:kith:k2tbnuucwqfl2qrhvqxypqsephg6blaljv2iunxy4v3ga3j4s22q";

fn good() -> serde_json::Value {
    serde_json::json!({
        "version": 1,
        "groups": {
            "org:acme": {"description": "Acme's people", "members": [ADA]},
            "strong": {"rule": "principal.aal >= 2"}
        },
        "roles": {
            "god": {"description": "Owner of every site.", "members": [ADA]},
            "hub-admin": {"members": ["role:god"]},
            "carterbox:viewer": {"members": ["group:org:acme", "role:god"]},
            "carterbox:admin": {"rule": "principal in Role::\"god\" && principal in Group::\"strong\""}
        },
        "directory": {(ADA): {"attrs": {"name": "Ada"}}},
        "policies": "permit(principal in Role::\"carterbox:viewer\", action, resource);"
    })
}

fn errors(text: &str) -> Vec<String> {
    check(text).errors
}

fn has(list: &[String], needle: &str) -> bool {
    list.iter().any(|e| e.contains(needle))
}

#[test]
fn a_good_bundle_passes_with_no_warnings() {
    let r = check(&serde_json::to_string_pretty(&good()).unwrap());
    assert!(r.ok(), "{r:?}");
    assert!(r.warnings.is_empty(), "{r:?}");
}

#[test]
fn json_that_does_not_parse_is_an_error() {
    let text = serde_json::to_string_pretty(&good()).unwrap();
    let e = errors(&text[..text.len() / 2]);
    assert!(has(&e, "JSON"), "{e:?}");
    assert!(has(&errors("[]"), "object"));
}

#[test]
fn members_the_hub_would_ignore_are_errors() {
    let mut b = good();
    b["rols"] = b["roles"].clone();
    assert!(has(&errors(&b.to_string()), "`rols`"));

    let mut b = good();
    b["roles"]["god"] = serde_json::json!({"member": [ADA]});
    let e = errors(&b.to_string());
    assert!(has(&e, "`member`") && has(&e, "god"), "{e:?}");

    let mut b = good();
    b["directory"][ADA] = serde_json::json!({"attributes": {"name": "Ada"}});
    assert!(has(&errors(&b.to_string()), "`attributes`"));
}

#[test]
fn a_key_written_twice_is_an_error() {
    // The second "god" silently replaces the first when the file is read.
    let text = r#"{"version": 1, "roles": {
        "god": {"members": ["did:kith:a"]},
        "hub-admin": {"members": ["role:god"]},
        "god": {"members": ["did:kith:b"]}
    }}"#;
    let e = errors(text);
    assert!(has(&e, "roles.god"), "{e:?}");
}

#[test]
fn a_reference_to_a_set_that_does_not_exist_is_an_error() {
    let mut b = good();
    b["roles"]["hub-admin"]["members"] = serde_json::json!(["role:gd"]);
    let e = errors(&b.to_string());
    assert!(has(&e, "role:gd") && has(&e, "hub-admin"), "{e:?}");

    let mut b = good();
    b["roles"]["carterbox:viewer"]["members"] = serde_json::json!(["group:org:acm"]);
    assert!(has(&errors(&b.to_string()), "group:org:acm"));
}

#[test]
fn policies_and_rules_must_parse() {
    let mut b = good();
    b["policies"] = serde_json::json!("permit(principal, action, resource) when {");
    assert!(has(&errors(&b.to_string()), "policies"));

    let mut b = good();
    b["groups"]["strong"]["rule"] = serde_json::json!("principal.aal >=");
    assert!(has(&errors(&b.to_string()), "strong"));
}

#[test]
fn the_version_must_be_1() {
    let mut b = good();
    b["version"] = serde_json::json!(2);
    assert!(has(&errors(&b.to_string()), "version"));
    let mut b = good();
    b.as_object_mut().unwrap().remove("version");
    assert!(has(&errors(&b.to_string()), "version"));
}

#[test]
fn likely_mistakes_are_warnings() {
    let mut b = good();
    b["groups"]["org:acme"]["members"] = serde_json::json!([ADA, ADA, "ada"]);
    b["roles"]["empty"] = serde_json::json!({"description": "nobody yet"});
    b["roles"]["carterbox:admin"]["rule"] = serde_json::json!("principal in Role::\"gods\"");
    b["policies"] =
        serde_json::json!("permit(principal in Group::\"org:acmee\", action, resource);");
    let r = check(&b.to_string());
    assert!(r.ok(), "{r:?}");
    for needle in [
        "twice",
        "`ada`",
        "`empty`",
        "Role::\"gods\"",
        "Group::\"org:acmee\"",
    ] {
        assert!(has(&r.warnings, needle), "{needle}: {r:?}");
    }
}

/// Spec §4.3.1: an assumable role is a setting on the role, and nothing else may lean on it.
#[test]
fn assumable_roles_are_checked() {
    let mut b = good();
    b["roles"]["break-glass"] = serde_json::json!({"assume": {"members": ["role:god", ADA], "rule": "principal.aal >= 2", "max_age": 600}});
    let r = check(&b.to_string());
    assert!(r.ok() && r.warnings.is_empty(), "{r:?}");

    let mut bad = b.clone();
    bad["roles"]["break-glass"]["assume"]["ttl"] = serde_json::json!(60);
    assert!(has(&errors(&bad.to_string()), "unknown member `ttl` in roles.break-glass.assume"));

    let mut bad = b.clone();
    bad["roles"]["break-glass"]["assume"]["members"] = serde_json::json!(["group:nobody"]);
    assert!(has(&errors(&bad.to_string()), "there is no group `nobody`"));

    // A set may lean on an assumable role: a session that assumes it is in the set too,
    // so a forbid on the set applies to it.
    let mut leaning = b.clone();
    leaning["groups"]["audited"] = serde_json::json!({"members": ["role:break-glass"]});
    leaning["groups"]["strong"]["rule"] = serde_json::json!("principal in Role::\"break-glass\"");
    let r = check(&leaning.to_string());
    assert!(r.ok() && r.warnings.is_empty(), "{r:?}");

    let mut bad = b.clone();
    bad["roles"]["break-glass"]["assume"] = serde_json::Value::Null;
    assert!(!errors(&bad.to_string()).is_empty(), "assume: null is refused");

    let mut bad = b.clone();
    bad["roles"]["god"]["assume"] = serde_json::json!({"members": [ADA]});
    assert!(has(&errors(&bad.to_string()), "held only by assuming it"), "god keeps its members, so it cannot also be assumable");

    let mut empty = b.clone();
    empty["roles"]["break-glass"]["assume"] = serde_json::json!({});
    assert!(has(&check(&empty.to_string()).warnings, "role `break-glass` can be assumed by no one"));
    assert!(!has(&check(&empty.to_string()).warnings, "`break-glass` has no members and no rule"), "an assumable role has none by design");
}
