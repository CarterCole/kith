import json
from pathlib import Path

import pytest

from kith import Engine, Principal, Resource

VECTORS = json.loads((Path(__file__).parents[3] / "spec/test-vectors/authz.json").read_text())
ENGINE = Engine(VECTORS["bundle"])


@pytest.mark.parametrize("m", VECTORS["memberships"], ids=lambda m: f"{m['id']}-{m['attrs']}")
def test_memberships(m):
    groups, roles = ENGINE.memberships(m["id"], ENGINE.attributes(m["id"], m["attrs"]))
    assert (groups, roles) == (m["groups"], m["roles"])


@pytest.mark.parametrize("d", VECTORS["decisions"], ids=lambda d: d["name"])
def test_decisions(d):
    p = ENGINE.principal(d["principal"], d["attrs"], actor=d.get("actor"), caps=d.get("caps"))
    r = d["resource"]
    got = ENGINE.authorize(p, d["action"], Resource(r["type"], r["id"], r.get("attrs", {})), d["context"])
    assert got.allowed == d["allowed"], got


def test_rule_injection_rejected():
    with pytest.raises(ValueError):
        Engine({"version": 1, "groups": {"x": {"rule": "true }; permit(principal, action, resource) when { true"}}, "policies": ""})


@pytest.mark.parametrize("name", ["ü1", "日本語", "😀", 'a"b', "a\\b", "line\nbreak", "tab\tx", "bell\x07", "nul\x00x", 'q"\\\n"'])
def test_any_id_can_be_named_in_a_request(name):
    """Principal, action and resource ids reach Cedar as text; none of these may break the parse."""
    engine = Engine({"version": 1, "policies": 'permit(principal, action == Action::"Invoice.read", resource);'})
    got = engine.authorize(Principal(name), "Invoice.read", Resource("Invoice", name))
    assert got.allowed and got.errors == [], got
    got = engine.authorize(Principal("did:kith:ada"), f"Invoice.{name}", Resource("Invoice", "i"))
    assert got.errors == [] and not got.allowed


def test_resource_uid_is_the_same_text_as_rust_and_js():
    assert Resource("Invoice", "ü1").uid == 'Invoice::"ü1"'
    assert Resource("Invoice", 'a"b\\').uid == 'Invoice::"a\\"b\\\\"'


def test_set_names_with_odd_characters_still_load():
    engine = Engine({"version": 1, "groups": {'wé"ird': {"rule": "principal has aal && principal.aal >= 2"}}, "policies": ""})
    assert engine.memberships("did:kith:x", {"aal": 2}) == (['wé"ird'], [])
