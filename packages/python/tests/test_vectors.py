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


ENTITIES = VECTORS["entities"]
ENTITY_ENGINE = Engine(ENTITIES["bundle"])


@pytest.mark.parametrize("d", ENTITIES["decisions"], ids=lambda d: d["name"])
def test_entity_decisions(d):
    """§4.2.1 and §4.2.2: resource parents, related entities and typed values. A request
    that cannot be built may raise, which the vectors count as a denial."""
    p = ENTITY_ENGINE.principal(d["principal"], d["attrs"])
    r = d["resource"]
    try:
        resource = Resource(r["type"], r["id"], r.get("attrs", {}), r.get("parents", []), r.get("related", []))
        allowed = ENTITY_ENGINE.authorize(p, d["action"], resource, d["context"]).allowed
    except Exception:
        allowed = False
    assert allowed == d["allowed"]


ASSUME = VECTORS["assume"]
ASSUME_ENGINE = Engine(ASSUME["bundle"])


@pytest.mark.parametrize("a", ASSUME["assumptions"], ids=lambda a: f"{a['id']}-{a['role']}-{a['attrs']}-{a.get('excluded', [])}")
def test_assumptions(a):
    """§4.3.1: who may assume which role, and what the session then holds."""
    got = ASSUME_ENGINE.assume(a["id"], ASSUME_ENGINE.attributes(a["id"], a["attrs"]), a.get("excluded", []), a["role"])
    assert got == (a["refused"] if "refused" in a else (a["groups"], a["roles"]))


@pytest.mark.parametrize("d", ASSUME["decisions"], ids=lambda d: d["name"])
def test_assume_decisions(d):
    attrs = ASSUME_ENGINE.attributes(d["principal"], d["attrs"])
    m = ASSUME_ENGINE.assume(d["principal"], attrs, [], d["assume"]) if "assume" in d else ASSUME_ENGINE.memberships(d["principal"], attrs)
    allowed = False
    if not isinstance(m, str):
        p = Principal(d["principal"], attrs, m[0], m[1], assumed=d.get("assume"))
        r = d["resource"]
        allowed = ASSUME_ENGINE.authorize(p, d["action"], Resource(r["type"], r["id"]), d["context"]).allowed
    assert allowed == d["allowed"]


@pytest.mark.parametrize("b", ASSUME["invalid"], ids=lambda b: b["note"])
def test_assume_invalid_bundles(b):
    with pytest.raises(Exception):
        Engine(b["bundle"])


def test_assume_max_age():
    assert ASSUME_ENGINE.assume_max_age("break-glass") == 600 and ASSUME_ENGINE.assume_max_age("god") is None


STEP_UP = VECTORS["step_up"]
STEP_UP_ENGINE = Engine(STEP_UP["bundle"])


@pytest.mark.parametrize("d", STEP_UP["decisions"], ids=lambda d: d["name"])
def test_step_up(d):
    """§4.3.2: the lowest level at which a denied request would be allowed."""
    e = STEP_UP_ENGINE
    attrs = e.attributes(d["principal"], d["attrs"])
    if "groups" in d:
        m = (d["groups"], d["roles"])
    elif "assume" in d:
        m = e.assume(d["principal"], attrs, [], d["assume"])
    else:
        m = e.memberships(d["principal"], attrs)
    p = Principal(d["principal"], attrs, m[0], m[1], actor=d.get("actor"), caps=d.get("caps"), assumed=d.get("assume"))
    r = Resource("Operation", d["action"])
    assert e.authorize(p, d["action"], r, d["context"]).allowed == d["allowed"]
    assert e.step_up(p, d["action"], r, d["context"]) == d["step_up"]


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
