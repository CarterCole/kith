import json
from pathlib import Path

import pytest

from kith import Engine, Resource

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
