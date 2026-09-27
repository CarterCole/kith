import json
from pathlib import Path

from graphql import build_schema, graphql_sync

from kith import Engine
from kith.graphql import KithMiddleware

EX = Path(__file__).parents[3] / "examples"
BUNDLE = json.loads((EX / "policy/bundle.template.json").read_text().replace("__ADA__", "did:kith:ada").replace("__BOB__", "did:kith:bob"))
ENGINE = Engine(BUNDLE)
DATA = json.loads((EX / "graphql/data.json").read_text())
SCHEMA = build_schema((EX / "graphql/schema.graphql").read_text())


class Root:
    def me(self, info):
        p = info.context["kith"]
        return {"did": p.id, "actor": p.actor, "groups": p.groups, "roles": p.roles, "aal": p.attrs["aal"]}

    def invoices(self, info):
        return DATA

    def invoice(self, info, id):
        return next((i for i in DATA if i["id"] == id), None)

    def payInvoice(self, info, id, amount):
        return {**next(i for i in DATA if i["id"] == id), "status": "paid"}


def run(q, principal=None):
    return graphql_sync(SCHEMA, q, root_value=Root(), context_value={"kith": principal}, middleware=[KithMiddleware(ENGINE)])


def test_unauthenticated():
    assert run("{ me { did } }").errors[0].extensions["code"] == "UNAUTHENTICATED"


def test_reader_sees_rows_not_notes():
    r = run("{ invoices { id internalNotes } }", ENGINE.principal("did:kith:ada", {"aal": 1}))
    assert [i["id"] for i in r.data["invoices"]] == ["inv_1", "inv_2", "inv_3"]
    assert r.data["invoices"][0]["internalNotes"] is None
    assert r.errors[0].extensions["code"] == "FORBIDDEN"


def test_admin_notes_and_pay_limit():
    ada = ENGINE.principal("did:kith:ada", {"aal": 2})
    r = run("{ invoices { internalNotes } }", ada)
    assert r.errors is None and r.data["invoices"][0]["internalNotes"] == "net 30"
    assert run('mutation { payInvoice(id: "inv_1", amount: 1200) { status } }', ada).data["payInvoice"]["status"] == "paid"
    assert run('mutation { payInvoice(id: "inv_3", amount: 25000) { status } }', ada).errors[0].extensions["code"] == "FORBIDDEN"


def test_staff_sees_only_own_rows():
    bob = ENGINE.principal("did:kith:bob", {"aal": 1})
    assert run("{ invoices { id } }", bob).data["invoices"] == [{"id": "inv_2"}]
    assert run('{ invoice(id: "inv_1") { id } }', bob).errors[0].extensions["code"] == "FORBIDDEN"


def test_delegated_mutation_forbidden():
    ada = ENGINE.principal("did:kith:ada", {"aal": 2}, actor="did:kith:assistant", caps=[{"action": "*"}])
    r = run("{ me { actor } }", ada)
    assert r.data["me"]["actor"] == "did:kith:assistant"
    assert run('mutation { payInvoice(id: "inv_1", amount: 5) { status } }', ada).errors[0].extensions["code"] == "FORBIDDEN"
