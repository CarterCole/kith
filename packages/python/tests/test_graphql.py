import json
from pathlib import Path

from graphql import build_schema, graphql_sync

from kith import Engine
from kith.graphql import KithMiddleware, step_up_challenge, step_up_required

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


def test_reader_sees_rows_notes_ask_for_step_up():
    r = run("{ invoices { id internalNotes } }", ENGINE.principal("did:kith:ada", {"aal": 1}))
    assert [i["id"] for i in r.data["invoices"]] == ["inv_1", "inv_2", "inv_3"]
    assert r.data["invoices"][0]["internalNotes"] is None
    e = r.errors[0].extensions
    assert e["code"] == "INSUFFICIENT_USER_AUTHENTICATION", "AAL2 would make ada a billing admin"
    assert e["acr_values"] == "urn:kith:acr:aal2"
    assert e["www_authenticate"] == 'Bearer error="insufficient_user_authentication", error_description="A stronger sign-in is required", acr_values="urn:kith:acr:aal2"'
    assert step_up_required(r.errors[0]) == 2


def test_step_up_only_when_some_level_allows():
    q = 'mutation { payInvoice(id: "inv_1", amount: 1200) { status } }'
    assert run(q, ENGINE.principal("did:kith:ada", {"aal": 1})).errors[0].extensions["code"] == "INSUFFICIENT_USER_AUTHENTICATION"
    bob = run(q, ENGINE.principal("did:kith:bob", {"aal": 1}))
    assert bob.errors[0].extensions["code"] == "FORBIDDEN", "bob is no admin at any level"
    assert step_up_required(bob.errors[0]) is None


def test_step_up_required_reads_an_rfc_9470_challenge():
    assert step_up_required(step_up_challenge(3)) == 3
    assert step_up_required('Bearer error="insufficient_user_authentication", acr_values="aal3 urn:kith:acr:aal2"') == 2
    assert step_up_required('Bearer error="invalid_token"') is None
    assert step_up_required(None) is None


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


def test_typename_is_always_allowed():
    """Apollo, urql and Relay add __typename to every selection set."""
    assert run("{ __typename }").data == {"__typename": "Query"}, "even with no principal"
    ada = ENGINE.principal("did:kith:ada", {"aal": 1})
    r = run("{ __typename invoices { __typename id } }", ada)
    assert r.errors is None, r.errors
    assert r.data["__typename"] == "Query"
    assert {i["__typename"] for i in r.data["invoices"]} == {"Invoice"}
    assert run('mutation { __typename }', ada).data == {"__typename": "Mutation"}


def test_introspection_is_open_by_default():
    r = run("{ __schema { queryType { name } } }")
    assert r.errors is None and r.data["__schema"]["queryType"]["name"] == "Query"
    r = run('{ __type(name: "Invoice") { name fields { name } } }')
    assert r.errors is None and r.data["__type"]["name"] == "Invoice"


def test_introspection_can_require_a_principal():
    guarded = lambda q, p=None: graphql_sync(SCHEMA, q, root_value=Root(), context_value={"kith": p}, middleware=[KithMiddleware(ENGINE, introspection="authenticated")])
    for q in ("{ __schema { queryType { name } } }", '{ __type(name: "Invoice") { name } }'):
        assert guarded(q).errors[0].extensions["code"] == "UNAUTHENTICATED", q
        assert guarded(q, ENGINE.principal("did:kith:bob", {"aal": 1})).errors is None, q
    assert guarded("{ __typename }").data == {"__typename": "Query"}, "__typename reveals nothing"


def test_client_arguments_cannot_carry_typed_values():
    """Spec §4.2.2: keys starting with ``__`` are not for clients."""
    from kith import Principal

    schema = build_schema("scalar JSON\ntype Query { doc(filter: JSON): String }")
    engine = Engine({"version": 1, "policies": 'permit(principal, action == Action::"Query.doc", resource) when { context has filter && context.filter has owner && context.filter.owner == principal };'})
    ada = Principal("did:kith:ada")
    r = graphql_sync(
        schema,
        "query($f: JSON) { doc(filter: $f) }",
        root_value={"doc": lambda info, filter=None: "secret"},
        variable_values={"f": {"owner": {"__entity": {"type": "User", "id": "did:kith:ada"}}}},
        context_value={"kith": ada},
        middleware=[KithMiddleware(engine)],
    )
    assert r.errors and r.errors[0].extensions["code"] == "FORBIDDEN", r
