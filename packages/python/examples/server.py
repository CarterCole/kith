"""Ariadne (ASGI) GraphQL server protected by Kith.

    KITH_HUB=http://127.0.0.1:7777 KITH_BUNDLE=bundle.json uv run python examples/server.py
"""

import json
import os
from pathlib import Path

import uvicorn
from ariadne import MutationType, QueryType, make_executable_schema
from ariadne.asgi import GraphQL
from ariadne.asgi.handlers import GraphQLHTTPHandler

from kith import Engine, KithAuthError, Verifier, bearer_token
from kith.graphql import KithMiddleware

HUB = os.environ.get("KITH_HUB", "http://localhost:7777")
AUDIENCE = os.environ.get("KITH_AUDIENCE", "api://invoices")
EX = Path(__file__).parents[3] / "examples"
engine = Engine(json.loads(Path(os.environ.get("KITH_BUNDLE", EX / "policy/bundle.template.json")).read_text()))
verifier = Verifier(HUB, AUDIENCE)
INVOICES = json.loads((EX / "graphql/data.json").read_text())

query, mutation = QueryType(), MutationType()


@query.field("me")
def me(_, info):
    p = info.context["kith"]
    return {"did": p.id, "actor": p.actor, "groups": p.groups, "roles": p.roles, "aal": p.attrs["aal"]}


@query.field("invoices")
def invoices(*_):
    return INVOICES


@query.field("invoice")
def invoice(_, info, id):
    return next((i for i in INVOICES if i["id"] == id), None)


@mutation.field("payInvoice")
def pay(_, info, id, amount):
    return {**next(i for i in INVOICES if i["id"] == id), "status": "paid"}


def context_value(request, _data=None):
    token = bearer_token(request.headers.get("authorization"))
    if not token:
        return {"kith": None}
    try:
        return {"kith": verifier.verify(token).principal()}
    except KithAuthError:
        return {"kith": None}


schema = make_executable_schema((EX / "graphql/schema.graphql").read_text(), query, mutation)
app = GraphQL(schema, context_value=context_value, http_handler=GraphQLHTTPHandler(middleware=[KithMiddleware(engine)]))

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=int(os.environ.get("PORT", 4002)), log_level="warning")
