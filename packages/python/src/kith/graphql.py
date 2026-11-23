"""Lock down GraphQL resolvers with Kith (graphql-core middleware).

Works with anything that takes graphql-core middleware: Ariadne, Graphene, plain
``graphql()``. (Strawberry has its own extension mechanism and needs a small wrapper,
which this package does not ship yet.) Same rules as the JS package:

* Root fields are checked as ``"<Type>.<field>"`` on ``Operation::"<Type>.<field>"``
  with the arguments + ``operationType`` as Cedar context. Default deny.
* Object fields marked ``@auth`` (or listed in ``fields``) are checked with the parent
  object as the resource.
* Types marked ``@auth`` (or in ``row_level``) are checked per object with
  ``"<Type>.read"``; lists are filtered.
* A denied field that a higher assurance level would allow is an
  ``INSUFFICIENT_USER_AUTHENTICATION`` error carrying the RFC 9470 challenge in
  ``extensions["www_authenticate"]`` (spec §4.3.2), not FORBIDDEN.
* ``__typename`` is always allowed, since client libraries add it to every selection
  set. ``__schema`` and ``__type`` (introspection) are open unless
  ``introspection="authenticated"``, which asks for a principal.
"""

from __future__ import annotations

import inspect
import re
from typing import Any, Callable

from graphql import GraphQLError, GraphQLResolveInfo, get_named_type

from .authz import Engine, Principal, Resource

AUTH_DIRECTIVE_SDL = '''
"Kith: check this field (optionally with a custom action), or check every object of this type (row level)."
directive @auth(action: String) on FIELD_DEFINITION | OBJECT
'''


def _auth_directive(node: Any) -> dict | None:
    for d in getattr(node, "directives", None) or []:
        if d.name.value == "auth":
            out: dict = {}
            for a in d.arguments or []:
                if a.name.value == "action":
                    out["action"] = a.value.value
            return out
    return None


def default_to_resource(type_name: str, obj: Any) -> Resource:
    src = obj if isinstance(obj, dict) else getattr(obj, "__dict__", {})
    attrs = {k: v for k, v in src.items() if v is None or isinstance(v, (str, int, float, bool))}
    return Resource(type_name, str(src.get("id", "?")), attrs)


def client_args(v: Any) -> Any:
    """Client arguments with every key that starts with ``__`` removed, at any depth. Those
    keys spell typed values (``__entity``, ``__extn``, spec §4.2.2), which only the server
    may make."""
    if isinstance(v, (list, tuple)):
        return [client_args(x) for x in v]
    if isinstance(v, dict):
        return {k: client_args(x) for k, x in v.items() if not str(k).startswith("__")}
    return v


def _forbidden(action: str) -> GraphQLError:
    return GraphQLError(f"Not authorized: {action}", extensions={"code": "FORBIDDEN", "action": action})


ACR_PREFIX = "urn:kith:acr:aal"


def step_up_challenge(level: int) -> str:
    """The RFC 9470 ``WWW-Authenticate`` value that asks the client to sign in again at
    ``level`` (spec §4.3.2). The client sends the user to the hub with ``acr_values``
    set to the ``acr_values`` it names."""
    return f'Bearer error="insufficient_user_authentication", error_description="A stronger sign-in is required", acr_values="{ACR_PREFIX}{level}"'


def step_up_required(source: Any) -> int | None:
    """The level a resource server asked for, or ``None``: from a ``WWW-Authenticate``
    value or a GraphQL error from :class:`KithMiddleware`. Of several ``acr_values``,
    the lowest Kith level wins, as the hub reads them."""
    if isinstance(source, str):
        text = source
    elif isinstance(getattr(source, "extensions", None), dict):
        e = source.extensions
        if e.get("code") != "INSUFFICIENT_USER_AUTHENTICATION":
            return None
        text = f'Bearer error="insufficient_user_authentication", acr_values="{e.get("acr_values", "")}"'
    else:
        return None
    if 'error="insufficient_user_authentication"' not in text:
        return None
    m = re.search(r'acr_values="([^"]*)"', text)
    levels = [int(v[len(ACR_PREFIX):]) for v in (m.group(1).split() if m else []) if v in (f"{ACR_PREFIX}2", f"{ACR_PREFIX}3")]
    return min(levels) if levels else None


def _step_up(action: str, level: int) -> GraphQLError:
    return GraphQLError(
        f"A stronger sign-in is required for {action}",
        extensions={
            "code": "INSUFFICIENT_USER_AUTHENTICATION",
            "action": action,
            "acr_values": f"{ACR_PREFIX}{level}",
            # For the framework to send as the response's WWW-Authenticate header.
            "www_authenticate": step_up_challenge(level),
        },
    )


class KithMiddleware:
    """graphql-core middleware. Pass ``middleware=[KithMiddleware(engine)]``."""

    def __init__(
        self,
        engine: Engine,
        get_principal: Callable[[Any], Principal | None] | None = None,
        anonymous: Principal | None = None,
        row_level: list[str] | None = None,
        fields: list[str] | None = None,
        to_resource: Callable[[str, Any], Resource] = default_to_resource,
        on_deny: str = "error",
        introspection: str = "open",
        step_up: bool = True,
    ):
        self.engine = engine
        self.get_principal = get_principal or (lambda ctx: (ctx.get("kith") if isinstance(ctx, dict) else getattr(ctx, "kith", None)))
        self.anonymous = anonymous
        self.row_level = set(row_level or [])
        self.fields = set(fields or [])
        self.to_resource = to_resource
        self.on_deny = on_deny
        if introspection not in ("open", "authenticated"):
            raise ValueError('introspection must be "open" or "authenticated"')
        self.introspection = introspection
        self.step_up = step_up

    def _check(self, principal: Principal, action: str, resource: Resource, context: dict) -> bool:
        return self.engine.authorize(principal, action, resource, context).allowed

    def _deny(self, principal: Principal, action: str, resource: Resource, context: dict):
        # A denied field that a stronger sign-in would allow asks for one, even with
        # on_deny="null": the user can do something about it. Rows filtered out of a
        # list are not stepped up.
        level = self.engine.step_up(principal, action, resource, context) if self.step_up else None
        if level:
            raise _step_up(action, level)
        if self.on_deny == "null":
            return None
        raise _forbidden(action)

    def resolve(self, next_: Callable, root: Any, info: GraphQLResolveInfo, **args: Any) -> Any:
        schema = info.schema
        parent = info.parent_type
        # Meta-fields and the introspection types are not part of the schema's own fields.
        if info.field_name.startswith("__") or parent.name.startswith("__"):
            if info.field_name in ("__schema", "__type") and self.introspection == "authenticated":
                if (self.get_principal(info.context) or self.anonymous) is None:
                    raise GraphQLError("Authentication required", extensions={"code": "UNAUTHENTICATED"})
            return next_(root, info, **args)
        roots = {t.name for t in (schema.query_type, schema.mutation_type, schema.subscription_type) if t}
        is_root = parent.name in roots
        field_def = parent.fields[info.field_name]
        key = f"{parent.name}.{info.field_name}"
        directive = _auth_directive(field_def.ast_node)
        check_field = is_root or key in self.fields or directive is not None
        rtype = get_named_type(field_def.type)
        row_check = rtype.name in self.row_level or _auth_directive(getattr(rtype, "ast_node", None)) is not None
        if not check_field and not row_check:
            return next_(root, info, **args)

        principal = self.get_principal(info.context) or self.anonymous
        if principal is None:
            raise GraphQLError("Authentication required", extensions={"code": "UNAUTHENTICATED"})
        op = info.operation.operation.value
        if check_field:
            action = (directive or {}).get("action") or key
            resource = Resource("Operation", key) if is_root else self.to_resource(parent.name, root)
            context = {**client_args(args), "operationType": op, "field": key}
            if not self._check(principal, action, resource, context):
                return self._deny(principal, action, resource, context)

        result = next_(root, info, **args)
        if not row_check:
            return result
        read = f"{rtype.name}.read"

        def filter_rows(value: Any) -> Any:
            if value is None:
                return None
            ctx = {"operationType": op, "field": key}
            ok = lambda item: item is None or self._check(principal, read, self.to_resource(rtype.name, item), ctx)
            if isinstance(value, (list, tuple)):
                return [i for i in value if ok(i)]
            return value if ok(value) else self._deny(principal, read, self.to_resource(rtype.name, value), ctx)

        if inspect.isawaitable(result):
            async def awaited():
                return filter_rows(await result)

            return awaited()
        return filter_rows(result)
