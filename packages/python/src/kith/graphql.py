"""Lock down GraphQL resolvers with Kith (graphql-core middleware).

Works with anything built on graphql-core: Ariadne, Strawberry (``KithExtension``),
Graphene, plain ``graphql()``. Same rules as the JS package:

* Root fields are checked as ``"<Type>.<field>"`` on ``Operation::"<Type>.<field>"``
  with the arguments + ``operationType`` as Cedar context. Default deny.
* Object fields marked ``@auth`` (or listed in ``fields``) are checked with the parent
  object as the resource.
* Types marked ``@auth`` (or in ``row_level``) are checked per object with
  ``"<Type>.read"``; lists are filtered.
"""

from __future__ import annotations

import inspect
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


def _forbidden(action: str) -> GraphQLError:
    return GraphQLError(f"Not authorized: {action}", extensions={"code": "FORBIDDEN", "action": action})


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
    ):
        self.engine = engine
        self.get_principal = get_principal or (lambda ctx: (ctx.get("kith") if isinstance(ctx, dict) else getattr(ctx, "kith", None)))
        self.anonymous = anonymous
        self.row_level = set(row_level or [])
        self.fields = set(fields or [])
        self.to_resource = to_resource
        self.on_deny = on_deny

    def _check(self, principal: Principal, action: str, resource: Resource, context: dict) -> bool:
        return self.engine.authorize(principal, action, resource, context).allowed

    def _deny(self, action: str):
        if self.on_deny == "null":
            return None
        raise _forbidden(action)

    def resolve(self, next_: Callable, root: Any, info: GraphQLResolveInfo, **args: Any) -> Any:
        schema = info.schema
        parent = info.parent_type
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
            if not self._check(principal, action, resource, {**args, "operationType": op, "field": key}):
                return self._deny(action)

        result = next_(root, info, **args)
        if not row_check:
            return result
        read = f"{rtype.name}.read"

        def filter_rows(value: Any) -> Any:
            if value is None:
                return None
            ok = lambda item: item is None or self._check(principal, read, self.to_resource(rtype.name, item), {"operationType": op, "field": key})
            if isinstance(value, (list, tuple)):
                return [i for i in value if ok(i)]
            return value if ok(value) else self._deny(read)

        if inspect.isawaitable(result):
            async def awaited():
                return filter_rows(await result)

            return awaited()
        return filter_rows(result)
