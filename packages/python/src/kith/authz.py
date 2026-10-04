"""Groups (explicit + dynamic), roles and Cedar policy evaluation.

Semantics match ``kith_core::authz`` (Rust) and ``@kith/auth`` (JS) exactly; all three
run the shared vectors in ``spec/test-vectors/authz.json``.
"""

from __future__ import annotations

import json
import math
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping

import cedarpy

MEMBER_ACTION = "kith:member"


@dataclass
class Principal:
    id: str
    attrs: dict[str, Any] = field(default_factory=dict)
    groups: list[str] = field(default_factory=list)
    roles: list[str] = field(default_factory=list)
    #: Set when an actor exercises a delegation on this principal's behalf.
    actor: str | None = None
    caps: list[dict[str, str]] | None = None


@dataclass
class Resource:
    type: str
    id: str
    attrs: dict[str, Any] = field(default_factory=dict)

    @property
    def uid(self) -> str:
        return f"{self.type}::{json.dumps(self.id)}"


@dataclass
class Decision:
    allowed: bool
    reasons: list[str]
    errors: list[str]


def cedar_value(v: Any) -> Any:
    """Cedar has no null or floats: drop ``None``, stringify non-integers."""
    if v is None:
        return None
    if isinstance(v, bool) or isinstance(v, (int, str)):
        return v
    if isinstance(v, float):
        return str(v)
    if isinstance(v, (list, tuple, set)):
        return [c for c in (cedar_value(x) for x in v) if c is not None]
    if isinstance(v, Mapping):
        return {str(k): c for k, x in v.items() if (c := cedar_value(x)) is not None}
    return str(v)


def number_text(v: float | int) -> str:
    """The pinned text of a stringified number (spec §4.2): ECMAScript ``Number::toString``
    of the double nearest ``v``, the form RFC 8785 §3.2.2.3 uses. It is the shortest
    digits that read back as that double, written plainly when the decimal exponent is in
    −7 < e < 21 and as ``d.ddde+N`` or ``d.ddde-N`` otherwise."""
    try:
        f = float(v)
    except OverflowError:  # an int beyond the double range rounds to an infinity
        f = math.inf if v > 0 else -math.inf
    if f != f:
        return "NaN"
    if f == 0:
        return "0"
    sign = "-" if f < 0 else ""
    if math.isinf(f):
        return sign + "Infinity"
    # repr() gives the shortest digits, as ``ddd.ddd`` or ``d.ddde[+-]NN``.
    mantissa, _, exp = repr(abs(f)).partition("e")
    whole, _, frac = mantissa.partition(".")
    digits = (whole + frac).lstrip("0")
    # The decimal point sits after digit ``n`` of the ``k`` digits.
    n = len(whole) + int(exp or 0) - (len(whole + frac) - len(digits))
    digits = digits.rstrip("0")
    k = len(digits)
    if k <= n <= 21:
        return sign + digits + "0" * (n - k)
    if 0 < n <= 21:
        return f"{sign}{digits[:n]}.{digits[n:]}"
    if -6 < n <= 0:
        return f"{sign}0.{'0' * -n}{digits}"
    point = "." if k > 1 else ""
    return f"{sign}{digits[0]}{point}{digits[1:]}e{'+' if n > 0 else '-'}{abs(n - 1)}"


def _glob(pattern: str, value: str) -> bool:
    return pattern == "*" or pattern == value or (pattern.endswith("*") and value.startswith(pattern[:-1]))


def caps_allow(caps: Iterable[Mapping[str, str]], action: str, resource: str) -> bool:
    return any(_glob(c["action"], action) and _glob(c.get("resource", "*"), resource) for c in caps)


def _uid(kind: str, id: str) -> str:
    return f"{kind}::{json.dumps(id)}"


def _entity(kind: str, id: str, attrs: Mapping[str, Any], parents: Iterable[tuple[str, str]]) -> dict:
    return {
        "uid": {"type": kind, "id": id},
        "attrs": cedar_value(dict(attrs)) or {},
        "parents": [{"type": t, "id": i} for t, i in parents],
    }


class Engine:
    """Loads a Kith policy bundle (see ``spec/04-authorization.md``)."""

    def __init__(self, bundle: Mapping[str, Any]):
        self.bundle = dict(bundle)
        self.groups: dict[str, dict] = dict(bundle.get("groups") or {})
        self.roles: dict[str, dict] = dict(bundle.get("roles") or {})
        self.directory: dict[str, dict] = dict(bundle.get("directory") or {})
        self._policies = cedarpy.PolicySet.from_str(bundle.get("policies") or "")
        self._membership: dict[tuple[str, str], Any] = {}
        for kind, sets in (("Group", self.groups), ("Role", self.roles)):
            for name, d in sets.items():
                rule = d.get("rule")
                if not rule:
                    continue
                src = (
                    f'permit(principal, action == Action::"{MEMBER_ACTION}", '
                    f"resource == {kind}::{json.dumps(name)}) when {{ {rule} }};"
                )
                # Exactly one policy per rule: rejects rules that smuggle in extra policies.
                if len(json.loads(cedarpy.policies_to_json_str(src))["staticPolicies"]) != 1:
                    raise ValueError(f"{kind} {name}: rule must be a single expression")
                self._membership[(kind, name)] = cedarpy.PolicySet.from_str(src)

    @classmethod
    def from_json(cls, text: str) -> "Engine":
        return cls(json.loads(text))

    def attributes(self, id: str, attrs: Mapping[str, Any] | None = None) -> dict[str, Any]:
        """Directory attributes merged with (and overridden by) ``attrs``."""
        out = dict((self.directory.get(id) or {}).get("attrs") or {})
        out.update(attrs or {})
        return out

    def _set_entities(self) -> list[dict]:
        return [_entity("Group", g, {}, []) for g in self.groups] + [_entity("Role", r, {}, []) for r in self.roles]

    def _principal_entity(self, p_id: str, attrs: Mapping[str, Any], groups: Iterable[str], roles: Iterable[str]) -> dict:
        return _entity("User", p_id, attrs, [("Group", g) for g in groups] + [("Role", r) for r in roles])

    def memberships(self, id: str, attrs: Mapping[str, Any]) -> tuple[list[str], list[str]]:
        """Compute explicit + nested + dynamic membership (fixpoint)."""
        groups: set[str] = set()
        roles: set[str] = set()
        for _ in range(len(self.groups) + len(self.roles) + 1):
            changed = False
            entities = self._set_entities() + [self._principal_entity(id, attrs, sorted(groups), sorted(roles))]
            for kind, sets, current in (("Group", self.groups, groups), ("Role", self.roles, roles)):
                for name, d in sets.items():
                    if name in current:
                        continue
                    explicit = any(
                        m == id
                        or (m.startswith("group:") and m[6:] in groups)
                        or (m.startswith("role:") and m[5:] in roles)
                        for m in d.get("members") or []
                    )
                    dynamic = False
                    if not explicit and (kind, name) in self._membership:
                        r = cedarpy.is_authorized(
                            {"principal": _uid("User", id), "action": _uid("Action", MEMBER_ACTION), "resource": _uid(kind, name), "context": {}},
                            self._membership[(kind, name)],
                            entities,
                        )
                        dynamic = r.allowed
                    if explicit or dynamic:
                        current.add(name)
                        changed = True
            if not changed:
                break
        return sorted(groups), sorted(roles)

    def principal(self, id: str, attrs: Mapping[str, Any] | None = None, **kw: Any) -> Principal:
        """Build a principal from directory + ``attrs``, computing memberships."""
        a = self.attributes(id, attrs)
        groups, roles = self.memberships(id, a)
        return Principal(id=id, attrs=a, groups=groups, roles=roles, **kw)

    def authorize(self, principal: Principal, action: str, resource: Resource, context: Mapping[str, Any] | None = None) -> Decision:
        """Evaluate ``action`` on ``resource``. Delegation can only narrow access."""
        if principal.caps is not None and not caps_allow(principal.caps, action, resource.uid):
            return Decision(False, ["delegation:cap"], [])
        ctx = cedar_value(dict(context or {})) or {}
        if principal.actor:
            ctx["actor"] = principal.actor
        entities = self._set_entities() + [
            self._principal_entity(principal.id, principal.attrs, principal.groups, principal.roles),
            _entity(resource.type, resource.id, resource.attrs, []),
        ]
        r = cedarpy.is_authorized(
            {"principal": _uid("User", principal.id), "action": _uid("Action", action), "resource": resource.uid, "context": ctx},
            self._policies,
            entities,
        )
        return Decision(bool(r.allowed), list(r.diagnostics.reasons), [str(e) for e in r.diagnostics.errors])
