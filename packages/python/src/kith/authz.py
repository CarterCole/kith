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
#: The action an ``assume`` rule compiles to (spec §4.3.1).
ASSUME_ACTION = "kith:assume"


@dataclass
class Principal:
    id: str
    attrs: dict[str, Any] = field(default_factory=dict)
    groups: list[str] = field(default_factory=list)
    roles: list[str] = field(default_factory=list)
    #: Set when an actor exercises a delegation on this principal's behalf.
    actor: str | None = None
    caps: list[dict[str, str]] | None = None
    #: The role this session assumed (spec §4.3.1). It is in ``roles`` as well.
    assumed: str | None = None


@dataclass
class Entity:
    """An entity a request describes besides its principal and resource (spec §4.2.1):
    an ancestor of the resource, or something one of its attributes refers to.
    ``parents`` are ``{"type": ..., "id": ...}`` references."""

    type: str
    id: str
    attrs: dict[str, Any] = field(default_factory=dict)
    parents: list[Mapping[str, str]] = field(default_factory=list)


@dataclass
class Resource:
    type: str
    id: str
    attrs: dict[str, Any] = field(default_factory=dict)
    #: What the resource is directly in, as ``{"type": ..., "id": ...}`` references.
    #: ``resource in Folder::"x"`` holds when ``x`` is a parent, or is reached from one
    #: through ``related``.
    parents: list[Mapping[str, str]] = field(default_factory=list)
    #: The other entities policies may walk to from this resource: :class:`Entity`
    #: values, or mappings with the same members.
    related: list[Any] = field(default_factory=list)

    @property
    def uid(self) -> str:
        """``Type::"id"`` as capabilities are matched against it, the same text as in Rust and JS."""
        return f"{self.type}::{json.dumps(self.id, ensure_ascii=False)}"


@dataclass
class Decision:
    allowed: bool
    reasons: list[str]
    errors: list[str]


def cedar_value(v: Any) -> Any:
    """Cedar has no null or floats: drop ``None``, stringify non-integers.

    A float with no fractional part (``2.0``) is the integer it says, as in JavaScript,
    where the two cannot be told apart.
    """
    if v is None:
        return None
    if isinstance(v, bool) or isinstance(v, (int, str)):
        return v
    if isinstance(v, float):
        return int(v) if v.is_integer() and abs(v) <= 2**53 - 1 else str(v)
    if isinstance(v, (list, tuple, set)):
        return [c for c in (cedar_value(x) for x in v) if c is not None]
    if isinstance(v, Mapping):
        return {str(k): c for k, x in v.items() if (c := cedar_value(x)) is not None}
    return str(v)


def _ext(fn: str, arg: str) -> dict:
    return {"__extn": {"fn": fn, "arg": arg}}


# Typed values (spec §4.2.2), in the form Cedar's JSON reads. A plain string is always a
# ``String``: an address, a time or a decimal has to say that it is one.


def ip(text: str) -> dict:
    """An IP address or CIDR range: ``10.1.2.3``, ``10.0.0.0/8``, ``::1``."""
    return _ext("ip", text)


def decimal(text: str) -> dict:
    """A decimal with at most four fractional digits: ``12.50``."""
    return _ext("decimal", text)


def datetime(text: str) -> dict:
    """A date or an instant: ``2030-01-01``, ``2030-01-01T09:30:00Z``."""
    return _ext("datetime", text)


def duration(text: str) -> dict:
    """A length of time: ``1h30m``, ``-2d``."""
    return _ext("duration", text)


def entity_ref(type: str, id: str) -> dict:
    """A reference to another entity, such as a document's owner."""
    return {"__entity": {"type": type, "id": id}}


def _reserved_type(type: str) -> bool:
    """Entity types a request may not describe: the bundle and the engine supply these."""
    return type in ("Group", "Role", "Action") or type.endswith("::Action")


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


def _cedar_string(s: str) -> str:
    """A Cedar string literal. JSON's escapes are not Cedar's: ``\\u00fc`` is not valid,
    ``\\u{fc}`` is, and non-ASCII text can simply stand."""
    out = ['"']
    for ch in s:
        if ch in '"\\':
            out.append("\\" + ch)
        elif ord(ch) < 0x20 or ord(ch) == 0x7F:
            out.append("\\u{%x}" % ord(ch))
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _uid(kind: str, id: str) -> str:
    """``Type::"id"`` as policy source. Requests use :func:`_ref` instead."""
    return f"{kind}::{_cedar_string(id)}"


def _ref(kind: str, id: str) -> dict:
    """An entity reference in cedarpy's structured form. The string form has to be exactly
    Cedar's canonical text, which not every id has a simple spelling in (newlines, NUL)."""
    return {"type": kind, "id": id}


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
        self._assume: dict[str, Any] = {}
        for kind, sets in (("Group", self.groups), ("Role", self.roles)):
            for name, d in sets.items():
                rule = d.get("rule")
                if not rule:
                    continue
                src = (
                    f'permit(principal, action == Action::"{MEMBER_ACTION}", '
                    f"resource == {_uid(kind, name)}) when {{ {rule} }};"
                )
                # Exactly one policy per rule: rejects rules that smuggle in extra policies.
                if len(json.loads(cedarpy.policies_to_json_str(src))["staticPolicies"]) != 1:
                    raise ValueError(f"{kind} {name}: rule must be a single expression")
                self._membership[(kind, name)] = cedarpy.PolicySet.from_str(src)
        for kind, sets in (("Group", self.groups), ("Role", self.roles)):
            for name, d in sets.items():
                a = d.get("assume")
                if a is None:
                    continue
                if kind == "Group":
                    raise ValueError(f"group {name}: only a role can be assumed")
                if d.get("members") or d.get("rule") is not None:
                    raise ValueError(f"role {name} is assumable, so it is held only by assuming it: it has no members and no rule")
                if not isinstance(a, Mapping):
                    raise ValueError(f"role {name}: assume is an object")
                members = a.get("members", [])
                if not isinstance(members, list) or not all(isinstance(m, str) for m in members):
                    raise ValueError(f"role {name}: assume.members is a list of strings")
                max_age = a.get("max_age")
                if max_age is not None and not (type(max_age) is int and max_age > 0):
                    raise ValueError(f"role {name}: max_age is a positive number of seconds")
                rule = a.get("rule")
                if rule is not None:
                    if not isinstance(rule, str):
                        raise ValueError(f"role {name}: assume.rule is a string")
                    src = f'permit(principal, action == Action::"{ASSUME_ACTION}", resource == {_uid("Role", name)}) when {{ {rule} }};'
                    if len(json.loads(cedarpy.policies_to_json_str(src))["staticPolicies"]) != 1:
                        raise ValueError(f"role {name}: assume rule must be a single expression")
                    self._assume[name] = cedarpy.PolicySet.from_str(src)

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

    def memberships(self, id: str, attrs: Mapping[str, Any], excluded: Iterable[str] = ()) -> tuple[list[str], list[str]]:
        """Compute explicit + nested + dynamic membership (fixpoint). Sets in ``excluded``
        (``Group::x``, ``Role::x``, from revocations) never join, so neither do sets that
        depended on them."""
        excluded = set(excluded)
        groups: set[str] = set()
        roles: set[str] = set()
        for _ in range(len(self.groups) + len(self.roles) + 1):
            changed = False
            entities = self._set_entities() + [self._principal_entity(id, attrs, sorted(groups), sorted(roles))]
            for kind, sets, current in (("Group", self.groups, groups), ("Role", self.roles, roles)):
                for name, d in sets.items():
                    if name in current or f"{kind}::{name}" in excluded:
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
                            {"principal": _ref("User", id), "action": _ref("Action", MEMBER_ACTION), "resource": _ref(kind, name), "context": {}},
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

    def assume(self, id: str, attrs: Mapping[str, Any], excluded: Iterable[str], role: str) -> tuple[list[str], list[str]] | str:
        """Memberships for a session that assumes ``role`` (spec §4.3.1): the standing ones,
        with the sets in ``excluded`` revoked, plus the role. Returns ``(groups, roles)``, or
        the refusal: ``"not_assumable"`` or ``"not_eligible"``."""
        a = (self.roles.get(role) or {}).get("assume")
        if a is None:
            return "not_assumable"
        excluded = set(excluded)
        groups, roles = self.memberships(id, attrs, excluded)
        if f"Role::{role}" in excluded:
            return "not_eligible"
        listed = any(
            m == id or (m.startswith("group:") and m[6:] in groups) or (m.startswith("role:") and m[5:] in roles)
            for m in a.get("members") or []
        )
        if not listed and role in self._assume:
            entities = self._set_entities() + [self._principal_entity(id, attrs, groups, roles)]
            r = cedarpy.is_authorized(
                {"principal": _ref("User", id), "action": _ref("Action", ASSUME_ACTION), "resource": _ref("Role", role), "context": {}},
                self._assume[role],
                entities,
            )
            listed = bool(r.allowed)
        if not listed:
            return "not_eligible"
        return groups, sorted(roles + [role])

    def assume_max_age(self, role: str) -> int | None:
        """The longest an access token may carry ``role`` as assumed, if the role says."""
        return ((self.roles.get(role) or {}).get("assume") or {}).get("max_age")

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
        refs = lambda ps: [(p["type"], p["id"]) for p in ps or []]  # noqa: E731
        entities = self._set_entities() + [
            self._principal_entity(principal.id, principal.attrs, principal.groups, principal.roles),
            _entity(resource.type, resource.id, resource.attrs, refs(resource.parents)),
        ]
        # A related entity describes something new. It never restates the principal, the
        # resource, a set or an action, whose parents decide who is in what.
        seen = {("User", principal.id), (resource.type, resource.id)}
        for r in resource.related or []:
            e = r if isinstance(r, Entity) else Entity(r["type"], r["id"], r.get("attrs") or {}, r.get("parents") or [])
            if _reserved_type(e.type) or (e.type, e.id) in seen:
                return Decision(False, ["entities:conflict"], [])
            seen.add((e.type, e.id))
            entities.append(_entity(e.type, e.id, e.attrs, refs(e.parents)))
        r = cedarpy.is_authorized(
            {"principal": _ref("User", principal.id), "action": _ref("Action", action), "resource": _ref(resource.type, resource.id), "context": ctx},
            self._policies,
            entities,
        )
        return Decision(bool(r.allowed), list(r.diagnostics.reasons), [str(e) for e in r.diagnostics.errors])
