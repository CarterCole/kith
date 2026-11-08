"""Verify hub-issued Kith access tokens (RFC 9068 JWTs, EdDSA)."""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field, replace
from typing import Any, Callable

import jwt

from .authz import Principal


class KithAuthError(Exception):
    status = 401


@dataclass
class AccessClaims:
    iss: str
    sub: str
    aud: str
    iat: int
    exp: int
    jti: str
    aal: int
    groups: list[str] = field(default_factory=list)
    roles: list[str] = field(default_factory=list)
    attrs: dict[str, Any] = field(default_factory=dict)
    amr: list[str] = field(default_factory=list)
    dev: str | None = None
    act: dict | None = None
    cap: list[dict] | None = None
    cnf: dict | None = None
    # The org whose policy produced groups and roles, and the policy root and newest
    # revocation entry they came from. Absent for memberships from a bundle file (spec 10.8).
    org: str | None = None
    pol: dict | None = None

    def for_org(self, org: str) -> "AccessClaims":
        """The claims as a resource server configured with ``org`` may rely on them (spec 10.8):
        groups and roles survive only if the token says ``org`` produced them."""
        if self.org == org:
            return self
        return replace(self, groups=[], roles=[])

    def principal(self) -> Principal:
        return Principal(
            id=self.sub,
            attrs={**self.attrs, "aal": self.aal, "amr": self.amr},
            groups=list(self.groups),
            roles=list(self.roles),
            actor=(self.act or {}).get("sub"),
            caps=self.cap,
        )


@dataclass
class AccountAttestation:
    """The hub's signed statement that ``sub`` signed in as ``account`` at ``provider_iss`` (spec 7.8.1)."""

    iss: str
    sub: str
    aud: str
    iat: int
    exp: int
    jti: str
    provider: str
    provider_iss: str
    account: str
    verified_at: int


def _number(v: Any) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool)


class Verifier:
    """Verifies tokens against the hub's JWKS (fetched and cached by PyJWT).

    The rules are spec 3.5 and the shared vectors in ``spec/test-vectors/tokens.json``:
    ``typ`` is ``at+jwt``, ``alg`` is EdDSA, the token names its ``kid``, ``iss`` and
    ``aud`` match (``aud`` is one string, not a list), and ``exp``, ``iat``, ``sub``,
    ``jti`` and ``aal`` are all there. ``now`` is the clock, in seconds; tests pin it.
    """

    _typ = "at+jwt"
    _claims: type = AccessClaims
    _required = ("aal",)
    _strings = ("sub", "jti")

    def __init__(
        self,
        issuer: str,
        audience: str,
        jwks_url: str | None = None,
        jwks: dict | None = None,
        leeway: int = 60,
        now: Callable[[], float] = time.time,
        org: str | None = None,
    ):
        self.org = org
        self.issuer = issuer
        self.audience = audience
        self.leeway = leeway
        self._now = now
        self._static = jwt.PyJWKSet.from_dict(jwks) if jwks else None
        self._client = None if jwks else jwt.PyJWKClient(jwks_url or f"{issuer.rstrip('/')}/.well-known/jwks.json", cache_keys=True)

    def _key(self, token: str):
        kid = jwt.get_unverified_header(token).get("kid")
        if not kid:
            raise KithAuthError("the token has no kid")
        if self._static is not None:
            for k in self._static.keys:
                if k.key_id == kid:
                    return k.key
            raise KithAuthError(f"unknown kid {kid}")
        return self._client.get_signing_key_from_jwt(token).key

    def verify(self, token: str) -> Any:
        try:
            typ = jwt.get_unverified_header(token).get("typ")
            # RFC 7515 4.1.9: media types are case-insensitive and "application/" may be left off.
            if not isinstance(typ, str) or re.sub(r"^application/", "", typ.lower()) != self._typ:
                raise KithAuthError(f"expected typ {self._typ}")
            c = jwt.decode(
                token,
                self._key(token),
                algorithms=["EdDSA"],
                audience=self.audience,
                issuer=self.issuer,
                # Times are checked below, against the clock this verifier was given.
                options={"require": ["exp", "iat", "sub", "iss", "aud", "jti", *self._required], "verify_exp": False, "verify_iat": False, "verify_nbf": False},
            )
            self._check(c)
        except KithAuthError:
            raise
        except jwt.PyJWTError as e:
            raise KithAuthError(f"invalid token: {e}") from e
        known = self._claims.__dataclass_fields__.keys()
        claims = self._claims(**{k: v for k, v in c.items() if k in known})
        return claims.for_org(self.org) if self.org is not None and isinstance(claims, AccessClaims) else claims

    def _check(self, c: dict) -> None:
        now = self._now()
        if not isinstance(c["aud"], str):
            raise KithAuthError('invalid token: "aud" must be a single string')
        for name in self._strings:
            if not isinstance(c[name], str) or not c[name]:
                raise KithAuthError(f'invalid token: "{name}" must be a non-empty string')
        self._check_extra(c, now)
        if not _number(c["exp"]) or not _number(c["iat"]):
            raise KithAuthError('invalid token: "exp" and "iat" must be numbers')
        # RFC 7519: the time must be before exp, so a token is expired once exp + leeway is reached.
        if c["exp"] + self.leeway <= now:
            raise KithAuthError("invalid token: expired")
        if c["iat"] - self.leeway > now:
            raise KithAuthError('invalid token: "iat" is in the future')
        if "nbf" in c and (not _number(c["nbf"]) or c["nbf"] - self.leeway > now):
            raise KithAuthError("invalid token: not valid yet")

    def _check_extra(self, c: dict, now: float) -> None:
        if type(c["aal"]) is not int or not 1 <= c["aal"] <= 3:
            raise KithAuthError('invalid token: "aal" must be 1, 2 or 3')
        if "org" in c and (not isinstance(c["org"], str) or not c["org"]):
            raise KithAuthError('invalid token: "org" must be a non-empty string')
        if "pol" in c:
            pol = c["pol"]
            if "org" not in c:
                raise KithAuthError('invalid token: "pol" needs an "org"')
            ok = isinstance(pol, dict) and isinstance(pol.get("root"), str) and pol["root"] and type(pol.get("rev")) is int and pol["rev"] >= 0
            if not ok:
                raise KithAuthError('invalid token: "pol" must be {root, rev}')


class AttestationVerifier(Verifier):
    """Verifies account attestations (spec 7.8.1). ``audience`` is the app's client id.

    The rules are those of :class:`Verifier` with ``typ`` ``kith-account+jwt``. An
    attestation says who signed in and when (``verified_at``); how recent that has to
    be is the app's call.
    """

    _typ = "kith-account+jwt"
    _claims = AccountAttestation
    _required = ("provider", "provider_iss", "account", "verified_at")
    _strings = ("sub", "jti", "provider", "provider_iss", "account")

    def _check_extra(self, c: dict, now: float) -> None:
        if not _number(c["verified_at"]):
            raise KithAuthError('invalid token: "verified_at" must be a number')
        if c["verified_at"] - self.leeway > now:
            raise KithAuthError('invalid token: "verified_at" is in the future')


def bearer_token(header: str | None) -> str | None:
    """The token from an ``Authorization: Bearer …`` header, with the same whitespace rules as the JS package."""
    m = re.match(r"^Bearer\s+(.+)$", header or "", re.IGNORECASE)
    return m.group(1) if m else None
