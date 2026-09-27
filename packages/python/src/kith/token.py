"""Verify hub-issued Kith access tokens (RFC 9068 JWTs, EdDSA)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

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

    def principal(self) -> Principal:
        return Principal(
            id=self.sub,
            attrs={**self.attrs, "aal": self.aal, "amr": self.amr},
            groups=list(self.groups),
            roles=list(self.roles),
            actor=(self.act or {}).get("sub"),
            caps=self.cap,
        )


class Verifier:
    """Verifies tokens against the hub's JWKS (fetched and cached by PyJWT)."""

    def __init__(self, issuer: str, audience: str, jwks_url: str | None = None, jwks: dict | None = None, leeway: int = 60):
        self.issuer = issuer
        self.audience = audience
        self.leeway = leeway
        self._static = jwt.PyJWKSet.from_dict(jwks) if jwks else None
        self._client = None if jwks else jwt.PyJWKClient(jwks_url or f"{issuer.rstrip('/')}/.well-known/jwks.json", cache_keys=True)

    def _key(self, token: str):
        kid = jwt.get_unverified_header(token).get("kid")
        if self._static is not None:
            for k in self._static.keys:
                if k.key_id == kid:
                    return k.key
            raise KithAuthError(f"unknown kid {kid}")
        return self._client.get_signing_key_from_jwt(token).key

    def verify(self, token: str) -> AccessClaims:
        try:
            if jwt.get_unverified_header(token).get("typ") != "at+jwt":
                raise KithAuthError("expected typ at+jwt")
            c = jwt.decode(
                token,
                self._key(token),
                algorithms=["EdDSA"],
                audience=self.audience,
                issuer=self.issuer,
                leeway=self.leeway,
                options={"require": ["exp", "iat", "sub", "iss", "aud"]},
            )
        except KithAuthError:
            raise
        except jwt.PyJWTError as e:
            raise KithAuthError(f"invalid token: {e}") from e
        known = AccessClaims.__dataclass_fields__.keys()
        return AccessClaims(**{k: v for k, v in c.items() if k in known})


def bearer_token(header: str | None) -> str | None:
    if header and header.lower().startswith("bearer "):
        return header[7:].strip()
    return None
