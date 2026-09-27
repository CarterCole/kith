import json
import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from kith import KithAuthError, Verifier


def make(aud="api", typ="at+jwt"):
    key = Ed25519PrivateKey.generate()
    jwk = json.loads(jwt.algorithms.OKPAlgorithm.to_jwk(key.public_key()))
    jwk.update(kid="k1", alg="EdDSA")
    now = int(time.time())
    claims = {"iss": "http://hub", "aud": aud, "sub": "did:kith:ada", "iat": now, "exp": now + 60, "jti": "j", "aal": 2,
              "groups": ["finance"], "roles": ["billing-reader"], "attrs": {"email": "ada@acme.test"}, "amr": ["hwk"], "act": {"sub": "did:kith:agent"}}
    tok = jwt.encode(claims, key, algorithm="EdDSA", headers={"kid": "k1", "typ": typ})
    return tok, {"keys": [jwk]}


def test_verify_and_principal():
    tok, jwks = make()
    p = Verifier("http://hub", "api", jwks=jwks).verify(tok).principal()
    assert p.id == "did:kith:ada" and p.attrs["aal"] == 2 and p.actor == "did:kith:agent"


def test_wrong_audience_and_typ():
    tok, jwks = make(aud="other")
    with pytest.raises(KithAuthError):
        Verifier("http://hub", "api", jwks=jwks).verify(tok)
    tok, jwks = make(typ="JWT")
    with pytest.raises(KithAuthError):
        Verifier("http://hub", "api", jwks=jwks).verify(tok)
