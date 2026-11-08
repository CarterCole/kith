import json
import time
from pathlib import Path

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


VECTORS = json.loads((Path(__file__).parents[3] / "spec/test-vectors/tokens.json").read_text())


@pytest.mark.parametrize("case", VECTORS["cases"], ids=lambda c: c["name"])
def test_token_vectors(case):
    """The cases every implementation runs (spec 3.5): accept a token if and only if the vector says so."""
    verifier = Verifier(VECTORS["issuer"], VECTORS["audience"], jwks=VECTORS["jwks"], leeway=VECTORS["leeway"], now=lambda: VECTORS["now"])
    if not case["valid"]:
        with pytest.raises(KithAuthError):
            verifier.verify(case["token"])
        return
    got = verifier.verify(case["token"])
    for name, want in case.get("claims", {}).items():
        assert getattr(got, name) == want, name
    if "resource_org" in case:
        # A resource server configured with an org keeps memberships only from that org (spec 10.8).
        scoped = Verifier(VECTORS["issuer"], VECTORS["audience"], jwks=VECTORS["jwks"], leeway=VECTORS["leeway"], now=lambda: VECTORS["now"], org=case["resource_org"]).verify(case["token"])
        assert scoped.groups == case["groups_kept"]
        if not case["groups_kept"]:
            assert scoped.roles == []
        assert scoped.sub == got.sub


ATTESTATIONS = json.loads((Path(__file__).parents[3] / "spec/test-vectors/attestations.json").read_text())


@pytest.mark.parametrize("case", ATTESTATIONS["cases"], ids=lambda c: c["name"])
def test_attestation_vectors(case):
    """An app accepts "this is that account" if and only if the vector says so (spec 7.8.1, 7.8.2)."""
    from kith import AttestationVerifier

    v = ATTESTATIONS
    verifier = AttestationVerifier(v["issuer"], case.get("audience", v["audience"]), jwks=v["jwks"], leeway=v["leeway"], now=lambda: v["now"])
    if not case["valid"]:
        with pytest.raises(KithAuthError):
            verifier.verify(case["token"])
        return
    got = verifier.verify(case["token"])
    for name, want in case.get("claims", {}).items():
        assert getattr(got, name) == want, name


def test_bearer_token_reads_the_header_the_same_way_as_js():
    from kith import bearer_token

    assert bearer_token("Bearer abc") == "abc"
    assert bearer_token("bearer   abc") == "abc"
    assert bearer_token("BEARER\tabc") == "abc"
    for none in (None, "", "Bearer", "Bearer ", "Basic abc", "abc"):
        assert bearer_token(none) is None
