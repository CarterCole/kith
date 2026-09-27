import { test } from "node:test";
import assert from "node:assert/strict";
import { SignJWT, exportJWK, generateKeyPair } from "jose";
import { createVerifier, principalFromClaims } from "./token.ts";

test("verifies an at+jwt and maps claims to a principal", async () => {
  const { publicKey, privateKey } = await generateKeyPair("EdDSA", { crv: "Ed25519" });
  const jwk = { ...(await exportJWK(publicKey)), kid: "k1", alg: "EdDSA" };
  const now = Math.floor(Date.now() / 1000);
  const token = await new SignJWT({ groups: ["finance"], roles: ["billing-reader"], attrs: { email: "ada@acme.test" }, aal: 2, amr: ["hwk"], act: { sub: "did:kith:agent" } })
    .setProtectedHeader({ alg: "EdDSA", typ: "at+jwt", kid: "k1" })
    .setIssuer("http://hub").setAudience("api").setSubject("did:kith:ada").setIssuedAt(now).setExpirationTime(now + 60).setJti("j")
    .sign(privateKey);
  const verify = createVerifier({ issuer: "http://hub", audience: "api", jwks: { keys: [jwk] } });
  const p = principalFromClaims(await verify(token));
  assert.equal(p.id, "did:kith:ada");
  assert.equal(p.attrs.aal, 2);
  assert.equal(p.actor, "did:kith:agent");
  await assert.rejects(createVerifier({ issuer: "http://hub", audience: "other", jwks: { keys: [jwk] } })(token));
});
