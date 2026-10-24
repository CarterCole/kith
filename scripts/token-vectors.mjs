#!/usr/bin/env node
// Regenerates spec/test-vectors/tokens.json (spec section 3.5): access tokens a
// resource server must accept or refuse, with a fixed clock and fixed keys, so the file
// is the same every time. Ed25519 signatures are deterministic.
//
//   node scripts/token-vectors.mjs
//
// Every case is a good token with one thing changed. Implementations verify `token`
// against `jwks` as of `now`, with `issuer`, `audience` and `leeway`, and must accept
// it if and only if `valid` is true. For accepted tokens `claims` holds values the
// verifier must return.
import { writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { ed25519 } from "../packages/js/node_modules/@noble/curves/ed25519.js";

const OUT = join(dirname(fileURLToPath(import.meta.url)), "../spec/test-vectors/tokens.json");
const NOW = 1_800_000_000;
const LEEWAY = 60;
const ISSUER = "https://hub.example";
const AUDIENCE = "api://invoices";

const b64u = (bytes) => Buffer.from(bytes).toString("base64url");
const enc = (o) => b64u(new TextEncoder().encode(JSON.stringify(o)));
const hub = new Uint8Array(32).fill(7);
const stranger = new Uint8Array(32).fill(8);
const jwk = { kty: "OKP", crv: "Ed25519", x: b64u(ed25519.getPublicKey(hub)), kid: "k1", alg: "EdDSA", use: "sig" };

const header = { typ: "at+jwt", alg: "EdDSA", kid: "k1" };
const claims = {
  iss: ISSUER, aud: AUDIENCE, sub: "did:kith:ada", iat: NOW - 10, exp: NOW + 890, jti: "jti-1",
  groups: ["finance"], roles: ["billing-reader"], attrs: { email: "ada@acme.test" }, aal: 2, amr: ["hwk"],
};

function mint(c = claims, h = header, key = hub) {
  const input = `${enc(h)}.${enc(c)}`;
  return `${input}.${b64u(ed25519.sign(new TextEncoder().encode(input), key))}`;
}
const without = (k) => Object.fromEntries(Object.entries(claims).filter(([name]) => name !== k));
const withHeader = (changes) => ({ ...header, ...changes });
const withoutHeader = (k) => Object.fromEntries(Object.entries(header).filter(([name]) => name !== k));
const expect = { sub: claims.sub, aal: 2, jti: "jti-1", groups: ["finance"] };

const good = mint();
const [h0, p0, s0] = good.split(".");

const cases = [
  { name: "a good token", token: good, valid: true, claims: expect },
  { name: "typ application/at+jwt is the same type (RFC 7515 4.1.9)", token: mint(claims, withHeader({ typ: "application/at+jwt" })), valid: true, claims: expect },
  { name: "typ AT+JWT, media types are case-insensitive", token: mint(claims, withHeader({ typ: "AT+JWT" })), valid: true, claims: expect },
  { name: "expired 59 s ago, inside the leeway", token: mint({ ...claims, exp: NOW - 59 }), valid: true, claims: expect },
  { name: "expired 60 s ago, the leeway is used up (RFC 7519: now must be before exp)", token: mint({ ...claims, exp: NOW - 60 }), valid: false },
  { name: "expired 61 s ago", token: mint({ ...claims, exp: NOW - 61 }), valid: false },
  { name: "issued 60 s from now, inside the leeway", token: mint({ ...claims, iat: NOW + 60 }), valid: true, claims: expect },
  { name: "issued 61 s from now", token: mint({ ...claims, iat: NOW + 61 }), valid: false },
  { name: "issued one day from now", token: mint({ ...claims, iat: NOW + 86400, exp: NOW + 90000 }), valid: false },
  { name: "not before 60 s from now, inside the leeway", token: mint({ ...claims, nbf: NOW + 60 }), valid: true, claims: expect },
  { name: "not before 61 s from now", token: mint({ ...claims, nbf: NOW + 61 }), valid: false },
  { name: "valid until the end of time", token: mint({ ...claims, exp: 9_007_199_254_740_991 }), valid: true, claims: expect },
  ...["exp", "iat", "sub", "jti", "aal", "iss", "aud"].map((k) => ({ name: `no ${k}`, token: mint(without(k)), valid: false })),
  { name: "empty sub", token: mint({ ...claims, sub: "" }), valid: false },
  { name: "sub is not a string", token: mint({ ...claims, sub: 7 }), valid: false },
  { name: "aal 0", token: mint({ ...claims, aal: 0 }), valid: false },
  { name: "aal 4", token: mint({ ...claims, aal: 4 }), valid: false },
  { name: "aal as a string", token: mint({ ...claims, aal: "2" }), valid: false },
  { name: "aal 1.5", token: mint({ ...claims, aal: 1.5 }), valid: false },
  { name: "another issuer", token: mint({ ...claims, iss: "https://evil.example" }), valid: false },
  { name: "another audience", token: mint({ ...claims, aud: "api://other" }), valid: false },
  { name: "audience in a list, alone", token: mint({ ...claims, aud: [AUDIENCE] }), valid: false },
  { name: "audience in a list, with another", token: mint({ ...claims, aud: [AUDIENCE, "api://other"] }), valid: false },
  { name: "typ JWT", token: mint(claims, withHeader({ typ: "JWT" })), valid: false },
  { name: "no typ", token: mint(claims, withoutHeader("typ")), valid: false },
  { name: "alg none, no signature", token: `${enc(withHeader({ alg: "none" }))}.${p0}.`, valid: false },
  { name: "alg HS256 over the same input", token: `${enc(withHeader({ alg: "HS256" }))}.${p0}.${s0}`, valid: false },
  { name: "alg ES256 over the same input", token: `${enc(withHeader({ alg: "ES256" }))}.${p0}.${s0}`, valid: false },
  { name: "a kid the JWKS does not have", token: mint(claims, withHeader({ kid: "k2" })), valid: false },
  { name: "no kid", token: mint(claims, withoutHeader("kid")), valid: false },
  { name: "signed by another key under the right kid", token: mint(claims, header, stranger), valid: false },
  { name: "claims changed after signing", token: `${h0}.${enc({ ...claims, aal: 3 })}.${s0}`, valid: false },
  { name: "signature bytes flipped", token: `${h0}.${p0}.${b64u(Buffer.from(s0, "base64url").map((b, i) => (i === 0 ? b ^ 1 : b)))}`, valid: false },
  { name: "two segments", token: `${h0}.${p0}`, valid: false },
  { name: "four segments", token: `${good}.${s0}`, valid: false },
  { name: "empty", token: "", valid: false },
  { name: "not base64", token: "!!!.???.***", valid: false },
];

writeFileSync(
  OUT,
  JSON.stringify(
    {
      description:
        "Access token vectors (spec 3.5). Verify `token` against `jwks` as of `now` for `issuer` and `audience`, with `leeway` seconds of clock tolerance. Accept it if and only if `valid`. For accepted tokens `claims` holds values the verifier must return. Regenerate with node scripts/token-vectors.mjs.",
      now: NOW,
      leeway: LEEWAY,
      issuer: ISSUER,
      audience: AUDIENCE,
      jwks: { keys: [jwk] },
      cases,
    },
    null,
    2,
  ) + "\n",
);
console.log(`${cases.length} cases (${cases.filter((c) => c.valid).length} valid) -> ${OUT}`);
