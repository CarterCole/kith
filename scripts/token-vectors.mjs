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

// Provenance (spec section 10.8): `org` names the org whose policy produced `groups` and
// `roles`, `pol` the root and revocation entry they came from. A resource server configured
// with `resource_org` keeps `groups_kept` of the token's groups.
const ORG = "did:kith:acme";
const POL = { root: "bagu7hcv3wa5jsdzxyvnbt6hqz3km2lqmoawyotv6rzpuqbxupxhna", rev: 4 };
const provenance = { org: ORG, pol: POL };
const expectProv = { ...expect, roles: ["billing-reader"], ...provenance };
const withProv = (c) => mint({ ...claims, ...c });

const cases = [
  { name: "a good token", token: good, valid: true, claims: expect },
  { name: "org and pol, read by a resource server for that org", token: withProv(provenance), valid: true, claims: expectProv, resource_org: ORG, groups_kept: ["finance"] },
  { name: "org and pol, read by a resource server for another org", token: withProv(provenance), valid: true, claims: expectProv, resource_org: "did:kith:globex", groups_kept: [] },
  { name: "no org (a bundle file), read by a resource server for an org", token: good, valid: true, claims: expect, resource_org: ORG, groups_kept: [] },
  { name: "an org without pol is still an org", token: withProv({ org: ORG }), valid: true, claims: { ...expect, org: ORG }, resource_org: ORG, groups_kept: ["finance"] },
  { name: "pol without org", token: withProv({ pol: POL }), valid: false },
  { name: "empty org", token: withProv({ org: "" }), valid: false },
  { name: "org is not a string", token: withProv({ org: 7 }), valid: false },
  { name: "pol has no root", token: withProv({ org: ORG, pol: { rev: 4 } }), valid: false },
  { name: "pol has an empty root", token: withProv({ org: ORG, pol: { root: "", rev: 4 } }), valid: false },
  { name: "pol has no rev", token: withProv({ org: ORG, pol: { root: POL.root } }), valid: false },
  { name: "pol.rev is negative", token: withProv({ org: ORG, pol: { ...POL, rev: -1 } }), valid: false },
  { name: "pol.rev is 1.5", token: withProv({ org: ORG, pol: { ...POL, rev: 1.5 } }), valid: false },
  { name: "pol is not an object", token: withProv({ org: ORG, pol: "bagu" }), valid: false },
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

// Account attestations (spec section 7.8.1): the hub saying which upstream account signed
// in. Same keys and clock. The audience is the OAuth client it was issued to.
const ATTEST_OUT = join(dirname(OUT), "attestations.json");
const CLIENT = "app";
const PUBLIC = "urn:kith:public";
const attHeader = { typ: "kith-account+jwt", alg: "EdDSA", kid: "k1" };
const att = {
  iss: ISSUER, aud: CLIENT, sub: "did:kith:ada", iat: NOW - 10, exp: NOW + 890, jti: "att-1",
  provider: "facebook", provider_iss: "https://www.facebook.com", account: "1029384756", verified_at: NOW - 30,
};
const attWithout = (k) => Object.fromEntries(Object.entries(att).filter(([name]) => name !== k));
const attExpect = { sub: att.sub, provider: att.provider, provider_iss: att.provider_iss, account: att.account, verified_at: att.verified_at, jti: att.jti };
const attGood = mint(att, attHeader);
const [ah0, ap0, as0] = attGood.split(".");

const attestations = [
  { name: "a good attestation", token: attGood, valid: true, claims: attExpect },
  { name: "typ application/kith-account+jwt is the same type", token: mint(att, { ...attHeader, typ: "application/kith-account+jwt" }), valid: true, claims: attExpect },
  { name: "typ in upper case", token: mint(att, { ...attHeader, typ: "KITH-ACCOUNT+JWT" }), valid: true, claims: attExpect },
  { name: "expired 59 s ago, inside the leeway", token: mint({ ...att, exp: NOW - 59 }, attHeader), valid: true, claims: attExpect },
  { name: "expired 60 s ago", token: mint({ ...att, exp: NOW - 60 }, attHeader), valid: false },
  { name: "issued 61 s from now", token: mint({ ...att, iat: NOW + 61 }, attHeader), valid: false },
  { name: "verified 60 s from now, inside the leeway", token: mint({ ...att, verified_at: NOW + 60 }, attHeader), valid: true, claims: { ...attExpect, verified_at: NOW + 60 } },
  { name: "verified 61 s from now", token: mint({ ...att, verified_at: NOW + 61 }, attHeader), valid: false },
  ...["iss", "aud", "sub", "iat", "exp", "jti", "provider", "provider_iss", "account", "verified_at"].map((k) => ({ name: `no ${k}`, token: mint(attWithout(k), attHeader), valid: false })),
  ...["sub", "jti", "provider", "provider_iss", "account"].map((k) => ({ name: `empty ${k}`, token: mint({ ...att, [k]: "" }, attHeader), valid: false })),
  { name: "account is not a string", token: mint({ ...att, account: 1029384756 }, attHeader), valid: false },
  { name: "verified_at is not a number", token: mint({ ...att, verified_at: "yesterday" }, attHeader), valid: false },
  { name: "another issuer", token: mint({ ...att, iss: "https://evil.example" }, attHeader), valid: false },
  { name: "another client", token: mint({ ...att, aud: "other" }, attHeader), valid: false },
  { name: "audience in a list", token: mint({ ...att, aud: [CLIENT] }, attHeader), valid: false },
  { name: "an access token, even with every attestation claim", token: mint(att, header), valid: false },
  { name: "typ JWT, the way an ID token is typed", token: mint(att, { ...attHeader, typ: "JWT" }), valid: false },
  { name: "no typ", token: mint(att, { alg: "EdDSA", kid: "k1" }), valid: false },
  { name: "alg none, no signature", token: `${enc({ ...attHeader, alg: "none" })}.${ap0}.`, valid: false },
  { name: "alg HS256 over the same input", token: `${enc({ ...attHeader, alg: "HS256" })}.${ap0}.${as0}`, valid: false },
  { name: "a kid the JWKS does not have", token: mint(att, { ...attHeader, kid: "k2" }), valid: false },
  { name: "no kid", token: mint(att, { typ: attHeader.typ, alg: "EdDSA" }), valid: false },
  { name: "signed by another key under the right kid", token: mint(att, attHeader, stranger), valid: false },
  { name: "another account swapped in after signing", token: `${ah0}.${enc({ ...att, account: "1" })}.${as0}`, valid: false },
  // Verified contacts (spec section 7.8.2): the hub checked a code itself, so it is the provider.
  ...[
    ["an email address the hub verified", { provider: "email", account: "mailto:ada@example.com" }],
    ["a phone number the hub verified", { provider: "phone", account: "tel:+15555550100" }],
  ].map(([name, c]) => {
    const claims = { ...att, ...c, provider_iss: ISSUER, jti: "att-c" };
    return { name, token: mint(claims, attHeader), valid: true, claims: { ...attExpect, ...c, provider_iss: ISSUER, jti: "att-c" } };
  }),
  // A public lookup's answer: anyone may check it, with the audience urn:kith:public.
  (() => {
    const pub = { ...att, aud: PUBLIC, provider: "email", provider_iss: ISSUER, account: "mailto:ada@example.com", jti: "att-p" };
    return { name: "a public attestation, checked as public", audience: PUBLIC, token: mint(pub, attHeader), valid: true, claims: { ...attExpect, provider: "email", provider_iss: ISSUER, account: pub.account, jti: "att-p" } };
  })(),
  { name: "a public attestation is not an app's", token: mint({ ...att, aud: PUBLIC }, attHeader), valid: false },
  { name: "an app's attestation is not public", audience: PUBLIC, token: attGood, valid: false },
];

writeFileSync(
  ATTEST_OUT,
  JSON.stringify(
    {
      description:
        "Account attestation vectors (spec 7.8.1, 7.8.2). Verify `token` against `jwks` as of `now` for `issuer` and `audience` (the client id; a case's own `audience` replaces it), with `leeway` seconds of clock tolerance. Accept if and only if `valid`; for accepted tokens, `claims` are values the verifier must return.",
      now: NOW,
      leeway: LEEWAY,
      issuer: ISSUER,
      audience: CLIENT,
      jwks: { keys: [jwk] },
      cases: attestations,
    },
    null,
    2,
  ) + "\n",
);
console.log(`${attestations.length} cases (${attestations.filter((c) => c.valid).length} valid) -> ${ATTEST_OUT}`);
