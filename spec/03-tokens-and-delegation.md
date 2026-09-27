# 3. Tokens and delegation

There are two tiers of tokens:
- **Chain tokens** are signed by the identity's own keys. They are verifiable by anyone
  who can resolve the KEL. They work without a hub and are how you delegate.
- **Access tokens** are signed by a hub and are ordinary RFC 9068 JWTs. Every
  framework already knows how to verify one, so resource servers only need a JWKS URL.

## 3.1 JWS algorithms

`EdDSA` (Ed25519), `ES256`, and `ES256K` are standard. `WebAuthn` is Kith-specific:
- The signing input is the usual `b64u(header).b64u(payload)`.
- The signature segment is
  `b64u(JSON{authenticator_data, client_data_json, sig})`.
- The WebAuthn challenge is `SHA-256(signing input)`.

This lets a passkey sign a grant directly.

## 3.2 Grant (device → session key)

```
header  { "typ": "kith-grant+jwt", "alg": "EdDSA" | "ES256" | "WebAuthn", "kid": "<did>#<device id>" }
payload { "iss": "<did>", "dev": "<device id>", "cnf": { "jwk": <session public key> },
          "aal": 2, "iat": …, "exp": …, "jti": … }
```

The grant is signed by the device key named in `dev`. Its lifetime is typically 12
hours. That limits how long a stolen session key is useful, while device revocation
stays immediate.

## 3.3 Session and delegation tokens (session key → anyone)

The session key signs both. The grant rides in the header:

```
header { "typ": "kith-session+jwt" | "kith-delegation+jwt", "alg": "EdDSA", "kith_grant": "<grant JWT>" }
```

| typ | Payload | Lifetime |
|-----|---------|----------|
| session | `iss`, `aud`, `iat`, `exp`, `jti` (+ extra claims) | ≤ 300 s, single use |
| delegation | `iss` (delegator), `sub` (delegate DID), `aud`, `cap[]`, `iat`, `exp`, `jti` | ≤ the grant's `exp` |

**Chain verification** (normative):
1. Decode the outer token. `typ` must be the expected type, and there must be a
   `kith_grant`.
2. Decode the grant. Its `typ` must be `kith-grant+jwt`.
3. Resolve the key state for `grant.iss`. `grant.dev` must be an **active** device.
4. Verify the grant signature with the device key. Check `iat` and `exp` with 60 s leeway.
5. Verify the outer signature with `grant.cnf.jwk`. Check the times. The token must not
   outlive the grant, and `iss` must equal `grant.iss`.
6. For sessions:
   - `aud` must match;
   - the device needs the `session` cap;
   - the verifier MUST reject a `jti` it has already seen.
7. The effective aal is `min(grant.aal, device.aal)`.

**Capabilities** have the form `{ "action": "Query.invoices" | "Invoice.*" | "*",
"resource": "Invoice::\"inv_1\"" | "*" }`. The `*` suffix is a prefix glob.

Delegation **only attenuates**. A delegated request is allowed only if two things are
true:
- the delegator's own policies allow it (§4);
- a capability matches the action and resource.

Policies can also see `context.actor` and refuse specific delegated actions, for
example "no mutations through delegation".

Re-delegation (a chain of delegations, as in UCAN) is future work. The planned design
has each hop include its parent and narrow its `cap`.

## 3.4 Token exchange (RFC 8693)

`POST /v1/oauth/token`, `application/x-www-form-urlencoded`:

| Parameter | Session login | Delegated login |
|-----------|---------------|-----------------|
| `grant_type` | `urn:ietf:params:oauth:grant-type:token-exchange` | same |
| `subject_token` | session token | delegation token |
| `subject_token_type` | `urn:kith:params:oauth:token-type:session` | `urn:kith:params:oauth:token-type:delegation` |
| `actor_token` | — | the delegate's session token |
| `audience` | resource server id, e.g. `api://invoices` | same |
| `totp` (Kith extension) | optional step-up code | — |

For a delegated login, `delegation.sub` must equal the actor's DID. The resulting token
has these claims:
- `sub` is the delegator.
- `act.sub` is the actor. Nested `act` claims record earlier actors, per RFC 8693.
- `cap` is the delegated capabilities.
- `aal` is the actor's.

## 3.5 Access token (RFC 9068 profile)

```json
{
  "typ": "at+jwt", "alg": "EdDSA", "kid": "<RFC 7638 thumbprint>"
}
{
  "iss": "https://hub.example", "aud": "api://invoices", "sub": "did:kith:…",
  "iat": …, "exp": … (15 min), "jti": …,
  "groups": ["finance", "staff", "strong-auth"],
  "roles": ["billing-admin", "billing-reader"],
  "attrs": { "email": "ada@acme.test", "department": "finance", "aal": 2, "aliases": [] },
  "aal": 2, "amr": ["swk", "otp", "mfa"], "dev": "dev_…",
  "act": { "sub": "did:kith:…actor" }?, "cap": [ … ]?, "cnf": { "jkt": … }?
}
```

A resource server MUST check:
- `typ` is `at+jwt` and `alg` is `EdDSA`;
- the signature against the hub JWKS;
- `iss` and `aud`;
- `exp` and `iat` (60 s leeway).

It then builds the principal from these fields:
- `id` = `sub`;
- `attrs` = `attrs` plus `aal` and `amr`;
- `groups`, `roles`;
- `actor` = `act.sub`;
- `caps` = `cap`.

**Planned:**
- DPoP (RFC 9449) binding, with `cnf.jkt` set to the session key thumbprint.
- Per-audience claim release, so a token only carries the attributes and groups that
  audience's policies reference.
