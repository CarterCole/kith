# Kith protocol specification (draft 0)

Kith is a **spec, a protocol and a set of implementations**, the way Google Wave was.
The spec defines data formats and verification rules. The protocol defines how
parties exchange them. The implementations in this repo (Rust core, hub and CLI, a
JS/TS package and a Python package) are reference implementations. They must not be
the only way to read the spec.

> Status: draft for discussion. "Kith" is a working name. Formats will change until v1.

## The model in one picture

```
                    ┌───────────────────────────────────────────────────────────┐
  identity          │ did:kith:…   = hash of the genesis event of a key event log │
                    │ L0 rotation policy (pre-committed, cold: 2-of-3 recovery)   │
                    │ L1 manage policy   (e.g. Ledger OR 2-of-3 passkeys)         │
                    └───────────────┬───────────────────────────────────────────┘
                                    │ add_device / revoke_device (signed events)
  devices           ┌───────────────▼──────────────┐   passkey · Secure Enclave · YubiKey
                    │ L2 device keys (+ X25519)     │   software key · wallet
                    └───────────────┬──────────────┘
                                    │ grant JWT (device signs session key)
  sessions          ┌───────────────▼──────────────┐
                    │ L3 session keys (ephemeral)   │── delegation JWT ──▶ another identity
                    └───────────────┬──────────────┘
                                    │ RFC 8693 token exchange (or challenge login:
                                    │ signature / passkey / TOTP)
  hub (optional)    ┌───────────────▼──────────────┐
                    │ access token (RFC 9068 JWT)   │  sub, groups, roles, attrs,
                    │ signed by hub, JWKS published │  aal, amr, act, cap
                    └───────────────┬──────────────┘
                                    │ Bearer
  resource servers  ┌───────────────▼──────────────┐
                    │ Cedar policies + GraphQL /    │  root-field, field-level and
                    │ HTTP middleware (JS, Py, Rust)│  row-level decisions
                    └──────────────────────────────┘
  data (optional)     vault: skip-ratchet group keys sealed to device X25519 keys
```

## Documents

| # | Document | Covers |
|---|----------|--------|
| 1 | [Identity](01-identity.md) | `did:kith`, key event log, signers, signer policies, authority levels, rotation, recovery |
| 2 | [Authentication](02-authentication.md) | session chains, challenge login, passkeys, wallets, TOTP, assurance levels, TOTP co-signer |
| 3 | [Tokens & delegation](03-tokens-and-delegation.md) | grant, session and delegation JWTs, token exchange, access token claims |
| 4 | [Authorization](04-authorization.md) | policy bundles, explicit/nested/dynamic groups, roles, Cedar mapping, GraphQL mapping |
| 5 | [Aliases](05-aliases.md) | public and private aliases, proving the link on demand |
| 6 | [Vault](06-vault.md) | crypto-enforced access: skip ratchets, WNFS relationship |
| 7 | [OpenID Connect](07-oidc.md) | "Sign in with Kith": code + PKCE, passkey login page, SSO, step-up, pairwise subjects, browser passkey enrollment |
| 8 | [Policy DAG, revocations, freshness](08-policy-dag.md) | bundles as content-addressed blocks, provable slices, org policy roots, signed revocation chains, beacon heartbeats (drand, NIST 2.0), degraded mode, OpenTimestamps anchoring |
| — | [Test vectors](test-vectors/) | conformance vectors every implementation must pass |

## Conventions

- **Canonical JSON** is JSON with object keys sorted by UTF-16 code unit, no whitespace,
  and integers only. Floats are forbidden. It is a subset of RFC 8785 (JCS). Every hash
  and signature over JSON uses it.
- **base64url** means unpadded base64url. **Digest** means `base64url(SHA-256(canonical JSON))`.
- **Signer identifiers**:
  - `did:key` for raw keys: Ed25519 `z6Mk…`, P-256 `zDn…`, secp256k1 `zQ3s…`.
  - CAIP-10 account ids for chain accounts: `eip155:1:0x…` and `bip122:<genesis>:<addr>`.
- MUST, SHOULD and MAY are used as in RFC 2119.

## Conformance

An implementation claims one or more profiles:

| Profile | Must implement |
|---------|----------------|
| **Resource server** | Verify access tokens against a JWKS (§3.5). Pass `test-vectors/authz.json` (§4). |
| **Slice reader** | The above, plus load slices and follow revocations (§8). Pass `test-vectors/policy-dag.json` and `test-vectors/beacons.json`. |
| **Verifier** | The above, plus KEL replay (§1.6), session-chain verification (§3.3), and alias proofs (§5). |
| **Hub** | The above, plus the endpoints of §2, §3.4 and §7. |
| **Wallet / agent** | Create and sign KEL events, grants, session tokens and delegations. |

Current implementations:

| Implementation | Profile |
|----------------|---------|
| Rust (`kith-core`, `kith-hub`, `kith` CLI) | All five, plus DAG building and OpenTimestamps (`test-vectors/ots.json`). |
| JS (`@kith/auth`) | Resource server and slice reader (Ed25519 revokers only), plus a browser client for passkey and wallet login. |
| Python (`kith-auth`) | Resource server. |
