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

## Interoperability

Kith reuses an existing standard wherever one fits. Nothing here asks you to replace
the keys, tools or services you already use. An identity is its key log, which anyone
can mirror and verify (§1.8), so moving it elsewhere never needs anything a hub holds.

1. **Bring the keys you have.** A signer is a public key plus a signature format. It is
   not a Kith-specific wallet. Passkeys, Ethereum accounts, hardware tokens, OpenPGP
   (GPG) keys and SSH keys can all be signers (§1.3). The identity does not care where
   a key lives.
2. **Standard formats on the wire.**

   | Need | Standard |
   |------|----------|
   | Raw keys | `did:key` multikeys, CAIP-10 account ids |
   | Identity documents | W3C DID Core, `Multikey` verification methods (§1.7) |
   | Tokens | JOSE and JWT, RFC 9068 access tokens, RFC 8693 token exchange |
   | Sign-in | OpenID Connect (§7), WebAuthn |
   | Signatures | EIP-191, EIP-1271, ERC-6492, OpenSSH `SSHSIG`; draft: OpenPGP |
   | Policy | Cedar |
   | Storage | DAG-JSON and CIDv1, served by any IPFS trustless gateway (§8) |
   | Time | drand, NIST beacon 2.0, OpenTimestamps `.ots` files (§8) |

3. **Standard tools can check the standard parts.** An `SSHSIG` signer's signatures
   come from `ssh-keygen` and check with `ssh-keygen -Y check-novalidate -n kith`; the
   vectors record its verdict (§1.3.1). Anchors are ordinary `.ots` files (§8.10), and
   policy blocks have the same CIDs that `@ipld/dag-json` computes, so an IPFS client
   can fetch them from a hub's `/ipfs/{cid}` route (§8.11).
4. **Kith-specific formats are few and listed.** They are the `did:kith` method and its
   log format (§1), the `WebAuthn` JWS algorithm and the `kith-*+jwt` token types (§3),
   and the policy DAG layout (§8). Each has conformance vectors, and none is the only
   way to read the spec.
5. **Say what a key is for.** Keys are annotated with the primitive and the purposes
   they may be used for, using DID Core's vocabulary, so any resolver can read them
   (§1.3.2, draft).

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
