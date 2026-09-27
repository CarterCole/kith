# Roadmap, open questions and known gaps

## What works today (verified by `scripts/test-all.sh`, `scripts/cli-flows.sh`, `scripts/demo.sh`)

- **Identity.** A `did:kith` identity from a KEL: nested threshold signer policies,
  pre-rotation, device add and revoke with proof of possession, public and private
  aliases, fork (duplicity) rejection, DID documents.
- **Signers.** Ed25519, P-256, secp256k1, passkeys (WebAuthn), Ethereum EOAs (EIP-191).
- **Login.** Session-chain login, SIWE-style challenge login (device key or passkey),
  TOTP enrollment and step-up, AAL/AMR computation.
- **Recovery.** The TOTP-gated hub co-signer as a rotation signer. The demo recovers an
  identity with one paper key plus TOTP after losing the other keys.
- **Delegation.** RFC 8693 exchange producing `act` and `cap`. Attenuation is enforced
  by every resource server.
- **Authorization.** Cedar policies with explicit, nested and dynamic groups and roles.
  Identical results in Rust, JS and Python, checked against shared vectors.
- **GraphQL.** Root, field and row-level enforcement for graphql-js (Yoga, Apollo) and
  graphql-core (Ariadne, Strawberry, Graphene). Both example APIs return identical
  results.
- **Browser client.** Passkey creation, enrollment and login against a live hub, using a
  WebCrypto authenticator in tests.
- **Vault.** Skip-ratchet group keyrings with join-later, skip-ahead, and re-key, sealed
  to devices' X25519 keys from the KEL.
- **OpenID Connect provider** ([spec §7](../spec/07-oidc.md)).
  - Code + PKCE, a username-less passkey login page, wallet sign-in, TOTP step-up.
  - SSO cookie, `prompt`, `max_age`, `acr_values`.
  - RS256/EdDSA ID tokens, userinfo, rotating refresh tokens that die with the device,
    pairwise subjects, logout.
  - Browser passkey enrollment brokered by the hub (`kith passkey enroll`).
  - Verified in headless Chrome with a virtual authenticator against `openid-client`.

## Known gaps in the reference code (not production ready)

- **Keys at rest.** The CLI stores keys in plaintext JSON (mode 0600). Next steps:
  - OS keychain;
  - Secure Enclave via `security-framework`;
  - TPM;
  - YubiKey PIV / FIDO;
  - hardware wallets for manage keys.
- **Hub durability.** Challenges, replay caches, TOTP lockouts and all OIDC state
  (SSO sessions, codes, refresh tokens) live in memory, so a restart signs everyone out. There
  is no TLS, no rate limiting beyond TOTP, no audit log, and no admin API. The bundle is
  a hot-reloaded file.
- **Audiences.** The hub mints tokens for any `audience`. It needs a registry of
  resource servers and per-audience claim release (privacy, and smaller tokens).
- **Signers still to do:**
  - EIP-1271 needs a `ChainVerifier` implementation (JSON-RPC, pinned block, ERC-6492);
  - BIP-322;
  - SSH signatures.
- **OIDC gaps.** No consent screen, dynamic registration, PAR, back-channel logout, or
  rate limiting on `/oauth/login`. The wallet button on the login page has not been
  tested in a browser (the server path is tested). The Grafana config in §7.8 has not
  been tried against a real Grafana.
- **Co-signer safety.** A time delay plus device notification before co-signing
  `rotate`, as did:plc does with its 72-hour window.
- **Other.**
  - DPoP binding of access tokens to session keys.
  - Multi-hop delegation (UCAN 1.0 or Biscuit).
  - Session and access token revocation before expiry (short TTLs are the only
    mechanism today).
  - Cedar schemas, for validation and policy analysis.
  - Partial-evaluation pushdown of row-level filters into SQL.
  - The vault uses an HPKE-shaped construction; move to RFC 9180 HPKE.

## Open questions (need a decision)

1. **New DID method, or a did:webvh profile?** did:webvh already has pre-rotation,
   witnesses, a ratified spec, and three implementations. Kith's additions are
   wallet/contract signers, nested per-level policies, and first-class devices. These
   could be expressed as a did:webvh extension. Recommendation: prototype the
   extension before v1. Adoption beats novelty.
2. **Is the hub required?** Today resource servers trust hub tokens. The alternative is
   for resource servers to verify chain tokens directly (the `verifier` profile) and
   compute memberships themselves, with no hub. Both work. Deciding which one the SDKs
   default to matters for the "universal" story.
3. **Where do attributes come from, and who can assert them?** Options include a
   directory, verifiable credentials (SD-JWT VC, mdoc), upstream IdPs, and passports.
   Each source needs a trust policy (which issuers, for which attributes).
4. **Name.** "Kith" is a placeholder.

## Suggested next milestones

| # | Milestone | Why |
|---|-----------|-----|
| ~~1~~ | ~~Hub as an OIDC provider and a passkey login page~~ | Done ([spec §7](../spec/07-oidc.md)) |
| 1b | Durable hub state (SQLite): sessions, refresh tokens, clients; an admin API; rate limits | A hub restart shouldn't sign everyone out |
| 2 | Secure key storage in the CLI (keychain and Secure Enclave) plus a mobile wallet app shell | Real devices, not demo keys |
| 3 | EIP-1271 ChainVerifier and a Safe/Coinbase Smart Wallet manage policy | "A signer could be an Ethereum contract" |
| 4 | Digital Credentials API attribute source, then Self/ZKPassport proofs | Government-ID-backed attributes ([passports](passports.md)) |
| 5 | Cedar partial evaluation to SQL/Prisma filters; DataLoader-friendly row checks | "Lock down the query" at scale |
| 6 | rs-wnfs integration, with `did:kith` as the WNFS agent | Encrypted shared data for groups |
| 7 | Witnesses and optional chain anchoring | Third-party duplicity detection and public timestamps |
