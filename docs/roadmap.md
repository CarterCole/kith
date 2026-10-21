# Roadmap, open questions and known gaps

## What works today (verified by `scripts/test-all.sh`, `scripts/cli-flows.sh`, `scripts/demo.sh`)

- **Identity.** A `did:kith` identity from a KEL: nested threshold signer policies,
  pre-rotation, device add and revoke with proof of possession, public and private
  aliases, fork (duplicity) rejection, DID documents.
- **Names for roots** ([spec §5.1.1–5.1.2](../spec/05-aliases.md)). `kith resolve`
  follows a public alias's WebFinger, DNS TXT or did:web back-link to a root and
  accepts it only if the root's KEL links the alias back and no other root passes
  too (two is an error, never a pick). `kith name add` pins the result as a local
  petname; names work wherever a DID does, and `kith name check` re-resolves the book
  and reports names that moved, went ambiguous or stopped resolving. Private alias
  labels are unique. `scripts/cli-flows.sh` serves a WebFinger back-link and checks
  that it alone does not resolve, that two roots linking one alias is ambiguous, and
  that a re-pointed alias shows up as `moved`.
- **Signers.** Ed25519, P-256, secp256k1, passkeys (WebAuthn), Ethereum EOAs (EIP-191).
  SSH keys (`SSHSIG`, Ed25519 and P-256) in the Rust core, checked against vectors that
  real `ssh-keygen` signed (`scripts/sshsig-vectors.mjs`).
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
- **Keys at rest in the CLI** ([spec §1.3.3](../spec/01-identity.md)). On macOS every
  private key is a login-keychain item keyed by DID and key id, and this device's key
  is a P-256 key in the Secure Enclave that signs inside the chip, enrolled as a
  `hardware` device. `kith init --keystore keychain|file`, `kith keys list`, `kith keys
  migrate` (file → keychain), `kith keys forget`. Linux keeps the plaintext file (0600).
  Checked by `scripts/cli-flows.sh` (Ada's whole flow runs from the keychain and the
  Enclave; Bob migrates mid-run) and Rust tests that round-trip a key through the
  keychain and through the Enclave's handle.
- **Policy DAG, revocations, freshness** ([spec §8](../spec/08-policy-dag.md)).
  - Bundles become DAG-JSON blocks. The CIDs match `@ipld/dag-json` + `multiformats`.
  - A slice (one action, or one principal) decides exactly like the full bundle for
    every conformance vector. Withholding any block fails the load.
  - Org `policy_root` events and revoke-only devices.
  - Hash-chained revocation entries with gap, fork and forgery detection.
  - Heartbeats with drand quicknet (BLS12-381) and NIST 2.0 (RSA) beacons. Tested with
    real rounds and pulses, in Rust and JS.
  - Fresh, degraded and stale levels, `context.kith.sync_age` for per-action
    budgets, and a monotonic clock.
  - Hub tokens are issued from the DAG with revocations applied.
  - OpenTimestamps: parse and write `.ots` byte-exactly, Bitcoin header verification,
    calendar stamp and upgrade.
- **OpenID Connect provider** ([spec §7](../spec/07-oidc.md)).
  - Code + PKCE, a username-less passkey login page, wallet sign-in, TOTP step-up.
  - SSO cookie, `prompt`, `max_age`, `acr_values`.
  - RS256/EdDSA ID tokens, userinfo, rotating refresh tokens that die with the device,
    pairwise subjects, logout.
  - A consent page with remembered grants, `prompt=consent`.
  - Dynamic client registration behind a registration token.
  - Back- and front-channel logout notices.
  - ID tokens encrypted to the client (`RSA-OAEP-256`, `ECDH-ES`; checked against `jose`).
  - Browser passkey enrollment brokered by the hub (`kith passkey enroll`).
  - Upstream OIDC providers as a login factor, starting with Telegram Login
    ([spec §7.8](../spec/07-oidc.md)). Tested against a stand-in provider, not yet
    against Telegram itself.
  - Upstream attributes from the ID token and UserInfo, behind a per-provider
    allowlist.
  - Verified in headless Chrome with a virtual authenticator against `openid-client`.
- **Hub state and operations** ([spec §7.9–7.10](../spec/07-oidc.md)).
  - One SQLite file holds sessions, codes, refresh tokens, pending sign-in requests,
    consent, registered clients, TOTP enrollments and lockouts, co-signer keys, the
    replay cache and rate-limit counters. A restart signs nobody out. Bearer secrets
    are stored hashed.
  - Rate limits on `/oauth/login` and `/oauth/register` per client address, with
    `--behind-proxy` for the address a reverse proxy appends.
  - An admin API (admin token, or any identity in the `hub-admin` role): list and end
    sessions, sign an identity out everywhere, list and delete registered clients,
    list and withdraw consent.

## Known gaps in the reference code (not production ready)

- **Keys at rest.** The macOS keychain and the Secure Enclave are done
  ([spec §1.3.3](../spec/01-identity.md)). Still to do:
  - Linux: a Secret Service (libsecret) backend, and a TPM for the device key. Today
    `--keystore keychain` there warns and writes the plaintext file;
  - YubiKey PIV / FIDO;
  - hardware wallets for manage keys;
  - an Enclave key for a device enrolled later: `kith device add` makes portable
    software keys, and `kith keys migrate` cannot move an existing key into the chip
    (re-enroll the device instead);
  - `kith init --touch-id` (a Touch ID prompt per signature, enrolled at AAL3) is
    implemented but not exercised by the scripts, which cannot answer the prompt;
  - keychain items are tied to the binary that created them, so a rebuilt or upgraded
    `kith` gets one macOS prompt per item ("Always Allow" ends it). A signed binary with
    a keychain access group would avoid that.
- **Hub operations.** The hub speaks plain HTTP (terminate TLS in front of it). There
  is no audit log, and the admin API only lists and deletes: no editing of clients,
  no RFC 7592. Login challenges and passkey enrollments in progress are still in
  memory (the page retries after a restart). The bundle is a hot-reloaded file, and
  there is no rate limit on anything but login, registration and TOTP.
- **Audiences.** The hub mints tokens for any `audience`. It needs a registry of
  resource servers and per-audience claim release (privacy, and smaller tokens).
- **Signers still to do:**
  - EIP-1271 needs a `ChainVerifier` implementation (JSON-RPC, pinned block, ERC-6492);
  - BIP-322;
  - SSH signatures, the rest: `kith` signing through `ssh-keygen` or `ssh-agent`
    (today you run `ssh-keygen -Y sign -n kith` yourself), JS and Python verifiers,
    and FIDO `sk-` keys.
  - OpenPGP signatures. Specified as a draft ([spec §1.3.1](../spec/01-identity.md)),
    not implemented. It needs a minimal signature-packet parser, which is a larger
    attack surface than `SSHSIG`, and vectors made with real `gpg`.
  - RSA signatures, after the above. Many existing SSH and GPG keys are RSA, so
    "bring the keys you have" is only partly true without it. It is a new key type
    through the KEL, the `did:key` encoding and all three languages; the hub's OIDC
    RSA code is a start.
  - Key purposes (`use`, `alg`) on device keys, and `keyAgreement` in the DID document.
    Specified as a draft ([spec §1.3.2](../spec/01-identity.md)), not implemented.
- **OIDC gaps.** No PAR, no user-facing page to withdraw consent (the admin API
  can), and no open registration. Logout notices are best effort and only sent on
  RP-initiated logout or from the admin API. The consent page is tested in Chrome;
  the front-channel sign-out page is tested in process only. The wallet button on the login page has not been
  tested in a browser (the server path is tested). The Grafana config in §7.9 has not
  been tried against a real Grafana.
- **Co-signer safety.** A time delay plus device notification before co-signing
  `rotate`, as did:plc does with its 72-hour window.
- **Other.**
  - DPoP binding of access tokens to session keys.
  - Multi-hop delegation (UCAN 1.0 or Biscuit).
  - Session and access token revocation before expiry exists as `token {jti}`
    revocations (§8). The GraphQL middleware doesn't consult a revocation follower yet.
  - Cedar schemas and audience namespaces, for validation and policy analysis.
    Specified as a draft ([spec §9](../spec/09-schemas.md)), not implemented.
  - Partial-evaluation pushdown of row-level filters into SQL.
  - The vault uses an HPKE-shaped construction; move to RFC 9180 HPKE.

- **Policy DAG follow-ups.**
  - Python slice reader.
  - JS revokers other than Ed25519: P-256, and WebAuthn passkeys as revoke devices.
  - An `ipfs dag import` CAR export instead of a directory of blocks.
  - Encrypting the `members` and `directory` maps with the vault, for public DAGs.
  - Witnesses for heartbeats. Several hubs co-signing would stop one relay from
    silently withholding them.
  - Wiring `HubFeed` into `kithGraphQL`.
  - `kith anchor stamp` follows the reference client, but has not been run against
    the public calendars yet (a live stamp publishes a hash to them).
- **NIST beacon signatures.** Since 2026-09-03 (chain 2, pulse 1925734), NIST's pulses
  are signed with a 4096-bit key. The certificate NIST publishes for their
  `certificateId` holds a 2048-bit key, so they fail verification, and Kith rejects
  them (tested). Older NIST pulses and Brazil's current pulses verify, and drand is the
  default. Worth reporting to NIST (beacon@nist.gov).

- **Alias back-links.** Only WebFinger, DNS TXT and did:web are followed. GitHub
  (gist), ENS, wallet signatures and `at://` are listed in §5.1 but not resolvable.
  DNS answers are not DNSSEC-validated. `kith name check` is a command you run, not a
  watcher, and an `alias list` on a home made before labels were unique can still show
  two aliases with one label (`prove` uses the first).

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
| ~~1b~~ | ~~Durable hub state (SQLite): sessions, refresh tokens, clients; an admin API; rate limits~~ | Done ([spec §7.9–7.10](../spec/07-oidc.md)) |
| ~~2~~ | ~~Secure key storage in the CLI (keychain and Secure Enclave)~~ plus a mobile wallet app shell | Key storage done ([spec §1.3.3](../spec/01-identity.md)); the wallet app shell remains |
| 3 | EIP-1271 ChainVerifier and a Safe/Coinbase Smart Wallet manage policy | "A signer could be an Ethereum contract" |
| 4 | Digital Credentials API attribute source, then Self/ZKPassport proofs | Government-ID-backed attributes ([passports](passports.md)) |
| 5 | Cedar partial evaluation to SQL/Prisma filters; DataLoader-friendly row checks | "Lock down the query" at scale |
| 6 | rs-wnfs integration, with `did:kith` as the WNFS agent | Encrypted shared data for groups |
| 7 | Witnesses and optional chain anchoring. OpenTimestamps anchoring of policy roots and revocations is done (§8.10); KEL witnesses and heartbeat co-signing remain | Third-party duplicity detection and public timestamps |
