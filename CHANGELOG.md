# Changelog

Kith is a draft. The format will change until v1, so entries record what changed in
behaviour, not a promise about compatibility. Versions follow the workspace version in
`Cargo.toml`.

## Unreleased

### Added

- **Account attestations.** With the `linked_account` scope, an upstream login returns
  `account_attestation`, a hub-signed JWT naming the account that signed in (spec
  §7.8.1), with verifiers in Rust, JS and Python and shared vectors.
- **Facebook as an upstream provider**: `Upstream::facebook`, and `token_request: "get"`
  for its code exchange. Not yet run against Facebook itself.
- **Verified contacts** (spec §7.8.2). `kith contact add` and `confirm` prove an email
  address or phone number with a six-digit code. Contacts are private by default and go
  to an app only with its `email` or `phone` scope, as claims and as hub-signed
  `contact_attestations`. `kith contact publish` makes the hub answer
  `GET /v1/contacts/lookup` for one, with an attestation for `urn:kith:public`.
  Verifications go stale after 365 days (email) or 90 days (phone) until checked again,
  and whoever proves an address last holds it. Codes are sent through Amazon SES and AWS
  End User Messaging SMS (`--features aws`), or to an outbox file. New `phone` scope.
- `GET /login` redirects to the account page, `/whoami`, instead of answering 404.
- **`kith bundle check`** (spec §4.1.1) refuses a bundle file that a loader would quietly
  misread: a key written twice, an unknown member such as `"rols"`, a `group:` or `role:`
  member that names no set, or a policy or rule that does not parse. It warns about
  likely mistakes. `kith_core::bundle::check` is the library form.
- **`kith bundle edit`**: a local browser editor for a bundle file kept in git, with
  organizations (`org:` groups), roles by site, groups, people and raw JSON. It shows
  each person's groups and roles as the draft stands, saves only a file that passes the
  check, and renames it into place. Loopback only, behind a per-run token.
- **`GET /v1/admin/identities`** lists every identity with its contacts, devices, last
  sign-in and standing groups and roles. `GET /v1/admin/stats` gains `bundle`: which
  bundle file is in force, and why a newer one is not.

### Changed

- **A bundle file that fails to load leaves the last good one in force** (spec §7.9).
  Before, a half-written or invalid file made every sign-in fail until it was fixed.
  The hub logs the error and reports it in the stats; at startup a bad file still stops
  it. A file is now read again when its length changes as well as its modification time.

An audit of all three implementations, and the fixes that came out of it. Each fix has a
test that failed before it. The audit items that are still open are listed in
[`docs/roadmap.md`](docs/roadmap.md#still-open-from-the-october-2026-audit).

### Security

- **Devices now act within their capabilities.** A device without the `session` cap could
  still log in by signature or passkey, sign a grant, and mint a delegation. That
  included the hub's revoke-only relay, which could sign in as the organization.
- **`device` revocations are enforced.** The CLI issued them and nothing read them.
- **TOTP.** Parallel guesses were not all counted and one code could be accepted twice.
  Resetting is now possible, and sign-ins that rested on the authenticator alone end
  with it. Attempts are limited per address everywhere a code is checked.
- **OIDC redirect URIs.** `HTTP://evil.example/cb` passed as a private-use scheme, script
  schemes were accepted, and `post_logout_redirect_uris` were not validated at all.
- **Access tokens.** The JS verifier accepted tokens with no `exp`, `iat`, `sub`, `jti` or
  `aal` and a future `iat`; the Python verifier crashed on a token without `jti` or
  `aal`. Rust, JS and Python now agree, and run the same vectors.
- **Passkey grants** are worth what the assertion proved: without user verification they
  are AAL 1, and they must be for the device's `rp_id`.
- **Alias proofs** expire. **A signer** can no longer fill two seats of a threshold policy.
- **Claim times** saturate: an extreme `iat` or `exp` could panic, or wrap around the
  session-lifetime limit in a release build.
- **Malformed input** is an error, never a crash or a hang. A ratchet revision of 2^63 in
  an envelope overflowed the stack and aborted the process; a Merkle map 65 levels deep
  panicked; a diamond of shared children took exponential time; non-ASCII in a hex
  string or a timestamp panicked. A policy DAG whose indexes were not lists loaded as
  "no policies", forbids included. The file block store accepted `../` as a name.
- `kith passkey enroll` shows a fingerprint to compare with the enrollment page and
  asks before it signs.

### Changed

- **Signing out at the hub ends that session's refresh tokens.** The admin API already did.
  Before, they stayed valid after RP-initiated logout.
- Python: ids with non-ASCII characters work (they were denied), and an integral float
  (`2.0`) is an integer, as in JS. Rust now treats it that way as well.
- A token is expired once `exp` plus the 60 s leeway is reached (RFC 7519), not one second
  later.
- `verify_alias_proof` takes the time and a maximum age. `DeviceSigner::Passkey` has a
  `user_verified` field.

### Added

- `kith totp reset`, `DELETE /v1/totp`, and `DELETE /v1/admin/identities/{did}/totp`.
- `kith alias verify --nonce --max-age`, `kith passkey enroll --yes`.
- `introspection: "authenticated"` for the GraphQL middleware in JS and Python;
  `__typename` always works (the Python middleware failed on it).
- `spec/test-vectors/tokens.json` (and `scripts/token-vectors.mjs`), new cases in
  `authz.json`, and device revocations in `policy-dag.json`. The Rust generator now
  asserts the decisions it writes.
- CI on every push and pull request, `LICENSE` (Apache-2.0), `NOTICE`, `SECURITY.md`,
  `CLAUDE.md`. Release workflow actions are pinned to commits, and the JS and Python
  package versions are checked against the tag.

## 0.1.0 (2026-10-20)

The first release, as a draft specification with a reference implementation:

- Identity: `did:kith` key event logs with nested threshold signer policies,
  pre-rotation, devices, public and private aliases, and recovery by a TOTP-gated
  co-signer.
- Signers: Ed25519, P-256, secp256k1, passkeys, Ethereum accounts, and SSH keys
  (`SSHSIG`). Keys in the macOS keychain and Secure Enclave.
- Login: session chains, challenge login, TOTP step-up, delegation (RFC 8693).
- Authorization: Cedar with dynamic groups and roles; GraphQL enforcement for graphql-js
  and graphql-core; crypto-enforced sharing with skip ratchets.
- A hub that is an OpenID Connect provider (code with PKCE, passkey login, SSO, consent,
  dynamic registration, logout notices, encrypted ID tokens, upstream providers),
  durable state in SQLite, rate limits and an admin API.
- Policies as a content-addressed DAG with provable slices; pushed, hash-chained
  revocations with beacon-backed freshness (drand, NIST 2.0) and OpenTimestamps
  anchoring.
- Alias resolution through WebFinger, DNS and `did:web` back-links, and local names.
- A Homebrew formula and a release workflow.
