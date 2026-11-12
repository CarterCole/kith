# Changelog

Kith is a draft. The format will change until v1, so entries record what changed in
behaviour, not a promise about compatibility. Versions follow the workspace version in
`Cargo.toml`.

## Unreleased

### Added

- **Joining devices** (spec §7.13). `kith device join --hub …` makes this machine's key
  (in the Secure Enclave when there is one) and prints a link and a QR code; a browser
  signed in to the hub claims it, and the terminal checks the event the hub built before
  it signs. The account page's "Add a device" shows a QR code for a phone, which makes
  its own passkey there. Manage signers approve in the browser, or with
  `kith device approve`, until the manage policy is met; then the hub appends the event.
- **`kith manage set`** replaces the manage policy with a rotation signed by the recovery
  key from browser sign-up (its file, or `--recovery-words`), for example 2 of a passkey,
  a Mac and a phone, and saves a new recovery key in the same format. `kith manage show`
  lists the signers by device name.
- **Browser sign-up** (spec §7.11, `--signup`): a passkey and a recovery key the browser
  makes, or derives from secret words, create an identity the hub holds no key for. A
  provider account that no identity links can sign up the same way and is linked to it.
- **Work** (spec §7.12): `kith work` and the sign-up page spend compute on an identity,
  and tokens carry the best proof as `work`.
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
- Spec §7.2.1 drafts how an app asks to be admitted and waits for the operator.

### Changed

- **A bundle file that fails to load leaves the last good one in force** (spec §7.9).
  Before, a half-written or invalid file made every sign-in fail until it was fixed.
  The hub logs the error and reports it in the stats; at startup a bad file still stops
  it. A file is now read again when its length changes as well as its modification time.

## 0.2.0 (2026-11-08)

### Security (November 2026 review)

Each fix has a test that failed before it. The findings still open are listed under
"Known gaps" in [`docs/roadmap.md`](docs/roadmap.md).

- **Challenge login.** The CLI signs only a well-formed sign-in challenge for its own DID
  (spec §2.3). Before, a hub could send a grant's signing input as the "challenge" and
  get a device-signed grant for a key it held. Grants now live at most 24 hours (§3.2).
- **Delegated token exchange honours the org's revocations.** The delegator's revoked
  device, and a revoked actor or actor device, are refused, and the token's `dev` names
  the delegator's device (§3.4). Followers deny a revoked actor (`revoked:actor`).
- **`member` revocations need the manage policy**, and a follower allows only what is
  also allowed with every membership in place (§8.7, §8.9). Before, a revoke-only key
  could drop someone from `Group::suspended` and turn off a forbid on it.

### Added

- **Role provenance** (spec §10.8). In org mode a token's `org` and `pol` claims name the
  policy its `groups` and `roles` came from, and a resource server configured with an
  org ignores memberships from any other org or from a bundle file (Rust, JS, Python,
  `tokens.json` vectors). `kith policy why` shows who signed the `policy_root` event
  behind a membership, and why.
- `kith passkey enroll --qr` carries the enrollment link to a phone as a QR code.
- Delegated administration is specified as a draft (spec §10); grants and delegated
  roots are not implemented yet.
- Number text for Cedar strings: a formatter and conversion vectors (spec §4.2).

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
