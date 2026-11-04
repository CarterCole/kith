# 7. OpenID Connect provider ("Sign in with Kith")

The hub is a standard OpenID Connect provider, so any existing app can use Kith
without knowing anything about DIDs: Grafana, Argo, Next.js/Auth.js, Django, and
oauth2-proxy in front of anything else. The app sees ordinary OIDC. Behind it, the
login is a passkey (or wallet, or TOTP step-up), checked against the identity's KEL.
The hub can also accept a login from an upstream provider such as Telegram (§7.8).

It implements the flow in [How OpenID Connect
works](https://openid.net/developers/how-connect-works/) in both roles: as the provider
(this section) and as a relying party of other providers (§7.8).

Verified end to end in headless Chrome with a virtual WebAuthn authenticator, against
panva's certified `openid-client` (`scripts/oidc-demo.sh`), and by in-process Rust
tests (`crates/kith-hub/tests/oidc.rs`).

## 7.1 Endpoints and metadata

| Metadata | Value |
|----------|-------|
| `authorization_endpoint` | `{issuer}/oauth/authorize` |
| `token_endpoint` | `{issuer}/oauth/token` (code, refresh, and RFC 8693 exchange) |
| `userinfo_endpoint` | `{issuer}/oauth/userinfo` |
| `end_session_endpoint` | `{issuer}/oauth/logout` (RP-initiated logout) |
| `jwks_uri` | `{issuer}/.well-known/jwks.json` (Ed25519 + RSA) |
| `response_types_supported` | `code` |
| `code_challenge_methods_supported` | `S256`. **PKCE is required for every client**, as in the OAuth 2.1 draft. |
| `id_token_signing_alg_values_supported` | `RS256` (default; required by OIDC Core §15.1), `EdDSA` |
| `id_token_encryption_alg_values_supported` | `RSA-OAEP-256`, `ECDH-ES` (P-256), with `enc` `A256GCM` (§7.5) |
| `subject_types_supported` | `public` (the DID), `pairwise` |
| `token_endpoint_auth_methods_supported` | `client_secret_basic`, `client_secret_post`, `none` (public clients) |
| `acr_values_supported` | `urn:kith:acr:aal1`, `…aal2`, `…aal3` |
| `prompt_values_supported` | `none`, `login`, `consent` |
| `authorization_response_iss_parameter_supported` | `true` (RFC 9207 mix-up defense) |
| `registration_endpoint` | `{issuer}/oauth/register`, only when registration is turned on (§7.2) |
| `backchannel_logout_supported`, `frontchannel_logout_supported` | `true`, both with `…_session_supported` (§7.6) |

Discovery is served at both `/.well-known/openid-configuration` and
`/.well-known/oauth-authorization-server`.

## 7.2 Clients

Clients are registered in a JSON file, passed as `kith hub serve --clients clients.json`:

```json
{
  "client_id": "demo-rp",
  "client_secret": "…",                      // omit for public clients (SPA, native)
  "name": "Demo App",                        // shown on the login page
  "redirect_uris": ["https://app.example/cb"],
  "post_logout_redirect_uris": ["https://app.example/"],
  "audience": "api://invoices",              // aud of access tokens (default: client_id)
  "subject_type": "public" | "pairwise",
  "id_token_signed_response_alg": "RS256" | "EdDSA",
  "min_aal": 2,                              // always require at least AAL2
  "consent": "explicit" | "implied",         // ask before sharing (default), or never (§7.3)
  "backchannel_logout_uri": "https://app.example/hooks/logout",   // §7.6
  "frontchannel_logout_uri": "https://app.example/logout",        // §7.6
  "id_token_encrypted_response_alg": "RSA-OAEP-256" | "ECDH-ES",  // §7.5
  "jwks": { "keys": [ … ] }                  // the client's public keys, for encryption
}
```

Redirect URIs must be one of:
- `https`, with no userinfo (`https://good.example@evil.example` names evil.example);
- loopback `http` (`localhost`, `127.0.0.1`, `[::1]`);
- a private-use scheme (`com.example.app:/cb`), but never `javascript`, `data`,
  `vbscript`, `file`, `about`, `blob`, `ftp`, `ws` or `wss`.

Schemes are compared in lower case, so `HTTP://evil.example/cb` is plain http to a host
that is not loopback, and is refused. URIs are matched exactly and may not have a
fragment, whitespace or control characters. `post_logout_redirect_uris` follow the same
rules, because the sign-out page sends the browser there. `backchannel_logout_uri` and
`frontchannel_logout_uri` may be `https` or loopback `http` only. An unknown client or
an unregistered redirect URI is shown as an error page, **never redirected**.

**Dynamic registration** (RFC 7591, OpenID Connect Dynamic Client Registration 1.0).
`POST {issuer}/oauth/register` with client metadata as JSON returns `201` with a new
`client_id` and, unless `token_endpoint_auth_method` is `none`, a `client_secret`.

- It is off unless the hub is started with `--registration-token` (or
  `KITH_REGISTRATION_TOKEN`). The caller presents that value as a bearer: an RFC 7591
  initial access token. There is no open registration.
- Accepted metadata: `redirect_uris`, `client_name`, `token_endpoint_auth_method`,
  `grant_types` (`authorization_code`, `refresh_token`), `response_types` (`code`),
  `subject_type`, `id_token_signed_response_alg`, `post_logout_redirect_uris`,
  `backchannel_logout_uri`, `frontchannel_logout_uri`,
  `id_token_encrypted_response_alg`, `id_token_encrypted_response_enc`, `jwks`.
- `jwks_uri`, `sector_identifier_uri` and `request_uris` are refused with
  `invalid_client_metadata`: each would make the hub fetch a URL the client chose.
  A pairwise client must therefore keep all its redirect URIs on one host.
- A registered client always has `consent: explicit`, its `audience` is its
  `client_id`, and it cannot set `min_aal`. Its name is its own claim, so the consent
  page also shows the host the user will be sent back to.
- Registrations are kept in the hub's store (§7.9) and survive a restart. There is no
  RFC 7592 endpoint for a client to manage its own registration; the operator lists
  and deletes registrations through the admin API (§7.10).
- Every call counts against the registration rate limit, token or not (§7.9).

## 7.3 Authorization request

`GET /oauth/authorize` takes:
- `response_type=code`, `client_id`, `redirect_uri`, `scope` (must include `openid`);
- `state`, `nonce`;
- `code_challenge` + `code_challenge_method=S256`.

These optional parameters are also honoured:

| Parameter | Effect |
|-----------|--------|
| `prompt=login` | always show the login page |
| `prompt=none` | never show a page; return `login_required` if there is no suitable session, or `consent_required` if the user has not agreed yet |
| `prompt=consent` | always show the consent page, even for an `implied` client |
| `max_age=N` | reuse a session only if it authenticated within N seconds |
| `acr_values=urn:kith:acr:aal2` | minimum assurance. The least strict value listed wins, combined with the client's `min_aal`. |

**SSO.** A successful login sets the hub session cookie `kith_session`:
- `HttpOnly`, `SameSite=Lax`, 12 hours, and `Secure` when the issuer is https.
- A later authorization request for any client reuses the session. It skips the login
  page if the session is fresh enough, meets the required AAL, and its device is still
  active in the KEL.

**Consent.** After authentication, and before any code is issued, the hub asks the user
whether to share what the client requested (`GET /oauth/consent?request_id=…`).
- The page names the client and the host of its redirect URI, and lists each scope
  with the **values** it releases: the DID (or "an identifier made only for this app"
  for a pairwise client), name, email, groups and roles, and offline access.
- The page posts `{request_id, allow}` to `POST /oauth/consent`. Both the page and the
  post need the `kith_session` cookie of the login that the request is waiting on. A
  caller that knows only the `request_id` cannot answer for the user.
- **Allow** issues the code and is remembered for that identity, client and those
  scopes. A later request is asked again only for scopes not yet agreed to.
- **Deny** redirects with `error=access_denied`. Either answer uses up the request.
- A client with `consent: implied` is never asked. This is for first-party apps the
  hub's operator vouches for. `prompt=consent` asks even then.
- With `prompt=none`, a request that would need the page fails with
  `consent_required`.
- Remembered grants are in the hub's store and survive a restart. There is no page
  yet for the user to review or withdraw them; the operator can, through the admin
  API (§7.10).

## 7.4 Login page

The page is served by the hub with a per-response CSP nonce. Its data is embedded as
JSON and read with `textContent`, never interpolated into HTML.

1. **Passkey (username-less).**
   - The page calls `navigator.credentials.get({ challenge: SHA-256(message), rpId,
     allowCredentials: [] })`.
   - The credential's `userHandle` is the DID, set when the passkey was enrolled (§7.7).
   - The hub checks the assertion against that identity's passkey devices, with origin
     allowlist, RP id, UP flag, and signature. Any matching device counts.
2. **Ethereum wallet.** The user enters their DID, and the wallet `personal_sign`s the
   same message. The account must be a device or manage signer of the identity.
3. **TOTP** can be added to either, and raises the session to at least AAL2 (§2.5).
4. **An upstream provider**, one button for each the hub is configured with (§7.8).

The page posts `{request_id, challenge_id, did, factors}` to `POST /oauth/login`.
- On success, the response is `{redirect}` and sets the session cookie. The redirect
  goes to the client, or to the consent page first (§7.3).
- On failure, the response carries a **fresh challenge**, so the page can retry. For
  `step_up_required`, the response also includes `aal` and `required_aal`. The page then
  asks for a one-time code if that would be enough (AAL2), or explains that a hardware
  security key is needed (AAL3).

The challenge message is SIWE/CAIP-122-shaped and names the client:

```
localhost wants you to sign in to Demo App with your Kith identity.

URI: http://localhost:7777
Version: 1
Nonce: …
Issued At: …
Expiration Time: …
```

## 7.5 Tokens

`POST /oauth/token` with `grant_type=authorization_code`:
- Codes are single use and last 60 s.
- The code is bound to the client, `redirect_uri`, and PKCE challenge.

The response contains:

| Field | Contents |
|-------|----------|
| `id_token` | RS256 (or EdDSA) JWT: `iss`, `sub`, `aud`=client, `azp`, `iat`, `exp`, `auth_time`, `nonce`, `acr` (`urn:kith:acr:aalN`), `amr`, `sid`, plus scoped claims |
| `access_token` | the normal Kith RFC 9068 token (§3.5) with `aud` = client `audience`, `client_id`, `scope`, `groups`, `roles`, `attrs`, `aal`, `amr`, `dev` |
| `refresh_token` | only with `offline_access`. Rotating, single use, 30 days. **Invalid as soon as the device that logged in is revoked in the KEL.** Refresh re-evaluates groups and roles. |

Scoped claims (ID token and userinfo):

| Scope | Claims |
|-------|--------|
| `profile` | `name`, `preferred_username` |
| `email` | `email`, `email_verified` (from a verified contact if nothing else gives one, §7.8.2) |
| `phone` | `phone_number`, `phone_number_verified` (from a verified contact, §7.8.2) |
| `groups` | `groups`, `roles` (computed from the policy bundle, §4.3) |

`sid` identifies the hub session to the client, for logout (§7.6). It is a separate
random value, never the session cookie.

**Spent on sight.** A code is single use, and a code or refresh token shown by a client
it was not issued to, or with the wrong PKCE verifier, is spent anyway (RFC 6749
§4.1.2, §10.4). Presenting it elsewhere is a sign it leaked, so it must not stay good
for the next try.

**Encrypted ID tokens.** A client with `id_token_encrypted_response_alg` gets its ID
token as a JWE (RFC 7516) around the signed JWT: signed first, then encrypted.
- Key management is `RSA-OAEP-256` (RSA keys of 2048 bits or more) or `ECDH-ES` with
  P-256. Content encryption is `A256GCM`.
- The hub encrypts to the first key in the client's `jwks` that has the right type and
  is not marked `"use": "sig"` or for another `alg`. A client that asks for encryption
  without such a key is rejected at startup or registration.
- Only the ID token is encrypted. Userinfo responses are plain JSON over TLS.
- Checked against `jose` in both algorithms.

**Pairwise subjects.**
- `sub = base64url(HMAC-SHA256(hub secret, "kith-pairwise-v1|" + sector host + "|" + DID))`.
- The sector host is the host of the client's first redirect URI.
- The value is stable for that client and unlinkable across clients.
- Access tokens for pairwise clients use the same `sub`, and omit `attrs.aliases`
  (which would link back to the DID).

## 7.6 Userinfo and logout

`GET|POST /oauth/userinfo` takes the access token as a bearer. It returns `sub` plus the
scoped claims.

`GET /oauth/logout?post_logout_redirect_uri=…&state=…&client_id=…|id_token_hint=…`:
- It ends the hub session and clears the cookie. Codes of that session that were not
  redeemed yet stop working, and so do its refresh tokens.
- It redirects only to a URI registered for that client. Otherwise it shows a
  "signed out" page.

The hub then tells every client that received tokens in that session and registered
a logout URI:

- **Back channel** (OpenID Connect Back-Channel Logout 1.0). The hub POSTs
  `logout_token=<JWT>` to the client's `backchannel_logout_uri`. The token has
  `typ: logout+jwt` and is signed like that client's ID tokens. It carries `iss`,
  `aud`, `sub` (pairwise for a pairwise client), `iat`, `exp` (2 minutes), `jti`,
  `sid`, and `events: {"http://schemas.openid.net/event/backchannel-logout": {}}`. It
  never carries a `nonce`.
- **Front channel** (OpenID Connect Front-Channel Logout 1.0). The sign-out page loads
  each `frontchannel_logout_uri?iss=…&sid=…` in a hidden iframe, then goes on to the
  post-logout redirect, after at most 3 seconds. The page's CSP allows frames from
  exactly those origins.

Limits:
- Delivery is best effort and not retried. A client that is down misses the notice;
  its tokens still expire.
- RP-initiated logout and the admin API (§7.10) send notices. A session that expires,
  or ends because its device was revoked, does not.
- Signing out at the hub ends that session's refresh tokens, as the admin API does.
  OpenID Connect lets `offline_access` tokens outlive the session, and an earlier
  version of this hub left them valid. But every refresh token here is an
  `offline_access` token with a 30-day life that rolls forward, and signing out of a
  shared machine should mean it. A client that needs background access past a sign-out
  needs a different design from this. Revoking the device ends them as well (§7.5), and
  so does the admin API's sign-out-everywhere (§7.10).

## 7.7 Enrolling a browser passkey

A passkey must be created in the browser, on the hub's origin, but only the manage key
can add a device. `kith passkey enroll` brokers the two halves through the hub:

```
CLI      POST /v1/enroll (bearer)              → {id, url}; prints/opens url
Browser  GET  /enroll/{id}; credentials.create({ user.id = DID, residentKey: required, ES256 })
         POST /v1/enroll/{id}/key {key: did:key:zDn…, credential_id}
CLI      polls; signs add_device with the manage key
         POST /v1/enroll/{id}/event {device_id, message} (bearer)
Browser  polls; user taps "Confirm"; credentials.get(challenge = SHA-256(message))
         POST /v1/enroll/{id}/sig {sig}        (hub verifies it is the enrolled passkey)
CLI      polls; appends the proof-of-possession signature; publishes the KEL
```

- The enrollment id is a 128-bit capability that expires after 10 minutes.
- Whoever learns the id can submit a key first, and the hub is the one reporting the
  key back, so neither is trusted to say which key to add. The page shows a
  fingerprint of the key it made: the first six bytes of SHA-256 of the `did:key`, as
  `xxxx-xxxx-xxxx`. The CLI prints the same code for the key the hub reports and asks
  `[y/N]` before it signs; `--yes` skips the question. The person looking at both
  screens is the check.
- The passkey is stored as a `passkey` device with `rp_id` equal to the hub's RP id and
  AAL2.
- Only the passkey is ever in the browser, and only the CLI ever holds the manage key.

## 7.8 Upstream providers ("Sign in with Telegram")

The hub can be a relying party of other OpenID Connect providers and accept their
logins as a factor. [Telegram Login](https://core.telegram.org/bots/telegram-login) is
the first one. Any provider that supports the authorization code flow with PKCE and
signs ID tokens with `RS256`, `ES256`, `EdDSA` or `ES256K` is configured the same way.

Providers are registered in a JSON file, passed as
`kith hub serve --upstreams upstreams.json`:

```json
{
  "id": "telegram",                          // path segment and button id
  "name": "Telegram",                        // shown on the login button
  "issuer": "https://oauth.telegram.org",    // expected iss
  "client_id": "…",                          // from @BotFather → Login Widget
  "client_secret": "…",
  "scope": "openid"                          // default
}
```

`authorization_endpoint`, `token_endpoint` and `jwks_uri` may be given. Any that are
left out come from `{issuer}/.well-known/openid-configuration`.

For Telegram, register `{hub issuer}/oauth/upstream/telegram/callback` as an Allowed
URL in @BotFather.

**Linking.** An upstream account signs in the identity whose KEL has an `alias_link`
to `{iss}#{sub}` (§5.1):

```
kith alias link 'https://oauth.telegram.org#424242'
```

The `sub` is whatever the provider puts in its ID token. A login from an account that
is not linked yet fails with a page that shows the exact alias to link.

Anyone can link any alias in their own KEL. When several identities link the same
account, the hub will not guess: the login page passes the DID the user typed, and the
hub signs in that identity only if it is one of them.

**Flow.**

```
Browser  GET /oauth/upstream/{id}/start?request_id=…[&did=…]
Hub      302 → provider authorization endpoint
           (response_type=code, client_id, redirect_uri, scope, state, nonce,
            code_challenge, code_challenge_method=S256)
         Set-Cookie: kith_upstream=<state>
Browser  signs in at the provider
         GET /oauth/upstream/{id}/callback?code=…&state=…
Hub      POST token endpoint (code, redirect_uri, client_id, code_verifier; HTTP Basic)
         verifies the ID token, finds the identity, and finishes as §7.4 does
```

The hub MUST check:
- `state` is one it issued for this provider, unused, at most 10 minutes old, and equal
  to the `kith_upstream` cookie. The cookie binds the callback to the browser that
  started the flow (login CSRF).
- The ID token's signature against the provider's JWKS. `none` and HMAC algorithms are
  rejected.
- `iss` equals the configured issuer, `aud` contains the `client_id`, and `exp` has
  not passed.
- `nonce`, when the token carries one, equals the one sent.

**Assurance.** The hub cannot see how the provider authenticated the user, so the
login is AAL1 with `amr: ["fed"]` and no `dev` (§2.5).

**Step-up.** If the request needs more than AAL1, the callback shows the login page
again instead of redirecting. The page asks for a one-time code and posts
`{request_id, challenge_id, did, factors: [totp], federated}` to `/oauth/login`.
- `federated` is a token the hub gave only to that page.
- A caller that knows only the `request_id` cannot reuse the upstream login.
- Upstream login plus TOTP is AAL2, with `amr: ["otp", "fed", "mfa"]`.

**Revocation.** `alias_unlink` ends the hub sessions and refresh tokens that signed in
through that alias, the way revoking a device ends its sessions.

**Attributes.** A provider supplies attributes only if its entry says which, as a map
from its claim to the Kith attribute it becomes:

```json
{ "id": "telegram", …, "attributes": { "name": "name", "phone_number": "phone" } }
```

- With no `attributes` (the default), the provider only proves who signed in, and its
  UserInfo endpoint is never called.
- Otherwise the hub also calls UserInfo (`userinfo_endpoint`, or the one in discovery)
  with the access token. UserInfo's `sub` MUST equal the ID token's, or the login fails
  (OIDC Core §5.3.2). Claims in the signed ID token win over UserInfo's.
- Only the listed claims are kept, and only plain values (string, number, boolean).
- `email` is kept only with `email_verified: true`. `phone_number` is dropped when
  `phone_number_verified` is `false`.
- The directory and the KEL win: an upstream attribute fills a gap and never replaces
  a value the hub already has. No claim can become `aliases`, `aal` or
  `email_verified`.
- The attributes last for that login's session and its refresh tokens. They do not
  raise the AAL.
- Group rules see them (§4.3). Listing `email` for a provider therefore lets that
  provider put people in any group whose rule matches on email. List an attribute
  only for a provider you would trust with every rule that reads it.
- If UserInfo cannot be reached, the login continues with the ID token's claims only.

Not yet implemented:
- Signed or encrypted UserInfo responses (`application/jwt`).
- Linking from the browser. Today the alias is linked with the CLI.
- The API challenge flow (§2.3). Upstream login works through the login page only.
- Telegram's popup JS library and native SDKs. The hub uses the redirect flow.

Tested in process against a stand-in provider (`crates/kith-hub/tests/upstream.rs`).
Not yet run against Telegram itself.

### 7.8.1 Account attestations

The `aliases` attribute is what an identity says about itself: anyone can link any
alias (§5.1). An app that needs to know an account is really this person's asks the hub
to say so. The hub is the oracle here, so the app trusts the hub to have checked.

An app adds the `linked_account` scope. If the login came through an upstream provider,
the token response carries `account_attestation`, a JWT signed with the hub's EdDSA key
(in its JWKS), with header `typ: kith-account+jwt`:

```json
{
  "iss": "https://hub.example",
  "sub": "did:kith:…",                       // or the pairwise subject (§7.2)
  "aud": "app",                              // the client id
  "iat": 1800000000, "exp": 1800000900, "jti": "…",
  "provider": "facebook",                    // this hub's id for the provider
  "provider_iss": "https://www.facebook.com",
  "account": "1029384756",                   // the ID token's sub
  "verified_at": 1799999970                  // when the hub verified that ID token
}
```

- The hub MUST issue one only for the alias of the login in hand, whose ID token it
  verified (§7.8). It MUST NOT issue one from the KEL's alias list. A login with a
  passkey, a wallet or a device key gets none, even when the identity links accounts.
- The field is absent when there is nothing to attest. Absence proves nothing either way.
- A provider no longer in the hub's configuration gets none.
- Consent (§7.3) shows the account before it is released. Pairwise clients get it too if
  they ask, so the user's agreement is what links the pseudonym to the account.
- A refresh issues a new attestation with the original `verified_at`, and stops once the
  alias is unlinked (§7.8, Revocation).

An app MUST verify it as §3.5 says for access tokens, with `typ` `kith-account+jwt`, and
`aud` equal to its own client id. It MUST also refuse an empty `provider`, `provider_iss`
or `account`, and a `verified_at` in the future. It compares `provider_iss`, not
`provider`, and decides itself how old a `verified_at` it accepts. The shared cases are
`spec/test-vectors/attestations.json`. Verifiers: `verify_account_attestation` (Rust),
`createAttestationVerifier` (JS), `AttestationVerifier` (Python).

What it does not say: `account` is the provider's `sub`, which some providers scope to
the app. It proves "the same account this hub saw", not a public handle or a real name.

**Facebook.** `Upstream::facebook(app_id)` is the preset; as a JSON entry:

```json
{
  "id": "facebook", "name": "Facebook",
  "issuer": "https://www.facebook.com",
  "client_id": "<app id>",
  "authorization_endpoint": "https://www.facebook.com/v25.0/dialog/oauth",
  "token_endpoint": "https://graph.facebook.com/v25.0/oauth/access_token",
  "jwks_uri": "https://www.facebook.com/.well-known/oauth/openid/jwks/",
  "token_request": "get"
}
```

Facebook's discovery document lists neither the code flow nor a token endpoint, so all
three endpoints are given. `token_request: "get"` sends the code in a URL, as Facebook
documents. PKCE is the proof, and the hub refuses a `client_secret` on such an entry
rather than put it in a URL. `sub` is per app (`subject_types_supported: ["pairwise"]`).
Register `{hub issuer}/oauth/upstream/facebook/callback` as a redirect URI.

Tested against a stand-in that exchanges codes the same way. Not yet run against
Facebook itself. Providers without ID tokens (GitHub, X, Discord) are not supported.

### 7.8.2 Verified contacts (email and phone)

An identity can prove to its hub that it receives mail at an address, or texts at a
phone number. The hub then attests it the way it attests an upstream account
(§7.8.1), with itself as the provider. Nothing an app does not need is public:

- **Private by default.** A verified contact goes to an app only when the user has
  agreed to that app's `email` or `phone` scope, and to nobody else. It never goes into
  the KEL, the DID document or an access token's `attrs`.
- **Public if wanted.** The user can publish a contact. The hub then answers lookups
  for it with a signed attestation anyone can check. Unpublishing ends that.
- **Checked again.** A verification has an age, and past `max_age` the hub stops
  attesting the contact until the user proves control again. Anyone who proves control
  of an address takes it over: it is one identity's at a time.

The hub keeps a contact as it was verified; an address that only needs comparing would
be hashed, but this one is shown to apps, so it is stored as it is. Codes are hashed.

**Addresses.** Contacts are URIs:

| Input | Contact |
|-------|---------|
| `ada@Example.COM`, `mailto:ada@example.com` | `mailto:ada@example.com` (lower case; one `@`, a dot in the domain, at most 254 characters) |
| `+1 (555) 555-0100`, `tel:+15555550100` | `tel:+15555550100` (E.164: `+`, 8 to 15 digits; spaces, dots, dashes and brackets are dropped) |

A number without its `+` country code is refused, not guessed at. A hub MAY limit
phone numbers to some prefixes (`phone_prefixes`, e.g. `+1`), which is the cheapest
defence against SMS pumping fraud.

**Proving control.** All of these take a hub bearer token (`aud` = issuer):

| Request | Effect |
|---------|--------|
| `POST /v1/contacts` `{"address"}` | Sends a 6-digit code to the address. It lasts 10 minutes and allows 5 wrong tries. A new request replaces the code. Rate limited per identity, per address and per client address (`contact_limit`, default 5 an hour each) |
| `POST /v1/contacts/confirm` `{"address", "code"}` | Verifies the contact: `verified_at` is now. If another identity held the address, it no longer does |
| `GET /v1/contacts` | The caller's contacts: `address`, `kind` (`email` or `phone`), `verified_at`, `fresh_until`, `fresh`, `public` |
| `PUT /v1/contacts/public` `{"address", "public"}` | Publish or withdraw. Publishing needs a fresh contact, and a device with the `alias` cap (or no device: a manage key) |
| `DELETE /v1/contacts` `{"address"}` | Forget it |

The message says what the code is for and which hub sent it. A text ends with the
origin-bound line `@{rp_id} #{code}`, so phones that support it offer the code only on
that site. Checking again is the same request and confirmation. Until it is confirmed,
the old verification stands, if it is still fresh.

**Freshness.** A contact is fresh until `verified_at + max_age`: by default 365 days for
email and 90 days for phone numbers, because carriers give numbers to new subscribers
after a few months. A stale contact stays listed, so the user can check it again, but
nothing is released or published for it. An app that wants more recent proof than the
hub's `max_age` compares `verified_at` itself.

**What apps receive.** With the `email` scope, an app whose user has no email from the
directory or an upstream provider gets the most recently verified fresh email as
`email`, with `email_verified: true`. With the `phone` scope it gets `phone_number` and
`phone_number_verified: true` the same way. The ID token and userinfo carry them, and
so does the consent page before anything is released. The token response also carries
`contact_attestations`: one `kith-account+jwt` (§7.8.1) per fresh contact of a granted
kind, with

```json
{ "provider": "email",                    // or "phone"
  "provider_iss": "https://hub.example",  // this hub: it checked the code itself
  "account": "mailto:ada@example.com",    // or "tel:+15555550100"
  "verified_at": 1799999970, … }          // when the code was confirmed
```

Apps verify it exactly as §7.8.1 says. A refresh looks the contacts up again, so a
contact that was removed, went stale or was taken over drops out.

**Public lookups.** `GET /v1/contacts/lookup?address=…` needs no token. For a published,
fresh contact it answers

```json
{ "address": "mailto:ada@example.com", "did": "did:kith:…", "verified_at": 1799999970,
  "attestation": "<kith-account+jwt, aud urn:kith:public, sub the DID>" }
```

and `404` otherwise, the same for a private contact as for one that does not exist. The
attestation verifies as in §7.8.1 with `urn:kith:public` as the audience. It lasts 15
minutes, so a copy shows what the hub said then, not that the contact is still held.
Trust it only from a hub you trust to check codes: anyone can run a hub. Publishing
puts nothing in the KEL, so withdrawing really withdraws, apart from copies already
fetched. An address the user wants permanently on record belongs in an `alias_link`
with a back-link from its own domain (§5.1) instead.

**Delivery.** The reference hub sends through Amazon SES (email) and AWS End User
Messaging SMS (texts), built with the `aws` feature, or appends each message to an
outbox file for tests and development. With neither configured, the contact
endpoints answer `501`. AWS credentials come from the usual chain (environment,
profile, instance role).

Not yet implemented:
- `kith resolve` following public contacts. Today a resolver asks the hub's lookup
  itself.
- An app asking the hub to check a contact again during sign-in, and verification from
  the browser (CLI only today).
- Voice calls, and delivery receipts.

## 7.9 Deployment notes

- **State.** The data directory (`--data`, default `.kith-hub`) holds:
  - `hub.sqlite`: hub sessions, codes, refresh tokens, pending sign-in requests,
    remembered consent, registered clients, TOTP enrollments and lockouts, co-signer
    keys, the token replay cache and rate-limit counters. A restart signs nobody out
    and asks nobody for consent again. Session cookies, codes, refresh tokens and
    request ids are stored as their SHA-256, so a copy of the file cannot be replayed.
    It is in WAL mode: back up `hub.sqlite` and `hub.sqlite-wal` together, or use
    `sqlite3 hub.sqlite .backup`.
  - `kels/`: one JSON file per identity, as published. Anyone may mirror these.
  - `hub-key.json`, `hub-rsa-key.json`, `hub-secret.json`, `hub-revoker.json`: the
    hub's own keys. Losing them changes the issuer's keys and every pairwise subject.
  - `blocks/`, `revocations/`: policy DAGs and revocation chains (§8).

  A hub from before the store imports `totp.json`, `cosigners.json` and `clients.json`
  on first start and renames them `*.imported`. Login challenges (5 minutes) and
  passkey enrollments in progress (10 minutes) stay in memory: after a restart the
  login page is handed a fresh challenge and retries; an enrollment is started again.
- **Rate limits.** `POST /oauth/login` allows 20 attempts per minute and
  `POST /oauth/register` 20 per hour, per client address. One more answers `429` with
  a `Retry-After` header and `{"error": "rate_limited", "retry_after": <seconds>}`.
  Behind one reverse proxy, start the hub with `--behind-proxy`: the client address
  is then the last `X-Forwarded-For` entry, the one your proxy appended (earlier
  entries are whatever the client sent). Without the flag that header is ignored.
  Every place a TOTP code is checked (`/v1/auth/verify`, `/v1/cosign`, and a token
  exchange with `totp`) shares a third budget of 20 per minute per address
  (`totp_limit`), and a reset with a code counts against it too. TOTP has its own
  lockout per identity (§2.3). Counters live in the store, so a restart does not reset
  them.
- **TLS.** The hub speaks plain HTTP. Terminate TLS in front of it and set `--issuer`
  to the `https://` URL; cookies are then marked `Secure`.
- **RP id.** WebAuthn only allows passkeys on the RP id's domain.
  - For local development, the hub must be reached as `http://localhost:PORT`, not
    `127.0.0.1`. `kith hub serve` defaults the issuer accordingly.
  - In production, the issuer's host is the RP id, e.g. `id.example.com`, or set
    `--rp-id example.com` to share passkeys across subdomains.
- **Grafana** (generic OAuth). This configuration is not yet tested against a running
  Grafana:

```ini
[auth.generic_oauth]
enabled = true
name = Kith
client_id = grafana
client_secret = change-me
scopes = openid profile email groups
auth_url = https://id.example.com/oauth/authorize
token_url = https://id.example.com/oauth/token
api_url = https://id.example.com/oauth/userinfo
use_pkce = true
login_attribute_path = preferred_username
role_attribute_path = contains(roles[*], 'billing-admin') && 'Admin' || 'Viewer'
```

## 7.10 Admin API

For the hub's operator, under `{issuer}/v1/admin/`. Two credentials open it:

- the bearer token given as `kith hub serve --admin-token` (or `KITH_ADMIN_TOKEN`);
- a hub access token (`aud` = issuer, §2.3) for an identity whose roles include the
  admin role, `hub-admin` by default. The policy bundle decides who is in that role,
  so "who runs the hub" is an ordinary Kith authorization question.

| Method, path | Does |
|--------------|------|
| `GET /v1/admin/stats` | Counts of sessions, refresh tokens, codes, pending requests, grants, registered and configured clients, TOTP enrollments, co-signers and KELs; uptime. |
| `GET /v1/admin/sessions[?did=…]` | Live hub sessions: `sid`, `did`, `device`, `alias`, `aal`, `amr`, `auth_time`, `expires`, `clients`. Never the cookie. |
| `DELETE /v1/admin/sessions/{sid}` | Ends that session. Its unredeemed codes and its refresh tokens die; clients that registered a logout URI are told (§7.6). |
| `DELETE /v1/admin/identities/{did}/sessions` | Signs the identity out everywhere: every session, and every refresh token, including those whose session already expired. |
| `DELETE /v1/admin/identities/{did}/totp` | Forgets the identity's authenticator, for an owner who lost it and has no strong sign-in. Sign-ins that rested on it alone end (§2.3). |
| `GET /v1/admin/clients` | Configured and registered clients, with `source` and `has_secret` in place of the secret. |
| `DELETE /v1/admin/clients/{id}` | Deletes a registered client with its grants and refresh tokens. A configured client answers `409`: edit the clients file. |
| `GET /v1/admin/grants/{did}` | What the identity agreed to share, per client: scopes and when. |
| `DELETE /v1/admin/grants/{did}/{client_id}` | Withdraws that consent. The client's refresh tokens for the identity die, and it is asked again next time. |

Responses are JSON with `Cache-Control: no-store`. Errors have the API's usual
`error` and `error_description`: no credential is `401`, an identity outside the
role `403`.

```bash
curl -s -H "authorization: Bearer $KITH_ADMIN_TOKEN" https://id.example.com/v1/admin/sessions
curl -s -X DELETE -H "authorization: Bearer $KITH_ADMIN_TOKEN" \
  "https://id.example.com/v1/admin/identities/did:kith:…/sessions"
```

## 7.11 Not yet implemented

- A page for the user to review and withdraw remembered consent (the admin API can).
- Open client registration, and the registration management endpoint (RFC 7592).
- `jwks_uri` and `sector_identifier_uri` for clients; encrypted userinfo.
- Logout notices when a session expires or its device is revoked; retries.
- Session management through `check_session_iframe`.
- Pushed authorization requests (PAR), DPoP-bound tokens.
- `claims` request parameter; request objects (JAR).
- TOTP enrollment from the browser (CLI only today).
- Editing clients, and an audit log, through the admin API.
