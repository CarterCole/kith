# 7. OpenID Connect provider ("Sign in with Kith")

The hub is a standard OpenID Connect provider, so any existing app can use Kith
without knowing anything about DIDs: Grafana, Argo, Next.js/Auth.js, Django, and
oauth2-proxy in front of anything else. The app sees ordinary OIDC. Behind it, the
login is a passkey (or wallet, or TOTP step-up), checked against the identity's KEL.

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
| `subject_types_supported` | `public` (the DID), `pairwise` |
| `token_endpoint_auth_methods_supported` | `client_secret_basic`, `client_secret_post`, `none` (public clients) |
| `acr_values_supported` | `urn:kith:acr:aal1`, `…aal2`, `…aal3` |
| `authorization_response_iss_parameter_supported` | `true` (RFC 9207 mix-up defense) |

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
  "min_aal": 2                               // always require at least AAL2
}
```

Redirect URIs must be one of:
- `https`;
- loopback `http` (`localhost`, `127.0.0.1`, `[::1]`);
- a private-use scheme (`com.example.app:/cb`).

They are matched exactly. An unknown client or an unregistered redirect URI is shown as
an error page, **never redirected**.

## 7.3 Authorization request

`GET /oauth/authorize` takes:
- `response_type=code`, `client_id`, `redirect_uri`, `scope` (must include `openid`);
- `state`, `nonce`;
- `code_challenge` + `code_challenge_method=S256`.

These optional parameters are also honoured:

| Parameter | Effect |
|-----------|--------|
| `prompt=login` | always show the login page |
| `prompt=none` | never show it; return `login_required` if there is no suitable session |
| `max_age=N` | reuse a session only if it authenticated within N seconds |
| `acr_values=urn:kith:acr:aal2` | minimum assurance. The least strict value listed wins, combined with the client's `min_aal`. |

**SSO.** A successful login sets the hub session cookie `kith_session`:
- `HttpOnly`, `SameSite=Lax`, 12 hours, and `Secure` when the issuer is https.
- A later authorization request for any client reuses the session. It skips the login
  page if the session is fresh enough, meets the required AAL, and its device is still
  active in the KEL.

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

The page posts `{request_id, challenge_id, did, factors}` to `POST /oauth/login`.
- On success, the response is `{redirect}` and sets the session cookie.
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
| `id_token` | RS256 (or EdDSA) JWT: `iss`, `sub`, `aud`=client, `azp`, `iat`, `exp`, `auth_time`, `nonce`, `acr` (`urn:kith:acr:aalN`), `amr`, plus scoped claims |
| `access_token` | the normal Kith RFC 9068 token (§3.5) with `aud` = client `audience`, `client_id`, `scope`, `groups`, `roles`, `attrs`, `aal`, `amr`, `dev` |
| `refresh_token` | only with `offline_access`. Rotating, single use, 30 days. **Invalid as soon as the device that logged in is revoked in the KEL.** Refresh re-evaluates groups and roles. |

Scoped claims (ID token and userinfo):

| Scope | Claims |
|-------|--------|
| `profile` | `name`, `preferred_username` |
| `email` | `email`, `email_verified` |
| `groups` | `groups`, `roles` (computed from the policy bundle, §4.3) |

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
- It ends the hub session and clears the cookie.
- It redirects only to a URI registered for that client. Otherwise it shows a
  "signed out" page.

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
- The passkey is stored as a `passkey` device with `rp_id` equal to the hub's RP id and
  AAL2.
- Only the passkey is ever in the browser, and only the CLI ever holds the manage key.

## 7.8 Deployment notes

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

## 7.9 Not yet implemented

- Consent screen and remembered grants.
- Dynamic client registration.
- Pushed authorization requests (PAR), DPoP-bound tokens.
- Front- and back-channel logout.
- `claims` request parameter; request objects (JAR).
- Rate limiting on `/oauth/login`.
- Durable sessions: sessions, codes and refresh tokens are in memory, so a hub restart
  signs everyone out.
- TOTP enrollment from the browser (CLI only today).
