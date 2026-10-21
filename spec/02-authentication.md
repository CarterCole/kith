# 2. Authentication

"Log in with anything" means any authenticator can produce evidence about an identity.
The hub turns that evidence into an access token that states how strong it was
(`aal`, `amr`). Policies decide how much strength an action needs.

## 2.1 Authenticators

| Authenticator | Kind | Where it lives in Kith | Verifiable by third parties? |
|---------------|------|------------------------|------------------------------|
| Device key (software, Secure Enclave, TPM, YubiKey) | asymmetric | device in the KEL | yes |
| Passkey (WebAuthn) | asymmetric | device in the KEL, `kind: passkey`, alg `WebAuthn` | yes |
| Ethereum wallet (EOA) | asymmetric | signer in a manage or rotation policy (`eip155:…`) | yes |
| Contract wallet (Safe, Coinbase Smart Wallet) | contract | signer via EIP-1271 | yes, with chain access |
| Bitcoin wallet | asymmetric | signer via BIP-322 (planned) | yes |
| SSH key / ssh-agent | asymmetric | device key (planned: `ssh-keygen -Y sign` format) | yes |
| TOTP | **shared secret** | hub-side factor, optionally a co-signer (§2.6) | **no, only the secret holder** |
| Upstream OIDC (Telegram; any code + PKCE provider) | federated | hub-side factor, bound by an `alias_link` (§2.7) | only via the upstream IdP |
| Upstream SAML | federated | planned | only via the upstream IdP |
| Email / SMS link | shared channel | hub-side factor (planned, AAL1 at most) | no |
| Passport / mDL | credential | **attributes**, not login (see [passports](../docs/passports.md)) | yes (issuer signature) |

The key distinction is between asymmetric and shared-secret authenticators.
- An asymmetric signature can be checked by anyone. It can therefore go in a KEL, sign
  a session grant, or be one signer of a multisig.
- A TOTP code does prove possession of a device that holds the secret. But only a party
  holding the same secret can check it, so on its own it can only convince the hub.
  §2.6 shows how to bring it into multisig anyway.

## 2.2 Session-chain login (the default for apps and CLIs)

1. The device generates an ephemeral Ed25519 **session key**.
2. The device signs a **grant** certifying that session key (§3.2).
   - For a passkey device, the grant is signed with a WebAuthn assertion.
3. The session key signs a short-lived **session token** with `aud` set to the hub.
4. The client exchanges the session token at `POST /v1/oauth/token` (RFC 8693) for an
   access token, adding an optional `totp` for step-up.

The hub resolves the KEL, checks that the device is active, and verifies grant then
token. It also rejects replayed `jti` values. Revoking a device breaks every one of its
sessions immediately.

## 2.3 Challenge login (signature, passkey, wallet, TOTP)

```
POST /v1/auth/challenge {did}  →  {challenge_id, message, expires_at}
POST /v1/auth/verify    {challenge_id, audience, factors:[…]}  →  token response
```

The challenge text follows the CAIP-122 / EIP-4361 shape, so wallets render it
sensibly:

```
localhost wants you to sign in with your Kith identity:
did:kith:…

URI: http://127.0.0.1:7777
Version: 1
Nonce: …
Issued At: …
Expiration Time: …
```

Challenges are single-use and expire after 5 minutes. The `factors` array accepts:

| type | Fields | Checks |
|------|--------|--------|
| `signature` | `sig` (§1.3) | `sig.signer` is a device or manage signer of the identity, and the signature is over `message` |
| `webauthn` | `device_id`, `authenticator_data`, `client_data_json`, `signature` | §2.4 with an origin allowlist and RP id |
| `totp` | `code` | RFC 6238 ±1 step, no step reuse; 5 wrong codes lock the factor for 15 minutes (`429 locked`, with `retry_after`), and the lockout survives a hub restart |

## 2.4 Passkeys

A passkey is a P-256 device key whose signatures are WebAuthn assertions. Kith always
sets `challenge = SHA-256(message)`. That lets one passkey do all of these:
- sign a login challenge (§2.3);
- sign a session grant (JWS alg `WebAuthn`, §3.2);
- sign a key event, for example as one of "2 of my 3 passkeys" in a manage policy, or
  as proof of possession when it is enrolled.

A verifier MUST check:
- `clientData.type == "webauthn.get"`;
- the challenge;
- the user-present flag;
- the ES256 signature over `authenticatorData ‖ SHA-256(clientDataJSON)`.

For login it MUST also check the origin allowlist and `rpIdHash`. The user-verified
(UV) flag is reported and feeds the assurance level.

Enrollment from a browser:
1. `navigator.credentials.create()` returns the SPKI public key via `getPublicKey()`,
   which gives a `did:key:zDn…`.
2. The manage key signs an `add_device` event.
3. The passkey signs the same event (proof of possession).
4. The event is published.

## 2.5 Assurance

| Evidence | aal | amr |
|----------|-----|-----|
| software device key | device's aal (default 1) | `swk` |
| hardware or passkey session chain | device's aal | `hwk` |
| passkey assertion with UV | device's aal (default 2) | `hwk`, `user` |
| passkey assertion without UV | at most 1 | `hwk` |
| wallet signature | 2 | `wallet` |
| TOTP | 1 | `otp` |
| upstream OIDC login (Telegram, …) | 1 | `fed` |
| two or more distinct factor types | at least 2 | `+ mfa` |
| delegated | the **actor's** aal | `delegated` |

`aal` follows NIST SP 800-63B. A device's declared `aal` is set when it is enrolled and
signed by the manage policy. Hardware-attested enrollment (WebAuthn attestation,
Apple App Attest, Android Key Attestation) is future work.

## 2.6 TOTP-gated co-signer: putting TOTP into multisig

TOTP can't sign, but a hub can hold a key that **signs only after seeing a valid TOTP
code**:

```
POST /v1/cosigner   (Bearer)          →  {"signer": "did:key:z6Mk…", "gated_by": "totp"}
POST /v1/cosign     {did, code, event} →  Sig over event.signing_message()
```

1. Put that signer id in your rotation (or manage) policy, e.g.
   `2 of [paper key, Safe, hub co-signer]`.
2. After losing everything except a paper key and the phone with your TOTP app, you
   can still rotate. The paper key signs, and the co-signer signs on your code.
3. The hub can't act alone: it holds one share, and policy requires two.

Hub requirements:
- The hub MUST only co-sign the *next* event of the identity's current KEL.
- It SHOULD add a delay and notify existing devices before co-signing a `rotate`,
  like did:plc's 72-hour recovery window. This is not implemented yet.

## 2.7 Federation and legacy apps

- **Hub as an OIDC provider** (implemented, [§7](07-oidc.md)). Existing apps can
  "Sign in with Kith" through standard authorization code + PKCE, with a passkey login
  page, SSO and step-up.
- **Upstream IdPs as factors** (implemented for OIDC, [§7.8](07-oidc.md)). "Sign in
  with Telegram" is a factor. It is linked to the identity once, by an `alias_link` to
  the upstream subject, `{iss}#{sub}` (§5.1).
  - The evidence is an ID token only the hub checks, so it counts as AAL1 (`amr: fed`)
    and can never sign a key event or a session grant.
  - Adding TOTP makes it two factor types, so AAL2.
  - Unlinking the alias ends the sessions that signed in through it.
- **Upstream attributes** (implemented for OIDC, [§7.8](07-oidc.md)). The same login
  can supply attributes (name, phone, email) from the ID token and UserInfo. The trust
  policy is a per-provider allowlist of claims. The directory and the KEL always win.
