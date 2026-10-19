# 1. Identity

## 1.1 Goals

- One **root identity per person** (or org, or agent) that outlives any single key,
  device, provider or chain.
- Control is a **policy over many signers**, not one key. A signer can be a passkey, a
  hardware key, a software key, an OpenPGP or SSH key, an Ethereum account (EOA or
  contract wallet), or a Bitcoin address. Multisig is the normal case.
- Different **authority levels** get different policies. Rotating the identity should
  need more than adding a laptop, and adding a laptop should need more than signing in.
- **Self-certifying**: anyone can verify an identity's full history from the data alone.
  Hubs, registries and chains are availability layers, not trust roots.
- Compatible with **W3C DID Core**: every identity resolves to a DID document.

## 1.2 Identifier

```
did:kith:<base32-lower-nopad( SHA-256( canonical(inception event without sigs) ) )>
```

The identifier commits to the genesis event, which includes the initial policies, the
devices and a timestamp. The same approach is used by did:plc (whose id is a truncated
hash of the genesis operation) and by KERI's self-addressing identifiers. Nobody can
claim your DID without the genesis data, and the genesis data can't be changed without
changing the DID.

## 1.3 Signers and signatures

A signature is carried as:

```json
{ "signer": "<signer id>", "alg": "<alg>", "sig": "<base64url>", "webauthn": { … }? }
```

| alg | Signer id | Verification |
|-----|-----------|--------------|
| `Ed25519` | `did:key:z6Mk…` | RFC 8032 (strict) |
| `ES256` | `did:key:zDn…` | ECDSA P-256/SHA-256, raw `r‖s` or DER |
| `ES256K` | `did:key:zQ3s…` | ECDSA secp256k1/SHA-256 |
| `WebAuthn` | `did:key:zDn…` (a passkey) | WebAuthn assertion whose `challenge` = SHA-256(message) (§2.4) |
| `EIP191` | `eip155:<chain>:<addr>` | `personal_sign` ecrecover equals the address |
| `EIP1271` | `eip155:<chain>:<addr>` | the contract's `isValidSignature(EIP-191 hash, sig)` returns `0x1626ba7e` |
| `BIP322` | `bip122:<genesis>:<addr>` | BIP-322 generic signed message (not implemented yet) |
| `OpenPGP` | `did:key:z6Mk…`, `zDn…` or `zQ3s…` | detached OpenPGP signature over the message (draft, §1.3.1) |
| `SSHSIG` | `did:key:z6Mk…` or `zDn…` | OpenSSH `SSHSIG` over the message, namespace `kith` (§1.3.1) |

**Contract wallets** such as Safe, Coinbase Smart Wallet and ERC-4337 accounts use
`EIP1271`.
- Verification needs chain access, so implementations take a `ChainVerifier`.
- A verifier MUST record the block number it checked against. Contract signers can
  change, so the result is only valid "as of block N".
- Undeployed (counterfactual) wallets can be supported with ERC-6492 wrapping.

**The signed message** for a key event is plain text, so wallets and hardware keys can
show it to the user. It is also domain-separated:

```
kith identity event v1
did: <did or "new">
seq: <n>
kind: <kind>
digest: <digest of the event without sigs>
```

### 1.3.1 OpenPGP and SSH signatures

These let a GPG key or an SSH key, including one on a YubiKey, act as a signer. The
signature formats are the standards' own. This section only fixes the choices they
leave open.

Status: `SSHSIG` verification is implemented in the Rust core and pinned by
[`test-vectors/sshsig.json`](test-vectors/sshsig.json), whose signatures come from
`ssh-keygen`. `OpenPGP` is a draft and not implemented.

- **`sig`** is `base64url` of the binary signature.
  - OpenPGP: the detached signature packet as `gpg --detach-sign` writes it, not
    ASCII-armored.
  - SSHSIG: the blob inside the `-----BEGIN SSH SIGNATURE-----` armor.
- **Signed bytes** are the Kith message being signed, unchanged: a key event message
  as above, a revocation entry, a login challenge.
- **Signer id** is the `did:key` of the key that made the signature, which for OpenPGP
  is usually a signing subkey. It is never an OpenPGP fingerprint. A v4 fingerprint is
  a SHA-1 hash that covers the key's creation time, so it names a key at a moment
  rather than a key, and SHA-1 is a weak thing to name an identity with.
- **The certificate is never consulted.** User IDs, subkey binding signatures, expiry
  and OpenPGP revocation certificates have no effect. The key log is the only
  authority on whether a key is trusted.

**OpenPGP** (RFC 4880, RFC 9580):
- The `sig` holds exactly one signature packet and nothing else. Version 4 or 6.
  Signature type MUST be `0x00` (binary document).
- Public-key algorithms: EdDSA on Ed25519 (`z6Mk…`), ECDSA on NIST P-256 (`zDn…`),
  ECDSA on secp256k1 (`zQ3s…`). RSA is planned as a separate key type, since many
  existing keys use it. DSA, Ed448 and other curves are not supported.
- Hash: SHA-256, SHA-384 or SHA-512. Anything else is rejected.
- Only the hashed subpacket area counts, and the unhashed area MUST be ignored.
  Verifiers ignore the issuer, issuer fingerprint, creation time and expiration time
  subpackets, because log events are not time-bound. A signature with an unrecognized
  critical subpacket is invalid, as the RFC requires.

**SSHSIG** (OpenSSH `PROTOCOL.sshsig`):
- The namespace MUST be `kith`, the reserved field empty, and the hash `sha256` or
  `sha512`.
- Key types: `ssh-ed25519` (`z6Mk…`) and `ecdsa-sha2-nistp256` (`zDn…`). The public
  key inside the signature MUST equal the signer's key. FIDO `sk-` keys are a follow-up.
- Each vector records what `ssh-keygen -Y check-novalidate -n kith` says. It accepts
  two cases Kith must reject: a valid signature whose signer id names another key, and
  a P-384 key. It checks structure and the signature, not who signed.

**Domain separation.** SSHSIG has a namespace. OpenPGP has none, so separation rests on
the message text, which names the protocol, DID, sequence number and event digest. A
signing tool MUST show the user that text before signing.

**Tooling (planned).** `kith` will show the message and run `gpg --detach-sign` or
`ssh-keygen -Y sign -n kith`, directly or through the agent, so the private key never
enters Kith. Until then, `ssh-keygen -Y sign -n kith` on the message text produces a
valid `SSHSIG`.

### 1.3.2 Key purposes (draft, not implemented)

Today a device has one signing key (`key`) and an optional X25519 key (`xkey`) that
only the vault reads (§6). The curve is implied by the `did:key` prefix, and `caps`
says what the device may do. Nothing says what each *key* is for. The DID document
lists every device key under the signing relationships and leaves `xkey` out.

A device MAY annotate its keys:

```json
"device": { "id": "dev_x", "name": "yubikey", "kind": "hardware", "aal": 3,
  "keys": [
    { "id": "sig", "key": "did:key:z6Mk…", "alg": "OpenPGP",
      "use": ["authentication", "assertionMethod", "capabilityInvocation"] },
    { "id": "enc", "key": "did:key:z6LS…", "alg": "X25519", "use": ["keyAgreement"] }
  ] }
```

`use` is a subset of DID Core's verification relationships:

| `use` | The key may |
|-------|-------------|
| `authentication` | sign logins and session grants (the `session` cap is still required) |
| `capabilityInvocation` | sign the key log events its device is allowed to sign |
| `assertionMethod` | sign any other statement the identity makes |
| `keyAgreement` | receive messages encrypted to the identity, such as vault key rings (§6) |
| `capabilityDelegation` | reserved for re-delegation (§3.3, future work) |

`alg` names the format. The curve always comes from the `did:key`, and `alg` must be
compatible with it.
- For a signing key, `alg` is one of the algorithms in the table above.
- For a `keyAgreement` key, `alg` says how a sender seals to it. `X25519` is the
  vault's current construction. Other containers, such as an OpenPGP message to a
  cv25519 subkey so that `gpg --decrypt` works, can be added without changing the
  log format.

**Defaults.** A device without `keys` is read as its `key` with `use` set to
`authentication`, `assertionMethod` and `capabilityInvocation`, plus its `xkey` (if any)
with `use` set to `keyAgreement`. Existing logs keep their meaning.

**Rules.**
1. A verifier MUST NOT accept a signature from a key for an operation its `use` does
   not include. Annotations are part of `add_device`, which the manage policy signs, so
   a hub cannot change them. To change one, add a new device.
2. A key MUST NOT have both a signing use and `keyAgreement`. An Ed25519 key MUST NOT
   be converted to X25519 to get around this. Use one key per primitive.
3. Every key with a signing use MUST sign the `add_device` event, as `key` does today.
   A `keyAgreement` key can't sign, so the manage policy's signature covers it.

**DID document (§1.7).** Each key becomes a `Multikey` verification method, listed under
exactly the relationships in its `use`. Keys with `keyAgreement` appear under that
relationship, so any DID resolver can find an identity's encryption keys.

**Scope.** Annotations cover device keys. The signers inside the manage and `next`
policies are bare ids that only ever sign key log events.

## 1.4 Signer policies

```json
"did:key:z6Mk…"                                              // one signer
{ "threshold": 2, "of": ["did:key:…", "did:key:…", "eip155:1:0x…"] }
{ "threshold": 1, "of": [ "eip155:1:0xLedger…",
                          { "threshold": 2, "of": ["did:key:zDn…phone", "did:key:zDn…laptop", "did:key:zDn…yubikey"] } ] }
```

Policies nest. The shape mirrors Bitcoin miniscript `thresh()` and Safe owner
thresholds. A policy is satisfied by a set of signer ids that each produced a valid
signature over the same message. Invalid signatures make the event invalid; they are
never just ignored. A policy's digest is `digest(policy)`.

Future work: timelocks (`after(72h)`) and signer weights, so policies can express
"recovery keys can override within 72 hours" as did:plc does.

## 1.5 Authority levels

| Level | Held by | Can |
|-------|---------|-----|
| **L0 rotation** | the policy committed in `next` (kept cold) | `rotate`: replace the manage policy, optionally revoke all devices, commit a new `next` |
| **L1 manage** | `manage` policy | `add_device`, `revoke_device`, `alias_link`, `alias_unlink`, `alias_commit` |
| **L2 device** | active device keys | sign session grants (`session` cap), commit private aliases (`alias` cap), revoke itself |
| **L3 session** | ephemeral keys certified by a device | sign session tokens and delegations; never appear in the KEL |

**Pre-rotation** comes from KERI. The rotation keys are published only as a hash (`next`)
and are revealed only when they are used. An attacker who steals every *current* key
still can't rotate the identity, because rotation must be signed by keys nobody has seen.

A typical setup looks like Coinbase or Casa:

| Role | Example signers |
|------|-----------------|
| manage | Ledger OR 2-of-3 of my passkeys |
| next | 2-of-3 of {paper key, Safe multisig, hub TOTP co-signer (§2.6)} |
| devices | phone passkey (AAL2), laptop Secure Enclave key (AAL3), browser software key (AAL1) |

## 1.6 Key event log (KEL)

An event:

```json
{
  "v": 1,
  "did": "did:kith:…",          // absent in inception
  "seq": 3,
  "prev": "<digest of event seq-1>",   // absent in inception
  "ts": 1790000000,
  "kind": "add_device",
  "device": { "id": "dev_x", "key": "did:key:zDn…", "name": "phone", "kind": "passkey",
              "aal": 2, "caps": ["session"], "rp_id": "example.com",
              "xkey": "did:key:z6LS…" },
  "sigs": [ { "signer": "…", "alg": "Ed25519", "sig": "…" }, … ]
}
```

| kind | Body | Must be signed by |
|------|------|-------------------|
| `inception` | `manage`, `next`, `devices[]` | manage policy **and** each listed device (proof of possession) |
| `rotate` | `rotation`, `manage`, `next`, `revoke_devices` | `rotation`, which must satisfy `digest(rotation) == state.next` |
| `add_device` | `device` | manage policy **and** the new device key (proof of possession) |
| `revoke_device` | `device_id`, `reason?` | manage policy, or that device itself |
| `alias_commit` | `commitment` | manage policy, or a device with the `alias` cap |
| `alias_link` | `alias` | manage policy |
| `alias_unlink` | `alias` | manage policy |

To verify a log, replay it from `seq 0`.
- Each event must have `seq = prev.seq + 1` and `prev = digest(previous event)`.
- Timestamps must not go backwards.
- Every signature must verify, and the event's authority rule must be met.
- The result is the **key state**: DID, seq, digest, manage, next, active devices,
  revoked device ids, public aliases, and alias commitments.

**Duplicity** means two different valid events for the same `seq`. It is proof that a
controller key signed two histories.
- A hub MUST refuse a log that forks from the one it holds (HTTP 409).
- Verifiers SHOULD treat duplicity as a compromise signal and require a rotation.
- Witnesses (§1.8) make duplicity detectable by third parties.

## 1.7 DID document

The DID document is derived from the key state:
- Each active device becomes a `Multikey` verification method, listed under
  `authentication`, `assertionMethod` and `capabilityInvocation`.
- With key annotations (§1.3.2, draft), each key is listed only under the relationships
  in its `use`, and `keyAgreement` keys appear too.
- Public aliases go in `alsoKnownAs`.
- The hub goes in `service`.
- A `kith` member carries `seq`, `manage` and `next`, so resolvers can see the policy.

## 1.8 Hosting, witnesses and anchoring

A KEL is self-verifying, so where it is stored is only about availability.
- Hubs store logs (`GET/PUT /v1/kel/{did}`).
- Anyone can mirror them, on IPFS, S3 or a git repo.
- Planned:
  - **Witnesses** receipt events, as in KERI, so a verifier can require "k of n
    witnesses saw this event".
  - **Anchoring** is optional. It commits a KEL digest to Ethereum or Bitcoin for a
    public, ordered timestamp. That helps when a manage policy includes an EIP-1271
    contract whose owners change over time.

## 1.9 Relationship to existing DID methods

`did:kith` is deliberately close to three existing methods:
- **did:plc**: self-certifying genesis hash, a signed operation log, a directory for
  availability.
- **KERI**: pre-rotation, witnesses, duplicity.
- **did:webvh**: a web-hosted verifiable history with pre-rotation and witnesses. It is
  DIF-ratified v1.0 and has Rust, TypeScript and Python implementations.

The main differences:
- Signers can be wallets and contract wallets, not only raw keys.
- Policies are nested thresholds per authority level.
- Devices are first-class, with an assurance level and exchange keys.

The open question in [the roadmap](../docs/roadmap.md) is whether to become a did:webvh
profile rather than a new method.
