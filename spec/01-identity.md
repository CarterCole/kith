# 1. Identity

## 1.1 Goals

- One **root identity per person** (or org, or agent) that outlives any single key,
  device, provider or chain.
- Control is a **policy over many signers**, not one key. A signer can be a passkey, a
  hardware key, a software key, an Ethereum account (EOA or contract wallet), or a
  Bitcoin address. Multisig is the normal case.
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
