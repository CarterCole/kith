# Prior art

What exists, what Kith borrows, and why it doesn't just adopt one of them. Status as
of September 2026.

## Identity and key management

| Project | What it is | What Kith takes |
|---------|------------|-----------------|
| [W3C DID Core](https://www.w3.org/TR/did-1.1/) | The standard DID data model. DID 1.0 is a Recommendation. DID 1.1 and DID Resolution are Candidate Recommendations (March 2026). | `did:kith` resolves to a conforming DID document (Multikey verification methods, `alsoKnownAs`). |
| [KERI](https://trustoverip.github.io/kswg-keri-specification/) (ToIP) | Key event logs, **pre-rotation**, witnesses, duplicity detection. | The KEL and pre-rotation design. Not adopted wholesale because CESR encoding and the ecosystem add heavy complexity, and KERI has no wallet or contract signers. |
| [did:plc](https://web.plc.directory/spec/v0.1/did-plc) (Bluesky) | Self-certifying genesis hash, a signed operation log, and ordered `rotationKeys`. A higher-priority key can override within 72 hours. | The genesis-hash identifier and hub-as-directory model. The 72-hour recovery window is planned for co-signed rotations. |
| [did:webvh](https://identity.foundation/didwebvh/v1.0/) (DIF, ratified v1.0) | A web-hosted verifiable history with SCID, pre-rotation, and witnesses. Rust, TypeScript and Python implementations exist. | The closest existing method. **Open question**: ship `did:kith` as a did:webvh profile? See the [roadmap](roadmap.md). |
| [Keybase](https://book.keybase.io) | Per-user sigchains, per-device keys, "paper keys", and social proofs. | The device model, paper-key recovery, and bidirectional public alias proofs. |
| [Keyoxide / Ariadne](https://keyoxide.org) | Decentralized identity proofs (DNS, GitHub, fediverse). | Back-link formats for public aliases. |
| [Farcaster](https://github.com/farcasterxyz/protocol/blob/main/docs/SPECIFICATION.md) | A custody address (Ethereum) holds an fid. It adds and removes Ed25519 app signer keys through KeyRegistry, with an optional recovery address. | Validates the model: a wallet root delegates to app and device keys. Kith generalizes it to policies of many signer types, and keeps the log off chain. |
| Coinbase Smart Wallet, [Safe](https://safe.global), Casa | Passkey or multisig owned accounts, EIP-1271 signatures, and co-signer services. | Contract wallets as signers (EIP-1271, with ERC-6492 for undeployed wallets). The TOTP co-signer follows the Casa/Coinbase pattern. |
| Bitcoin miniscript / descriptors | Composable spending policies (`thresh`, `and`, `or`, `after`). | The signer policy shape. Timelocks are planned. |

## Authentication

| Project | Takeaway |
|---------|----------|
| **WebAuthn / passkeys** | Devices are passkeys. Kith sets the challenge to SHA-256(message) so one passkey can sign logins, grants and key events. |
| [EIP-4361 SIWE](https://eips.ethereum.org/EIPS/eip-4361) (Final), [CAIP-122 SIWx](https://chainagnostic.org/CAIPs/caip-122) | The challenge message format, so wallets render it well. |
| [BIP-322](https://github.com/bitcoin/bips/blob/master/bip-0322.mediawiki) (Complete; v2.0.0 June 2026) | Bitcoin wallet signatures. Planned. |
| RFC 6238 TOTP | A hub-side factor, plus the co-signer bridge into multisig. |
| NIST SP 800-63B | The `aal` levels and how factors combine. |
| [W3C Digital Credentials API](https://developer.chrome.com/blog/digital-credentials-api-shipped) | Stable in Chrome 141 and Safari 26 (September 2025). Lets a website request an mDL or ID from the OS wallet. Kith's attribute source for government ID (see [passports](passports.md)). |

## Tokens and delegation

| Project | Takeaway |
|---------|----------|
| RFC 9068 (JWT access tokens), RFC 8693 (token exchange, `act`), RFC 9449 (DPoP) | The hub speaks plain OAuth, so every framework can consume it. |
| [UCAN](https://github.com/ucan-wg/spec) v1.0 (Fission and others) | Capability delegation chains, now DAG-CBOR plus varsig rather than JWT. Kith's delegation token is UCAN-shaped (`iss`, `sub`, `cap`, attenuation). Planned: accept UCAN 1.0 delegations directly. |
| [Biscuit](https://github.com/eclipse-biscuit/biscuit-rust) (Eclipse; Rust 6.0, wasm, Python) | Datalog authorization tokens with offline attenuation. A candidate format for multi-hop delegation. |
| Macaroons, ZCAP-LD | Earlier caveat and capability designs. Same attenuation principle. |
| [GNAP](https://www.rfc-editor.org/info/rfc9635/) (RFC 9635) | A cleaner successor to OAuth for key-bound clients. Worth tracking; not needed yet. |
| [OpenID Federation 1.0](https://openid.net/openid-federation-1-0-final-specification-approved/) (Final, February 2026) | For federating many hubs: trust chains between hubs. |

## Authorization

| Project | Takeaway |
|---------|----------|
| [Cedar](https://www.cedarpolicy.com) (CNCF Sandbox) | **Adopted** as the policy and proposition language. See [spec §4.7](../spec/04-authorization.md#47-why-not-) for the comparison with OPA, CEL, Zanzibar and Biscuit. |
| Azure AD / Entra dynamic groups, Okta group rules | Prior art for proposition-defined membership. Kith makes the rules portable and evaluable client-side. |
| Google Zanzibar, OpenFGA, SpiceDB | Relationship-based access. Complementary: it could feed `in` relationships into Cedar entities. |
| Hasura permissions, Postgres RLS, graphql-shield | GraphQL row and field rules. Kith's `@auth` plus row-level filtering is the portable version. Partial-evaluation pushdown is planned. |

## Encrypted data

| Project | Takeaway |
|---------|----------|
| [Skip ratchet](https://github.com/fission-codes/skip-ratchet-paper) / [WNFS](https://github.com/wnfs-wg/rs-wnfs) | **Adopted** for crypto-enforced group access ([spec §6](../spec/06-vault.md)). |
| MLS (RFC 9420) | Group key agreement with post-compromise security for *messaging*. It is the better choice when members are online and interactive. The skip ratchet is better for storage shared with changing, offline groups. |

## Distribution, revocation and time

| Project | Takeaway |
|---------|----------|
| IPFS / IPLD (DAG-JSON, CIDv1, trustless gateways) | **Adopted** as the block format ([spec §8](../spec/08-policy-dag.md)). Any gateway or pinning service can serve policy blocks. |
| ATProto repositories (Merkle search tree, signed commits, did:plc) | The closest prior art: a signed root over a Merkle map, rooted in a self-certifying DID. Kith's map is a HAMT, and adds indexes built for policy slicing. |
| CRLs, OCSP stapling, CRLite | Grants propagate slowly, revocations are pushed. Kith's heartbeats play the part of stapled OCSP responses: any client can carry them. |
| [drand](https://drand.love) (League of Entropy) | **Adopted.** It is the default heartbeat beacon: threshold BLS, 3 s rounds, verifiable offline. |
| [NIST Interoperable Randomness Beacons](https://csrc.nist.gov/projects/interoperable-randomness-beacons) | **Supported** (the 2.0 format: NIST, Brazil). Pulses come every 60 s, RSA-signed. |
| [OpenTimestamps](https://opentimestamps.org) | **Adopted** for anchoring policy roots and revocations to Bitcoin (§8.10). |
| KERI witnesses | Planned for heartbeats. Several relays co-signing heads would make withholding detectable. |

## The Wave analogy

Google Wave was a protocol (federation over XMPP), a spec (operational transform), and
implementations. What sank it was mostly product, but also that the open implementation
lagged the hosted one. Kith's structure tries to prevent that:
- the spec is normative;
- the conformance vectors are shared;
- the hub is optional, because a KEL verifies without it;
- resource servers need nothing Kith-specific beyond a JWKS and Cedar.
