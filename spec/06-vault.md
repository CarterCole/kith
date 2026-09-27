# 6. Vault: crypto-enforced access (WNFS style)

Everything in §4 is **policy-enforced**: a server holds the data and decides who sees
it. That covers APIs. It does not cover data that sits on untrusted storage (IPFS,
S3, a peer's disk), data that must work offline, or data the server should not be able
to read. For those cases, access has to be **crypto-enforced**: holding the data is
useless without the key.

Fission's [WebNative File System](https://github.com/wnfs-wg/rs-wnfs) (WNFS) solved this
for files. Kith borrows its central primitive, the
[skip ratchet](https://github.com/fission-codes/skip-ratchet-paper). Development
continues under the wnfs-wg organisation (`wnfs` 0.3 on crates.io).

## 6.1 The skip ratchet

A skip ratchet is a hash chain structured like positional numerals. In the
`skip_ratchet` crate it has three digits: small, medium and large.
- Revision `n`'s key is derived from the ratchet state at `n`.
- Anyone holding the state at `n` can derive the keys for `n, n+1, …`. They can jump
  ahead in O(log) steps instead of O(distance).
- Nobody can derive keys for revisions before `n`. The state cannot be run backward.

That gives three kinds of share:

| Share | Grants |
|-------|--------|
| the ratchet state at `n` (a **temporal key**) | this revision and every later one: "from when you joined, onward" |
| one derived key (a **snapshot key**) | exactly one revision |
| a partially flattened state (per the paper) | a bounded range, such as "the rest of this epoch" |

## 6.2 Group keyrings

Each group, or any private collection, has a keyring made of a lineage number, a
revision number, and a ratchet.
- **Write**: advance the revision and encrypt under that revision's key
  (ChaCha20-Poly1305, with AAD = `group|lineage|revision`).
- **Join at revision n**: the member receives the temporal key at `n`. They get
  forward access and no history, matching a dynamic group's "member since".
- **Leave or remove**: **re-key**. Start a new lineage with a fresh ratchet and seal it
  to the remaining members only. A ratchet cannot be un-shared, so removal always means
  a new lineage. The removed member keeps what they already had, as with any
  end-to-end encrypted system.

## 6.3 Sealing to devices

Every device in a KEL may publish an X25519 exchange key (`xkey`). Temporal keys are
sealed to **each active device** of each member:
- X25519 key agreement, then HKDF-SHA256, then ChaCha20-Poly1305.
- The AAD binds the group and the member DID.
- Production should use RFC 9180 HPKE. The current construction is HPKE-shaped.

Because the recipients are the devices listed in the KEL:
- revoking a device automatically excludes it from future shares;
- adding a device can trigger re-sealing the current temporal keys to it.

## 6.4 Who gets keys: stewards

Cedar still decides membership, including dynamic, proposition-based groups. A
**key steward** turns decisions into keys. The steward is the hub, a group admin's
device, or a threshold of admins. It:
1. evaluates membership (§4.3);
2. seals the current temporal key to each new member's devices;
3. re-keys when a member drops out, for example when their email domain changes or
   their AAL-based rule stops matching.

This is the one place where crypto enforcement needs an online party. Propositions
can't be evaluated by math alone, so someone has to watch the attributes. A threshold of
stewards removes the single point of trust.

## 6.5 Relationship to WNFS

Kith's plan is to **integrate with rs-wnfs rather than reimplement it**:
- WNFS provides the file system: the private forest, HAMT, name accumulators, and
  content-addressed blocks.
- Kith provides:
  - identity (`did:kith` as the WNFS root agent);
  - device exchange keys (in place of WNFS's per-device exchange-key directory);
  - group membership and stewards (the answer to "share with the finance group,
    including whoever joins later");
  - UCAN-style delegation for write access.

`kith_core::vault` implements the key schedule on the same `skip_ratchet` crate WNFS
uses, so a WNFS private node's ratchet and a Kith group keyring are the same object.
It includes tests for join-later, skip-ahead, re-key exclusion, and sealing to devices
from a KEL.
