# 8. Policy DAG, revocations and freshness

§4 defines the policy bundle as one JSON document. That works while every verifier
can fetch and hold the whole thing. It stops working when:
- a browser session only needs to decide one GraphQL field;
- a device wants only its own grants;
- verifiers are offline, or fetch from peers or IPFS rather than a hub.

This chapter stores a bundle as **content-addressed blocks with indexes**. A reader
fetches only the slice it needs, from anyone, and can prove the slice is complete.
Grants reach verifiers eventually. Revocations are pushed as a signed chain,
with **heartbeats** that embed a public randomness beacon. A verifier chooses how
stale its view may get, and fails closed after that.

```
 org did:kith KEL ── policy_root {root: bagu…, revocations_through: 7}   (manage policy signs)
                               │
          ┌────────────────────┴───────────────────────────────┐
          │ root: actions · principals · sets · members · dir  │   content-addressed,
          └──┬──────────┬───────────┬──────────┬───────────────┘   pinned by whoever
             ▼          ▼           ▼          ▼                   needs them
          policy     policy      Group::    Role::…
          blocks     blocks      finance

 revocation chain:  #8 ─prev─▶ #9 ─prev─▶ #10          (revoke devices sign, pushed)
 heartbeat:         {seq: 10, head: <digest #10>, beacon: drand round 1234567}  every few s
```

## 8.1 Blocks and CIDs

- A **block** is canonical JSON (see [README](README.md#conventions)). A link to
  another block is the object `{"/": "<cid>"}`. Every block is therefore valid
  DAG-JSON, and can be pinned on IPFS and fetched from any trustless gateway.
- A **CID** is CIDv1, codec `dag-json` (0x0129), multihash sha2-256, multibase
  base32 lower case. CIDs start with `bagu`.
- A reader MUST check every block it uses against its CID. So a block store never
  needs to be trusted: a hub, an IPFS gateway, a peer and a local cache are all equal.
- Test: `{"hello":"world"}` has CID
  `baguqeerasords4njcts6vs7qvdjfcvgnume4hqohf65zsfguprqphs3icwea`, as computed by
  `@ipld/dag-json` + `multiformats`.

## 8.2 Merkle map

The indexes are hash-array-mapped tries whose shape depends only on their contents.
- A node holding at most 8 entries is a **leaf**: `{"e": [[key, value], …]}`, sorted
  by key (UTF-16 code units).
- A larger node is a **branch**: `{"c": [link | null, …]}` with exactly 16 slots. An
  entry goes to slot `nibble(d, SHA-256(key))` at depth `d`: the high nibble of byte
  `d/2` for even `d`, the low nibble for odd `d`.
- A lookup reads one node per level. Reaching a leaf without the key, or a `null`
  slot, is a **proof of absence**. That is what makes slices complete: "these are all
  the policies for `Query.invoices`" is a lookup result, not a claim.

## 8.3 Layout

The root block:

```json
{
  "kith": "kith-policy-dag/1",
  "version": 1,
  "actions":    {"/": "<map: action id | \"*\" → [policy links]>"},
  "principals": {"/": "<map: \"User::<did>\" | \"Group::<x>\" | \"Role::<x>\" | \"*\" → [policy links]>"},
  "sets":       {"/": "<map: \"Group::<x>\" | \"Role::<x>\" → set link>"},
  "members":    {"/": "<map: principal id → [\"Group::<x>\", …]>"},
  "directory":  {"/": "<map: principal id → {\"attrs\": {…}}>"},
  "rules":      ["Group::staff", "…"]
}
```

A **policy block** holds one Cedar policy:

```json
{"id": "read-invoices", "effect": "permit",
 "text": "@id(\"read-invoices\")\npermit(principal in Role::\"billing-reader\", …);",
 "refs": ["Role::billing-reader"]}
```

- `id` is the `@id` annotation, or Cedar's positional id (`policy0`, …) if there is
  none. Ids MUST be unique.
- `refs` lists every `Group::` and `Role::` entity the policy mentions, in its scope
  or its conditions. Readers use it to know which sets to fetch.

A **set block** holds one group or role:

```json
{"kind": "Role", "name": "billing-reader", "members": ["group:finance"],
 "deps": ["Group::finance"], "dependents": []}
```

- `deps` are the sets its membership depends on: `group:`/`role:` members and the
  sets its `rule` mentions.
- `dependents` is the reverse edge. Sets refer to each other by key, not by link, so
  the graph can have cycles while the blocks stay a DAG.

Directory attributes are stored after the Cedar value conversion of §4.2: nulls
dropped, non-integers stringified.

## 8.4 Filing rules (normative)

A builder MUST file every policy as follows. A reader relies on it for completeness.
- **By action.**
  - `action == A` goes under `A`.
  - `action in [A, B]` goes under both `A` and `B`.
  - An unconstrained action goes under `*`.
  - Action keys are the action's id; a non-`Action` entity type uses `Type::id`.
- **By principal.**
  - `principal == E`, `principal in E` and `principal is T in E` go under `E`,
    written `Type::id` without quotes.
  - An unconstrained principal, or `principal is T`, goes under `*`.
- Forbids are filed exactly like permits. A slice cannot contain a permit for an
  action and leave out a forbid for the same action.

## 8.5 Slices

A **query** is one of:
- `{"kind": "actions", "actions": [...], "principals": [...]}`: enough to decide those
  actions, for any principal whose directory entry is included.
- `{"kind": "principal", "id": "<did>"}`: every grant that can apply to one
  principal, across all actions.

Loading a slice:
1. Fetch the root. The root CID comes from the org's latest `policy_root` event (§8.6).
2. Policies:
   - **actions:** look up each action and `*` in `actions`.
   - **principal:** compute the candidate sets `U`, then look up `User::<id>`, `*` and
     every set in `U` in `principals`. `U` is the closure under `dependents` of the
     sets that list the principal in `members`, plus every set in `rules`.
     `U` contains every set the principal could possibly be in.
3. Sets: fetch the closure under `deps` of every policy's `refs`, plus `U`.
4. Directory: look up each principal.

**Property (normative, tested):** evaluating a slice with §4.3 and §4.4 gives the same
membership and the same decision as the full bundle, for the queried actions or
principal. `kith-core` checks this against every vector in `test-vectors/authz.json`.
It also checks that withholding any block makes loading fail, rather than succeed
with less.

`test-vectors/policy-dag.json` pins the root CID of the vector bundle, the blocks, and
the expected contents of several slices.

## 8.6 Organizations and the policy root

- An organization is an ordinary `did:kith`.
- A `policy_root` event in its KEL commits to the current DAG:

  ```json
  {"kind": "policy_root", "root": "bagu…", "revocations_through": 7}
  ```

  - It MUST satisfy the manage policy, so the org's admin quorum signs every grant.
  - `revocations_through` MUST NOT decrease. Entries up to it are already reflected
    in the new bundle, and verifiers drop them (compaction).
- A device with the capability `revoke` may sign revocation entries and heartbeats,
  and nothing else. A hub that signs heartbeats for an org holds one such key
  (`kith policy add-revoker`).
  - If a revoke key is stolen, the attacker can revoke access or withhold
    heartbeats, which is denial of service. They can never grant access.

## 8.7 Revocation chain

```json
{"v": 1, "org": "did:kith:…", "seq": 9, "prev": "<digest of #8>", "ts": 1790000000,
 "revoke": [{"kind": "member", "id": "did:kith:ada…", "set": "Group::finance"}],
 "sigs": [ … ]}
```

- `seq` starts at 1. `prev` is the digest of the previous entry, and is absent only
  for entry 1.
- Digest: `base64url(SHA-256(canonical JSON without sigs))`.
- Signing message: `kith revocation v1\norg: <org>\nseq: <seq>\ndigest: <digest>`.
- Signers: the manage policy, or one `revoke` device.
- Two different entries with the same `seq` are **duplicity**. A verifier that sees
  both MUST treat the org as `forked` and deny everything until an operator steps in.

Revocation kinds. Each one only ever removes access:

| kind | effect |
|------|--------|
| `principal {id}` | deny everything for the principal |
| `member {id, set}` | the principal is never a member of `set`; sets that depended on it are recomputed without it |
| `device {did, device}` | treat the device as revoked before its own KEL catches up |
| `policy {id}` | drop that **permit**. A `policy` revocation naming a forbid is ignored |
| `token {jti}` | deny that token or session |

- Memberships in a token (`groups`, `roles`) are a cache. A verifier applying
  `member` revocations MUST recompute memberships from a slice, not filter the token's
  list. For example, removing Ada from `finance` also removes `billing-reader`, which
  she held through `group:finance`.

## 8.8 Heartbeats, beacons and freshness

```json
{"v": 1, "org": "did:kith:…", "seq": 10, "head": "<digest of #10>", "ts": 1790000123,
 "beacon": {"type": "drand", "chain": "52db9ba7…", "round": 21000000, "signature": "…"},
 "sigs": [ … ]}
```

- Signing message: `kith revocation heartbeat v1\norg: <org>\nseq: <seq>\ndigest: <digest>`.
- `seq`/`head` name the newest entry. If a verifier holds entry `seq` with a
  different digest, that is duplicity.
- **The beacon proves the heartbeat is recent.** A beacon value can't be predicted
  before it is published. So a heartbeat that embeds one was signed after that
  moment, even by a signer with a wrong clock, and even by someone who briefly had
  signing access and tried to pre-sign a year of "nothing revoked". The heartbeat's
  **proven time** is the beacon's publication time.

Beacon types:

| `type` | source | period | publication time |
|--------|--------|--------|------------------|
| `drand` | League of Entropy drand, default chain *quicknet* (`52db9ba7…e971`). BLS12-381, signature on G1, over `SHA-256(round as 8 bytes big-endian)` | 3 s | `genesis + (round − 1) · period` |
| `nist2` | NIST Interoperable Randomness Beacon 2.0 pulse, verbatim. The same format is published by the Chilean and Brazilian beacons | 60 s | the pulse's `timeStamp` |

- A verifier MUST verify the beacon: the BLS signature against the chain's public key
  for drand, and the pulse's RSA signature and `outputValue` for NIST 2.0.
- A NIST 2.0 verifier MUST only accept pulses from origins it trusts. It fetches the
  signing certificate from that origin's `/certificate/{certificateId}`, and checks
  that its SHA-512 is the `certificateId`.

**Freshness.** Each verifier configures:

| setting | meaning | default |
|---------|---------|---------|
| `fresh_for` | age (s) up to which the view is *fresh* | 120 |
| `max_staleness` | age (s) up to which the view is *degraded*. Beyond it, deny everything. This is "how long I can go between syncs" | 900 |
| `require_beacon` | only beacon-backed heartbeats count | true |

- `age = clock − newest proven time`, where `clock` never goes backwards: it is the
  largest time the verifier has observed. Rolling the system clock back can't make a
  stale view look fresh.
- Levels, in order of precedence:

  | level | when | decisions |
  |-------|------|-----------|
  | `forked` | duplicity seen | all denied |
  | `behind` | a heartbeat or entry names a `seq` beyond the contiguous entries held | all denied until the gap is filled |
  | `stale` | no proven heartbeat, or `age > max_staleness` | all denied |
  | `degraded` | `fresh_for < age ≤ max_staleness` | allowed; policies see `degraded` |
  | `fresh` | `age ≤ fresh_for` | allowed |

- A device that syncs once a day sets `max_staleness: 86400`. A payments service sets
  `60`. They follow the same chain.

**Per-action budgets.** Policies see `context.kith`:

```json
{"sync_age": 42, "degraded": false, "revocation_seq": 10}
```

So a policy can demand a fresher view than the verifier's global budget:

```cedar
@id("pay-needs-fresh")
forbid(principal, action == Action::"Mutation.payInvoice", resource)
  unless { context has kith && context.kith.sync_age < 60 };
```

Write freshness forbids with `unless { context has kith && … }` as above. A `when`
condition that errors on a missing `kith` skips the forbid, which fails *open*.

## 8.9 Deciding with revocations (normative)

1. If the level is `forked`, `behind` or `stale`, deny with reason `freshness:<level>`.
2. If the principal is revoked, deny with `revoked:principal`. If the token's `jti` is
   revoked, deny with `revoked:token`.
3. Remove revoked permit policies from the slice.
4. Recompute memberships from the slice with the revoked `(principal, set)` pairs
   excluded (§4.3, where an excluded set never joins).
5. Evaluate with `context.kith` set.

## 8.10 Anchoring with OpenTimestamps

A beacon proves a heartbeat is **no older than** some time. An OpenTimestamps proof
proves a digest existed **no later than** a Bitcoin block. Together they bracket
checkpoints in time.

- Anchor the digest of each `policy_root` event, and a revocation entry digest
  periodically (hourly, say). OpenTimestamps calendars aggregate submissions, so
  this is free.
- An anchored history can't be rewritten or backdated, even by the admin quorum.
  That answers disputes like "was Ada revoked before 14:02?".
- Anchoring is for audit. It isn't on the decision path: Bitcoin confirmation takes
  hours.
- `kith anchor stamp|upgrade|verify` work with standard `.ots` files, so the
  reference `ots` client can check them too.

## 8.11 Transport

Everything is signed or content-addressed, so any transport works. The reference hub
offers:

| endpoint | purpose |
|----------|---------|
| `PUT /v1/blocks`, `GET /v1/blocks/{cid}`, `GET /ipfs/{cid}` | block store. The last is shaped like an IPFS trustless gateway (`application/vnd.ipld.raw`) |
| `GET /v1/policy/{org}`, `POST /v1/policy/{org}/slice` | root and slice with proof blocks. The response is a convenience; readers check it against the KEL |
| `GET/POST /v1/revocations/{org}` | entries after `?after=N`, append the next entry |
| `GET /v1/revocations/{org}/heartbeat` | newest heartbeat |
| `GET /v1/revocations/{org}/events` | server-sent events `entry` and `heartbeat` (push) |

- Clients MAY attach the newest heartbeat to requests, like OCSP stapling, so
  resource servers learn about new revocations from their own traffic.
- A heartbeat whose `seq` a server doesn't hold makes it `behind`. It fetches the
  missing entries from anyone, since they are signed.

## 8.12 Security notes

- **Withholding.** A block source can refuse to serve blocks. Loading then fails; it
  can never succeed with a policy missing. A relay can withhold heartbeats. The
  verifier then ages into `degraded` and then `stale`, after the budget it chose.
- **Replay.** Old heartbeats are valid but old: their proven time doesn't move.
- **Pre-signed heartbeats.** They are impossible, because they would need future
  beacon values.
- **Compromised revoke key.** It can cause denial of service only. Remove the device
  from the org KEL, which needs the manage policy.
- **Privacy.** A DAG on public IPFS reveals group membership and directory
  attributes. Keep public DAGs to policies and rules. Put the `members` and
  `directory` maps behind the vault (§6), or serve them only to authenticated
  readers.
- **Why not TOTP?** TOTP is a shared-secret HMAC of the time. Every verifier would
  hold a secret that lets it forge heartbeats, and the secret holder can compute codes
  for any future window. TOTP stays a human factor (§2).
