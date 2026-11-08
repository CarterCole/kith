# 10. Delegated administration

> Status: draft for discussion. The reference code does not implement this chapter
> yet, and there are no test vectors.

Two things are missing from §4 and §8:
- **Provenance.** An access token's `roles` is the hub's word. Nothing in the token
  names the org whose bundle defined the role, so one org's `admin` looks the same as
  another's. A resource server cannot tell a role the org's quorum granted from one
  written by whoever can edit the hub's bundle file or holds its signing key.
- **Anything between all and nothing.** Changing any group or role needs the org's
  manage policy (§8.6). The only way to let someone manage `blog-editor` is to let
  them sign the whole root, and the whole root includes `admin`.

This chapter adds **grants**. The org's quorum signs a grant in its root that lets
another identity decide the members of some sets. That identity publishes its own
signed **delegated root** holding those sets, and may pass a narrower grant on. A
verifier walks the chain from the org's KEL to each membership, the same way it walks a
session chain to a device (§3.3).

**The org decides what a set can do. A delegate decides who is in it.** Policies and
directory attributes stay in the org root. A delegate can never write either.

This is not §3.3 delegation. A delegation token lets someone act *as you*, within
capabilities. A grant lets someone decide *who is in a set*, within a scope.

```
 org KEL ── policy_root ──▶ org root
                             ├─ sets         Role::admin {members: [did:kith:carter…]}     only the quorum
                             ├─ policies     permit(principal in Role::"blog-editor", action in […], resource);
                             └─ delegations  blog ─▶ grant {to: did:kith:ada…, sets: [Role::blog-*],
                                                            may: [members], redelegate: 1}
                                                       │
 Ada's keys ── delegated root #4 {grant: <cid>} ──▶ Ada's sub-root
                                                     ├─ sets         Role::blog-editor {members: [did:kith:bob…]}
                                                     └─ delegations  comments ─▶ grant {to: did:kith:cy…,
                                                                                  sets: [Role::blog-commenter],
                                                                                  may: [members], redelegate: 0}
                                                                          │
 Cy's keys ── delegated root #1 ──▶ Cy's sub-root: Role::blog-commenter {members: […]}
```

Here Ada can put anyone in `Role::blog-editor` and pass a smaller grant to Cy. She
cannot add herself to `Role::admin`, which is outside her scope. She cannot write a
policy or give Cy a grant that may grant again. Each attempt makes her sub-root invalid
(§10.3), and it then contributes nothing.

## 10.1 Grants

A **grant block** is a DAG-JSON block (§8.1):

```json
{"kind": "grant", "to": "did:kith:ada…", "sets": ["Role::blog-*"], "may": ["members"],
 "require": "principal has aal && principal.aal >= 2", "redelegate": 1, "exp": 1800000000,
 "note": "blog editors"}
```

| field | meaning |
|-------|---------|
| `to` | the delegate, a `did:kith` |
| `sets` | the **scope**: set keys (`Group::x`, `Role::x`) or patterns. A trailing `*` is a prefix glob, as in capabilities (§3.3). A pattern MUST start with `Group::` or `Role::`, and `*` MAY appear only as its last character |
| `may` | what the delegate may write in those sets: `members` (explicit members), `rules` (dynamic rules, §4.3), or both. Not empty |
| `require` | optional. A Cedar expression every member through this grant must satisfy, like a rule. ARBAC97 calls this the prerequisite condition |
| `redelegate` | how many more hops may follow this one, 0 to 7. 0 means the delegate may not grant again |
| `exp` | optional. Unix seconds after which the grant is void |
| `note` | optional, for people |

Grants live in a `delegations` member: a Merkle map (§8.2) from a grant id to a grant
link. The org root gains one (§8.3):

```json
{"kith": "kith-policy-dag/1", …, "delegations": {"/": "<map: grant id → grant link>"}}
```

A delegated sub-root (§10.2) may have one too, holding the grants its delegate passes
on. A grant id is a name for people, unique within its map. A grant's identity is its
CID.

## 10.2 Delegated roots

A delegate publishes its sets with a signed **delegated root statement**:

```json
{"v": 1, "org": "did:kith:…", "grant": "bagu…", "seq": 4, "ts": 1790000000,
 "root": "bagu…", "sigs": [ … ]}
```

- `grant` is the CID of the grant this statement uses. `root` is the CID of the
  delegate's sub-root.
- Digest: `base64url(SHA-256(canonical JSON without sigs))`.
- Signing message: `kith delegated root v1\norg: <org>\ngrant: <grant cid>\nseq: <seq>\ndigest: <digest>`.
- Signers: the manage policy of the grant's `to`, or one active device of `to` with the
  `assign` capability (a new device cap, §1.5). Signatures are checked against the
  delegate's **current** key state. A statement whose signing device is later revoked,
  or whose manage policy is later rotated away, stops counting. The delegate signs it
  again with a current key.
- `seq` starts at 1 and increases for each `(org, grant)`. A verifier uses the
  statement with the highest `seq` it holds and ignores lower ones.
- Two different statements with the same `seq` and the same grant are duplicity. A
  verifier that holds both ignores that grant, and every grant below it, until it
  sees a statement with a higher `seq`. Other grants are not affected.
- `ts` is the signer's claim. It is for audit only.

A **sub-root** is a block shaped like an org root, with only two members:

```json
{"kith": "kith-delegated/1",
 "sets":        {"/": "<map: \"Group::<x>\" | \"Role::<x>\" → set link>"},
 "delegations": {"/": "<map: grant id → grant link>"}}
```

Set blocks are §8.3 set blocks. `delegations` may be absent. A sub-root has no
`members` or `rules` index: a reader loads all of its set blocks (§10.6).

## 10.3 Chain validity (normative)

A grant `g` is **valid** at time `t` when all of these hold. `t` is the verifier's
clock as defined in §8.8, which never goes backwards.
1. Its parent is valid:
   - either `g` is in the `delegations` of the org's current root (§8.6);
   - or `g` is in the `delegations` of the sub-root named by the statement a valid
     grant `p` currently uses, and `g` narrows `p` (below).
2. It is not expired: `exp` is absent, or `t < exp`.
3. Neither `g.to` nor the `to` of any grant above it is revoked by `principal` or
   `delegate` (§10.7).
4. It is at most 8 hops from the org root. A verifier MUST refuse deeper chains.

**`g` narrows `p`** when:
- every pattern in `g.sets` is covered by a pattern in `p.sets`. `P` covers `Q` if
  `P = Q`, or `P` ends in `*` and `Q` starts with `P` without its `*`;
- `g.may ⊆ p.may`;
- `g.redelegate < p.redelegate`;
- `p.exp` is absent, or `g.exp` is present and `g.exp ≤ p.exp`.

A grant that fails a narrowing rule is invalid, and so is every grant below it. A
parent's `require` is not copied into the child. It applies anyway, because §10.5
evaluates every `require` on the chain.

**A sub-root is valid for a valid grant `g`** when all of these hold:
- every key in `sets` is covered by `g.sets`, and every set block's `kind` and `name`
  match its key;
- a set block has `members` only if `g.may` has `members`, and a `rule` only if
  `g.may` has `rules`;
- every rule compiles to exactly one Cedar policy (§4.3), and names no
  delegation-dependent set (§10.4);
- `delegations` is absent or empty when `g.redelegate` is 0;
- it has no other members. A sub-root with `actions`, `principals`, `members`,
  `rules`, `directory`, `policies`, `attributes` or `schemas` is invalid;
- it is shaped as this section says. A malformed block makes the whole sub-root
  invalid. It is never partly read.

An invalid sub-root contributes nothing, and its `delegations` grant nothing. It is
never partly applied.

Members may name any set as `group:x` or `role:x`, inside the scope or outside it.
`members: ["role:admin"]` makes every admin a blog editor. That grants
`blog-editor`, and nothing about `admin`.

## 10.4 Building an org root with delegations (normative)

A **delegated set** is one whose key some pattern in a grant of the org root covers.
Sub-grants narrow their parents, so the org root alone says which sets are delegated.

A set is **delegation-dependent** if it is delegated, or if its `members` name a
delegation-dependent set.

A builder MUST reject a bundle unless:
1. no forbid names a delegation-dependent set, in its scope or its conditions;
2. a permit names a delegation-dependent set only in its principal scope
   (`principal in Role::"x"`), never in a condition or in its resource scope;
3. no rule and no `require` names a delegation-dependent set. To build on a delegated
   set, list it in `members` (`role:blog-editor`);
4. every grant is well formed (§10.1), and its `require` compiles to exactly one Cedar
   policy, as a rule does;
5. `sets` has a block for every delegated set that an org-root set or policy names,
   with its `dependents`, even when the org defines no members for it. Slices follow
   `dependents` edges from those blocks (§10.6).

**Why.** Under these rules, a delegated membership appears only in places where it
grants. A permit's principal scope and a set's `members` list only ever add access.
So **removing any statement, sub-root or grant from a verifier's view never turns a
deny into an allow.** Withholding fails closed. A stale view, or a delegate that never
publishes, costs grants and never costs a forbid. Without rule 1, a delegate who
manages `Group::contractors` could make a `forbid(principal in Group::"contractors", …)`
fail open, just by having a block source withhold its sub-root.

This property is normative. The vectors (§10.10) test it by removing each statement in
turn.

## 10.5 Membership (normative)

§4.3 runs over the union of the org root's sets and the in-scope sets of every valid
sub-root:

```
G, R := ∅, ∅
repeat at most |sets| + 1 times:
    for each set S (groups, then roles, in name order) not yet in G or R:
        S is a member set if
           S's org-root definition makes it one (§4.3),
        or for some valid grant g with a valid sub-root that defines S:
               (the principal id ∈ S.members,
                or group:X ∈ S.members with X ∈ G,
                or role:X ∈ S.members with X ∈ R,
                or S.rule evaluates to true for User(principal) whose parents are G ∪ R)
           and every require on g's chain, from the org root down to g,
               evaluates to true for User(principal) whose parents are G ∪ R
    stop when nothing changed
```

- Contributions are a union. The org root and several delegates may all define
  members of one set.
- `require` limits membership *through that grant*. It does not limit the org root's
  own definition of the set, or another grant's.
- An evaluation error, in a rule or a `require`, means "not a member".
- A `member {id, set}` revocation excludes the set as in §4.3, whatever defined it.

## 10.6 Slices

Loading a slice (§8.5) gains one step after fetching the root:
- Walk every valid grant from the org root down. For each grant, fetch the statement
  it uses, that statement's sub-root, and every set block in the sub-root.
- **principal** queries: add to `U` every delegated set that names the principal in
  its `members` or has a `rule`. Close `U` under the reverse of `deps`, across the org
  root and every sub-root. A sub-root's blocks cannot list `dependents` in other
  sub-roots, which is why the reader loads them all.
- **actions** queries: the same, for each listed principal.

Delegated sets are meant to be small: who edits the blog, not every customer. A
membership list that large belongs in the org root, where slices fetch only what a
principal needs.

Delegated data comes with no completeness proof, and needs none: by §10.4, missing
delegated data can only deny. Org-root data keeps its proofs (§8.5). A sub-root that
fails to load is treated as absent, not as an error. Withholding one delegate's blocks
must not take down the org.

A slice response (§8.11) includes the statements it used, so a reader without its own
copy can check them.

## 10.7 Revocation

The revocation chain (§8.7) gains one kind, and one existing kind gains an effect:

| kind | effect |
|------|--------|
| `delegate {id}` | void every grant to `id` in this org, at every depth, and every grant below them |
| `principal {id}` | as before, and also void every grant to `id` |

- Signers do not change: the manage policy, or one revoke device. A delegate never
  signs the org's chain. A chain with many signers is one any of them can fork, and a
  fork denies the whole org (§8.8).
- A delegate removes people in two ways:
  - republish its sub-root without them. This takes effect eventually, as a new org
    root does;
  - ask for a `member` revocation, which takes effect within heartbeat freshness.
- The reference hub's revoker appends a `member {id, set}` revocation when a delegate
  asks for one, if that delegate's valid chain covers `set`. The request is signed like
  a statement, with the signing message
  `kith revocation request v1\norg: <org>\ndigest: <digest>`. A revoke device can already
  sign any revocation, so this gives the delegate no new power. The hub keeps the
  request for audit.

## 10.8 Provenance in access tokens

Two claims join the access token (§3.5):

```json
{"org": "did:kith:…", "pol": {"root": "bagu…", "rev": 10}}
```

- `org` is the org whose policy produced `groups` and `roles`. `pol.root` is the root
  they were computed from, and `pol.rev` is the newest revocation entry applied.
- A hub that takes memberships from an org (§8.6) MUST include both. A hub that takes
  them from a bundle file MUST omit both. Such memberships have no provenance.
- A resource server configured with an org MUST ignore `groups` and `roles` in a token
  whose `org` is absent or names another org. It still accepts the token as
  authentication.
- These claims do not remove trust in the hub. A hub with its signing key can write
  any claim. For decisions where that matters, a resource server recomputes
  memberships from a slice (§8.9, §10.5) and trusts the hub for nothing but
  availability.

## 10.9 Hub and CLI (planned)

| What | Does |
|------|------|
| `kith policy grant <did> --sets 'Role::blog-*' --may members [--require …] [--redelegate N] [--exp …]` | add a grant to the org's bundle and publish a new root (needs the manage policy) |
| `kith policy publish --grant <cid> <bundle.json>` | as a delegate: build a sub-root, sign a statement, upload both |
| `kith policy chain <did>` | print every grant chain that gives `did` a membership, and why each link is valid |
| `GET /v1/policy/{org}/delegated` | the current statement for each grant |
| `PUT /v1/policy/{org}/delegated` | upload a statement. The hub checks the chain and the sub-root before it stores either |
| `POST /v1/revocations/{org}/requests` | a delegate's signed `member` revocation request (§10.7) |

In org mode the admin API (§7.10) never writes policy. A hub admin changes memberships
only through a grant the org signed, like anyone else. That closes the gap where any
identity in `hub-admin` could edit the bundle and give itself any role.

## 10.10 Security notes

- **A wide pattern hands out a lot.** `Role::*` lets the delegate put anyone in any
  role, `admin` included. Keep the sets that define the org out of every pattern, and
  name them so no likely pattern covers them.
- **Rules are wide too.** With `rules` in `may`, the rule `true` makes everyone a
  member. Use `require` to bound it, or grant `members` only.
- **Revoking a sub-grant is not revoking its parent.** If the org revokes Cy's grant
  by asking Ada to republish, Ada can issue it again. To stop Ada, revoke Ada
  (`delegate {id}`).
- **Removals are eventual unless revoked.** A block source can serve an older
  statement to a verifier that has not seen a newer one. That keeps old members in.
  Use a `member` revocation when a removal must be prompt, as for org roots.
- **Rotation drops statements.** Statements signed by keys that are no longer current
  stop counting (§10.2), so a delegate re-signs after rotating or revoking a device.
- **Size.** A verifier MAY cap the size of a sub-root, and its number of sets. A sub-root
  over the cap is treated as absent.
- **Privacy.** Grants show who administers what. On a public DAG, treat them like the
  `members` map (§8.12).

## 10.11 Prior art

- **ARBAC97** (Sandhu, Bhamidipati and Munawer, 1999) separates assigning users to
  roles from defining roles. Its `can_assign(admin role, prerequisite, role range)` is a
  grant's `to`, `require` and `sets`.
- **SPKI/SDSI, UCAN and Biscuit** chain signed delegations, where each hop can only
  narrow. Grants use that rule for the right to assign memberships, not for the right
  to act. Multi-hop *action* delegation (§3.3) is still future work, and could use the
  same chain walk.
- **X.509 name constraints** limit which names a subordinate CA may certify. Patterns
  in `sets` do the same for set names.

## 10.12 Not yet implemented, and open questions

Not implemented: all of it. In particular:
- the grant block, `delegations` in the org root and in sub-roots;
- delegated root statements and their storage on the hub;
- chain validity, sub-root validity and the builder rules, in Rust, JS and Python;
- the membership extension and the slice step;
- `delegate` revocations and the hub's revocation requests;
- the `org` and `pol` claims;
- `assign` as a device capability;
- the CLI commands and hub routes of §10.9;
- `test-vectors/delegation.json`. Planned cases:
  - a valid two-hop chain;
  - a sub-root with an out-of-scope set;
  - a sub-grant that widens `sets`, `may`, `redelegate` or `exp`;
  - expiry;
  - a `require` that is false, and one that errors;
  - duplicate statements, and an older `seq`;
  - a revoked delegate, and a revoked ancestor;
  - a statement whose signing device was revoked;
  - builder rejections for rules 1 to 3 of §10.4;
  - the withholding property: removing each statement in turn never allows more.

Open questions:
1. **Who signs a statement?** A new `assign` device capability keeps the manage policy
   cold. Requiring the manage policy is simpler and slower to use. Either way, should
   a grant be able to set a minimum assurance level for the signing device?
2. **Should delegates write policies?** An API team could own the policies for its
   own audience (§9.10, question 3). That needs forbid completeness for sub-roots,
   which this chapter avoids by allowing no policies at all.
3. **Revoke one grant, or every grant to a delegate?** `delegate {id}` is blunt. A
   `grant {cid}` kind would be finer, but the parent can always issue a near copy.
4. **File mode.** Should a hub enforce `delegations` in a bundle file for its own admin
   write API? It would limit hub admins but prove nothing to resource servers.
5. **Is `require` worth having?** A permit's condition can check the same thing. But
   `require` also bounds the membership itself, which flows into tokens and into other
   sets.
