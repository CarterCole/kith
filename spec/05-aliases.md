# 5. Aliases

The requirement: "as many public aliases of the root as you want, and you can prove
them whenever you like." There are two kinds.

## 5.1 Public aliases

Public aliases are Keybase and Keyoxide style. The root publishes
`alias_link { alias }` in its KEL, signed by the manage policy. The alias can be:
- `mailto:ada@acme.test`
- `https://github.com/ada`
- `did:web:ada.dev`
- `eip155:1:0x…` or an ENS name
- `at://ada.bsky.social`

Verification is **bidirectional**: the alias side must also point back to the root. The
back-link can be:
- a WebFinger link at the domain (§5.1.1);
- a DNS TXT record at `_kith.<domain>` (§5.1.1);
- for `did:web`, the DID document's `alsoKnownAs` (§5.1.1);
- a gist;
- an ENS text record;
- a signed message from the wallet (`EIP191` over "I am did:kith:…").

Public aliases show up in the DID document's `alsoKnownAs` and in the access token's
`attrs.aliases`, so policies can use them.

### 5.1.1 Back-links and resolution

Resolution turns an alias into its root, and it needs both directions: the alias
side carries a **back-link** that names the root, and the root's KEL carries an
`alias_link` that names the alias. Either alone proves nothing. Anyone can put any
DID in a DNS record, and anyone can link any name in their own log.

The back-link is one of:

- **WebFinger** ([RFC 7033](https://www.rfc-editor.org/rfc/rfc7033)) at the alias's
  host: `GET https://{host}/.well-known/webfinger?resource={alias}`. A `mailto:` alias
  is queried as `acct:` ([RFC 7565](https://www.rfc-editor.org/rfc/rfc7565)), so a
  host that already answers WebFinger for Mastodon or similar adds one link. The JRD
  carries:

  ```json
  { "subject": "acct:ada@acme.test",
    "links": [ { "rel": "urn:kith:root", "href": "did:kith:…",
                 "properties": { "urn:kith:hub": "https://hub.example" } } ] }
  ```

  A link with `rel` `urn:kith:root` names a root in `href`. The optional
  `urn:kith:hub` property names a hub that serves the root's KEL; without it the
  resolver asks its own hub. Several such links MAY be present, and each is checked.
  Only a root that links the alias back counts, and at most one may (step 3 below), so
  a handover lists only the new root, or the old root unlinks the alias first.
- **DNS**: a TXT record at `_kith.{host}` reading `did=did:kith:…`, optionally
  followed by `;hub=https://hub.example`. It vouches for the host's own aliases,
  `https://{host}` and `did:web:{host}`, and not for accounts at the host.
- **did:web**: the DID document at the method's usual location, with the root in
  `alsoKnownAs`. Only for `did:web:` aliases.

**Resolution (normative).**

1. From the alias, the lookups to make, in order:

   | Alias | Lookups |
   |-------|---------|
   | `mailto:u@h`, `acct:u@h` | WebFinger at `h` for `acct:u@h` |
   | `https://h`, `https://h/` | TXT `_kith.h`, then WebFinger at `h` for the alias |
   | `https://h/path` | WebFinger at `h` for the alias |
   | `did:web:h` | the DID document, then TXT `_kith.h`, then WebFinger at `h` |
   | `did:web:h:path` | the DID document, then WebFinger at `h` |

2. Every root the lookups name is a candidate. Links, records and `alsoKnownAs`
   entries that do not name a `did:kith` are ignored. A root named by more than one
   back-link is one candidate. A lookup that fails is a note, not an error, as long as
   some lookup names a root.
3. For **every** candidate, fetch and replay its KEL (§1.6). A candidate **passes** if
   its current state links the alias. `acct:` and `mailto:` for the same address are
   the same alias, and an `https://` origin matches with or without its trailing
   slash. Nothing else is normalized: the string the alias side returns must be the
   string the log links.
4. If exactly one candidate passes, that root is the answer. If none does, the alias
   does not resolve. If **more than one** passes, the alias is **ambiguous**:
   resolution MUST fail and SHOULD report every root that passed. A resolver MUST NOT
   choose among them, whether by lookup order, by the order of links in the JRD, or
   by anything else, because the choice would be arbitrary and the person it
   misdirects is the one trusting the answer. Resolvers MUST check all candidates
   even after one passes, since a later one may make the alias ambiguous.
5. An `alias_unlink` ends resolution as soon as the log is replayed; the alias side
   need not change. Ambiguity ends when the alias side stops naming one of the roots
   or one of them unlinks the alias.

Resolvers MUST use `https://` except for `localhost`, `*.localhost`, `127.0.0.1` and
`[::1]`, which MAY be plain `http://` so tests can run without certificates.

Not resolvable yet: GitHub (a gist), ENS text records, a wallet's signed message
and `at://`. Those aliases can be linked, but `kith resolve` does not follow them.

### 5.1.2 Names are local

A resolved alias is an address, not a name to keep: DNS and WebFinger answers can
be re-pointed, and a resolver sees only what they say today. The reference CLI
therefore keeps a **petname** book, `names.json` in its home directory:

```
kith name add ada mailto:ada@acme.test   # resolve, then pin the root it resolved to
kith name add bob did:kith:…             # or pin a DID you were handed
kith delegate --to ada --action 'Query.*'
kith name list
```

An entry records the root and, for a name added from an alias, the alias, how it
resolved (`webfinger`, `dns` or `did:web`), the hub that served the log, and when.
Every command that takes a DID takes a name, or an alias resolved on the spot. A
name that would move to a different root is refused unless the user passes
`--replace`. Names are never sent anywhere. They are the memorable corner of
Zooko's triangle; the alias is the global one and the KEL the secure one.

**Drift.** A pinned name does not follow its alias: if the alias side is re-pointed, or
the root unlinks it, the name keeps its root, which is the point of pinning. Nothing
says so, though, so `kith name check [NAME…]` re-resolves every name that was added
from an alias and reports one of these for each, as JSON:

| `status` | Meaning |
|----------|---------|
| `ok` | the alias still resolves to the pinned root. `verified` is refreshed |
| `moved` | the alias now resolves to a different root, given as `now` |
| `ambiguous` | more than one root passes (§5.1.1) |
| `unresolved` | no back-link, a fetch failed, or the root no longer links the alias. `reason` says which |
| `pinned` | added from a DID; nothing to compare |

It exits non-zero if any name is `moved`, `ambiguous` or `unresolved`, and it never
changes a name's root. The user decides whether the move is legitimate (a person
changing keys) or a takeover of the alias side, and follows it with `kith name add
NAME ALIAS --replace`.

### 5.1.3 Namespaces and collisions

Each kind of name gets its uniqueness from somewhere different:

- **Aliases** are namespaced by their own syntax: a scheme and a host, such as
  `mailto:ada@acme.test`. Uniqueness comes from the host, and so ultimately from DNS:
  whoever controls `acme.test` decides who `ada@acme.test` is. Kith adds no registry.
- **Squatting** needs the host. Anyone can link any alias in their own log
  (§5.1), but it resolves only if the alias side names that root. A root that links
  `ada@acme.test` without control of `acme.test` gets nothing. When two roots do both
  link an alias, only the ones the alias side names are candidates, and if two pass
  the result is ambiguous, not a pick (§5.1.1 step 4).
- **Petnames** are one flat namespace per user, in the user's own home directory.
  There is nothing to collide with, because nobody else's names are ever consulted.
  Adding a name that already points at a different root is refused without `--replace`.
  A name contains no `:`, so it cannot be mistaken for a DID or an alias.
- **Private alias labels** are also local: `kith alias new` refuses a label the
  identity already uses, since `kith alias prove` finds an alias by label. The label is
  never published; the KEL holds only the commitment.

Protocol identifiers are namespaced by their owner: the WebFinger relation and
property are `urn:kith:…` and the DNS label is `_kith`.

## 5.2 Private aliases (unlinkable until you choose)

1. Generate an alias key pair (`did:key`). Use it anywhere, even as its own login.
   Nothing public connects it to the root.
2. Commit in the root KEL:
   `alias_commit { commitment: digest({t:"kith-alias-v1", root, alias, salt}) }`.
   The KEL shows only *that* the root committed to something, and when.
3. To prove the link to a verifier, send an **alias proof**:

```json
{ "v": 1, "root": "did:kith:…", "alias": "did:key:z6Mk…", "salt": "…", "seq": 7,
  "aud": "https://shop.example", "nonce": "…", "iat": …,
  "sig": { "signer": "did:key:z6Mk…(alias)", "alg": "Ed25519", "sig": "…" } }
```

The alias key signs:

```
kith alias link v1
root: <root>
alias: <alias>
aud: <aud or *>
nonce: <nonce or ->
iat: <iat>
```

To verify, the verifier:
1. Resolves the root KEL.
2. Recomputes the commitment and finds it at `seq`.
3. Checks the alias signature, the `aud`, and the `nonce`.

Both sides have now consented: the root committed, and the alias signed.

## 5.3 Privacy notes and planned improvements

- **Revealing is permanent.** Once `(alias, salt)` is shown to someone, they can show it
  to others. The `aud` and `nonce` stop them from *replaying* the proof as fresh, but not
  from sharing what they learned. A zero-knowledge proof of commitment membership would
  remove this. It is planned; see the passport ZK work in
  [../docs/passports.md](../docs/passports.md).
- **Commitments leak count and timing.** Planned mitigations:
  - batch commitments as a Merkle root;
  - add decoy commitments;
  - derive alias keys from a root secret so they can be recovered without being
    enumerable.
- An alias can have **its own KEL** (a `did:kith` rather than a `did:key`) when it needs
  its own devices and rotation.
