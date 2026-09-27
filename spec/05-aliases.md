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
- a DNS TXT record;
- `/.well-known/kith.json` on the domain;
- a gist;
- an ENS text record;
- a signed message from the wallet (`EIP191` over "I am did:kith:…").

Public aliases show up in the DID document's `alsoKnownAs` and in the access token's
`attrs.aliases`, so policies can use them.

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
