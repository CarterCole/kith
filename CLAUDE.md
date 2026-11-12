# Kith

A draft protocol for identity and authorization, and its reference implementation:
Rust (`crates/kith-core`, `crates/kith-hub`, `crates/kith-cli`), JS/TS (`packages/js`)
and Python (`packages/python`). [`README.md`](README.md) is the overview,
[`spec/`](spec/README.md) is normative, and [`docs/roadmap.md`](docs/roadmap.md) is the
task list.

## Working on the roadmap

"Work on roadmap" means: take the next open item from the milestone table at the bottom
of `docs/roadmap.md`, or a "Known gaps" item, and implement it. Docs are part of the
work. Update these together:

- the matching `spec/0N-*.md` section, including its "not yet implemented" list;
- `docs/roadmap.md`: "What works today", "Known gaps", and the milestone table (strike
  through what is done);
- `README.md`: the usage block and the crates table;
- the crate doc table at the top of `crates/kith-hub/src/lib.rs`, if routes changed.

Write the test first and watch it fail for the right reason. Do not commit unless asked.

## Checking a change

```bash
cargo clippy --workspace --all-targets   # keep it warning-free
scripts/test-all.sh                      # Rust, JS and Python unit tests and vectors
scripts/cli-flows.sh                     # real hub + CLI: TOTP, co-signer, delegation (about 2 min)
scripts/oidc-demo.sh                     # headless Chrome, a virtual passkey; needs Chrome
scripts/policy-dag-demo.sh               # needs the network (a drand beacon)
```

The CI workflow runs the first two, plus `cli-flows.sh`, on every push and pull request.
The scripts use fixed ports (7788, 7790, 7791, 7799, 4001, 4002, 3000), so run them one at a
time. On macOS `cli-flows.sh` puts keys in the login keychain and cleans up after itself.

## Shared conformance vectors

`spec/test-vectors/` is what makes three implementations one protocol. Every
implementation runs the same files, so a change to behaviour changes a vector first.

| File | Run by | Regenerate with |
|------|--------|-----------------|
| `authz.json` | Rust, JS, Python | edit by hand |
| `tokens.json`, `attestations.json` | Rust, JS, Python | `node scripts/token-vectors.mjs` |
| `policy-dag.json`, `beacons.json` | Rust, JS | `KITH_WRITE_VECTORS=1 cargo test -p kith-core --test policy_dag_vectors` |
| `ots.json` | Rust | from the reference client's examples |
| `sshsig.json` | Rust | `node scripts/sshsig-vectors.mjs` (needs `ssh-keygen`) |

The Rust generator for `policy-dag.json` asserts the decisions it writes, so rewriting the
file cannot bless a changed answer.

## Conventions

- Never trust a claim you did not verify: times come from signed but untrusted input, so
  use `saturating_*` on them. Parsers of external bytes return errors, never panic.
- A device acts only within its `caps` (`session`, `alias`, `revoke`). Check them where a
  device key is accepted.
- Hub secrets that must be recoverable (TOTP seeds, co-signer keys) are stored as they
  are; secrets that only need comparing (cookies, codes, refresh tokens) are hashed.
- Contact addresses in examples and docs use `example.com`, or `carter@cartercole.com`
  where a real one is needed.
