# Security

Kith is a draft specification with a reference implementation. **It is not production
ready.** The roadmap lists what is missing, including plaintext keys on Linux, no TLS
in the hub, no audit log and no DPoP binding:
[known gaps](docs/roadmap.md#known-gaps-in-the-reference-code-not-production-ready).
Read it before you trust this with anything that matters.

## Reporting a problem

Email **carter@cartercole.com** with what you found and how to reproduce it. Please do
not open a public issue for something that can be exploited. A report that includes the
commit or release, the steps, and what an attacker gains is the most useful.

You will get an answer within a few days. Fixes are credited unless you ask otherwise.
There is no bounty.

## What counts

The specification in [`spec/`](spec/README.md) is as much in scope as the code. A rule
that lets a verifier accept something it should refuse is a vulnerability even if every
implementation follows it.

- The protocol: key event logs, signer policies, session chains, delegation, tokens,
  the policy DAG, revocations and freshness, aliases, the vault.
- The Rust crates `kith-core`, `kith-hub` and `kith-cli`.
- The JS package `@kith/auth` and the Python package `kith-auth`.

Findings the roadmap already lists as known gaps are welcome as a reminder, but they are
not news.

## Supported versions

Only the latest release and `main`. The format will change until v1.

## Checks that run on every change

[`ci.yml`](.github/workflows/ci.yml) runs the unit tests of all three languages against the
shared conformance vectors in [`spec/test-vectors/`](spec/test-vectors/), clippy with
warnings as errors, a typecheck, the end-to-end CLI flows, and a report of known
vulnerabilities in dependencies (`cargo audit`, `npm audit`, `pip-audit`).
