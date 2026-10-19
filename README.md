# Kith: universal identity and authorization

> Working name. A spec, a protocol, and implementations: Rust core, hub and CLI; JS/TS
> for browser and Node; Python.

- **One root identity per person.** It is a self-certifying `did:kith` backed by a
  signed key event log.
- **Controlled by a policy over many signers.** Passkeys, hardware keys, Ethereum
  wallets (including contract wallets through EIP-1271), Bitcoin (planned), SSH keys,
  GPG keys (specified, not yet implemented), and software keys. Interoperability is a
  goal: keys you already have, standard formats on the wire
  ([spec](spec/README.md#interoperability)). Different levels need different quorums,
  for example "2 of my 3 passkeys to add a device, and my cold recovery keys to rotate".
- **Keys cascade.** identity → devices → session keys → optional delegation to someone
  else.
- **Log in with anything.** A device session chain, a signed challenge (SIWE-style), a
  passkey, TOTP step-up. The hub turns the evidence into a normal JWT with `aal` and
  `amr` claims.
- **"Sign in with Kith" for existing apps.** The hub is a standard OpenID Connect
  provider: code flow with PKCE, username-less passkey login, SSO, step-up through
  `acr_values`, and pairwise subjects.
- **Aliases.** Public ones are proved in both directions. Private ones are unlinkable
  until you choose to prove the link.
- **Authorization** uses Cedar policies with explicit, nested and dynamic groups and
  roles. Dynamic groups are defined by propositions. It plugs into GraphQL at the root,
  field and row level in JS and Python.
- **Crypto-enforced sharing** uses skip-ratchet group keys, WNFS style, sealed to
  device keys. It covers data that lives on untrusted storage.
- **Policies as a content-addressed DAG.**
  - The bundle is stored as IPFS-compatible blocks with indexes, and the org's KEL
    commits to the root.
  - A session that reads one GraphQL field fetches only that field's policies,
    from anyone. It can prove nothing was left out.
- **Pushed revocations with provable freshness.** A signed, hash-chained revocation
  list plus heartbeats that embed a drand or NIST beacon.
  - Each verifier sets how long it can go between syncs: fresh, then degraded, then
    it fails closed.
  - Policies can demand a fresher view, for example payments under 60 s.
  - OpenTimestamps anchors the history to Bitcoin.

Start with [`spec/`](spec/README.md). Then read [prior art](docs/prior-art.md),
[passports](docs/passports.md), and the [roadmap](docs/roadmap.md).

## Try it

```bash
scripts/demo.sh        # hub + JS API + Python API, CLI logins, TOTP step-up, delegation, browser passkey
scripts/cli-flows.sh   # devices, passkeys, aliases, delegation, revocation, TOTP co-signed recovery
scripts/oidc-demo.sh   # real Chrome + virtual passkey: enroll from the browser, OIDC sign-in, SSO, step-up, logout
scripts/policy-dag-demo.sh  # org publishes a policy DAG, provable slices, revocation push, drand-verified freshness
scripts/test-all.sh    # unit tests (Rust, JS, Python) incl. shared conformance vectors
```

You need a recent stable Rust, Node 23.6+ (it runs TypeScript directly) and uv. The demo
waits for fresh TOTP windows, so it takes about a minute. The OIDC demo drives your
installed Google Chrome headlessly.

## Use it

**Terminal**

```bash
kith init --hub https://hub.example          # root identity + this device + 2-of-3 recovery keys
kith device add --name phone --kind passkey --out phone.json
kith login --aud api://invoices --totp 123456
curl -H "authorization: Bearer $(kith token --aud api://invoices)" https://api.example/graphql …
kith alias new gaming && kith alias prove gaming --aud https://shop.example
kith delegate --to did:kith:… --action 'Query.*'
kith rotate --revoke-devices                 # recovery keys (or paper key + TOTP co-signer)
kith hub serve --bundle bundle.json --clients clients.json   # run a hub (+ OIDC clients)
kith passkey enroll                          # create a passkey in your browser, approve it here
```

**Any existing app, through OpenID Connect** ([spec](spec/07-oidc.md))

Register the app in `clients.json`, then point it at the hub's discovery URL,
`https://id.example.com/.well-known/openid-configuration`. Users sign in with a passkey.
The app receives an RS256 ID token with `sub`, `email`, `groups`, `roles` and
`acr=urn:kith:acr:aal2`, plus a Kith access token for your APIs.

```ts
import * as oidc from "openid-client";   // or Auth.js, Django allauth, oauth2-proxy, Grafana…
const config = await oidc.discovery(new URL("https://id.example.com"), "demo-rp");
```

**Browser**

```ts
import { KithClient } from "@kith/auth/client";
const kith = new KithClient({ hub: "https://hub.example", rpId: "example.com" });
await kith.loginWithPasskey({ did, deviceId, audience: "api://invoices" });
const res = await kith.fetch("api://invoices", "/graphql", { method: "POST", body });
```

**GraphQL server, Node** (Yoga, Apollo, Envelop, anything on graphql-js)

```ts
import { Engine, createVerifier, kithGraphQL, kithContextFactory } from "@kith/auth";
kithGraphQL(schema, { engine: new Engine(bundle) });   // root fields default-deny, @auth rows and fields
createYoga({ schema, context: kithContextFactory(createVerifier({ issuer: HUB, audience: "api://invoices" })) });
```

**GraphQL server, Python** (Ariadne, Strawberry, Graphene, anything on graphql-core)

```python
from kith import Engine, Verifier
from kith.graphql import KithMiddleware
GraphQL(schema, context_value=…, http_handler=GraphQLHTTPHandler(middleware=[KithMiddleware(Engine(bundle))]))
```

**Rust**

```rust
use kith_core::{token::verify_access_token, authz::{Engine, Principal, Resource}};
let claims = verify_access_token(tok, &jwks, HUB, "api://invoices", now())?;
let ok = engine.authorize(&principal, "Query.invoices", &Resource::new("Operation", "Query.invoices"), &ctx)?.allowed;
```

**Policy slices and revocations** ([spec §8](spec/08-policy-dag.md))

```bash
kith policy publish bundle.json              # as the org: DAG blocks up, root into the org's KEL
kith policy add-revoker                      # let the hub sign heartbeats (a revoke-only device)
kith policy slice --org did:kith:… --action Query.invoices   # just that field, checked against the KEL
kith revoke member did:kith:ada… Group::finance              # pushed, signed, hash-chained
kith revocations --org did:kith:… --max-staleness 86400      # "I sync once a day"
kith anchor stamp --out root.ots             # OpenTimestamps: existed by Bitcoin block N
```

```ts
import { loadSlice, gatewayBlocks, Follower, HubFeed, Verifiers, authorize } from "@kith/auth";
const slice = await loadSlice(gatewayBlocks("https://ipfs.io"), root, { kind: "actions", actions: ["Query.invoices"] });
const feed = new HubFeed(HUB, org, new Follower(org.did, through, { fresh_for: 60, max_staleness: 900, require_beacon: true }), await Verifiers.create());
await feed.sync(); feed.listen();
authorize(slice, feed.follower, { principal, jti, action: "Query.invoices", resource }, Date.now() / 1000 | 0);
```

**Policies** ([example bundle](examples/policy/bundle.template.json))

```cedar
// dynamic role: finance members, but only on AAL2+ sessions
//   "billing-admin": { "rule": "principal in Group::\"finance\" && principal in Group::\"strong-auth\"" }
permit(principal in Role::"billing-admin", action == Action::"Mutation.payInvoice", resource)
  when { context has amount && context.amount < 10000 };
permit(principal, action == Action::"Invoice.read", resource)
  when { principal has email && resource has ownerEmail && resource.ownerEmail == principal.email };
forbid(principal, action, resource) when { context has actor && context.operationType == "mutation" };
```

## Layout

| Path | What |
|------|------|
| `spec/` | Normative spec and [conformance vectors](spec/test-vectors/) |
| `crates/kith-core` | Keys, WebAuthn, signer policies, KEL, aliases, JWS, sessions and delegation, access tokens, TOTP, Cedar authz, vault, policy DAG, revocations, beacons (drand, NIST 2.0), OpenTimestamps |
| `crates/kith-hub` | Reference hub: KEL registry, challenge login, token exchange, TOTP, co-signer, OpenID Connect provider with passkey login and enrollment pages, block store and IPFS-gateway route, revocation feeds and heartbeats |
| `crates/kith-cli` | `kith` binary |
| `packages/js` | `@kith/auth`: verifier, Cedar engine (wasm), GraphQL middleware, browser client, policy DAG slices, revocation follower, beacon verifiers |
| `packages/python` | `kith-auth`: verifier, Cedar engine (cedarpy), graphql-core middleware |
| `examples/` | Shared policy bundle, GraphQL schema and data used by every example and test |

**Status:** a draft spec with a working reference implementation. It is not production
ready. The CLI stores keys in plaintext, and the hub keeps some state in memory. See
[the roadmap](docs/roadmap.md#known-gaps-in-the-reference-code-not-production-ready).
