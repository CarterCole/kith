# 4. Authorization

The requirements were attribute-level RBAC, groups with explicit and dynamic members
defined by propositions, and a way to lock down GraphQL by user and group membership.
Kith uses [Cedar](https://www.cedarpolicy.com) as its policy language, for these reasons:
- It has native attribute-based access control (ABAC) and entity hierarchies, so groups
  and roles need no extra machinery.
- It has formal semantics, a Lean-verified model, and a policy analyzer.
- One Rust core ships to every target:
  - `cedar-policy` for Rust;
  - `@cedar-policy/cedar-wasm` for the browser and Node;
  - `cedarpy` for Python.
  - Bindings also exist for Go and Java.
- It is a CNCF Sandbox project (since October 2025) and runs Amazon Verified
  Permissions.

**Propositions are Cedar expressions.** A dynamic group rule and a permission condition
are written in the same language:

```cedar
principal has email && principal.email like "*@acme.test"
```

## 4.1 Policy bundle

The portable unit that hubs and resource servers load:

```json
{
  "version": 1,
  "groups": {
    "finance":     { "members": ["did:kith:ada…", "group:finance-contractors"] },
    "staff":       { "rule": "principal has email && principal.email like \"*@acme.test\"" },
    "strong-auth": { "rule": "principal has aal && principal.aal >= 2" }
  },
  "roles": {
    "billing-reader": { "members": ["group:finance"] },
    "billing-admin":  { "rule": "principal in Group::\"finance\" && principal in Group::\"strong-auth\"" },
    "break-glass":    { "assume": { "members": ["group:finance"], "max_age": 600 } }
  },
  "directory": { "did:kith:ada…": { "attrs": { "email": "ada@acme.test", "department": "finance" } } },
  "policies": "permit(principal in Role::\"billing-reader\", action == Action::\"Query.invoices\", resource); …"
}
```

- `members` holds principal ids, `group:<name>`, or `role:<name>`. A set may have both
  `members` and a `rule`. Membership is the union.
- A role with an `assume` setting is held only for a session that asks for it (§4.3.1).
- `directory` holds admin-assigned attributes. Other attribute sources (verified
  credentials, upstream IdPs, KEL-derived data such as aliases) merge into the same map.
- A bundle MAY also carry `attributes` and `schemas` (§9, draft). They declare the
  attributes, actions and object types that policies may name, and give each audience
  its own namespace.

### 4.1.1 Checking a bundle file

A loader accepts any bundle that parses, and JSON forgives mistakes that change who has
access: an unknown member (`"rols"`, `"member"`) is ignored, a key written twice keeps
only its last value, and `role:gd` names a set whether or not `gd` exists. Tools that
write or deploy a bundle SHOULD refuse it when any of these hold (`kith bundle check`
does, and the reference implementation is `kith_core::bundle::check`):

- it is not valid JSON, not an object, or its `version` is not `1`;
- an object key appears twice in the same object, anywhere in the file;
- a member is unknown: at the top level (other than the ones above), in a set (other
  than `description`, `members`, `rule`, `assume`), in an `assume` (other than
  `members`, `rule`, `max_age`), or in a directory entry (other than `attrs`);
- a policy or rule does not parse;
- a `group:x` or `role:x` member names a set the bundle does not define, in `members`
  or in an `assume`;

They SHOULD warn about a member that is not a DID, `group:` or `role:`; a set with no
members and no rule (an assumable role aside); an `assume` with no members and no rule; a member listed twice in one set; a directory entry for something
that is not a DID; and a `Group::"x"` or `Role::"x"` in a rule or policy that names no set.

## 4.2 Entity model

| Cedar entity | Kith meaning |
|--------------|--------------|
| `User::"<did>"` | the principal. Attributes are the merged attrs plus `aal` and `amr`. Parents are its groups and roles. |
| `Group::"<name>"`, `Role::"<name>"` | sets. They have no attributes. Membership is expressed as entity parents. |
| `Action::"<Type>.<field>"` | GraphQL fields and other named operations. |
| `Operation::"<Type>.<field>"` | the resource used for root operations. |
| any other `<Type>::"<id>"` | entities the request relates to the resource: its ancestors, and what its attributes refer to (§4.2.1). |
| `<GraphQLType>::"<id>"` | object resources. Attributes are the object's scalar fields. Parents are what the request says it is in (§4.2.1). |
| `context` | request data: field arguments, `operationType`, `field`, and `actor` when delegated. |

Cedar has no `null` and no floats. Implementations MUST drop nulls and stringify
non-integer numbers when building entities and context. §4.2.2 has the values that are
neither a string nor an integer: addresses, decimals, times and entity references. A number with no fractional
part (`2.0`) is the integer it says: JavaScript cannot tell the two apart, so the
others must not either.

Ids reach Cedar as text, so any character may appear in one: non-ASCII, quotes,
backslashes, control characters. An implementation MUST NOT let such an id break the
request or change what it names. The text that capabilities are matched against
(`Type::"id"`, §3.3) is the JSON string of the id with non-ASCII left as it is, the
same in every implementation.

### 4.2.1 Resource hierarchy (normative)

A policy can scope a resource to a container, `resource in Folder::"finance"`, and read
through a reference, `resource.folder.ownerEmail`. Cedar answers both from the entities
it is given, so the resource server has to describe them. A resource carries two
optional members:

```json
{ "type": "Document", "id": "d1", "attrs": { "folder": { "__entity": { "type": "Folder", "id": "q3" } } },
  "parents": [ { "type": "Folder", "id": "q3" } ],
  "related": [ { "type": "Folder", "id": "q3", "attrs": { "ownerEmail": "ada@acme.test" },
                 "parents": [ { "type": "Folder", "id": "finance" } ] } ] }
```

- `parents` lists what the resource is directly in.
- `related` lists other entities a policy may reach: ancestors further up, and anything
  an attribute refers to. Each has a `type`, an `id`, and optional `attrs` and `parents`.
- `in` is transitive over the entities the request describes, and over nothing else.
  If `q3` is a parent and no related entity says where `q3` is, the resource is in
  `q3` only. Reading an attribute of an entity nobody described is an evaluation error,
  which skips that policy.
- The resource server answers for all of it, as it does for `attrs`. The hub and the
  token say nothing about what a document is in.

An implementation MUST deny, with reason `entities:conflict`, when a related entity:
- has the type and id of the principal, of the resource, or of another related entity;
- has the type `Group`, `Role` or `Action`, or a type ending in `::Action` (§9).

The principal's parents are its memberships (§4.3) and nothing a request says can add
to them. Another `User` may be related: a document's owner, with attributes.

Capabilities (§3.3) do not follow the hierarchy. A capability on `Folder::"finance"`
names that folder, not what is in it.

### 4.2.2 Typed values (normative)

A JSON string is a Cedar `String`, and stays one. `"10.1.2.3"` is not an address, and
`context.sourceIp.isInRange(ip("10.0.0.0/8"))` on it is an evaluation error. A value of
another type says so, in the form Cedar's own JSON uses:

| Value | JSON | Text |
|-------|------|------|
| IP address or range | `{"__extn": {"fn": "ip", "arg": "10.1.2.3"}}` | IPv4 or IPv6, with an optional `/prefix` |
| decimal | `{"__extn": {"fn": "decimal", "arg": "12.50"}}` | one to four fractional digits |
| date or instant | `{"__extn": {"fn": "datetime", "arg": "2030-01-01T09:30:00Z"}}` | `YYYY-MM-DD`, or with a time and `Z` or an offset, to the millisecond |
| duration | `{"__extn": {"fn": "duration", "arg": "1h30m"}}` | `d`, `h`, `m`, `s`, `ms` parts, in that order |
| entity reference | `{"__entity": {"type": "User", "id": "did:kith:ada…"}}` | |

- They may appear anywhere a value may: principal and resource attributes, related
  entities, the context, and inside records and sets.
- The helpers that build them are `ip`, `decimal`, `datetime`, `duration` and
  `entityRef` in JS, the same names in Python (`entity_ref`), and
  `kith_core::authz::typed` in Rust.
- A request with a value Cedar cannot read (`"arg": "10.1.2.300"`, an unknown `fn`)
  MUST NOT be allowed. An implementation may report an error instead of a decision.
- An object that has the key but not the shape, such as an `__entity` with no `id`, is
  whatever Cedar makes of it. It is never the entity it failed to name.
- A typed value that fails to evaluate skips its policy, forbids included (§8.8). Write
  a forbid so that the missing or malformed case is the forbidden one:
  `forbid(…) unless { context has sourceIp && context.sourceIp.isInRange(ip("10.0.0.0/8")) }`.
- **Keys starting with `__` are not for clients.** A context built from client input
  (GraphQL arguments through a JSON scalar, for instance) can otherwise hand a policy a
  typed value the server never made. The GraphQL middlewares (§4.5) MUST drop every
  such key, at any depth, from the arguments they put in the context (`clientArgs` in
  JS, `client_args` in Python). GraphQL reserves such names in its own schemas, so
  ordinary input types cannot carry them; a JSON scalar can.

## 4.3 Membership semantics (normative)

Membership is computed to a fixpoint:

```
G, R := ∅, ∅
repeat at most |groups| + |roles| + 1 times:
    for each set S (groups, then roles, in name order) not yet in G or R:
        S is a member set if the principal id ∈ S.members,
           or group:X ∈ S.members with X ∈ G,
           or role:X ∈ S.members with X ∈ R,
           or S.rule evaluates to true for User(principal) whose parents are G ∪ R
    stop when nothing changed
```

- Each rule compiles to exactly one Cedar policy:
  `permit(principal, action == Action::"kith:member", resource == <Kind>::"<name>") when { <rule> };`
- An implementation MUST reject a rule that parses to anything other than one policy.
  That blocks policy injection through rule text.
- An evaluation error, such as a missing attribute, means "not a member".
- Rules should be monotone, meaning no `!(principal in Group::…)`. A negated reference
  is evaluated against the previous iteration's state.

**Where membership is computed:**
- By default, the hub computes it when it issues a token, and puts `groups` and `roles`
  in the token.
- A resource server that has the bundle and attributes MAY recompute it. The algorithm
  is deterministic, and `test-vectors/authz.json` pins the results.

§10.5 (draft) extends this algorithm with members that delegates add under a grant
the org signed.

### 4.3.1 Assumable roles (normative)

A role is either held or assumable, and the bundle says which. A held role is in every
token of everyone in it. An assumable role is in a token only when the session asked
for it, for no longer than the role allows. This is how a break-glass or an audit role
works: you have it when you say you need it, and the log shows that you said so.

```json
"god":         { "members": ["did:kith:root…"] },
"break-glass": { "assume": { "rule": "principal in Group::\"oncall\" && principal has aal && principal.aal >= 2", "max_age": 600 } },
"auditor":     { "assume": { "members": ["did:kith:bob…", "role:billing-reader"] } }
```

**The setting.** `assume` is an object with three optional members:
- `members` and `rule` say who may assume the role. They work as a set's do (§4.3):
  the principal may assume the role if it is listed, is in a listed set, or the rule
  holds. The rule compiles to exactly one policy,
  `permit(principal, action == Action::"kith:assume", resource == Role::"<name>") when { <rule> };`.
- `max_age` is the longest an access token carrying the role may live, in seconds: a
  positive integer.

**A role without `assume` is never assumed.** `god` above is held by its members and
by no one else, and asking for it is refused whoever asks, its members included. An
implementation MUST refuse to load a bundle where:
- a role with `assume` has `members` or a `rule`. It is held only by assuming it;
- a group has `assume`. Only a role can be assumed;
- `assume` is not an object, its `members` is not a list of strings, its `rule` is not a
  string or does not compile to exactly one policy, or its `max_age` is not a positive
  integer. A member written as `null` is one of these, not an absent member: read as
  absent, `"assume": null` would make a role quietly unassumable in one implementation
  and a refused bundle in another.

**Assuming.** For principal `p` asking for role `x`, with the sets `E` excluded by
revocations (§8.7):
1. If `x` is not a role with `assume`, refuse with `not_assumable`.
2. Compute `p`'s memberships `G, R` as in §4.3, with `E` excluded.
3. If `Role::x` is in `E`, refuse with `not_eligible`.
4. If `p` is not listed in `assume.members`, directly or through a set in `G` or `R`,
   and `assume.rule` does not hold for `User(p)` with parents `G ∪ R`, refuse with
   `not_eligible`.
5. Compute memberships again as in §4.3, with `E` excluded and `x` in `R` from the
   start. The session holds the result, which includes `x`.

- Assuming adds a role. It removes nothing, so a forbid that names one of the
  principal's groups or roles still applies. A session cannot shed a forbid by
  assuming its way around it.
- Step 5 puts the session in every set that lists `role:x` or whose rule names
  `Role::"x"`. So `"audited": {"members": ["role:break-glass"]}` with a forbid on
  `Group::"audited"` binds every break-glass session. Without step 5 the forbid would
  never apply, because nobody holds `x` standing.
- Eligibility (step 4) is decided on standing memberships only. Sets that depend on
  `x` cannot make the principal eligible for `x`.
- Policies name an assumed role like any other: `permit(principal in Role::"break-glass", …)`.

**Issuing.** A session asks with the token exchange's `role` parameter (§3.4). The
access token carries `x` in `roles` and in `assumed` (§3.5), and its `exp` is at most
`iat + max_age`. A delegated session cannot assume a role: the exchange refuses
`role` with a delegation token. The hub answers a refusal with HTTP 403,
`"error": "access_denied"` and `"refusal": "not_assumable"` or `"not_eligible"`.

**Deciding.** A resource server that recomputes memberships (§8.9) recomputes an
assumed role with these steps, so a revocation ends a session that already holds it.
A resource server that takes `roles` from the token trusts the hub's answer, as it
does for every other role.

`test-vectors/authz.json`, under `assume`, has who may assume what, the memberships
that result, decisions made with them, and bundles that must not load.

## 4.4 Delegation

Before evaluating Cedar, if the principal carries `caps`, the action and resource must
match a capability (§3.3). Otherwise the answer is deny. `context.actor` is set so
policies can refuse specific delegated actions.

## 4.5 GraphQL mapping

JS (`kithGraphQL(schema, {engine})`) and Python (`KithMiddleware(engine)`) behave the
same way.

| What | Action | Resource | Context |
|------|--------|----------|---------|
| Every root field (`Query`, `Mutation`, `Subscription`), **default deny** | `"<Root>.<field>"` | `Operation::"<Root>.<field>"` | arguments, `operationType`, `field` |
| Object field marked `@auth` (or listed) | `"<Type>.<field>"` or `@auth(action:)` | the parent object | same |
| Every object of a type marked `@auth` (**row level**) | `"<Type>.read"` | the object | `operationType`, `field` |

- Lists of row-level types are filtered. A denied single object returns null plus a
  `FORBIDDEN` error.
- No principal gives `UNAUTHENTICATED`, unless an `anonymous` principal is configured.
- `__typename` is always allowed. Client libraries add it to every selection set, and it
  reveals only a name the client already has.
- Introspection (`__schema`, `__type`) is open by default. With `introspection:
  "authenticated"` (JS) or `introspection="authenticated"` (Python) it needs a
  principal, or the `anonymous` one. The other introspection types follow from those two.

```graphql
directive @auth(action: String) on FIELD_DEFINITION | OBJECT

type Invoice @auth {            # row level: Invoice.read per object
  id: ID!
  ownerEmail: String!
  internalNotes: String @auth   # field level: Invoice.internalNotes
}
```

**Scaling row-level checks.** Per-object checks cost microseconds, but loading rows
only to filter them out is wasteful. The planned approach uses Cedar partial evaluation
(`isAuthorizedPartial` / `is_authorized_partial`):
1. Evaluate with the resource unknown.
2. Compile the residual (`resource.ownerEmail == "ada@acme.test"`) into a SQL `WHERE`
   clause or an ORM filter.
3. Push that filter down to the data source.

## 4.6 Conformance

Every implementation MUST pass [`test-vectors/authz.json`](test-vectors/authz.json).
The vectors cover explicit, nested, dynamic and role-of-group membership, AAL-dependent
dynamic roles, context conditions, row-level attributes (including floats and nulls),
and delegation attenuation. Its `entities` suite covers §4.2.1 and §4.2.2: parents,
related entities, the conflicts that deny, and every typed value. Rust, JS and Python
all run them (`scripts/test-all.sh`).

Not yet implemented:
- **Action groups.** `action in Action::"…"` matches nothing, because no action has
  parents. §9 (draft) puts groups in an audience's schema.
- **Hierarchy in the GraphQL mapping.** The middlewares pass no parents by themselves.
  An application supplies them through `toResource` (JS) or `to_resource` (Python).

## 4.7 Why not …

| Option | Reason for not choosing it |
|--------|----------------------------|
| OPA/Rego | More general, but not designed for application authorization. No formal analysis, and a heavier runtime in the browser. |
| Zanzibar-style ReBAC (OpenFGA, SpiceDB) | Excellent for relationship graphs such as documents shared with users. Weaker for attribute propositions. It could sit beside Cedar as an entity source for `in` relationships. |
| CEL (Google IAM conditions, Kubernetes) | A good expression language, but not a policy language: no entity hierarchy, no permit/forbid semantics. |
| Biscuit | Datalog tokens with offline attenuation (Rust, wasm, Python). A strong candidate for the *delegation token* format in a later version. |
