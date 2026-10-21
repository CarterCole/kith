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
    "billing-admin":  { "rule": "principal in Group::\"finance\" && principal in Group::\"strong-auth\"" }
  },
  "directory": { "did:kith:ada…": { "attrs": { "email": "ada@acme.test", "department": "finance" } } },
  "policies": "permit(principal in Role::\"billing-reader\", action == Action::\"Query.invoices\", resource); …"
}
```

- `members` holds principal ids, `group:<name>`, or `role:<name>`. A set may have both
  `members` and a `rule`. Membership is the union.
- `directory` holds admin-assigned attributes. Other attribute sources (verified
  credentials, upstream IdPs, KEL-derived data such as aliases) merge into the same map.
- A bundle MAY also carry `attributes` and `schemas` (§9, draft). They declare the
  attributes, actions and object types that policies may name, and give each audience
  its own namespace.

## 4.2 Entity model

| Cedar entity | Kith meaning |
|--------------|--------------|
| `User::"<did>"` | the principal. Attributes are the merged attrs plus `aal` and `amr`. Parents are its groups and roles. |
| `Group::"<name>"`, `Role::"<name>"` | sets. They have no attributes. Membership is expressed as entity parents. |
| `Action::"<Type>.<field>"` | GraphQL fields and other named operations. |
| `Operation::"<Type>.<field>"` | the resource used for root operations. |
| `<GraphQLType>::"<id>"` | object resources. Attributes are the object's scalar fields. |
| `context` | request data: field arguments, `operationType`, `field`, and `actor` when delegated. |

Cedar has no `null` and no floats. Implementations MUST drop nulls and stringify
non-integer numbers when building entities and context.

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
and delegation attenuation. Rust, JS and Python all run them (`scripts/test-all.sh`).

## 4.7 Why not …

| Option | Reason for not choosing it |
|--------|----------------------------|
| OPA/Rego | More general, but not designed for application authorization. No formal analysis, and a heavier runtime in the browser. |
| Zanzibar-style ReBAC (OpenFGA, SpiceDB) | Excellent for relationship graphs such as documents shared with users. Weaker for attribute propositions. It could sit beside Cedar as an entity source for `in` relationships. |
| CEL (Google IAM conditions, Kubernetes) | A good expression language, but not a policy language: no entity hierarchy, no permit/forbid semantics. |
| Biscuit | Datalog tokens with offline attenuation (Rust, wasm, Python). A strong candidate for the *delegation token* format in a later version. |
