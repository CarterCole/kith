# 9. Schemas and namespaces

> Status: draft for discussion. The reference code does not implement this chapter
> yet, and there are no test vectors. The Cedar behaviour it relies on was checked
> against Cedar 4.13, the version the Rust and JS packages pin.

§4 lets a policy name any action and read any attribute. Nothing says which ones
exist. That has two costs:
- **Mistakes are silent.** `Action::"Query.invoces"` is a valid policy that never
  matches. Reading a missing attribute is an evaluation error, which skips the
  policy. §8.8 shows how that makes a forbid fail open.
- **One flat vocabulary.** A bundle is org-wide, so `Invoice.read` means the same
  thing at every resource server.

This chapter gives each audience a **schema** in its own Cedar namespace. The schema
lists the audience's actions, the object types they apply to, and the attributes of
each type. It is the catalogue of permissions an API offers. Policies are checked
against it before the org publishes them.

```
 bundle
   attributes ──────────────▶ core       User · Group · Role             (no namespace)
   schemas
     api://invoices ────────▶ Invoices   Invoice · Operation · actions
     api://reports  ────────▶ Reports    Report · Operation · actions
   policies ── validated against all of the above before a policy_root is signed
```

## 9.1 Typed bundles

A bundle (§4.1) gains two optional members:

```json
{
  "version": 1,
  "groups": { … }, "roles": { … }, "directory": { … }, "policies": "…",
  "attributes": {
    "email":      {"type": "String"},
    "department": {"type": "String"}
  },
  "schemas": {
    "api://invoices": {
      "namespace": "Invoices",
      "schema": {"entityTypes": { … }, "actions": { … }, "commonTypes": { … }}
    }
  }
}
```

- `attributes` declares every attribute a principal may carry, as name → type in the
  Cedar JSON schema format. It defaults to `{}`.
- `schemas` maps an **audience** (the `aud` of an access token, §3.5) to its schema.
  - `namespace` is a Cedar namespace such as `Invoices` or `Acme::Billing`, or `""`
    (§9.8).
  - `schema` is one namespace definition in the Cedar JSON schema format.
    `entityTypes` and `actions` are required, though either may be empty.
    `commonTypes` is optional.
- A bundle with a `schemas` member is **typed**. A bundle without one behaves exactly
  as in §4.

Schemas use Cedar's JSON format, not its text format, for two reasons:
- A schema is then canonical JSON, so it can be a block (§8.1).
- A tool in any language can list an API's actions without a Cedar parser.

The examples below use the text format because it is shorter.

## 9.2 Core types

Every typed bundle has the same core. Only the last line of `User` varies: it comes
from `attributes`.

```cedarschema
entity Group;
entity Role;
entity User in [Group, Role] = {
  aal?: Long, amr?: Set<String>, aliases?: Set<String>,   // set by Kith
  email?: String, department?: String                     // from `attributes`
};
action "kith:member" appliesTo { principal: User, resource: [Group, Role], context: {} };

namespace Kith {
  type Freshness = { sync_age: Long, degraded: Bool, revocation_seq: Long };
}
```

- Principals, groups and roles stay in the empty namespace, so every §4 policy keeps
  its meaning.
- Every principal attribute is optional, because a principal may have no directory
  entry. A policy must guard each one with `has`.
- `aal`, `amr` and `aliases` are reserved. `attributes` MUST NOT declare them.
- `kith:member` is the action that membership rules compile to (§4.3). Action ids
  starting with `kith:` are reserved, and so is the namespace `Kith`.
- `Kith::Freshness` is the type of `context.kith` (§8.8).
- Cedar does not let a namespace define a name that the empty namespace already
  defines. So no audience can have an object type called `User`, `Group` or `Role`
  (open question 1).

## 9.3 Audience schemas

The schema for the example API in `examples/graphql/`:

```cedarschema
namespace Invoices {
  entity Operation;
  @doc("An invoice. Checked per object with Invoice.read.")
  entity Invoice = {
    id: String, ownerEmail: String, amount: Long, status: String,
    internalNotes?: String
  };

  type Request = { operationType: String, field: String, actor?: String, kith?: Kith::Freshness };

  action "all";
  action "Query.me", "Query.invoices" in [Action::"all"]
    appliesTo { principal: User, resource: Operation, context: Request };
  action "Query.invoice" in [Action::"all"]
    appliesTo { principal: User, resource: Operation,
                context: { id: String,
                           operationType: String, field: String, actor?: String, kith?: Kith::Freshness } };
  action "Mutation.payInvoice" in [Action::"all"]
    appliesTo { principal: User, resource: Operation,
                context: { id: String, amount: Long,
                           operationType: String, field: String, actor?: String, kith?: Kith::Freshness } };
  action "Invoice.read", "Invoice.internalNotes" in [Action::"all"]
    appliesTo { principal: User, resource: Invoice, context: Request };
}
```

Policies then name the namespace. Principals do not change:

```cedar
permit(principal in Role::"billing-reader", action == Invoices::Action::"Invoice.read", resource);
permit(principal, action == Invoices::Action::"Invoice.read", resource)
  when { principal has email && resource.ownerEmail == principal.email };
permit(principal in Role::"invoices-admin", action in Invoices::Action::"all", resource);
```

Rules for every audience schema:
- The principal type of every action MUST be `User`.
- Every action's context MUST declare two reserved attributes, both optional:
  `actor: String` (§4.4) and `kith: Kith::Freshness`.
- **Action groups.** An action may list other actions in `memberOf`. Those are
  groups, and `action in` a group matches every member.
  - A group MUST be in the same namespace as its members.
  - The empty namespace MUST NOT have groups (§9.6 gives the reason).
- `annotations.doc` on an action, a type or an attribute is its description.
  Catalogue tools show it.

## 9.4 Generating a schema from GraphQL

For a GraphQL API the schema follows from the mapping of §4.5. A generator MUST
produce:

| GraphQL | Cedar |
|---------|-------|
| Every root field | action `"<Root>.<field>"` on `Operation`. The field's arguments go in the context |
| Field marked `@auth` | action `"<Type>.<field>"` on the parent type. The field's arguments go in the context |
| Type marked `@auth` | action `"<Type>.read"` on that type |
| Each type an action applies to | entity type whose attributes are the type's scalar fields |
| A description | `annotations.doc` |

| GraphQL type | Cedar type |
|--------------|------------|
| `ID`, `String`, an enum | `String` |
| `Int` | `Long` |
| `Boolean` | `Bool` |
| Input object (arguments only) | record |
| List (arguments only) | `Set` of the element type |
| `Float`, custom scalars; list and object fields of a type | left out (open question 2) |

- `@auth(action: "…")` replaces the action id. Fields that share an action make it
  apply to all their parent types, and their arguments MUST agree.
- A nullable field or argument is optional, because §4.2 drops nulls. `T!` is
  required.
- Every context also has `operationType: String`, `field: String` and the reserved
  attributes of §9.3. An argument with one of those four names is an error.
- The generator declares one group, `all`, holding every action it generates. It
  does not do this in the empty namespace.
- If an action applies to a type named `User`, `Group` or `Role`, the generator MUST
  fail and ask for another name (§9.2).
- The middleware converts `ID` values to strings.

A schema does not have to come from GraphQL. Any API can write one by hand, with its
operations as actions and its objects as entity types.

## 9.5 Publishing (normative)

A builder MUST reject a typed bundle unless all of these hold:

1. The **effective schema** is a valid Cedar schema. It is the core, plus
   `{namespace: schema}` for every entry of `schemas`. Entries that share a namespace
   are merged, and a name that two of them define MUST have the same definition.
2. Every policy passes Cedar validation in strict mode against the effective schema,
   and Cedar does not report it as impossible.
3. Every membership rule, compiled to a policy as in §4.3, passes the same validation
   against the core alone.
4. Every `Group::` and `Role::` that a policy or rule names is defined in the bundle.
   Cedar does not check this.
5. Every directory attribute is declared in `attributes` and has the declared type.
6. The rules of §9.2 and §9.3 hold.

What this catches, using the schema of §9.3:

| Policy text | Result |
|-------------|--------|
| `action == Invoices::Action::"Query.invoces"` | rejected: no such action |
| `action == Action::"Query.invoices"` | rejected: the action is in `Invoices` |
| `when { resource.owner == "x" }` | rejected: `Invoice` has no `owner` |
| `when { resource.amount == "12" }` | rejected: `amount` is a `Long` |
| `when { context.kith.sync_age > 60 }` | rejected: `kith` is optional and unguarded. This is the fail-open shape of §8.8 |
| `principal in Role::"bilng-reader"` | Cedar accepts it. Check 4 rejects it |

One mistake gets through. `principal has emial` is not an error in Cedar: `has` on
an undeclared attribute is simply false. Validation notices only when that makes the
whole policy impossible. A misspelling inside one branch of an `||` is not caught.

A verifier does not repeat these checks. It relies on the admin quorum that signs
the `policy_root` (§8.6), as it does for the filing rules of §8.4.

## 9.6 In the policy DAG

The root block (§8.3) gains two optional members:

```json
{
  "attributes": {"email": {"type": "String"}, "department": {"type": "String"}},
  "schemas":    {"/": "<map: audience → schema link>"}
}
```

A **schema block** is one entry of `schemas`, stored exactly as the bundle gives it:

```json
{"namespace": "Invoices",
 "schema": {
   "entityTypes": {
     "Operation": {},
     "Invoice": {"shape": {"type": "Record", "attributes": {
       "id": {"type": "String"}, "internalNotes": {"type": "String", "required": false}, …}}}},
   "actions": {
     "all": {},
     "Invoice.read": {"memberOf": [{"id": "all"}], "appliesTo": {
       "principalTypes": ["User"], "resourceTypes": ["Invoice"], "context": {"type": "Request"}}},
     …},
   "commonTypes": {"Request": {"type": "Record", "attributes": { … }}}}}
```

- A root without these members is a §8 root, and its CID does not change.
- Several audiences may link to the same block, for example the staging and
  production deployments of one API.
- **Filing is unchanged.** §8.4 already gives a namespaced action the key `Type::id`,
  here `Invoices::Action::Invoice.read`. An action in the empty namespace keeps its
  bare id. A policy scoped to a group is filed under the group's key.

Queries (§8.5):
- `{"kind": "audience", "audience": "api://invoices", "principals": [...]}` is new.
  It returns the schema block and everything needed to decide every action the block
  declares. This is what a resource server loads.
- An `actions` query may add `"audience"`. Its `actions` are then ids in that
  audience's namespace.

Loading for an audience:
1. Look up the audience in `schemas`. If it is absent, fail.
2. For each action, look up three things in `actions`: its key, the key of every
   group it belongs to (directly or through other groups), and `*`.
3. Continue with steps 3 and 4 of §8.5.

An `actions` query without `audience` works as in §8.5 and covers the empty namespace
only. That is why the empty namespace has no groups: a reader written before this
chapter looks up an action's own key and `*`, and its slices stay complete.

**Property (normative):** a slice loaded for an audience gives the same decisions
(§9.7) as the full typed bundle, for that audience's actions.

## 9.7 Deciding with a schema (normative)

A resource server is configured with its audience and loads that audience's schema
block. `N` is the block's namespace. These steps replace the evaluation of §4.4, and
step 5 of §8.9:

1. The token's `aud` MUST be the configured audience (§3.5).
2. **Qualify.** Action `A` becomes `N::Action::"A"`. A resource of type `T` becomes
   `N::T::"<id>"`. With `N = ""` nothing changes. The principal, groups and roles are
   never qualified.
3. If the block does not declare `A`, deny with reason `schema:action`.
4. **Delegation.** If the principal carries `caps`, match them (§3.3) against the
   action's key (§8.4) and the qualified resource: `Invoices::Action::Invoice.read`
   and `Invoices::Invoice::"inv_1"`.
5. **Project.** For the principal, the resource and the context, keep the declared
   attributes whose value has the declared type, and drop the rest. If a required
   attribute is then missing, deny with reason `schema:shape`.
6. Add the action as an entity whose parents are its groups.
7. Evaluate.

- Step 4 scopes a delegation to one API. `{"action": "Invoices::*", "resource": "*"}`
  delegates everything in the Invoices API and nothing else. §3.3 cannot say that
  today: a capability written as `Invoice.*` is honoured at every resource server.
- Step 5 makes implementations agree on values. A JSON string is a `String`, an
  integer is a `Long`, `true` and `false` are `Bool`, an array is a `Set` if every
  element has the element type, and an object is a record if it projects with no
  required attribute missing. So `"amount": 12.5` is dropped rather than stringified.
- Dropping is safe. §9.5 rejected every policy that reads an undeclared attribute, or
  reads an optional one without `has`.
- The hub projects the principal the same way before it computes membership (§4.3).

**Middleware.** A GraphQL middleware (§4.5) that is given a schema block MUST refuse
to start if the GraphQL schema implies an action (§9.4) that the block does not
declare. An API that is ahead of its published schema then fails at start-up, not
with scattered denials.

## 9.8 Migration and change

**The empty namespace.** An audience may declare `"namespace": ""`. Its actions and
types then have exactly the names §4 uses, such as `Action::"Query.invoices"` and
`Invoice::"inv_1"`. Its policies, capabilities and DAG keys stay as they are. The
policies in `examples/policy/` validate this way without changes.

1. Add `attributes`, and a schema with `"namespace": ""` for each audience. Every
   audience needs one, because check 2 rejects a policy for an undeclared action.
   The bundle is now validated and no policy has changed.
2. When a second API needs the same names, give each a real namespace and rewrite
   `Action::"X"` as `N::Action::"X"`. A resource server takes `N` from the block, so
   the policies and the server switch at the same root. Capabilities that use the
   old names stop matching and must be issued again.

**Changing a schema.**
- Adding an action, a type or an optional attribute is compatible. Publish the root
  first, then deploy the API that uses it.
- Removing or renaming one, changing a type, or making an attribute required is
  breaking. Deploy the API first, then publish the root. Check 2 guarantees that no
  policy still names what was removed.

## 9.9 Security notes

- **A policy with no action constraint spans every namespace.**
  `permit(principal in Role::"admin", action, resource)` grants every action of every
  API, including APIs added later. Scope it to a group instead:
  `action in Invoices::Action::"all"`. Forbids are usually meant to span everything.
- **A schema grants nothing.** Declaring an action lets no one perform it. §4 is
  still default deny.
- **Trust.** Schema blocks sit under the root, so the same admin quorum signs them
  as signs the policies (§8.6). A revoke key cannot change them.
- **Privacy.** A schema describes an API's operations and field names. On a public
  DAG, treat it like the `directory` (§8.12).

## 9.10 Not covered, and open questions

Not covered here:
- **Object hierarchy and relationships.** A schema may declare `memberOfTypes` and
  entity-typed attributes, but §4 has no way to supply an object's parents or
  relationships. Until it does, `resource in Folder::"x"` validates and is never true.
- **Per-object grants** signed by an object's owner, for sharing across orgs.
- **Conformance.** Planned: `test-vectors/schemas.json`, with bundles a builder must
  accept and reject, projections, decisions with their reasons, and audience slices.

Open questions:
1. **Should the core types leave the empty namespace?** Keeping them there keeps
   every existing policy valid. It also reserves `User`, `Group` and `Role`, which
   are common names for API object types. `Kith::User` and so on would free the names,
   at the cost of rewriting every policy and every `principals` key (§8.3). This needs
   a decision before v1.
2. **`Float`.** It is left out because its Cedar value depends on the number and on
   the JSON parser. `12.5` becomes a string. `12.0` stays an integer in JS and becomes
   a string in Rust. Cedar's `decimal` type (four fractional digits) is the candidate.
3. **Who owns a schema?** Today the admin quorum signs the whole root. An API team
   could sign the block for its own audience. That belongs with the audience registry
   (see the [roadmap](../docs/roadmap.md)).
