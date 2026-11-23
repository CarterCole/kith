import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { Engine, datetime, entityRef, ip } from "./authz.ts";

const vectors = JSON.parse(readFileSync(new URL("../../../spec/test-vectors/authz.json", import.meta.url), "utf8"));
const engine = new Engine(vectors.bundle);

for (const m of vectors.memberships) {
  test(`membership ${m.id} ${JSON.stringify(m.attrs)}`, () => {
    const got = engine.memberships(m.id, engine.attributes(m.id, m.attrs));
    assert.deepEqual(got, { groups: m.groups, roles: m.roles });
  });
}

for (const d of vectors.decisions) {
  test(`decision: ${d.name}`, () => {
    const attrs = engine.attributes(d.principal, d.attrs);
    const { groups, roles } = engine.memberships(d.principal, attrs);
    const got = engine.authorize({ id: d.principal, attrs, groups, roles, actor: d.actor, caps: d.caps }, d.action, d.resource, d.context);
    assert.equal(got.allowed, d.allowed, JSON.stringify(got));
  });
}

// §4.2.1 and §4.2.2: resource parents, related entities and typed values.
const entityEngine = new Engine(vectors.entities.bundle);
for (const d of vectors.entities.decisions) {
  test(`entities: ${d.name}`, () => {
    const attrs = entityEngine.attributes(d.principal, d.attrs);
    const { groups, roles } = entityEngine.memberships(d.principal, attrs);
    const got = entityEngine.authorize({ id: d.principal, attrs, groups, roles }, d.action, d.resource, d.context);
    assert.equal(got.allowed, d.allowed, JSON.stringify(got));
  });
}

test("typed value helpers build what the vectors use", () => {
  assert.deepEqual(ip("10.1.2.3"), { __extn: { fn: "ip", arg: "10.1.2.3" } });
  assert.deepEqual(datetime(new Date(Date.UTC(2030, 0, 1))), { __extn: { fn: "datetime", arg: "2030-01-01T00:00:00.000Z" } });
  assert.deepEqual(entityRef("User", "did:kith:bob"), { __entity: { type: "User", id: "did:kith:bob" } });
  const d = entityEngine.authorize({ id: "did:kith:bob", attrs: {}, groups: [], roles: [] }, "Query.report", { type: "Operation", id: "Query.report" }, { now: datetime(new Date(Date.UTC(2029, 5, 1))) });
  assert.equal(d.allowed, true, JSON.stringify(d));
});

// §4.3.1: who may assume which role, what the session then holds, and what it may do.
const assumeEngine = new Engine(vectors.assume.bundle);
for (const a of vectors.assume.assumptions) {
  test(`assume: ${a.id} ${a.role} ${JSON.stringify(a.attrs)} ${JSON.stringify(a.excluded ?? [])}`, () => {
    const got = assumeEngine.assume(a.id, assumeEngine.attributes(a.id, a.attrs), new Set(a.excluded ?? []), a.role);
    assert.deepEqual(got, a.refused ? { refused: a.refused } : { groups: a.groups, roles: a.roles });
  });
}
for (const d of vectors.assume.decisions) {
  test(`assume decision: ${d.name}`, () => {
    const attrs = assumeEngine.attributes(d.principal, d.attrs);
    const m = d.assume ? assumeEngine.assume(d.principal, attrs, new Set(), d.assume) : assumeEngine.memberships(d.principal, attrs);
    const allowed = !("refused" in m) && assumeEngine.authorize({ id: d.principal, attrs, ...m, assumed: d.assume }, d.action, d.resource, d.context).allowed;
    assert.equal(allowed, d.allowed);
  });
}
for (const b of vectors.assume.invalid) {
  test(`assume: does not load: ${b.note}`, () => {
    assert.throws(() => new Engine(b.bundle));
  });
}
test("assume: max_age", () => assert.equal(assumeEngine.assumeMaxAge("break-glass"), 600));

// §4.3.2: the lowest level at which a denied request would be allowed.
const stepUpEngine = new Engine(vectors.step_up.bundle);
for (const d of vectors.step_up.decisions) {
  test(`step-up: ${d.name}`, () => {
    const attrs = stepUpEngine.attributes(d.principal, d.attrs);
    const m = d.groups
      ? { groups: d.groups, roles: d.roles }
      : d.assume
        ? (stepUpEngine.assume(d.principal, attrs, new Set(), d.assume) as { groups: string[]; roles: string[] })
        : stepUpEngine.memberships(d.principal, attrs);
    const p = { id: d.principal, attrs, ...m, actor: d.actor, caps: d.caps, assumed: d.assume };
    const r = { type: "Operation", id: d.action };
    assert.equal(stepUpEngine.authorize(p, d.action, r, d.context).allowed, d.allowed);
    assert.equal(stepUpEngine.stepUp(p, d.action, r, d.context), d.step_up);
  });
}

test("rule injection is rejected", () => {
  assert.throws(() => new Engine({ version: 1, groups: { x: { rule: 'true }; permit(principal, action, resource) when { true' } }, policies: "" }));
});
