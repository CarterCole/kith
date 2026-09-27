import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { Engine } from "./authz.ts";

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

test("rule injection is rejected", () => {
  assert.throws(() => new Engine({ version: 1, groups: { x: { rule: 'true }; permit(principal, action, resource) when { true' } }, policies: "" }));
});
