import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { buildSchema, graphql } from "graphql";
import { Engine, type Principal } from "./authz.ts";
import { kithGraphQL } from "./graphql.ts";

const root = new URL("../../../examples/", import.meta.url);
const template = readFileSync(new URL("policy/bundle.template.json", root), "utf8");
const bundle = JSON.parse(template.replaceAll("__ADA__", "did:kith:ada").replaceAll("__BOB__", "did:kith:bob"));
const engine = new Engine(bundle);
const data = JSON.parse(readFileSync(new URL("graphql/data.json", root), "utf8"));

const schema = buildSchema(readFileSync(new URL("graphql/schema.graphql", root), "utf8"));
const resolvers = {
  me: (_: unknown, ctx: any) => ({ did: ctx.kith.principal.id, actor: ctx.kith.principal.actor, groups: ctx.kith.principal.groups, roles: ctx.kith.principal.roles, aal: ctx.kith.principal.attrs.aal }),
  invoices: () => data,
  invoice: ({ id }: { id: string }) => data.find((i: any) => i.id === id),
  payInvoice: ({ id }: { id: string }) => ({ ...data.find((i: any) => i.id === id), status: "paid" }),
};
// buildSchema + rootValue style: wrap Query/Mutation fields so they call the root resolvers.
for (const t of [schema.getQueryType()!, schema.getMutationType()!]) {
  for (const f of Object.values(t.getFields())) {
    const r = (resolvers as any)[f.name];
    f.resolve = (_src, args, ctx) => r(args, ctx);
  }
}
kithGraphQL(schema, { engine });

function principal(id: string, aal: number, extra: Partial<Principal> = {}): Principal {
  const attrs = engine.attributes(id, { aal });
  return { id, attrs, ...engine.memberships(id, attrs), ...extra };
}

const run = (source: string, p?: Principal) => graphql({ schema, source, contextValue: p ? { kith: { principal: p } } : {} });

test("unauthenticated is rejected", async () => {
  const r = await run("{ me { did } }");
  assert.equal(r.errors?.[0].extensions?.code, "UNAUTHENTICATED");
});

test("billing reader sees all rows but not internal notes at AAL1", async () => {
  const r = await run("{ invoices { id internalNotes } }", principal("did:kith:ada", 1));
  assert.deepEqual((r.data as any).invoices.map((i: any) => i.id), ["inv_1", "inv_2", "inv_3"]);
  assert.equal((r.data as any).invoices[0].internalNotes, null);
  assert.equal(r.errors?.[0].extensions?.code, "FORBIDDEN");
});

test("billing admin (AAL2) sees internal notes and can pay under the limit", async () => {
  const ada = principal("did:kith:ada", 2);
  const r = await run("{ invoices { id internalNotes } }", ada);
  assert.equal(r.errors, undefined);
  assert.equal((r.data as any).invoices[0].internalNotes, "net 30");
  const pay = await run('mutation { payInvoice(id: "inv_1", amount: 1200) { status } }', ada);
  assert.equal((pay.data as any).payInvoice.status, "paid");
  const tooMuch = await run('mutation { payInvoice(id: "inv_3", amount: 25000) { status } }', ada);
  assert.equal(tooMuch.errors?.[0].extensions?.code, "FORBIDDEN");
});

test("staff member only sees their own rows", async () => {
  const r = await run("{ invoices { id ownerEmail } }", principal("did:kith:bob", 1));
  assert.deepEqual(JSON.parse(JSON.stringify((r.data as any).invoices)), [{ id: "inv_2", ownerEmail: "bob@acme.test" }]);
  const one = await run('{ invoice(id: "inv_1") { id } }', principal("did:kith:bob", 1));
  assert.equal(one.errors?.[0].extensions?.code, "FORBIDDEN");
});

test("delegated principal: caps narrow access and mutations are forbidden", async () => {
  const ada = principal("did:kith:ada", 2, { actor: "did:kith:assistant", caps: [{ action: "Query.*" }, { action: "Invoice.read" }, { action: "Mutation.*" }] });
  const r = await run("{ me { did actor } invoices { id } }", ada);
  assert.equal((r.data as any).me.actor, "did:kith:assistant");
  assert.equal((r.data as any).invoices.length, 3);
  const pay = await run('mutation { payInvoice(id: "inv_1", amount: 5) { status } }', ada);
  assert.equal(pay.errors?.[0].extensions?.code, "FORBIDDEN");
});
