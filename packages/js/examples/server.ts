/**
 * GraphQL Yoga server protected by Kith.
 *   KITH_HUB=http://127.0.0.1:7777 KITH_BUNDLE=bundle.json node examples/server.ts
 */
import { createServer } from "node:http";
import { readFileSync } from "node:fs";
import { createSchema, createYoga } from "graphql-yoga";
import { Engine, createVerifier, kithContextFactory, kithGraphQL } from "../src/index.ts";

const HUB = process.env.KITH_HUB ?? "http://localhost:7777";
const AUDIENCE = process.env.KITH_AUDIENCE ?? "api://invoices";
const PORT = Number(process.env.PORT ?? 4001);
const examples = new URL("../../../examples/", import.meta.url);
const engine = new Engine(JSON.parse(readFileSync(process.env.KITH_BUNDLE ?? new URL("policy/bundle.template.json", examples), "utf8")));
const invoices = JSON.parse(readFileSync(new URL("graphql/data.json", examples), "utf8"));

const schema = createSchema({
  typeDefs: readFileSync(new URL("graphql/schema.graphql", examples), "utf8"),
  resolvers: {
    Query: {
      me: (_: unknown, __: unknown, ctx: any) => {
        const p = ctx.kith.principal;
        return { did: p.id, actor: p.actor, groups: p.groups, roles: p.roles, aal: p.attrs.aal };
      },
      invoices: () => invoices,
      invoice: (_: unknown, { id }: { id: string }) => invoices.find((i: any) => i.id === id),
    },
    Mutation: {
      payInvoice: (_: unknown, { id }: { id: string }) => ({ ...invoices.find((i: any) => i.id === id), status: "paid" }),
    },
  },
});

// One line: every root field default-deny, @auth types row-filtered, @auth fields checked.
kithGraphQL(schema, { engine });

const yoga = createYoga({ schema, context: kithContextFactory(createVerifier({ issuer: HUB, audience: AUDIENCE })), maskedErrors: false });
createServer(yoga).listen(PORT, () => console.error(`graphql (js) on http://127.0.0.1:${PORT}/graphql`));
