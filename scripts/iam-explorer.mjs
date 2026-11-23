#!/usr/bin/env node
// Explore AWS IAM as Kith sees it: who holds what, who can assume which role, what each
// session may do, and a simulator that asks Kith's own engine (packages/js) for a decision.
//
//   node scripts/iam-import.mjs auth.json out/
//   node scripts/iam-explorer.mjs out/ [--addr 127.0.0.1:7802]
//
// Like `kith bundle edit`, it listens on loopback only and every API call carries the
// random token in the address it prints, so other pages in the browser cannot read it.
// IAM data is sensitive: keep out/ outside the repository.

import { createServer } from "node:http";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { randomBytes, timingSafeEqual } from "node:crypto";
import { fileURLToPath } from "node:url";
import { Engine } from "../packages/js/src/authz.ts";

const args = process.argv.slice(2);
const dir = args.find((a) => !a.startsWith("--"));
const addrAt = args.indexOf("--addr");
const [host, port] = (addrAt >= 0 ? args[addrAt + 1] : "127.0.0.1:7802").split(":");
if (!dir) {
  console.error("usage: iam-explorer.mjs <dir with bundle.json and iam.json> [--addr 127.0.0.1:7802]");
  process.exit(2);
}
if (!["127.0.0.1", "localhost", "::1"].includes(host)) {
  console.error("refusing to listen beyond loopback");
  process.exit(2);
}

const bundle = JSON.parse(readFileSync(join(dir, "bundle.json"), "utf8"));
const meta = JSON.parse(readFileSync(join(dir, "iam.json"), "utf8"));
const PAGE_FILE = join(dirname(fileURLToPath(import.meta.url)), "iam-explorer.html");
const TOKEN = randomBytes(24).toString("base64url");

const policyText = {};
for (const chunk of bundle.policies.split("\n\n")) {
  const m = chunk.match(/^@id\((".*?")\)/);
  if (m) policyText[JSON.parse(m[1])] = chunk;
}
// Policies by id, so a decision names the IAM statement that decided it.
const engine = new Engine({ ...bundle, policies: policyText });

/** The policy ids a session holding these sets is covered by. */
function covering(id, m) {
  return Object.entries(meta.sources)
    .filter(([, s]) => (s.scope.kind === "group" && m.groups.includes(s.scope.name)) || (s.scope.kind === "role" && m.roles.includes(s.scope.name)) || (s.scope.kind === "user" && s.scope.name === id))
    .map(([pid]) => pid);
}

const roleNames = Object.keys(bundle.roles ?? {});
const principals = [
  ...meta.users.map((u) => ({ id: u.id, kind: "user", label: u.name })),
  ...meta.trusted.map((t) => ({ id: t.id, kind: t.kind, label: t.label })),
];

/** Standing memberships, and every role each principal may assume, as the engine decides. */
function analysis() {
  return principals.map((p) => {
    const attrs = engine.attributes(p.id);
    const standing = engine.memberships(p.id, attrs);
    const assumable = {};
    for (const r of roleNames) {
      const a = engine.assume(p.id, attrs, new Set(), r);
      assumable[r] = "refused" in a ? a.refused : "ok";
    }
    return { ...p, standing, policies: covering(p.id, standing), assumable };
  });
}

/** What holding `role` gives, apart from what the holder has anyway. */
function roleSession(role) {
  const m = { groups: [], roles: [role] };
  for (let changed = true; changed; ) {
    changed = false;
    for (const [g, def] of Object.entries(bundle.groups ?? {})) {
      if (m.groups.includes(g)) continue;
      if ((def.members ?? []).some((x) => (x.startsWith("role:") && m.roles.includes(x.slice(5))) || (x.startsWith("group:") && m.groups.includes(x.slice(6))))) {
        m.groups.push(g);
        changed = true;
      }
    }
  }
  return { ...m, policies: covering("", m) };
}

function check(req) {
  const id = String(req.principal ?? "");
  const attrs = engine.attributes(id, req.attrs ?? {});
  let m;
  if (req.assume) {
    const a = engine.assume(id, attrs, new Set(), String(req.assume));
    if ("refused" in a) return { refused: a.refused };
    m = a;
  } else m = engine.memberships(id, attrs);
  const action = String(req.action ?? "").toLowerCase();
  const arn = String(req.resource ?? "*");
  const principal = { id, attrs, groups: m.groups, roles: m.roles, ...(req.assume ? { assumed: String(req.assume) } : {}) };
  const decision = engine.authorize(principal, action, { type: "AwsResource", id: arn, attrs: { arn } }, { ...(req.context ?? {}), iamAction: action });
  return { memberships: m, decision };
}

const model = () => ({
  meta,
  bundle: { groups: bundle.groups, roles: bundle.roles },
  policyText,
  analysis: analysis(),
  roleSessions: Object.fromEntries(roleNames.map((r) => [r, roleSession(r)])),
});

const sameToken = (t) => typeof t === "string" && t.length === TOKEN.length && timingSafeEqual(Buffer.from(t), Buffer.from(TOKEN));
const send = (res, status, body, headers = {}) => {
  res.writeHead(status, { "cache-control": "no-store", "x-content-type-options": "nosniff", "referrer-policy": "no-referrer", ...headers });
  res.end(body);
};
const json = (res, status, v) => send(res, status, JSON.stringify(v), { "content-type": "application/json" });

createServer((req, res) => {
  // A page on another origin that resolves its own name to 127.0.0.1 sends its own Host.
  const h = (req.headers.host ?? "").replace(/:\d+$/, "");
  if (!["127.0.0.1", "localhost", "[::1]"].includes(h)) return json(res, 403, { error: "wrong host" });
  const url = new URL(req.url, "http://x");
  if (req.method === "GET" && url.pathname === "/") {
    const nonce = randomBytes(16).toString("base64url");
    return send(res, 200, readFileSync(PAGE_FILE, "utf8").replaceAll("{{NONCE}}", nonce), {
      "content-type": "text/html; charset=utf-8",
      "content-security-policy": `default-src 'none'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; connect-src 'self'; img-src data:; form-action 'none'; frame-ancestors 'none'; base-uri 'none'`,
    });
  }
  if (!sameToken(req.headers["x-explorer-token"])) return json(res, 401, { error: "missing or wrong token" });
  if (req.method === "GET" && url.pathname === "/api/model") return json(res, 200, model());
  if (req.method === "POST" && url.pathname === "/api/check") {
    let body = "";
    req.on("data", (c) => {
      body += c;
      if (body.length > 1 << 16) req.destroy();
    });
    req.on("end", () => {
      try {
        json(res, 200, check(JSON.parse(body)));
      } catch (e) {
        json(res, 400, { error: String(e.message ?? e) });
      }
    });
    return;
  }
  json(res, 404, { error: "not found" });
}).listen(Number(port), host, () => {
  console.log(`IAM explorer for account ${meta.account}: http://${host}:${port}/#t=${TOKEN}`);
});
