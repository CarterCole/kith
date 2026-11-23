#!/usr/bin/env node
// Convert AWS IAM into a Kith bundle (spec §4) so it can be explored and checked with
// Kith's own engine.
//
//   aws iam get-account-authorization-details --output json > auth.json
//   node scripts/iam-import.mjs auth.json out/          # writes bundle.json and iam.json
//
// The mapping:
//   IAM user            a principal whose id is the user's ARN
//   managed policy      a group `policy/<name>` whose members are the users and roles it is attached to
//   IAM role            an assumable role; its trust policy becomes the `assume` rule and
//                       MaxSessionDuration its `max_age`
//   trusted principal   `service:<name>`, `federated:<provider>` or an IAM ARN; a web
//                       identity's claims (`sub`, `aud`) are its attributes
//   statement           a `permit` (Allow) or `forbid` (Deny) matching `context.iamAction`
//                       and `resource.arn`, which the explorer fills in
//
// Some IAM has no Kith form yet. Those parts are listed in iam.json's `notes`: an Allow
// that cannot be expressed is left out (so it never grants) and a Deny is kept without
// its unexpressible part (so it denies more, never less).

import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";

const [input, outDir] = process.argv.slice(2);
if (!input || !outDir) {
  console.error("usage: iam-import.mjs <get-account-authorization-details.json> <out-dir>");
  process.exit(2);
}
const auth = JSON.parse(readFileSync(input, "utf8"));
const notes = [];
const note = (where, what) => notes.push({ where, what });

const str = (s) => JSON.stringify(s); // Cedar string literals use JSON's escapes
const list = (x) => (x === undefined ? [] : Array.isArray(x) ? x : [x]);
/** An IAM wildcard pattern as a Cedar `like` pattern; `?` has no Cedar form. */
function like(pattern, where) {
  if (pattern.includes("?")) note(where, `"${pattern}": IAM's ? wildcard is read as *`);
  if (/\$\{[^}]+\}/.test(pattern)) return null;
  return str(pattern.replace(/\?/g, "*"));
}
const decode = (doc) => (typeof doc === "string" ? JSON.parse(decodeURIComponent(doc)) : doc);
const account = (auth.UserDetailList?.[0] ?? auth.RoleDetailList?.[0])?.Arn.split(":")[4] ?? "";

// ---- statements ----------------------------------------------------------------------

/** A condition block as a Cedar expression over `on` (`context` or `principal`), or null. */
function condition(cond, where, on = "context", keyName = (k) => k) {
  const parts = [];
  for (const [rawOp, kv] of Object.entries(cond ?? {})) {
    const ifExists = rawOp.endsWith("IfExists");
    const quantifier = rawOp.startsWith("ForAnyValue:") ? "any" : rawOp.startsWith("ForAllValues:") ? "all" : null;
    const op = rawOp.replace(/IfExists$/, "").replace(/^For(Any|All)Values?:/, "");
    if (quantifier) return note(where, `${rawOp}: multi-valued condition keys are not mapped`), null;
    for (const [rawKey, values] of Object.entries(kv)) {
      const key = keyName(rawKey);
      const ref = `${on}[${str(key)}]`;
      const has = `${on} has ${str(key)}`;
      const vs = list(values).map(String);
      let test;
      const negated = op.includes("Not");
      switch (op) {
        case "StringEquals":
        case "StringNotEquals":
        case "ArnEquals":
        case "ArnNotEquals":
          test = vs.map((v) => `${ref} == ${str(v)}`).join(" || ");
          break;
        case "StringEqualsIgnoreCase":
        case "StringNotEqualsIgnoreCase":
          return note(where, `${rawOp} ${rawKey}: case-insensitive match is not mapped`), null;
        case "StringLike":
        case "StringNotLike":
        case "ArnLike":
        case "ArnNotLike": {
          const ps = vs.map((v) => like(v, where));
          if (ps.includes(null)) return note(where, `${rawOp} ${rawKey}: policy variables are not mapped`), null;
          test = ps.map((p) => `${ref} like ${p}`).join(" || ");
          break;
        }
        case "Bool":
          test = vs.map((v) => `${ref} == ${v.toLowerCase() === "true"}`).join(" || ");
          break;
        case "Null":
          parts.push(vs[0].toLowerCase() === "true" ? `!(${has})` : has);
          continue;
        default:
          return note(where, `${rawOp} ${rawKey}: this condition operator is not mapped`), null;
      }
      // IAM: a missing key fails a positive test and passes a negated one; IfExists passes either way.
      if (negated) parts.push(`(!(${has}) || !(${test}))`);
      else parts.push(ifExists ? `(!(${has}) || ${test})` : `(${has} && (${test}))`);
    }
  }
  return parts.join(" && ");
}

const policies = [];
const sources = {};

/** One IAM statement as one Cedar policy, filed under `scope` (who it applies to). */
function statement(s, where, scope, principalClause) {
  const allow = s.Effect === "Allow";
  if (s.Principal || s.NotPrincipal) note(where, "a Principal in an identity policy is ignored");
  const clauses = ["context has iamAction"];
  // Actions: IAM matches them without regard to case.
  if (s.Action !== undefined || s.NotAction !== undefined) {
    const acts = list(s.Action ?? s.NotAction);
    if (!acts.includes("*") || s.NotAction) {
      const t = acts.map((a) => `context.iamAction like ${like(a.toLowerCase(), where)}`).join(" || ");
      clauses.push(s.NotAction ? `!(${t})` : `(${t})`);
    }
  }
  // Resources: ARNs match with case.
  const res = list(s.Resource ?? s.NotResource);
  if (!res.includes("*") || s.NotResource) {
    const ps = res.map((r) => like(r, where));
    if (ps.includes(null)) {
      note(where, `${res.join(", ")}: policy variables such as \${aws:username} are not mapped`);
      if (allow) return;
    } else {
      const t = ps.map((p) => `resource.arn like ${p}`).join(" || ");
      clauses.push(`resource has arn`, s.NotResource ? `!(${t})` : `(${t})`);
    }
  }
  if (s.Condition) {
    const c = condition(s.Condition, where);
    if (c === null) {
      if (allow) return note(where, "left out: an Allow with an unmapped condition never grants");
    } else if (c) clauses.push(c);
  }
  const id = `${where}`;
  policies.push(`@id(${str(id)})\n${allow ? "permit" : "forbid"}(${principalClause}, action, resource)\nwhen { ${clauses.join("\n    && ")} };`);
  sources[id] = { scope, statement: s, effect: s.Effect };
}

function document(doc, label, scope, principalClause) {
  list(decode(doc).Statement).forEach((s, i) => statement(s, `${label}#${s.Sid || i}`, scope, principalClause));
}

// ---- principals, policies and roles --------------------------------------------------

const groups = {};
const roles = {};
const directory = {};
const managed = {}; // name -> { arn, attached: [] }
const users = [];
const roleInfo = [];

for (const p of auth.Policies ?? []) {
  const v = p.PolicyVersionList.find((x) => x.IsDefaultVersion);
  const name = `policy/${p.PolicyName}`;
  managed[p.Arn] = { name, arn: p.Arn, aws: p.Arn.startsWith("arn:aws:iam::aws:"), members: [] };
  groups[name] = { description: `IAM managed policy ${p.Arn}`, members: [] };
  document(v.Document, name, { kind: "group", name }, `principal in Group::${str(name)}`);
}
const attach = (list_, member, where) => {
  for (const a of list_ ?? []) {
    const m = managed[a.PolicyArn];
    if (!m) note(where, `${a.PolicyArn} is attached but not in the input`);
    else groups[m.name].members.push(member);
  }
};

for (const u of auth.UserDetailList ?? []) {
  const id = u.Arn;
  directory[id] = { attrs: { iamType: "user", name: u.UserName, account } };
  users.push({ id, name: u.UserName, groups: u.GroupList ?? [], tags: u.Tags ?? [] });
  attach(u.AttachedManagedPolicies, id, `user/${u.UserName}`);
  for (const p of u.UserPolicyList ?? []) document(p.PolicyDocument, `user/${u.UserName}/${p.PolicyName}`, { kind: "user", name: id }, `principal == User::${str(id)}`);
  if (u.PermissionsBoundary) note(`user/${u.UserName}`, "a permissions boundary (a ceiling) is not mapped; Kith has no intersections yet");
}

for (const g of auth.GroupDetailList ?? []) {
  const name = `iam-group/${g.GroupName}`;
  groups[name] = { description: `IAM group ${g.Arn}`, members: (auth.UserDetailList ?? []).filter((u) => (u.GroupList ?? []).includes(g.GroupName)).map((u) => u.Arn) };
  attach(g.AttachedManagedPolicies, `group:${name}`, name);
  for (const p of g.GroupPolicyList ?? []) document(p.PolicyDocument, `${name}/${p.PolicyName}`, { kind: "group", name }, `principal in Group::${str(name)}`);
}

const trusted = new Map(); // principal id -> { kind, label }
for (const r of auth.RoleDetailList ?? []) {
  const where = `role/${r.RoleName}`;
  const rules = [];
  for (const [i, s] of list(decode(r.AssumeRolePolicyDocument).Statement).entries()) {
    const w = `${where}/trust#${s.Sid || i}`;
    if (s.Effect !== "Allow") {
      note(w, "a Deny in a trust policy is not mapped");
      continue;
    }
    if (s.NotPrincipal) {
      note(w, "NotPrincipal is not mapped");
      continue;
    }
    for (const [kind, vals] of Object.entries(s.Principal ?? {})) {
      for (const v of list(vals)) {
        let who;
        let keyName = (k) => k;
        if (kind === "Service") {
          const id = `service:${v}`;
          trusted.set(id, { kind: "service", label: v });
          who = `principal == User::${str(id)}`;
        } else if (kind === "Federated") {
          const provider = v.replace(/^arn:aws:iam::\d+:oidc-provider\//, "").replace(/^arn:aws:iam::\d+:saml-provider\//, "saml:");
          const id = `federated:${provider}`;
          trusted.set(id, { kind: "federated", label: provider });
          who = `principal == User::${str(id)}`;
          // A web identity's claims are its attributes: `token.actions.githubusercontent.com:sub` is `sub`.
          keyName = (k) => (k.startsWith(`${provider}:`) ? k.slice(provider.length + 1) : k);
        } else if (kind === "AWS") {
          if (v === "*") who = "true";
          else if (/^\d{12}$/.test(v) || v.endsWith(":root")) {
            const acct = v.match(/\d{12}/)[0];
            note(w, `trusts account ${acct}: in IAM a caller there also needs sts:AssumeRole in its own policies, which an assume rule cannot ask`);
            who = `principal has account && principal.account == ${str(acct)}`;
          } else if (v.includes(":role/")) {
            note(w, `${v}: role chaining is not mapped (an assumable role is never held standing)`);
            continue;
          } else {
            trusted.set(v, { kind: "aws", label: v });
            who = `principal == User::${str(v)}`;
          }
        } else {
          note(w, `${kind} principals are not mapped`);
          continue;
        }
        if (s.Condition) {
          const c = condition(s.Condition, w, "principal", keyName);
          if (c === null) {
            note(w, "left out: a trust statement with an unmapped condition admits no one");
            continue;
          }
          if (c) who = `${who} && ${c}`;
        }
        rules.push(`(${who})`);
      }
    }
  }
  const assume = { max_age: r.MaxSessionDuration ?? 3600 };
  if (rules.length) assume.rule = rules.join(" || ");
  else assume.members = [];
  roles[r.RoleName] = { description: `IAM role ${r.Arn}${r.Description ? `: ${r.Description}` : ""}`, assume };
  roleInfo.push({ name: r.RoleName, arn: r.Arn, path: r.Path, description: r.Description ?? "", maxSessionDuration: r.MaxSessionDuration, trust: decode(r.AssumeRolePolicyDocument), lastUsed: r.RoleLastUsed ?? null });
  // An assumable role has no members, so the policies attached to it are reached through
  // groups that list it: holding the role (by assuming it) joins them.
  attach(r.AttachedManagedPolicies, `role:${r.RoleName}`, where);
  for (const p of r.RolePolicyList ?? []) document(p.PolicyDocument, `${where}/${p.PolicyName}`, { kind: "role", name: r.RoleName }, `principal in Role::${str(r.RoleName)}`);
  if (r.PermissionsBoundary) note(where, "a permissions boundary (a ceiling) is not mapped; Kith has no intersections yet");
}

// Managed policies attached to no one are kept: they show what would be granted.
for (const [id, t] of trusted) directory[id] ??= { attrs: { iamType: t.kind, name: t.label } };

note("account", "resource-based policies (S3 bucket, KMS key, Lambda, SNS/SQS policies), SCPs and session policies are not in get-account-authorization-details and are not imported");

const bundle = { version: 1, groups, roles, directory, policies: policies.join("\n\n") };
const meta = {
  account,
  imported: new Date().toISOString(),
  users,
  roles: roleInfo,
  trusted: [...trusted].map(([id, t]) => ({ id, ...t })),
  managed: Object.values(managed).map((m) => ({ ...m, members: groups[m.name].members })),
  sources,
  notes,
};
mkdirSync(outDir, { recursive: true });
writeFileSync(join(outDir, "bundle.json"), JSON.stringify(bundle, null, 2));
writeFileSync(join(outDir, "iam.json"), JSON.stringify(meta, null, 2));
console.log(`${users.length} users, ${roleInfo.length} roles, ${Object.keys(managed).length} managed policies -> ${policies.length} Cedar policies; ${notes.length} notes`);
