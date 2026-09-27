/**
 * Groups (explicit + dynamic), roles and Cedar policy evaluation.
 *
 * Semantics match `kith_core::authz` in Rust exactly: dynamic membership rules are
 * Cedar expressions compiled into one policy each and evaluated to a fixpoint.
 */
import * as cedar from "@cedar-policy/cedar-wasm/nodejs";

export const MEMBER_ACTION = "kith:member";

export interface SetDef {
  description?: string;
  members?: string[];
  rule?: string;
}

export interface Bundle {
  version: number;
  groups?: Record<string, SetDef>;
  roles?: Record<string, SetDef>;
  directory?: Record<string, { attrs?: Record<string, unknown> }>;
  policies?: string;
}

export interface Capability {
  action: string;
  resource?: string;
}

export interface Principal {
  id: string;
  attrs: Record<string, unknown>;
  groups: string[];
  roles: string[];
  /** Set when an actor exercises a delegation on this principal's behalf. */
  actor?: string;
  caps?: Capability[];
}

export interface Resource {
  type: string;
  id: string;
  attrs?: Record<string, unknown>;
}

export interface Decision {
  allowed: boolean;
  reasons: string[];
  errors: string[];
}

type CedarValue = cedar.CedarValueJson;

/** Cedar has no null or floats: drop nulls, stringify non-integers, drop functions. */
export function cedarValue(v: unknown): CedarValue | undefined {
  if (v === null || v === undefined || typeof v === "function" || typeof v === "symbol") return undefined;
  if (typeof v === "number") return Number.isInteger(v) ? v : String(v);
  if (typeof v === "bigint") return Number(v);
  if (typeof v === "string" || typeof v === "boolean") return v;
  if (v instanceof Date) return v.toISOString();
  if (Array.isArray(v)) return v.map(cedarValue).filter((x): x is CedarValue => x !== undefined);
  if (typeof v === "object") {
    const out: Record<string, CedarValue> = {};
    for (const [k, x] of Object.entries(v as Record<string, unknown>)) {
      const c = cedarValue(x);
      if (c !== undefined) out[k] = c;
    }
    return out;
  }
  return undefined;
}

function cedarRecord(v: Record<string, unknown> | undefined): Record<string, CedarValue> {
  return (cedarValue(v ?? {}) as Record<string, CedarValue>) ?? {};
}

function glob(pattern: string, value: string): boolean {
  return pattern === "*" || pattern === value || (pattern.endsWith("*") && value.startsWith(pattern.slice(0, -1)));
}

export function capsAllow(caps: Capability[], action: string, resource: string): boolean {
  return caps.some((c) => glob(c.action, action) && glob(c.resource ?? "*", resource));
}

export function resourceUid(r: Resource): string {
  return `${r.type}::${JSON.stringify(r.id)}`;
}

let engineCounter = 0;

export class Engine {
  readonly bundle: Bundle;
  private readonly policySetId: string;
  private readonly membership: Record<string, string>;

  constructor(bundle: Bundle) {
    this.bundle = bundle;
    this.policySetId = `kith-${++engineCounter}`;
    const parsed = cedar.preparsePolicySet(this.policySetId, { staticPolicies: bundle.policies ?? "" });
    if (parsed.type === "failure") throw new Error(`policies: ${parsed.errors.map((e) => e.message).join("; ")}`);
    this.membership = {};
    for (const [kind, sets] of [["Group", bundle.groups], ["Role", bundle.roles]] as const) {
      for (const [name, def] of Object.entries(sets ?? {})) {
        if (!def.rule) continue;
        this.membership[`member:${kind}:${name}`] =
          `permit(principal, action == Action::"${MEMBER_ACTION}", resource == ${kind}::${JSON.stringify(name)}) when { ${def.rule} };`;
      }
    }
    // Parse each rule as exactly one policy: rejects rule text that tries to smuggle in extra policies.
    const check = cedar.checkParsePolicySet({ staticPolicies: this.membership });
    if (check.type === "failure") throw new Error(`membership rules: ${check.errors.map((e) => e.message).join("; ")}`);
  }

  /** Directory attributes merged with (and overridden by) `attrs`. */
  attributes(id: string, attrs: Record<string, unknown> = {}): Record<string, unknown> {
    return { ...(this.bundle.directory?.[id]?.attrs ?? {}), ...attrs };
  }

  private setEntities(): cedar.EntityJson[] {
    const out: cedar.EntityJson[] = [];
    for (const g of Object.keys(this.bundle.groups ?? {})) out.push({ uid: { type: "Group", id: g }, attrs: {}, parents: [] });
    for (const r of Object.keys(this.bundle.roles ?? {})) out.push({ uid: { type: "Role", id: r }, attrs: {}, parents: [] });
    return out;
  }

  private principalEntity(id: string, attrs: Record<string, unknown>, groups: Iterable<string>, roles: Iterable<string>): cedar.EntityJson {
    return {
      uid: { type: "User", id },
      attrs: cedarRecord(attrs),
      parents: [...[...groups].map((g) => ({ type: "Group", id: g })), ...[...roles].map((r) => ({ type: "Role", id: r }))],
    };
  }

  /** Compute explicit + nested + dynamic group and role membership. */
  memberships(id: string, attrs: Record<string, unknown>): { groups: string[]; roles: string[] } {
    const groups = new Set<string>();
    const roles = new Set<string>();
    const defs = [["Group", this.bundle.groups ?? {}, groups], ["Role", this.bundle.roles ?? {}, roles]] as const;
    const limit = Object.keys(this.bundle.groups ?? {}).length + Object.keys(this.bundle.roles ?? {}).length + 1;
    for (let i = 0; i < limit; i++) {
      let changed = false;
      const entities = [...this.setEntities(), this.principalEntity(id, attrs, groups, roles)];
      for (const [kind, sets, current] of defs) {
        for (const [name, def] of Object.entries(sets)) {
          if (current.has(name)) continue;
          const explicit = (def.members ?? []).some(
            (m) => m === id || (m.startsWith("group:") && groups.has(m.slice(6))) || (m.startsWith("role:") && roles.has(m.slice(5))),
          );
          let dynamic = false;
          if (!explicit && def.rule) {
            const r = cedar.isAuthorized({
              principal: { type: "User", id },
              action: { type: "Action", id: MEMBER_ACTION },
              resource: { type: kind, id: name },
              context: {},
              policies: { staticPolicies: { [`member:${kind}:${name}`]: this.membership[`member:${kind}:${name}`] } },
              entities,
            });
            dynamic = r.type === "success" && r.response.decision === "allow";
          }
          if (explicit || dynamic) {
            current.add(name);
            changed = true;
          }
        }
      }
      if (!changed) break;
    }
    return { groups: [...groups].sort(), roles: [...roles].sort() };
  }

  /**
   * Evaluate `action` on `resource`. Delegated principals must also hold a matching
   * capability: delegation can only narrow what the delegator could do.
   */
  authorize(principal: Principal, action: string, resource: Resource, context: Record<string, unknown> = {}): Decision {
    if (principal.caps && !capsAllow(principal.caps, action, resourceUid(resource))) {
      return { allowed: false, reasons: ["delegation:cap"], errors: [] };
    }
    const ctx = cedarRecord(context);
    if (principal.actor) ctx.actor = principal.actor;
    const r = cedar.statefulIsAuthorized({
      principal: { type: "User", id: principal.id },
      action: { type: "Action", id: action },
      resource: { type: resource.type, id: resource.id },
      context: ctx,
      preparsedPolicySetId: this.policySetId,
      entities: [
        ...this.setEntities(),
        this.principalEntity(principal.id, principal.attrs, principal.groups, principal.roles),
        { uid: { type: resource.type, id: resource.id }, attrs: cedarRecord(resource.attrs), parents: [] },
      ],
    });
    if (r.type === "failure") return { allowed: false, reasons: [], errors: r.errors.map((e) => e.message) };
    return {
      allowed: r.response.decision === "allow",
      reasons: r.response.diagnostics.reason,
      errors: r.response.diagnostics.errors.map((e) => `${e.policyId}: ${JSON.stringify(e.error)}`),
    };
  }
}
