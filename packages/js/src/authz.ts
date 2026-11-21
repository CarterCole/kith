/**
 * Groups (explicit + dynamic), roles and Cedar policy evaluation.
 *
 * Semantics match `kith_core::authz` in Rust exactly: dynamic membership rules are
 * Cedar expressions compiled into one policy each and evaluated to a fixpoint.
 */
import * as cedar from "@cedar-policy/cedar-wasm/nodejs";

export const MEMBER_ACTION = "kith:member";
/** The action an `assume` rule compiles to (spec §4.3.1). */
export const ASSUME_ACTION = "kith:assume";

/** Who may take on a role for a session, and for how long (spec §4.3.1). */
export interface AssumeDef {
  /** Principal ids, `group:<name>` and `role:<name>`, as in a set's `members`. */
  members?: string[];
  /** A Cedar expression over `principal`, as in a set's `rule`. */
  rule?: string;
  /** The longest an access token carrying the role may live, in seconds. */
  max_age?: number;
}

export interface SetDef {
  description?: string;
  members?: string[];
  rule?: string;
  /** Roles only: who may assume this role. Such a role has no `members` and no `rule`. A role without it is never assumed. */
  assume?: AssumeDef | null;
}

/** Why a session may not assume a role (spec §4.3.1). */
export type Refusal = "not_assumable" | "not_eligible";

export interface Bundle {
  version: number;
  groups?: Record<string, SetDef>;
  roles?: Record<string, SetDef>;
  directory?: Record<string, { attrs?: Record<string, unknown> }>;
  /** Cedar source, or policies by id (as a policy DAG slice provides them). */
  policies?: string | Record<string, string>;
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
  /** The role this session assumed (spec §4.3.1). It is in `roles` as well. */
  assumed?: string;
}

/** A reference to an entity: a parent of a resource (spec §4.2.1). */
export interface EntityRef {
  type: string;
  id: string;
}

/**
 * An entity a request describes besides its principal and resource (spec §4.2.1): an
 * ancestor of the resource, or something one of its attributes refers to.
 */
export interface Entity extends EntityRef {
  attrs?: Record<string, unknown>;
  parents?: EntityRef[];
}

export interface Resource {
  type: string;
  id: string;
  attrs?: Record<string, unknown>;
  /** What the resource is directly in. `resource in Folder::"x"` holds when `x` is a parent, or is reached from one through `related`. */
  parents?: EntityRef[];
  /** The other entities policies may walk to from this resource. */
  related?: Entity[];
}

/**
 * Typed values (spec §4.2.2), in the form Cedar's JSON reads. A plain string is always
 * a `String`: an address, a time or a decimal has to say that it is one.
 */
const ext = (fn: string, arg: string) => ({ __extn: { fn, arg } });
/** An IP address or CIDR range: `10.1.2.3`, `10.0.0.0/8`, `::1`. */
export const ip = (text: string) => ext("ip", text);
/** A decimal with at most four fractional digits: `12.50`. */
export const decimal = (text: string) => ext("decimal", text);
/** A date or an instant: `2030-01-01`, `2030-01-01T09:30:00Z`, or a `Date`. */
export const datetime = (value: string | Date) => ext("datetime", typeof value === "string" ? value : value.toISOString());
/** A length of time: `1h30m`, `-2d`. */
export const duration = (text: string) => ext("duration", text);
/** A reference to another entity, such as a document's owner. */
export const entityRef = (type: string, id: string) => ({ __entity: { type, id } });

/** Entity types a request may not describe: the bundle and the engine supply these. */
function reservedType(type: string): boolean {
  return type === "Group" || type === "Role" || type === "Action" || type.endsWith("::Action");
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
  if (typeof v === "number") return Number.isSafeInteger(v) ? v : String(v);
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
  private readonly assumeRules: Record<string, string>;

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
    this.assumeRules = {};
    for (const [kind, sets] of [["Group", bundle.groups], ["Role", bundle.roles]] as const) {
      for (const [name, def] of Object.entries(sets ?? {})) {
        const a = def.assume;
        if (a === undefined) continue;
        if (a === null) throw new Error(`${kind.toLowerCase()} ${name}: assume is an object, not null`);
        if (kind === "Group") throw new Error(`group ${name}: only a role can be assumed`);
        if ((def.members ?? []).length > 0 || def.rule !== undefined) {
          throw new Error(`role ${name} is assumable, so it is held only by assuming it: it has no members and no rule`);
        }
        if (typeof a !== "object" || Array.isArray(a)) throw new Error(`role ${name}: assume is an object`);
        if (a.members !== undefined && (!Array.isArray(a.members) || a.members.some((m) => typeof m !== "string"))) {
          throw new Error(`role ${name}: assume.members is a list of strings`);
        }
        if (a.rule !== undefined && typeof a.rule !== "string") throw new Error(`role ${name}: assume.rule is a string`);
        if (a.max_age !== undefined && !(Number.isSafeInteger(a.max_age) && a.max_age > 0)) {
          throw new Error(`role ${name}: max_age is a positive number of seconds`);
        }
        if (a.rule !== undefined) {
          this.assumeRules[`assume:${name}`] =
            `permit(principal, action == Action::"${ASSUME_ACTION}", resource == Role::${JSON.stringify(name)}) when { ${a.rule} };`;
        }
      }
    }
    // Parse each rule as exactly one policy: rejects rule text that tries to smuggle in extra policies.
    const check = cedar.checkParsePolicySet({ staticPolicies: { ...this.membership, ...this.assumeRules } });
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

  /**
   * Compute explicit + nested + dynamic group and role membership. Sets in
   * `excluded` (`Group::x`, `Role::x`, from revocations) never join, so neither do
   * sets that depended on them.
   */
  memberships(id: string, attrs: Record<string, unknown>, excluded: Set<string> = new Set()): { groups: string[]; roles: string[] } {
    return this.fixpoint(id, attrs, excluded);
  }

  /** The §4.3 fixpoint. `seed` is an assumed role (§4.3.1), held from the start. */
  private fixpoint(id: string, attrs: Record<string, unknown>, excluded: Set<string>, seed?: string): { groups: string[]; roles: string[] } {
    const groups = new Set<string>();
    const roles = new Set<string>(seed === undefined ? [] : [seed]);
    const defs = [["Group", this.bundle.groups ?? {}, groups], ["Role", this.bundle.roles ?? {}, roles]] as const;
    const limit = Object.keys(this.bundle.groups ?? {}).length + Object.keys(this.bundle.roles ?? {}).length + 1;
    for (let i = 0; i < limit; i++) {
      let changed = false;
      const entities = [...this.setEntities(), this.principalEntity(id, attrs, groups, roles)];
      for (const [kind, sets, current] of defs) {
        for (const [name, def] of Object.entries(sets)) {
          if (current.has(name) || excluded.has(`${kind}::${name}`)) continue;
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
   * Memberships for a session that assumes `role` (spec §4.3.1): the standing ones, with
   * the sets in `excluded` revoked, plus the role. The role must have an `assume`
   * setting that the principal meets, and must not be in `excluded`.
   */
  assume(id: string, attrs: Record<string, unknown>, excluded: Set<string>, role: string): { groups: string[]; roles: string[] } | { refused: Refusal } {
    const def = Object.hasOwn(this.bundle.roles ?? {}, role) ? this.bundle.roles![role] : undefined;
    const a = def?.assume;
    if (a === undefined || a === null) return { refused: "not_assumable" };
    const m = this.memberships(id, attrs, excluded);
    if (excluded.has(`Role::${role}`)) return { refused: "not_eligible" };
    const listed = (a.members ?? []).some(
      (x) => x === id || (x.startsWith("group:") && m.groups.includes(x.slice(6))) || (x.startsWith("role:") && m.roles.includes(x.slice(5))),
    );
    let byRule = false;
    if (!listed && a.rule !== undefined) {
      const r = cedar.isAuthorized({
        principal: { type: "User", id },
        action: { type: "Action", id: ASSUME_ACTION },
        resource: { type: "Role", id: role },
        context: {},
        policies: { staticPolicies: { [`assume:${role}`]: this.assumeRules[`assume:${role}`] } },
        entities: [...this.setEntities(), this.principalEntity(id, attrs, m.groups, m.roles)],
      });
      byRule = r.type === "success" && r.response.decision === "allow";
    }
    if (!listed && !byRule) return { refused: "not_eligible" };
    // Eligibility is decided on what the principal holds standing; the session is then
    // computed with the role in place, so a forbid on a set that lists it applies.
    return this.fixpoint(id, attrs, excluded, role);
  }

  /** The longest an access token may carry `role` as assumed, if the role says. */
  assumeMaxAge(role: string): number | undefined {
    return Object.hasOwn(this.bundle.roles ?? {}, role) ? (this.bundle.roles![role].assume?.max_age ?? undefined) : undefined;
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
    const refs = (ps: EntityRef[] | undefined) => (ps ?? []).map((p) => ({ type: p.type, id: p.id }));
    // A related entity describes something new. It never restates the principal, the
    // resource, a set or an action, whose parents decide who is in what.
    const seen = new Set([JSON.stringify(["User", principal.id]), JSON.stringify([resource.type, resource.id])]);
    const related: cedar.EntityJson[] = [];
    for (const r of resource.related ?? []) {
      const key = JSON.stringify([r.type, r.id]);
      if (reservedType(r.type) || seen.has(key)) return { allowed: false, reasons: ["entities:conflict"], errors: [] };
      seen.add(key);
      related.push({ uid: { type: r.type, id: r.id }, attrs: cedarRecord(r.attrs), parents: refs(r.parents) });
    }
    const r = cedar.statefulIsAuthorized({
      principal: { type: "User", id: principal.id },
      action: { type: "Action", id: action },
      resource: { type: resource.type, id: resource.id },
      context: ctx,
      preparsedPolicySetId: this.policySetId,
      entities: [
        ...this.setEntities(),
        this.principalEntity(principal.id, principal.attrs, principal.groups, principal.roles),
        { uid: { type: resource.type, id: resource.id }, attrs: cedarRecord(resource.attrs), parents: refs(resource.parents) },
        ...related,
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
