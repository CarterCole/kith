/**
 * Lock down a graphql-js schema (Yoga, Apollo, Envelop, Mercurius, …) with Kith.
 *
 * - Every root field (`Query.*`, `Mutation.*`, `Subscription.*`) is checked as action
 *   `"<Type>.<field>"` on resource `Operation::"<Type>.<field>"`, with the field's
 *   arguments plus `operationType` as Cedar `context`. Default deny.
 * - Object fields are checked when marked `@auth` (or listed in `fields`, or with
 *   `mode: "all"`): action `"<Type>.<field>"` on the parent object as the resource.
 * - Row level: for types marked `@auth` at the type level (or listed in `rowLevel`),
 *   every object is checked with `"<Type>.read"`; lists are filtered, single objects
 *   are denied.
 */
import {
  GraphQLError,
  GraphQLObjectType,
  defaultFieldResolver,
  getNamedType,
  isObjectType,
  type GraphQLField,
  type GraphQLFieldResolver,
  type GraphQLSchema,
  type DirectiveNode,
} from "graphql";
import type { Engine, Principal, Resource } from "./authz.ts";
import { bearerToken, principalFromClaims, KithAuthError, type AccessClaims } from "./token.ts";

export const authDirectiveTypeDefs = /* GraphQL */ `
  "Kith: check this field (optionally with a custom action), or check every object of this type (row level)."
  directive @auth(action: String) on FIELD_DEFINITION | OBJECT
`;

export interface KithContext {
  kith?: { principal: Principal; claims?: AccessClaims };
}

export interface KithGraphQLOptions {
  engine: Engine;
  getPrincipal?: (ctx: any) => Principal | undefined;
  /** Principal used when no token is presented (policies can then allow public fields). */
  anonymous?: Principal;
  mode?: "root" | "all";
  rowLevel?: string[];
  fields?: string[];
  toResource?: (typeName: string, obj: any) => Resource;
  /** "error" (default) adds a FORBIDDEN error; "null" silently returns null. */
  onDeny?: "error" | "null";
  onDecision?: (e: { principal: Principal; action: string; resource: Resource; allowed: boolean; reasons: string[] }) => void;
}

function authDirective(nodes: readonly { directives?: readonly DirectiveNode[] }[] | undefined | null): { action?: string } | undefined {
  for (const n of nodes ?? []) {
    const d = n.directives?.find((x) => x.name.value === "auth");
    if (d) {
      const a = d.arguments?.find((x) => x.name.value === "action");
      return { action: a && a.value.kind === "StringValue" ? a.value.value : undefined };
    }
  }
  return undefined;
}

export function defaultToResource(typeName: string, obj: any): Resource {
  const attrs: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(obj ?? {})) {
    if (v === null || ["string", "number", "boolean"].includes(typeof v)) attrs[k] = v;
  }
  return { type: typeName, id: String(obj?.id ?? obj?._id ?? "?"), attrs };
}

function forbidden(action: string) {
  return new GraphQLError(`Not authorized: ${action}`, { extensions: { code: "FORBIDDEN", action } });
}

export function kithGraphQL(schema: GraphQLSchema, opts: KithGraphQLOptions): GraphQLSchema {
  const getPrincipal = opts.getPrincipal ?? ((ctx: KithContext) => ctx?.kith?.principal);
  const toResource = opts.toResource ?? defaultToResource;
  const rowTypes = new Set(opts.rowLevel ?? []);
  const fieldSet = new Set(opts.fields ?? []);
  const roots = new Set([schema.getQueryType(), schema.getMutationType(), schema.getSubscriptionType()].filter(Boolean).map((t) => t!.name));

  for (const type of Object.values(schema.getTypeMap())) {
    if (isObjectType(type) && !type.name.startsWith("__") && authDirective([type.astNode ?? {}, ...(type.extensionASTNodes ?? [])])) {
      rowTypes.add(type.name);
    }
  }

  const check = (principal: Principal, action: string, resource: Resource, context: Record<string, unknown>) => {
    const d = opts.engine.authorize(principal, action, resource, context);
    opts.onDecision?.({ principal, action, resource, allowed: d.allowed, reasons: d.reasons });
    return d.allowed;
  };

  for (const type of Object.values(schema.getTypeMap())) {
    if (!(type instanceof GraphQLObjectType) || type.name.startsWith("__")) continue;
    const isRoot = roots.has(type.name);
    for (const field of Object.values(type.getFields()) as GraphQLField<any, any>[]) {
      const key = `${type.name}.${field.name}`;
      const directive = authDirective([field.astNode ?? {}]);
      const checkField = isRoot || opts.mode === "all" || fieldSet.has(key) || !!directive;
      const returnType = getNamedType(field.type).name;
      const rowCheck = rowTypes.has(returnType);
      if (!checkField && !rowCheck) continue;

      const action = directive?.action ?? key;
      const original: GraphQLFieldResolver<any, any> = field.resolve ?? defaultFieldResolver;
      field.resolve = async (source, args, ctx, info) => {
        const principal = getPrincipal(ctx) ?? opts.anonymous;
        if (!principal) {
          throw new GraphQLError("Authentication required", { extensions: { code: "UNAUTHENTICATED" } });
        }
        const context = { ...args, operationType: info.operation.operation, field: key };
        if (checkField) {
          const resource = isRoot ? { type: "Operation", id: key } : toResource(type.name, source);
          if (!check(principal, action, resource, context)) {
            if (opts.onDeny === "null") return null;
            throw forbidden(action);
          }
        }
        const result = await original(source, args, ctx, info);
        if (!rowCheck || result == null) return result;
        const readAction = `${returnType}.read`;
        const visible = (item: any) => item == null || check(principal, readAction, toResource(returnType, item), { operationType: info.operation.operation, field: key });
        if (Array.isArray(result)) return result.filter(visible);
        if (!visible(result)) {
          if (opts.onDeny === "null") return null;
          throw forbidden(readAction);
        }
        return result;
      };
    }
  }
  return schema;
}

/** Build the GraphQL context from a Fetch `Request` (Yoga, Hono, Next, Workers, Deno…). */
export function kithContextFactory(verify: (token: string) => Promise<AccessClaims>) {
  return async ({ request }: { request: Request }): Promise<KithContext> => {
    const token = bearerToken(request.headers.get("authorization"));
    if (!token) return {};
    try {
      const claims = await verify(token);
      return { kith: { principal: principalFromClaims(claims), claims } };
    } catch (e) {
      if (e instanceof KithAuthError) throw new GraphQLError(e.message, { extensions: { code: "UNAUTHENTICATED", http: { status: 401 } } });
      throw e;
    }
  };
}
