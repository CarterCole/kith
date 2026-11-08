/** Verify hub-issued Kith access tokens (RFC 9068 JWTs, EdDSA) and turn them into principals. */
import { createRemoteJWKSet, createLocalJWKSet, jwtVerify, type JSONWebKeySet, type JWTVerifyGetKey } from "jose";
import type { Capability, Principal } from "./authz.ts";

export interface AccessClaims {
  iss: string;
  sub: string;
  aud: string;
  iat: number;
  exp: number;
  jti: string;
  /** The org whose policy produced `groups` and `roles`. Absent for memberships from a bundle file (spec 10.8). */
  org?: string;
  /** The policy root and newest revocation entry those memberships were computed from. */
  pol?: { root: string; rev: number };
  groups: string[];
  roles: string[];
  attrs: Record<string, unknown>;
  aal: number;
  amr: string[];
  dev?: string;
  act?: { sub: string; act?: unknown };
  cap?: Capability[];
}

/** The hub's signed statement that `sub` signed in as `account` at `provider_iss` (spec 7.8.1). */
export interface AccountAttestation {
  iss: string;
  sub: string;
  aud: string;
  iat: number;
  exp: number;
  jti: string;
  provider: string;
  provider_iss: string;
  account: string;
  verified_at: number;
}

export interface VerifierOptions {
  issuer: string;
  audience: string;
  /** Defaults to `${issuer}/.well-known/jwks.json`. */
  jwksUrl?: string;
  /** Static keys instead of fetching (tests, air-gapped). */
  jwks?: JSONWebKeySet;
  clockTolerance?: number;
  /**
   * Take `groups` and `roles` only from tokens that say this org produced them (spec 10.8).
   * Any other token still authenticates `sub`, with no memberships.
   */
  org?: string;
  /** Seconds since the epoch. Defaults to the system clock; tests pin it. */
  now?: () => number;
}

export class KithAuthError extends Error {
  readonly status: number;
  constructor(message: string, status = 401) {
    super(message);
    this.name = "KithAuthError";
    this.status = status;
  }
}

function hubKeys(opts: VerifierOptions): JWTVerifyGetKey {
  const jwks: JWTVerifyGetKey = opts.jwks
    ? createLocalJWKSet(opts.jwks)
    : createRemoteJWKSet(new URL(opts.jwksUrl ?? `${opts.issuer.replace(/\/$/, "")}/.well-known/jwks.json`));
  // A token names its key. With one key in the set jose would pick it without a kid.
  return (header, token) => {
    if (typeof header.kid !== "string" || !header.kid) throw new Error('the token has no "kid"');
    return jwks(header, token);
  };
}

/**
 * A verifier for hub access tokens (spec 3.5). It refuses a token that lacks `exp`,
 * `iat`, `sub`, `jti` or `aal`, that has no `kid`, whose `aud` is a list, or that was
 * issued in the future, and then returns the claims with defaults for the optional ones.
 */
export function createVerifier(opts: VerifierOptions) {
  const keys = hubKeys(opts);
  const tolerance = opts.clockTolerance ?? 60;
  const clock = opts.now ?? (() => Date.now() / 1000);
  return async function verify(token: string): Promise<AccessClaims> {
    try {
      const now = clock();
      const { payload } = await jwtVerify(token, keys, {
        issuer: opts.issuer,
        audience: opts.audience,
        typ: "at+jwt",
        algorithms: ["EdDSA"],
        clockTolerance: tolerance,
        currentDate: new Date(now * 1000),
        requiredClaims: ["exp", "iat", "sub", "jti", "aal"],
      });
      // jose accepts a list of audiences; a token minted for several could be replayed
      // between them, so ours name one.
      if (typeof payload.aud !== "string") throw new Error('"aud" must be a single string');
      if (typeof payload.sub !== "string" || !payload.sub) throw new Error('"sub" must be a non-empty string');
      if (typeof payload.jti !== "string" || !payload.jti) throw new Error('"jti" must be a non-empty string');
      if (!Number.isInteger(payload.aal) || (payload.aal as number) < 1 || (payload.aal as number) > 3) throw new Error('"aal" must be 1, 2 or 3');
      if ((payload.iat as number) - tolerance > now) throw new Error('"iat" is in the future');
      if (payload.org !== undefined && (typeof payload.org !== "string" || !payload.org)) throw new Error('"org" must be a non-empty string');
      if (payload.pol !== undefined) {
        const pol = payload.pol as { root?: unknown; rev?: unknown } | null;
        if (payload.org === undefined) throw new Error('"pol" needs an "org"');
        if (!pol || typeof pol !== "object" || typeof pol.root !== "string" || !pol.root || !Number.isInteger(pol.rev) || (pol.rev as number) < 0) {
          throw new Error('"pol" must be {root, rev}');
        }
      }
      const c = payload as unknown as Partial<AccessClaims>;
      const claims = { ...c, groups: c.groups ?? [], roles: c.roles ?? [], attrs: c.attrs ?? {}, amr: c.amr ?? [] } as AccessClaims;
      return opts.org === undefined ? claims : forOrg(claims, opts.org);
    } catch (e) {
      throw new KithAuthError(`invalid token: ${(e as Error).message}`);
    }
  };
}

/**
 * The claims as a resource server configured with `org` may rely on them (spec 10.8):
 * `groups` and `roles` survive only if the token says `org` produced them.
 */
export function forOrg(c: AccessClaims, org: string): AccessClaims {
  return c.org === org ? c : { ...c, groups: [], roles: [] };
}

/**
 * A verifier for account attestations (spec 7.8.1). `audience` is the app's client id.
 * Same rules as access tokens, with `typ` `kith-account+jwt`. It says who signed in and
 * when (`verified_at`); how recent that has to be is the app's call.
 */
export function createAttestationVerifier(opts: VerifierOptions) {
  const keys = hubKeys(opts);
  const tolerance = opts.clockTolerance ?? 60;
  const clock = opts.now ?? (() => Date.now() / 1000);
  return async function verify(token: string): Promise<AccountAttestation> {
    try {
      const now = clock();
      const { payload } = await jwtVerify(token, keys, {
        issuer: opts.issuer,
        audience: opts.audience,
        typ: "kith-account+jwt",
        algorithms: ["EdDSA"],
        clockTolerance: tolerance,
        currentDate: new Date(now * 1000),
        requiredClaims: ["exp", "iat", "sub", "jti", "provider", "provider_iss", "account", "verified_at"],
      });
      if (typeof payload.aud !== "string") throw new Error('"aud" must be a single string');
      for (const k of ["sub", "jti", "provider", "provider_iss", "account"]) {
        if (typeof payload[k] !== "string" || !payload[k]) throw new Error(`"${k}" must be a non-empty string`);
      }
      if (typeof payload.verified_at !== "number") throw new Error('"verified_at" must be a number');
      if ((payload.iat as number) - tolerance > now) throw new Error('"iat" is in the future');
      if (payload.verified_at - tolerance > now) throw new Error('"verified_at" is in the future');
      return payload as unknown as AccountAttestation;
    } catch (e) {
      throw new KithAuthError(`invalid attestation: ${(e as Error).message}`);
    }
  };
}

export function bearerToken(header: string | null | undefined): string | undefined {
  const m = /^Bearer\s+(.+)$/i.exec(header ?? "");
  return m?.[1];
}

export function principalFromClaims(c: AccessClaims): Principal {
  return {
    id: c.sub,
    attrs: { ...c.attrs, aal: c.aal, amr: c.amr },
    groups: c.groups,
    roles: c.roles,
    actor: c.act?.sub,
    caps: c.cap,
  };
}
