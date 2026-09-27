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
  groups: string[];
  roles: string[];
  attrs: Record<string, unknown>;
  aal: number;
  amr: string[];
  dev?: string;
  act?: { sub: string; act?: unknown };
  cap?: Capability[];
}

export interface VerifierOptions {
  issuer: string;
  audience: string;
  /** Defaults to `${issuer}/.well-known/jwks.json`. */
  jwksUrl?: string;
  /** Static keys instead of fetching (tests, air-gapped). */
  jwks?: JSONWebKeySet;
  clockTolerance?: number;
}

export class KithAuthError extends Error {
  readonly status: number;
  constructor(message: string, status = 401) {
    super(message);
    this.name = "KithAuthError";
    this.status = status;
  }
}

export function createVerifier(opts: VerifierOptions) {
  const keys: JWTVerifyGetKey = opts.jwks
    ? createLocalJWKSet(opts.jwks)
    : createRemoteJWKSet(new URL(opts.jwksUrl ?? `${opts.issuer.replace(/\/$/, "")}/.well-known/jwks.json`));
  return async function verify(token: string): Promise<AccessClaims> {
    try {
      const { payload } = await jwtVerify(token, keys, {
        issuer: opts.issuer,
        audience: opts.audience,
        typ: "at+jwt",
        algorithms: ["EdDSA"],
        clockTolerance: opts.clockTolerance ?? 60,
      });
      const c = payload as unknown as Partial<AccessClaims>;
      return { ...c, groups: c.groups ?? [], roles: c.roles ?? [], attrs: c.attrs ?? {}, amr: c.amr ?? [] } as AccessClaims;
    } catch (e) {
      throw new KithAuthError(`invalid token: ${(e as Error).message}`);
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
