/**
 * Revocations, heartbeats and freshness (spec §8.6–8.9). Same semantics as
 * `kith_core::revoke`: follow an org's signed revocation chain, measure how fresh
 * the view is from beacon-backed heartbeats, and decide with both applied.
 *
 * The org's key state (manage policy and devices) comes from a resolver you trust
 * for it (a hub, a pinned copy); entries and heartbeats are verified here.
 */
import { ed25519 } from "@noble/curves/ed25519.js";
import { b64u, b64uDecode, sha256 } from "./encoding.ts";
import { canonical, type Slice } from "./dag.ts";
import type { Decision, Principal, Resource } from "./authz.ts";
import type { BeaconValue, BeaconVerifier } from "./beacon.ts";

export type Revocation =
  | { kind: "principal"; id: string }
  | { kind: "member"; id: string; set: string }
  | { kind: "device"; did: string; device: string }
  | { kind: "policy"; id: string }
  | { kind: "token"; jti: string };

export interface Sig {
  signer: string;
  alg: string;
  sig: string;
}

export interface Entry {
  v: 1;
  org: string;
  seq: number;
  prev?: string;
  ts: number;
  revoke: Revocation[];
  sigs: Sig[];
}

export interface Heartbeat {
  v: 1;
  org: string;
  seq: number;
  head?: string;
  ts: number;
  beacon?: BeaconValue;
  sigs: Sig[];
}

export type SignerPolicy = string | { threshold: number; of: SignerPolicy[] };

/** What a verifier needs of an org's key state. */
export interface OrgState {
  did: string;
  manage: SignerPolicy;
  devices: { id: string; key: string; caps?: string[] }[];
}

export interface FreshnessPolicy {
  /** Up to this age (s) the view is fresh. */
  fresh_for: number;
  /** Up to this age (s) it is degraded; beyond, everything is denied. */
  max_staleness: number;
  /** Only beacon-backed heartbeats count. */
  require_beacon: boolean;
}

export const DEFAULT_FRESHNESS: FreshnessPolicy = { fresh_for: 120, max_staleness: 900, require_beacon: true };

export type Level = "fresh" | "degraded" | "stale" | "behind" | "forked";

export interface Freshness {
  level: Level;
  age: number | null;
  seq: number;
  head_seq: number;
}

const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

function base58Decode(s: string): Uint8Array {
  let n = 0n;
  for (const c of s) {
    const i = B58.indexOf(c);
    if (i < 0) throw new Error("bad base58");
    n = n * 58n + BigInt(i);
  }
  const bytes: number[] = [];
  while (n > 0n) {
    bytes.unshift(Number(n % 256n));
    n /= 256n;
  }
  for (const c of s) {
    if (c !== "1") break;
    bytes.unshift(0);
  }
  return new Uint8Array(bytes);
}

/** Verify one signature. JS supports Ed25519 `did:key` signers. */
function verifySig(s: Sig, msg: Uint8Array): boolean {
  if (!s.signer.startsWith("did:key:z") || s.alg !== "Ed25519") throw new Error(`unsupported signer ${s.signer} (${s.alg}) in JS`);
  const raw = base58Decode(s.signer.slice("did:key:z".length));
  if (raw.length !== 34 || raw[0] !== 0xed || raw[1] !== 0x01) throw new Error(`${s.signer} is not an Ed25519 did:key`);
  return ed25519.verify(b64uDecode(s.sig), msg, raw.slice(2));
}

function satisfied(p: SignerPolicy, signed: Set<string>): boolean {
  if (typeof p === "string") return signed.has(p);
  return p.of.filter((x) => satisfied(x, signed)).length >= p.threshold;
}

function mayRevoke(org: OrgState, signed: Set<string>): boolean {
  return satisfied(org.manage, signed) || org.devices.some((d) => (d.caps ?? []).includes("revoke") && signed.has(d.key));
}

async function digestOf(v: object): Promise<string> {
  const { sigs: _, ...payload } = v as Record<string, unknown>;
  return b64u(await sha256(canonical(payload)));
}

export const entryDigest = (e: Entry) => digestOf(e);
export const heartbeatDigest = (h: Heartbeat) => digestOf(h);

async function checkSigned(org: OrgState, sigs: Sig[], msg: string, what: string) {
  const bytes = new TextEncoder().encode(msg);
  const signed = new Set<string>();
  for (const s of sigs) {
    if (!verifySig(s, bytes)) throw new Error(`${what}: bad signature by ${s.signer}`);
    signed.add(s.signer);
  }
  if (!mayRevoke(org, signed)) throw new Error(`${what} is not signed by a revoker of ${org.did}`);
}

export async function verifyEntry(org: OrgState, e: Entry): Promise<string> {
  if (e.v !== 1 || e.org !== org.did || !(e.seq >= 1) || (e.seq === 1) !== (e.prev === undefined)) throw new Error(`malformed revocation entry ${e.seq}`);
  const d = await entryDigest(e);
  await checkSigned(org, e.sigs, `kith revocation v1\norg: ${e.org}\nseq: ${e.seq}\ndigest: ${d}`, `revocation ${e.seq}`);
  return d;
}

export async function verifyHeartbeat(org: OrgState, h: Heartbeat): Promise<void> {
  if (h.v !== 1 || h.org !== org.did || (h.seq === 0) !== (h.head === undefined)) throw new Error("malformed heartbeat");
  const d = await heartbeatDigest(h);
  await checkSigned(org, h.sigs, `kith revocation heartbeat v1\norg: ${h.org}\nseq: ${h.seq}\ndigest: ${d}`, "heartbeat");
}

/** A verifier's view of one org's revocations. */
export class Follower {
  readonly org: string;
  readonly policy: FreshnessPolicy;
  private base: number;
  private readonly entries = new Map<number, Entry>();
  private readonly digests = new Map<number, string>();
  private proven: number | null = null;
  private headSeq: number;
  private clock = 0;
  private forked = false;

  constructor(org: string, base = 0, policy: FreshnessPolicy = DEFAULT_FRESHNESS) {
    this.org = org;
    this.base = base;
    this.headSeq = base;
    this.policy = policy;
  }

  /** A new policy root arrived: drop entries it already reflects. */
  setBase(base: number) {
    if (base <= this.base) return;
    this.base = base;
    for (const s of [...this.entries.keys()]) if (s <= base) this.entries.delete(s);
    this.headSeq = Math.max(this.headSeq, base);
  }

  /** Newest contiguous entry held (or the base). */
  seq(): number {
    let s = this.base;
    while (this.entries.has(s + 1)) s++;
    return s;
  }

  async applyEntry(org: OrgState, e: Entry): Promise<void> {
    if (org.did !== this.org) throw new Error("entry for another org");
    const d = await verifyEntry(org, e);
    const known = this.digests.get(e.seq);
    if (known !== undefined) {
      if (known !== d) {
        this.forked = true;
        throw new Error(`duplicity: two revocation entries at seq ${e.seq}`);
      }
      return;
    }
    const before = this.digests.get(e.seq - 1);
    if (e.prev !== undefined && before !== undefined && e.prev !== before) {
      this.forked = true;
      throw new Error(`revocation ${e.seq} does not chain to ${e.seq - 1}`);
    }
    const next = this.entries.get(e.seq + 1);
    if (next && next.prev !== d) {
      this.forked = true;
      throw new Error(`revocation ${e.seq + 1} does not chain to ${e.seq}`);
    }
    this.digests.set(e.seq, d);
    if (e.seq > this.base) this.entries.set(e.seq, e);
    this.headSeq = Math.max(this.headSeq, e.seq);
  }

  async applyHeartbeat(org: OrgState, h: Heartbeat, beacons: BeaconVerifier, now: number): Promise<void> {
    if (org.did !== this.org) throw new Error("heartbeat for another org");
    await verifyHeartbeat(org, h);
    const known = this.digests.get(h.seq);
    if (h.head !== undefined && known !== undefined && h.head !== known) {
      this.forked = true;
      throw new Error(`duplicity: heartbeat names another entry ${h.seq}`);
    }
    let proven: number | null = null;
    if (h.beacon) proven = await beacons.verify(h.beacon);
    else if (!this.policy.require_beacon) proven = Math.min(h.ts, now);
    if (proven !== null) {
      if (proven > Math.max(now, this.clock) + 60) throw new Error("heartbeat proves a time in the future");
      this.proven = this.proven === null ? proven : Math.max(this.proven, proven);
    }
    this.headSeq = Math.max(this.headSeq, h.seq);
  }

  /** Freshness as of `now` (Unix seconds). The clock never goes backwards. */
  freshness(now: number): Freshness {
    this.clock = Math.max(this.clock, now);
    const seq = this.seq();
    const age = this.proven === null ? null : Math.max(0, this.clock - this.proven);
    let level: Level;
    if (this.forked) level = "forked";
    else if (this.headSeq > seq) level = "behind";
    else if (age !== null && age <= this.policy.fresh_for) level = "fresh";
    else if (age !== null && age <= this.policy.max_staleness) level = "degraded";
    else level = "stale";
    return { level, age, seq, head_seq: this.headSeq };
  }

  private *revocations(): Iterable<Revocation> {
    for (const e of this.entries.values()) yield* e.revoke;
  }

  isPrincipalRevoked(id: string): boolean {
    for (const r of this.revocations()) if (r.kind === "principal" && r.id === id) return true;
    return false;
  }
  isTokenRevoked(jti: string): boolean {
    for (const r of this.revocations()) if (r.kind === "token" && r.jti === jti) return true;
    return false;
  }
  isDeviceRevoked(did: string, device: string): boolean {
    for (const r of this.revocations()) if (r.kind === "device" && r.did === did && r.device === device) return true;
    return false;
  }
  excludedSets(id: string): Set<string> {
    const out = new Set<string>();
    for (const r of this.revocations()) if (r.kind === "member" && r.id === id) out.add(r.set);
    return out;
  }
  revokedPolicies(): Set<string> {
    const out = new Set<string>();
    for (const r of this.revocations()) if (r.kind === "policy") out.add(r.id);
    return out;
  }
}

export interface Request {
  principal: Principal;
  /** The token's `jti`, if the principal came from a token. */
  jti?: string;
  action: string;
  resource: Resource;
  context?: Record<string, unknown>;
}

/**
 * Decide with revocations and freshness applied (spec §8.9). Memberships are always
 * recomputed from the slice, so a token's `groups`/`roles` claims can't outlive a
 * revocation. Policies see `context.kith = {sync_age, degraded, revocation_seq}`.
 */
export function authorize(slice: Slice, follower: Follower, req: Request, now: number): Decision {
  const deny = (why: string): Decision => ({ allowed: false, reasons: [why], errors: [] });
  const f = follower.freshness(now);
  if (f.level !== "fresh" && f.level !== "degraded") return deny(`freshness:${f.level}`);
  if (follower.isPrincipalRevoked(req.principal.id)) return deny("revoked:principal");
  if (req.jti && follower.isTokenRevoked(req.jti)) return deny("revoked:token");
  const engine = slice.engine(follower.revokedPolicies());
  const attrs = engine.attributes(req.principal.id, req.principal.attrs);
  const m = engine.memberships(req.principal.id, attrs, follower.excludedSets(req.principal.id));
  const kith = { sync_age: f.age ?? Number.MAX_SAFE_INTEGER, degraded: f.level !== "fresh", revocation_seq: f.seq };
  return engine.authorize({ ...req.principal, attrs, groups: m.groups, roles: m.roles }, req.action, req.resource, { ...(req.context ?? {}), kith });
}

/**
 * Follow an org through a hub: fetch entries and the newest heartbeat now, then
 * keep up via server-sent events. `onChange` fires after every applied update.
 */
export class HubFeed {
  readonly follower: Follower;
  private readonly hub: string;
  private readonly org: OrgState;
  private readonly beacons: BeaconVerifier;
  private abort?: AbortController;

  constructor(hub: string, org: OrgState, follower: Follower, beacons: BeaconVerifier) {
    this.hub = hub.replace(/\/$/, "");
    this.org = org;
    this.follower = follower;
    this.beacons = beacons;
  }

  async sync(): Promise<void> {
    const r = await fetch(`${this.hub}/v1/revocations/${this.org.did}?after=${this.follower.seq()}`);
    if (!r.ok) throw new Error(`hub returned ${r.status}`);
    const body = (await r.json()) as { entries: Entry[]; heartbeat?: Heartbeat | null };
    for (const e of body.entries) await this.follower.applyEntry(this.org, e);
    if (body.heartbeat) await this.follower.applyHeartbeat(this.org, body.heartbeat, this.beacons, Math.floor(Date.now() / 1000));
  }

  /** Subscribe to pushes. Resolves when the stream ends or `stop()` is called. */
  async listen(onChange?: (f: Freshness) => void): Promise<void> {
    this.abort = new AbortController();
    const r = await fetch(`${this.hub}/v1/revocations/${this.org.did}/events`, { signal: this.abort.signal, headers: { accept: "text/event-stream" } });
    if (!r.ok || !r.body) throw new Error(`hub returned ${r.status}`);
    const reader = r.body.pipeThrough(new TextDecoderStream()).getReader();
    let buf = "";
    try {
      for (;;) {
        const { value, done } = await reader.read();
        if (done) return;
        buf += value;
        let i: number;
        while ((i = buf.indexOf("\n\n")) >= 0) {
          const block = buf.slice(0, i);
          buf = buf.slice(i + 2);
          const event = /^event: ?(.*)$/m.exec(block)?.[1];
          const data = block.split("\n").filter((l) => l.startsWith("data:")).map((l) => l.slice(5).trimStart()).join("\n");
          if (!data) continue;
          const now = Math.floor(Date.now() / 1000);
          if (event === "entry") await this.follower.applyEntry(this.org, JSON.parse(data));
          else if (event === "heartbeat") await this.follower.applyHeartbeat(this.org, JSON.parse(data), this.beacons, now);
          else continue;
          onChange?.(this.follower.freshness(now));
        }
      }
    } catch (e) {
      if ((e as Error).name !== "AbortError") throw e;
    }
  }

  stop() {
    this.abort?.abort();
  }
}
