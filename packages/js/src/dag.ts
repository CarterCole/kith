/**
 * Content-addressed blocks and the policy DAG reader (spec §8.1–8.5).
 *
 * Blocks are canonical JSON (valid DAG-JSON); CIDs are CIDv1 / dag-json / sha2-256.
 * Every block is hash-checked, so a block source can be anyone: the hub, an IPFS
 * trustless gateway, a peer, a cache. `loadSlice` reads only what one question
 * needs, and fails rather than returning a slice with something missing.
 */
import { sha256 } from "./encoding.ts";
import { Engine, type Bundle, type SetDef } from "./authz.ts";

export const DAG_VERSION = "kith-policy-dag/1";
export const ANY = "*";

/** Canonical JSON: sorted keys (UTF-16 order), no whitespace, integers only. */
export function canonical(v: unknown): string {
  if (v === null) return "null";
  if (typeof v === "boolean") return v ? "true" : "false";
  if (typeof v === "number") {
    if (!Number.isInteger(v)) throw new Error("canonical JSON forbids non-integer numbers");
    return String(v);
  }
  if (typeof v === "string") return JSON.stringify(v);
  if (Array.isArray(v)) return `[${v.map(canonical).join(",")}]`;
  if (typeof v === "object") {
    const o = v as Record<string, unknown>;
    const keys = Object.keys(o).filter((k) => o[k] !== undefined).sort();
    return `{${keys.map((k) => `${JSON.stringify(k)}:${canonical(o[k])}`).join(",")}}`;
  }
  throw new Error(`canonical JSON: unsupported ${typeof v}`);
}

const B32 = "abcdefghijklmnopqrstuvwxyz234567";

function base32(bytes: Uint8Array): string {
  let bits = 0, value = 0, out = "";
  for (const b of bytes) {
    value = (value << 8) | b;
    bits += 8;
    while (bits >= 5) {
      out += B32[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += B32[(value << (5 - bits)) & 31];
  return out;
}

/** CIDv1, dag-json (0x0129), sha2-256, base32 (`bagu…`). */
export async function cidOf(bytes: Uint8Array): Promise<string> {
  const digest = await sha256(bytes);
  return "b" + base32(new Uint8Array([0x01, 0xa9, 0x02, 0x12, 0x20, ...digest]));
}

/** Where blocks come from. Untrusted: `getVerified` checks every hash. */
export interface BlockSource {
  get(cid: string): Promise<Uint8Array | undefined> | Uint8Array | undefined;
}

/** Blocks held in memory, e.g. the `blocks` of a slice response (`{cid: text}`). */
export class MemBlocks implements BlockSource {
  readonly blocks = new Map<string, Uint8Array>();
  constructor(blocks: Record<string, string> = {}) {
    for (const [cid, text] of Object.entries(blocks)) this.blocks.set(cid, new TextEncoder().encode(text));
  }
  get(cid: string) {
    return this.blocks.get(cid);
  }
}

/** Any IPFS trustless gateway, or a Kith hub (`{base}/ipfs/{cid}`). */
export function gatewayBlocks(base: string, fetchImpl: typeof fetch = fetch): BlockSource {
  return {
    async get(cid) {
      const r = await fetchImpl(`${base.replace(/\/$/, "")}/ipfs/${cid}?format=raw`, { headers: { accept: "application/vnd.ipld.raw" } });
      return r.ok ? new Uint8Array(await r.arrayBuffer()) : undefined;
    },
  };
}

/** Wraps a source and records every block read: the proof for what was loaded. */
export class Recording implements BlockSource {
  readonly seen = new Map<string, Uint8Array>();
  private readonly inner: BlockSource;
  constructor(inner: BlockSource) {
    this.inner = inner;
  }
  async get(cid: string) {
    const b = await this.inner.get(cid);
    if (b) this.seen.set(cid, b);
    return b;
  }
}

export async function getVerified(src: BlockSource, cid: string): Promise<any> {
  const bytes = await src.get(cid);
  if (!bytes) throw new Error(`block ${cid} not found`);
  if ((await cidOf(bytes)) !== cid) throw new Error(`block ${cid} does not match its hash`);
  return JSON.parse(new TextDecoder().decode(bytes));
}

export function asLink(v: unknown): string | undefined {
  if (v && typeof v === "object" && !Array.isArray(v)) {
    const o = v as Record<string, unknown>;
    const keys = Object.keys(o);
    if (keys.length === 1 && typeof o["/"] === "string") return o["/"] as string;
  }
  return undefined;
}

async function nibble(key: string, depth: number): Promise<number> {
  const h = await sha256(key);
  const b = h[depth >> 1];
  return depth % 2 === 0 ? b >> 4 : b & 0x0f;
}

/** Look `key` up in a Merkle map. `undefined` is a proof of absence. */
export async function mapGet(src: BlockSource, root: string, key: string): Promise<unknown> {
  let cid = root;
  for (let depth = 0; depth <= 64; depth++) {
    const node = await getVerified(src, cid);
    if (Array.isArray(node.e)) {
      for (const [k, v] of node.e) if (k === key) return v;
      return undefined;
    }
    if (!Array.isArray(node.c) || node.c.length !== 16) throw new Error(`merkle map node ${cid} is malformed`);
    const child = node.c[await nibble(key, depth)];
    if (child === null) return undefined;
    const next = asLink(child);
    if (!next) throw new Error("merkle map child is not a link");
    cid = next;
  }
  throw new Error("merkle map too deep");
}

export interface PolicyEntry {
  id: string;
  effect: "permit" | "forbid";
  text: string;
  refs: string[];
}

export interface SetEntry {
  kind: "Group" | "Role";
  name: string;
  description?: string;
  members: string[];
  rule?: string;
  deps: string[];
  dependents: string[];
}

export type Query = { kind: "actions"; actions: string[]; principals?: string[] } | { kind: "principal"; id: string };

/** A verified, complete slice of a policy DAG. */
export class Slice {
  readonly root: string;
  readonly version: number;
  readonly sets: Map<string, SetEntry>;
  readonly policies: PolicyEntry[];
  readonly directory: Record<string, { attrs?: Record<string, unknown> }>;

  constructor(root: string, version: number, sets: Map<string, SetEntry>, policies: PolicyEntry[], directory: Record<string, { attrs?: Record<string, unknown> }>) {
    this.root = root;
    this.version = version;
    this.sets = sets;
    this.policies = policies;
    this.directory = directory;
  }

  policyIds(): string[] {
    return this.policies.map((p) => p.id);
  }

  /** The slice as a bundle. `skip` drops permit policies by id (revocation); forbids stay. */
  bundle(skip: Set<string> = new Set()): Bundle {
    const groups: Record<string, SetDef> = {};
    const roles: Record<string, SetDef> = {};
    for (const s of this.sets.values()) {
      const def: SetDef = { members: s.members };
      if (s.rule !== undefined) def.rule = s.rule;
      if (s.description !== undefined) def.description = s.description;
      (s.kind === "Group" ? groups : roles)[s.name] = def;
    }
    const policies: Record<string, string> = {};
    for (const p of this.policies) if (!(p.effect === "permit" && skip.has(p.id))) policies[p.id] = p.text;
    return { version: this.version, groups, roles, directory: this.directory, policies };
  }

  engine(skip: Set<string> = new Set()): Engine {
    return new Engine(this.bundle(skip));
  }
}

/** Read the slice for `query` from the DAG at `root` (the org's committed root). */
export async function loadSlice(src: BlockSource, root: string, query: Query): Promise<Slice> {
  const r = await getVerified(src, root);
  if (r.kith !== DAG_VERSION) throw new Error(`unsupported policy dag ${r.kith}`);
  const index = (name: string) => {
    const l = asLink(r[name]);
    if (!l) throw new Error(`policy dag root has no ${name} index`);
    return l;
  };
  const policies = new Map<string, PolicyEntry>();
  const sets = new Map<string, SetEntry>();
  const directory: Record<string, { attrs?: Record<string, unknown> }> = {};

  const addPolicies = async (idx: string, key: string) => {
    const links = (await mapGet(src, index(idx), key)) as unknown[] | undefined;
    for (const l of links ?? []) {
      const cid = asLink(l);
      if (!cid) throw new Error("policy index entry is not a link");
      const e = (await getVerified(src, cid)) as PolicyEntry;
      policies.set(e.id, e);
    }
  };
  const closure = async (start: string[], up: boolean) => {
    const queue = [...start];
    while (queue.length) {
      const k = queue.pop()!;
      if (sets.has(k)) continue;
      const l = await mapGet(src, index("sets"), k);
      if (l === undefined) continue;
      const cid = asLink(l);
      if (!cid) throw new Error("set index entry is not a link");
      const s = (await getVerified(src, cid)) as SetEntry;
      sets.set(k, s);
      queue.push(...(up ? s.dependents : s.deps));
    }
  };

  let principals: string[];
  if (query.kind === "actions") {
    for (const a of [...query.actions, ANY]) await addPolicies("actions", a);
    principals = query.principals ?? [];
  } else {
    const direct = ((await mapGet(src, index("members"), query.id)) as string[] | undefined) ?? [];
    await closure([...direct, ...((r.rules as string[]) ?? [])], true);
    for (const key of [...sets.keys(), ANY, `User::${query.id}`]) await addPolicies("principals", key);
    principals = [query.id];
  }
  const wanted = [...[...policies.values()].flatMap((p) => p.refs), ...[...sets.values()].flatMap((s) => s.deps)];
  await closure(wanted, false);
  for (const id of principals) {
    const d = await mapGet(src, index("directory"), id);
    if (d !== undefined) directory[id] = d as { attrs?: Record<string, unknown> };
  }
  const sortedSets = new Map([...sets.entries()].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)));
  const list = [...policies.values()].sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
  return new Slice(root, Number(r.version ?? 0), sortedSets, list, directory);
}
