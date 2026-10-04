/**
 * Public randomness beacons as proof of freshness (spec §8.8). Same semantics as
 * `kith_core::beacon`: a verified beacon value becomes the time it was published.
 *
 * Works in browsers and Node: BLS12-381 via @noble/curves, RSA via WebCrypto.
 */
import { bls12_381 } from "@noble/curves/bls12-381.js";
import { sha256 as nobleSha256 } from "@noble/hashes/sha2.js";
import { INMETRO_CERT } from "./certs.ts";

export const QUICKNET_CHAIN = "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971";
export const QUICKNET_PUBLIC_KEY =
  "83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c8c4b450b6a0a6c3ac6a5776a2d1064510d1fec758c921cc22b0e17e63aaf4bcb5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a";
const DRAND_G1_DST = "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_";

export const NIST2_ORIGINS = ["https://beacon.nist.gov/beacon/2.0", "https://beacon.inmetro.gov.br/beacon/2.1", "https://beacon.inmetro.gov.br/beacon/2.0"];

export type BeaconValue = { type: "drand"; chain: string; round: number; signature: string } | { type: "nist2"; pulse: Record<string, any> };

export interface BeaconVerifier {
  /** The Unix time the value was published; throws if it doesn't verify. */
  verify(v: BeaconValue): Promise<number>;
}

export interface DrandChain {
  publicKey: string;
  genesis: number;
  period: number;
}

export function hexBytes(s: string): Uint8Array<ArrayBuffer> {
  if (s.length % 2 !== 0 || /[^0-9a-f]/i.test(s)) throw new Error("bad hex");
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function toHex(b: Uint8Array): string {
  return [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
}

/** Verify an unchained drand G1 signature (quicknet); returns the round's time. */
export function verifyDrand(chain: DrandChain, round: number, signatureHex: string): number {
  if (!Number.isInteger(round) || round < 1) throw new Error("drand round must be a positive integer");
  const msg = new Uint8Array(8);
  new DataView(msg.buffer).setBigUint64(0, BigInt(round), false);
  const bls = bls12_381.shortSignatures;
  let ok = false;
  try {
    ok = bls.verify(hexBytes(signatureHex), bls.hash(nobleSha256(msg), DRAND_G1_DST), hexBytes(chain.publicKey));
  } catch {
    ok = false;
  }
  if (!ok) throw new Error(`drand round ${round}: bad signature`);
  return chain.genesis + (round - 1) * chain.period;
}

/** The byte string a NIST 2.0 pulse is signed over, as deployed (4-byte lengths). */
export function nist2Serialize(p: Record<string, any>): Uint8Array<ArrayBuffer> {
  const parts: number[] = [];
  const u32 = (n: number) => parts.push((n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255);
  const u64 = (n: number) => {
    const b = new Uint8Array(8);
    new DataView(b.buffer).setBigUint64(0, BigInt(n), false);
    parts.push(...b);
  };
  const bytes = (b: Uint8Array) => (u32(b.length), parts.push(...b));
  const str = (s: unknown) => {
    if (typeof s !== "string") throw new Error("beacon pulse: missing string field");
    bytes(new TextEncoder().encode(s));
  };
  const hex = (s: unknown) => {
    if (typeof s !== "string") throw new Error("beacon pulse: missing hex field");
    bytes(hexBytes(s));
  };
  const int = (n: unknown) => {
    if (typeof n !== "number") throw new Error("beacon pulse: missing integer");
    return n;
  };
  str(p.uri);
  str(p.version);
  u32(int(p.cipherSuite));
  u32(int(p.period));
  hex(p.certificateId);
  u64(int(p.chainIndex));
  u64(int(p.pulseIndex));
  str(p.timeStamp);
  hex(p.localRandomValue);
  const ext = p.external;
  if (!ext || typeof ext !== "object" || Array.isArray(ext)) throw new Error("beacon pulse: `external` must be one object");
  hex(ext.sourceId);
  u32(int(ext.statusCode));
  hex(ext.value);
  const list: any[] = p.listValues ?? [];
  for (const t of ["previous", "hour", "day", "month", "year"]) {
    const v = list.find((x) => x.type === t);
    if (!v) throw new Error(`beacon pulse: no ${t} value`);
    hex(v.value);
  }
  hex(p.precommitmentValue);
  u32(int(p.statusCode));
  return new Uint8Array(parts);
}

function pemToDer(pem: string): Uint8Array<ArrayBuffer> {
  const body = pem.split(/\r?\n/).map((l) => l.trim()).filter((l) => l && !l.startsWith("-----")).join("");
  return Uint8Array.from(atob(body), (c) => c.charCodeAt(0));
}

function tlv(b: Uint8Array, at: number): { tag: number; start: number; end: number; body: number } {
  const tag = b[at];
  let len = b[at + 1];
  let hdr = 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n === 0 || n > 4) throw new Error("certificate DER");
    len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + b[at + 2 + i];
    hdr = 2 + n;
  }
  if (at + hdr + len > b.length) throw new Error("certificate DER");
  return { tag, start: at, end: at + hdr + len, body: at + hdr };
}

/** SubjectPublicKeyInfo of an X.509 certificate (DER). */
function spkiOf(der: Uint8Array<ArrayBuffer>): Uint8Array<ArrayBuffer> {
  const cert = tlv(der, 0);
  const tbs = tlv(der, cert.body);
  const fields: { tag: number; start: number; end: number }[] = [];
  for (let at = tbs.body; at < tbs.end; ) {
    const f = tlv(der, at);
    fields.push(f);
    at = f.end;
  }
  const skip = fields[0]?.tag === 0xa0 ? 1 : 0;
  const spki = fields[skip + 5];
  if (!spki) throw new Error("certificate has no public key");
  return der.slice(spki.start, spki.end);
}

/** Parse `YYYY-MM-DDTHH:MM:SS(.fff)Z` as Unix seconds. */
export function parseUtc(s: string): number {
  if (!/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)?Z$/.test(s)) throw new Error(`timestamp ${s}`);
  return Math.floor(Date.parse(s) / 1000);
}

/** drand chains by hash, and NIST 2.0-format beacons by origin, certificates by id. */
export class Verifiers implements BeaconVerifier {
  readonly drand = new Map<string, DrandChain>([[QUICKNET_CHAIN, { publicKey: QUICKNET_PUBLIC_KEY, genesis: 1692803367, period: 3 }]]);
  readonly nistOrigins = [...NIST2_ORIGINS];
  private readonly nistKeys = new Map<string, CryptoKey>();

  /** The standard set, with the pinned Inmetro certificate loaded. */
  static async create(): Promise<Verifiers> {
    const v = new Verifiers();
    await v.addNistCertificate(INMETRO_CERT);
    return v;
  }

  /** Fetch and add the certificate a pulse names, from its own (allowed) origin. */
  async loadNistCertificate(pulse: Record<string, any>, fetchImpl: typeof fetch = fetch): Promise<void> {
    const { base, id } = this.nistCertificateUrl(pulse);
    if (this.nistKeys.has(id)) return;
    const r = await fetchImpl(`${base}/certificate/${id}`);
    if (!r.ok) throw new Error(`beacon certificate ${id}: ${r.status}`);
    if ((await this.addNistCertificate(await r.text())) !== id) throw new Error(`beacon certificate ${id}: served certificate has another id`);
  }

  /** Where a pulse's certificate lives: `${base}/certificate/${id}`. */
  nistCertificateUrl(pulse: Record<string, any>): { base: string; id: string } {
    const uri = String(pulse.uri ?? "");
    const base = this.nistOrigins.find((o) => uri.startsWith(o + "/"));
    if (!base) throw new Error(`beacon origin of ${uri} is not allowed`);
    return { base, id: String(pulse.certificateId ?? "").toLowerCase() };
  }

  /** Add a certificate (PEM). Its id is SHA-512 of its DER. Returns the id. */
  async addNistCertificate(pem: string): Promise<string> {
    const der = pemToDer(pem);
    const id = toHex(new Uint8Array(await crypto.subtle.digest("SHA-512", der)));
    const key = await crypto.subtle.importKey("spki", spkiOf(der), { name: "RSASSA-PKCS1-v1_5", hash: "SHA-512" }, false, ["verify"]);
    this.nistKeys.set(id, key);
    return id;
  }

  hasNistCertificate(id: string): boolean {
    return this.nistKeys.has(id.toLowerCase());
  }

  async verify(v: BeaconValue): Promise<number> {
    if (v.type === "drand") {
      const chain = this.drand.get(v.chain);
      if (!chain) throw new Error(`unknown drand chain ${v.chain}`);
      return verifyDrand(chain, v.round, v.signature);
    }
    const p = v.pulse;
    const { id } = this.nistCertificateUrl(p);
    if (p.cipherSuite !== 0) throw new Error(`NIST beacon cipher suite ${p.cipherSuite}`);
    const key = this.nistKeys.get(id);
    if (!key) throw new Error(`beacon certificate ${id} not loaded`);
    const msg = nist2Serialize(p);
    const sig = hexBytes(String(p.signatureValue ?? ""));
    if (!(await crypto.subtle.verify("RSASSA-PKCS1-v1_5", key, sig, msg))) throw new Error(`beacon pulse ${p.uri}: bad signature`);
    // NIST hashes the raw signature into outputValue; Inmetro a length-prefixed one.
    const out = String(p.outputValue ?? "").toLowerCase();
    const len = new Uint8Array(4);
    new DataView(len.buffer).setUint32(0, sig.length, false);
    const raw = toHex(new Uint8Array(await crypto.subtle.digest("SHA-512", new Uint8Array([...msg, ...sig]))));
    const prefixed = toHex(new Uint8Array(await crypto.subtle.digest("SHA-512", new Uint8Array([...msg, ...len, ...sig]))));
    if (out !== raw && out !== prefixed) throw new Error("beacon pulse: outputValue does not match");
    return parseUtc(p.timeStamp);
  }
}
