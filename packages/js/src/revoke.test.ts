import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { loadSlice, MemBlocks } from "./dag.ts";
import { Verifiers } from "./beacon.ts";
import { ed25519 } from "@noble/curves/ed25519.js";
import { b64u } from "./encoding.ts";
import { authorize, Follower, entryDigest, type Entry, type FreshnessPolicy } from "./revoke.ts";

/** The vectors' org admin key is Ed25519 with a seed of 32 × 0x01. */
async function signAsAdmin(e: Entry): Promise<Entry> {
  const unsigned = { ...e, sigs: [] };
  const d = await entryDigest(unsigned);
  const msg = new TextEncoder().encode(`kith revocation v1\norg: ${e.org}\nseq: ${e.seq}\ndigest: ${d}`);
  return { ...unsigned, sigs: [{ signer: e.sigs[0].signer, alg: "Ed25519", sig: b64u(ed25519.sign(msg, new Uint8Array(32).fill(1))) }] };
}

const v = JSON.parse(readFileSync(new URL("../../../spec/test-vectors/policy-dag.json", import.meta.url), "utf8"));
const r = v.revocations;

test("revocation vectors: decisions in order", async () => {
  const slice = await loadSlice(new MemBlocks(v.blocks), v.root, { kind: "actions", ...r.slice });
  const f = new Follower(r.org.did, 0, r.freshness as FreshnessPolicy);
  for (const e of r.entries) await f.applyEntry(r.org, e);
  await f.applyHeartbeat(r.org, r.heartbeat, await Verifiers.create(), r.heartbeat_received_at);
  for (const d of r.decisions) {
    assert.equal(f.freshness(d.now).level, d.level, d.name);
    const got = authorize(slice, f, { principal: { id: d.principal, attrs: d.attrs, groups: [], roles: [], actor: d.actor, caps: d.caps }, jti: d.jti, action: d.action, resource: d.resource, context: d.context }, d.now);
    assert.equal(got.allowed, d.allowed, `${d.name}: ${JSON.stringify(got)}`);
    if (d.reasons) assert.deepEqual(got.reasons, d.reasons, d.name);
  }
});

test("gaps, forks and forged signatures", async () => {
  const [e1, e2, e3] = r.entries as Entry[];
  const f = new Follower(r.org.did, 0, r.freshness);
  await f.applyEntry(r.org, e1);
  await f.applyEntry(r.org, e3);
  assert.equal(f.freshness(0).level, "behind", "entry 2 missing");
  await f.applyEntry(r.org, e2);
  assert.equal(f.seq(), 3);
  // A changed entry with a stale signature is just a forgery: rejected, no fork.
  await assert.rejects(f.applyEntry(r.org, { ...e3, ts: e3.ts + 1 }), /bad signature/);
  assert.equal(f.freshness(0).level, "stale");
  // A validly signed second entry 3: duplicity, and the org is treated as forked.
  const other = await signAsAdmin({ ...e3, ts: e3.ts + 1 });
  assert.equal((await entryDigest(await signAsAdmin(e3))), await entryDigest(e3), "re-signing reproduces the vector");
  await assert.rejects(f.applyEntry(r.org, other), /duplicity/);
  assert.equal(f.freshness(0).level, "forked");
  // A signature by a key that isn't a revoker.
  const g = new Follower(r.org.did, 0, r.freshness);
  const forged: Entry = { ...e1, sigs: [{ ...e1.sigs[0], signer: "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK" }] };
  await assert.rejects(g.applyEntry(r.org, forged));
  assert.equal(await entryDigest(e1), e2.prev);
});

test("a heartbeat claiming a beacon it doesn't have is rejected", async () => {
  const f = new Follower(r.org.did, 0, r.freshness);
  const hb = { ...r.heartbeat, beacon: { ...r.heartbeat.beacon, round: r.heartbeat.beacon.round + 1 } };
  await assert.rejects(f.applyHeartbeat(r.org, hb, await Verifiers.create(), r.heartbeat_received_at));
});
