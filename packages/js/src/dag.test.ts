import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { cidOf, canonical, loadSlice, MemBlocks, Recording, type Query } from "./dag.ts";

const vectors = JSON.parse(readFileSync(new URL("../../../spec/test-vectors/policy-dag.json", import.meta.url), "utf8"));

test("CIDs match @ipld/dag-json + multiformats", async () => {
  const bytes = new TextEncoder().encode(canonical({ hello: "world" }));
  assert.equal(await cidOf(bytes), "baguqeerasords4njcts6vs7qvdjfcvgnume4hqohf65zsfguprqphs3icwea");
});

test("every vector block hashes to its CID", async () => {
  for (const [cid, text] of Object.entries(vectors.blocks as Record<string, string>)) {
    assert.equal(await cidOf(new TextEncoder().encode(text)), cid);
    assert.equal(canonical(JSON.parse(text)), text, "blocks are canonical JSON");
  }
});

for (const s of vectors.slices) {
  test(`slice ${JSON.stringify(s.query)}`, async () => {
    const rec = new Recording(new MemBlocks(vectors.blocks));
    const slice = await loadSlice(rec, vectors.root, s.query as Query);
    assert.deepEqual(slice.policyIds(), s.policies);
    assert.deepEqual([...slice.sets.keys()], s.sets);
    assert.deepEqual(Object.keys(slice.directory).sort(), s.directory);
    // Reads exactly the proof blocks Rust read: no more, no less.
    assert.deepEqual([...rec.seen.keys()].sort(), s.proof);
  });
}

test("a withheld block fails closed", async () => {
  const q = vectors.slices[1];
  const blocks = { ...vectors.blocks };
  const forbid = q.proof.find((c: string) => blocks[c].includes('"effect":"forbid"'));
  delete blocks[forbid];
  await assert.rejects(loadSlice(new MemBlocks(blocks), vectors.root, q.query));
});

test("a tampered block is rejected", async () => {
  const blocks = { ...vectors.blocks };
  blocks[vectors.root] = blocks[vectors.root].replace('"version":1', '"version":2');
  await assert.rejects(loadSlice(new MemBlocks(blocks), vectors.root, vectors.slices[0].query), /does not match its hash/);
});
