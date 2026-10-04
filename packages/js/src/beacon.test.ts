import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { Verifiers, parseUtc } from "./beacon.ts";

const v = JSON.parse(readFileSync(new URL("../../../spec/test-vectors/beacons.json", import.meta.url), "utf8"));

for (const c of v.drand.cases) {
  test(`drand: ${c.name}`, async () => {
    const verifiers = await Verifiers.create();
    const got = verifiers.verify({ type: "drand", chain: v.drand.chain, round: c.round, signature: c.signature });
    if (c.ok) assert.equal(await got, c.time);
    else await assert.rejects(got);
  });
}

for (const c of v.nist2.cases) {
  test(`nist2: ${c.name}`, async () => {
    const verifiers = await Verifiers.create();
    for (const pem of Object.values(v.nist2.certificates) as string[]) await verifiers.addNistCertificate(pem);
    const got = verifiers.verify({ type: "nist2", pulse: c.pulse });
    if (c.ok) assert.equal(await got, c.time);
    else await assert.rejects(got);
  });
}

test("nist2: origins outside the allowlist are refused", async () => {
  const verifiers = await Verifiers.create();
  const pulse = { ...v.nist2.cases[0].pulse, uri: "https://evil.example/beacon/2.0/chain/2/pulse/1" };
  await assert.rejects(verifiers.verify({ type: "nist2", pulse }), /not allowed/);
});

test("utc parsing", () => {
  assert.equal(parseUtc("2026-09-27T19:49:00.000Z"), 1790538540);
});
