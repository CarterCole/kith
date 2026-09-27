import { test } from "node:test";
import assert from "node:assert/strict";
import { KithClient } from "./client.ts";
import { SoftAuthenticator } from "./testing.ts";
import { b64uDecode, p256DidKey } from "./encoding.ts";

test("p256DidKey produces a zDn… did:key from SPKI", async () => {
  const auth = new SoftAuthenticator("localhost", "http://localhost");
  const { spki } = await auth.addKey();
  assert.match(p256DidKey(spki), /^did:key:zDn/);
});

test("loginWithPasskey sends a webauthn factor whose challenge is SHA-256(message)", async () => {
  const auth = new SoftAuthenticator("localhost", "http://localhost");
  await auth.addKey();
  const calls: any[] = [];
  const fakeFetch = (async (url: string, init: any) => {
    const body = JSON.parse(init.body);
    calls.push({ url, body });
    if (url.endsWith("/challenge")) return new Response(JSON.stringify({ challenge_id: "c1", message: "hello" }));
    return new Response(JSON.stringify({ access_token: "tok", token_type: "Bearer", expires_in: 900 }));
  }) as typeof fetch;
  const client = new KithClient({ hub: "http://hub", credentials: auth as any, fetch: fakeFetch, rpId: "localhost" });
  const tok = await client.loginWithPasskey({ did: "did:kith:x", deviceId: "dev_1", audience: "api" });
  assert.equal(tok, "tok");
  const factor = calls[1].body.factors[0];
  assert.equal(factor.type, "webauthn");
  const clientData = JSON.parse(new TextDecoder().decode(b64uDecode(factor.client_data_json)));
  const expected = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode("hello")));
  assert.deepEqual(b64uDecode(clientData.challenge), expected);
  assert.equal(client.token("api"), "tok");
});
