/**
 * Browser-style passkey flow against a live hub, using a WebCrypto authenticator
 * in place of navigator.credentials:
 *   1. create a passkey → did:key
 *   2. `kith device add --key` (manage key signs), passkey signs for proof of possession
 *   3. loginWithPasskey → access token → call the GraphQL API
 * Usage: KITH_HOME=… KITH_BIN=… KITH_HUB=… node examples/passkey-e2e.ts
 */
import { execFileSync } from "node:child_process";
import { KithClient } from "../src/client.ts";
import { SoftAuthenticator } from "../src/testing.ts";

const hub = process.env.KITH_HUB!;
const kith = (...args: string[]) => execFileSync(process.env.KITH_BIN!, args, { encoding: "utf8", env: process.env });
const authenticator = new SoftAuthenticator("localhost", "http://localhost");
const client = new KithClient({ hub, credentials: authenticator as any, rpId: "localhost" });

const { did: passkey } = await client.createPasskey({ userName: "ada" });
const pending = JSON.parse(kith("device", "add", "--name", "browser passkey", "--key", passkey, "--kind", "passkey"));
const pop = await client.signWithPasskey(pending.message, passkey);
kith("device", "complete", "--sig", JSON.stringify(pop));
const did = kith("status").match(/"did": "([^"]+)"/)![1];

await client.loginWithPasskey({ did, deviceId: pending.device_id, audience: "api://invoices" });
const r = await client.fetch("api://invoices", process.env.GRAPHQL_URL ?? "http://127.0.0.1:4001/graphql", {
  method: "POST",
  headers: { "content-type": "application/json" },
  body: JSON.stringify({ query: "{ me { did aal roles } }" }),
});
console.log(JSON.stringify(await r.json()));
