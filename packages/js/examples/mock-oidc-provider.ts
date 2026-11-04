/**
 * A stand-in "Sign in with …" provider for tests: authorization code + PKCE, ES256 ID
 * tokens, discovery and JWKS. It signs in the same account every time, with no prompt.
 *   MOCK_SUB=browser-user-1 PORT=7792 node examples/mock-oidc-provider.ts
 */
import { createServer } from "node:http";
import { createHash, generateKeyPairSync, randomUUID, sign } from "node:crypto";

const PORT = Number(process.env.PORT ?? 7792);
const ISSUER = `http://localhost:${PORT}`;
const SUB = process.env.MOCK_SUB ?? "browser-user-1";
const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
const jwk = { ...publicKey.export({ format: "jwk" }), kid: "mock-1", alg: "ES256", use: "sig" };
const codes = new Map<string, { challenge: string; nonce: string; client: string }>();
const b64u = (b: Buffer | string) => Buffer.from(b).toString("base64url");

createServer(async (req, res) => {
  const url = new URL(req.url!, ISSUER);
  const json = (v: unknown, status = 200) => (res.writeHead(status, { "content-type": "application/json" }), res.end(JSON.stringify(v)));
  if (url.pathname === "/.well-known/openid-configuration") {
    return json({ issuer: ISSUER, authorization_endpoint: `${ISSUER}/auth`, token_endpoint: `${ISSUER}/token`, jwks_uri: `${ISSUER}/jwks` });
  }
  if (url.pathname === "/jwks") return json({ keys: [jwk] });
  if (url.pathname === "/auth") {
    const q = url.searchParams;
    const code = randomUUID();
    codes.set(code, { challenge: q.get("code_challenge")!, nonce: q.get("nonce")!, client: q.get("client_id")! });
    const back = new URL(q.get("redirect_uri")!);
    back.searchParams.set("code", code);
    back.searchParams.set("state", q.get("state")!);
    res.writeHead(302, { location: back.toString() });
    return res.end();
  }
  if (url.pathname === "/token" && req.method === "POST") {
    let body = "";
    for await (const c of req) body += c;
    const f = new URLSearchParams(body);
    const grant = codes.get(f.get("code") ?? "");
    codes.delete(f.get("code") ?? "");
    const verifier = f.get("code_verifier") ?? "";
    if (!grant || createHash("sha256").update(verifier).digest("base64url") !== grant.challenge) return json({ error: "invalid_grant" }, 400);
    const now = Math.floor(Date.now() / 1000);
    const head = b64u(JSON.stringify({ alg: "ES256", typ: "JWT", kid: "mock-1" }));
    const claims = b64u(JSON.stringify({ iss: ISSUER, sub: SUB, aud: grant.client, iat: now, exp: now + 300, nonce: grant.nonce }));
    const sig = sign("sha256", Buffer.from(`${head}.${claims}`), { key: privateKey, dsaEncoding: "ieee-p1363" });
    return json({ id_token: `${head}.${claims}.${b64u(sig)}`, access_token: randomUUID(), token_type: "Bearer", expires_in: 300 });
  }
  json({ error: "not_found" }, 404);
}).listen(PORT, () => console.log(`mock provider on ${ISSUER}`));
