/**
 * A relying party that signs in with Kith using panva's certified `openid-client`.
 *   KITH_ISSUER=http://localhost:7777 node examples/oidc-rp.ts   → http://localhost:3000
 */
import { createServer } from "node:http";
import * as oidc from "openid-client";

const ISSUER = process.env.KITH_ISSUER ?? "http://localhost:7777";
const PORT = Number(process.env.PORT ?? 3000);
const BASE = `http://localhost:${PORT}`;
const config = await oidc.discovery(new URL(ISSUER), process.env.OIDC_CLIENT_ID ?? "demo-rp", undefined, oidc.None(), {
  execute: [oidc.allowInsecureRequests], // http://localhost only
});

type Session = { pkce?: string; state?: string; nonce?: string; user?: any };
const sessions = new Map<string, Session>();

createServer(async (req, res) => {
  const url = new URL(req.url!, BASE);
  const sid = /rp_sid=([^;]+)/.exec(req.headers.cookie ?? "")?.[1] ?? crypto.randomUUID();
  const s = sessions.get(sid) ?? {};
  sessions.set(sid, s);
  res.setHeader("set-cookie", `rp_sid=${sid}; Path=/; HttpOnly; SameSite=Lax`);
  try {
    if (url.pathname === "/login") {
      s.pkce = oidc.randomPKCECodeVerifier();
      s.state = oidc.randomState();
      s.nonce = oidc.randomNonce();
      const params: Record<string, string> = {
        redirect_uri: `${BASE}/cb`,
        scope: "openid profile email groups offline_access",
        code_challenge: await oidc.calculatePKCECodeChallenge(s.pkce),
        code_challenge_method: "S256",
        state: s.state,
        nonce: s.nonce,
      };
      if (url.searchParams.get("acr")) params.acr_values = `urn:kith:acr:${url.searchParams.get("acr")}`;
      if (url.searchParams.get("prompt")) params.prompt = url.searchParams.get("prompt")!;
      res.writeHead(302, { location: oidc.buildAuthorizationUrl(config, params).href }).end();
    } else if (url.pathname === "/cb") {
      const tokens = await oidc.authorizationCodeGrant(config, url, { pkceCodeVerifier: s.pkce, expectedState: s.state, expectedNonce: s.nonce, idTokenExpected: true });
      const claims = tokens.claims()!;
      const userinfo = await oidc.fetchUserInfo(config, tokens.access_token, claims.sub);
      const refreshed = await oidc.refreshTokenGrant(config, tokens.refresh_token!);
      s.user = { claims, userinfo, refreshed: !!refreshed.access_token, id_token: tokens.id_token };
      res.writeHead(302, { location: "/" }).end();
    } else if (url.pathname === "/me.json") {
      res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify(s.user ?? null));
    } else if (url.pathname === "/logout") {
      const hint = s.user?.id_token;
      s.user = undefined;
      res.writeHead(302, { location: oidc.buildEndSessionUrl(config, { post_logout_redirect_uri: `${BASE}/`, id_token_hint: hint }).href }).end();
    } else {
      res.writeHead(200, { "content-type": "text/html" }).end(
        s.user
          ? `<h1>Signed in</h1><pre id="claims">${JSON.stringify(s.user.claims, null, 2).replace(/</g, "&lt;")}</pre><a href="/logout">Sign out</a>`
          : `<h1>Demo App</h1><a id="login" href="/login">Sign in with Kith</a>`,
      );
    }
  } catch (e) {
    res.writeHead(500, { "content-type": "text/plain" }).end(`RP error: ${(e as Error).message}`);
  }
}).listen(PORT, () => console.error(`relying party on ${BASE}`));
