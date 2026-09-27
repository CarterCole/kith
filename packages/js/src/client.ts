/**
 * Browser (and Node) client for a Kith hub.
 *
 * - `loginWithPasskey` – WebAuthn assertion over the hub's challenge
 * - `loginWithWallet`  – EIP-191 `personal_sign` from any EIP-1193 wallet
 * - `createPasskey` / `signWithPasskey` – enroll a passkey as a Kith device
 * - `fetch` – adds the bearer token
 *
 * Kith always sets the WebAuthn challenge to SHA-256(message), so the same passkey
 * can sign a login challenge, a key event, or a session grant.
 */
import { b64u, p256DidKey, sha256 } from "./encoding.ts";

export interface Sig {
  signer: string;
  alg: string;
  sig: string;
  webauthn?: { authenticator_data: string; client_data_json: string };
}

export interface TokenResponse {
  access_token: string;
  token_type: "Bearer";
  expires_in: number;
}

export interface Eip1193Provider {
  request(args: { method: string; params?: unknown[] }): Promise<unknown>;
}

export interface KithClientOptions {
  hub: string;
  /** Defaults to globalThis.navigator.credentials. Injectable for tests / native shells. */
  credentials?: Pick<CredentialsContainer, "get" | "create">;
  fetch?: typeof fetch;
  rpId?: string;
}

export class KithClient {
  readonly hub: string;
  private readonly creds?: Pick<CredentialsContainer, "get" | "create">;
  private readonly http: typeof fetch;
  private readonly rpId?: string;
  private tokens = new Map<string, { token: string; exp: number }>();

  constructor(opts: KithClientOptions) {
    this.hub = opts.hub.replace(/\/$/, "");
    this.creds = opts.credentials ?? (globalThis as any).navigator?.credentials;
    this.http = opts.fetch ?? fetch.bind(globalThis);
    this.rpId = opts.rpId;
  }

  private async post(path: string, body: unknown): Promise<any> {
    const r = await this.http(`${this.hub}${path}`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
    const j = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(`${path}: ${j.error_description ?? r.status}`);
    return j;
  }

  private store(audience: string, t: TokenResponse): string {
    this.tokens.set(audience, { token: t.access_token, exp: Date.now() / 1000 + t.expires_in });
    return t.access_token;
  }

  token(audience: string): string | undefined {
    const t = this.tokens.get(audience);
    return t && t.exp > Date.now() / 1000 + 30 ? t.token : undefined;
  }

  async challenge(did: string): Promise<{ challenge_id: string; message: string }> {
    return this.post("/v1/auth/challenge", { did });
  }

  private requireCreds() {
    if (!this.creds) throw new Error("WebAuthn is not available here");
    return this.creds;
  }

  /** Sign an arbitrary Kith message (key event, grant) with a passkey. */
  async signWithPasskey(message: string, signer: string, credentialId?: Uint8Array<ArrayBuffer>): Promise<Sig> {
    const a = (await this.requireCreds().get({
      publicKey: {
        challenge: await sha256(message),
        rpId: this.rpId,
        userVerification: "preferred",
        allowCredentials: credentialId ? [{ type: "public-key", id: credentialId }] : [],
      },
    })) as PublicKeyCredential;
    const r = a.response as AuthenticatorAssertionResponse;
    return {
      signer,
      alg: "WebAuthn",
      sig: b64u(r.signature),
      webauthn: { authenticator_data: b64u(r.authenticatorData), client_data_json: b64u(r.clientDataJSON) },
    };
  }

  async loginWithPasskey(opts: { did: string; deviceId: string; audience: string; totp?: string; credentialId?: Uint8Array<ArrayBuffer> }): Promise<string> {
    const ch = await this.challenge(opts.did);
    const s = await this.signWithPasskey(ch.message, "", opts.credentialId);
    const factors: unknown[] = [{
      type: "webauthn",
      device_id: opts.deviceId,
      authenticator_data: s.webauthn!.authenticator_data,
      client_data_json: s.webauthn!.client_data_json,
      signature: s.sig,
    }];
    if (opts.totp) factors.push({ type: "totp", code: opts.totp });
    return this.store(opts.audience, await this.post("/v1/auth/verify", { challenge_id: ch.challenge_id, audience: opts.audience, factors }));
  }

  /** The wallet account must be a manage/device signer of the identity. */
  async loginWithWallet(opts: { did: string; audience: string; provider: Eip1193Provider; chainId?: number }): Promise<string> {
    const ch = await this.challenge(opts.did);
    const [account] = (await opts.provider.request({ method: "eth_requestAccounts" })) as string[];
    const hex = (await opts.provider.request({ method: "personal_sign", params: [toHex(ch.message), account] })) as string;
    const sig = Uint8Array.from(hex.replace(/^0x/, "").match(/../g)!.map((h) => parseInt(h, 16)));
    const factor = { type: "signature", sig: { signer: `eip155:${opts.chainId ?? 1}:${account.toLowerCase()}`, alg: "EIP191", sig: b64u(sig) } };
    return this.store(opts.audience, await this.post("/v1/auth/verify", { challenge_id: ch.challenge_id, audience: opts.audience, factors: [factor] }));
  }

  /**
   * Create a passkey and return its Kith signer id. Add it as a device with
   * `kith device add --key <did> --kind passkey` (the manage key signs), then sign
   * the pending event with `signWithPasskey` for proof of possession.
   */
  async createPasskey(opts: { userName: string; rpName?: string; userId?: Uint8Array<ArrayBuffer> }): Promise<{ did: string; credentialId: string }> {
    const cred = (await this.requireCreds().create({
      publicKey: {
        rp: { id: this.rpId, name: opts.rpName ?? "Kith" },
        user: { id: opts.userId ?? crypto.getRandomValues(new Uint8Array(16)), name: opts.userName, displayName: opts.userName },
        challenge: crypto.getRandomValues(new Uint8Array(32)),
        pubKeyCredParams: [{ type: "public-key", alg: -7 }],
        authenticatorSelection: { residentKey: "preferred", userVerification: "preferred" },
      },
    })) as PublicKeyCredential;
    const spki = (cred.response as AuthenticatorAttestationResponse).getPublicKey();
    if (!spki) throw new Error("authenticator did not return a public key");
    return { did: p256DidKey(spki), credentialId: b64u(cred.rawId) };
  }

  /** fetch() with `Authorization: Bearer` for `audience`. */
  async fetch(audience: string, input: string | URL, init: RequestInit = {}): Promise<Response> {
    const token = this.token(audience);
    if (!token) throw new Error(`not logged in for ${audience}`);
    const headers = new Headers(init.headers);
    headers.set("authorization", `Bearer ${token}`);
    return this.http(input, { ...init, headers });
  }
}

function toHex(s: string): string {
  return "0x" + [...new TextEncoder().encode(s)].map((b) => b.toString(16).padStart(2, "0")).join("");
}
