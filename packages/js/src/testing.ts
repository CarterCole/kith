/**
 * A software WebAuthn authenticator backed by WebCrypto, for tests and demos.
 * Implements just enough of `navigator.credentials` for KithClient.
 */
import { b64u } from "./encoding.ts";

export class SoftAuthenticator {
  private keys = new Map<string, CryptoKeyPair>();
  readonly rpId: string;
  readonly origin: string;
  constructor(rpId: string, origin: string) {
    this.rpId = rpId;
    this.origin = origin;
  }

  async addKey(pair?: CryptoKeyPair): Promise<{ id: Uint8Array<ArrayBuffer>; spki: ArrayBuffer }> {
    const kp = pair ?? ((await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])) as CryptoKeyPair);
    const id = crypto.getRandomValues(new Uint8Array(16));
    this.keys.set(b64u(id), kp);
    return { id, spki: await crypto.subtle.exportKey("spki", kp.publicKey) };
  }

  async create(opts: CredentialCreationOptions): Promise<any> {
    const { id, spki } = await this.addKey();
    return { rawId: id.buffer, response: { getPublicKey: () => spki } };
  }

  async get(opts: CredentialRequestOptions): Promise<any> {
    const pk = opts.publicKey!;
    const wanted = pk.allowCredentials?.[0]?.id;
    const key = wanted ? this.keys.get(b64u(wanted as Uint8Array)) : [...this.keys.values()][0];
    if (!key) throw new Error("no credential");
    const rpHash = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(pk.rpId ?? this.rpId)));
    const authData = new Uint8Array([...rpHash, 0x05, 0, 0, 0, 1]); // UP | UV, counter 1
    const clientData = new TextEncoder().encode(JSON.stringify({
      type: "webauthn.get",
      challenge: b64u(pk.challenge as Uint8Array),
      origin: this.origin,
      crossOrigin: false,
    }));
    const clientHash = new Uint8Array(await crypto.subtle.digest("SHA-256", clientData));
    const raw = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key.privateKey, new Uint8Array([...authData, ...clientHash])));
    // Real authenticators return ASN.1 DER signatures; so do we.
    return { rawId: new Uint8Array(16).buffer, response: { authenticatorData: authData.buffer, clientDataJSON: clientData.buffer, signature: rawToDer(raw).buffer } };
  }
}

function derInt(b: Uint8Array): number[] {
  let i = 0;
  while (i < b.length - 1 && b[i] === 0) i++;
  const v = [...b.slice(i)];
  if (v[0] & 0x80) v.unshift(0);
  return [0x02, v.length, ...v];
}

function rawToDer(raw: Uint8Array): Uint8Array<ArrayBuffer> {
  const body = [...derInt(raw.slice(0, 32)), ...derInt(raw.slice(32))];
  return new Uint8Array([0x30, body.length, ...body]);
}
