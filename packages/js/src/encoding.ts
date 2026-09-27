/** Small encoding helpers shared by the client and tests (no dependencies). */

export function b64u(bytes: ArrayBuffer | Uint8Array): string {
  const b = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let s = "";
  for (const x of b) s += String.fromCharCode(x);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function b64uDecode(s: string): Uint8Array<ArrayBuffer> {
  const bin = atob(s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4));
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

export function base58btc(bytes: Uint8Array): string {
  let n = 0n;
  for (const b of bytes) n = n * 256n + BigInt(b);
  let out = "";
  while (n > 0n) {
    out = B58[Number(n % 58n)] + out;
    n /= 58n;
  }
  for (const b of bytes) {
    if (b !== 0) break;
    out = "1" + out;
  }
  return out;
}

export async function sha256(data: string | Uint8Array): Promise<Uint8Array<ArrayBuffer>> {
  const bytes = typeof data === "string" ? new TextEncoder().encode(data) : data;
  return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes as Uint8Array<ArrayBuffer>));
}

/** P-256 public key (SPKI DER or 65-byte uncompressed point) → `did:key:zDn…`. */
export function p256DidKey(spkiOrPoint: ArrayBuffer | Uint8Array): string {
  const b = spkiOrPoint instanceof Uint8Array ? spkiOrPoint : new Uint8Array(spkiOrPoint);
  const point = b.slice(b.length - 65); // SPKI for P-256 ends with the 0x04||x||y point
  if (point[0] !== 0x04) throw new Error("expected an uncompressed P-256 point");
  const x = point.slice(1, 33);
  const yOdd = point[64] & 1;
  const compressed = new Uint8Array([yOdd ? 0x03 : 0x02, ...x]);
  return "did:key:z" + base58btc(new Uint8Array([0x80, 0x24, ...compressed]));
}
