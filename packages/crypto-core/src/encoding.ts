/** Byte/text encoding helpers. base64url (no padding) is the wire encoding. */

const enc = new TextEncoder();
const dec = new TextDecoder("utf-8", { fatal: true });

export function utf8ToBytes(s: string): Uint8Array {
  return enc.encode(s);
}

export function bytesToUtf8(b: Uint8Array): string {
  return dec.decode(b);
}

export function toBase64Url(b: Uint8Array): string {
  return Buffer.from(b.buffer, b.byteOffset, b.byteLength).toString("base64url");
}

export function fromBase64Url(s: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]*$/.test(s)) {
    throw new Error("invalid base64url");
  }
  return new Uint8Array(Buffer.from(s, "base64url"));
}

export function toHex(b: Uint8Array): string {
  return Buffer.from(b.buffer, b.byteOffset, b.byteLength).toString("hex");
}

export function fromHex(s: string): Uint8Array {
  if (s.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(s)) {
    throw new Error("invalid hex");
  }
  return new Uint8Array(Buffer.from(s, "hex"));
}

export function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const a of arrays) total += a.length;
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrays) {
    out.set(a, off);
    off += a.length;
  }
  return out;
}

/** Constant-time equality for equal-length secrets/tags. */
export function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= (a[i] as number) ^ (b[i] as number);
  return diff === 0;
}
