/**
 * Byte/text encoding helpers. Pure JavaScript with no `Buffer` dependency, so
 * this runs unchanged in Node, the browser, and React Native. base64url (no
 * padding) is the wire encoding throughout.
 */

import { bytesToHex, hexToBytes } from "@noble/hashes/utils";

const enc = new TextEncoder();
const dec = new TextDecoder("utf-8", { fatal: true });

export function utf8ToBytes(s: string): Uint8Array {
  return enc.encode(s);
}

export function bytesToUtf8(b: Uint8Array): string {
  return dec.decode(b);
}

const B64U = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const B64U_REV: Int16Array = (() => {
  const t = new Int16Array(128).fill(-1);
  for (let i = 0; i < B64U.length; i++) t[B64U.charCodeAt(i)] = i;
  return t;
})();

export function toBase64Url(b: Uint8Array): string {
  let out = "";
  const n = b.length;
  for (let i = 0; i < n; i += 3) {
    const b0 = b[i] as number;
    const b1 = i + 1 < n ? (b[i + 1] as number) : 0;
    const b2 = i + 2 < n ? (b[i + 2] as number) : 0;
    out += B64U[b0 >> 2];
    out += B64U[((b0 & 3) << 4) | (b1 >> 4)];
    if (i + 1 < n) out += B64U[((b1 & 15) << 2) | (b2 >> 6)];
    if (i + 2 < n) out += B64U[b2 & 63];
  }
  return out;
}

export function fromBase64Url(s: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]*$/.test(s)) throw new Error("invalid base64url");
  // A single leftover base64 char cannot encode any whole byte — reject it.
  if (s.length % 4 === 1) throw new Error("invalid base64url length");
  const out = new Uint8Array(Math.floor((s.length * 3) / 4));
  let oi = 0;
  let buf = 0;
  let bits = 0;
  for (let i = 0; i < s.length; i++) {
    const v = B64U_REV[s.charCodeAt(i)] as number;
    buf = (buf << 6) | v;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[oi++] = (buf >> bits) & 0xff;
    }
  }
  // Reject non-canonical encodings: the unused trailing bits of the final quantum
  // must be zero, so exactly one string maps to each byte sequence (no malleability).
  if ((buf & ((1 << bits) - 1)) !== 0) throw new Error("non-canonical base64url");
  return out;
}

export function toHex(b: Uint8Array): string {
  return bytesToHex(b);
}

export function fromHex(s: string): Uint8Array {
  if (s.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(s)) {
    throw new Error("invalid hex");
  }
  return hexToBytes(s);
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
