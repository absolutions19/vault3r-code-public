/**
 * XChaCha20-Poly1305 AEAD.
 *
 * Node ships the IETF ChaCha20-Poly1305 (96-bit nonce). XChaCha extends the
 * nonce to 192 bits — large enough that random nonces never collide, so callers
 * don't have to coordinate a counter. We construct it the standard way
 * (draft-irtf-cfrg-xchacha): derive a subkey with HChaCha20 over the first 16
 * nonce bytes, then run IETF ChaCha20-Poly1305 with that subkey and a 96-bit
 * nonce of `00 00 00 00 || nonce[16:24]`.
 */

import { xchacha20poly1305 } from "@noble/ciphers/chacha";
import { concatBytes } from "./encoding.js";

const SIGMA = new Uint32Array([0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]);

function rotl(x: number, n: number): number {
  return ((x << n) | (x >>> (32 - n))) >>> 0;
}

function quarterRound(s: Uint32Array, a: number, b: number, c: number, d: number): void {
  s[a] = (s[a]! + s[b]!) >>> 0;
  s[d] = rotl(s[d]! ^ s[a]!, 16);
  s[c] = (s[c]! + s[d]!) >>> 0;
  s[b] = rotl(s[b]! ^ s[c]!, 12);
  s[a] = (s[a]! + s[b]!) >>> 0;
  s[d] = rotl(s[d]! ^ s[a]!, 8);
  s[c] = (s[c]! + s[d]!) >>> 0;
  s[b] = rotl(s[b]! ^ s[c]!, 7);
}

function readLE32(b: Uint8Array, off: number): number {
  return (b[off]! | (b[off + 1]! << 8) | (b[off + 2]! << 16) | (b[off + 3]! << 24)) >>> 0;
}

function writeLE32(out: Uint8Array, off: number, v: number): void {
  out[off] = v & 0xff;
  out[off + 1] = (v >>> 8) & 0xff;
  out[off + 2] = (v >>> 16) & 0xff;
  out[off + 3] = (v >>> 24) & 0xff;
}

/** HChaCha20: 32-byte key + 16-byte nonce -> 32-byte subkey (no state addition). */
export function hchacha20(key: Uint8Array, nonce16: Uint8Array): Uint8Array {
  if (key.length !== 32) throw new Error("hchacha20 key must be 32 bytes");
  if (nonce16.length !== 16) throw new Error("hchacha20 nonce must be 16 bytes");
  const s = new Uint32Array(16);
  s[0] = SIGMA[0]!;
  s[1] = SIGMA[1]!;
  s[2] = SIGMA[2]!;
  s[3] = SIGMA[3]!;
  for (let i = 0; i < 8; i++) s[4 + i] = readLE32(key, i * 4);
  for (let i = 0; i < 4; i++) s[12 + i] = readLE32(nonce16, i * 4);

  for (let i = 0; i < 10; i++) {
    quarterRound(s, 0, 4, 8, 12);
    quarterRound(s, 1, 5, 9, 13);
    quarterRound(s, 2, 6, 10, 14);
    quarterRound(s, 3, 7, 11, 15);
    quarterRound(s, 0, 5, 10, 15);
    quarterRound(s, 1, 6, 11, 12);
    quarterRound(s, 2, 7, 8, 13);
    quarterRound(s, 3, 4, 9, 14);
  }

  const out = new Uint8Array(32);
  for (let i = 0; i < 4; i++) writeLE32(out, i * 4, s[i]!);
  for (let i = 0; i < 4; i++) writeLE32(out, 16 + i * 4, s[12 + i]!);
  return out;
}

export const XCHACHA_NONCE_BYTES = 24;
export const XCHACHA_TAG_BYTES = 16;
export const XCHACHA_KEY_BYTES = 32;

export interface SealedBox {
  nonce: Uint8Array; // 24 bytes
  ciphertext: Uint8Array;
  tag: Uint8Array; // 16 bytes
}

/** Encrypt with XChaCha20-Poly1305. `aad` is authenticated but not encrypted. */
export function xchachaSeal(
  key: Uint8Array,
  nonce24: Uint8Array,
  plaintext: Uint8Array,
  aad: Uint8Array,
): SealedBox {
  if (key.length !== XCHACHA_KEY_BYTES) throw new Error("key must be 32 bytes");
  if (nonce24.length !== XCHACHA_NONCE_BYTES) throw new Error("nonce must be 24 bytes");
  const combined = xchacha20poly1305(key, nonce24, aad).encrypt(plaintext); // ciphertext || tag
  const split = combined.length - XCHACHA_TAG_BYTES;
  return {
    nonce: nonce24,
    ciphertext: combined.subarray(0, split),
    tag: combined.subarray(split),
  };
}

/** Decrypt; returns null on any authentication failure (never throws on bad tag). */
export function xchachaOpen(
  key: Uint8Array,
  nonce24: Uint8Array,
  ciphertext: Uint8Array,
  tag: Uint8Array,
  aad: Uint8Array,
): Uint8Array | null {
  if (key.length !== XCHACHA_KEY_BYTES) throw new Error("key must be 32 bytes");
  if (nonce24.length !== XCHACHA_NONCE_BYTES) throw new Error("nonce must be 24 bytes");
  if (tag.length !== XCHACHA_TAG_BYTES) return null;
  try {
    return xchacha20poly1305(key, nonce24, aad).decrypt(concatBytes(ciphertext, tag));
  } catch {
    return null;
  }
}
