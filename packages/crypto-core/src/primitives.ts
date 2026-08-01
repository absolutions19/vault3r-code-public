/**
 * Cryptographic primitives, backed by the audited @noble/* libraries. These are
 * pure JavaScript and run identically in Node and the browser (and React Native),
 * so the same crypto-core powers the vault engine, the SDK, and a browser build.
 *
 * The public surface is unchanged from the previous Node-crypto implementation;
 * Ed25519 (RFC 8032) and X25519 (RFC 7748) are deterministic, so results are
 * byte-identical across backends.
 */

import { ed25519, x25519 } from "@noble/curves/ed25519";
import { sha256 as nobleSha256 } from "@noble/hashes/sha2";
import { hkdf } from "@noble/hashes/hkdf";
import { randomBytes as nobleRandomBytes } from "@noble/hashes/utils";

export function randomBytes(n: number): Uint8Array {
  return nobleRandomBytes(n);
}

export function sha256(data: Uint8Array): Uint8Array {
  return nobleSha256(data);
}

export function hkdfSha256(
  ikm: Uint8Array,
  salt: Uint8Array,
  info: Uint8Array,
  length: number,
): Uint8Array {
  return hkdf(nobleSha256, ikm, salt, info, length);
}

export interface RawKeyPair {
  publicKey: Uint8Array; // 32 bytes
  privateKey: Uint8Array; // 32 bytes (seed / scalar)
}

// ---------------------------------------------------------------------------
// Ed25519 (identity + device signatures)
// ---------------------------------------------------------------------------

export function ed25519Generate(): RawKeyPair {
  const privateKey = ed25519.utils.randomPrivateKey();
  return { privateKey, publicKey: ed25519.getPublicKey(privateKey) };
}

export function ed25519PublicFromSeed(seed32: Uint8Array): Uint8Array {
  if (seed32.length !== 32) throw new Error("ed25519 seed must be 32 bytes");
  return ed25519.getPublicKey(seed32);
}

export function ed25519Sign(message: Uint8Array, seed32: Uint8Array): Uint8Array {
  if (seed32.length !== 32) throw new Error("ed25519 seed must be 32 bytes");
  return ed25519.sign(message, seed32);
}

export function ed25519Verify(
  message: Uint8Array,
  signature: Uint8Array,
  publicKey32: Uint8Array,
): boolean {
  if (publicKey32.length !== 32 || signature.length !== 64) return false;
  try {
    return ed25519.verify(signature, message, publicKey32);
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// X25519 (transport key agreement)
// ---------------------------------------------------------------------------

export function x25519Generate(): RawKeyPair {
  const privateKey = x25519.utils.randomPrivateKey();
  return { privateKey, publicKey: x25519.getPublicKey(privateKey) };
}

export function x25519PublicFromPrivate(private32: Uint8Array): Uint8Array {
  if (private32.length !== 32) throw new Error("x25519 private must be 32 bytes");
  return x25519.getPublicKey(private32);
}

/** Raw X25519 ECDH shared secret (32 bytes). */
export function x25519SharedSecret(privateKey32: Uint8Array, peerPublicKey32: Uint8Array): Uint8Array {
  return x25519.getSharedSecret(privateKey32, peerPublicKey32);
}
