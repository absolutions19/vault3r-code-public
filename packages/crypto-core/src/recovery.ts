/**
 * Mnemonic-based recovery of the Data Encryption Key (DEK).
 *
 * Recovery strength = mnemonic strength. A BIP-39 24-word phrase (256 bits of
 * entropy) is stretched with Argon2id into a recovery key that wraps the DEK
 * under XChaCha20-Poly1305. The wrapped blob is self-describing (it carries its
 * KDF parameters and salt, all bound into the AEAD associated data so they can't
 * be tampered) and contains no secret beyond the AEAD-protected ciphertext, so it
 * is safe for the user to export (QR / file / cloud) — only someone with the
 * mnemonic can unwrap it.
 *
 * This is the full recovery logic in JS, proven by tests. On device, the only
 * remaining work is storing/transporting the opaque blob (which the native module
 * does without ever exposing the DEK to JS).
 */

import { argon2id } from "@noble/hashes/argon2";
import { generateMnemonic, validateMnemonic } from "@scure/bip39";
import { wordlist } from "@scure/bip39/wordlists/english";
import { canonicalBytes } from "@vault/protocol";
import { xchachaSeal, xchachaOpen } from "./xchacha.js";
import { randomBytes } from "./primitives.js";
import { toBase64Url, fromBase64Url, utf8ToBytes } from "./encoding.js";

/** Argon2id parameters. `m` is memory in KiB. */
export interface RecoveryParams {
  t: number; // time cost (iterations)
  m: number; // memory cost (KiB)
  p: number; // parallelism
}

/**
 * Default Argon2id cost. 64 MiB / 3 passes is a reasonable device default; raise
 * `m` toward 256 MiB for high-assurance deployments. Because the blob stores the
 * params it used, unwrapping always works even if the default later changes.
 */
export const DEFAULT_RECOVERY_PARAMS: RecoveryParams = { t: 3, m: 64 * 1024, p: 1 };

const DEK_BYTES = 32;
const SALT_BYTES = 16;

export function generateRecoveryMnemonic(): string {
  return generateMnemonic(wordlist, 256); // 24 words
}

export function isValidRecoveryMnemonic(mnemonic: string): boolean {
  return validateMnemonic(mnemonic.trim(), wordlist);
}

/** Derive the 32-byte recovery key from a mnemonic + salt + params. */
export function deriveRecoveryKey(mnemonic: string, salt: Uint8Array, params: RecoveryParams): Uint8Array {
  return argon2id(utf8ToBytes(mnemonic.normalize("NFKD").trim()), salt, {
    t: params.t,
    m: params.m,
    p: params.p,
    dkLen: 32,
  });
}

/** A portable, self-describing wrapped-DEK blob. */
export interface RecoveryBlob {
  v: 1;
  kdf: "argon2id";
  t: number;
  m: number;
  p: number;
  salt: string; // base64url
  nonce: string; // base64url
  ct: string; // base64url
  tag: string; // base64url
}

/** Bind the KDF params + salt into the AEAD associated data (anti-tamper). */
function recoveryAad(t: number, m: number, p: number, salt: Uint8Array): Uint8Array {
  return canonicalBytes({ tag: "vault-recovery/1", kdf: "argon2id", t, m, p, salt: toBase64Url(salt) });
}

/** Wrap a DEK under a mnemonic, producing an exportable recovery blob. */
export function createRecoveryBlob(
  dek: Uint8Array,
  mnemonic: string,
  params: RecoveryParams = DEFAULT_RECOVERY_PARAMS,
): RecoveryBlob {
  if (dek.length !== DEK_BYTES) throw new Error("DEK must be 32 bytes");
  if (!isValidRecoveryMnemonic(mnemonic)) throw new Error("invalid recovery mnemonic");
  const salt = randomBytes(SALT_BYTES);
  const key = deriveRecoveryKey(mnemonic, salt, params);
  const nonce = randomBytes(24);
  const box = xchachaSeal(key, nonce, dek, recoveryAad(params.t, params.m, params.p, salt));
  return {
    v: 1,
    kdf: "argon2id",
    t: params.t,
    m: params.m,
    p: params.p,
    salt: toBase64Url(salt),
    nonce: toBase64Url(nonce),
    ct: toBase64Url(box.ciphertext),
    tag: toBase64Url(box.tag),
  };
}

/** Unwrap a DEK from a recovery blob using the mnemonic. Null on wrong mnemonic/tamper. */
export function restoreDekFromRecovery(blob: RecoveryBlob, mnemonic: string): Uint8Array | null {
  if (blob.v !== 1 || blob.kdf !== "argon2id") return null;
  if (!isValidRecoveryMnemonic(mnemonic)) return null;
  let salt: Uint8Array, nonce: Uint8Array, ct: Uint8Array, tag: Uint8Array;
  try {
    salt = fromBase64Url(blob.salt);
    nonce = fromBase64Url(blob.nonce);
    ct = fromBase64Url(blob.ct);
    tag = fromBase64Url(blob.tag);
  } catch {
    return null;
  }
  const key = deriveRecoveryKey(mnemonic, salt, { t: blob.t, m: blob.m, p: blob.p });
  return xchachaOpen(key, nonce, ct, tag, recoveryAad(blob.t, blob.m, blob.p, salt));
}

/** Serialize a blob to a compact string the user can store (QR / file). */
export function serializeRecoveryBlob(blob: RecoveryBlob): string {
  return toBase64Url(utf8ToBytes(JSON.stringify(blob)));
}

export function parseRecoveryBlob(s: string): RecoveryBlob {
  const obj = JSON.parse(new TextDecoder().decode(fromBase64Url(s))) as RecoveryBlob;
  if (obj.v !== 1 || obj.kdf !== "argon2id") throw new Error("unsupported recovery blob");
  return obj;
}
