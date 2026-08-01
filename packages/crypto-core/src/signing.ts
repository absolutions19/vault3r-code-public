/**
 * Signing/verification over EIP-712-shaped typed data. The delegated session key
 * (`d_sess`) signs every data-plane request; the vault verifies against the
 * public key pinned by the delegation.
 */

import { typedSigningPreimage, type TypedData, type PrimaryType } from "@vault/protocol";
import { ed25519Sign, ed25519Verify } from "./primitives.js";
import { toBase64Url, fromBase64Url } from "./encoding.js";

export function signTyped<P extends PrimaryType>(typed: TypedData<P>, seed32: Uint8Array): string {
  return toBase64Url(ed25519Sign(typedSigningPreimage(typed), seed32));
}

export function verifyTyped<P extends PrimaryType>(
  typed: TypedData<P>,
  sigB64: string,
  publicKey32B64: string,
): boolean {
  let sig: Uint8Array;
  let pub: Uint8Array;
  try {
    sig = fromBase64Url(sigB64);
    pub = fromBase64Url(publicKey32B64);
  } catch {
    return false;
  }
  return ed25519Verify(typedSigningPreimage(typed), sig, pub);
}
