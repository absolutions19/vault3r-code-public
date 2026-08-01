/**
 * Session handshake. Both peers perform X25519 ECDH and derive a symmetric
 * session key with HKDF. A transcript hash over the negotiated parameters is
 * returned so it can be bound into the identity signature — an attacker who
 * swaps a public key or downgrades a parameter changes the transcript and
 * breaks that signature (closes pairing-relay MITM).
 */

import { canonicalBytes } from "@vault/protocol";
import { hkdfSha256, sha256, x25519SharedSecret } from "./primitives.js";
import { concatBytes, fromBase64Url, toHex, utf8ToBytes } from "./encoding.js";

export interface HandshakeParams {
  proposerPublicKey: string; // base64url X25519 pub
  responderPublicKey: string; // base64url X25519 pub
  protocolVersion: string;
  /** Fresh pairing nonce (from the pairing URI). */
  pairingNonce: string;
}

/** Deterministic transcript hash (hex) over the handshake parameters. */
export function transcriptHash(p: HandshakeParams): string {
  const bytes = canonicalBytes({
    tag: "vault-handshake/v1",
    proposerPublicKey: p.proposerPublicKey,
    responderPublicKey: p.responderPublicKey,
    protocolVersion: p.protocolVersion,
    pairingNonce: p.pairingNonce,
  });
  return `sha256:${toHex(sha256(bytes))}`;
}

/**
 * Derive the 32-byte session key. `salt` is a hash of both public keys so the
 * derivation is bound to this specific pair of ephemeral keys; `info` binds the
 * transcript so the key and the signed transcript cannot be split apart.
 */
export function deriveSessionKey(
  ourPrivate: Uint8Array,
  peerPublic: Uint8Array,
  params: HandshakeParams,
): Uint8Array {
  const shared = x25519SharedSecret(ourPrivate, peerPublic);
  const salt = sha256(
    concatBytes(fromBase64Url(params.proposerPublicKey), fromBase64Url(params.responderPublicKey)),
  );
  const info = concatBytes(utf8ToBytes("vault-session/v1|"), utf8ToBytes(transcriptHash(params)));
  return hkdfSha256(shared, salt, info, 32);
}
