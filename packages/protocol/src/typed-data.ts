/**
 * EIP-712-shaped typed data. Every authorizing request carries a typed struct so
 * the vault can render a human-legible approval prompt AND sign/verify over a
 * domain-separated, canonically-encoded preimage. The domain separator binds a
 * signature to a specific vault instance + protocol version, so a signature can
 * never be replayed against a different vault or a different protocol revision.
 */

import { canonicalBytes, type CanonicalValue } from "./canonical.js";
import { PROTOCOL_VERSION, TYPED_DOMAIN_NAME } from "./constants.js";

export interface TypedDomain {
  name: string;
  version: string;
  /** Unique per vault install. */
  vaultId: string;
  /** The verifying key id (device key) where relevant. */
  verifyingKeyId?: string;
}

export type PrimaryType = "VaultConnect" | "VaultRead" | "VaultWrite" | "VaultPatch" | "VaultRevoke";

export interface TypedMessageBase {
  /** The namespace the caller *claims* — used only as an equality tripwire. */
  namespace: string;
  /** Monotonic-ish anti-replay nonce (unique per session). */
  nonce: string;
  /** Epoch ms the request was issued. */
  issuedAt: number;
  /** Epoch ms after which the request must be rejected. */
  expiry: number;
  /** Session id this request belongs to. */
  sessionId: string;
}

export interface ChangeDescriptor {
  op: "replace" | "add" | "remove";
  /** JSON Pointer (RFC 6901), namespace-relative. */
  path: string;
  /** SHA-256 (hex, `sha256:...`) of canonical value bytes — never the value itself. */
  valueHash?: string;
}

export interface ConnectMessage extends TypedMessageBase {
  /** Ephemeral pubkeys + transcript hash bound into the identity signature. */
  proposerPublicKey: string;
  responderPublicKey?: string;
  transcriptHash: string;
}

export interface ReadMessage extends TypedMessageBase {
  paths: string[];
}

export interface WriteMessage extends TypedMessageBase {
  changes: ChangeDescriptor[];
  baseVersion?: string;
}

export interface PatchMessage extends TypedMessageBase {
  changes: ChangeDescriptor[];
  baseVersion?: string;
}

export interface RevokeMessage extends TypedMessageBase {
  reason?: string;
}

export type TypedMessageFor<P extends PrimaryType> = P extends "VaultConnect"
  ? ConnectMessage
  : P extends "VaultRead"
    ? ReadMessage
    : P extends "VaultWrite"
      ? WriteMessage
      : P extends "VaultPatch"
        ? PatchMessage
        : P extends "VaultRevoke"
          ? RevokeMessage
          : never;

export interface TypedData<P extends PrimaryType = PrimaryType> {
  primaryType: P;
  domain: TypedDomain;
  message: TypedMessageFor<P>;
}

/**
 * Build the signing preimage bytes for a typed struct. A single tag ("VAULT712")
 * plus the domain and primaryType are folded in so the bytes are unambiguous
 * across struct kinds and can never be reinterpreted as a different type.
 */
export function typedSigningPreimage(td: TypedData): Uint8Array {
  const envelope: CanonicalValue = {
    tag: "VAULT712",
    primaryType: td.primaryType,
    domain: td.domain as unknown as CanonicalValue,
    message: td.message as unknown as CanonicalValue,
  };
  return canonicalBytes(envelope);
}

/** Convenience to build a well-formed domain with defaults. */
export function makeDomain(vaultId: string, verifyingKeyId?: string): TypedDomain {
  const d: TypedDomain = { name: TYPED_DOMAIN_NAME, version: PROTOCOL_VERSION, vaultId };
  if (verifyingKeyId !== undefined) d.verifyingKeyId = verifyingKeyId;
  return d;
}
