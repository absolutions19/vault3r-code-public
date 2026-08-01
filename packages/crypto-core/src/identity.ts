/**
 * Identity attestation. Verifies the self-signed `.well-known` record proof and
 * the domain-signed SessionDelegation. Also provides the signing helpers used by
 * the reference backend signer and by tests to mint valid records/delegations.
 *
 * Domain binding itself comes from the vault fetching the record over TLS from
 * the claimed host (done in @vault/vault-core); this module verifies the
 * cryptographic proofs, which is the other half of the binding chain.
 */

import { canonicalBytes, type SessionDelegation, type VaultIdentityRecord, type IdentityKey } from "@vault/protocol";
import type { CanonicalValue } from "@vault/protocol";
import { ed25519Sign, ed25519Verify } from "./primitives.js";
import { toBase64Url, fromBase64Url } from "./encoding.js";

function omit<T extends object, K extends keyof T>(obj: T, key: K): Omit<T, K> {
  const { [key]: _drop, ...rest } = obj;
  return rest;
}

export interface ProofResult {
  ok: boolean;
  kid?: string;
  reason?: string;
}

function findKey(record: VaultIdentityRecord, kid: string): IdentityKey | undefined {
  return record.keys.find((k) => k.kid === kid);
}

/**
 * Whether a key may mint NEW authority (sign a fresh delegation or record proof).
 * Only `active` keys qualify — `retired` keys may still verify historical
 * signatures elsewhere, but must not authorize new sessions, and `revoked` keys
 * are unusable entirely.
 */
function keyUsable(key: IdentityKey, now: number): boolean {
  if (key.status !== "active") return false;
  if (key.expires && Date.parse(key.expires) < now) return false;
  return true;
}

/** Verify the record's self-signature (internal consistency of the identity doc). */
export function verifyIdentityRecordProof(record: VaultIdentityRecord, now = Date.now()): ProofResult {
  if (record.schema !== "vault-identity/1") return { ok: false, reason: "unknown schema" };
  const key = findKey(record, record.proof.kid);
  if (!key) return { ok: false, reason: "proof kid not in keys" };
  if (key.alg !== "Ed25519") return { ok: false, reason: "unsupported proof alg" };
  if (!keyUsable(key, now)) return { ok: false, reason: "proof key not usable" };
  let sig: Uint8Array;
  let pub: Uint8Array;
  try {
    sig = fromBase64Url(record.proof.sig);
    pub = fromBase64Url(key.publicKey);
  } catch {
    return { ok: false, reason: "malformed proof/key encoding" };
  }
  const preimage = canonicalBytes(omit(record, "proof") as unknown as CanonicalValue);
  if (!ed25519Verify(preimage, sig, pub)) return { ok: false, reason: "proof signature invalid" };
  return { ok: true, kid: record.proof.kid };
}

export interface DelegationResult {
  ok: boolean;
  keyId?: string;
  reason?: string;
}

/**
 * Verify a delegation is signed by an active key in the record and is for the
 * record's domain. Does NOT check expiry/vaultId/pairing binding — those are
 * policy checks the vault engine performs with full context.
 */
export function verifyDelegation(
  delegation: SessionDelegation,
  record: VaultIdentityRecord,
  now = Date.now(),
): DelegationResult {
  if (delegation.domain !== record.domain) return { ok: false, reason: "delegation domain mismatch" };
  const key = findKey(record, delegation.keyId);
  if (!key) return { ok: false, reason: "delegation keyId not in record" };
  if (key.alg !== "Ed25519") return { ok: false, reason: "unsupported delegation alg" };
  if (!keyUsable(key, now)) return { ok: false, reason: "delegation key not usable" };
  let sig: Uint8Array;
  let pub: Uint8Array;
  try {
    sig = fromBase64Url(delegation.sig);
    pub = fromBase64Url(key.publicKey);
  } catch {
    return { ok: false, reason: "malformed delegation encoding" };
  }
  const preimage = canonicalBytes(omit(delegation, "sig") as unknown as CanonicalValue);
  if (!ed25519Verify(preimage, sig, pub)) return { ok: false, reason: "delegation signature invalid" };
  return { ok: true, keyId: delegation.keyId };
}

// ---------------------------------------------------------------------------
// Signing helpers (reference backend signer / tests)
// ---------------------------------------------------------------------------

/** Sign an identity record (record given without `proof`) with a domain seed. */
export function signIdentityRecord(
  recordNoProof: Omit<VaultIdentityRecord, "proof">,
  kid: string,
  seed32: Uint8Array,
): VaultIdentityRecord {
  const preimage = canonicalBytes(recordNoProof as unknown as CanonicalValue);
  const sig = toBase64Url(ed25519Sign(preimage, seed32));
  return { ...recordNoProof, proof: { kid, sig } };
}

/** Sign a delegation body (given without `sig`) with a domain seed. */
export function signDelegation(
  delegationNoSig: Omit<SessionDelegation, "sig">,
  seed32: Uint8Array,
): SessionDelegation {
  const preimage = canonicalBytes(delegationNoSig as unknown as CanonicalValue);
  const sig = toBase64Url(ed25519Sign(preimage, seed32));
  return { ...delegationNoSig, sig };
}
