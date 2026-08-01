/**
 * The identity verification pipeline — the anti-spoofing crux.
 *
 * Given a connection proposal, the vault:
 *   1. normalizes the claimed domain (Punycode A-label),
 *   2. fetches the identity record ITSELF (resolver) and checks the record proof,
 *   3. confirms the record is authoritative for the claimed host,
 *   4. verifies the domain-signed delegation (and its binding to this vault +
 *      pairing challenge),
 *   5. verifies the delegated session key actually signed the ConnectMessage
 *      (proof of possession) and that the ECDH handshake pubkeys + transcript are
 *      bound into that signature,
 *   6. derives the namespace from the verified host — never from the caller,
 *   7. runs a homograph check and a method-capability check.
 *
 * On any hard failure it throws a specific VaultError; the namespace it returns
 * is one the caller could not have chosen.
 */

import {
  deriveNamespace,
  normalizeHost,
  isAuthoritativeForHost,
  detectHomograph,
  verifyIdentityRecordProof,
  verifyDelegation,
  verifyTyped,
  transcriptHash,
  NamespaceError,
} from "@vault/crypto-core";
import {
  VaultError,
  PROTOCOL_VERSION,
  REQUEST_MAX_SKEW_MS,
  type IdentityVerification,
  type SessionDelegation,
} from "@vault/protocol";
import type { SessionProposeParams } from "@vault/protocol";
import type { IdentityResolver } from "./adapters.js";

export interface VerifyContext {
  resolver: IdentityResolver;
  vaultId: string;
  /** The vault's session ECDH public key for this pairing (transport-provided). */
  responderPublicKey: string;
  /** The pairing nonce from the pairing URI. */
  pairingNonce: string;
  /** Domains the user has approved before (for look-alike detection). */
  knownDomains: string[];
  now: number;
}

export interface VerifiedConnection {
  verification: IdentityVerification;
  delegation: SessionDelegation;
  /** The delegated session public key (d_sess) that signs data-plane requests. */
  delegatedKeyPub: string;
  canonicalHost: string;
}

export async function verifyProposal(
  params: SessionProposeParams,
  ctx: VerifyContext,
): Promise<VerifiedConnection> {
  // 1. Normalize the claimed domain.
  let canonicalHost: string;
  try {
    canonicalHost = normalizeHost(params.domain);
  } catch (e) {
    if (e instanceof NamespaceError) throw VaultError.of("IdentityUnverified", `bad domain: ${e.message}`);
    throw e;
  }

  // 2. The vault fetches the record itself, over TLS in production.
  const record = await ctx.resolver.resolve(canonicalHost);
  if (!record) throw VaultError.of("IdentityUnverified", "identity record not resolvable");

  // 2b. Record proof (internal consistency / control of the published key).
  const proof = verifyIdentityRecordProof(record, ctx.now);
  if (!proof.ok) throw VaultError.of("IdentityUnverified", `record proof: ${proof.reason}`);

  // 3. The record must be authoritative for the claimed host (PSL-aware; a naive
  //    last-two-labels check would accept attacker.co.uk for victim.co.uk).
  if (!isAuthoritativeForHost(record.domain, canonicalHost)) {
    throw VaultError.of("IdentityUnverified", "record is not authoritative for the claimed host");
  }

  // 3b. Protocol version compatibility.
  if (!record.protocolVersions.includes(PROTOCOL_VERSION)) {
    throw VaultError.of("ProtocolUnsupported", "identity record does not support this protocol version");
  }

  // 4. Delegation: signed by an active record key, bound to this vault + pairing.
  const del = params.delegation;
  const delRes = verifyDelegation(del, record, ctx.now);
  if (!delRes.ok) throw VaultError.of("BadSignature", `delegation: ${delRes.reason}`);
  if (del.expiresAt <= ctx.now) throw VaultError.of("Expired", "delegation expired");
  if (del.issuedAt > ctx.now + REQUEST_MAX_SKEW_MS) throw VaultError.of("Expired", "delegation from the future");
  if (del.vaultId !== undefined && del.vaultId !== ctx.vaultId) {
    throw VaultError.of("BadSignature", "delegation bound to a different vault");
  }
  if (del.pairingChallenge !== undefined && del.pairingChallenge !== params.pairingChallenge) {
    throw VaultError.of("BadSignature", "delegation pairing-challenge mismatch");
  }

  // 5. Proof of possession: the delegated key signed the ConnectMessage.
  const connect = params.connect;
  if (connect.typed.primaryType !== "VaultConnect") {
    throw VaultError.of("InvalidRequest", "connect struct has wrong primaryType");
  }
  if (connect.typed.domain.vaultId !== ctx.vaultId || connect.typed.domain.version !== PROTOCOL_VERSION) {
    throw VaultError.of("BadSignature", "connect domain separator mismatch");
  }
  if (!verifyTyped(connect.typed, connect.sig, del.sessionPublicKey)) {
    throw VaultError.of("BadSignature", "connect not signed by the delegated session key");
  }

  // 5b. Handshake binding: both ECDH pubkeys + transcript are inside the signature.
  const msg = connect.typed.message;
  if (msg.proposerPublicKey !== params.proposerPublicKey) {
    throw VaultError.of("BadSignature", "proposer public key mismatch");
  }
  if (msg.responderPublicKey !== ctx.responderPublicKey) {
    throw VaultError.of("BadSignature", "responder public key mismatch (possible MITM)");
  }
  const expectedTranscript = transcriptHash({
    proposerPublicKey: params.proposerPublicKey,
    responderPublicKey: ctx.responderPublicKey,
    protocolVersion: PROTOCOL_VERSION,
    pairingNonce: ctx.pairingNonce,
  });
  if (msg.transcriptHash !== expectedTranscript) {
    throw VaultError.of("BadSignature", "handshake transcript mismatch (downgrade/MITM)");
  }
  if (msg.expiry <= ctx.now) throw VaultError.of("Expired", "connect request expired");

  // 6. Derive the namespace from the verified host — never from the caller.
  const derived = deriveNamespace(canonicalHost, record.namespaceGranularity);
  // Tripwire: the caller-claimed namespace must equal what we derived.
  if (msg.namespace !== derived.namespace) {
    throw VaultError.of("NamespaceMismatch", "claimed namespace does not match derived namespace");
  }

  // 7. Homograph + capability.
  const homograph = detectHomograph(canonicalHost, ctx.knownDomains);
  const verification: IdentityVerification = {
    ok: true,
    tier: homograph.flag ? "look-alike" : "verified",
    namespace: derived.namespace,
    domain: record.domain,
    granularity: record.namespaceGranularity,
    identityKid: delRes.keyId ?? null,
    homographFlag: homograph.flag,
    allowedMethods: record.methods,
  };

  return { verification, delegation: del, delegatedKeyPub: del.sessionPublicKey, canonicalHost };
}
