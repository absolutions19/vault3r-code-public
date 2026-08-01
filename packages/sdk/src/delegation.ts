/**
 * The delegation seam. In production the SDK asks the app's own backend for a
 * SessionDelegation over a CSRF-protected, proof-of-possession-bound endpoint —
 * the domain private key never enters the browser. `LocalDelegationSigner` is a
 * same-process implementation for tests and single-process demos ONLY; it holds
 * the domain key directly, which a real deployment must never do in the client.
 */

import { signDelegation, randomBytes, toBase64Url } from "@vault/crypto-core";
import { DELEGATION_DEFAULT_TTL_MS, type RequestedScope, type SessionDelegation } from "@vault/protocol";

export interface DelegationRequest {
  /** The ephemeral session public key (d_sess) the delegation authorizes. */
  sessionPublicKey: string;
  scopes: RequestedScope[];
  /** Binds the delegation to this pairing (anti-relay). */
  pairingChallenge: string;
  /** Binds the delegation to the specific vault it will be presented to. */
  vaultId: string;
}

export interface DelegationSigner {
  getDelegation(req: DelegationRequest): Promise<SessionDelegation>;
}

export interface LocalDelegationSignerOptions {
  domain: string;
  kid: string;
  domainSeed: Uint8Array;
  assertedAccount?: string;
  ttlMs?: number;
  clock?: () => number;
}

export class LocalDelegationSigner implements DelegationSigner {
  constructor(private readonly opts: LocalDelegationSignerOptions) {}

  async getDelegation(req: DelegationRequest): Promise<SessionDelegation> {
    const now = (this.opts.clock ?? Date.now)();
    const body: Omit<SessionDelegation, "sig"> = {
      domain: this.opts.domain,
      sessionPublicKey: req.sessionPublicKey,
      scopes: req.scopes,
      vaultId: req.vaultId,
      pairingChallenge: req.pairingChallenge,
      issuedAt: now,
      expiresAt: now + (this.opts.ttlMs ?? DELEGATION_DEFAULT_TTL_MS),
      nonce: toBase64Url(randomBytes(12)),
      keyId: this.opts.kid,
    };
    if (this.opts.assertedAccount !== undefined) body.assertedAccount = this.opts.assertedAccount;
    return signDelegation(body, this.opts.domainSeed);
  }
}

/**
 * A DelegationSigner that calls a backend endpoint. The endpoint MUST enforce
 * CSRF, an Origin allow-list, and proof-of-possession (the browser signs a fresh
 * server challenge with d_sess before the delegation is minted).
 */
export class HttpDelegationSigner implements DelegationSigner {
  constructor(
    private readonly endpoint: string,
    private readonly fetchImpl: typeof fetch = fetch,
  ) {}

  async getDelegation(req: DelegationRequest): Promise<SessionDelegation> {
    const res = await this.fetchImpl(this.endpoint, {
      method: "POST",
      headers: { "content-type": "application/json" },
      credentials: "include",
      body: JSON.stringify(req),
    });
    if (!res.ok) throw new Error(`delegation endpoint returned ${res.status}`);
    return (await res.json()) as SessionDelegation;
  }
}
