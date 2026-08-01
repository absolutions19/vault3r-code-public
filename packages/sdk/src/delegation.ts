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
  /**
   * Proof-of-possession callback: signs a server-issued challenge with d_sess.
   * The backend verifies this so a stolen cookie cannot mint a delegation for an
   * attacker-chosen key. Supplied by VaultClient (which holds d_sess).
   */
  signChallenge: (challenge: string) => string;
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

/** Same-process signer for tests/demos. Skips the network + PoP round-trip. */
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

export interface HttpDelegationSignerOptions {
  /** GET here (with credentials) to obtain a fresh challenge + CSRF token. */
  challengeUrl: string;
  /** POST here (with credentials + CSRF header) to mint the delegation. */
  mintUrl: string;
  /** Origin header value (set automatically by the browser; explicit in Node). */
  origin?: string;
  fetchImpl?: typeof fetch;
}

interface ChallengeResponse {
  challenge: string;
  csrfToken: string;
}

/**
 * Production signer: runs the challenge → proof-of-possession → mint flow against
 * the app's backend. The backend enforces CSRF, an Origin allow-list, PoP, and a
 * static scope clamp before signing.
 */
export class HttpDelegationSigner implements DelegationSigner {
  private readonly fetchImpl: typeof fetch;
  constructor(private readonly opts: HttpDelegationSignerOptions) {
    // Bind to the global so calling it as `this.fetchImpl(...)` doesn't trip the
    // browser's "Illegal invocation" (global fetch must run with window as `this`).
    const base = opts.fetchImpl ?? fetch;
    this.fetchImpl = base.bind(globalThis);
  }

  async getDelegation(req: DelegationRequest): Promise<SessionDelegation> {
    const chalRes = await this.fetchImpl(this.opts.challengeUrl, { method: "GET", credentials: "include" });
    if (!chalRes.ok) throw new Error(`challenge endpoint returned ${chalRes.status}`);
    const { challenge, csrfToken } = (await chalRes.json()) as ChallengeResponse;

    const popSig = req.signChallenge(challenge);
    const headers: Record<string, string> = { "content-type": "application/json", "x-csrf-token": csrfToken };
    if (this.opts.origin) headers["origin"] = this.opts.origin;

    const res = await this.fetchImpl(this.opts.mintUrl, {
      method: "POST",
      headers,
      credentials: "include",
      body: JSON.stringify({
        sessionPublicKey: req.sessionPublicKey,
        scopes: req.scopes,
        pairingChallenge: req.pairingChallenge,
        vaultId: req.vaultId,
        challenge,
        popSig,
      }),
    });
    if (!res.ok) throw new Error(`delegation endpoint returned ${res.status}`);
    return (await res.json()) as SessionDelegation;
  }
}
