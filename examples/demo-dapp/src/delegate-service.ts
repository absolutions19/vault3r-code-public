/**
 * Reference delegation backend (framework-agnostic core).
 *
 * This is where the two CRITICAL red-team fixes live. To mint a SessionDelegation
 * the caller must clear ALL of:
 *   - a first-party auth session (modeled as a sessionId the caller is logged in as),
 *   - an Origin on the allow-list,
 *   - a matching CSRF token,
 *   - proof-of-possession: a signature over a fresh, single-use server challenge
 *     by the very session key the delegation will authorize,
 * and even then the requested scopes are clamped to a static allow-list before
 * signing. A stolen cookie alone (from evil.com) cannot mint a delegation for an
 * attacker-controlled key, because it cannot satisfy Origin + CSRF + PoP.
 */

import {
  ed25519Verify,
  signDelegation,
  signIdentityRecord,
  ed25519PublicFromSeed,
  randomBytes,
  toBase64Url,
  fromBase64Url,
  utf8ToBytes,
} from "@vault/crypto-core";
import {
  DELEGATION_DEFAULT_TTL_MS,
  PROTOCOL_VERSION,
  type RequestedScope,
  type FieldRule,
  type SessionDelegation,
  type VaultIdentityRecord,
} from "@vault/protocol";

export class DelegateError extends Error {
  constructor(
    message: string,
    readonly status: number,
    readonly code: string,
  ) {
    super(message);
    this.name = "DelegateError";
  }
}

export interface DelegateServiceConfig {
  domain: string;
  kid: string;
  domainSeed: Uint8Array;
  /** Static least-privilege ceiling; requested scopes are clamped to this. */
  allowedScopes: RequestedScope[];
  originAllowlist: string[];
  ttlMs?: number;
  challengeTtlMs?: number;
  clock?: () => number;
}

export interface MintRequest {
  sessionPublicKey: string;
  scopes: RequestedScope[];
  pairingChallenge: string;
  vaultId: string;
  challenge: string;
  popSig: string;
}

export interface MintContext {
  /** The Origin header the browser sent (trustworthy; set by the browser). */
  origin: string;
  /** The CSRF token from the request header. */
  csrfToken: string;
  /** The authenticated account for this first-party session. */
  account: string;
}

interface ChallengeEntry {
  challenge: string;
  csrfToken: string;
  expiry: number;
}

function pointerTokens(p: string): string[] {
  return p === "" ? [] : p.slice(1).split("/");
}
function covers(rule: string, path: string): boolean {
  const r = pointerTokens(rule);
  const t = pointerTokens(path);
  if (r.length > t.length) return false;
  return r.every((seg, i) => seg === t[i]);
}

export class DelegateService {
  private readonly challenges = new Map<string, ChallengeEntry>();
  private readonly clock: () => number;
  private readonly challengeTtlMs: number;

  constructor(private readonly config: DelegateServiceConfig) {
    this.clock = config.clock ?? Date.now;
    this.challengeTtlMs = config.challengeTtlMs ?? 120_000;
  }

  /** The `.well-known/vault-identity.json` document for this app. */
  wellKnownRecord(): VaultIdentityRecord {
    const publicKey = toBase64Url(ed25519PublicFromSeed(this.config.domainSeed));
    return signIdentityRecord(
      {
        schema: "vault-identity/1",
        domain: this.config.domain,
        namespaceGranularity: "registrable-domain",
        keys: [{ kid: this.config.kid, alg: "Ed25519", publicKey, created: "2026-01-01T00:00:00Z", status: "active" }],
        methods: this.config.allowedScopes.flatMap((s) => s.methods),
        protocolVersions: [PROTOCOL_VERSION],
      },
      this.config.kid,
      this.config.domainSeed,
    );
  }

  /** Issue a fresh single-use challenge + CSRF token bound to a first-party session. */
  issueChallenge(sessionId: string): { challenge: string; csrfToken: string } {
    const challenge = toBase64Url(randomBytes(24));
    const csrfToken = toBase64Url(randomBytes(24));
    this.challenges.set(sessionId, { challenge, csrfToken, expiry: this.clock() + this.challengeTtlMs });
    return { challenge, csrfToken };
  }

  /** Verify all gates and mint a scope-clamped, domain-signed delegation. */
  mintDelegation(sessionId: string, req: MintRequest, ctx: MintContext): SessionDelegation {
    // 1. Origin allow-list (defeats a top-level cross-site POST from evil.com).
    if (!this.config.originAllowlist.includes(ctx.origin)) {
      throw new DelegateError(`origin not allowed: ${ctx.origin}`, 403, "bad_origin");
    }
    // 2. CSRF + challenge binding (both scoped to the first-party session).
    const entry = this.challenges.get(sessionId);
    if (!entry) throw new DelegateError("no challenge issued", 400, "no_challenge");
    if (entry.expiry < this.clock()) {
      this.challenges.delete(sessionId);
      throw new DelegateError("challenge expired", 400, "challenge_expired");
    }
    if (ctx.csrfToken !== entry.csrfToken) throw new DelegateError("bad CSRF token", 403, "bad_csrf");
    if (req.challenge !== entry.challenge) throw new DelegateError("challenge mismatch", 400, "bad_challenge");
    // Single-use: consume the challenge regardless of what happens next.
    this.challenges.delete(sessionId);

    // 3. Proof-of-possession: the caller must control the key it is delegating to.
    let popOk = false;
    try {
      popOk = ed25519Verify(utf8ToBytes(req.challenge), fromBase64Url(req.popSig), fromBase64Url(req.sessionPublicKey));
    } catch {
      popOk = false;
    }
    if (!popOk) throw new DelegateError("proof-of-possession failed", 403, "bad_pop");

    // 4. Scope clamp to the static allow-list (least privilege).
    const scopes = this.clampScopes(req.scopes);
    if (scopes.every((s) => s.methods.length === 0 && s.fields.length === 0)) {
      throw new DelegateError("no requested scope is permitted", 403, "empty_scope");
    }

    // 5. Mint. assertedAccount comes from the authenticated session, never the caller.
    const now = this.clock();
    return signDelegation(
      {
        domain: this.config.domain,
        sessionPublicKey: req.sessionPublicKey,
        scopes,
        vaultId: req.vaultId,
        pairingChallenge: req.pairingChallenge,
        assertedAccount: ctx.account,
        issuedAt: now,
        expiresAt: now + (this.config.ttlMs ?? DELEGATION_DEFAULT_TTL_MS),
        nonce: toBase64Url(randomBytes(12)),
        keyId: this.config.kid,
      },
      this.config.domainSeed,
    );
  }

  private clampScopes(requested: RequestedScope[]): RequestedScope[] {
    const allowedMethods = new Set(this.config.allowedScopes.flatMap((s) => s.methods));
    const allowedFields = this.config.allowedScopes.flatMap((s) => s.fields);
    return requested.map((scope) => {
      const methods = scope.methods.filter((m) => allowedMethods.has(m));
      const fields: FieldRule[] = [];
      for (const f of scope.fields) {
        const allow = allowedFields.find((a) => covers(a.path, f.path));
        if (!allow) continue; // requested a field outside the ceiling — drop it
        fields.push({
          path: f.path,
          read: f.read && allow.read,
          write: f.write && allow.write,
          ...(f.sensitive || allow.sensitive ? { sensitive: true } : {}),
        });
      }
      return { methods, fields };
    });
  }
}
