/**
 * VaultEngine — the single authorization authority and the request chokepoint.
 *
 * Every data-plane request funnels through `authorizeSigned`, which enforces, in
 * one place and one order: typed-domain separation → delegated-key signature →
 * session binding → namespace tripwire → freshness/replay → method grant. Only
 * then does a handler touch storage, and it applies the exact value that was
 * hashed into the signed request.
 */

import {
  Method,
  VaultError,
  PROTOCOL_VERSION,
  SESSION_DEFAULT_TTL_MS,
  SESSION_ABSOLUTE_MAX_TTL_MS,
  MAX_PATHS_PER_REQUEST,
  MAX_PATCH_OPS,
  MAX_NAMESPACE_BYTES,
  MAX_JSON_DEPTH,
  makeNotification,
  settleSigningPreimage,
  type SessionProposeParams,
  type SessionSettleResult,
  type GetDataParams,
  type GetDataResult,
  type SetDataParams,
  type SetDataResult,
  type PatchDataParams,
  type PatchDataResult,
  type SubscribeParams,
  type SubscribeResult,
  type UnsubscribeParams,
  type UnsubscribeResult,
  type RevokeParams,
  type RevokeResult,
  type ExtendParams,
  type ExtendResult,
  type GetPermissionsParams,
  type GetPermissionsResult,
  type PermissionsChangedNotification,
  type FieldRule,
  type Grant,
  type JsonRpcRequest,
  type JsonRpcResponse,
  type JsonRpcNotification,
  makeSuccess,
  makeFailure,
} from "@vault/protocol";
import type { ChangeDescriptor, TypedData } from "@vault/protocol";
import { deriveNamespace, hashJsonValue, randomBytes, toBase64Url, utf8ToBytes } from "@vault/crypto-core";
import { verifyTyped } from "@vault/crypto-core";
import type { Clock, ConsentAdapter, IdentityResolver, KeystoreAdapter, RevocationChecker, StorageAdapter } from "./adapters.js";
import { systemClock } from "./adapters.js";
import { DocumentStore, versionToEtag, etagToVersion } from "./document-store.js";
import { fieldAllows, intersectScopes, normalizeFields, pathIsSensitive } from "./grants.js";
import { pointerGet, pointerRemove, pointerSet, withinDepth, type Json } from "./json-pointer.js";
import { ReplayGuard } from "./replay.js";
import { SessionStore, type Session } from "./session.js";
import { verifyProposal } from "./identity-verify.js";

export interface VaultEngineConfig {
  keystore: KeystoreAdapter;
  storage: StorageAdapter;
  resolver: IdentityResolver;
  consent: ConsentAdapter;
  /** Optional short-TTL key-revocation checker (record.statusEndpoint). */
  revocation?: RevocationChecker;
  /** How often to re-check revocation on the data plane (ms). Default 60s. */
  revocationRecheckMs?: number;
  clock?: Clock;
  knownDomains?: string[];
  sessionTtlMs?: number;
  randomId?: () => string;
}

export interface ProposeContext {
  responderPublicKey: string;
  pairingNonce: string;
}

/** Emits a JSON-RPC notification (subscription update or permissions_changed) to a session. */
export type NotificationEmitter = (sessionId: string, notification: JsonRpcNotification) => void;

export class VaultEngine {
  private readonly keystore: KeystoreAdapter;
  private readonly resolver: IdentityResolver;
  private readonly consent: ConsentAdapter;
  private readonly revocation: RevocationChecker | undefined;
  private readonly revocationRecheckMs: number;
  private readonly clock: Clock;
  private readonly docStore: DocumentStore;
  private readonly sessions = new SessionStore();
  private readonly replay = new ReplayGuard();
  private readonly sessionTtlMs: number;
  private readonly randomId: () => string;
  private knownDomains: string[];
  private emitter?: NotificationEmitter;

  constructor(config: VaultEngineConfig) {
    this.keystore = config.keystore;
    this.resolver = config.resolver;
    this.consent = config.consent;
    this.revocation = config.revocation;
    this.revocationRecheckMs = config.revocationRecheckMs ?? 60_000;
    this.clock = config.clock ?? systemClock;
    this.docStore = new DocumentStore(config.keystore, config.storage);
    this.sessionTtlMs = config.sessionTtlMs ?? SESSION_DEFAULT_TTL_MS;
    this.randomId = config.randomId ?? (() => toBase64Url(randomBytes(16)));
    this.knownDomains = config.knownDomains ?? [];
  }

  setEmitter(fn: NotificationEmitter): void {
    this.emitter = fn;
  }

  /** This vault's stable install id (used in typed-domain separation). */
  vaultId(): string {
    return this.keystore.vaultId();
  }

  /** Connected apps, for the vault's own management UI. */
  listConnections(): { sessionId: string; grant: Grant; expiresAt: number }[] {
    return this.sessions.all().map((s) => ({ sessionId: s.id, grant: s.grant, expiresAt: s.expiresAt }));
  }

  /** User-initiated revocation from the vault UI (no signed request required). */
  adminRevoke(sessionId: string): void {
    this.sessions.delete(sessionId);
  }

  async unlock(): Promise<boolean> {
    return this.keystore.unlock({ reason: "unlock", prompt: "Unlock your vault" });
  }

  // --------------------------------------------------------------------------
  // Connection
  // --------------------------------------------------------------------------

  async connect(params: SessionProposeParams, ctx: ProposeContext): Promise<SessionSettleResult> {
    const now = this.clock.now();

    const verified = await verifyProposal(params, {
      resolver: this.resolver,
      ...(this.revocation ? { revocation: this.revocation } : {}),
      vaultId: this.keystore.vaultId(),
      responderPublicKey: ctx.responderPublicKey,
      pairingNonce: ctx.pairingNonce,
      knownDomains: this.knownDomains,
      now,
    });

    const requested = intersectScopes(params.requestedScopes, verified.verification.allowedMethods);
    if (requested.methods.length === 0) {
      throw VaultError.of("UnsupportedMethod", "no requested method is permitted by the identity record");
    }

    const decision = await this.consent.requestConnect({
      verification: verified.verification,
      appMetadata: params.appMetadata,
      requestedScopes: params.requestedScopes,
      pairingChallenge: params.pairingChallenge,
      ...(verified.delegation.assertedAccount !== undefined
        ? { assertedAccount: verified.delegation.assertedAccount }
        : {}),
    });
    if (!decision.approved) throw VaultError.of("UserRejected", decision.reason ?? "user declined");

    const bio = await this.keystore.authenticate({ reason: "connect", prompt: `Connect ${verified.verification.domain}` });
    if (!bio) throw VaultError.of("BiometricFailed");
    if (!this.keystore.isUnlocked() && !(await this.keystore.unlock())) throw VaultError.of("VaultLocked");

    const grantedMethods = decision.grantedMethods ?? requested.methods;
    const grantedFields = normalizeFields(decision.grantedFields ?? requested.fields);
    const writePolicy = decision.writePolicy ?? "ask-once-per-session";
    const derived = deriveNamespace(verified.canonicalHost, verified.verification.granularity ?? "registrable-domain");
    const expiresAt = now + this.sessionTtlMs;
    const grantId = this.randomId();

    const grant: Grant = {
      id: grantId,
      namespace: verified.verification.namespace,
      domain: verified.verification.domain,
      appMetadata: params.appMetadata,
      verified: verified.verification.ok,
      methods: grantedMethods,
      fields: grantedFields,
      writePolicy,
      createdAt: now,
      expiresAt,
      identityKid: verified.verification.identityKid,
    };

    const sessionId = this.randomId();
    const deviceKeyPub = this.keystore.deviceKeyPublic();
    const session: Session = {
      id: sessionId,
      namespace: verified.verification.namespace,
      storageKey: derived.storageKey,
      grant,
      delegatedKeyPub: verified.delegatedKeyPub,
      proposerPublicKey: params.proposerPublicKey,
      responderPublicKey: ctx.responderPublicKey,
      deviceKeyPub,
      createdAt: now,
      expiresAt,
      statusEndpoint: verified.statusEndpoint,
      identityKid: verified.verification.identityKid,
      lastRevocationCheckAt: now,
      writePolicy,
      writeApprovedThisSession: false,
      subscriptions: new Map(),
      domain: verified.verification.domain,
      verified: verified.verification.ok,
    };
    this.sessions.create(session);
    if (verified.verification.domain && !this.knownDomains.includes(verified.verification.domain)) {
      this.knownDomains.push(verified.verification.domain);
    }

    const vaultSig = await this.keystore.signDevice(
      settleSigningPreimage({
        sessionId,
        namespace: session.namespace,
        grantId,
        responderPublicKey: ctx.responderPublicKey,
        vaultDeviceKey: deviceKeyPub,
        expiresAt,
        methods: grantedMethods,
      }),
    );

    return {
      sessionId,
      granted: grant,
      responderPublicKey: ctx.responderPublicKey,
      vaultDeviceKey: deviceKeyPub,
      expiresAt,
      vaultSig,
    };
  }

  // --------------------------------------------------------------------------
  // Request dispatch
  // --------------------------------------------------------------------------

  async handleRequest(sessionId: string, req: JsonRpcRequest): Promise<JsonRpcResponse> {
    try {
      const session = this.requireSession(sessionId);
      if (!this.keystore.isUnlocked()) throw VaultError.of("VaultLocked");
      await this.enforceRevocation(session, false);
      const result = await this.dispatch(session, req);
      return makeSuccess(req.id, result);
    } catch (err) {
      return makeFailure(req.id, VaultError.fromUnknown(err).toRpcError());
    }
  }

  /**
   * Re-check the pinned revocation status on the data plane so a key revoked
   * AFTER connect loses access without waiting for the session to expire. Cached
   * to `revocationRecheckMs` on normal requests; `force` bypasses the cache (used
   * on session extension). Fails closed: a revoked key OR a checker error tears
   * the session down.
   */
  private async enforceRevocation(session: Session, force: boolean): Promise<void> {
    if (!this.revocation || !session.statusEndpoint || !session.identityKid) return;
    const now = this.clock.now();
    if (!force && now - session.lastRevocationCheckAt < this.revocationRecheckMs) return;
    let revoked: boolean;
    try {
      revoked = await this.revocation.isRevoked(session.statusEndpoint, session.identityKid);
    } catch {
      this.sessions.delete(session.id);
      throw VaultError.of("Disconnected", "revocation status could not be re-checked");
    }
    if (revoked) {
      this.sessions.delete(session.id);
      throw VaultError.of("Disconnected", "identity key has been revoked");
    }
    session.lastRevocationCheckAt = now;
  }

  private requireSession(sessionId: string): Session {
    const session = this.sessions.get(sessionId);
    if (!session) throw VaultError.of("Disconnected", "unknown session");
    const now = this.clock.now();
    // Absolute-lifetime ceiling: past it, a full reconnect + consent is required,
    // regardless of how many times the session was extended.
    if (now > session.createdAt + SESSION_ABSOLUTE_MAX_TTL_MS) {
      this.sessions.delete(sessionId);
      throw VaultError.of("Disconnected", "session reached its absolute lifetime cap");
    }
    if (now > session.expiresAt) {
      this.sessions.delete(sessionId);
      throw VaultError.of("Disconnected", "session expired");
    }
    return session;
  }

  private async dispatch(session: Session, req: JsonRpcRequest): Promise<unknown> {
    switch (req.method) {
      case Method.GetData:
        return this.getData(session, req.params as GetDataParams);
      case Method.SetData:
        return this.setData(session, req.params as SetDataParams);
      case Method.PatchData:
        return this.patchData(session, req.params as PatchDataParams);
      case Method.Subscribe:
        return this.subscribe(session, req.params as SubscribeParams);
      case Method.Unsubscribe:
        return this.unsubscribe(session, req.params as UnsubscribeParams);
      case Method.Revoke:
        return this.revoke(session, req.params as RevokeParams);
      case Method.SessionExtend:
        return this.extendSession(session, req.params as ExtendParams);
      case Method.GetPermissions:
        return this.getPermissions(session, req.params as GetPermissionsParams);
      default:
        throw VaultError.of("UnsupportedMethod", `method not supported: ${req.method}`);
    }
  }

  /** The one chokepoint every signed data-plane request passes through. */
  private authorizeSigned(
    session: Session,
    signed: { typed: TypedData; sig: string },
    primaryType: string,
    methodName: string,
    opts: { skipMethodCheck?: boolean } = {},
  ): Record<string, unknown> {
    const now = this.clock.now();
    const typed = signed.typed;
    if (typed.primaryType !== primaryType) throw VaultError.of("InvalidRequest", "wrong primaryType");
    if (typed.domain.vaultId !== this.keystore.vaultId() || typed.domain.version !== PROTOCOL_VERSION) {
      throw VaultError.of("BadSignature", "typed-domain separator mismatch");
    }
    if (!verifyTyped(signed.typed, signed.sig, session.delegatedKeyPub)) {
      throw VaultError.of("BadSignature", "request signature invalid");
    }
    const msg = typed.message as unknown as Record<string, unknown>;
    if (msg["sessionId"] !== session.id) throw VaultError.of("Unauthorized", "session mismatch");
    if (msg["namespace"] !== session.namespace) throw VaultError.of("NamespaceMismatch");
    this.replay.check(
      session.id,
      String(msg["nonce"]),
      Number(msg["issuedAt"]),
      Number(msg["expiry"]),
      now,
    );
    if (!opts.skipMethodCheck && !session.grant.methods.includes(methodName)) {
      throw VaultError.of("Unauthorized", `method not granted: ${methodName}`);
    }
    return msg;
  }

  private async getData(session: Session, params: GetDataParams): Promise<GetDataResult> {
    const msg = this.authorizeSigned(session, params, "VaultRead", Method.GetData);
    const paths = (msg["paths"] as string[]) ?? [];
    if (paths.length > MAX_PATHS_PER_REQUEST) throw VaultError.of("QuotaExceeded", "too many paths");
    for (const path of paths) {
      if (!fieldAllows(session.grant.fields, path, "read")) {
        throw VaultError.of("FieldOutOfScope", `read not granted: ${path}`);
      }
      if (pathIsSensitive(session.grant.fields, path)) {
        const ok = await this.keystore.authenticate({ reason: "sensitive-read", prompt: `Read ${path}` });
        if (!ok) throw VaultError.of("BiometricFailed");
      }
    }
    const { doc, version } = await this.docStore.load(session.storageKey);
    const values: Record<string, unknown> = {};
    for (const path of paths) {
      const got = pointerGet(doc, path);
      values[path] = got === undefined ? null : got;
    }
    return { values, version: versionToEtag(version) };
  }

  private async setData(session: Session, params: SetDataParams): Promise<SetDataResult> {
    const msg = this.authorizeSigned(session, params, "VaultWrite", Method.SetData);
    const version = await this.applyChanges(
      session,
      msg["changes"] as ChangeDescriptor[],
      params.values,
      msg["baseVersion"] as string | undefined,
    );
    return { applied: true, version: versionToEtag(version) };
  }

  private async patchData(session: Session, params: PatchDataParams): Promise<PatchDataResult> {
    const msg = this.authorizeSigned(session, params, "VaultPatch", Method.PatchData);
    const changes = (msg["changes"] as ChangeDescriptor[]) ?? [];
    const version = await this.applyChanges(session, changes, params.values, msg["baseVersion"] as string | undefined);
    return { applied: true, version: versionToEtag(version) };
  }

  /** Shared write path for setData/patchData with per-op scope + value-hash checks. */
  private async applyChanges(
    session: Session,
    changes: ChangeDescriptor[],
    values: Record<string, unknown>,
    baseVersion: string | undefined,
  ): Promise<number> {
    // Op-count cap enforced here so it applies to BOTH setData and patchData
    // (they funnel through this one chokepoint).
    if (changes.length > MAX_PATCH_OPS) throw VaultError.of("QuotaExceeded", "too many changes in one request");

    // Write-policy gating.
    const anySensitive = changes.some((c) => pathIsSensitive(session.grant.fields, c.path));
    const needBiometric =
      anySensitive ||
      session.writePolicy === "ask-every" ||
      (session.writePolicy === "ask-once-per-session" && !session.writeApprovedThisSession);
    if (needBiometric) {
      const ok = await this.keystore.authenticate({ reason: anySensitive ? "sensitive-write" : "write", prompt: "Approve write" });
      if (!ok) throw VaultError.of("BiometricFailed");
      session.writeApprovedThisSession = true;
    }

    const loaded = await this.docStore.load(session.storageKey);
    const baseV = etagToVersion(baseVersion);
    if (baseV !== undefined && baseV !== loaded.version) {
      throw VaultError.of("VersionConflict", `stale baseVersion (have ${loaded.version})`);
    }

    let doc = loaded.doc;
    const changedPaths: string[] = [];
    for (const change of changes) {
      const path = change.path;
      if (change.op === "remove") {
        if (!fieldAllows(session.grant.fields, path, "write")) {
          throw fieldAllows(session.grant.fields, path, "read")
            ? VaultError.of("WriteForbidden", path)
            : VaultError.of("FieldOutOfScope", path);
        }
        doc = pointerRemove(doc, path);
        changedPaths.push(path);
        continue;
      }
      // add / replace
      if (!fieldAllows(session.grant.fields, path, "write")) {
        throw fieldAllows(session.grant.fields, path, "read")
          ? VaultError.of("WriteForbidden", path)
          : VaultError.of("FieldOutOfScope", path);
      }
      if (!(path in values)) throw VaultError.of("InvalidRequest", `missing value for ${path}`);
      const value = values[path] as Json;
      if (change.valueHash !== undefined && hashJsonValue(value as never) !== change.valueHash) {
        throw VaultError.of("BadSignature", `value hash mismatch for ${path}`);
      }
      doc = pointerSet(doc, path, value);
      changedPaths.push(path);
    }

    // Stored-doc depth cap: keep the document re-parseable by a strict peer
    // (paths add nesting on top of value nesting, so this is checked here).
    if (!withinDepth(doc, MAX_JSON_DEPTH)) {
      throw VaultError.of("QuotaExceeded", "namespace document exceeds nesting depth");
    }
    // Per-namespace document quota (measured on the UTF-8 serialization).
    if (utf8ToBytes(JSON.stringify(doc)).length > MAX_NAMESPACE_BYTES) {
      throw VaultError.of("QuotaExceeded", "namespace document exceeds size cap");
    }

    const newVersion = loaded.version + 1;
    await this.docStore.save(session.storageKey, doc, newVersion);
    this.fanOutChanges(session, changedPaths, doc, newVersion);
    return newVersion;
  }

  private fanOutChanges(source: Session, changedPaths: string[], doc: Json, version: number): void {
    if (!this.emitter || changedPaths.length === 0) return;
    for (const session of this.sessions.forNamespace(source.namespace)) {
      for (const sub of session.subscriptions.values()) {
        const hit = changedPaths.filter(
          (p) => sub.paths.some((watch) => p === watch || p.startsWith(`${watch}/`)) && fieldAllows(session.grant.fields, p, "read"),
        );
        if (hit.length === 0) continue;
        const changes: Record<string, unknown> = {};
        for (const p of hit) {
          const got = pointerGet(doc, p);
          changes[p] = got === undefined ? null : got;
        }
        this.emitter(
          session.id,
          makeNotification(Method.Subscription, { subscriptionId: sub.id, changes, version: versionToEtag(version) }),
        );
      }
    }
  }

  private async subscribe(session: Session, params: SubscribeParams): Promise<SubscribeResult> {
    const msg = this.authorizeSigned(session, params, "VaultRead", Method.Subscribe);
    const paths = (msg["paths"] as string[]) ?? [];
    if (paths.length > MAX_PATHS_PER_REQUEST) throw VaultError.of("QuotaExceeded", "too many subscription paths");
    for (const path of paths) {
      if (!fieldAllows(session.grant.fields, path, "read")) {
        throw VaultError.of("FieldOutOfScope", `read not granted: ${path}`);
      }
    }
    const subscriptionId = this.randomId();
    session.subscriptions.set(subscriptionId, { id: subscriptionId, paths });
    return { subscriptionId };
  }

  private async unsubscribe(session: Session, params: UnsubscribeParams): Promise<UnsubscribeResult> {
    session.subscriptions.delete(params.subscriptionId);
    return { ok: true };
  }

  private async revoke(session: Session, params: RevokeParams): Promise<RevokeResult> {
    this.authorizeSigned(session, params, "VaultRevoke", Method.Revoke, { skipMethodCheck: true });
    this.sessions.delete(session.id);
    return { ok: true };
  }

  private async extendSession(session: Session, params: ExtendParams): Promise<ExtendResult> {
    const msg = this.authorizeSigned(session, params, "VaultExtend", Method.SessionExtend, { skipMethodCheck: true });
    const now = this.clock.now();
    const cap = session.createdAt + SESSION_ABSOLUTE_MAX_TTL_MS;
    if (now >= cap) {
      this.sessions.delete(session.id);
      throw VaultError.of("Disconnected", "session at absolute cap; reconnect required");
    }
    // Never extend a session whose key has since been revoked (always re-check).
    await this.enforceRevocation(session, true);
    // Honoring an extension requires a fresh biometric.
    const ok = await this.keystore.authenticate({ reason: "grant-change", prompt: "Extend session" });
    if (!ok) throw VaultError.of("BiometricFailed");

    const requested = Math.max(0, Number(msg["requestedTtlMs"]) || 0);
    // Extend, never shorten: take the later of the current expiry and now+requested,
    // clamped to the absolute cap.
    session.expiresAt = Math.min(cap, Math.max(session.expiresAt, now + requested));
    return { expiresAt: session.expiresAt, atAbsoluteCap: session.expiresAt >= cap };
  }

  /**
   * User-initiated grant narrowing from the vault UI. Replaces the granted fields,
   * tears down any subscription that is no longer in scope, and notifies the app
   * with a permissions_changed event so it can't keep relying on stale access.
   */
  narrowGrant(sessionId: string, fields: FieldRule[]): void {
    const session = this.sessions.get(sessionId);
    if (!session) return;
    session.grant.fields = fields;
    const revokedSubscriptions: string[] = [];
    for (const [subId, sub] of session.subscriptions) {
      const stillReadable = sub.paths.some((p) => fieldAllows(fields, p, "read"));
      if (!stillReadable) {
        session.subscriptions.delete(subId);
        revokedSubscriptions.push(subId);
      }
    }
    const note: PermissionsChangedNotification = { sessionId, fields, revokedSubscriptions };
    this.emitter?.(sessionId, makeNotification(Method.PermissionsChanged, note));
  }

  private async getPermissions(session: Session, _params: GetPermissionsParams): Promise<GetPermissionsResult> {
    return { grant: session.grant };
  }
}
