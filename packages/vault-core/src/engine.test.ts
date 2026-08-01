import { beforeEach, describe, expect, it, vi } from "vitest";
import {
  ed25519Generate,
  x25519Generate,
  toBase64Url,
  signIdentityRecord,
  signDelegation,
  signTyped,
  transcriptHash,
  deriveNamespace,
  hashJsonValue,
  randomBytes,
  type RawKeyPair,
} from "@vault/crypto-core";
import {
  makeDomain,
  makeRequest,
  Method,
  ErrorCode,
  PROTOCOL_VERSION,
  type FieldRule,
  type SessionProposeParams,
  type SessionSettleResult,
  type TypedData,
  type VaultIdentityRecord,
  type JsonRpcResponse,
  type JsonRpcFailure,
} from "@vault/protocol";
import { VaultEngine } from "./engine.js";
import { InMemoryKeystore, InMemoryStorage, StaticIdentityResolver, AutoConsent, StaticRevocationChecker } from "./in-memory.js";

const FIXED_NOW = 1_760_000_000_000;
const clock = { now: () => FIXED_NOW };

function failure(res: JsonRpcResponse): JsonRpcFailure {
  if (!("error" in res)) throw new Error(`expected failure, got ${JSON.stringify(res)}`);
  return res;
}

/** A test client that mints valid records, delegations, and signed requests. */
class TestClient {
  domainKey: RawKeyPair;
  sessKey: RawKeyPair; // d_sess
  proposer = x25519Generate();
  responder = x25519Generate(); // stands in for the vault session key
  pairingNonce = toBase64Url(randomBytes(16));
  record: VaultIdentityRecord;
  private nonce = 0;

  constructor(
    public domain: string,
    public vaultId: string,
    fields: FieldRule[],
    methods: string[] = [
      Method.GetData,
      Method.SetData,
      Method.PatchData,
      Method.Subscribe,
      Method.Unsubscribe,
      Method.Revoke,
      Method.GetPermissions,
    ],
    keyStatus: "active" | "retired" | "revoked" = "active",
    statusEndpoint: string | null = null,
  ) {
    this.domainKey = ed25519Generate();
    this.sessKey = ed25519Generate();
    this.fields = fields;
    this.methods = methods;
    this.record = signIdentityRecord(
      {
        schema: "vault-identity/1",
        domain,
        namespaceGranularity: "registrable-domain",
        keys: [
          {
            kid: "k1",
            alg: "Ed25519",
            publicKey: toBase64Url(this.domainKey.publicKey),
            created: "2026-01-01T00:00:00Z",
            status: keyStatus,
          },
        ],
        ...(statusEndpoint ? { statusEndpoint } : {}),
        methods,
        protocolVersions: [PROTOCOL_VERSION],
      },
      "k1",
      this.domainKey.privateKey,
    );
  }
  fields: FieldRule[];
  methods: string[];

  get namespace(): string {
    return deriveNamespace(this.domain, "registrable-domain").namespace;
  }

  private nextNonce(): string {
    return `n${this.nonce++}`;
  }

  proposal(overrides: Partial<{ pairingChallenge: string }> = {}): {
    params: SessionProposeParams;
    ctx: { responderPublicKey: string; pairingNonce: string };
  } {
    const pairingChallenge = overrides.pairingChallenge ?? "42815937";
    const delegation = signDelegation(
      {
        domain: this.domain,
        sessionPublicKey: toBase64Url(this.sessKey.publicKey),
        scopes: [{ methods: this.methods, fields: this.fields }],
        vaultId: this.vaultId,
        pairingChallenge,
        assertedAccount: "alice@" + this.domain,
        issuedAt: FIXED_NOW,
        expiresAt: FIXED_NOW + 300_000,
        nonce: "d0",
        keyId: "k1",
      },
      this.domainKey.privateKey,
    );
    const proposerPublicKey = toBase64Url(this.proposer.publicKey);
    const responderPublicKey = toBase64Url(this.responder.publicKey);
    const th = transcriptHash({
      proposerPublicKey,
      responderPublicKey,
      protocolVersion: PROTOCOL_VERSION,
      pairingNonce: this.pairingNonce,
    });
    const connectTyped: TypedData<"VaultConnect"> = {
      primaryType: "VaultConnect",
      domain: makeDomain(this.vaultId),
      message: {
        namespace: this.namespace,
        nonce: this.nextNonce(),
        issuedAt: FIXED_NOW,
        expiry: FIXED_NOW + 300_000,
        sessionId: this.pairingNonce,
        proposerPublicKey,
        responderPublicKey,
        transcriptHash: th,
      },
    };
    const params: SessionProposeParams = {
      domain: this.domain,
      appMetadata: { name: "Test App" },
      requestedScopes: [{ methods: this.methods, fields: this.fields }],
      delegation,
      proposerPublicKey,
      protocolVersions: [PROTOCOL_VERSION],
      connect: { typed: connectTyped, identity: { keyId: "k1", algo: "Ed25519" }, sig: signTyped(connectTyped, this.sessKey.privateKey) },
      pairingChallenge,
    };
    return { params, ctx: { responderPublicKey, pairingNonce: this.pairingNonce } };
  }

  private signed<P extends "VaultRead" | "VaultWrite" | "VaultPatch" | "VaultRevoke" | "VaultExtend">(
    primaryType: P,
    sessionId: string,
    extra: Record<string, unknown>,
    claimNamespace?: string,
  ) {
    const typed = {
      primaryType,
      domain: makeDomain(this.vaultId),
      message: {
        namespace: claimNamespace ?? this.namespace,
        nonce: this.nextNonce(),
        issuedAt: FIXED_NOW,
        expiry: FIXED_NOW + 200_000,
        sessionId,
        ...extra,
      },
    } as TypedData<P>;
    return { typed, identity: { keyId: "k1", algo: "Ed25519" as const }, sig: signTyped(typed, this.sessKey.privateKey) };
  }

  getData(sessionId: string, paths: string[], claimNamespace?: string) {
    return makeRequest(this.nextNonce(), Method.GetData, this.signed("VaultRead", sessionId, { paths }, claimNamespace));
  }

  setData(sessionId: string, path: string, value: unknown, baseVersion?: string) {
    const changes = [{ op: "replace" as const, path, valueHash: hashJsonValue(value as never) }];
    const s = this.signed("VaultWrite", sessionId, baseVersion ? { changes, baseVersion } : { changes });
    return makeRequest(this.nextNonce(), Method.SetData, { ...s, values: { [path]: value } });
  }

  subscribe(sessionId: string, paths: string[]) {
    return makeRequest(this.nextNonce(), Method.Subscribe, this.signed("VaultRead", sessionId, { paths }));
  }

  writeMany(sessionId: string, entries: { path: string; value: unknown }[]) {
    const changes = entries.map((e) => ({ op: "replace" as const, path: e.path, valueHash: hashJsonValue(e.value as never) }));
    const values: Record<string, unknown> = {};
    for (const e of entries) values[e.path] = e.value;
    const s = this.signed("VaultWrite", sessionId, { changes });
    return makeRequest(this.nextNonce(), Method.SetData, { ...s, values });
  }

  patchMany(sessionId: string, entries: { path: string; value: unknown }[]) {
    const changes = entries.map((e) => ({ op: "replace" as const, path: e.path, valueHash: hashJsonValue(e.value as never) }));
    const values: Record<string, unknown> = {};
    for (const e of entries) values[e.path] = e.value;
    const s = this.signed("VaultPatch", sessionId, { changes });
    return makeRequest(this.nextNonce(), Method.PatchData, { ...s, values });
  }

  extend(sessionId: string, requestedTtlMs: number) {
    return makeRequest(this.nextNonce(), Method.SessionExtend, this.signed("VaultExtend", sessionId, { requestedTtlMs }));
  }
}

function newEngine(resolver: StaticIdentityResolver, keystore = new InMemoryKeystore({ vaultId: "vault-under-test" })) {
  return new VaultEngine({ keystore, storage: new InMemoryStorage(), resolver, consent: new AutoConsent(), clock });
}

describe("VaultEngine — connection + data plane", () => {
  let resolver: StaticIdentityResolver;
  let engine: VaultEngine;
  let alice: TestClient;

  beforeEach(async () => {
    resolver = new StaticIdentityResolver();
    engine = newEngine(resolver);
    alice = new TestClient("example.com", "vault-under-test", [
      { path: "/profile", read: true, write: true },
      { path: "/readonly", read: true, write: false },
      { path: "/secret", read: true, write: true, sensitive: true },
    ]);
    resolver.set(alice.record);
  });

  it("connects and settles with a vault-signed result", async () => {
    const { params, ctx } = alice.proposal();
    const settle: SessionSettleResult = await engine.connect(params, ctx);
    expect(settle.sessionId).toBeTruthy();
    expect(settle.granted.namespace).toBe("web:example.com");
    expect(settle.vaultSig).toBeTruthy();
  });

  it("writes then reads back a value", async () => {
    const { params, ctx } = alice.proposal();
    const { sessionId } = await engine.connect(params, ctx);
    const w = await engine.handleRequest(sessionId, alice.setData(sessionId, "/profile/name", "Alice"));
    expect("result" in w).toBe(true);
    const r = await engine.handleRequest(sessionId, alice.getData(sessionId, ["/profile/name"]));
    expect((r as { result: { values: Record<string, unknown> } }).result.values["/profile/name"]).toBe("Alice");
  });

  it("rejects reads outside the granted scope", async () => {
    const { params, ctx } = alice.proposal();
    const { sessionId } = await engine.connect(params, ctx);
    const r = await engine.handleRequest(sessionId, alice.getData(sessionId, ["/not-granted"]));
    expect(failure(r).error.code).toBe(ErrorCode.FieldOutOfScope);
  });

  it("rejects writes to read-only fields", async () => {
    const { params, ctx } = alice.proposal();
    const { sessionId } = await engine.connect(params, ctx);
    const r = await engine.handleRequest(sessionId, alice.setData(sessionId, "/readonly", "x"));
    expect(failure(r).error.code).toBe(ErrorCode.WriteForbidden);
  });

  it("rejects a value whose hash does not match the signed valueHash", async () => {
    const { params, ctx } = alice.proposal();
    const { sessionId } = await engine.connect(params, ctx);
    const req = alice.setData(sessionId, "/profile/name", "Alice");
    (req.params as { values: Record<string, unknown> }).values["/profile/name"] = "Mallory"; // swap value after signing
    const r = await engine.handleRequest(sessionId, req);
    expect(failure(r).error.code).toBe(ErrorCode.BadSignature);
  });

  it("enforces optimistic concurrency via baseVersion", async () => {
    const { params, ctx } = alice.proposal();
    const { sessionId } = await engine.connect(params, ctx);
    await engine.handleRequest(sessionId, alice.setData(sessionId, "/profile/a", 1));
    const stale = await engine.handleRequest(sessionId, alice.setData(sessionId, "/profile/a", 2, "etag:0"));
    expect(failure(stale).error.code).toBe(ErrorCode.VersionConflict);
  });

  it("rejects a replayed nonce", async () => {
    const { params, ctx } = alice.proposal();
    const { sessionId } = await engine.connect(params, ctx);
    const req = alice.getData(sessionId, ["/profile/name"]);
    await engine.handleRequest(sessionId, req);
    const replayed = await engine.handleRequest(sessionId, req); // identical signed request
    expect(failure(replayed).error.code).toBe(ErrorCode.NonceReplay);
  });

  it("delivers subscription notifications on write, re-checking scope", async () => {
    const { params, ctx } = alice.proposal();
    const { sessionId } = await engine.connect(params, ctx);
    const emitted: unknown[] = [];
    engine.setEmitter((sid, note) => emitted.push({ sid, note }));
    await engine.handleRequest(sessionId, alice.subscribe(sessionId, ["/profile"]));
    await engine.handleRequest(sessionId, alice.setData(sessionId, "/profile/status", "online"));
    expect(emitted.length).toBe(1);
  });
});

describe("VaultEngine — anti-spoofing", () => {
  let resolver: StaticIdentityResolver;
  let engine: VaultEngine;
  let alice: TestClient;
  let evil: TestClient;

  beforeEach(() => {
    resolver = new StaticIdentityResolver();
    engine = newEngine(resolver);
    alice = new TestClient("example.com", "vault-under-test", [{ path: "/profile", read: true, write: true }]);
    evil = new TestClient("evil.com", "vault-under-test", [{ path: "/profile", read: true, write: true }]);
    resolver.set(alice.record);
    resolver.set(evil.record);
  });

  it("derives a distinct namespace per verified domain", async () => {
    const ap = alice.proposal();
    const ep = evil.proposal();
    const a = await engine.connect(ap.params, ap.ctx);
    const e = await engine.connect(ep.params, ep.ctx);
    expect(a.granted.namespace).toBe("web:example.com");
    expect(e.granted.namespace).toBe("web:evil.com");
  });

  it("blocks a malicious site from addressing another namespace (tripwire)", async () => {
    const ep = evil.proposal();
    const evilConn = await engine.connect(ep.params, ep.ctx);
    // Evil signs a well-formed request but claims Alice's namespace.
    const spoof = evil.getData(evilConn.sessionId, ["/profile"], "web:example.com");
    const r = await engine.handleRequest(evilConn.sessionId, spoof);
    expect(failure(r).error.code).toBe(ErrorCode.NamespaceMismatch);
  });

  it("keeps each namespace's data physically separate", async () => {
    const aConn = await engine.connect(alice.proposal().params, alice.proposal().ctx);
    const eConn = await engine.connect(evil.proposal().params, evil.proposal().ctx);
    await engine.handleRequest(aConn.sessionId, alice.setData(aConn.sessionId, "/profile/secret", "alices-secret"));
    // Evil reads its own /profile/secret — must be empty, never Alice's value.
    const r = await engine.handleRequest(eConn.sessionId, evil.getData(eConn.sessionId, ["/profile/secret"]));
    expect((r as { result: { values: Record<string, unknown> } }).result.values["/profile/secret"]).toBeNull();
  });

  it("rejects an unverified domain (no resolvable identity record)", async () => {
    const stranger = new TestClient("stranger.example", "vault-under-test", [{ path: "/x", read: true, write: true }]);
    // resolver has no record for stranger.example
    await expect(engine.connect(stranger.proposal().params, stranger.proposal().ctx)).rejects.toMatchObject({
      code: ErrorCode.IdentityUnverified,
    });
  });

  it("rejects a MITM'd handshake (responder key substitution)", async () => {
    const { params } = alice.proposal();
    // Attacker swaps the responder public key the vault actually holds.
    const mitmCtx = { responderPublicKey: toBase64Url(x25519Generate().publicKey), pairingNonce: alice.pairingNonce };
    await expect(engine.connect(params, mitmCtx)).rejects.toMatchObject({ code: ErrorCode.BadSignature });
  });

  it("rejects a delegation with a mismatched pairing challenge", async () => {
    const { params, ctx } = alice.proposal();
    params.pairingChallenge = "00000000"; // does not match the challenge signed into the delegation
    await expect(engine.connect(params, ctx)).rejects.toMatchObject({ code: ErrorCode.BadSignature });
  });

  it("rejects a delegation bound to a different vault", async () => {
    const otherVaultClient = new TestClient("example.com", "some-other-vault", [{ path: "/profile", read: true, write: true }]);
    resolver.set(otherVaultClient.record);
    await expect(
      engine.connect(otherVaultClient.proposal().params, otherVaultClient.proposal().ctx),
    ).rejects.toMatchObject({ code: ErrorCode.BadSignature });
  });
});

describe("VaultEngine — session extension caps", () => {
  const SEVEN_DAYS = 7 * 24 * 60 * 60_000;
  let resolver: StaticIdentityResolver;
  let alice: TestClient;

  beforeEach(() => {
    resolver = new StaticIdentityResolver();
    alice = new TestClient("example.com", "vault-under-test", [{ path: "/profile", read: true, write: true }]);
    resolver.set(alice.record);
  });

  it("extends within the absolute cap (biometric required, never shortens)", async () => {
    const engine = newEngine(resolver);
    const { sessionId } = await engine.connect(alice.proposal().params, alice.proposal().ctx);
    // Default session TTL is 4h; request a longer 6h window → grows to now+6h.
    const r = await engine.handleRequest(sessionId, alice.extend(sessionId, 6 * 60 * 60_000));
    expect("result" in r).toBe(true);
    const res = (r as { result: { expiresAt: number; atAbsoluteCap: boolean } }).result;
    expect(res.expiresAt).toBe(FIXED_NOW + 6 * 60 * 60_000);
    expect(res.atAbsoluteCap).toBe(false);

    // A shorter request never reduces the expiry.
    const r2 = await engine.handleRequest(sessionId, alice.extend(sessionId, 60 * 60_000));
    expect((r2 as { result: { expiresAt: number } }).result.expiresAt).toBe(FIXED_NOW + 6 * 60 * 60_000);
  });

  it("clamps an over-long extension to the absolute cap", async () => {
    const engine = newEngine(resolver);
    const { sessionId } = await engine.connect(alice.proposal().params, alice.proposal().ctx);
    const r = await engine.handleRequest(sessionId, alice.extend(sessionId, 30 * 24 * 60 * 60_000)); // +30d
    const res = (r as { result: { expiresAt: number; atAbsoluteCap: boolean } }).result;
    expect(res.expiresAt).toBe(FIXED_NOW + SEVEN_DAYS); // clamped to createdAt + absolute cap
    expect(res.atAbsoluteCap).toBe(true);
  });

  it("requires a fresh biometric to honor an extension", async () => {
    const keystore = new InMemoryKeystore({ vaultId: "vault-under-test", authResponder: (req) => req.reason !== "grant-change" });
    const engine = newEngine(resolver, keystore);
    const { sessionId } = await engine.connect(alice.proposal().params, alice.proposal().ctx);
    const r = await engine.handleRequest(sessionId, alice.extend(sessionId, 60 * 60_000));
    expect(failure(r).error.code).toBe(ErrorCode.BiometricFailed);
  });

  it("kills a session past its absolute lifetime cap", async () => {
    let t = FIXED_NOW;
    const engine = new VaultEngine({
      keystore: new InMemoryKeystore({ vaultId: "vault-under-test" }),
      storage: new InMemoryStorage(),
      resolver,
      consent: new AutoConsent(),
      clock: { now: () => t },
    });
    const { sessionId } = await engine.connect(alice.proposal().params, alice.proposal().ctx);
    t = FIXED_NOW + SEVEN_DAYS + 1; // jump past the absolute cap
    const r = await engine.handleRequest(sessionId, alice.getData(sessionId, ["/profile/x"]));
    expect(failure(r).error.code).toBe(ErrorCode.Disconnected);
  });
});

describe("VaultEngine — subscription re-auth on grant change", () => {
  let resolver: StaticIdentityResolver;
  let engine: VaultEngine;
  let alice: TestClient;

  beforeEach(() => {
    resolver = new StaticIdentityResolver();
    engine = newEngine(resolver);
    alice = new TestClient("example.com", "vault-under-test", [
      { path: "/profile", read: true, write: true },
      { path: "/other", read: true, write: true },
    ]);
    resolver.set(alice.record);
  });

  it("tears down out-of-scope subscriptions and emits permissions_changed when a grant is narrowed", async () => {
    const { sessionId } = await engine.connect(alice.proposal().params, alice.proposal().ctx);
    const notes: { method: string; params: unknown }[] = [];
    engine.setEmitter((_sid, n) => notes.push({ method: n.method, params: n.params }));

    await engine.handleRequest(sessionId, alice.subscribe(sessionId, ["/profile"]));
    await engine.handleRequest(sessionId, alice.setData(sessionId, "/profile/status", "online"));
    expect(notes.filter((n) => n.method === "vault_subscription")).toHaveLength(1);

    // Narrow the grant to drop /profile entirely.
    engine.narrowGrant(sessionId, [{ path: "/other", read: true, write: true }]);
    const changed = notes.find((n) => n.method === "vault_permissionsChanged");
    expect(changed).toBeTruthy();
    expect((changed!.params as { revokedSubscriptions: string[] }).revokedSubscriptions).toHaveLength(1);

    // A further write to /profile must NOT emit (subscription is gone + out of scope).
    const before = notes.length;
    await engine.handleRequest(sessionId, alice.setData(sessionId, "/profile/status", "away"));
    // wait a tick in case of async emit
    await Promise.resolve();
    expect(notes.length).toBe(before);
  });

  it("re-authorizes every emit: a surviving subscription drops changes now out of scope", async () => {
    const { sessionId } = await engine.connect(alice.proposal().params, alice.proposal().ctx);
    const emitted: Record<string, unknown>[] = [];
    engine.setEmitter((_sid, n) => {
      if (n.method === "vault_subscription") emitted.push((n.params as { changes: Record<string, unknown> }).changes);
    });
    // Watch both areas.
    await engine.handleRequest(sessionId, alice.subscribe(sessionId, ["/profile", "/other"]));
    // Narrow: drop READ on /other (keep write) but keep /profile — the subscription survives.
    engine.narrowGrant(sessionId, [
      { path: "/profile", read: true, write: true },
      { path: "/other", read: false, write: true },
    ]);
    // Write to /other — must NOT emit (read no longer granted).
    await engine.handleRequest(sessionId, alice.setData(sessionId, "/other/x", 1));
    expect(emitted).toHaveLength(0);
    // Write to /profile — still emits.
    await engine.handleRequest(sessionId, alice.setData(sessionId, "/profile/y", 2));
    expect(emitted).toHaveLength(1);
    expect(emitted[0]).toHaveProperty("/profile/y", 2);
  });
});

describe("VaultEngine — input hardening caps", () => {
  let resolver: StaticIdentityResolver;
  let engine: VaultEngine;
  let alice: TestClient;

  beforeEach(() => {
    resolver = new StaticIdentityResolver();
    engine = newEngine(resolver);
    alice = new TestClient("example.com", "vault-under-test", [{ path: "/profile", read: true, write: true }]);
    resolver.set(alice.record);
  });

  it("rejects an over-long JSON pointer (path length cap)", async () => {
    const { sessionId } = await engine.connect(alice.proposal().params, alice.proposal().ctx);
    const longPath = "/profile/" + "a".repeat(600); // > MAX_FIELD_PATH_LEN (512)
    const r = await engine.handleRequest(sessionId, alice.getData(sessionId, [longPath]));
    expect(failure(r).error.code).toBe(ErrorCode.QuotaExceeded);
  });

  it("rejects a write that would exceed the per-namespace document cap", async () => {
    const { sessionId } = await engine.connect(alice.proposal().params, alice.proposal().ctx);
    const big = "x".repeat(70 * 1024); // MAX_NAMESPACE_BYTES is 64 KiB
    const r = await engine.handleRequest(sessionId, alice.setData(sessionId, "/profile/blob", big));
    expect(failure(r).error.code).toBe(ErrorCode.QuotaExceeded);
  });

  it("caps the number of changes on setData too (not just patch)", async () => {
    const { sessionId } = await engine.connect(alice.proposal().params, alice.proposal().ctx);
    const entries = Array.from({ length: 200 }, (_, k) => ({ path: `/profile/k${k}`, value: k })); // > MAX_PATCH_OPS (128)
    const r = await engine.handleRequest(sessionId, alice.writeMany(sessionId, entries));
    expect(failure(r).error.code).toBe(ErrorCode.QuotaExceeded);
  });

  it("caps the number of subscription paths", async () => {
    const { sessionId } = await engine.connect(alice.proposal().params, alice.proposal().ctx);
    const paths = Array.from({ length: 200 }, () => "/profile");
    const r = await engine.handleRequest(sessionId, alice.subscribe(sessionId, paths));
    expect(failure(r).error.code).toBe(ErrorCode.QuotaExceeded);
  });

  it("rejects a write that nests deeper than MAX_JSON_DEPTH", async () => {
    const { sessionId } = await engine.connect(alice.proposal().params, alice.proposal().ctx);
    let deep: unknown = 1;
    for (let k = 0; k < 40; k++) deep = { x: deep }; // 40 > MAX_JSON_DEPTH (32)
    const r = await engine.handleRequest(sessionId, alice.setData(sessionId, "/profile/deep", deep));
    expect(failure(r).error.code).toBe(ErrorCode.QuotaExceeded);
  });

  it("stored-doc depth boundary: exactly MAX_JSON_DEPTH accepted, +1 rejected", async () => {
    const { sessionId } = await engine.connect(alice.proposal().params, alice.proposal().ctx);
    const nestArr = (n: number): unknown => (n === 0 ? [] : [nestArr(n - 1)]);
    // "/profile/deep" is 2 containers; a value of (MAX_JSON_DEPTH-2) nested arrays -> depth MAX.
    const okVal = nestArr(32 - 2 - 1); // 29 nested arrays + innermost empty = 30 containers; +2 path = 32
    const okR = await engine.handleRequest(sessionId, alice.setData(sessionId, "/profile/deep", okVal));
    expect("result" in okR).toBe(true);
    const overVal = nestArr(32 - 2); // one deeper -> depth 33
    const overR = await engine.handleRequest(sessionId, alice.setData(sessionId, "/profile/deep2", overVal));
    expect(failure(overR).error.code).toBe(ErrorCode.QuotaExceeded);
  });

  it("op-count boundary: MAX_PATCH_OPS accepted and +1 rejected, via BOTH set and patch", async () => {
    const { sessionId } = await engine.connect(alice.proposal().params, alice.proposal().ctx);
    const entries = (n: number) => Array.from({ length: n }, (_, k) => ({ path: `/profile/k${k}`, value: k }));
    expect("result" in (await engine.handleRequest(sessionId, alice.writeMany(sessionId, entries(128))))).toBe(true);
    expect(failure(await engine.handleRequest(sessionId, alice.writeMany(sessionId, entries(129)))).error.code).toBe(ErrorCode.QuotaExceeded);
    expect("result" in (await engine.handleRequest(sessionId, alice.patchMany(sessionId, entries(128))))).toBe(true);
    expect(failure(await engine.handleRequest(sessionId, alice.patchMany(sessionId, entries(129)))).error.code).toBe(ErrorCode.QuotaExceeded);
  });

  it("subscribe path-count boundary: MAX_PATHS_PER_REQUEST accepted and +1 rejected", async () => {
    const { sessionId } = await engine.connect(alice.proposal().params, alice.proposal().ctx);
    const paths = (n: number) => Array.from({ length: n }, () => "/profile");
    expect("result" in (await engine.handleRequest(sessionId, alice.subscribe(sessionId, paths(64))))).toBe(true);
    expect(failure(await engine.handleRequest(sessionId, alice.subscribe(sessionId, paths(65)))).error.code).toBe(ErrorCode.QuotaExceeded);
  });

  it("measures the pointer cap in UTF-8 bytes (multibyte can't bypass it)", async () => {
    const { sessionId } = await engine.connect(alice.proposal().params, alice.proposal().ctx);
    const path = "/" + "一".repeat(250); // 251 UTF-16 units but ~751 UTF-8 bytes > MAX_FIELD_PATH_LEN (512)
    const r = await engine.handleRequest(sessionId, alice.getData(sessionId, [path]));
    expect(failure(r).error.code).toBe(ErrorCode.QuotaExceeded);
  });

  it("a rejected over-limit write leaves the prior stored state unchanged", async () => {
    const { sessionId } = await engine.connect(alice.proposal().params, alice.proposal().ctx);
    await engine.handleRequest(sessionId, alice.setData(sessionId, "/profile/a", "keep-me"));
    const rejected = await engine.handleRequest(sessionId, alice.setData(sessionId, "/profile/blob", "x".repeat(70 * 1024)));
    expect(failure(rejected).error.code).toBe(ErrorCode.QuotaExceeded);
    const read = await engine.handleRequest(sessionId, alice.getData(sessionId, ["/profile/a"]));
    expect((read as { result: { values: Record<string, unknown> } }).result.values["/profile/a"]).toBe("keep-me");
  });
});

describe("VaultEngine — key revocation", () => {
  const STATUS = "https://example.com/.well-known/vault-status";
  let resolver: StaticIdentityResolver;
  let alice: TestClient;

  beforeEach(() => {
    resolver = new StaticIdentityResolver();
    // Alice's record declares a revocation status endpoint.
    alice = new TestClient("example.com", "vault-under-test", [{ path: "/profile", read: true, write: true }], undefined, "active", STATUS);
    resolver.set(alice.record);
  });

  it("FAILS CLOSED at connect when the record declares a statusEndpoint but no checker is configured", async () => {
    const engine = new VaultEngine({
      keystore: new InMemoryKeystore({ vaultId: "vault-under-test" }),
      storage: new InMemoryStorage(),
      resolver,
      consent: new AutoConsent(),
      // no revocation checker
      clock,
    });
    await expect(engine.connect(alice.proposal().params, alice.proposal().ctx)).rejects.toMatchObject({
      code: ErrorCode.IdentityUnverified,
    });
  });

  it("connects normally when the key is not revoked", async () => {
    const revocation = new StaticRevocationChecker();
    const engine = new VaultEngine({
      keystore: new InMemoryKeystore({ vaultId: "vault-under-test" }),
      storage: new InMemoryStorage(),
      resolver,
      consent: new AutoConsent(),
      revocation,
      clock,
    });
    const settle = await engine.connect(alice.proposal().params, alice.proposal().ctx);
    expect(settle.granted.namespace).toBe("web:example.com");
  });

  it("rejects a connect when the identity key is revoked at the status endpoint", async () => {
    const revocation = new StaticRevocationChecker();
    revocation.revoke("https://example.com/.well-known/vault-status", "k1");
    const engine = new VaultEngine({
      keystore: new InMemoryKeystore({ vaultId: "vault-under-test" }),
      storage: new InMemoryStorage(),
      resolver,
      consent: new AutoConsent(),
      revocation,
      clock,
    });
    await expect(engine.connect(alice.proposal().params, alice.proposal().ctx)).rejects.toMatchObject({
      code: ErrorCode.IdentityUnverified,
    });
  });

  it("fails closed if the revocation checker throws", async () => {
    const engine = new VaultEngine({
      keystore: new InMemoryKeystore({ vaultId: "vault-under-test" }),
      storage: new InMemoryStorage(),
      resolver,
      consent: new AutoConsent(),
      revocation: { isRevoked: async () => { throw new Error("status endpoint unreachable"); } },
      clock,
    });
    await expect(engine.connect(alice.proposal().params, alice.proposal().ctx)).rejects.toMatchObject({
      code: ErrorCode.IdentityUnverified,
    });
  });

  it("revokes data-plane access when the key is revoked AFTER connect (TOCTOU)", async () => {
    const revocation = new StaticRevocationChecker();
    const engine = new VaultEngine({
      keystore: new InMemoryKeystore({ vaultId: "vault-under-test" }),
      storage: new InMemoryStorage(),
      resolver,
      consent: new AutoConsent(),
      revocation,
      revocationRecheckMs: 0, // re-check every request
      clock,
    });
    const { sessionId } = await engine.connect(alice.proposal().params, alice.proposal().ctx);
    // Works before revocation.
    expect("result" in (await engine.handleRequest(sessionId, alice.setData(sessionId, "/profile/a", 1)))).toBe(true);
    // Revoke the key mid-session.
    revocation.revoke("https://example.com/.well-known/vault-status", "k1");
    const rRead = await engine.handleRequest(sessionId, alice.getData(sessionId, ["/profile/a"]));
    const rWrite = await engine.handleRequest(sessionId, alice.setData(sessionId, "/profile/a", 2));
    expect(failure(rRead).error.code).toBe(ErrorCode.Disconnected);
    expect(failure(rWrite).error.code).toBe(ErrorCode.Disconnected);
  });

  it("tears the session down on the data plane if revocation status can no longer be confirmed (fail closed)", async () => {
    // A checker that confirms 'not revoked' at connect, then can't be reached.
    let calls = 0;
    const flaky = {
      isRevoked: async () => {
        if (calls++ === 0) return false; // connect
        throw new Error("status endpoint unreachable"); // data plane
      },
    };
    const engine = new VaultEngine({
      keystore: new InMemoryKeystore({ vaultId: "vault-under-test" }),
      storage: new InMemoryStorage(),
      resolver,
      consent: new AutoConsent(),
      revocation: flaky,
      revocationRecheckMs: 0,
      clock,
    });
    const { sessionId } = await engine.connect(alice.proposal().params, alice.proposal().ctx);
    const r = await engine.handleRequest(sessionId, alice.getData(sessionId, ["/profile/a"]));
    expect(failure(r).error.code).toBe(ErrorCode.Disconnected);
    // The session was torn down — a follow-up request has no session.
    const r2 = await engine.handleRequest(sessionId, alice.getData(sessionId, ["/profile/a"]));
    expect(failure(r2).error.code).toBe(ErrorCode.Disconnected);
  });

  it("refuses to extend a session whose key was revoked after connect", async () => {
    const revocation = new StaticRevocationChecker();
    const engine = new VaultEngine({
      keystore: new InMemoryKeystore({ vaultId: "vault-under-test" }),
      storage: new InMemoryStorage(),
      resolver,
      consent: new AutoConsent(),
      revocation,
      revocationRecheckMs: 60_000, // NOT re-checked on normal cadence within the test window
      clock,
    });
    const { sessionId } = await engine.connect(alice.proposal().params, alice.proposal().ctx);
    revocation.revoke("https://example.com/.well-known/vault-status", "k1");
    // extend forces a fresh revocation check regardless of cadence.
    const r = await engine.handleRequest(sessionId, alice.extend(sessionId, 6 * 60 * 60_000));
    expect(failure(r).error.code).toBe(ErrorCode.Disconnected);
  });

  it("rejects a fresh delegation signed by a RETIRED key", async () => {
    const retired = new TestClient(
      "retired.example",
      "vault-under-test",
      [{ path: "/profile", read: true, write: true }],
      undefined,
      "retired",
    );
    resolver.set(retired.record);
    const engine = new VaultEngine({
      keystore: new InMemoryKeystore({ vaultId: "vault-under-test" }),
      storage: new InMemoryStorage(),
      resolver,
      consent: new AutoConsent(),
      clock,
    });
    // A retired key may not mint new authority — connect must fail.
    await expect(engine.connect(retired.proposal().params, retired.proposal().ctx)).rejects.toMatchObject({
      code: ErrorCode.IdentityUnverified,
    });
  });
});

describe("VaultEngine — biometric gating", () => {
  it("fails the connection if biometric auth is declined", async () => {
    const resolver = new StaticIdentityResolver();
    const keystore = new InMemoryKeystore({
      vaultId: "vault-under-test",
      authResponder: (req) => req.reason !== "connect",
    });
    const engine = newEngine(resolver, keystore);
    const alice = new TestClient("example.com", "vault-under-test", [{ path: "/profile", read: true, write: true }]);
    resolver.set(alice.record);
    await expect(engine.connect(alice.proposal().params, alice.proposal().ctx)).rejects.toMatchObject({
      code: ErrorCode.BiometricFailed,
    });
  });

  it("forces biometric on sensitive reads", async () => {
    const resolver = new StaticIdentityResolver();
    const authSpy = vi.fn((req: { reason: string }) => true);
    const keystore = new InMemoryKeystore({ vaultId: "vault-under-test", authResponder: authSpy });
    const engine = newEngine(resolver, keystore);
    const alice = new TestClient("example.com", "vault-under-test", [
      { path: "/secret", read: true, write: true, sensitive: true },
    ]);
    resolver.set(alice.record);
    const { sessionId } = await engine.connect(alice.proposal().params, alice.proposal().ctx);
    authSpy.mockClear();
    await engine.handleRequest(sessionId, alice.setData(sessionId, "/secret/token", "t")); // write first (creates it)
    await engine.handleRequest(sessionId, alice.getData(sessionId, ["/secret/token"]));
    const reasons = authSpy.mock.calls.map((c) => c[0].reason);
    expect(reasons).toContain("sensitive-read");
  });
});
