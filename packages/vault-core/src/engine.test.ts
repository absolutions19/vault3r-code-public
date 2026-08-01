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
import { InMemoryKeystore, InMemoryStorage, StaticIdentityResolver, AutoConsent } from "./in-memory.js";

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
            status: "active",
          },
        ],
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

  private signed<P extends "VaultRead" | "VaultWrite" | "VaultPatch" | "VaultRevoke">(
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
