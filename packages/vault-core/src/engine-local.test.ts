/**
 * Trusted in-process host mode (browser Option B).
 *
 * These tests exercise `connectLocal` + the `local*` data plane, which skip the
 * relay / identity-proof / delegation / per-request signature (the host process
 * is the trust boundary) while still enforcing every property that protects the
 * user's data: per-origin namespace isolation, explicit consent, per-field
 * grants, method gating, input caps, and subscriptions.
 */

import { beforeEach, describe, expect, it } from "vitest";
import { deriveNamespace, storageKeyForNamespace } from "@vault/crypto-core";
import {
  Method,
  MAX_PATHS_PER_REQUEST,
  MAX_PATCH_OPS,
  type RequestedScope,
} from "@vault/protocol";
import { VaultEngine, type LocalChange } from "./engine.js";
import { InMemoryKeystore, InMemoryStorage, StaticIdentityResolver, AutoConsent } from "./in-memory.js";

const FIXED_NOW = 1_760_000_000_000;
const clock = { now: () => FIXED_NOW };

const ALL_METHODS = [
  Method.GetData,
  Method.SetData,
  Method.PatchData,
  Method.Subscribe,
  Method.Unsubscribe,
  Method.Revoke,
  Method.GetPermissions,
];

/** Full-access scopes over a small field tree. */
function scopes(): RequestedScope[] {
  return [
    {
      methods: ALL_METHODS,
      fields: [
        { path: "/profile", read: true, write: true },
        { path: "/readonly", read: true, write: false },
        { path: "/secret", read: true, write: true, sensitive: true },
      ],
    },
  ];
}

function newEngine(consent = new AutoConsent(), keystore = new InMemoryKeystore({ vaultId: "vault-local" })) {
  return new VaultEngine({
    keystore,
    storage: new InMemoryStorage(),
    resolver: new StaticIdentityResolver(),
    consent,
    clock,
  });
}

/** Assert a promise rejects with a VaultError of a specific code name. */
async function expectCode(p: Promise<unknown>, codeName: string): Promise<void> {
  const err = await p.then(
    () => {
      throw new Error(`expected rejection with ${codeName}, but it resolved`);
    },
    (e) => e as { codeName?: string },
  );
  expect(err.codeName).toBe(codeName);
}

describe("VaultEngine — trusted in-process (local) mode", () => {
  let engine: VaultEngine;

  beforeEach(() => {
    engine = newEngine();
  });

  it("derives the same web namespace as the relay path for http(s) origins", async () => {
    const r = await engine.connectLocal({
      origin: "https://app.example.com",
      appMetadata: { name: "Example App" },
      requestedScopes: scopes(),
    });
    // A site reached through the browser lands on the exact namespace it would
    // over the relay, so its data is the same across both transports.
    expect(r.namespace).toBe(deriveNamespace("example.com", "registrable-domain").namespace);
    expect(r.namespace).toBe("web:example.com");
    expect(r.grant.namespace).toBe("web:example.com");
    expect(r.grant.verified).toBe(true);
  });

  it("gives decentralized-web origins a distinct, collision-proof namespace", async () => {
    const r = await engine.connectLocal({
      origin: "bzz://deadbeefcafe",
      appMetadata: { name: "Swarm dApp" },
      requestedScopes: scopes(),
    });
    expect(r.namespace.startsWith("web:dweb:bzz:")).toBe(true);
    // The `dweb:` infix carries a colon an eTLD+1 never can, so it can never
    // collide with an http(s) registrable-domain namespace.
    expect(r.namespace).not.toBe("web:example.com");
  });

  it("keeps sites isolated: one origin cannot read another's data", async () => {
    const open: RequestedScope[] = [{ methods: ALL_METHODS, fields: [{ path: "/profile", read: true, write: true }] }];
    const a = await engine.connectLocal({ origin: "https://a.example", appMetadata: {}, requestedScopes: open });
    const b = await engine.connectLocal({ origin: "https://b.example", appMetadata: {}, requestedScopes: open });
    expect(a.namespace).not.toBe(b.namespace);

    await engine.localSet(a.sessionId, { "/profile/name": "alice" });
    const ra = await engine.localGet(a.sessionId, ["/profile/name"]);
    expect(ra.values["/profile/name"]).toBe("alice");

    // b addresses a different namespace/storage key entirely -> sees nothing.
    const rb = await engine.localGet(b.sessionId, ["/profile/name"]);
    expect(rb.values["/profile/name"]).toBe(null);
  });

  it("round-trips a write and read within one site", async () => {
    const r = await engine.connectLocal({ origin: "https://site.example", appMetadata: {}, requestedScopes: scopes() });
    const w = await engine.localSet(r.sessionId, { "/profile/handle": "@vault" });
    expect(w.applied).toBe(true);
    const g = await engine.localGet(r.sessionId, ["/profile/handle"]);
    expect(g.values["/profile/handle"]).toBe("@vault");
    expect(g.version).toBe(w.version);
  });

  it("rejects when the user declines consent", async () => {
    const declining = newEngine(new AutoConsent(() => ({ approved: false, reason: "user declined" })));
    await expectCode(
      declining.connectLocal({ origin: "https://nope.example", appMetadata: {}, requestedScopes: scopes() }),
      "UserRejected",
    );
  });

  it("enforces per-field grants (read-only + out-of-scope)", async () => {
    const r = await engine.connectLocal({ origin: "https://fields.example", appMetadata: {}, requestedScopes: scopes() });
    // /readonly is granted read but not write.
    await expectCode(engine.localSet(r.sessionId, { "/readonly": 1 }), "WriteForbidden");
    // /billing was never granted at all.
    await expectCode(engine.localGet(r.sessionId, ["/billing"]), "FieldOutOfScope");
    await expectCode(engine.localSet(r.sessionId, { "/billing": 1 }), "FieldOutOfScope");
  });

  it("enforces the granted method set", async () => {
    // Consent narrows the grant to read-only.
    const readOnly = newEngine(new AutoConsent(() => ({ approved: true, grantedMethods: [Method.GetData] })));
    const r = await readOnly.connectLocal({ origin: "https://ro.example", appMetadata: {}, requestedScopes: scopes() });
    await expectCode(readOnly.localSet(r.sessionId, { "/profile/x": 1 }), "Unauthorized");
    // Reads still work.
    const g = await readOnly.localGet(r.sessionId, ["/profile/x"]);
    expect(g.values["/profile/x"]).toBe(null);
  });

  it("enforces input caps (too many paths / too many patch ops)", async () => {
    const r = await engine.connectLocal({ origin: "https://caps.example", appMetadata: {}, requestedScopes: scopes() });
    const tooManyPaths = Array.from({ length: MAX_PATHS_PER_REQUEST + 1 }, (_, i) => `/profile/p${i}`);
    await expectCode(engine.localGet(r.sessionId, tooManyPaths), "QuotaExceeded");

    const tooManyOps: LocalChange[] = Array.from({ length: MAX_PATCH_OPS + 1 }, (_, i) => ({
      op: "replace",
      path: `/profile/p${i}`,
      value: i,
    }));
    await expectCode(engine.localPatch(r.sessionId, tooManyOps), "QuotaExceeded");
  });

  it("does not accept a trusted session on the signed request path", async () => {
    const r = await engine.connectLocal({ origin: "https://cross.example", appMetadata: {}, requestedScopes: scopes() });
    // A local session has no delegated signing key, so any signed request fails.
    const res = await engine.handleRequest(r.sessionId, {
      jsonrpc: "2.0",
      id: "1",
      method: Method.GetData,
      params: { paths: ["/profile"] },
    } as never);
    expect("error" in res).toBe(true);
  });

  it("localRevoke ends the session and every op then fails closed", async () => {
    const r = await engine.connectLocal({ origin: "https://bye.example", appMetadata: {}, requestedScopes: scopes() });
    await engine.localRevoke(r.sessionId);
    await expectCode(engine.localGet(r.sessionId, ["/profile"]), "Disconnected");
    await expectCode(engine.localSet(r.sessionId, { "/profile/x": 1 }), "Disconnected");
    await expectCode(engine.localPatch(r.sessionId, [{ op: "replace", path: "/profile/x", value: 1 }]), "Disconnected");
    await expectCode(engine.localSubscribe(r.sessionId, ["/profile"]), "Disconnected");
    await expectCode(engine.localGetPermissions(r.sessionId), "Disconnected");
  });

  it("gates localGetPermissions on the GetData/GetPermissions grant like the signed path", async () => {
    // Grant excludes GetPermissions.
    const narrowed = newEngine(
      new AutoConsent(() => ({ approved: true, grantedMethods: [Method.GetData, Method.SetData] })),
    );
    const r = await narrowed.connectLocal({ origin: "https://gp.example", appMetadata: {}, requestedScopes: scopes() });
    await expectCode(narrowed.localGetPermissions(r.sessionId), "Unauthorized");

    // When granted, it returns the grant.
    const full = await engine.connectLocal({ origin: "https://gp2.example", appMetadata: {}, requestedScopes: scopes() });
    const perms = await engine.localGetPermissions(full.sessionId);
    expect(perms.grant?.namespace).toBe("web:gp2.example");
  });

  it("always allows a session to revoke itself, even without the Revoke method", async () => {
    // Read-only grant: no Revoke method. Self-revoke still works (mirrors signed skipMethodCheck).
    const ro = newEngine(new AutoConsent(() => ({ approved: true, grantedMethods: [Method.GetData] })));
    const r = await ro.connectLocal({ origin: "https://selfrevoke.example", appMetadata: {}, requestedScopes: scopes() });
    await expect(ro.localRevoke(r.sessionId)).resolves.toEqual({ ok: true });
    await expectCode(ro.localGet(r.sessionId, ["/profile"]), "Disconnected");
  });

  it("fails closed once a local session has expired", async () => {
    let now = FIXED_NOW;
    const mutable = new VaultEngine({
      keystore: new InMemoryKeystore({ vaultId: "vault-local" }),
      storage: new InMemoryStorage(),
      resolver: new StaticIdentityResolver(),
      consent: new AutoConsent(),
      clock: { now: () => now },
      sessionTtlMs: 1_000,
    });
    const r = await mutable.connectLocal({ origin: "https://ttl.example", appMetadata: {}, requestedScopes: scopes() });
    // Within TTL: fine.
    await expect(mutable.localGet(r.sessionId, ["/profile"])).resolves.toBeTruthy();
    // Past expiry: requireSession tears it down.
    now = FIXED_NOW + 2_000;
    await expectCode(mutable.localGet(r.sessionId, ["/profile"]), "Disconnected");
  });

  it("fails closed if the keystore cannot unlock", async () => {
    const locked = newEngine(
      new AutoConsent(),
      new InMemoryKeystore({ vaultId: "vault-local", startsLocked: true, authResponder: () => false }),
    );
    await expectCode(
      locked.connectLocal({ origin: "https://locked.example", appMetadata: {}, requestedScopes: scopes() }),
      "VaultLocked",
    );
  });

  it("delivers subscription updates to a trusted subscriber on write", async () => {
    const received: { sessionId: string; method: string; params: unknown }[] = [];
    engine.setEmitter((sessionId, note) => {
      received.push({ sessionId, method: note.method, params: (note as { params: unknown }).params });
    });
    const r = await engine.connectLocal({ origin: "https://live.example", appMetadata: {}, requestedScopes: scopes() });
    const { subscriptionId } = await engine.localSubscribe(r.sessionId, ["/profile"]);
    await engine.localSet(r.sessionId, { "/profile/name": "live" });

    expect(received.length).toBe(1);
    expect(received[0]!.sessionId).toBe(r.sessionId);
    expect(received[0]!.method).toBe(Method.Subscription);
    const params = received[0]!.params as { subscriptionId: string; changes: Record<string, unknown> };
    expect(params.subscriptionId).toBe(subscriptionId);
    expect(params.changes["/profile/name"]).toBe("live");

    // After unsubscribe, no further deliveries.
    await engine.localUnsubscribe(r.sessionId, subscriptionId);
    await engine.localSet(r.sessionId, { "/profile/name": "silent" });
    expect(received.length).toBe(1);
  });
});

describe("VaultEngine — owner/admin plane (vault management UI)", () => {
  let ks: InMemoryKeystore;
  let engine: VaultEngine;

  beforeEach(() => {
    ks = new InMemoryKeystore({ vaultId: "vault-local" });
    engine = new VaultEngine({
      keystore: ks,
      storage: new InMemoryStorage(),
      resolver: new StaticIdentityResolver(),
      consent: new AutoConsent(),
      clock,
    });
  });

  async function seed(origin: string, values: Record<string, unknown>) {
    const r = await engine.connectLocal({ origin, appMetadata: {}, requestedScopes: scopes() });
    await engine.localSet(r.sessionId, values);
    return { sessionId: r.sessionId, namespace: r.namespace, storageKey: storageKeyForNamespace(r.namespace) };
  }

  it("adminReadPartition returns the owner's whole decrypted document", async () => {
    const p = await seed("https://owned.example", { "/profile/name": "alice", "/profile/city": "NYC" });
    const doc = (await engine.adminReadPartition(p.storageKey)) as Record<string, unknown>;
    expect(doc).toEqual({ profile: { name: "alice", city: "NYC" } });
  });

  it("adminReadPartition is isolated per storage key", async () => {
    const a = await seed("https://a.example", { "/profile/name": "A" });
    const b = await seed("https://b.example", { "/profile/name": "B" });
    expect(await engine.adminReadPartition(a.storageKey)).toEqual({ profile: { name: "A" } });
    expect(await engine.adminReadPartition(b.storageKey)).toEqual({ profile: { name: "B" } });
  });

  it("adminReadPartition fails closed when the vault is locked", async () => {
    const p = await seed("https://lock.example", { "/profile/name": "x" });
    ks.lock();
    await expectCode(engine.adminReadPartition(p.storageKey), "VaultLocked");
  });

  it("adminDeletePartition drops the data, clears the manifest (no rollback error), and allows a clean re-create", async () => {
    const p = await seed("https://del.example", { "/profile/name": "gone" });
    await engine.adminDeletePartition(p.storageKey);
    // Anti-rollback would throw KeyInvalidated if the manifest still expected the blob;
    // a clean read returns an empty doc instead.
    expect(await engine.adminReadPartition(p.storageKey)).toEqual({});
    // And the namespace can be used again from scratch.
    const r2 = await engine.connectLocal({ origin: "https://del.example", appMetadata: {}, requestedScopes: scopes() });
    await engine.localSet(r2.sessionId, { "/profile/name": "fresh" });
    expect(await engine.adminReadPartition(p.storageKey)).toEqual({ profile: { name: "fresh" } });
  });

  it("adminDeletePartition tears down live sessions for that namespace", async () => {
    const p = await seed("https://teardown.example", { "/profile/name": "x" });
    await engine.adminDeletePartition(p.storageKey);
    await expectCode(engine.localGet(p.sessionId, ["/profile/name"]), "Disconnected");
  });
});

describe("VaultEngine — concurrent writes", () => {
  /** Read/write on every path the tests below touch (a grant on `/` is not a wildcard). */
  const paths = ["/profile", "/prefs", "/v", ...Array.from({ length: 8 }, (_, i) => `/k${i}`)];
  const open: RequestedScope[] = [{ methods: ALL_METHODS, fields: paths.map((path) => ({ path, read: true, write: true })) }];

  /**
   * A storage adapter that yields to the event loop on every operation, so two
   * in-flight writers genuinely interleave the way real file I/O does. Without
   * the queue, both load version N and the second save discards the first.
   */
  class SlowStorage extends InMemoryStorage {
    override async get(key: string) {
      await new Promise((r) => setTimeout(r, 1));
      return super.get(key);
    }
    override async put(key: string, value: Uint8Array) {
      await new Promise((r) => setTimeout(r, 1));
      return super.put(key, value);
    }
  }

  function slowEngine() {
    return new VaultEngine({
      keystore: new InMemoryKeystore({ vaultId: "vault-race" }),
      storage: new SlowStorage(),
      resolver: new StaticIdentityResolver(),
      consent: new AutoConsent(),
      clock,
    });
  }

  it("two sessions writing different paths of one namespace lose nothing", async () => {
    const engine = slowEngine();
    // Two tabs on the same origin: two sessions, one namespace.
    const tab1 = await engine.connectLocal({ origin: "https://race.example", appMetadata: {}, requestedScopes: open });
    const tab2 = await engine.connectLocal({ origin: "https://race.example", appMetadata: {}, requestedScopes: open });

    await Promise.all([
      engine.localSet(tab1.sessionId, { "/profile": { name: "alice" } }),
      engine.localSet(tab2.sessionId, { "/prefs": { theme: "dark" } }),
    ]);

    const g = await engine.localGet(tab1.sessionId, ["/profile", "/prefs"]);
    expect(g.values["/profile"]).toEqual({ name: "alice" });
    expect(g.values["/prefs"]).toEqual({ theme: "dark" });
    expect(g.version).toBe("etag:2");
  });

  it("a burst of writes from one session all land, in order", async () => {
    const engine = slowEngine();
    const s = await engine.connectLocal({ origin: "https://burst.example", appMetadata: {}, requestedScopes: open });

    await Promise.all(Array.from({ length: 8 }, (_, i) => engine.localSet(s.sessionId, { [`/k${i}`]: i })));

    const g = await engine.localGet(s.sessionId, Array.from({ length: 8 }, (_, i) => `/k${i}`));
    for (let i = 0; i < 8; i++) expect(g.values[`/k${i}`]).toBe(i);
    expect(g.version).toBe("etag:8");
  });

  it("writes to different namespaces do not drop each other's manifest entry", async () => {
    const engine = slowEngine();
    const a = await engine.connectLocal({ origin: "https://a.example", appMetadata: {}, requestedScopes: open });
    const b = await engine.connectLocal({ origin: "https://b.example", appMetadata: {}, requestedScopes: open });

    await Promise.all([
      engine.localSet(a.sessionId, { "/v": "a" }),
      engine.localSet(b.sessionId, { "/v": "b" }),
    ]);
    // A second round exposes a lost manifest entry: the anti-rollback check
    // compares each blob's version to the manifest's expectation.
    await Promise.all([
      engine.localSet(a.sessionId, { "/v": "a2" }),
      engine.localSet(b.sessionId, { "/v": "b2" }),
    ]);

    expect((await engine.localGet(a.sessionId, ["/v"])).values["/v"]).toBe("a2");
    expect((await engine.localGet(b.sessionId, ["/v"])).values["/v"]).toBe("b2");
  });

  it("a failed write does not wedge the queue for the next one", async () => {
    const engine = slowEngine();
    const s = await engine.connectLocal({ origin: "https://wedge.example", appMetadata: {}, requestedScopes: open });
    await engine.localSet(s.sessionId, { "/v": 1 });

    await expectCode(engine.localSet(s.sessionId, { "/v": 2 }, "etag:99"), "VersionConflict");
    const w = await engine.localSet(s.sessionId, { "/v": 3 });
    expect(w.version).toBe("etag:2");
  });
});
