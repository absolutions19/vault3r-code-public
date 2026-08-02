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
import { deriveNamespace } from "@vault/crypto-core";
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

  it("localRevoke ends the session", async () => {
    const r = await engine.connectLocal({ origin: "https://bye.example", appMetadata: {}, requestedScopes: scopes() });
    engine.localRevoke(r.sessionId);
    await expectCode(engine.localGet(r.sessionId, ["/profile"]), "Disconnected");
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
    engine.localUnsubscribe(r.sessionId, subscriptionId);
    await engine.localSet(r.sessionId, { "/profile/name": "silent" });
    expect(received.length).toBe(1);
  });
});
