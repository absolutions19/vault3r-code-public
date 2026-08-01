/**
 * End-to-end: a real target-app SDK talks to a real vault runtime through a real
 * relay WebSocket. This is the walking skeleton — pair → connect → write → read →
 * subscribe — plus the headline security property proven across the wire: two
 * different sites get isolated namespaces and cannot reach each other's data.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { RelayServer } from "@vault/relay";
import { VaultEngine, VaultNode, InMemoryKeystore, InMemoryStorage, StaticIdentityResolver, AutoConsent } from "@vault/vault-core";
import { VaultClient, RelayTransport, LocalDelegationSigner } from "@vault/sdk";
import { ed25519Generate, signIdentityRecord, toBase64Url } from "@vault/crypto-core";
import { PROTOCOL_VERSION, ErrorCode, type RequestedScope, type VaultIdentityRecord } from "@vault/protocol";

const VAULT_ID = "vault-e2e";

interface App {
  domain: string;
  record: VaultIdentityRecord;
  delegationSigner: LocalDelegationSigner;
}

function makeApp(domain: string, methods: string[]): App {
  const key = ed25519Generate();
  const record = signIdentityRecord(
    {
      schema: "vault-identity/1",
      domain,
      namespaceGranularity: "registrable-domain",
      keys: [{ kid: "k1", alg: "Ed25519", publicKey: toBase64Url(key.publicKey), created: "2026-01-01T00:00:00Z", status: "active" }],
      methods,
      protocolVersions: [PROTOCOL_VERSION],
    },
    "k1",
    key.privateKey,
  );
  const delegationSigner = new LocalDelegationSigner({ domain, kid: "k1", domainSeed: key.privateKey, assertedAccount: `user@${domain}` });
  return { domain, record, delegationSigner };
}

const ALL_METHODS = [
  "vault_getData",
  "vault_setData",
  "vault_patchData",
  "vault_subscribe",
  "vault_unsubscribe",
  "vault_revoke",
  "vault_getPermissions",
];

const fullScope = (): RequestedScope[] => [
  { methods: ALL_METHODS, fields: [{ path: "/profile", read: true, write: true }] },
];

describe("VAULT end-to-end over the relay", () => {
  let relay: RelayServer;
  let relayUrl: string;
  let resolver: StaticIdentityResolver;
  let engine: VaultEngine;
  let node: VaultNode;
  const openClients: VaultClient[] = [];

  beforeEach(async () => {
    relay = new RelayServer();
    const port = await relay.listen(0);
    relayUrl = `ws://127.0.0.1:${port}`;
    resolver = new StaticIdentityResolver();
    engine = new VaultEngine({
      keystore: new InMemoryKeystore({ vaultId: VAULT_ID }),
      storage: new InMemoryStorage(),
      resolver,
      consent: new AutoConsent(),
    });
    node = new VaultNode(engine, new RelayTransport(relayUrl));
  });

  afterEach(async () => {
    for (const c of openClients.splice(0)) await c.disconnect().catch(() => {});
    await relay.close();
  });

  function newClient(app: App): VaultClient {
    const client = new VaultClient({
      domain: app.domain,
      relayUrl,
      delegationSigner: app.delegationSigner,
      transport: new RelayTransport(relayUrl),
      appMetadata: { name: app.domain },
      onDisplayUri: (uri) => void node.pair(uri), // the phone "scans" the QR
    });
    openClients.push(client);
    return client;
  }

  it("pairs, connects, writes and reads back a value", async () => {
    const app = makeApp("example.com", ALL_METHODS);
    resolver.set(app.record);
    const client = newClient(app);

    const result = await client.connect(fullScope());
    expect(result.namespace).toBe("web:example.com");

    await client.set("/profile/name", "Alice");
    const values = await client.get("/profile/name");
    expect(values["/profile/name"]).toBe("Alice");
  });

  it("extends the session over the wire (SDK → relay → vault)", async () => {
    const app = makeApp("example.com", ALL_METHODS);
    resolver.set(app.record);
    const client = newClient(app);
    const conn = await client.connect(fullScope());
    const ext = await client.extendSession(60 * 60_000);
    expect(ext.expiresAt).toBeGreaterThan(conn.grant.expiresAt - 1);
    expect(typeof ext.atAbsoluteCap).toBe("boolean");
  });

  it("delivers a live subscription notification on write", async () => {
    const app = makeApp("example.com", ALL_METHODS);
    resolver.set(app.record);
    const client = newClient(app);
    await client.connect(fullScope());

    const notes: Record<string, unknown>[] = [];
    await client.subscribe(["/profile"], (changes) => notes.push(changes));
    await client.set("/profile/status", "online");

    // allow the notification to round-trip through the relay
    await new Promise((r) => setTimeout(r, 150));
    expect(notes.length).toBeGreaterThanOrEqual(1);
    expect(notes[0]?.["/profile/status"]).toBe("online");
  });

  it("isolates two different sites' data across the wire", async () => {
    const alice = makeApp("alice.com", ALL_METHODS);
    const evil = makeApp("evil.com", ALL_METHODS);
    resolver.set(alice.record);
    resolver.set(evil.record);

    const aClient = newClient(alice);
    const eClient = newClient(evil);
    const aRes = await aClient.connect(fullScope());
    const eRes = await eClient.connect(fullScope());
    expect(aRes.namespace).toBe("web:alice.com");
    expect(eRes.namespace).toBe("web:evil.com");

    await aClient.set("/profile/secret", "alices-only");
    const evilView = await eClient.get("/profile/secret");
    expect(evilView["/profile/secret"]).toBeNull(); // evil sees its own empty namespace
  });

  it("rejects connecting from a domain with no resolvable identity record", async () => {
    const stranger = makeApp("stranger.example", ALL_METHODS);
    // deliberately NOT added to the resolver
    const client = newClient(stranger);
    await expect(client.connect(fullScope())).rejects.toMatchObject({ code: ErrorCode.IdentityUnverified });
  });

  it("enforces field scope end-to-end (read outside grant fails)", async () => {
    const app = makeApp("scoped.com", ALL_METHODS);
    resolver.set(app.record);
    const client = new VaultClient({
      domain: app.domain,
      relayUrl,
      delegationSigner: app.delegationSigner,
      transport: new RelayTransport(relayUrl),
      onDisplayUri: (uri) => void node.pair(uri),
    });
    openClients.push(client);
    await client.connect([{ methods: ALL_METHODS, fields: [{ path: "/profile", read: true, write: true }] }]);
    await expect(client.get("/billing/card")).rejects.toMatchObject({ code: ErrorCode.FieldOutOfScope });
  });
});
