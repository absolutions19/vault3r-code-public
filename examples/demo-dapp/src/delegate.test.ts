import { afterEach, describe, expect, it } from "vitest";
import type { AddressInfo } from "node:net";
import { DelegateService } from "./delegate-service.js";
import { createDelegateServer } from "./http-server.js";
import { ed25519Generate, ed25519Sign, toBase64Url, utf8ToBytes, verifyDelegation } from "@vault/crypto-core";
import { RelayServer } from "@vault/relay";
import { VaultEngine, VaultNode, InMemoryKeystore, InMemoryStorage, StaticIdentityResolver, AutoConsent } from "@vault/vault-core";
import { VaultClient, RelayTransport, HttpDelegationSigner } from "@vault/sdk";
import type { MintRequest } from "./delegate-service.js";

const ORIGIN = "https://demo.example";
const DOMAIN = "demo.example";
const ALLOWED = [
  {
    methods: ["vault_getData", "vault_setData", "vault_subscribe", "vault_unsubscribe", "vault_revoke", "vault_getPermissions"],
    fields: [{ path: "/profile", read: true, write: true }],
  },
];

function newService() {
  const domainKey = ed25519Generate();
  const service = new DelegateService({
    domain: DOMAIN,
    kid: "k1",
    domainSeed: domainKey.privateKey,
    allowedScopes: ALLOWED,
    originAllowlist: [ORIGIN],
  });
  return { service, domainKey };
}

/** A well-formed PoP mint request for a fresh d_sess. */
function goodRequest(challenge: string, dsess = ed25519Generate()): MintRequest {
  return {
    sessionPublicKey: toBase64Url(dsess.publicKey),
    scopes: ALLOWED,
    pairingChallenge: "42815937",
    vaultId: "vault-x",
    challenge,
    popSig: toBase64Url(ed25519Sign(utf8ToBytes(challenge), dsess.privateKey)),
  };
}

const ctx = (over: Partial<{ origin: string; csrfToken: string; account: string }> = {}) => ({
  origin: ORIGIN,
  csrfToken: "",
  account: "user@demo.example",
  ...over,
});

describe("DelegateService — security gates", () => {
  it("mints a valid delegation when all gates pass", () => {
    const { service, domainKey } = newService();
    const { challenge, csrfToken } = service.issueChallenge("sess1");
    const req = goodRequest(challenge);
    const del = service.mintDelegation("sess1", req, ctx({ csrfToken }));
    const record = service.wellKnownRecord();
    expect(verifyDelegation(del, record).ok).toBe(true);
    expect(del.assertedAccount).toBe("user@demo.example");
    expect(domainKey).toBeTruthy();
  });

  it("rejects a disallowed Origin (cross-site POST)", () => {
    const { service } = newService();
    const { challenge, csrfToken } = service.issueChallenge("sess1");
    expect(() => service.mintDelegation("sess1", goodRequest(challenge), ctx({ csrfToken, origin: "https://evil.com" }))).toThrow(/origin/i);
  });

  it("rejects a missing/wrong CSRF token", () => {
    const { service } = newService();
    const { challenge } = service.issueChallenge("sess1");
    expect(() => service.mintDelegation("sess1", goodRequest(challenge), ctx({ csrfToken: "wrong" }))).toThrow(/csrf/i);
  });

  it("rejects a failed proof-of-possession (key the caller does not control)", () => {
    const { service } = newService();
    const { challenge, csrfToken } = service.issueChallenge("sess1");
    const attacker = ed25519Generate();
    const victim = ed25519Generate();
    const req: MintRequest = {
      ...goodRequest(challenge, victim),
      sessionPublicKey: toBase64Url(attacker.publicKey), // claim attacker's key, sign with victim's
    };
    expect(() => service.mintDelegation("sess1", req, ctx({ csrfToken }))).toThrow(/possession/i);
  });

  it("rejects a replayed (single-use) challenge", () => {
    const { service } = newService();
    const { challenge, csrfToken } = service.issueChallenge("sess1");
    service.mintDelegation("sess1", goodRequest(challenge), ctx({ csrfToken }));
    expect(() => service.mintDelegation("sess1", goodRequest(challenge), ctx({ csrfToken }))).toThrow(/challenge/i);
  });

  it("clamps over-requested scopes to the static allow-list", () => {
    const { service } = newService();
    const { challenge, csrfToken } = service.issueChallenge("sess1");
    const req = goodRequest(challenge);
    req.scopes = [{ methods: ["vault_getData", "vault_setData"], fields: [{ path: "/billing", read: true, write: true }] }];
    const del = service.mintDelegation("sess1", req, ctx({ csrfToken }));
    // /billing is outside the ceiling → dropped entirely.
    expect(del.scopes[0]!.fields).toEqual([]);
  });
});

describe("Full stack with the HTTP delegation backend + PoP", () => {
  let relay: RelayServer;
  let backend: ReturnType<typeof createDelegateServer>;
  let client: VaultClient | undefined;

  afterEach(async () => {
    if (client) await client.disconnect().catch(() => {});
    backend?.close();
    await relay?.close();
  });

  it("connects, writes and reads using a backend-minted delegation", async () => {
    const domainKey = ed25519Generate();
    const service = new DelegateService({
      domain: DOMAIN,
      kid: "k1",
      domainSeed: domainKey.privateKey,
      allowedScopes: ALLOWED,
      originAllowlist: [ORIGIN],
    });

    // Backend HTTP server.
    backend = createDelegateServer({ service, accountDomain: DOMAIN });
    const backendPort = await new Promise<number>((resolve) => backend.listen(0, () => resolve((backend.address() as AddressInfo).port)));
    const base = `http://127.0.0.1:${backendPort}`;

    // Relay + vault runtime. The vault resolves identity from the backend's record.
    relay = new RelayServer();
    const relayPort = await relay.listen(0);
    const resolver = new StaticIdentityResolver();
    resolver.set(service.wellKnownRecord());
    const engine = new VaultEngine({
      keystore: new InMemoryKeystore({ vaultId: "vault-http" }),
      storage: new InMemoryStorage(),
      resolver,
      consent: new AutoConsent(),
    });
    const node = new VaultNode(engine, new RelayTransport(`ws://127.0.0.1:${relayPort}`));

    // Cookie jar so the SDK's challenge + mint calls share a first-party session.
    let cookie = "";
    const jarFetch: typeof fetch = async (input, init) => {
      const headers = new Headers(init?.headers);
      if (cookie) headers.set("cookie", cookie);
      const res = await fetch(input, { ...init, headers });
      const sc = res.headers.get("set-cookie");
      if (sc) cookie = sc.split(";")[0]!;
      return res;
    };

    client = new VaultClient({
      domain: DOMAIN,
      relayUrl: `ws://127.0.0.1:${relayPort}`,
      transport: new RelayTransport(`ws://127.0.0.1:${relayPort}`),
      delegationSigner: new HttpDelegationSigner({
        challengeUrl: `${base}/vault/delegate/challenge`,
        mintUrl: `${base}/vault/delegate`,
        origin: ORIGIN,
        fetchImpl: jarFetch,
      }),
      onDisplayUri: (uri) => void node.pair(uri),
    });

    const res = await client.connect(ALLOWED);
    expect(res.namespace).toBe("web:demo.example");
    await client.set("/profile/name", "Backed By PoP");
    const values = await client.get("/profile/name");
    expect(values["/profile/name"]).toBe("Backed By PoP");
  });
});
