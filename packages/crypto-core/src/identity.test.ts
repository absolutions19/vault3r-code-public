import { describe, expect, it } from "vitest";
import { ed25519Generate } from "./primitives.js";
import { toBase64Url } from "./encoding.js";
import {
  signIdentityRecord,
  verifyIdentityRecordProof,
  signDelegation,
  verifyDelegation,
} from "./identity.js";
import {
  deriveNamespace,
  deriveOriginNamespace,
  normalizeHost,
  registrableDomain,
  isAuthoritativeForHost,
  detectHomograph,
  isMixedScript,
  confusableSkeleton,
  NamespaceError,
} from "./namespace.js";
import type { SessionDelegation, VaultIdentityRecord } from "@vault/protocol";

const domainKey = ed25519Generate();

function makeRecord(domain: string): VaultIdentityRecord {
  return signIdentityRecord(
    {
      schema: "vault-identity/1",
      domain,
      namespaceGranularity: "registrable-domain",
      keys: [
        {
          kid: "k1",
          alg: "Ed25519",
          publicKey: toBase64Url(domainKey.publicKey),
          created: "2026-01-01T00:00:00Z",
          status: "active",
        },
      ],
      methods: ["vault_getData", "vault_setData"],
      protocolVersions: ["1"],
    },
    "k1",
    domainKey.privateKey,
  );
}

describe("namespace derivation", () => {
  it("derives web:<registrable-domain> by default", () => {
    expect(deriveNamespace("app.example.com", "registrable-domain").namespace).toBe("web:example.com");
    expect(deriveNamespace("example.com", "registrable-domain").canonicalKey).toBe("example.com");
  });
  it("derives web:<host> at host granularity (multi-tenant isolation)", () => {
    expect(deriveNamespace("tenant1.saas.com", "host").namespace).toBe("web:tenant1.saas.com");
    expect(deriveNamespace("tenant2.saas.com", "host").namespace).toBe("web:tenant2.saas.com");
  });
  it("produces a distinct deterministic storage key per namespace", () => {
    const a = deriveNamespace("a.com", "registrable-domain");
    const b = deriveNamespace("b.com", "registrable-domain");
    expect(a.storageKey).not.toBe(b.storageKey);
    expect(deriveNamespace("a.com", "registrable-domain").storageKey).toBe(a.storageKey);
  });
  it("normalizes IDN to punycode A-label", () => {
    // bücher.example -> xn--bcher-kva.example
    expect(normalizeHost("bücher.example")).toContain("xn--");
  });
  it("rejects IP literals and bare hosts", () => {
    expect(() => normalizeHost("127.0.0.1")).toThrow(NamespaceError);
    expect(() => normalizeHost("localhost")).toThrow(NamespaceError);
  });
  it("registrableDomain reduces subdomains", () => {
    expect(registrableDomain("a.b.example.co.uk")).toBe("example.co.uk");
  });
});

describe("origin namespace derivation (browser mode): the namespace IS the origin", () => {
  it("keeps the scheme, the host and the port, verbatim", () => {
    expect(deriveOriginNamespace("https://example.com").namespace).toBe("web:https://example.com");
    expect(deriveOriginNamespace("http://example.com").namespace).toBe("web:http://example.com");
    expect(deriveOriginNamespace("https://example.com:8080").namespace).toBe("web:https://example.com:8080");
    expect(deriveOriginNamespace("bzz://name.eth").namespace).toBe("web:bzz://name.eth");
    // A bare origin with the URL parser's normalized root path is still accepted.
    expect(deriveOriginNamespace("https://example.com/").namespace).toBe("web:https://example.com");
  });

  it("does NOT collapse subdomains — a staging host is not production", () => {
    const prod = deriveOriginNamespace("https://site.example").namespace;
    for (const sub of ["https://www.site.example", "https://app.site.example", "https://staging.site.example"]) {
      expect(deriveOriginNamespace(sub).namespace).not.toBe(prod);
    }
    expect(deriveOriginNamespace("https://app.site.example").namespace).toBe("web:https://app.site.example");
  });

  it("does NOT collapse tenants of a shared host (the eTLD+1 leak)", () => {
    // Under registrable-domain keying every one of these was ONE partition,
    // because the suffix list calls `pages.example` a public suffix only when
    // it happens to be listed. Two unrelated tenants shared a document.
    expect(deriveOriginNamespace("https://alice.pages.example").namespace).not.toBe(
      deriveOriginNamespace("https://bob.pages.example").namespace,
    );
    expect(deriveOriginNamespace("https://alice.github.io").namespace).not.toBe(
      deriveOriginNamespace("https://bob.github.io").namespace,
    );
  });

  it("separates http from https on one host", () => {
    // An http origin is network-attackable and is not the same principal as its
    // https twin; every other storage API in the browser agrees.
    expect(deriveOriginNamespace("http://site.example").namespace).not.toBe(
      deriveOriginNamespace("https://site.example").namespace,
    );
  });

  it("separates ports without needing a loopback special case", () => {
    expect(deriveOriginNamespace("http://app.localhost:8765").namespace).toBe("web:http://app.localhost:8765");
    expect(deriveOriginNamespace("http://app.localhost:8765").storageKey).not.toBe(
      deriveOriginNamespace("http://app.localhost:8766").storageKey,
    );
    // A real host now keeps its port too — the old rule dropped it here and
    // kept it only for `*.localhost`.
    expect(deriveOriginNamespace("https://site.example:8443").namespace).not.toBe(
      deriveOriginNamespace("https://site.example").namespace,
    );
    // The scheme's default port is not a port: `http://app.localhost` and `:80` agree.
    expect(deriveOriginNamespace("http://app.localhost:80").namespace).toBe(
      deriveOriginNamespace("http://app.localhost").namespace,
    );
    expect(deriveOriginNamespace("https://site.example:443").namespace).toBe(
      deriveOriginNamespace("https://site.example").namespace,
    );
  });

  it("accepts bare localhost and IP literals — only the relay needs a name", () => {
    expect(deriveOriginNamespace("http://localhost:9999").namespace).toBe("web:http://localhost:9999");
    expect(deriveOriginNamespace("http://127.0.0.1:9999").namespace).toBe("web:http://127.0.0.1:9999");
    expect(deriveOriginNamespace("http://[::1]:9999").namespace).toBe("web:http://[::1]:9999");
    // And they are distinct from each other and from a loopback name.
    const ns = ["http://localhost:9999", "http://127.0.0.1:9999", "http://app.localhost:9999"].map(
      (o) => deriveOriginNamespace(o).namespace,
    );
    expect(new Set(ns).size).toBe(3);
  });

  it("keys a dweb origin on its scheme and authority, so the transport matters", () => {
    // One name, three transports, three partitions: changing a contenthash from
    // Swarm to IPFS moves the namespace. Documented as deployment discipline.
    expect(deriveOriginNamespace("bzz://name.eth").namespace).toBe("web:bzz://name.eth");
    expect(deriveOriginNamespace("ipfs://name.eth").namespace).toBe("web:ipfs://name.eth");
    expect(
      new Set(["bzz://name.eth", "ipfs://name.eth", "ipns://name.eth"].map((o) => deriveOriginNamespace(o).namespace))
        .size,
    ).toBe(3);
    expect(deriveOriginNamespace("bzz://v2.name.eth").namespace).not.toBe(
      deriveOriginNamespace("bzz://name.eth").namespace,
    );
  });

  it("folds case for name schemes and preserves it for addressed ones", () => {
    expect(deriveOriginNamespace("bzz://DeadBeefCafe").namespace).toBe("web:bzz://deadbeefcafe");
    expect(deriveOriginNamespace("ens://MyApp.eth").namespace).toBe("web:ens://myapp.eth");
    expect(deriveOriginNamespace("https://EXAMPLE.com").namespace).toBe("web:https://example.com");
    // Case-sensitive content-address / key schemes preserve case verbatim.
    expect(deriveOriginNamespace("ipfs://QmHash").namespace).toBe("web:ipfs://QmHash");
    expect(deriveOriginNamespace("ar://AbC-123").namespace).toBe("web:ar://AbC-123");
  });

  it("never aliases distinct case-sensitive dweb identifiers (isolation)", () => {
    // IPFS CIDv0 (Base58btc), Arweave (Base64URL), Radicle (Base58 z-RID) are
    // case-significant — two spellings must be two namespaces.
    expect(deriveOriginNamespace("ipfs://QmAbc").namespace).not.toBe(deriveOriginNamespace("ipfs://Qmabc").namespace);
    expect(deriveOriginNamespace("ar://Ab").namespace).not.toBe(deriveOriginNamespace("ar://ab").namespace);
    expect(deriveOriginNamespace("rad://z6MkAbc").namespace).not.toBe(deriveOriginNamespace("rad://z6mkabc").namespace);
    expect(deriveOriginNamespace("ipns://k51Xyz").namespace).not.toBe(deriveOriginNamespace("ipns://k51xyz").namespace);
  });

  it("cannot collide a dweb namespace with an http(s) one", () => {
    // The scheme is always present, so no two origins share a canonical key
    // without being the same origin. The old `web:dweb:` infix guard existed
    // only because the http(s) form dropped its scheme.
    const all = [
      "https://example.com",
      "http://example.com",
      "ens://example.com",
      "bzz://example.com",
      "ipfs://example.com",
    ].map((o) => deriveOriginNamespace(o).namespace);
    expect(new Set(all).size).toBe(all.length);
    expect(deriveOriginNamespace("bzz://a").storageKey).not.toBe(deriveOriginNamespace("bzz://b").storageKey);
  });

  it("derives no namespace from the Public Suffix List", () => {
    // The point of the rule: two hosts differing only below a suffix must
    // differ, whether or not that suffix is in anyone's list. A regression here
    // means eTLD+1 keying came back.
    expect(deriveOriginNamespace("https://a.site.co.uk").namespace).not.toBe(
      deriveOriginNamespace("https://b.site.co.uk").namespace,
    );
    expect(deriveOriginNamespace("https://site.co.uk").namespace).toBe("web:https://site.co.uk");
  });

  // Adversarial: a crafted URL must not smuggle non-authoritative components past
  // derivation, and only web / whitelisted-dweb schemes may mint a namespace.
  it("rejects non-authoritative URL components (userinfo/path/query/fragment)", () => {
    expect(() => deriveOriginNamespace("https://user:pass@example.com")).toThrow(NamespaceError);
    expect(() => deriveOriginNamespace("https://evil.com@example.com")).toThrow(NamespaceError);
    expect(() => deriveOriginNamespace("https://example.com/some/path")).toThrow(NamespaceError);
    expect(() => deriveOriginNamespace("https://example.com?q=1")).toThrow(NamespaceError);
    expect(() => deriveOriginNamespace("https://example.com#frag")).toThrow(NamespaceError);
    expect(() => deriveOriginNamespace("bzz://root/deep/path")).toThrow(NamespaceError);
  });
  it("rejects unsupported / dangerous schemes", () => {
    for (const bad of [
      "file:///etc/passwd",
      "data:text/html,hi",
      "javascript:alert(1)",
      "blob:https://example.com/uuid",
      "about:blank",
      "ws://example.com",
      "chrome://settings",
      "web3://0xabc",
      "freedom://dapps",
    ]) {
      expect(() => deriveOriginNamespace(bad)).toThrow(NamespaceError);
    }
  });
  it("rejects origins with no real authority", () => {
    expect(() => deriveOriginNamespace("bzz:opaque")).toThrow(NamespaceError);
    expect(() => deriveOriginNamespace("ipfs:")).toThrow(NamespaceError);
  });
  it("rejects empty / junk origins", () => {
    expect(() => deriveOriginNamespace("")).toThrow(NamespaceError);
    expect(() => deriveOriginNamespace("   ")).toThrow(NamespaceError);
    expect(() => deriveOriginNamespace("not a url")).toThrow(NamespaceError);
  });
});

describe("record authoritativeness for a host (anti-spoofing, PSL-aware)", () => {
  it("accepts exact host and same registrable domain", () => {
    expect(isAuthoritativeForHost("example.com", "example.com")).toBe(true);
    expect(isAuthoritativeForHost("example.com", "app.example.com")).toBe(true);
    expect(isAuthoritativeForHost("example.com", "a.b.example.com")).toBe(true);
  });
  it("rejects unrelated domains", () => {
    expect(isAuthoritativeForHost("evil.com", "example.com")).toBe(false);
    expect(isAuthoritativeForHost("example.com", "example.org")).toBe(false);
  });
  it("rejects public-suffix siblings (the naive last-two-labels bug)", () => {
    // Both end in `co.uk`, but they are DIFFERENT registrable domains.
    expect(isAuthoritativeForHost("attacker.co.uk", "victim.co.uk")).toBe(false);
    expect(isAuthoritativeForHost("attacker.co.uk", "app.victim.co.uk")).toBe(false);
  });
  it("rejects a parent-domain claim over a different child registrable", () => {
    expect(isAuthoritativeForHost("com", "example.com")).toBe(false);
    expect(isAuthoritativeForHost("co.uk", "victim.co.uk")).toBe(false);
  });
});

describe("homograph detection", () => {
  it("flags mixed-script hosts", () => {
    // 'аpple.com' with a Cyrillic 'а'
    expect(isMixedScript("аpple.com")).toBe(true);
    expect(detectHomograph("аpple.com").flag).toBe(true);
  });
  it("flags look-alikes of previously-approved domains", () => {
    // digit '1' folds to 'l' and '0' folds to 'o' in the skeleton table
    expect(confusableSkeleton("paypa1.com")).toBe(confusableSkeleton("paypal.com"));
    expect(detectHomograph("paypa1.com", ["paypal.com"]).flag).toBe(true);
    expect(detectHomograph("g00gle.com", ["google.com"]).flag).toBe(true);
  });
  it("does not flag a plain ASCII host with no look-alikes", () => {
    expect(detectHomograph("example.com", ["other.com"]).flag).toBe(false);
  });
});

describe("identity record proof", () => {
  it("verifies a well-formed self-signed record", () => {
    const rec = makeRecord("example.com");
    expect(verifyIdentityRecordProof(rec).ok).toBe(true);
  });
  it("rejects a tampered record", () => {
    const rec = makeRecord("example.com");
    rec.domain = "evil.com";
    expect(verifyIdentityRecordProof(rec).ok).toBe(false);
  });
  it("rejects a record whose proof kid is absent", () => {
    const rec = makeRecord("example.com");
    rec.proof.kid = "missing";
    expect(verifyIdentityRecordProof(rec).ok).toBe(false);
  });
});

describe("delegation verification", () => {
  function makeDelegation(domain: string): SessionDelegation {
    return signDelegation(
      {
        domain,
        sessionPublicKey: toBase64Url(ed25519Generate().publicKey),
        scopes: [{ methods: ["vault_getData"], fields: [{ path: "/profile", read: true, write: false }] }],
        vaultId: "vault-1",
        pairingChallenge: "12345678",
        issuedAt: Date.now(),
        expiresAt: Date.now() + 300000,
        nonce: "n1",
        keyId: "k1",
      },
      domainKey.privateKey,
    );
  }
  it("verifies a delegation signed by an active record key", () => {
    const rec = makeRecord("example.com");
    expect(verifyDelegation(makeDelegation("example.com"), rec).ok).toBe(true);
  });
  it("rejects a delegation for a different domain", () => {
    const rec = makeRecord("example.com");
    expect(verifyDelegation(makeDelegation("evil.com"), rec).ok).toBe(false);
  });
  it("rejects a tampered delegation (scope widening)", () => {
    const rec = makeRecord("example.com");
    const d = makeDelegation("example.com");
    d.scopes[0]!.fields[0]!.write = true;
    expect(verifyDelegation(d, rec).ok).toBe(false);
  });
});
