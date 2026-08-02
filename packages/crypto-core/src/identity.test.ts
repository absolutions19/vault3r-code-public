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

describe("origin namespace derivation (trusted in-process host mode)", () => {
  it("reduces http(s) origins to the same web:<registrable-domain> as the relay path", () => {
    expect(deriveOriginNamespace("https://app.example.com").namespace).toBe("web:example.com");
    expect(deriveOriginNamespace("http://example.com:8080/some/path").namespace).toBe("web:example.com");
    // Identical to what deriveNamespace produces for the bare host.
    expect(deriveOriginNamespace("https://app.example.com").storageKey).toBe(
      deriveNamespace("example.com", "registrable-domain").storageKey,
    );
  });
  it("honors host granularity for http(s) origins", () => {
    expect(deriveOriginNamespace("https://tenant1.saas.com", "host").namespace).toBe("web:tenant1.saas.com");
  });
  it("keys decentralized-web origins on the full canonical authority under web:dweb:", () => {
    expect(deriveOriginNamespace("bzz://DeadBeefCafe").namespace).toBe("web:dweb:bzz:deadbeefcafe");
    expect(deriveOriginNamespace("ipfs://QmHash").namespace).toBe("web:dweb:ipfs:qmhash");
  });
  it("never collides a dweb namespace with an http(s) registrable domain", () => {
    const web = deriveOriginNamespace("https://example.com").namespace;
    const dweb = deriveOriginNamespace("ens://example.com").namespace;
    expect(web).not.toBe(dweb);
    expect(deriveOriginNamespace("bzz://a").storageKey).not.toBe(deriveOriginNamespace("bzz://b").storageKey);
  });
  it("rejects junk origins", () => {
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
