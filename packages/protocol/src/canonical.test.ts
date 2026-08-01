import { describe, expect, it } from "vitest";
import { canonicalStringify, canonicalBytes, CanonicalizeError } from "./canonical.js";
import { typedSigningPreimage, makeDomain, type TypedData } from "./typed-data.js";
import { VaultError, ErrorCode, isVaultError } from "./errors.js";

describe("canonical encoder", () => {
  it("sorts object keys deterministically (UTF-16 order)", () => {
    expect(canonicalStringify({ b: 1, a: 2, c: 3 })).toBe('{"a":2,"b":1,"c":3}');
  });

  it("produces identical bytes regardless of insertion order", () => {
    const a = canonicalStringify({ x: { z: 1, y: 2 }, w: [3, 2, 1] });
    const b = canonicalStringify({ w: [3, 2, 1], x: { y: 2, z: 1 } });
    expect(a).toBe(b);
  });

  it("drops undefined object members but keeps null", () => {
    expect(canonicalStringify({ a: undefined, b: null })).toBe('{"b":null}');
  });

  it("normalizes -0 to 0", () => {
    expect(canonicalStringify(-0)).toBe("0");
  });

  it("rejects non-integer numbers (no ambiguous float formatting in signed data)", () => {
    expect(() => canonicalStringify(1.5)).toThrow(CanonicalizeError);
  });

  it("rejects NaN and Infinity", () => {
    expect(() => canonicalStringify(NaN)).toThrow(CanonicalizeError);
    expect(() => canonicalStringify(Infinity)).toThrow(CanonicalizeError);
  });

  it("rejects unsafe integers", () => {
    expect(() => canonicalStringify(Number.MAX_SAFE_INTEGER + 1)).toThrow(CanonicalizeError);
  });

  it("rejects undefined array elements", () => {
    expect(() => canonicalStringify([1, undefined as unknown as number, 3])).toThrow(CanonicalizeError);
  });

  it("encodes strings with JSON escaping", () => {
    expect(canonicalStringify('a"b\\c')).toBe('"a\\"b\\\\c"');
  });

  it("canonicalBytes is UTF-8 of the canonical string", () => {
    const bytes = canonicalBytes({ "é": 1 });
    expect(new TextDecoder().decode(bytes)).toBe(canonicalStringify({ "é": 1 }));
  });
});

describe("typed data signing preimage", () => {
  it("differs across primaryType even with identical messages", () => {
    const domain = makeDomain("vault-1");
    const message = {
      namespace: "web:example.com",
      nonce: "n1",
      issuedAt: 1,
      expiry: 2,
      sessionId: "s1",
      paths: ["/a"],
    };
    const read: TypedData = { primaryType: "VaultRead", domain, message: message as never };
    const write: TypedData = {
      primaryType: "VaultWrite",
      domain,
      message: { ...message, changes: [] } as never,
    };
    expect(typedSigningPreimage(read)).not.toEqual(typedSigningPreimage(write));
  });

  it("differs across vaultId (domain separation)", () => {
    const message = { namespace: "web:a.com", nonce: "n", issuedAt: 1, expiry: 2, sessionId: "s", paths: [] };
    const a: TypedData = { primaryType: "VaultRead", domain: makeDomain("v-a"), message: message as never };
    const b: TypedData = { primaryType: "VaultRead", domain: makeDomain("v-b"), message: message as never };
    expect(typedSigningPreimage(a)).not.toEqual(typedSigningPreimage(b));
  });
});

describe("VaultError", () => {
  it("maps codes to names and default messages", () => {
    const e = VaultError.of("NamespaceMismatch");
    expect(e.code).toBe(ErrorCode.NamespaceMismatch);
    expect(e.codeName).toBe("NamespaceMismatch");
    expect(isVaultError(e)).toBe(true);
  });

  it("serializes to a compact JSON-RPC error without stack", () => {
    const e = VaultError.of("Unauthorized", "nope", { path: "/x" });
    expect(e.toRpcError()).toEqual({ code: 4100, message: "nope", data: { path: "/x" } });
  });

  it("wraps unknown errors", () => {
    expect(VaultError.fromUnknown(new Error("boom")).message).toBe("boom");
    expect(VaultError.fromUnknown("str").code).toBe(ErrorCode.InvalidRequest);
  });
});
