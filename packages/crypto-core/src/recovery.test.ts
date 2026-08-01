import { describe, expect, it } from "vitest";
import {
  generateRecoveryMnemonic,
  isValidRecoveryMnemonic,
  createRecoveryBlob,
  restoreDekFromRecovery,
  serializeRecoveryBlob,
  parseRecoveryBlob,
  type RecoveryParams,
} from "./recovery.js";
import { randomBytes, toHex, toBase64Url } from "./index.js";

// Fast Argon2id params for tests; production uses DEFAULT_RECOVERY_PARAMS (64 MiB).
const FAST: RecoveryParams = { t: 2, m: 8 * 1024, p: 1 };

describe("recovery mnemonic", () => {
  it("generates a valid 24-word BIP-39 mnemonic", () => {
    const m = generateRecoveryMnemonic();
    expect(m.split(" ")).toHaveLength(24);
    expect(isValidRecoveryMnemonic(m)).toBe(true);
  });
  it("rejects an invalid mnemonic", () => {
    expect(isValidRecoveryMnemonic("not a real mnemonic phrase at all")).toBe(false);
  });
});

const CTX = "vault-abc";

describe("DEK wrap / unwrap via Argon2id", () => {
  it("round-trips the DEK with the correct mnemonic + context", () => {
    const dek = randomBytes(32);
    const mnemonic = generateRecoveryMnemonic();
    const blob = createRecoveryBlob(dek, mnemonic, CTX, FAST);
    const restored = restoreDekFromRecovery(blob, mnemonic, CTX);
    expect(restored).not.toBeNull();
    expect(toHex(restored!)).toBe(toHex(dek));
  });

  it("fails with the wrong mnemonic", () => {
    const dek = randomBytes(32);
    const blob = createRecoveryBlob(dek, generateRecoveryMnemonic(), CTX, FAST);
    expect(restoreDekFromRecovery(blob, generateRecoveryMnemonic(), CTX)).toBeNull();
  });

  it("fails when the context differs (blob bound to a specific vault)", () => {
    const dek = randomBytes(32);
    const mnemonic = generateRecoveryMnemonic();
    const blob = createRecoveryBlob(dek, mnemonic, CTX, FAST);
    expect(restoreDekFromRecovery(blob, mnemonic, "other-vault")).toBeNull();
    // And a tampered context field breaks the AEAD too.
    expect(restoreDekFromRecovery({ ...blob, context: "other-vault" }, mnemonic, "other-vault")).toBeNull();
  });

  it("carries and honors its own KDF params (self-describing)", () => {
    const dek = randomBytes(32);
    const mnemonic = generateRecoveryMnemonic();
    const blob = createRecoveryBlob(dek, mnemonic, CTX, FAST);
    expect(blob).toMatchObject({ v: 1, kdf: "argon2id", context: CTX, t: FAST.t, m: FAST.m, p: FAST.p });
    expect(toHex(restoreDekFromRecovery(blob, mnemonic, CTX)!)).toBe(toHex(dek));
  });

  it("rejects a tampered blob (params/salt bound into AEAD)", () => {
    const dek = randomBytes(32);
    const mnemonic = generateRecoveryMnemonic();
    const blob = createRecoveryBlob(dek, mnemonic, CTX, FAST);
    expect(restoreDekFromRecovery({ ...blob, t: blob.t + 1 }, mnemonic, CTX)).toBeNull();
    const badCt = { ...blob, ct: blob.ct.slice(0, -2) + (blob.ct.endsWith("A") ? "B" : "A") };
    expect(restoreDekFromRecovery(badCt, mnemonic, CTX)).toBeNull();
  });

  it("fails CLOSED (returns null, never throws) on malformed valid-base64url fields", () => {
    const dek = randomBytes(32);
    const mnemonic = generateRecoveryMnemonic();
    const blob = createRecoveryBlob(dek, mnemonic, CTX, FAST);
    // Nonce of the wrong length (valid base64url, but xchachaOpen would throw).
    expect(restoreDekFromRecovery({ ...blob, nonce: toBase64Url(randomBytes(12)) }, mnemonic, CTX)).toBeNull();
    // Tag of the wrong length.
    expect(restoreDekFromRecovery({ ...blob, tag: toBase64Url(randomBytes(8)) }, mnemonic, CTX)).toBeNull();
    // Out-of-range KDF params.
    expect(restoreDekFromRecovery({ ...blob, m: 1 }, mnemonic, CTX)).toBeNull();
    expect(restoreDekFromRecovery({ ...blob, t: 0 }, mnemonic, CTX)).toBeNull();
    // Bogus structural fields.
    expect(restoreDekFromRecovery({ ...blob, v: 2 as unknown as 1 }, mnemonic, CTX)).toBeNull();
  });

  it("serializes to a portable string and back", () => {
    const dek = randomBytes(32);
    const mnemonic = generateRecoveryMnemonic();
    const blob = createRecoveryBlob(dek, mnemonic, CTX, FAST);
    const s = serializeRecoveryBlob(blob);
    expect(typeof s).toBe("string");
    const restored = restoreDekFromRecovery(parseRecoveryBlob(s), mnemonic, CTX);
    expect(toHex(restored!)).toBe(toHex(dek));
  });

  it("rejects a non-32-byte DEK, invalid mnemonic, and empty context at wrap time", () => {
    expect(() => createRecoveryBlob(randomBytes(16), generateRecoveryMnemonic(), CTX, FAST)).toThrow(/32 bytes/);
    expect(() => createRecoveryBlob(randomBytes(32), "bogus phrase", CTX, FAST)).toThrow(/invalid recovery mnemonic/);
    expect(() => createRecoveryBlob(randomBytes(32), generateRecoveryMnemonic(), "", FAST)).toThrow(/context required/);
  });
});
