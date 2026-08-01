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
import { randomBytes, toHex } from "./index.js";

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

describe("DEK wrap / unwrap via Argon2id", () => {
  it("round-trips the DEK with the correct mnemonic", () => {
    const dek = randomBytes(32);
    const mnemonic = generateRecoveryMnemonic();
    const blob = createRecoveryBlob(dek, mnemonic, FAST);
    const restored = restoreDekFromRecovery(blob, mnemonic);
    expect(restored).not.toBeNull();
    expect(toHex(restored!)).toBe(toHex(dek));
  });

  it("fails with the wrong mnemonic", () => {
    const dek = randomBytes(32);
    const blob = createRecoveryBlob(dek, generateRecoveryMnemonic(), FAST);
    expect(restoreDekFromRecovery(blob, generateRecoveryMnemonic())).toBeNull();
  });

  it("carries and honors its own KDF params (self-describing)", () => {
    const dek = randomBytes(32);
    const mnemonic = generateRecoveryMnemonic();
    const blob = createRecoveryBlob(dek, mnemonic, FAST);
    expect(blob).toMatchObject({ v: 1, kdf: "argon2id", t: FAST.t, m: FAST.m, p: FAST.p });
    // Restoring uses the params in the blob, not any external default.
    expect(toHex(restoreDekFromRecovery(blob, mnemonic)!)).toBe(toHex(dek));
  });

  it("rejects a tampered blob (params/salt bound into AEAD)", () => {
    const dek = randomBytes(32);
    const mnemonic = generateRecoveryMnemonic();
    const blob = createRecoveryBlob(dek, mnemonic, FAST);
    // Flip a param the attacker might try to weaken; AEAD binding must reject it.
    expect(restoreDekFromRecovery({ ...blob, t: blob.t + 1 }, mnemonic)).toBeNull();
    // Tamper the ciphertext.
    const badCt = { ...blob, ct: blob.ct.slice(0, -2) + (blob.ct.endsWith("A") ? "B" : "A") };
    expect(restoreDekFromRecovery(badCt, mnemonic)).toBeNull();
  });

  it("serializes to a portable string and back", () => {
    const dek = randomBytes(32);
    const mnemonic = generateRecoveryMnemonic();
    const blob = createRecoveryBlob(dek, mnemonic, FAST);
    const s = serializeRecoveryBlob(blob);
    expect(typeof s).toBe("string");
    const restored = restoreDekFromRecovery(parseRecoveryBlob(s), mnemonic);
    expect(toHex(restored!)).toBe(toHex(dek));
  });

  it("rejects a non-32-byte DEK and an invalid mnemonic at wrap time", () => {
    expect(() => createRecoveryBlob(randomBytes(16), generateRecoveryMnemonic(), FAST)).toThrow(/32 bytes/);
    expect(() => createRecoveryBlob(randomBytes(32), "bogus phrase", FAST)).toThrow(/invalid recovery mnemonic/);
  });
});
