/**
 * vault-keystore — the native hardware boundary.
 *
 * This is the ONE piece that cannot be JavaScript: it owns the biometric-gated
 * KEK in the Secure Enclave (iOS) / Android Keystore, unwraps the DEK only after
 * a successful biometric, derives per-namespace subkeys, and performs the at-rest
 * AEAD — all so key bytes never cross into the JS (Hermes) heap.
 *
 * The JS side calls these methods with base64 arguments; the native side keeps
 * the DEK in secure native memory for the unlocked session and zeroizes it on
 * lock / backgrounding.
 */

import { requireOptionalNativeModule } from "expo-modules-core";

export type SecurityLevel = "strongbox" | "tee" | "secure-enclave" | "software";

export interface ProvisionResult {
  // The wrapped DEK is persisted natively (inside the Keychain / Keystore) and is
  // never exposed to JS — the JS side only receives the public device key + id.
  deviceKeyPublic: string; // Ed25519 device public key (base64url)
  vaultId: string;
}

export interface VaultKeystoreNativeModule {
  isAvailable(): boolean;
  hasHardwareBackedKeys(): Promise<boolean>;
  getSecurityLevel(): Promise<SecurityLevel>;

  /** First-run: create the biometric-gated KEK + random DEK; return wrapped DEK. */
  provision(): Promise<ProvisionResult>;

  /** Biometric unlock: unwrap the DEK into a native session handle. */
  unlock(reason: string): Promise<boolean>;
  lock(): Promise<void>;
  isUnlocked(): Promise<boolean>;
  /** Per-operation biometric (e.g. sensitive read/write, connect). */
  authenticate(reason: string): Promise<boolean>;

  /** Seal/open a per-namespace document (HKDF subkey + XChaCha20-Poly1305). */
  seal(storageKey: string, aadB64: string, plaintextB64: string): Promise<string>;
  open(storageKey: string, aadB64: string, blobB64: string): Promise<string | null>;

  /** Device-key operations for signing settle + responses. */
  deviceSign(bytesB64: string): Promise<string>;
  deviceKeyPublic(): Promise<string>;

  /**
   * Recovery is handled entirely natively: the wrapped-DEK material never crosses
   * the JS boundary. `createRecoveryBackup` derives K_recovery = Argon2id(mnemonic),
   * wraps the DEK, and writes the opaque blob to a native-managed backup location;
   * `restoreFromRecovery` reads it, unwraps with the mnemonic, and re-provisions.
   * JS only ever sees a boolean.
   */
  hasRecoveryBackup(): Promise<boolean>;
  createRecoveryBackup(mnemonic: string): Promise<boolean>;
  restoreFromRecovery(mnemonic: string): Promise<boolean>;
}

/** The native module, or null on platforms/dev builds where it is absent. */
export const VaultKeystore = requireOptionalNativeModule<VaultKeystoreNativeModule>("VaultKeystore");

export function isNativeKeystoreAvailable(): boolean {
  return VaultKeystore != null && VaultKeystore.isAvailable();
}
