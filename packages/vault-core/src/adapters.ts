/**
 * Platform adapter interfaces. The engine is platform-agnostic: on a phone these
 * are backed by the Secure Enclave / Android Keystore, biometric prompts, and
 * encrypted on-device storage; in tests and the relay e2e they are backed by
 * in-memory implementations. The engine never touches raw key material — it only
 * asks the keystore to seal/open and to authenticate the user.
 */

import type { Base64Url } from "@vault/protocol";

/** Reason a biometric prompt is being shown (drives the prompt copy + policy). */
export type AuthReason =
  | "unlock"
  | "connect"
  | "sensitive-read"
  | "write"
  | "sensitive-write"
  | "grant-change"
  | "revoke";

export interface AuthRequest {
  reason: AuthReason;
  /** Human-readable summary rendered in the biometric prompt subtitle. */
  prompt: string;
}

/**
 * Biometric-gated key store. Wraps the hardware KEK→DEK hierarchy. On real
 * devices `authenticate` triggers FaceID / BiometricPrompt; sealing/opening a
 * namespace derives a per-namespace subkey from the DEK via HKDF so each site's
 * data is cryptographically isolated.
 */
export interface KeystoreAdapter {
  isUnlocked(): boolean;
  /** Unlock the DEK (biometric). Idempotent while unlocked. */
  unlock(req?: AuthRequest): Promise<boolean>;
  lock(): void;
  /** Per-operation biometric check (returns false if failed/cancelled). */
  authenticate(req: AuthRequest): Promise<boolean>;

  /** Seal plaintext for a namespace (per-namespace subkey + AEAD, aad bound). */
  sealNamespace(storageKey: string, aad: Uint8Array, plaintext: Uint8Array): Uint8Array;
  /** Open a sealed namespace blob; returns null on authentication failure. */
  openNamespace(storageKey: string, aad: Uint8Array, blob: Uint8Array): Uint8Array | null;

  /** The vault's device public key (base64url Ed25519) used to sign responses. */
  deviceKeyPublic(): Base64Url;
  /** Sign bytes with the device key (settle + response authentication). */
  signDevice(bytes: Uint8Array): Base64Url;

  /** A stable per-install id, unique to this vault (used in the typed domain). */
  vaultId(): string;
}

/** Opaque persistent key/value store for sealed blobs and engine metadata. */
export interface StorageAdapter {
  get(key: string): Promise<Uint8Array | null>;
  put(key: string, value: Uint8Array): Promise<void>;
  delete(key: string): Promise<void>;
  listKeys(prefix: string): Promise<string[]>;
}

/**
 * Resolves a domain's `.well-known/vault-identity.json`. On device this fetches
 * over TLS with SSRF guards; in tests it is a static registry. Returns null when
 * the record cannot be fetched/validated at the transport level.
 */
export interface IdentityResolver {
  resolve(domain: string): Promise<import("@vault/protocol").VaultIdentityRecord | null>;
}

/** The connection/permission decision surface (the consent UI). */
export interface ConsentDecision {
  approved: boolean;
  /** Field paths the user actually granted (a subset of requested). */
  grantedFields?: import("@vault/protocol").FieldRule[];
  /** Methods the user actually granted. */
  grantedMethods?: string[];
  writePolicy?: import("@vault/protocol").WritePolicy;
  reason?: string;
}

export interface ConsentRequest {
  verification: import("@vault/protocol").IdentityVerification;
  appMetadata: import("@vault/protocol").AppMetadata;
  requestedScopes: import("@vault/protocol").RequestedScope[];
  /** The number-matching code the user must confirm (anti pairing-relay). */
  pairingChallenge: string;
  assertedAccount?: string;
}

export interface ConsentAdapter {
  requestConnect(req: ConsentRequest): Promise<ConsentDecision>;
}

export interface Clock {
  now(): number;
}

export const systemClock: Clock = { now: () => Date.now() };
