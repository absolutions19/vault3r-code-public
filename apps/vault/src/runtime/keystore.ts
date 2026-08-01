/**
 * RnKeystore — implements the vault-core KeystoreAdapter on the device.
 *
 * When the native `vault-keystore` module is present it delegates every key
 * operation to the Secure Enclave / Android Keystore (key bytes never enter JS).
 * When it is absent (Expo Go / simulator / dev), it falls back to a pure-JS
 * implementation using @vault/crypto-core, persisting the master DEK in
 * SecureStore. THE JS FALLBACK IS FOR DEVELOPMENT ONLY — it does not provide
 * hardware isolation and must never ship to production.
 */

import * as SecureStore from "expo-secure-store";
import type { KeystoreAdapter, AuthRequest } from "@vault/vault-core";
import {
  ed25519Generate,
  ed25519Sign,
  hkdfSha256,
  sha256,
  xchachaSeal,
  xchachaOpen,
  randomBytes,
  toBase64Url,
  fromBase64Url,
  concatBytes,
  utf8ToBytes,
  createRecoveryBlob,
  restoreDekFromRecovery,
  serializeRecoveryBlob,
  parseRecoveryBlob,
} from "@vault/crypto-core";
import * as LocalAuthentication from "expo-local-authentication";
import { VaultKeystore, isNativeKeystoreAvailable } from "../../modules/vault-keystore";

/** React Native injects `__DEV__` (true in dev builds, false in release). */
declare const __DEV__: boolean;

const PACK = 0x01;
const SS = { dek: "vault.masterDek", device: "vault.deviceSeed", vaultId: "vault.vaultId", recovery: "vault.recoveryBlob" };

// --- native-boundary validation -------------------------------------------
// Never trust a native return value. Decode strictly as base64url and enforce
// expected lengths; a validation failure is a keystore failure (fail closed).

class KeystoreError extends Error {}

function decodeNative(value: string, name: string): Uint8Array {
  try {
    return fromBase64Url(value); // throws on non-base64url alphabet
  } catch {
    throw new KeystoreError(`native keystore returned invalid base64url for ${name}`);
  }
}

/** Validate a native base64url return; optionally assert exact decoded length. */
function requireNativeB64u(value: unknown, name: string, expectedLen?: number): string {
  if (typeof value !== "string" || value.length === 0) {
    throw new KeystoreError(`native keystore returned an empty/non-string ${name}`);
  }
  const bytes = decodeNative(value, name);
  if (expectedLen !== undefined && bytes.length !== expectedLen) {
    throw new KeystoreError(`native keystore returned ${bytes.length}-byte ${name}, expected ${expectedLen}`);
  }
  return value;
}

function requireNativeBytes(value: unknown, name: string): Uint8Array {
  if (typeof value !== "string" || value.length === 0) {
    throw new KeystoreError(`native keystore returned an empty/non-string ${name}`);
  }
  return decodeNative(value, name);
}

export class RnKeystore implements KeystoreAdapter {
  private native: boolean;
  private unlocked = false;
  private masterDek?: Uint8Array; // JS fallback only
  private deviceSeed?: Uint8Array; // JS fallback only
  private deviceKeyPubB64 = "";
  private vaultIdStr = "";

  private constructor(native: boolean) {
    this.native = native;
  }

  static async create(): Promise<RnKeystore> {
    const native = isNativeKeystoreAvailable();
    // Fail CLOSED in production: the pure-JS fallback provides no hardware
    // isolation, so a release build must never silently downgrade to it.
    if (!native && !__DEV__) {
      throw new Error(
        "Hardware-backed keystore unavailable. The JS fallback is development-only; " +
          "refusing to store vault secrets without Secure Enclave / Android Keystore.",
      );
    }
    const ks = new RnKeystore(native);
    if (ks.native) {
      const has = await SecureStore.getItemAsync(SS.vaultId);
      if (!has) {
        const prov = await VaultKeystore!.provision();
        if (typeof prov.vaultId !== "string" || prov.vaultId.length === 0) {
          throw new KeystoreError("native keystore returned an empty vaultId");
        }
        ks.deviceKeyPubB64 = requireNativeB64u(prov.deviceKeyPublic, "device public key", 32);
        await SecureStore.setItemAsync(SS.vaultId, prov.vaultId);
        ks.vaultIdStr = prov.vaultId;
      } else {
        ks.vaultIdStr = has;
        ks.deviceKeyPubB64 = requireNativeB64u(await VaultKeystore!.deviceKeyPublic(), "device public key", 32);
      }
    } else {
      await ks.initJsFallback();
    }
    return ks;
  }

  private async initJsFallback(): Promise<void> {
    let dek = await SecureStore.getItemAsync(SS.dek);
    let device = await SecureStore.getItemAsync(SS.device);
    let vaultId = await SecureStore.getItemAsync(SS.vaultId);
    if (!dek || !device || !vaultId) {
      const kp = ed25519Generate();
      dek = toBase64Url(randomBytes(32));
      device = toBase64Url(kp.privateKey);
      vaultId = toBase64Url(randomBytes(16));
      // Dev-only path. Still request biometric gating on the DEK where the OS
      // supports it (falls back automatically on a device without enrolled
      // biometrics, e.g. a bare simulator).
      const hasBio = await LocalAuthentication.hasHardwareAsync().catch(() => false);
      await SecureStore.setItemAsync(SS.dek, dek, { requireAuthentication: hasBio });
      await SecureStore.setItemAsync(SS.device, device);
      await SecureStore.setItemAsync(SS.vaultId, vaultId);
    }
    this.masterDek = fromBase64Url(dek);
    this.deviceSeed = fromBase64Url(device);
    this.vaultIdStr = vaultId;
    const { ed25519PublicFromSeed } = await import("@vault/crypto-core");
    this.deviceKeyPubB64 = toBase64Url(ed25519PublicFromSeed(this.deviceSeed));
  }

  isUnlocked(): boolean {
    return this.unlocked;
  }

  async unlock(req?: AuthRequest): Promise<boolean> {
    if (this.native) {
      // Only a literal `true` unlocks; a malformed/non-boolean return is failure.
      const ok = (await VaultKeystore!.unlock(req?.prompt ?? "Unlock your vault")) === true;
      this.unlocked = ok;
      return ok;
    }
    const res = await LocalAuthentication.authenticateAsync({ promptMessage: req?.prompt ?? "Unlock your vault" });
    this.unlocked = res.success === true;
    return this.unlocked;
  }

  lock(): void {
    this.unlocked = false;
    if (this.native) void VaultKeystore!.lock();
  }

  async authenticate(req: AuthRequest): Promise<boolean> {
    if (this.native) return (await VaultKeystore!.authenticate(req.prompt)) === true;
    const res = await LocalAuthentication.authenticateAsync({ promptMessage: req.prompt });
    return res.success === true;
  }

  async sealNamespace(storageKey: string, aad: Uint8Array, plaintext: Uint8Array): Promise<Uint8Array> {
    if (this.native) {
      const ct = await VaultKeystore!.seal(storageKey, toBase64Url(aad), toBase64Url(plaintext));
      return requireNativeBytes(ct, "sealed blob");
    }
    const key = this.nsKey(storageKey);
    const nonce = randomBytes(24);
    const box = xchachaSeal(key, nonce, plaintext, aad);
    return concatBytes(new Uint8Array([PACK]), box.nonce, box.tag, box.ciphertext);
  }

  async openNamespace(storageKey: string, aad: Uint8Array, blob: Uint8Array): Promise<Uint8Array | null> {
    if (this.native) {
      const pt = await VaultKeystore!.open(storageKey, toBase64Url(aad), toBase64Url(blob));
      return pt == null ? null : requireNativeBytes(pt, "opened blob");
    }
    if (blob.length < 41 || blob[0] !== PACK) return null;
    const key = this.nsKey(storageKey);
    return xchachaOpen(key, blob.subarray(1, 25), blob.subarray(41), blob.subarray(25, 41), aad);
  }

  deviceKeyPublic(): string {
    return this.deviceKeyPubB64;
  }

  async signDevice(bytes: Uint8Array): Promise<string> {
    if (this.native) {
      return requireNativeB64u(await VaultKeystore!.deviceSign(toBase64Url(bytes)), "device signature", 64);
    }
    return toBase64Url(ed25519Sign(bytes, this.deviceSeed!));
  }

  vaultId(): string {
    return this.vaultIdStr;
  }

  // --- recovery (mnemonic wrap/unwrap of the DEK) ---------------------------
  // On native, the wrapped blob is created/consumed inside the module and never
  // crosses to JS. In the dev fallback we use the tested crypto-core recovery and
  // keep the opaque blob in SecureStore.

  async hasRecoveryBackup(): Promise<boolean> {
    if (this.native) return (await VaultKeystore!.hasRecoveryBackup()) === true;
    return (await SecureStore.getItemAsync(SS.recovery)) != null;
  }

  async createRecoveryBackup(mnemonic: string): Promise<boolean> {
    if (this.native) return (await VaultKeystore!.createRecoveryBackup(mnemonic)) === true;
    if (!this.masterDek) throw new KeystoreError("vault not provisioned");
    const blob = serializeRecoveryBlob(createRecoveryBlob(this.masterDek, mnemonic));
    await SecureStore.setItemAsync(SS.recovery, blob);
    return true;
  }

  async restoreFromRecovery(mnemonic: string): Promise<boolean> {
    if (this.native) return (await VaultKeystore!.restoreFromRecovery(mnemonic)) === true;
    const stored = await SecureStore.getItemAsync(SS.recovery);
    if (!stored) return false;
    const dek = restoreDekFromRecovery(parseRecoveryBlob(stored), mnemonic);
    if (!dek) return false;
    this.masterDek = dek;
    await SecureStore.setItemAsync(SS.dek, toBase64Url(dek));
    return true;
  }

  private nsKey(storageKey: string): Uint8Array {
    if (!this.masterDek) throw new Error("vault locked / not provisioned");
    const salt = sha256(utf8ToBytes(`vault-ns-salt|${storageKey}`));
    return hkdfSha256(this.masterDek, salt, utf8ToBytes(`vault-ns/v1|${storageKey}`), 32);
  }
}
