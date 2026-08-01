/**
 * RnStorage — implements the vault-core StorageAdapter on the device. Sealed
 * blobs (already AEAD-encrypted by the keystore) are written to the app's private
 * document directory; the small manifest lives in SecureStore. Blobs are opaque
 * ciphertext, so the filesystem never sees plaintext.
 */

import * as FileSystem from "expo-file-system";
import * as SecureStore from "expo-secure-store";
import type { StorageAdapter } from "@vault/vault-core";
import { toBase64Url, fromBase64Url } from "@vault/crypto-core";

const DIR = `${FileSystem.documentDirectory}vault/`;
const MANIFEST_SS_KEY = "vault.manifest";

async function ensureDir(): Promise<void> {
  const info = await FileSystem.getInfoAsync(DIR);
  if (!info.exists) await FileSystem.makeDirectoryAsync(DIR, { intermediates: true });
}

function fileFor(key: string): string {
  // key is already a safe hex/opaque id; encode to be filesystem-safe.
  return `${DIR}${encodeURIComponent(key)}.blob`;
}

export class RnStorage implements StorageAdapter {
  async get(key: string): Promise<Uint8Array | null> {
    if (key === "manifest") {
      const v = await SecureStore.getItemAsync(MANIFEST_SS_KEY);
      return v ? fromBase64Url(v) : null;
    }
    await ensureDir();
    const info = await FileSystem.getInfoAsync(fileFor(key));
    if (!info.exists) return null;
    const b64 = await FileSystem.readAsStringAsync(fileFor(key), { encoding: FileSystem.EncodingType.Base64 });
    return new Uint8Array(Buffer.from(b64, "base64"));
  }

  async put(key: string, value: Uint8Array): Promise<void> {
    if (key === "manifest") {
      await SecureStore.setItemAsync(MANIFEST_SS_KEY, toBase64Url(value));
      return;
    }
    await ensureDir();
    await FileSystem.writeAsStringAsync(fileFor(key), Buffer.from(value).toString("base64"), {
      encoding: FileSystem.EncodingType.Base64,
    });
  }

  async delete(key: string): Promise<void> {
    if (key === "manifest") {
      await SecureStore.deleteItemAsync(MANIFEST_SS_KEY);
      return;
    }
    await FileSystem.deleteAsync(fileFor(key), { idempotent: true });
  }

  async listKeys(prefix: string): Promise<string[]> {
    await ensureDir();
    const files = await FileSystem.readDirectoryAsync(DIR);
    return files
      .filter((f) => f.endsWith(".blob"))
      .map((f) => decodeURIComponent(f.replace(/\.blob$/, "")))
      .filter((k) => k.startsWith(prefix));
  }
}
