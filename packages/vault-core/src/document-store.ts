/**
 * Encrypted per-namespace document store with anti-rollback.
 *
 * Each namespace document is sealed under its own subkey. A sealed manifest
 * records the latest version of every namespace; on load we refuse a blob whose
 * version is behind the manifest (rollback) or a missing blob the manifest still
 * expects (deletion). The manifest itself is AEAD-sealed, so it cannot be forged.
 */

import { utf8ToBytes, bytesToUtf8 } from "@vault/crypto-core";
import { VaultError } from "@vault/protocol";
import type { KeystoreAdapter, StorageAdapter } from "./adapters.js";
import type { Json } from "./json-pointer.js";

const MANIFEST_KEY = "manifest";
const MANIFEST_STORAGE_KEY = "__vault_manifest__";
const MANIFEST_AAD = utf8ToBytes("vault-manifest/1");

function docStorageId(storageKey: string): string {
  return `doc:${storageKey}`;
}
function docAad(storageKey: string): Uint8Array {
  return utf8ToBytes(`vault-doc/1|${storageKey}`);
}

interface SealedDoc {
  v: number;
  doc: Json;
}

export interface LoadedDoc {
  doc: Json;
  version: number;
}

export function versionToEtag(v: number): string {
  return `etag:${v}`;
}
export function etagToVersion(etag: string | undefined): number | undefined {
  if (!etag) return undefined;
  const m = /^etag:(\d+)$/.exec(etag);
  return m ? Number(m[1]) : undefined;
}

export class DocumentStore {
  constructor(
    private readonly keystore: KeystoreAdapter,
    private readonly storage: StorageAdapter,
  ) {}

  private async loadManifest(): Promise<Record<string, number>> {
    const blob = await this.storage.get(MANIFEST_KEY);
    if (!blob) return {};
    const pt = await this.keystore.openNamespace(MANIFEST_STORAGE_KEY, MANIFEST_AAD, blob);
    if (pt === null) throw VaultError.of("KeyInvalidated", "manifest failed to authenticate (tampering?)");
    return JSON.parse(bytesToUtf8(pt)) as Record<string, number>;
  }

  private async saveManifest(m: Record<string, number>): Promise<void> {
    const blob = await this.keystore.sealNamespace(MANIFEST_STORAGE_KEY, MANIFEST_AAD, utf8ToBytes(JSON.stringify(m)));
    await this.storage.put(MANIFEST_KEY, blob);
  }

  /** Load a namespace document, enforcing anti-rollback against the manifest. */
  async load(storageKey: string): Promise<LoadedDoc> {
    const manifest = await this.loadManifest();
    const expected = manifest[storageKey] ?? 0;
    const blob = await this.storage.get(docStorageId(storageKey));
    if (!blob) {
      if (expected > 0) throw VaultError.of("KeyInvalidated", "namespace blob missing (rollback/deletion)");
      return { doc: {}, version: 0 };
    }
    const pt = await this.keystore.openNamespace(storageKey, docAad(storageKey), blob);
    if (pt === null) throw VaultError.of("KeyInvalidated", "namespace blob failed to authenticate");
    const parsed = JSON.parse(bytesToUtf8(pt)) as SealedDoc;
    if (parsed.v < expected) throw VaultError.of("KeyInvalidated", "namespace blob is stale (rollback)");
    return { doc: parsed.doc, version: parsed.v };
  }

  /** Persist a new version of a namespace document and advance the manifest. */
  async save(storageKey: string, doc: Json, newVersion: number): Promise<void> {
    const payload: SealedDoc = { v: newVersion, doc };
    const blob = await this.keystore.sealNamespace(storageKey, docAad(storageKey), utf8ToBytes(JSON.stringify(payload)));
    await this.storage.put(docStorageId(storageKey), blob);
    const manifest = await this.loadManifest();
    manifest[storageKey] = newVersion;
    await this.saveManifest(manifest);
  }
}
