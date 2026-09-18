/**
 * Encrypted per-namespace document store with anti-rollback.
 *
 * Each namespace document is sealed under its own subkey. A sealed manifest
 * records the latest version of every namespace; on load we refuse a blob whose
 * version is behind the manifest (rollback) or a missing blob the manifest still
 * expects (deletion). The manifest itself is AEAD-sealed, so it cannot be forged.
 */

import { utf8ToBytes, bytesToUtf8, sha256, toHex } from "@vault/crypto-core";
import { VaultError } from "@vault/protocol";
import type { KeystoreAdapter, StorageAdapter } from "./adapters.js";
import type { Json } from "./json-pointer.js";

const MANIFEST_KEY = "manifest";
const MANIFEST_STORAGE_KEY = "__vault_manifest__";
const MANIFEST_AAD = utf8ToBytes("vault-manifest/1");

/**
 * Cleartext fingerprint of the identity that sealed this store. A blob that fails
 * to authenticate looks identical whether it was sealed under a different mnemonic
 * or torn on disk; this is the only way to tell the two apart, and it turned an
 * hour of chasing a mnemonic that had never changed into a one-line diagnosis.
 *
 * Stored as sha256 over the vaultId rather than the vaultId itself, so the value
 * the signing domain uses is not written in the clear. Any deterministic
 * fingerprint links two stores sealed under one mnemonic — that linkability is
 * inherent to the feature and is the price of the diagnosis.
 */
const OWNER_KEY = "manifest-owner";
const OWNER_DOMAIN = "vault-owner/1|";

/** Why a sealed blob failed to open. Surfaced as `VaultError.data.reason`. */
export type AuthFailureReason = "wrong-identity" | "corrupt" | "unknown";

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
  /**
   * Every mutation runs through this one queue. A per-namespace lock would not
   * be enough, for two reasons:
   *
   *  1. `save` does a read-modify-write on the SHARED manifest, so two saves to
   *     different namespaces can each load the manifest, each add their own
   *     entry, and the second write drops the first's.
   *  2. Nothing lets the store assume the adapter makes overlapping writes to
   *     one key atomic against each other; a real filesystem adapter with a
   *     shared temp path tore blobs in practice.
   *
   * Vault writes are small and rare — a dapp saving a profile — so strict
   * serialisation costs nothing measurable and is obviously correct.
   */
  private writeQueue: Promise<unknown> = Promise.resolve();

  constructor(
    private readonly keystore: KeystoreAdapter,
    private readonly storage: StorageAdapter,
  ) {}

  /**
   * Run `fn` after every previously queued mutation has settled, and before any
   * queued after it. Callers that do load → modify → `save` MUST wrap the whole
   * sequence, or two of them can both load the same version and the second save
   * silently discards the first's changes.
   */
  serialize<T>(fn: () => Promise<T>): Promise<T> {
    const run = this.writeQueue.then(fn, fn);
    this.writeQueue = run.then(
      () => undefined,
      () => undefined,
    );
    return run;
  }

  private async loadManifest(): Promise<Record<string, number>> {
    const blob = await this.storage.get(MANIFEST_KEY);
    if (!blob) return {};
    const pt = await this.keystore.openNamespace(MANIFEST_STORAGE_KEY, MANIFEST_AAD, blob);
    if (pt === null) throw await this.authFailure("manifest");
    return JSON.parse(bytesToUtf8(pt)) as Record<string, number>;
  }

  private async saveManifest(m: Record<string, number>): Promise<void> {
    const blob = await this.keystore.sealNamespace(MANIFEST_STORAGE_KEY, MANIFEST_AAD, utf8ToBytes(JSON.stringify(m)));
    await this.storage.put(MANIFEST_KEY, blob);
    await this.recordOwner();
  }

  /** The current keystore's owner fingerprint, or null if it cannot be read (locked). */
  private ownerFingerprint(): string | null {
    let id: string;
    try {
      id = this.keystore.vaultId();
    } catch {
      return null;
    }
    if (typeof id !== "string" || id.length === 0) return null;
    return toHex(sha256(utf8ToBytes(OWNER_DOMAIN + id)));
  }

  /** Write the owner fingerprint if absent or stale. One read per save; a write only on change. */
  private async recordOwner(): Promise<void> {
    const current = this.ownerFingerprint();
    if (!current) return;
    const stored = await this.storage.get(OWNER_KEY);
    if (stored && bytesToUtf8(stored) === current) return;
    await this.storage.put(OWNER_KEY, utf8ToBytes(current));
  }

  /**
   * Build the KeyInvalidated error for a blob that failed to authenticate, naming
   * the cause when the owner fingerprint lets us: sealed by a different identity,
   * or corrupt under the right one. `unknown` when no fingerprint was recorded
   * (stores written before this existed) or the keystore is locked.
   */
  private async authFailure(what: "manifest" | "namespace blob"): Promise<VaultError> {
    const stored = await this.storage.get(OWNER_KEY);
    const current = this.ownerFingerprint();
    let reason: AuthFailureReason = "unknown";
    if (stored && current) reason = bytesToUtf8(stored) === current ? "corrupt" : "wrong-identity";

    const message =
      reason === "wrong-identity"
        ? `${what} was sealed under a different identity (mnemonic) than the one unlocked now`
        : reason === "corrupt"
          ? `${what} is corrupt — it failed to authenticate under the identity that sealed it`
          : `${what} failed to authenticate`;
    return VaultError.of("KeyInvalidated", message, { reason });
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
    if (pt === null) throw await this.authFailure("namespace blob");
    const parsed = JSON.parse(bytesToUtf8(pt)) as SealedDoc;
    if (parsed.v < expected) throw VaultError.of("KeyInvalidated", "namespace blob is stale (rollback)");
    return { doc: parsed.doc, version: parsed.v };
  }

  /**
   * Persist a new version of a namespace document and advance the manifest.
   * Call only inside `serialize` — see the note there.
   */
  async save(storageKey: string, doc: Json, newVersion: number): Promise<void> {
    const payload: SealedDoc = { v: newVersion, doc };
    const blob = await this.keystore.sealNamespace(storageKey, docAad(storageKey), utf8ToBytes(JSON.stringify(payload)));
    await this.storage.put(docStorageId(storageKey), blob);
    const manifest = await this.loadManifest();
    manifest[storageKey] = newVersion;
    await this.saveManifest(manifest);
  }

  /**
   * Owner-initiated deletion of a namespace's document. Removes the sealed blob
   * AND clears its manifest entry, so the anti-rollback guard in `load` treats a
   * later absence as "never existed" rather than a rollback/deletion attack. This
   * is the ONLY legitimate way to drop a namespace; a bare `storage.delete` would
   * leave the manifest expecting the blob and brick every future load.
   *
   * The manifest is loaded BEFORE the blob is removed. In the other order, a
   * manifest that fails to open leaves the blob already gone with the manifest
   * still expecting it — the exact bricked state this method exists to prevent.
   * Serialised with every other mutation.
   */
  async deleteNamespace(storageKey: string): Promise<void> {
    await this.serialize(async () => {
      const manifest = await this.loadManifest();
      await this.storage.delete(docStorageId(storageKey));
      if (storageKey in manifest) {
        delete manifest[storageKey];
        await this.saveManifest(manifest);
      }
    });
  }
}
