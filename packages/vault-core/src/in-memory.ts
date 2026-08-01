/**
 * In-memory adapter implementations for tests and the relay end-to-end harness.
 * They mirror the security-relevant behavior of the on-device adapters (biometric
 * gating, per-namespace subkeys, AEAD sealing) without any hardware.
 */

import {
  ed25519Generate,
  hkdfSha256,
  randomBytes,
  sha256,
  xchachaSeal,
  xchachaOpen,
  ed25519Sign,
  toBase64Url,
  concatBytes,
  utf8ToBytes,
  type RawKeyPair,
} from "@vault/crypto-core";
import type { Base64Url, VaultIdentityRecord } from "@vault/protocol";
import { VaultError } from "@vault/protocol";
import type {
  AuthRequest,
  ConsentAdapter,
  ConsentDecision,
  ConsentRequest,
  IdentityResolver,
  KeystoreAdapter,
  RevocationChecker,
  StorageAdapter,
} from "./adapters.js";

const PACK_VERSION = 0x01;

export interface InMemoryKeystoreOptions {
  /** Decide each biometric prompt. Default: always approve. */
  authResponder?: (req: AuthRequest) => boolean | Promise<boolean>;
  startsLocked?: boolean;
  vaultId?: string;
}

export class InMemoryKeystore implements KeystoreAdapter {
  private readonly masterDek: Uint8Array;
  private readonly device: RawKeyPair;
  private readonly id: string;
  private readonly authResponder: (req: AuthRequest) => boolean | Promise<boolean>;
  private unlocked: boolean;

  constructor(opts: InMemoryKeystoreOptions = {}) {
    this.masterDek = randomBytes(32);
    this.device = ed25519Generate();
    this.id = opts.vaultId ?? toBase64Url(randomBytes(16));
    this.authResponder = opts.authResponder ?? (() => true);
    this.unlocked = !opts.startsLocked;
  }

  isUnlocked(): boolean {
    return this.unlocked;
  }

  async unlock(req?: AuthRequest): Promise<boolean> {
    if (this.unlocked) return true;
    const ok = await this.authResponder(req ?? { reason: "unlock", prompt: "Unlock your vault" });
    if (ok) this.unlocked = true;
    return ok;
  }

  lock(): void {
    this.unlocked = false;
  }

  async authenticate(req: AuthRequest): Promise<boolean> {
    return this.authResponder(req);
  }

  private nsKey(storageKey: string): Uint8Array {
    if (!this.unlocked) throw VaultError.of("VaultLocked");
    const salt = sha256(utf8ToBytes(`vault-ns-salt|${storageKey}`));
    const info = utf8ToBytes(`vault-ns/v1|${storageKey}`);
    return hkdfSha256(this.masterDek, salt, info, 32);
  }

  async sealNamespace(storageKey: string, aad: Uint8Array, plaintext: Uint8Array): Promise<Uint8Array> {
    const key = this.nsKey(storageKey);
    const nonce = randomBytes(24);
    const box = xchachaSeal(key, nonce, plaintext, aad);
    return concatBytes(new Uint8Array([PACK_VERSION]), box.nonce, box.tag, box.ciphertext);
  }

  async openNamespace(storageKey: string, aad: Uint8Array, blob: Uint8Array): Promise<Uint8Array | null> {
    const key = this.nsKey(storageKey);
    if (blob.length < 1 + 24 + 16 || blob[0] !== PACK_VERSION) return null;
    const nonce = blob.subarray(1, 25);
    const tag = blob.subarray(25, 41);
    const ct = blob.subarray(41);
    return xchachaOpen(key, nonce, ct, tag, aad);
  }

  deviceKeyPublic(): Base64Url {
    return toBase64Url(this.device.publicKey);
  }

  async signDevice(bytes: Uint8Array): Promise<Base64Url> {
    return toBase64Url(ed25519Sign(bytes, this.device.privateKey));
  }

  vaultId(): string {
    return this.id;
  }
}

export class InMemoryStorage implements StorageAdapter {
  private readonly map = new Map<string, Uint8Array>();

  async get(key: string): Promise<Uint8Array | null> {
    return this.map.get(key) ?? null;
  }
  async put(key: string, value: Uint8Array): Promise<void> {
    this.map.set(key, value);
  }
  async delete(key: string): Promise<void> {
    this.map.delete(key);
  }
  async listKeys(prefix: string): Promise<string[]> {
    return [...this.map.keys()].filter((k) => k.startsWith(prefix));
  }
}

/** Static identity resolver: a registry of domain -> record. Absence = fetch fail. */
export class StaticIdentityResolver implements IdentityResolver {
  private readonly records = new Map<string, VaultIdentityRecord>();

  set(record: VaultIdentityRecord): void {
    this.records.set(record.domain, record);
  }
  remove(domain: string): void {
    this.records.delete(domain);
  }
  async resolve(domain: string): Promise<VaultIdentityRecord | null> {
    return this.records.get(domain) ?? null;
  }
}

/** In-memory revocation checker: a set of revoked `<statusEndpoint>|<kid>` keys. */
export class StaticRevocationChecker implements RevocationChecker {
  private readonly revoked = new Set<string>();

  revoke(statusEndpoint: string, kid: string): void {
    this.revoked.add(`${statusEndpoint}|${kid}`);
  }
  async isRevoked(statusEndpoint: string, kid: string): Promise<boolean> {
    return this.revoked.has(`${statusEndpoint}|${kid}`);
  }
}

/** Auto-approving consent adapter for tests; can be configured to deny/narrow. */
export class AutoConsent implements ConsentAdapter {
  constructor(
    private readonly decide: (req: ConsentRequest) => ConsentDecision | Promise<ConsentDecision> = () => ({
      approved: true,
    }),
  ) {}
  async requestConnect(req: ConsentRequest): Promise<ConsentDecision> {
    return this.decide(req);
  }
}
