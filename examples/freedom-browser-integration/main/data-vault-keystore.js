/**
 * Data-Vault Keystore (Freedom Browser integration, main process)
 *
 * A KeystoreAdapter for VAULT's engine that derives its master DEK from the
 * browser's ALREADY-UNLOCKED identity mnemonic — so the user's single unlock of
 * the browser's identity vault also unlocks the data vault ("one unlock",
 * integration decision #2). The data-vault DEK is domain-separated from every
 * wallet key via HKDF, so it can never coincide with a signing key.
 *
 * This is REFERENCE glue for `solardev-xyz/freedom-browser`. It is written in the
 * browser's style (CommonJS, JSDoc, `[Component]` logs) and is meant to be copied
 * into `src/main/` there. It is not wired into the Vault3r monorepo build.
 *
 * Trust model: in Option B the Electron main process supplies the caller's origin
 * authoritatively, so VAULT runs in TRUSTED host mode (engine.connectLocal +
 * local* data plane) — no relay, no per-request signatures. This keystore
 * therefore only needs the sealing + unlock surface; the device-signing methods
 * exist to satisfy the adapter interface and are derived deterministically.
 */

const {
  hkdfSha256,
  sha256,
  ed25519PublicFromSeed,
  ed25519Sign,
  xchachaSeal,
  xchachaOpen,
  toBase64Url,
  toHex,
  concatBytes,
  utf8ToBytes,
  randomBytes,
} = require('@vault/crypto-core');

const PACK_VERSION = 0x01;

// Domain-separation labels. Changing any of these re-keys existing data, so treat
// them as a storage format constant.
const DEK_SALT = 'vault3r/data-vault/dek/salt/v1';
const DEK_INFO = 'vault3r/data-vault/dek/v1';
const DEVICE_INFO = 'vault3r/data-vault/device-ed25519-seed/v1';
const VAULTID_INFO = 'vault3r/data-vault/vault-id/v1';

/**
 * @typedef {Object} IdentityVaultBridge
 * @property {() => boolean} isUnlocked      Whether the browser identity vault is unlocked.
 * @property {() => (string|null)} getMnemonic  The unlocked mnemonic, or null when locked.
 * @property {() => Promise<boolean>} [ensureUnlocked]  Optional: prompt the user to unlock.
 */

class DataVaultKeystore {
  /**
   * @param {IdentityVaultBridge} identityVault  Thin bridge over src/main/identity/vault.js.
   */
  constructor(identityVault) {
    this._identity = identityVault;
    /** @type {Uint8Array|null} */
    this._masterDek = null;
    /** @type {{ publicKey: Uint8Array, privateKey: Uint8Array }|null} */
    this._device = null;
    /** @type {string|null} */
    this._vaultId = null;
  }

  /**
   * Derive (once per unlock) all key material from the unlocked mnemonic. Called
   * lazily by every operation; throws VaultLocked-style if the identity vault is
   * locked. The mnemonic never leaves this process and is never persisted here.
   * @private
   */
  _material() {
    if (!this._identity.isUnlocked()) {
      const err = new Error('The vault is locked.');
      err.code = 4312; // ErrorCode.VaultLocked
      throw err;
    }
    const mnemonic = this._identity.getMnemonic();
    if (!mnemonic) {
      const err = new Error('The vault is locked.');
      err.code = 4312;
      throw err;
    }
    // Re-derive if we have not yet, or if the mnemonic changed (account switch).
    const ikm = utf8ToBytes(mnemonic);
    const fingerprint = toHex(sha256(ikm));
    if (!this._masterDek || this._fingerprint !== fingerprint) {
      this._masterDek = hkdfSha256(ikm, utf8ToBytes(DEK_SALT), utf8ToBytes(DEK_INFO), 32);
      // Deterministic device key from the same seed (kept even though trusted mode
      // doesn't sign settle payloads — the adapter contract requires it).
      const deviceSeed = hkdfSha256(ikm, utf8ToBytes(DEK_SALT), utf8ToBytes(DEVICE_INFO), 32);
      this._device = { privateKey: deviceSeed, publicKey: ed25519PublicFromSeed(deviceSeed) };
      const idBytes = hkdfSha256(ikm, utf8ToBytes(DEK_SALT), utf8ToBytes(VAULTID_INFO), 16);
      this._vaultId = 'fbvault_' + toHex(idBytes);
      this._fingerprint = fingerprint;
    }
    return this._masterDek;
  }

  // --- KeystoreAdapter surface -------------------------------------------------

  isUnlocked() {
    return this._identity.isUnlocked();
  }

  async unlock() {
    if (this._identity.isUnlocked()) return true;
    if (typeof this._identity.ensureUnlocked === 'function') {
      return this._identity.ensureUnlocked();
    }
    return false;
  }

  lock() {
    // Zeroize the derived material; the browser's identity vault owns the mnemonic.
    if (this._masterDek) this._masterDek.fill(0);
    this._masterDek = null;
    this._device = null;
    this._vaultId = null;
    this._fingerprint = undefined;
  }

  /**
   * Per-op user confirmation. In trusted mode the single unlock covers routine
   * access; sensitive fields and write-policy prompts route here. A host can wire
   * this to a modal. Default: allow while unlocked (one-unlock model).
   * @param {{ reason: string, prompt: string }} _req
   */
  async authenticate(_req) {
    return this.isUnlocked();
  }

  /** @private per-namespace subkey (HKDF over the master DEK), mirroring InMemoryKeystore. */
  _nsKey(storageKey) {
    const master = this._material();
    const salt = sha256(utf8ToBytes(`vault-ns-salt|${storageKey}`));
    const info = utf8ToBytes(`vault-ns/v1|${storageKey}`);
    return hkdfSha256(master, salt, info, 32);
  }

  async sealNamespace(storageKey, aad, plaintext) {
    const key = this._nsKey(storageKey);
    const nonce = randomBytes(24);
    const box = xchachaSeal(key, nonce, plaintext, aad);
    return concatBytes(new Uint8Array([PACK_VERSION]), box.nonce, box.tag, box.ciphertext);
  }

  async openNamespace(storageKey, aad, blob) {
    const key = this._nsKey(storageKey);
    if (blob.length < 1 + 24 + 16 || blob[0] !== PACK_VERSION) return null;
    const nonce = blob.subarray(1, 25);
    const tag = blob.subarray(25, 41);
    const ct = blob.subarray(41);
    return xchachaOpen(key, nonce, ct, tag, aad);
  }

  deviceKeyPublic() {
    this._material();
    return toBase64Url(this._device.publicKey);
  }

  async signDevice(bytes) {
    this._material();
    return toBase64Url(ed25519Sign(bytes, this._device.privateKey));
  }

  vaultId() {
    this._material();
    return this._vaultId;
  }
}

module.exports = { DataVaultKeystore };
