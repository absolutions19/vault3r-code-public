/**
 * Data-Vault Storage (Freedom Browser integration, main process)
 *
 * A StorageAdapter for VAULT's engine that persists each namespace's SEALED blob
 * (opaque ciphertext produced by DataVaultKeystore.sealNamespace) as a file under
 * the browser's userData directory. The engine's anti-rollback document store
 * layers version + manifest checks on top; this adapter only moves bytes.
 *
 * REFERENCE glue for `solardev-xyz/freedom-browser` — copy into `src/main/`.
 * Storage keys are hex SHA-256 (see deriveOriginNamespace), so they are safe
 * filenames; we still guard against path traversal defensively.
 */

const fs = require('fs');
const path = require('path');

const DIR_NAME = 'vault-data'; // under app.getPath('userData')

class DataVaultStorage {
  /**
   * @param {string} dataDir  Absolute path, typically app.getPath('userData').
   */
  constructor(dataDir) {
    this._root = path.join(dataDir, DIR_NAME);
    if (!fs.existsSync(this._root)) {
      fs.mkdirSync(this._root, { recursive: true });
    }
  }

  /** @private Resolve a storage key to a file path, rejecting anything non-hex. */
  _pathFor(key) {
    if (typeof key !== 'string' || !/^[0-9a-f]{1,128}$/.test(key)) {
      throw new Error(`[DataVaultStorage] invalid storage key: ${key}`);
    }
    const p = path.join(this._root, `${key}.bin`);
    // Defense-in-depth: the resolved path must stay inside the root.
    if (path.dirname(p) !== this._root) {
      throw new Error('[DataVaultStorage] path traversal blocked');
    }
    return p;
  }

  /** @returns {Promise<Uint8Array|null>} */
  async get(key) {
    const p = this._pathFor(key);
    try {
      const buf = await fs.promises.readFile(p);
      return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
    } catch (err) {
      if (err && err.code === 'ENOENT') return null;
      throw err;
    }
  }

  async put(key, value) {
    const p = this._pathFor(key);
    // Atomic replace: write to a temp file then rename, so a crash mid-write can
    // never leave a half-sealed blob the engine would reject.
    const tmp = `${p}.tmp`;
    await fs.promises.writeFile(tmp, Buffer.from(value.buffer, value.byteOffset, value.byteLength), {
      mode: 0o600,
    });
    await fs.promises.rename(tmp, p);
  }

  async delete(key) {
    const p = this._pathFor(key);
    try {
      await fs.promises.unlink(p);
    } catch (err) {
      if (!err || err.code !== 'ENOENT') throw err;
    }
  }

  async listKeys(prefix) {
    const entries = await fs.promises.readdir(this._root).catch(() => []);
    return entries
      .filter((f) => f.endsWith('.bin'))
      .map((f) => f.slice(0, -4))
      .filter((k) => k.startsWith(prefix));
  }
}

module.exports = { DataVaultStorage };
