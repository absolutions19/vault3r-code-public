/**
 * Data-Vault Storage (Freedom Browser integration, main process)
 *
 * A StorageAdapter for VAULT's engine that persists each namespace's SEALED blob
 * (opaque ciphertext produced by DataVaultKeystore.sealNamespace) as a file under
 * the browser's userData directory. The engine's anti-rollback document store
 * layers version + manifest checks on top; this adapter only moves bytes.
 *
 * REFERENCE glue for `solardev-xyz/freedom-browser` — copy into `src/main/`.
 * The engine chooses its own storage keys (`manifest`, `doc:<hex>`), so keys are
 * NOT all bare hex. We map each key to a filesystem-safe filename with a
 * reversible encoding (percent-encoding), so `listKeys` can recover the exact
 * key, and guard against path traversal defensively.
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

  /** @private Resolve a storage key to a file path via a reversible safe encoding. */
  _pathFor(key) {
    if (typeof key !== 'string' || key.length === 0 || key.length > 512) {
      throw new Error(`[DataVaultStorage] invalid storage key: ${key}`);
    }
    // encodeURIComponent yields only [A-Za-z0-9-_.!~*'()%] — no '/', no '\', no
    // ':' — so the basename can never contain a path separator or traverse out.
    const p = path.join(this._root, `${encodeURIComponent(key)}.bin`);
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
      .map((f) => decodeURIComponent(f.slice(0, -4)))
      .filter((k) => k.startsWith(prefix));
  }

  /** On-disk size in bytes of a single sealed blob (0 if absent). */
  async byteSize(key) {
    try {
      const st = await fs.promises.stat(this._pathFor(key));
      return st.size;
    } catch (err) {
      if (err && err.code === 'ENOENT') return 0;
      throw err;
    }
  }

  /** Total on-disk bytes across every sealed blob (docs + manifest). */
  async totalBytes() {
    const entries = await fs.promises.readdir(this._root).catch(() => []);
    let total = 0;
    for (const f of entries) {
      if (!f.endsWith('.bin')) continue;
      try {
        total += (await fs.promises.stat(path.join(this._root, f))).size;
      } catch {
        /* file vanished between readdir and stat — skip */
      }
    }
    return total;
  }
}

module.exports = { DataVaultStorage };
