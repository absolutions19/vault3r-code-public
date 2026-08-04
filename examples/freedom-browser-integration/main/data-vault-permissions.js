/**
 * Data-Vault Permissions (Freedom Browser integration, main process)
 *
 * Remembers which origins the user has granted a data vault, and the exact
 * per-field grant they approved, so a returning site reconnects WITHOUT
 * re-prompting (integration decisions #1 and #3). This mirrors the browser's
 * existing `src/main/wallet/dapp-permissions.js` file-for-file in shape:
 * origin-keyed JSON, in-memory cache, load/get/grant/revoke/getAll + IPC.
 *
 * NOTE the deliberate naming split: the browser already has an "identity vault"
 * (the mnemonic store). This is the "DATA vault" — site storage — so nothing here
 * touches wallet keys. Keys are the VAULT namespace (from deriveOriginNamespace),
 * which is transport-stable for ENS names via the browser's getPermissionKey.
 *
 * ENCRYPTED AT REST via Electron `safeStorage` (Keychain / DPAPI / libsecret).
 *
 * What lives in this file is a list of every site you hold data for, with grants,
 * timestamps and pinned icons — a browsing-history-shaped artifact. `0600` keeps
 * other *users* out, but not backups (Time Machine, iCloud, OneDrive all sync app
 * data), disk clones, or a powered-off machine without FDE.
 *
 * It is deliberately NOT sealed under the vault DEK: that key only exists while
 * the mnemonic is unlocked, and this store must still be READABLE while the vault
 * is locked: the remembered-grant lookup in `_decideConsent` runs before the
 * engine's unlock check, and `openSite` resolves a launcher tile to its origin.
 * (The UI shows none of this while locked — both the Data pane and the launcher
 * render an unlock prompt instead — but that is a display rule, not the reason
 * for the key choice.) `safeStorage` is keyed to the OS user session instead, so
 * we get at-rest encryption with no locked-state cost.
 *
 * What this does and does not buy: it protects at-rest snapshots (backups, clones,
 * other users). It does NOT stop malware running as you — unlocked it can read the
 * plaintext or drive the IPC; locked it can wait. And the sealed-blob directory
 * still leaks by shape: filenames are `doc:<sha256(namespace)>.bin`, an unsalted
 * hash of a low-entropy input, so someone with the folder can confirm guesses from
 * a domain wordlist and read per-site sizes from `stat`. Closing that needs
 * key-derived filenames and size padding — see SECURITY.md.
 *
 * REFERENCE glue — copy into `src/main/vault/` there and add the channels to
 * `src/shared/ipc-channels.js` (see vault-ipc-channels.js).
 */

const { app, ipcMain } = require('electron');
const path = require('path');
const fs = require('fs');
const CH = require('./vault-ipc-channels');

const PERMISSIONS_FILE = 'vault-permissions.enc';
/** Pre-encryption file, migrated on first load and then deleted. */
const LEGACY_PERMISSIONS_FILE = 'vault-permissions.json';

// A 4-byte header makes the on-disk form self-describing, so a machine that gains
// (or loses) keychain support later can still read what it wrote before.
const MAGIC_ENCRYPTED = Buffer.from('VLT1');
const MAGIC_PLAINTEXT = Buffer.from('VLT0');

/** @type {Object|null} */
let permissionsCache = null;
/** Set when a file exists but could not be read — never silently overwrite it. */
let loadFailed = false;
let warnedNoEncryption = false;

function getPermissionsPath() {
  return path.join(app.getPath('userData'), PERMISSIONS_FILE);
}
function getLegacyPermissionsPath() {
  return path.join(app.getPath('userData'), LEGACY_PERMISSIONS_FILE);
}

/**
 * Electron's OS-keychain encryptor, or null when unavailable. On Linux this
 * depends on the desktop keyring; `isEncryptionAvailable()` returning false means
 * the `basic_text` backend, which is not meaningfully encrypted — we refuse to
 * pretend and fall back to a clearly-labelled plaintext file instead.
 * @returns {{ encryptString: Function, decryptString: Function }|null}
 */
function encryptor() {
  try {
    // eslint-disable-next-line global-require
    const { safeStorage } = require('electron');
    if (safeStorage && typeof safeStorage.isEncryptionAvailable === 'function' && safeStorage.isEncryptionAvailable()) {
      return safeStorage;
    }
  } catch {
    /* not running under Electron (tests) */
  }
  if (!warnedNoEncryption) {
    warnedNoEncryption = true;
    console.warn('[DataVaultPermissions] OS encryption unavailable — the permission store will be written in plaintext.');
  }
  return null;
}

/** @private Decode a file written by savePermissions(). Throws if unreadable. */
function decodeFile(buf) {
  const header = buf.subarray(0, 4);
  if (header.equals(MAGIC_ENCRYPTED)) {
    const safe = encryptor();
    if (!safe) throw new Error('file is encrypted but OS encryption is unavailable');
    return JSON.parse(safe.decryptString(buf.subarray(4)));
  }
  if (header.equals(MAGIC_PLAINTEXT)) return JSON.parse(buf.subarray(4).toString('utf-8'));
  throw new Error('unrecognized permission store format');
}

function loadPermissions() {
  if (permissionsCache !== null) return permissionsCache;
  const filePath = getPermissionsPath();
  const legacyPath = getLegacyPermissionsPath();

  try {
    if (fs.existsSync(filePath)) {
      permissionsCache = decodeFile(fs.readFileSync(filePath));
    } else if (fs.existsSync(legacyPath)) {
      // One-time migration off the old plaintext file.
      permissionsCache = JSON.parse(fs.readFileSync(legacyPath, 'utf-8'));
      savePermissions();
      fs.unlinkSync(legacyPath);
      console.log('[DataVaultPermissions] Migrated the plaintext store to encrypted storage.');
    } else {
      permissionsCache = {};
    }
  } catch (err) {
    // Losing the keychain entry (or moving the profile between machines) must not
    // silently drop every grant: keep the file, start empty, and make savePermissions
    // preserve the original alongside the new one.
    console.error('[DataVaultPermissions] Failed to load:', err);
    loadFailed = true;
    permissionsCache = {};
  }
  return permissionsCache;
}

function savePermissions() {
  try {
    const filePath = getPermissionsPath();
    if (loadFailed && fs.existsSync(filePath)) {
      const kept = `${filePath}.unreadable`;
      fs.renameSync(filePath, kept);
      console.warn(`[DataVaultPermissions] Kept the unreadable store at ${kept}`);
      loadFailed = false;
    }
    const json = JSON.stringify(permissionsCache, null, 2);
    const safe = encryptor();
    const payload = safe
      ? Buffer.concat([MAGIC_ENCRYPTED, safe.encryptString(json)])
      : Buffer.concat([MAGIC_PLAINTEXT, Buffer.from(json, 'utf-8')]);
    fs.writeFileSync(filePath, payload, { mode: 0o600 });
  } catch (err) {
    console.error('[DataVaultPermissions] Failed to save:', err);
  }
}

/**
 * Replace the whole permission map (import/restore). Used by `importAll` so a
 * restored vault reconnects its sites silently instead of re-prompting for every
 * one — and so the "Data" pane, which enumerates by grant, can see the data at all.
 * @param {Object} map
 */
function replaceAll(map) {
  permissionsCache = map && typeof map === 'object' ? map : {};
  savePermissions();
  return Object.keys(permissionsCache).length;
}

/**
 * @param {string} namespace  The VAULT namespace (permission key).
 * @returns {Object|null} The stored grant record, or null.
 */
function getPermission(namespace) {
  return loadPermissions()[namespace] || null;
}

/**
 * Persist the exact grant the user approved at the consent prompt.
 *
 * NOTE on `icon`: the tile icon a site supplied at connect is pinned HERE, next
 * to the grant, and only ever rewritten when the user consents again. That makes
 * it trust-on-first-use: a site cannot silently restyle its own tile after the
 * fact to impersonate another. The manager validates and re-encodes the bytes
 * (data-vault-icon.js) before they reach this function.
 *
 * @param {string} namespace
 * @param {{ origin: string, appMetadata?: object, icon?: object|null, methods: string[], fields: object[], writePolicy?: string }} grant
 */
function grantPermission(namespace, grant, now) {
  const permissions = loadPermissions();
  const previous = permissions[namespace];
  const record = {
    namespace,
    origin: grant.origin,
    appMetadata: grant.appMetadata || {},
    // Keep the previously pinned icon when this consent supplied none.
    icon: grant.icon !== undefined ? grant.icon : previous?.icon ?? null,
    methods: grant.methods,
    fields: grant.fields,
    writePolicy: grant.writePolicy || 'ask-once-per-session',
    connectedAt: permissions[namespace]?.connectedAt ?? now,
    lastUsed: now,
  };
  permissions[namespace] = record;
  permissionsCache = permissions;
  savePermissions();
  console.log('[DataVaultPermissions] Granted:', namespace);
  return record;
}

/**
 * Revoke a site's data-vault permission. The manager also tears down any live
 * session so in-flight access stops immediately (see data-vault-manager.js).
 * @param {string} namespace
 */
function revokePermission(namespace) {
  const permissions = loadPermissions();
  if (permissions[namespace]) {
    delete permissions[namespace];
    permissionsCache = permissions;
    savePermissions();
    console.log('[DataVaultPermissions] Revoked:', namespace);
    return true;
  }
  return false;
}

function getAllPermissions() {
  return Object.values(loadPermissions()).sort((a, b) => (b.lastUsed || 0) - (a.lastUsed || 0));
}

function updateLastUsed(namespace, now) {
  const permissions = loadPermissions();
  if (permissions[namespace]) {
    permissions[namespace].lastUsed = now;
    permissionsCache = permissions;
    savePermissions();
    return true;
  }
  return false;
}

/**
 * Register the management IPC handlers (for the browser's own settings UI).
 * The per-site connect/data channels live in data-vault-manager.js.
 * @param {(namespace: string) => void} [onRevoke]  Called so the manager can drop the live session.
 */
function registerDataVaultPermissionsIpc(onRevoke) {
  ipcMain.handle(CH.VAULT_GET_ALL_PERMISSIONS, () => getAllPermissions());
  ipcMain.handle(CH.VAULT_REVOKE_PERMISSION, (_event, namespace) => {
    const ok = revokePermission(namespace);
    if (ok && typeof onRevoke === 'function') onRevoke(namespace);
    return ok;
  });
  console.log('[DataVaultPermissions] IPC handlers registered');
}

function _resetCache() {
  permissionsCache = null;
  loadFailed = false;
}

module.exports = {
  loadPermissions,
  getPermission,
  grantPermission,
  revokePermission,
  getAllPermissions,
  updateLastUsed,
  replaceAll,
  registerDataVaultPermissionsIpc,
  _resetCache,
};
