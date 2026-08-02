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
 * REFERENCE glue — copy into `src/main/vault/` there and add the channels to
 * `src/shared/ipc-channels.js` (see vault-ipc-channels.js).
 */

const { app, ipcMain } = require('electron');
const path = require('path');
const fs = require('fs');
const CH = require('./vault-ipc-channels');

const PERMISSIONS_FILE = 'vault-permissions.json';

/** @type {Object|null} */
let permissionsCache = null;

function getPermissionsPath() {
  return path.join(app.getPath('userData'), PERMISSIONS_FILE);
}

function loadPermissions() {
  if (permissionsCache !== null) return permissionsCache;
  try {
    const filePath = getPermissionsPath();
    permissionsCache = fs.existsSync(filePath) ? JSON.parse(fs.readFileSync(filePath, 'utf-8')) : {};
  } catch (err) {
    console.error('[DataVaultPermissions] Failed to load:', err);
    permissionsCache = {};
  }
  return permissionsCache;
}

function savePermissions() {
  try {
    fs.writeFileSync(getPermissionsPath(), JSON.stringify(permissionsCache, null, 2), { mode: 0o600 });
  } catch (err) {
    console.error('[DataVaultPermissions] Failed to save:', err);
  }
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
 * @param {string} namespace
 * @param {{ origin: string, appMetadata?: object, methods: string[], fields: object[], writePolicy?: string }} grant
 */
function grantPermission(namespace, grant, now) {
  const permissions = loadPermissions();
  const record = {
    namespace,
    origin: grant.origin,
    appMetadata: grant.appMetadata || {},
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
}

module.exports = {
  loadPermissions,
  getPermission,
  grantPermission,
  revokePermission,
  getAllPermissions,
  updateLastUsed,
  registerDataVaultPermissionsIpc,
  _resetCache,
};
