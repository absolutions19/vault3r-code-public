/**
 * Data-Vault Manager (Freedom Browser integration, main process)
 *
 * The single VAULT host for the browser. Owns one VaultEngine in TRUSTED host
 * mode (Option B) and routes each page's `window.vault` requests to it. The
 * authoritative origin comes from `event.senderFrame.url` — NEVER from anything
 * the page sends — which is what makes per-origin isolation real: the page cannot
 * name another site's namespace.
 *
 * Security responsibilities that live HERE (not in the engine):
 *  - Derive the authoritative origin from the sender frame and map it to a VAULT
 *    namespace via deriveOriginNamespace.
 *  - Bind every session to the webContents that created it, so one tab/page can
 *    never drive another's session (the engine trusts the sessionId it is given).
 *  - Remember approved grants (data-vault-permissions.js) so a returning site
 *    reconnects without a prompt (decisions #1/#3), and tear down live sessions
 *    when the user revokes.
 *
 * REFERENCE glue for `solardev-xyz/freedom-browser` — copy into `src/main/vault/`.
 * Follow the architecture-boundaries + new-IPC-channel playbooks when wiring it.
 */

const { ipcMain, dialog } = require('electron');
const fs = require('fs');
const { VaultEngine } = require('@vault/vault-core');
const { deriveOriginNamespace, storageKeyForNamespace } = require('@vault/crypto-core');
const CH = require('./vault-ipc-channels');
const perms = require('./data-vault-permissions');
const { DataVaultKeystore } = require('./data-vault-keystore');
const { DataVaultStorage } = require('./data-vault-storage');

// VAULT method names (mirror @vault/protocol Method).
const M = {
  connect: 'vault_connect',
  getData: 'vault_getData',
  setData: 'vault_setData',
  patchData: 'vault_patchData',
  subscribe: 'vault_subscribe',
  unsubscribe: 'vault_unsubscribe',
  revoke: 'vault_revoke',
  getPermissions: 'vault_getPermissions',
};

class DataVaultManager {
  /**
   * @param {object} deps
   * @param {string} deps.dataDir  app.getPath('userData').
   * @param {import('./data-vault-keystore').IdentityVaultBridge} deps.identityVault
   * @param {(payload: object) => Promise<object>} deps.promptConsent
   *   Show the per-site / per-field consent sheet; resolve to
   *   { approved, grantedMethods?, grantedFields?, writePolicy?, reason? }.
   * @param {() => number} [deps.now]  Injectable clock (tests).
   */
  constructor({ dataDir, identityVault, promptConsent, now }) {
    this._now = now || (() => Date.now());
    this._promptConsent = promptConsent;
    this._storage = new DataVaultStorage(dataDir);
    this._keystore = new DataVaultKeystore(identityVault);

    // Per-connect consent: consult the remembered grant first; only prompt when a
    // site connects for the first time or asks for more than it was granted.
    const consent = {
      requestConnect: (req) => this._decideConsent(req),
    };

    this._engine = new VaultEngine({
      keystore: this._keystore,
      storage: this._storage,
      // The trusted path never calls the resolver/relay; a stub satisfies the type.
      resolver: { resolve: async () => null },
      consent,
      clock: { now: this._now },
    });

    /** sessionId -> { namespace, origin, webContentsId } — the session/tab binding. */
    this._sessions = new Map();
    /** namespace -> the consent request currently in flight (dedupe double-connect). */
    this._pendingByNamespace = new Map();

    this._engine.setEmitter((sessionId, notification) => this._emit(sessionId, notification));
  }

  // --- lifecycle ---------------------------------------------------------------

  register() {
    // Site-facing provider path (untrusted pages via window.vault).
    ipcMain.handle(CH.VAULT_PROVIDER_REQUEST, (event, msg) => this._onRequest(event, msg));
    ipcMain.handle(CH.VAULT_IMPORT, (_event, bundle) => this.importAll(bundle));
    // Revoking a permission from the settings UI must also kill any live session.
    perms.registerDataVaultPermissionsIpc((namespace) => this._teardownNamespace(namespace));

    // Owner-facing management path (trusted wallet UI only — the "Data" pane).
    // These are on the main-window preload, NEVER reachable from a site.
    ipcMain.handle(CH.VAULT_LIST_PARTITIONS, () => this.listPartitions());
    ipcMain.handle(CH.VAULT_USAGE, () => this.getUsage());
    ipcMain.handle(CH.VAULT_GET_PARTITION_DATA, (_e, namespace) => this.getPartitionData(namespace));
    ipcMain.handle(CH.VAULT_DELETE_PARTITION, (_e, namespace) => this.deletePartition(namespace));
    ipcMain.handle(CH.VAULT_CLEAR_ALL, () => this.clearAll());
    ipcMain.handle(CH.VAULT_EXPORT, () => this.exportToFile());
    console.log('[DataVaultManager] registered');
  }

  // --- request routing ---------------------------------------------------------

  /** @private The authoritative origin of the calling frame (never page-supplied). */
  _originOf(event) {
    const frame = event.senderFrame;
    const url = frame && frame.url ? frame.url : event.sender.getURL();
    return originForNamespace(url);
  }

  /** @private */
  async _onRequest(event, { method, params }) {
    try {
      const origin = this._originOf(event);
      if (!origin) throw rpcError(4100, 'no authoritative origin for caller');

      if (method === M.connect) {
        return ok(await this._connect(event, origin, params || {}));
      }
      // All data-plane methods carry a sessionId that MUST belong to this frame.
      const sessionId = params && params.sessionId;
      this._requireOwnedSession(event, origin, sessionId);

      switch (method) {
        case M.getData:
          return ok(await this._engine.localGet(sessionId, params.paths || []));
        case M.setData:
          return ok(await this._engine.localSet(sessionId, params.values || {}, params.baseVersion));
        case M.patchData:
          return ok(await this._engine.localPatch(sessionId, params.ops || [], params.baseVersion));
        case M.subscribe:
          return ok(await this._engine.localSubscribe(sessionId, params.paths || []));
        case M.unsubscribe:
          return ok(await this._engine.localUnsubscribe(sessionId, params.subscriptionId));
        case M.revoke: {
          const r = await this._engine.localRevoke(sessionId);
          this._sessions.delete(sessionId);
          return ok(r);
        }
        case M.getPermissions:
          return ok(await this._engine.localGetPermissions(sessionId));
        default:
          throw rpcError(4200, `method not supported: ${method}`);
      }
    } catch (err) {
      return { error: toRpcError(err) };
    }
  }

  /** @private Reject a sessionId that isn't bound to this exact frame/origin. */
  _requireOwnedSession(event, origin, sessionId) {
    const rec = sessionId && this._sessions.get(sessionId);
    if (!rec || rec.webContentsId !== event.sender.id || rec.origin !== origin) {
      throw rpcError(4900, 'unknown or unauthorized session');
    }
    return rec;
  }

  /** @private */
  async _connect(event, origin, params) {
    const derived = deriveOriginNamespace(origin); // throws on a non-authoritative origin
    const result = await this._engine.connectLocal({
      origin,
      appMetadata: params.appMetadata || {},
      requestedScopes: params.requestedScopes || [],
    });
    this._sessions.set(result.sessionId, {
      namespace: derived.namespace,
      origin,
      webContentsId: event.sender.id,
    });
    perms.updateLastUsed(derived.namespace, this._now());
    return { sessionId: result.sessionId, grant: result.grant, namespace: result.namespace };
  }

  /**
   * @private VaultEngine consent hook. Auto-approves from a remembered grant when
   * the site asks for no more than it was granted; otherwise shows the prompt and
   * persists the user's decision.
   */
  async _decideConsent(req) {
    const namespace = req.verification.namespace;
    const requestedMethods = uniqMethods(req.requestedScopes);
    const requestedFields = flattenFields(req.requestedScopes);

    const remembered = perms.getPermission(namespace);
    if (remembered && covers(remembered, requestedMethods, requestedFields)) {
      return {
        approved: true,
        grantedMethods: remembered.methods,
        grantedFields: remembered.fields,
        writePolicy: remembered.writePolicy,
      };
    }

    // First connect (or an escalation): ask the user. Dedupe concurrent prompts.
    if (this._pendingByNamespace.has(namespace)) {
      return this._pendingByNamespace.get(namespace);
    }
    const p = (async () => {
      const decision = await this._promptConsent({
        origin: req.verification.domain,
        namespace,
        appMetadata: req.appMetadata,
        requestedScopes: req.requestedScopes,
        previousGrant: remembered || null,
      });
      if (decision && decision.approved) {
        perms.grantPermission(
          namespace,
          {
            origin: req.verification.domain,
            appMetadata: req.appMetadata,
            methods: decision.grantedMethods || requestedMethods,
            fields: decision.grantedFields || requestedFields,
            writePolicy: decision.writePolicy,
          },
          this._now(),
        );
      }
      return decision || { approved: false, reason: 'no decision' };
    })();
    this._pendingByNamespace.set(namespace, p);
    try {
      return await p;
    } finally {
      this._pendingByNamespace.delete(namespace);
    }
  }

  /** @private Push a subscription / permissions_changed notification to the page. */
  _emit(sessionId, notification) {
    const rec = this._sessions.get(sessionId);
    if (!rec) return;
    const wc = webContentsById(rec.webContentsId);
    if (wc && !wc.isDestroyed()) {
      wc.send(CH.VAULT_PROVIDER_EVENT, { sessionId, notification });
    }
  }

  /** @private Kill every live session for a namespace (on user revoke). */
  _teardownNamespace(namespace) {
    for (const [sessionId, rec] of this._sessions) {
      if (rec.namespace === namespace) {
        this._engine.adminRevoke(sessionId);
        this._sessions.delete(sessionId);
        const wc = webContentsById(rec.webContentsId);
        if (wc && !wc.isDestroyed()) {
          wc.send(CH.VAULT_PROVIDER_EVENT, {
            sessionId,
            notification: { method: 'vault_permissionsRevoked', params: { namespace } },
          });
        }
      }
    }
  }

  // --- export / import (integration decision #5) -------------------------------

  /**
   * Export every site's data as a portable bundle. The blobs are the SEALED
   * ciphertext exactly as stored, so export never decrypts; a restore on another
   * device only works with the SAME mnemonic (the DEK is derived from it).
   */
  async exportAll() {
    const keys = await this._storage.listKeys('');
    const entries = {};
    for (const key of keys) {
      const blob = await this._storage.get(key);
      if (blob) entries[key] = Buffer.from(blob).toString('base64');
    }
    return {
      format: 'vault3r-data-export/1',
      exportedAt: this._now(),
      permissions: perms.loadPermissions(),
      entries,
    };
  }

  /** Restore a bundle produced by exportAll. Sealed blobs are written verbatim. */
  async importAll(bundle) {
    if (!bundle || bundle.format !== 'vault3r-data-export/1') {
      throw new Error('[DataVaultManager] unrecognized export format');
    }
    for (const [key, b64] of Object.entries(bundle.entries || {})) {
      await this._storage.put(key, new Uint8Array(Buffer.from(b64, 'base64')));
    }
    return { imported: Object.keys(bundle.entries || {}).length };
  }

  // --- owner-facing management API (the "Data" pane) ---------------------------
  //
  // These serve the vault OWNER through the trusted wallet UI. They read/delete
  // by namespace and are wired ONLY to the main-window preload — a website can
  // never reach them.

  /**
   * List every site that has a data partition, with its on-disk size. This is
   * metadata (origins/grants/sizes live in the plaintext permission store + file
   * sizes), so it works even when the vault is locked — only viewing the data
   * inside a partition needs an unlock.
   */
  async listPartitions() {
    const all = perms.getAllPermissions();
    const out = [];
    for (const p of all) {
      const storageKey = storageKeyForNamespace(p.namespace);
      const bytes = await this._storage.byteSize(`doc:${storageKey}`);
      out.push({
        namespace: p.namespace,
        origin: p.origin,
        appName: (p.appMetadata && p.appMetadata.name) || null,
        fields: p.fields || [],
        methods: p.methods || [],
        bytes,
        lastUsed: p.lastUsed || null,
        connectedAt: p.connectedAt || null,
      });
    }
    out.sort((a, b) => b.bytes - a.bytes);
    return out;
  }

  /** Total on-disk storage used by the whole vault, and how many sites. */
  async getUsage() {
    return {
      totalBytes: await this._storage.totalBytes(),
      partitionCount: perms.getAllPermissions().length,
      unlocked: this._keystore.isUnlocked(),
    };
  }

  /** Owner view of one site's stored data. Requires the vault to be unlocked. */
  async getPartitionData(namespace) {
    if (!this._keystore.isUnlocked()) return { namespace, locked: true };
    const storageKey = storageKeyForNamespace(namespace);
    const data = await this._engine.adminReadPartition(storageKey);
    const bytes = await this._storage.byteSize(`doc:${storageKey}`);
    return { namespace, locked: false, data, bytes };
  }

  /** Delete one site's partition: data + manifest entry + grant + live sessions. */
  async deletePartition(namespace) {
    const storageKey = storageKeyForNamespace(namespace);
    const freedBytes = await this._storage.byteSize(`doc:${storageKey}`);
    await this._engine.adminDeletePartition(storageKey); // data + manifest + sessions
    this._teardownNamespace(namespace); // our session/tab bindings + notify pages
    perms.revokePermission(namespace); // forget the remembered grant
    return { deleted: true, namespace, freedBytes };
  }

  /** Delete EVERY site's partition. */
  async clearAll() {
    const all = perms.getAllPermissions();
    let freedBytes = 0;
    for (const p of all) {
      const r = await this.deletePartition(p.namespace);
      freedBytes += r.freedBytes;
    }
    return { cleared: all.length, freedBytes };
  }

  /** Export the whole vault to a user-chosen file (sealed blobs; never decrypted). */
  async exportToFile() {
    const bundle = await this.exportAll();
    const { canceled, filePath } = await dialog.showSaveDialog({
      title: 'Export vault data',
      defaultPath: `vault-export-${this._now()}.json`,
      filters: [{ name: 'Vault export', extensions: ['json'] }],
    });
    if (canceled || !filePath) return { saved: false, canceled: true };
    await fs.promises.writeFile(filePath, JSON.stringify(bundle, null, 2), { mode: 0o600 });
    return { saved: true, path: filePath, partitions: Object.keys(bundle.entries || {}).length };
  }
}

// --- helpers -----------------------------------------------------------------

/**
 * Map a display URL (or the browser's transport-stable permission key) to an
 * origin string deriveOriginNamespace accepts. Kept tiny; the browser's
 * src/shared/origin-utils.js getPermissionKey is the richer, canonical source and
 * should be used in the real integration so VAULT namespaces track permissions.
 * @param {string} url
 * @returns {string|null}
 */
function originForNamespace(url) {
  if (!url || typeof url !== 'string') return null;
  try {
    const u = new URL(url);
    const scheme = u.protocol.replace(/:$/, '').toLowerCase();
    if (scheme === 'http' || scheme === 'https') return `${scheme}://${u.host}`;
    // dweb scheme: origin is scheme + authority (path/query/fragment dropped).
    if (u.host) return `${scheme}://${u.host}`;
    return null;
  } catch {
    return null;
  }
}

function uniqMethods(scopes) {
  const s = new Set();
  for (const sc of scopes || []) for (const m of sc.methods || []) s.add(m);
  return [...s];
}
function flattenFields(scopes) {
  const out = [];
  for (const sc of scopes || []) for (const f of sc.fields || []) out.push(f);
  return out;
}
/** Does a remembered grant cover everything now requested? (method + field paths) */
function covers(remembered, methods, fields) {
  const have = new Set(remembered.methods || []);
  if (!methods.every((m) => have.has(m))) return false;
  const havePaths = new Set((remembered.fields || []).map((f) => f.path));
  return fields.every((f) => havePaths.has(f.path));
}

function ok(result) {
  return { result };
}
function rpcError(code, message) {
  const e = new Error(message);
  e.code = code;
  return e;
}
function toRpcError(err) {
  return { code: (err && err.code) || 4010, message: (err && err.message) || 'error' };
}

// Late-bound so the module loads without electron in unit tests.
function webContentsById(id) {
  try {
    // eslint-disable-next-line global-require
    return require('electron').webContents.fromId(id);
  } catch {
    return null;
  }
}

module.exports = { DataVaultManager, originForNamespace, covers };
