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
const { normalizeIcon, monogramFor, sanitizeName } = require('./data-vault-icon');

/** Schemes the home page is allowed to launch. Anything else (javascript:, file:,
 *  data:, blob:) is rejected — the launcher must never become a way to navigate
 *  the browser somewhere a stored grant didn't come from. */
const LAUNCHABLE_SCHEMES = new Set(['http', 'https', 'ipfs', 'ipns', 'bzz', 'swarm', 'ens', 'ar', 'rad', 'hyper']);

const EXPORT_FORMAT = 'vault3r-data-export/2';
/** Reserved key for vault-owned metadata; distinct from any site's namespace. */
const META_STORAGE_KEY = storageKeyForNamespace('meta:export-permissions');
const META_AAD = `${EXPORT_FORMAT}|permissions`;

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
  requestUnlock: 'vault_requestUnlock',
};

// Methods every grant carries, whatever the site asked for. The engine gates
// `vault_getPermissions` on its own presence in the granted method list, so a
// site that requests only read/write scopes cannot read back the grant it
// already holds — a confusing failure that leaks nothing when allowed, since
// the caller is asking about permissions it was itself given.
const ALWAYS_GRANTED_METHODS = [M.getPermissions];

/**
 * Unlock-prompt policy for `vault_requestUnlock`.
 *
 * The prompt is the host's own unlock screen, so a site that could raise it
 * freely would own a nuisance surface. Holding a live session is the first
 * gate; these bound what a granted site can still do with it. The shape follows
 * Chromium's permission embargo: a dismissal is not a denial, but repeated
 * dismissals stop the asking.
 */
const UNLOCK_COOLDOWN_MS = 60_000;
/** Consecutive dismissals before a namespace stops being able to prompt. */
const UNLOCK_MAX_DISMISSALS = 3;

class DataVaultManager {
  /**
   * @param {object} deps
   * @param {string} deps.dataDir  app.getPath('userData').
   * @param {import('./data-vault-keystore').IdentityVaultBridge} deps.identityVault
   * @param {(payload: object) => Promise<object>} deps.promptConsent
   *   Show the per-site / per-field consent sheet; resolve to
   *   { approved, grantedMethods?, grantedFields?, writePolicy?, reason? }.
   * @param {(url: string) => void} [deps.openUrl]
   *   Navigate the browser to a site the user clicked on the vault home page.
   *   Supplied by the host (freedom-browser's tab API); the manager validates the
   *   namespace and scheme before ever calling it.
   * @param {(event: object) => boolean} [deps.isHomeFrame]
   *   Authoritative check that an owner-plane home-page request really came from
   *   the vault home page — `event.senderFrame.url` matched against the internal
   *   page's file URL. REQUIRED for the `datavault:home-*` channels: if the host
   *   exposes `window.vaultHome` through a preload that web content also loads
   *   (freedom-browser's shared webview preload does), a renderer-side location
   *   check is not a boundary, and enumerating the site list is exactly the
   *   cross-origin history leak the vault exists to prevent. Omit it and those
   *   channels are not registered at all.
   * @param {{ createFromBuffer: Function }} [deps.nativeImage]
   *   Electron's `nativeImage`, used to re-encode site-supplied icons. Omitted in
   *   headless tests, where validated original bytes are kept instead.
   * @param {() => void} [deps.onActivity]
   *   Report that a dapp is actively using the vault, so the host can push out
   *   its auto-lock timer. Supplied by the host (freedom-browser calls
   *   `resetVaultAutoLockTimer`). Without it a site whose only vault traffic is
   *   get/set/patch/subscribe is invisible to the timer and gets locked out
   *   mid-session — the writes themselves being what the timer is meant to
   *   notice. Hosts that gate publishing on the same lock should wire both.
   * @param {() => number} [deps.now]  Injectable clock (tests).
   */
  constructor({ dataDir, identityVault, promptConsent, openUrl, isHomeFrame, nativeImage, onActivity, now }) {
    this._now = now || (() => Date.now());
    this._promptConsent = promptConsent;
    this._openUrl = openUrl || null;
    this._isHomeFrame = typeof isHomeFrame === 'function' ? isHomeFrame : null;
    this._nativeImage = nativeImage || null;
    this._onActivity = typeof onActivity === 'function' ? onActivity : () => {};
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
    /** namespace -> { dismissals, lastPromptAt } for vault_requestUnlock. */
    this._unlockPrompts = new Map();
    /** The unlock prompt in flight, shared by every caller. */
    this._pendingUnlock = null;

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

    // Vault home page (the launcher). Read-only + navigate, nothing destructive.
    // Fail closed: without an authoritative sender check these channels would let
    // ANY frame reachable by the exposing preload enumerate the user's site list.
    if (this._isHomeFrame) {
      const homeOnly = (fn) => (event, ...args) => {
        if (!this._isHomeFrame(event)) {
          throw rpcError(4100, 'vault home API is not available to this frame');
        }
        return fn(...args);
      };
      ipcMain.handle(CH.VAULT_HOME_STATUS, homeOnly(() => this.getHomeStatus()));
      ipcMain.handle(CH.VAULT_HOME_TILES, homeOnly(() => this.listHomeTiles()));
      ipcMain.handle(CH.VAULT_HOME_OPEN, homeOnly((namespace) => this.openSite(namespace)));
      ipcMain.handle(CH.VAULT_HOME_UNLOCK, homeOnly(() => this.requestUnlock()));
    } else {
      console.warn('[DataVaultManager] no isHomeFrame check supplied — home-page channels NOT registered');
    }
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
      const session = this._requireOwnedSession(event, origin, sessionId);

      // Every successful data-plane call is dapp activity. Hosts with an
      // auto-lock timer must hear about it, or using the vault is the one thing
      // that does NOT keep the vault alive.
      const active = (value) => {
        this._onActivity();
        return value;
      };

      switch (method) {
        case M.getData:
          return ok(active(await this._engine.localGet(sessionId, params.paths || [])));
        case M.setData:
          return ok(active(await this._engine.localSet(sessionId, params.values || {}, params.baseVersion)));
        case M.patchData:
          return ok(active(await this._engine.localPatch(sessionId, params.ops || [], params.baseVersion)));
        case M.subscribe:
          return ok(active(await this._engine.localSubscribe(sessionId, params.paths || [])));
        case M.unsubscribe:
          return ok(active(await this._engine.localUnsubscribe(sessionId, params.subscriptionId)));
        case M.revoke: {
          const r = await this._engine.localRevoke(sessionId);
          this._sessions.delete(sessionId);
          return ok(r);
        }
        case M.getPermissions:
          return ok(await this._engine.localGetPermissions(sessionId));
        case M.requestUnlock:
          // Deliberately NOT an engine method and NOT gated on the grant: it
          // asks the user for the host's own unlock screen, it reads and writes
          // nothing, and requiring it in the scope list would reproduce the
          // vault_getPermissions trap — a site cannot request what it did not
          // know to ask for. Holding this session is the authorisation.
          return ok(await this._requestUnlockForSite(session.namespace));
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
        grantedMethods: withAlwaysGranted(remembered.methods),
        grantedFields: remembered.fields,
        writePolicy: remembered.writePolicy,
      };
    }

    // First connect (or an escalation): ask the user. Dedupe concurrent prompts.
    if (this._pendingByNamespace.has(namespace)) {
      return this._pendingByNamespace.get(namespace);
    }
    // Clamp the page's claimed name/icon ONCE, and show the consent sheet the
    // same values the home-page tile will use — the user must approve exactly
    // what they will later see, or the tile becomes a spoofing surface.
    const claimed = this._sanitizeAppMetadata(req.appMetadata);

    const p = (async () => {
      const decision = await this._promptConsent({
        origin: req.verification.domain,
        namespace,
        appMetadata: claimed.appMetadata,
        icon: claimed.icon,
        requestedScopes: req.requestedScopes,
        previousGrant: remembered || null,
      });
      if (decision && decision.approved) {
        const grantedMethods = withAlwaysGranted(decision.grantedMethods || requestedMethods);
        perms.grantPermission(
          namespace,
          {
            origin: req.verification.domain,
            appMetadata: claimed.appMetadata,
            icon: claimed.icon,
            methods: grantedMethods,
            fields: decision.grantedFields || requestedFields,
            writePolicy: decision.writePolicy,
          },
          this._now(),
        );
        return { ...decision, grantedMethods };
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
   *
   * The permission map — the list of every site you hold data for, with grants and
   * pinned icons — is SEALED under the DEK too, in a bundle the user may well drop
   * in cloud storage. (Before v0.5.0 it rode along as cleartext JSON.) Sealing it
   * means export now requires an unlock, which is right: this is the same material
   * the "Data" pane makes you unlock to read.
   */
  async exportAll() {
    if (!this._keystore.isUnlocked()) {
      throw rpcError(4312, 'unlock the vault to export');
    }
    const keys = await this._storage.listKeys('');
    const entries = {};
    for (const key of keys) {
      const blob = await this._storage.get(key);
      if (blob) entries[key] = Buffer.from(blob).toString('base64');
    }
    const sealed = await this._keystore.sealNamespace(
      META_STORAGE_KEY,
      Buffer.from(META_AAD, 'utf-8'),
      Buffer.from(JSON.stringify(perms.loadPermissions()), 'utf-8'),
    );
    return {
      format: EXPORT_FORMAT,
      exportedAt: this._now(),
      permissionsSealed: Buffer.from(sealed).toString('base64'),
      entries,
    };
  }

  /**
   * Restore a bundle produced by exportAll. Sealed blobs are written verbatim, and
   * the sealed permission map is restored so returning sites reconnect silently —
   * without it the "Data" pane, which enumerates by grant, cannot see the restored
   * data at all. Legacy `/1` bundles (cleartext permissions) still import their
   * blobs; their permission map is ignored.
   */
  async importAll(bundle) {
    if (!bundle || (bundle.format !== EXPORT_FORMAT && bundle.format !== 'vault3r-data-export/1')) {
      throw new Error('[DataVaultManager] unrecognized export format');
    }
    for (const [key, b64] of Object.entries(bundle.entries || {})) {
      await this._storage.put(key, new Uint8Array(Buffer.from(b64, 'base64')));
    }
    let restoredGrants = 0;
    if (bundle.permissionsSealed) {
      if (!this._keystore.isUnlocked()) throw rpcError(4312, 'unlock the vault to import');
      const opened = await this._keystore.openNamespace(
        META_STORAGE_KEY,
        Buffer.from(META_AAD, 'utf-8'),
        new Uint8Array(Buffer.from(bundle.permissionsSealed, 'base64')),
      );
      // Fails closed on the wrong mnemonic (or a tampered bundle): the AEAD tag
      // won't verify, so we restore blobs but no grants rather than guessing.
      if (!opened) throw rpcError(4310, 'could not open the exported permissions (wrong vault?)');
      restoredGrants = perms.replaceAll(JSON.parse(Buffer.from(opened).toString('utf-8')));
    }
    return { imported: Object.keys(bundle.entries || {}).length, restoredGrants };
  }

  // --- owner-facing management API (the "Data" pane) ---------------------------
  //
  // These serve the vault OWNER through the trusted wallet UI. They read/delete
  // by namespace and are wired ONLY to the main-window preload — a website can
  // never reach them.

  /**
   * List every site that has a data partition, with its on-disk size.
   *
   * Returns NOTHING while locked. The data is technically available — origins,
   * grants and sizes need no key — but "which sites do you hold data for" is a
   * browsing-history-shaped fact, and showing it beside a locked vault both leaks
   * it to anyone at an unattended browser and reads as though the vault were
   * open. The pane renders an unlock prompt instead, matching the launcher.
   */
  async listPartitions() {
    if (!this._keystore.isUnlocked()) return [];
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

  // --- vault home page (the dApp launcher) -------------------------------------
  //
  // Same owner-plane trust level as the "Data" pane above, wired only to the
  // internal page's preload. The launcher is deliberately READ-ONLY + navigate:
  // delete/revoke/export stay in the Data pane so nothing destructive is one
  // click away on a surface people open constantly.

  /**
   * Whether the grid can be shown at all. Reports NO count while locked: "how
   * many sites do you hold data for" is itself a fact about the user, and the
   * unlock prompt is the whole locked-state UI.
   */
  async getHomeStatus() {
    const unlocked = this._keystore.isUnlocked();
    return unlocked ? { unlocked: true, count: perms.getAllPermissions().length } : { unlocked: false };
  }

  /**
   * The launcher grid: one tile per site holding data, most recently used first.
   *
   * Locked returns no tiles at all. This is a UI boundary, not a cryptographic
   * one — the permission store is encrypted under the OS keychain, which the OS
   * unlocks at login regardless of the vault's own lock state. The point is that
   * whoever walks up to an unattended, locked browser must not be shown a
   * browsing-history-shaped list.
   */
  async listHomeTiles() {
    if (!this._keystore.isUnlocked()) return { locked: true, tiles: [] };
    const tiles = perms.getAllPermissions().map((p) => {
      const name = (p.appMetadata && p.appMetadata.name) || null;
      return {
        namespace: p.namespace,
        name: name || hostOfOrigin(p.origin) || p.namespace,
        host: hostOfOrigin(p.origin),
        // Site-supplied, validated + pinned at consent. Null -> render a monogram.
        icon: p.icon ? p.icon.dataUri : null,
        monogram: monogramFor(p.namespace, name),
        lastUsed: p.lastUsed || null,
      };
    });
    return { locked: false, tiles };
  }

  /**
   * Launch a site from its tile. The page passes only a namespace — never a URL —
   * so the launcher can't be turned into "navigate anywhere": the destination is
   * whatever origin the browser itself observed when the grant was made.
   */
  async openSite(namespace) {
    const record = perms.getPermission(namespace);
    if (!record) return { opened: false, reason: 'unknown namespace' };
    const url = record.origin;
    if (!isLaunchable(url)) return { opened: false, reason: 'origin is not launchable' };
    if (typeof this._openUrl !== 'function') return { opened: false, reason: 'no openUrl host hook' };
    this._openUrl(url);
    return { opened: true, url };
  }

  /** Ask the host to unlock the identity vault (drives the locked-state button). */
  async requestUnlock() {
    const unlocked = await this._keystore.unlock();
    return { unlocked: !!unlocked };
  }

  /**
   * @private Site-facing unlock request (`vault_requestUnlock`).
   *
   * Raises the same unlock screen the home page raises, so a page whose
   * `vault_getData` just failed with 4312 can offer "Unlock" inline instead of
   * narrating where the host keeps its controls — prose that is a guess about
   * someone else's UI and goes stale when that UI moves.
   *
   * Resolves `{ unlocked }` always; `reason` says why when it is false, so a
   * site can tell "the user said no" from "stop asking".
   */
  async _requestUnlockForSite(namespace) {
    if (this._keystore.isUnlocked()) {
      // Seeing it unlocked — by our prompt, the toolbar, or anything else —
      // ends every embargo: the next lock is a new situation, not a
      // continuation of the one the user dismissed.
      this._unlockPrompts.clear();
      return { unlocked: true };
    }

    const state = this._unlockPrompts.get(namespace) || { dismissals: 0, lastPromptAt: 0 };
    if (state.dismissals >= UNLOCK_MAX_DISMISSALS) {
      return { unlocked: false, reason: 'embargoed' };
    }
    const since = this._now() - state.lastPromptAt;
    if (state.lastPromptAt && since < UNLOCK_COOLDOWN_MS) {
      return { unlocked: false, reason: 'cooldown' };
    }

    // One prompt at a time, whoever asks: the vault is global, and two sites
    // racing must not stack two unlock screens on the user.
    if (!this._pendingUnlock) {
      this._pendingUnlock = this.requestUnlock().finally(() => {
        this._pendingUnlock = null;
      });
    }
    state.lastPromptAt = this._now();
    this._unlockPrompts.set(namespace, state);

    const { unlocked } = await this._pendingUnlock;
    if (unlocked) {
      // A successful unlock clears everyone's dismissal count: the user has
      // shown they are willing, and the next lock is a fresh situation.
      this._unlockPrompts.clear();
      return { unlocked: true };
    }
    state.dismissals += 1;
    this._unlockPrompts.set(namespace, state);
    return { unlocked: false, reason: 'dismissed' };
  }

  /**
   * @private Clamp the page's claimed display metadata. Returns the sanitized
   * appMetadata plus the validated/re-encoded icon record (or null).
   */
  _sanitizeAppMetadata(raw) {
    const source = raw && typeof raw === 'object' ? raw : {};
    const name = sanitizeName(source.name);
    const result = normalizeIcon(source.icon, { nativeImage: this._nativeImage });
    if (!result.ok && result.reason !== 'absent') {
      console.warn('[DataVaultManager] rejected site icon:', result.reason);
    }
    return {
      appMetadata: { ...source, name: name || undefined, icon: undefined },
      icon: result.ok ? result.icon : null,
    };
  }

  /**
   * Total on-disk storage used by the whole vault, and how many sites. Reports
   * zeros while locked — the count alone is a fact about the user — but always
   * reports the lock state, which is what tells the pane to show its unlock
   * prompt instead of an empty vault.
   */
  async getUsage() {
    if (!this._keystore.isUnlocked()) return { totalBytes: 0, partitionCount: 0, unlocked: false };
    return {
      totalBytes: await this._storage.totalBytes(),
      partitionCount: perms.getAllPermissions().length,
      unlocked: true,
    };
  }

  /** Owner view of one site's stored data. Requires the vault to be unlocked. */
  async getPartitionData(namespace) {
    if (!this._keystore.isUnlocked()) return { namespace, locked: true };
    const storageKey = storageKeyForNamespace(namespace);
    const bytes = await this._storage.byteSize(`doc:${storageKey}`);
    let data;
    try {
      data = await this._engine.adminReadPartition(storageKey);
    } catch (err) {
      // A blob that will not open is a state the pane must describe, not an
      // exception to swallow into "Error: …". The engine names the cause when it
      // can (see DocumentStore's owner fingerprint): sealed by a different
      // identity, corrupt under this one, or unknown for stores written before
      // fingerprints existed. Anything else is a real failure and propagates.
      if (err && err.codeName === 'KeyInvalidated') {
        const reason = (err.data && err.data.reason) || 'unknown';
        return { namespace, locked: false, bytes, unreadable: { reason, message: err.message } };
      }
      throw err;
    }
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

/** Display host for a stored origin (`https://example.com` -> `example.com`). */
function hostOfOrigin(origin) {
  if (!origin || typeof origin !== 'string') return null;
  try {
    const u = new URL(origin);
    return u.host || origin.replace(/^[a-z0-9]+:\/\//i, '') || null;
  } catch {
    return origin;
  }
}

/** Only navigate to schemes the browser actually browses. */
function isLaunchable(url) {
  if (!url || typeof url !== 'string') return false;
  try {
    return LAUNCHABLE_SCHEMES.has(new URL(url).protocol.replace(/:$/, '').toLowerCase());
  } catch {
    return false;
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
/** Add the methods every grant carries to `methods`, without duplicating them. */
function withAlwaysGranted(methods) {
  return [...new Set([...(methods || []), ...ALWAYS_GRANTED_METHODS])];
}
function covers(remembered, methods, fields) {
  const have = new Set(withAlwaysGranted(remembered.methods));
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
