/**
 * Headless integration harness for the Freedom Browser reference glue.
 *
 * Loads the ACTUAL glue files (data-vault-manager/keystore/storage/permissions)
 * and drives a full window.vault flow through the manager's real request router,
 * with fakes for only the two Electron touchpoints (identity-vault bridge +
 * webContents). Proves: origin->namespace, consent + per-field grants, seal to
 * disk, per-origin isolation, session/tab binding, subscriptions, revoke
 * fail-closed, and export/import — without Electron or a GUI.
 *
 * Run from the Vault3r repo root:
 *   npx tsx examples/freedom-browser-integration/test/glue-smoke.cjs
 */

const path = require('path');
const fs = require('fs');
const os = require('os');
const Module = require('module');

const ROOT = findRepoRoot();
const GLUE = path.join(ROOT, 'examples', 'freedom-browser-integration', 'main');

function findRepoRoot() {
  // Prefer VAULT3R_ROOT / cwd, else walk up from this file to the repo root.
  const candidates = [process.env.VAULT3R_ROOT, process.cwd()];
  let d = __dirname;
  for (let i = 0; i < 12; i++) {
    candidates.push(d);
    d = path.dirname(d);
  }
  for (const c of candidates) {
    if (c && fs.existsSync(path.join(c, 'packages', 'vault-core', 'src', 'index.ts'))) return c;
  }
  throw new Error('could not locate Vault3r repo root (set VAULT3R_ROOT or run from repo root)');
}

// --- resolver shim: map @vault/* to workspace TS source; stub electron --------
const ALIASES = {
  '@vault/protocol': path.join(ROOT, 'packages', 'protocol', 'src', 'index.ts'),
  '@vault/crypto-core': path.join(ROOT, 'packages', 'crypto-core', 'src', 'index.ts'),
  '@vault/vault-core': path.join(ROOT, 'packages', 'vault-core', 'src', 'index.ts'),
};

// Fake electron: a registry-backed webContents so the manager's real _emit path
// (webContents.fromId(...).send(...)) actually delivers subscription events.
const wcRegistry = new Map();
const capturedEvents = [];
let saveDialogPath = null; // set per-test to drive exportToFile
// A stand-in for Electron's OS-keychain encryptor. Deliberately trivial (byte
// inversion) — the point is to prove the permission store round-trips through the
// seam and never hits disk as readable JSON, not to test Chromium's crypto.
let encryptionAvailable = true;
const fakeSafeStorage = {
  isEncryptionAvailable: () => encryptionAvailable,
  encryptString: (s) => Buffer.from(Buffer.from(s, 'utf-8').map((b) => b ^ 0xff)),
  decryptString: (buf) => Buffer.from(Buffer.from(buf).map((b) => b ^ 0xff)).toString('utf-8'),
};
const fakeElectron = {
  // Mutable so the migration test can point userData at a fresh profile.
  app: { getPath: () => DATA_DIR_REF.value },
  ipcMain: { handle() {}, on() {} },
  safeStorage: fakeSafeStorage,
  dialog: {
    showSaveDialog: async () =>
      saveDialogPath ? { canceled: false, filePath: saveDialogPath } : { canceled: true },
  },
  webContents: {
    fromId(id) {
      return wcRegistry.get(id) || null;
    },
  },
};
const ELECTRON_STUB_ID = '\0electron-stub';
Module._cache[ELECTRON_STUB_ID] = {
  id: ELECTRON_STUB_ID,
  filename: ELECTRON_STUB_ID,
  loaded: true,
  exports: fakeElectron,
};

const origResolve = Module._resolveFilename;
Module._resolveFilename = function (request, parent, isMain, options) {
  if (request === 'electron') return ELECTRON_STUB_ID;
  if (ALIASES[request]) return ALIASES[request];
  return origResolve.call(this, request, parent, isMain, options);
};

// --- test fixtures -----------------------------------------------------------
const DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'vault-glue-'));
/** Indirection so a test can retarget `app.getPath('userData')`. */
const DATA_DIR_REF = { value: DATA_DIR };
// A valid BIP-39 test mnemonic (Hardhat's). The keystore only HKDFs it.
const MNEMONIC = 'test test test test test test test test test test test junk';
let unlocked = true;
const identityVault = {
  isUnlocked: () => unlocked,
  getMnemonic: () => (unlocked ? MNEMONIC : null),
  ensureUnlocked: async () => unlocked,
};

// Auto-approving consent that grants exactly what was requested (first connect),
// echoing the per-field rules so we can see the grant is honored.
let consentCalls = 0;
async function promptConsent(payload) {
  consentCalls++;
  const methods = [...new Set((payload.requestedScopes || []).flatMap((s) => s.methods || []))];
  const fields = (payload.requestedScopes || []).flatMap((s) => s.fields || []);
  log('  [consent] prompt for', payload.namespace, '→ auto-approve', JSON.stringify({ methods, fields }));
  return { approved: true, grantedMethods: methods, grantedFields: fields, writePolicy: 'ask-once-per-session' };
}

// --- load the REAL glue ------------------------------------------------------
const { DataVaultManager } = require(path.join(GLUE, 'data-vault-manager.js'));
const { normalizeIcon, monogramFor, sanitizeName } = require(path.join(GLUE, 'data-vault-icon.js'));
const permsStore = require(path.join(GLUE, 'data-vault-permissions.js'));

/** Every URL the home page asked the host to navigate to. */
const openedUrls = [];

let clock = 1_760_000_000_000;
// Counts every onActivity report so the auto-lock keep-alive can be asserted.
let activityReports = 0;
const manager = new DataVaultManager({
  dataDir: DATA_DIR,
  identityVault,
  promptConsent,
  openUrl: (url) => openedUrls.push(url),
  onActivity: () => { activityReports += 1; },
  now: () => clock,
});

// A fake sender/frame for a given origin + webContents id. Registering it in the
// wcRegistry lets the manager's real event push reach us.
function makeSender(id, url) {
  const wc = {
    id,
    getURL: () => url,
    isDestroyed: () => false,
    send: (channel, payload) => capturedEvents.push({ id, channel, payload }),
  };
  wcRegistry.set(id, wc);
  return { senderFrame: { url }, sender: wc };
}
async function call(sender, method, params) {
  const res = await manager._onRequest(sender, { method, params });
  if (res.error) {
    const e = new Error(res.error.message);
    e.code = res.error.code;
    throw e;
  }
  return res.result;
}

// --- PNG fixtures ------------------------------------------------------------
// Real, structurally valid PNGs built here so the icon validator is exercised
// against actual bytes rather than a hand-waved string.
const zlib = require('zlib');

const CRC_TABLE = (() => {
  const t = new Int32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[n] = c;
  }
  return t;
})();
function crc32(buf) {
  let c = 0xffffffff;
  for (let i = 0; i < buf.length; i++) c = CRC_TABLE[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}
function pngChunk(type, data) {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length, 0);
  const body = Buffer.concat([Buffer.from(type, 'ascii'), data]);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(body), 0);
  return Buffer.concat([len, body, crc]);
}
/** @param {boolean} realPixels false = header-only (for dimension-bomb fixtures). */
function makePng(w, h, realPixels = true) {
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(w, 0);
  ihdr.writeUInt32BE(h, 4);
  ihdr[8] = 8; // bit depth
  ihdr[9] = 2; // colour type: truecolour
  const raw = realPixels ? Buffer.alloc(h * (1 + w * 3)) : Buffer.alloc(1);
  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    pngChunk('IHDR', ihdr),
    pngChunk('IDAT', zlib.deflateSync(raw)),
    pngChunk('IEND', Buffer.alloc(0)),
  ]);
}
function dataUri(mime, buf) {
  return `data:${mime};base64,${buf.toString('base64')}`;
}

// --- output helpers ----------------------------------------------------------
let pass = 0;
let fail = 0;
function log(...a) {
  console.log(...a);
}
function check(name, cond) {
  if (cond) {
    pass++;
    console.log('  ✓', name);
  } else {
    fail++;
    console.log('  ✗ FAIL:', name);
  }
}
function section(t) {
  console.log('\n' + t);
}

// --- the flow ----------------------------------------------------------------
(async () => {
  console.log('VAULT ↔ Freedom Browser glue — headless integration harness');
  console.log('data dir:', DATA_DIR);

  const SITE_A = makeSender(1, 'https://app.example.com/some/page?x=1#frag');
  const SITE_B = makeSender(2, 'https://other.example/index.html');
  const SWARM = makeSender(3, 'bzz://DeadBeefCafe/app');

  section('1) connect + consent + per-field grant (site A)');
  const connA = await call(SITE_A, 'vault_connect', {
    appMetadata: { name: 'Example App' },
    requestedScopes: [
      {
        methods: ['vault_getData', 'vault_setData', 'vault_subscribe', 'vault_getPermissions', 'vault_revoke'],
        fields: [
          { path: '/profile', read: true, write: true },
          { path: '/readonly', read: true, write: false },
        ],
      },
    ],
  });
  check('origin reduced to registrable-domain namespace', connA.namespace === 'web:example.com');
  check('consent prompt shown once', consentCalls === 1);
  check('got a sessionId', typeof connA.sessionId === 'string' && connA.sessionId.length > 0);

  section('2) write + read back (sealed to disk)');
  const w = await call(SITE_A, 'vault_setData', { sessionId: connA.sessionId, values: { '/profile/handle': '@alice' } });
  check('write applied', w.applied === true);
  const r = await call(SITE_A, 'vault_getData', { sessionId: connA.sessionId, paths: ['/profile/handle'] });
  check('read returns the written value', r.values['/profile/handle'] === '@alice');
  const files = fs.readdirSync(path.join(DATA_DIR, 'vault-data')).filter((f) => f.endsWith('.bin'));
  const docFile = files.find((f) => decodeURIComponent(f.slice(0, -4)).startsWith('doc:'));
  check('a sealed doc blob + manifest exist on disk', !!docFile && files.length === 2);
  const raw = fs.readFileSync(path.join(DATA_DIR, 'vault-data', docFile));
  check('the blob is ciphertext, not plaintext JSON', !raw.toString('utf8').includes('@alice'));

  section('3) per-field grant enforced');
  let blocked = false;
  try {
    await call(SITE_A, 'vault_setData', { sessionId: connA.sessionId, values: { '/readonly': 1 } });
  } catch (e) {
    blocked = e.code === 4306; // WriteForbidden
  }
  check('write to a read-only field is rejected (WriteForbidden)', blocked);
  let oos = false;
  try {
    await call(SITE_A, 'vault_getData', { sessionId: connA.sessionId, paths: ['/billing'] });
  } catch (e) {
    oos = e.code === 4305; // FieldOutOfScope
  }
  check('read of an ungranted path is rejected (FieldOutOfScope)', oos);

  section('4) subscription delivers on write');
  const sub = await call(SITE_A, 'vault_subscribe', { sessionId: connA.sessionId, paths: ['/profile'] });
  capturedEvents.length = 0;
  await call(SITE_A, 'vault_setData', { sessionId: connA.sessionId, values: { '/profile/handle': '@alice2' } });
  const evt = capturedEvents.find((e) => e.channel === 'vault:provider-event');
  check('subscriber received an event', !!evt);
  check('event carries the changed value', !!evt && evt.payload.notification.params.changes['/profile/handle'] === '@alice2');
  void sub;

  section('5) per-origin isolation (site B cannot see site A data)');
  const connB = await call(SITE_B, 'vault_connect', {
    appMetadata: { name: 'Other App' },
    requestedScopes: [{ methods: ['vault_getData', 'vault_setData'], fields: [{ path: '/profile', read: true, write: true }] }],
  });
  check('site B gets a different namespace', connB.namespace === 'web:other.example');
  const rb = await call(SITE_B, 'vault_getData', { sessionId: connB.sessionId, paths: ['/profile/handle'] });
  check('site B reads null for site A’s field', rb.values['/profile/handle'] === null);

  section('6) session/tab binding (site B cannot use site A’s sessionId)');
  let stolen = false;
  try {
    await call(SITE_B, 'vault_getData', { sessionId: connA.sessionId, paths: ['/profile/handle'] });
  } catch (e) {
    stolen = e.code === 4900; // unknown/unauthorized session
  }
  check('cross-session use is rejected', stolen);

  section('7) dweb origin gets a distinct dweb namespace');
  const connS = await call(SWARM, 'vault_connect', {
    appMetadata: { name: 'Swarm dApp' },
    requestedScopes: [{ methods: ['vault_getData', 'vault_setData'], fields: [{ path: '/state', read: true, write: true }] }],
  });
  check('bzz origin folds to web:dweb:bzz:<hex>', connS.namespace === 'web:dweb:bzz:deadbeefcafe');

  section('8) remembered grant → returning site reconnects WITHOUT a prompt');
  const consentBefore = consentCalls;
  const connA2 = await call(SITE_A, 'vault_connect', {
    appMetadata: { name: 'Example App' },
    requestedScopes: [{ methods: ['vault_getData'], fields: [{ path: '/profile', read: true, write: false }] }],
  });
  check('no new consent prompt (grant remembered)', consentCalls === consentBefore);
  check('reconnect still isolated to example.com', connA2.namespace === 'web:example.com');

  section('9) export / import round-trip (sealed blobs, decision #5)');
  const bundle = await manager.exportAll();
  check('export contains sealed entries', Object.keys(bundle.entries).length >= 1);
  check('export never contains plaintext', !JSON.stringify(bundle.entries).includes('@alice'));
  // wipe + reimport
  for (const f of fs.readdirSync(path.join(DATA_DIR, 'vault-data'))) fs.unlinkSync(path.join(DATA_DIR, 'vault-data', f));
  await manager.importAll(bundle);
  const rr = await call(SITE_A, 'vault_getData', { sessionId: connA.sessionId, paths: ['/profile/handle'] });
  check('data restored after wipe+import', rr.values['/profile/handle'] === '@alice2');

  section('10) revoke → fail closed');
  await call(SITE_A, 'vault_revoke', { sessionId: connA.sessionId });
  let closed = false;
  try {
    await call(SITE_A, 'vault_getData', { sessionId: connA.sessionId, paths: ['/profile/handle'] });
  } catch (e) {
    closed = e.code === 4900;
  }
  check('data-plane op after revoke is rejected', closed);

  section('11) locked vault fails closed');
  unlocked = false;
  let lockedFail = false;
  try {
    await call(SITE_B, 'vault_getData', { sessionId: connB.sessionId, paths: ['/profile/handle'] });
  } catch (e) {
    lockedFail = e.code === 4312; // VaultLocked
  }
  check('op while locked is rejected (VaultLocked)', lockedFail);
  unlocked = true;

  section('12) owner "Data" pane — list + usage + view + delete + clear');
  // Re-seed a couple sites with real content for the management view.
  const mA = await call(makeSender(10, 'https://alpha.example/x'), 'vault_connect', {
    appMetadata: { name: 'Alpha' },
    requestedScopes: [{ methods: ['vault_getData', 'vault_setData'], fields: [{ path: '/profile', read: true, write: true }] }],
  });
  await call(wcRegistry.get(10) && { senderFrame: { url: 'https://alpha.example/x' }, sender: wcRegistry.get(10) }, 'vault_setData', {
    sessionId: mA.sessionId,
    values: { '/profile/name': 'Alpha User' },
  });
  const mB = await call(makeSender(11, 'https://beta.example/y'), 'vault_connect', {
    appMetadata: { name: 'Beta' },
    requestedScopes: [{ methods: ['vault_getData', 'vault_setData'], fields: [{ path: '/data', read: true, write: true }] }],
  });
  await call({ senderFrame: { url: 'https://beta.example/y' }, sender: wcRegistry.get(11) }, 'vault_setData', {
    sessionId: mB.sessionId,
    values: { '/data/count': 42 },
  });

  const partitions = await manager.listPartitions();
  check('listPartitions returns every site with data', partitions.some((p) => p.namespace === 'web:alpha.example') && partitions.some((p) => p.namespace === 'web:beta.example'));
  const alpha = partitions.find((p) => p.namespace === 'web:alpha.example');
  check('a partition reports non-zero on-disk bytes', alpha && alpha.bytes > 0);

  const usage = await manager.getUsage();
  check('getUsage reports total bytes + count', usage.totalBytes > 0 && usage.partitionCount === partitions.length);

  const view = await manager.getPartitionData('web:alpha.example');
  check('getPartitionData decrypts the owner view', view.locked === false && view.data.profile.name === 'Alpha User');

  unlocked = false;
  const lockedView = await manager.getPartitionData('web:alpha.example');
  check('getPartitionData returns {locked} when vault is locked', lockedView.locked === true);
  unlocked = true;

  const del = await manager.deletePartition('web:alpha.example');
  const afterDel = await manager.listPartitions();
  check('deletePartition removes the site + frees bytes', del.deleted && del.freedBytes > 0 && !afterDel.some((p) => p.namespace === 'web:alpha.example'));
  const goneView = await manager.getPartitionData('web:alpha.example');
  check('deleted partition reads back empty (manifest cleared, no rollback error)', JSON.stringify(goneView.data) === '{}');

  section('13) export to file (sealed blobs) + clear all');
  const exportPath = path.join(DATA_DIR, 'export.json');
  saveDialogPath = exportPath;
  const exp = await manager.exportToFile();
  check('exportToFile writes a bundle', exp.saved && fs.existsSync(exportPath));
  check('exported file is sealed (no plaintext)', !fs.readFileSync(exportPath, 'utf8').includes('Alpha User') && !fs.readFileSync(exportPath, 'utf8').includes('"42"'));
  saveDialogPath = null;

  const cleared = await manager.clearAll();
  const empty = await manager.listPartitions();
  check('clearAll removes every partition', cleared.cleared >= 1 && empty.length === 0);

  section('14) site-supplied icon: validation (the page controls these bytes)');
  const goodPng = dataUri('image/png', makePng(64, 64));
  check('a valid PNG is accepted', normalizeIcon(goodPng).ok === true);

  const svg = dataUri('image/svg+xml', Buffer.from('<svg xmlns="http://www.w3.org/2000/svg"/>'));
  check('SVG is rejected (script-capable in a privileged page)', normalizeIcon(svg).ok === false);

  check(
    'an http(s) URL is rejected (no fetch path back into the renderer)',
    normalizeIcon('https://evil.example/icon.png').ok === false,
  );
  check('a file: URL is rejected', normalizeIcon('file:///etc/passwd').ok === false);

  const jpegBytesAsPng = dataUri('image/png', Buffer.from([0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10, 0x4a, 0x46, 0x49, 0x46]));
  check('declared MIME must match the magic bytes', normalizeIcon(jpegBytesAsPng).ok === false);

  const oversized = dataUri('image/png', Buffer.concat([makePng(64, 64), Buffer.alloc(70 * 1024, 0x41)]));
  check('an oversized icon is rejected (disk-fill / DoS cap)', normalizeIcon(oversized).ok === false);

  const bomb = dataUri('image/png', makePng(20000, 20000, false));
  check('a decompression bomb is rejected on its header dimensions', normalizeIcon(bomb).ok === false);

  check('a 4x4 icon is rejected (below the minimum)', normalizeIcon(dataUri('image/png', makePng(4, 4))).ok === false);
  check('a non-string icon is rejected', normalizeIcon({ toString: () => goodPng }).ok === false);

  // The re-encode seam: in the real browser Electron's nativeImage normalizes the
  // bytes, so what we persist was produced by us and carries no EXIF/animation.
  const stubNativeImage = {
    createFromBuffer: () => ({
      isEmpty: () => false,
      resize: () => ({ toPNG: () => makePng(128, 128) }),
    }),
  };
  const reencoded = normalizeIcon(dataUri('image/png', makePng(64, 64)), { nativeImage: stubNativeImage });
  check(
    'with a re-encoder present the icon is normalized to a 128px PNG',
    reencoded.ok && reencoded.icon.mime === 'image/png' && reencoded.icon.width === 128,
  );

  check('a claimed name with bidi/control chars is stripped', sanitizeName('ev‮il .com') === 'evil.com');
  check('a claimed name is length-capped', sanitizeName('x'.repeat(400)).length <= 128);
  check('monogram is deterministic per namespace', monogramFor('web:example.com').hue === monogramFor('web:example.com').hue);
  check('different namespaces get different hues', monogramFor('web:a.example').hue !== monogramFor('web:b.example').hue);

  section('15) vault home page (launcher grid)');
  const ICON_SITE = makeSender(11, 'https://iconic.example/app');
  const PLAIN_SITE = makeSender(12, 'https://plain.example/');
  await call(ICON_SITE, 'vault_connect', {
    appMetadata: { name: 'Iconic‮ App', icon: goodPng },
    requestedScopes: [{ methods: ['vault_getData', 'vault_setData'], fields: [{ path: '/x', read: true, write: true }] }],
  });
  await call(PLAIN_SITE, 'vault_connect', {
    appMetadata: { name: 'Plain App' }, // no icon
    requestedScopes: [{ methods: ['vault_getData', 'vault_setData'], fields: [{ path: '/x', read: true, write: true }] }],
  });

  const home = await manager.listHomeTiles();
  check('home lists a tile per site with a grant', home.locked === false && home.tiles.length === 2);
  const iconTile = home.tiles.find((t) => t.namespace === 'web:iconic.example');
  const plainTile = home.tiles.find((t) => t.namespace === 'web:plain.example');
  check('a site-supplied icon is pinned to its tile', !!iconTile && typeof iconTile.icon === 'string' && iconTile.icon.startsWith('data:image/png;base64,'));
  check('the pinned tile name is sanitized (no bidi override)', !!iconTile && !iconTile.name.includes('‮'));
  check('a site with no icon falls back to a monogram', !!plainTile && plainTile.icon === null && plainTile.monogram.letter === 'P');
  check('each tile carries the host the browser actually observed', !!iconTile && iconTile.host === 'iconic.example');

  const statusUnlocked = await manager.getHomeStatus();
  check('status reports the count while unlocked', statusUnlocked.unlocked === true && statusUnlocked.count === 2);

  openedUrls.length = 0;
  const opened = await manager.openSite('web:iconic.example');
  check('clicking a tile launches the origin observed at grant time', opened.opened === true && openedUrls[0] === 'https://iconic.example');
  const unknown = await manager.openSite('web:never-granted.example');
  check('launching an unknown namespace is refused', unknown.opened === false);

  // A grant whose stored origin is not a browsable scheme must never navigate —
  // the launcher must not become a way to reach javascript:/file:/data:.
  permsStore.grantPermission('web:hostile.example', { origin: 'javascript:alert(1)', methods: [], fields: [] }, clock);
  const hostile = await manager.openSite('web:hostile.example');
  check('a non-browsable scheme is refused', hostile.opened === false && openedUrls.length === 1);
  permsStore.revokePermission('web:hostile.example');

  unlocked = false;
  const lockedHome = await manager.listHomeTiles();
  const lockedStatus = await manager.getHomeStatus();
  check('locked: the grid returns no tiles at all', lockedHome.locked === true && lockedHome.tiles.length === 0);
  check('locked: status leaks no site count', lockedStatus.unlocked === false && lockedStatus.count === undefined);

  // The Data pane obeys the same rule: a locked vault shows an unlock prompt and
  // nothing else, so the owner API must not hand it a site list to render.
  const lockedParts = await manager.listPartitions();
  const lockedUsage = await manager.getUsage();
  check('locked: listPartitions returns nothing for the Data pane', Array.isArray(lockedParts) && lockedParts.length === 0);
  check('locked: getUsage reports the lock state and no counts', lockedUsage.unlocked === false && lockedUsage.partitionCount === 0 && lockedUsage.totalBytes === 0);
  unlocked = true;
  const unlockedParts = await manager.listPartitions();
  check('unlocked: the site list comes back', unlockedParts.length > 0);

  section('16) the permission store is encrypted at rest');
  const permPath = path.join(DATA_DIR, 'vault-permissions.enc');
  check('the store is written to the encrypted filename', fs.existsSync(permPath));
  const permBytes = fs.readFileSync(permPath);
  check('it carries the encrypted-format header', permBytes.subarray(0, 4).toString() === 'VLT1');
  check(
    'no site origin appears in the file bytes',
    !permBytes.includes('iconic.example') && !permBytes.includes('plain.example'),
  );
  check('no pinned icon appears in the file bytes', !permBytes.includes('data:image/png'));
  check('the legacy plaintext file is not left behind', !fs.existsSync(path.join(DATA_DIR, 'vault-permissions.json')));
  check('it is 0600', (fs.statSync(permPath).mode & 0o777) === 0o600);

  // Round-trip through a cold load (cache dropped, decrypt path exercised).
  permsStore._resetCache();
  check('grants survive a decrypt-on-load round-trip', permsStore.getPermission('web:iconic.example') !== null);

  // A profile carried over from before encryption must migrate, not be lost.
  const legacyDir = fs.mkdtempSync(path.join(os.tmpdir(), 'vault-legacy-'));
  const realDataDir = DATA_DIR_REF.value;
  DATA_DIR_REF.value = legacyDir;
  permsStore._resetCache();
  fs.writeFileSync(
    path.join(legacyDir, 'vault-permissions.json'),
    JSON.stringify({ 'web:legacy.example': { namespace: 'web:legacy.example', origin: 'https://legacy.example', methods: [], fields: [] } }),
  );
  const migrated = permsStore.getPermission('web:legacy.example');
  check('a legacy plaintext store is migrated on load', migrated !== null && migrated.origin === 'https://legacy.example');
  check('migration encrypts the file', fs.readFileSync(path.join(legacyDir, 'vault-permissions.enc')).subarray(0, 4).toString() === 'VLT1');
  check('migration deletes the plaintext original', !fs.existsSync(path.join(legacyDir, 'vault-permissions.json')));

  // No OS keyring (Linux without libsecret): label the file honestly rather than
  // pretending it is encrypted.
  encryptionAvailable = false;
  permsStore._resetCache();
  permsStore.grantPermission('web:nokeyring.example', { origin: 'https://nokeyring.example', methods: [], fields: [] }, clock);
  check(
    'without OS encryption the file is written as declared plaintext',
    fs.readFileSync(path.join(legacyDir, 'vault-permissions.enc')).subarray(0, 4).toString() === 'VLT0',
  );
  encryptionAvailable = true;
  DATA_DIR_REF.value = realDataDir;
  permsStore._resetCache();
  fs.rmSync(legacyDir, { recursive: true, force: true });

  section('17) export seals the site list (not just the data)');
  const exportPath2 = path.join(DATA_DIR, 'export2.json');
  saveDialogPath = exportPath2;
  await manager.exportToFile();
  saveDialogPath = null;
  const exportText = fs.readFileSync(exportPath2, 'utf8');
  check('the bundle is the v2 format', JSON.parse(exportText).format === 'vault3r-data-export/2');
  check('the exported bundle carries no cleartext site list', !exportText.includes('iconic.example') && !exportText.includes('plain.example'));
  check('the exported bundle carries no cleartext icon', !exportText.includes('data:image/png'));

  const bundle2 = JSON.parse(exportText);
  const wipedGrants = Object.keys(permsStore.loadPermissions()).length;
  permsStore.replaceAll({});
  const restored = await manager.importAll(bundle2);
  check('import restores the sealed grants', restored.restoredGrants === wipedGrants && restored.restoredGrants > 0);
  check('a restored site is listed again', (await manager.listHomeTiles()).tiles.some((t) => t.namespace === 'web:iconic.example'));

  unlocked = false;
  let exportBlocked = false;
  try {
    await manager.exportAll();
  } catch (e) {
    exportBlocked = e.code === 4312;
  }
  check('export while locked is refused (it would seal nothing)', exportBlocked);
  unlocked = true;

  // A bundle from a different vault must not silently half-restore.
  const foreign = { ...bundle2, permissionsSealed: Buffer.from(Buffer.from(bundle2.permissionsSealed, 'base64').map((b, i) => (i === 60 ? b ^ 0xff : b))).toString('base64') };
  let foreignRejected = false;
  try {
    await manager.importAll(foreign);
  } catch (e) {
    foreignRejected = e.code === 4310;
  }
  check('a tampered/foreign permission blob fails closed', foreignRejected);

  section('18) grant introspection and auto-lock keep-alive');

  // A site that never asked for vault_getPermissions must still be able to read
  // back the grant it holds — the engine gates that method on its own presence
  // in the granted list, so the manager adds it to every grant.
  // promptConsent auto-approves exactly what was asked for — so the granted
  // method list here is precisely the two below, and getPermissions must be
  // added by the manager rather than by the consent decision.
  const introspector = makeSender(90, 'https://introspect.example/app');
  const introRes = await manager._onRequest(introspector, {
    method: 'vault_connect',
    params: {
      appMetadata: { name: 'Introspector' },
      requestedScopes: [{ methods: ['vault_getData', 'vault_setData'], fields: [{ path: '/profile', read: true, write: true }] }],
    },
  });
  const introSession = introRes.result && introRes.result.sessionId;
  check('connect without vault_getPermissions succeeds', !!introSession);

  const permsRes = await manager._onRequest(introspector, {
    method: 'vault_getPermissions',
    params: { sessionId: introSession },
  });
  check('the site can read back its own grant anyway', !permsRes.error && !!permsRes.result);

  // Data-plane traffic is what an idle-lock timer must notice; without this the
  // one thing that does NOT keep the vault alive is using the vault.
  const before = activityReports;
  await manager._onRequest(introspector, {
    method: 'vault_setData',
    params: { sessionId: introSession, values: { '/profile/handle': '@intro' } },
  });
  await manager._onRequest(introspector, {
    method: 'vault_getData',
    params: { sessionId: introSession, paths: ['/profile/handle'] },
  });
  check('successful data-plane calls report activity', activityReports === before + 2);

  const beforeFailed = activityReports;
  await manager._onRequest(introspector, {
    method: 'vault_getData',
    params: { sessionId: 'not-a-session', paths: ['/profile/handle'] },
  });
  check('a rejected call reports no activity', activityReports === beforeFailed);

  section('19) overlapping writes to one storage key never leave a torn file');

  // The reported bricking: DataVaultStorage.put wrote every writer of a key to
  // the SAME `${p}.tmp`, so two in-flight writes truncated each other and a
  // partial blob got renamed over the real one. Fire many overlapping puts of
  // distinguishable payloads at one key and require the survivor to be one of
  // them, whole. Real files, real rename — this is not reproducible in memory.
  const { DataVaultStorage } = require(path.join(GLUE, 'data-vault-storage.js'));
  const raceDir = fs.mkdtempSync(path.join(os.tmpdir(), 'vault-race-'));
  const raceStore = new DataVaultStorage(raceDir);
  const payloads = Array.from({ length: 12 }, (_, i) => Buffer.alloc(64 * 1024, i + 1));
  let tornTrials = 0;
  for (let trial = 0; trial < 20; trial++) {
    await Promise.all(payloads.map((buf) => raceStore.put('doc:race', new Uint8Array(buf))));
    const survivor = Buffer.from(await raceStore.get('doc:race'));
    const intact = payloads.some((buf) => buf.equals(survivor));
    if (!intact) tornTrials++;
  }
  check('every trial leaves one complete payload on disk (0 torn)', tornTrials === 0);
  const leftovers = fs.readdirSync(path.join(raceDir, 'vault-data')).filter((f) => f.endsWith('.tmp'));
  check('no temp files are left behind', leftovers.length === 0);
  fs.rmSync(raceDir, { recursive: true, force: true });

  console.log(`\n${'='.repeat(52)}`);
  console.log(`RESULT: ${pass} passed, ${fail} failed`);
  console.log('='.repeat(52));
  // cleanup
  try {
    fs.rmSync(DATA_DIR, { recursive: true, force: true });
  } catch {}
  process.exit(fail === 0 ? 0 : 1);
})().catch((e) => {
  console.error('\nHARNESS ERROR:', e && e.stack ? e.stack : e);
  process.exit(2);
});
