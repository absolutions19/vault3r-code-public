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
const fakeElectron = {
  app: { getPath: () => DATA_DIR },
  ipcMain: { handle() {}, on() {} },
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

let clock = 1_760_000_000_000;
const manager = new DataVaultManager({
  dataDir: DATA_DIR,
  identityVault,
  promptConsent,
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
