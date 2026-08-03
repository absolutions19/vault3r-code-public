# VAULT ↔ Freedom Browser integration (reference glue)

Reference code for hosting **VAULT** inside
[`solardev-xyz/freedom-browser`](https://github.com/solardev-xyz/freedom-browser)
as a persistent, per-site **data vault** — "a crypto wallet, but for data."

This is **Option B**: the vault lives in the browser and is tied to the browser's
identity (one unlock covers both the wallet and the data vault). Any website can
*request* a data vault; the user confirms; nothing is granted by default.

> These files are **reference** — they live in the Vault3r repo so they can be
> versioned and reviewed, but they target the freedom-browser tree. Copy them into
> `src/main/` there and follow that repo's `AGENTS.md` playbooks
> (architecture-boundaries for new `src/main` files + new IPC channels, the
> security-checklist, and `npm run lint` after changes). Adding the `@vault/*`
> packages is a **new dependency** — get that approved per their AGENTS.md before
> wiring.

## Why a second, "trusted" path (and why it's still safe)

Over the network, VAULT proves a site's identity with a `.well-known` record, a
WalletConnect-style relay, a delegation, and a per-request signature. **Inside the
browser none of that is needed**: the Electron main process already knows the
caller's origin authoritatively (`event.senderFrame.url`). The transport *is* the
trust boundary.

So the integration uses VAULT's **trusted in-process host mode** (added in
`@vault/vault-core` v0.3.0): `engine.connectLocal()` + a `local*` data plane that
**skip** the relay / identity proof / delegation / signatures, while keeping every
property that protects the user's data:

| Property | Enforced by |
|---|---|
| A site only ever touches **its own** namespace | `deriveOriginNamespace(origin)` — origin comes from `senderFrame`, never the page |
| dweb origins can't collide with http(s) or with each other | `web:dweb:` prefix + case-preserving canonicalization (CIDs/tx-ids don't alias) |
| Explicit **consent** with **per-field** grants on first connect | `promptConsent` → persisted in `data-vault-permissions.js` |
| Method gating, input caps, write-policy, anti-rollback store | the engine chokepoint (unchanged from the signed path) |
| One page can't drive another's session | the **manager** binds each `sessionId` to its `webContents` |
| Revocation | user revokes in settings → manager tears down live sessions + drops the grant |

The trusted and signed paths **cannot cross**: `local*` methods only accept
`local` sessions, and a local session carries no delegated key so any signed
request against it fails.

## Files

| File | Where it goes | What it is |
|---|---|---|
| `main/data-vault-keystore.js` | `src/main/vault/` | `KeystoreAdapter` — derives the data-vault DEK from the **already-unlocked mnemonic** via domain-separated HKDF (one unlock). Seals per-namespace with XChaCha20-Poly1305. |
| `main/data-vault-storage.js` | `src/main/vault/` | `StorageAdapter` — writes each namespace's **sealed** blob under `userData/vault-data/` (atomic rename, `0600`, path-traversal-guarded). |
| `main/data-vault-permissions.js` | `src/main/vault/` | Remembered per-origin grants (mirrors `wallet/dapp-permissions.js`) so a returning site reconnects without a prompt. |
| `main/data-vault-manager.js` | `src/main/vault/` | The host. Owns one `VaultEngine`, derives the authoritative origin, binds sessions to tabs, bridges consent, pushes events, and does export/import. |
| `main/vault-provider-inject.js` | `src/main/` | `window.vault` provider **source-as-data** (mirrors `webview-preload-ethereum-inject.js`). Runs in the page realm. |
| `main/vault-ipc-channels.js` | merge into `src/shared/ipc-channels.js` | Channel names — site-facing `vault:*` + owner-facing `datavault:*`. |
| `preload-additions.js` | splice into `src/main/webview-preload.js` | The page↔main bridge for the site provider (mirrors the ethereum/swarm bridges). |
| `preload-main-additions.js` | splice into `src/main/preload.js` | The **owner** bridge — `window.vaultData` for the "Data" management pane. |

**Owner "Data" pane API** (`window.vaultData`, main-window only — never exposed to sites): `listPartitions()`, `getUsage()`, `getPartitionData(namespace)`, `deletePartition(namespace)`, `clearAll()`, `exportVault()`. Backed by an owner/admin plane in the engine (`adminReadPartition` / `adminDeletePartition`) that bypasses per-site grants **by design** — it's the vault owner viewing their own data through the trusted UI.

## Wiring (main process, `src/main/index.js`)

```js
const { app, webContents } = require('electron');
const { DataVaultManager } = require('./vault/data-vault-manager');
const VAULT_INJECT_SOURCE = require('./vault-provider-inject');
const identity = require('./identity/vault'); // the existing mnemonic vault

// 1) Serve the window.vault source to preloads (like the ethereum inject).
ipcMain.on(require('./vault/vault-ipc-channels').VAULT_GET_INJECT_SOURCE, (e) => {
  e.returnValue = VAULT_INJECT_SOURCE;
});

// 2) Bridge the browser's identity vault to VAULT's keystore.
const identityBridge = {
  isUnlocked: () => identity.isUnlocked(),
  getMnemonic: () => identity.getMnemonic(),
  // optional: prompt the user to unlock if a site connects while locked
  ensureUnlocked: async () => { /* show unlock modal; return identity.isUnlocked() */ },
};

// 3) Create + register the manager. `promptConsent` shows YOUR consent sheet.
const vault = new DataVaultManager({
  dataDir: app.getPath('userData'),
  identityVault: identityBridge,
  promptConsent: async (payload) => {
    // Render the per-site / per-field prompt in the main window and resolve to:
    //   { approved, grantedMethods?, grantedFields?, writePolicy? }
    return showVaultConsentModal(payload);
  },
});
app.whenReady().then(() => vault.register());
```

Then splice the three blocks from `preload-additions.js` into
`webview-preload.js`, and add the `vault:*` channels to `src/shared/ipc-channels.js`.

## What a website does

```js
// 1) Ask for a vault (user confirms once; grants persist).
const { sessionId } = await window.vault.connect({
  appMetadata: { name: 'My dApp', iconUrl: '/icon.png' },
  requestedScopes: [{
    methods: ['vault_getData', 'vault_setData', 'vault_subscribe'],
    fields: [
      { path: '/profile', read: true, write: true },
      { path: '/prefs',   read: true, write: true },
    ],
  }],
});

// 2) Read / write your own namespaced slice (JSON where it makes sense).
await window.vault.set(sessionId, { '/profile/handle': '@alice' });
const { values } = await window.vault.get(sessionId, ['/profile/handle']);

// 3) Live updates.
const { subscriptionId } = await window.vault.subscribe(sessionId, ['/profile']);
window.vault.on('change', (u) => console.log('changed', u.changes));
```

## Testing (before wiring into the browser)

A headless smoke test drives the **actual** glue (manager + keystore + storage +
permissions) end-to-end against the engine — no Electron, no GUI — with fakes for
only the two Electron touchpoints (the identity-vault bridge and `webContents`):

```bash
npx tsx examples/freedom-browser-integration/test/glue-smoke.cjs
```

It exercises: origin→namespace, consent + per-field grants, real sealing to disk
(asserts the on-disk blob is ciphertext, not plaintext), per-field enforcement,
subscriptions, per-origin **isolation**, **session/tab binding** (one page can't
use another's `sessionId`), dweb namespaces, remembered grants (no re-prompt),
export/import round-trip, and revoke/locked **fail-closed** — 32 checks. Run it
after any change to the glue.

## Naming

The browser already has an **identity vault** (the mnemonic store,
`src/main/identity/vault.js`). This is the **data vault** / **site storage** — it
never touches wallet keys; it derives its own DEK from the seed via HKDF domain
separation, so the two are cryptographically distinct even though one unlock opens
both.

## Namespaces & transport stability

`deriveOriginNamespace(origin)`:

- `https://app.example.com` → `web:example.com` (the **same** namespace the relay
  path derives — a site's data is identical across transports).
- `bzz://…`, `ipfs://…`, `ens://myapp.eth`, `rad://…` → `web:dweb:<scheme>:<authority>`.
  Case is preserved for content-address schemes (`ipfs`/`ipns`/`ar`/`rad`) so
  distinct CIDs never alias; folded only for name/hex schemes (`ens`/`bzz`/`swarm`/`hyper`).

For the richest, transport-stable keying (so `ens://myapp.eth` and
`bzz://myapp.eth` share one vault, matching the address bar), feed the browser's
own `src/shared/origin-utils.js` `getPermissionKey(displayUrl)` output through
`originForNamespace` before deriving. The manager's `originForNamespace` here is a
minimal stand-in.

## Export / import (decision #5)

`vault:export` returns a portable bundle of the **sealed** blobs (never
decrypted) + the permission map. `vault:import` writes them back verbatim. A
restore only decrypts on a device with the **same mnemonic** (the DEK is derived
from it) — the natural hook for future cloud sync.

## Open decisions to confirm with the team

- **DEK source.** Deriving from the mnemonic gives "one unlock" but couples data
  re-keying to a seed change. A separate data-vault secret would decouple them at
  the cost of a second unlock. This reference takes the one-unlock path.
- **Consent UX.** `promptConsent` is a seam — the modal (per-field toggles,
  remember-this-site, write policy) is the browser team's design.
- **Auto-lock.** The data vault follows the identity vault's lock state; if you
  want a separate idle timeout for data access, add it in the keystore bridge.
