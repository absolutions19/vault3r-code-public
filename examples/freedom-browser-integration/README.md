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

## Run it live

Expected layout: this repo and the vault-wired Freedom fork as siblings
(`…/vault3r-code-public` + `…/freedom-browser` from
[`0x-noad/freedom-browser`](https://github.com/0x-noad/freedom-browser)).
Reference files here are for re-applying to a clean
[`solardev-xyz/freedom-browser`](https://github.com/solardev-xyz/freedom-browser)
clone — see wiring below.

```bash
# From the Vault3r repo root
pnpm install
pnpm bundle:freedom                 # rebuilds src/main/vault/vendor/ in the fork
pnpm glue:smoke                     # 78 headless checks (no Electron)

# Launch Freedom (Ant/IPFS/Radicle downloads optional for vault-only testing)
cd ../freedom-browser
npm install
unset ELECTRON_RUN_AS_NODE          # required in Cursor/VS Code agent terminals
npm start                           # look for: [App] Data vault registered

# In another terminal — serve the test dApp
cd ../vault3r-code-public
pnpm serve:vault-test
```

Open **http://vault-test.localhost:8765/** in Freedom (not `127.0.0.1` —
IP literals and bare `localhost` are rejected by namespace derivation; Chromium
maps `*.localhost` → loopback). Unlock the wallet, **Connect**, then check the
sidebar **Data** tab and toolbar **Your dApps** (`freedom://dapps`).

| Script | What it does |
|---|---|
| `pnpm glue:smoke` | Headless e2e over the real glue files |
| `pnpm bundle:freedom [path]` | esbuild `@vault/*` → `freedom-browser/src/main/vault/vendor/` |
| `pnpm serve:vault-test` | `python3 -m http.server 8765` for `test-page/` |

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
| `main/data-vault-manager.js` | `src/main/vault/` | The host. Owns one `VaultEngine`, derives the authoritative origin, binds sessions to tabs, bridges consent, pushes events, serves the home-page grid, and does export/import. |
| `main/data-vault-icon.js` | `src/main/vault/` | Validates + re-encodes the site-supplied tile icon (data: URIs only, no SVG, magic-byte + size + dimension caps), and the deterministic monogram fallback. |
| `main/vault-provider-inject.js` | `src/main/` | `window.vault` provider **source-as-data** (mirrors `webview-preload-ethereum-inject.js`). Runs in the page realm. |
| `main/vault-ipc-channels.js` | merge into `src/shared/ipc-channels.js` | Channel names — site-facing `vault:*` + owner-facing `datavault:*`. |
| `preload-additions.js` | splice into `src/main/webview-preload.js` | The page↔main bridge for the site provider (mirrors the ethereum/swarm bridges). |
| `preload-main-additions.js` | splice into `src/main/preload.js` | The **owner** bridge — `window.vaultData` for the "Data" management pane. |
| `renderer/vault-data.js` | `src/renderer/lib/wallet/` | The "Data" pane submodule — list / detail / consent-request views. |
| `renderer/vault-data.css` | `src/renderer/styles/` (+ `@import`) | Pane styles, using the existing sidebar tokens. |
| `preload-home-additions.js` | `src/main/webview-preload.js` (guarded) / or a dedicated preload | The `window.vaultHome` bridge for the **launcher page only**. In the wired fork it is gated to `freedom://dapps` (`pages/dapps.html`) — never attach an unguarded home preload to a normal webview. |
| `renderer/vault-home.html` | `src/renderer/pages/dapps.html` (fork adapts this) | The `freedom://dapps` launcher page, with its own strict CSP. |
| `renderer/vault-home.js` | inlined into `dapps.html` (or `src/renderer/lib/`) | The launcher grid — tiles, monogram fallback, locked state. |
| `renderer/vault-home.css` | inlined / `src/renderer/styles/` | Launcher styles (existing tokens, light + dark). |
| `renderer/index-snippets.html` | splice into `src/renderer/index.html` | The tab button + `#tab-data` panel markup, the toolbar button for the launcher, and the wallet-ui wiring notes. |
| `test-page/` | serve locally | Minimal site that drives `window.vault` — see [Run it live](#run-it-live). |

## The "Data" management pane

A fourth wallet tab (**Data**) lets the vault owner see and control every site's
storage — mirroring freedom-browser's own vanilla-JS list/subscreen patterns.

- **List** — every site with a partition, its on-disk (sealed) size, and total usage.
- **View** — click a site to see its decrypted stored JSON (requires the vault unlocked).
- **Delete / Clear all** — drop one site or everything (data + manifest + grant + live sessions).
- **Export** — write the sealed bundle to a file.

`window.vaultData` (main-window only — never exposed to sites): `listPartitions()`,
`getUsage()`, `getPartitionData(namespace)`, `deletePartition(namespace)`,
`clearAll()`, `exportVault()`. Backed by an owner/admin plane in the engine
(`adminReadPartition` / `adminDeletePartition`) that bypasses per-site grants **by
design** — it's the owner viewing their own data through the trusted UI.

### Per-field consent in the Data tab

When a site calls `window.vault.connect(...)` for the first time, the manager's
`promptConsent` seam surfaces the request **in the Data tab**: it opens the
sidebar, switches to Data, and shows the requested fields as **per-field read/write
toggles** with Allow/Deny. Whatever the user leaves enabled *is* the grant (they
can downgrade or drop fields); Deny rejects the site's `connect()`. The host wires
`promptConsent` as a round-trip to the renderer:

```
site connect → manager.promptConsent(req)
   → main sends 'datavault:consent-request' to the wallet window (window.vaultData.onConsentRequest)
   → Data tab renders per-field toggles → user Allow/Deny
   → 'datavault:consent-response' → promptConsent resolves → grant persists → connect() resolves
```

Returning sites whose remembered grant already covers the request reconnect
silently (no prompt).

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
  // If your vault auto-locks on idle, wire this: every successful data-plane
  // call reports through it. Skip it and a site whose only vault traffic is
  // get/set/patch/subscribe is invisible to the timer and gets locked out
  // mid-session — the writes themselves being what should keep it alive.
  onActivity: () => resetVaultAutoLockTimer(),
});
app.whenReady().then(() => vault.register());
```

Then splice the three blocks from `preload-additions.js` into
`webview-preload.js`, and add the `vault:*` channels to `src/shared/ipc-channels.js`.

## The vault home page (`vault://home`)

A dedicated internal page, reached from a **toolbar button**: a grid of every site
holding data in your vault — the site's own icon, its name underneath, click to
launch. It is the launcher; the Data tab remains the manager.

**Why this is a browser page and not a bookmarked dweb site.** The list of sites
you hold data for is a cross-origin aggregate — browsing history, structurally.
Handing it to *any* web origin, even a pinned CID, would make the thing this whole
design calls "structurally unrepresentable" merely allowlisted, and one XSS or one
repointed `ens://` name later it exfiltrates in an `<img src>`. Rendering it in a
privileged internal page means the list never crosses into a page context at all.

Three properties the implementation must keep:

| Property | Enforced by |
|---|---|
| No page can read the site list | `window.vaultHome` is exposed **only** on the launcher's own preload; the site-facing provider has no such method |
| Opening the launcher makes **zero** network requests | icons arrive in-band at connect (below), and the page's CSP is `default-src 'none'; img-src data:; connect-src 'none'` |
| The launcher can't navigate anywhere arbitrary | tiles pass a **namespace**, never a URL; main resolves it to the origin *it* observed at grant time and checks the scheme against an allow-list |

Locked shows the unlock prompt and nothing else — no tiles, and no site *count*
either, since "how many sites" is itself a fact about the user.

Wiring in `src/main/index.js`:

```js
const { BrowserWindow, nativeImage } = require('electron');

// Pass the two new seams when constructing the manager (see above):
const vault = new DataVaultManager({
  /* …dataDir, identityVault, promptConsent… */
  nativeImage,                       // lets main re-encode site icons
  openUrl: (url) => openInNewTab(url), // your existing tab API
});

// The launcher window. These options are load-bearing, not boilerplate:
function openVaultHome() {
  const win = new BrowserWindow({
    webPreferences: {
      preload: path.join(__dirname, 'vault-home-preload.js'), // ONLY here
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
    },
  });
  win.loadFile(path.join(__dirname, '../renderer/vault-home.html'));
  // Never let this window become a web page — it holds a privileged bridge.
  win.webContents.on('will-navigate', (e) => e.preventDefault());
  win.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
}
```

If you instead render the launcher as a tab inside the main window, give it its
own `BrowserView`/partition with the same rules — the one thing that must never
happen is `vault-home-preload.js` ending up in a `webPreferences.preload` that web
content can reach.

## What a website does

Sites already write code to use the vault, so they supply their own tile icon —
**in-band, at connect**. There is no `.well-known` path and no fetch: a network
request per tile would beacon your whole vault list on every render and wouldn't
work for `ipfs://` or `ens://` sites at all.

```js
appMetadata: {
  name: 'My dApp',
  // PNG / JPEG / WebP as a data: URI. NO SVG (script-capable).
  // ≤ 64 KB, between 8×8 and 512×512. Main re-encodes it to a 128×128 PNG.
  icon: 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUg…',
}
```

The icon is **pinned at consent** and only rewritten when the user consents again,
so a site can't silently restyle its own tile later to imitate another one. A site
that supplies nothing gets a monogram — its first letter on a hue derived from the
namespace — so no tile is ever blank. The name is stripped of control and bidi
characters (the `ev‮il .com` trick) and length-capped before it is stored or shown.

Note that this is site-controlled artwork: it buys recognition, not verification.
That is why the tile's accessible name and tooltip always carry the **host the
browser actually observed**, and why nothing destructive lives on the launcher.

```js
// 1) Ask for a vault (user confirms once; grants persist).
const { sessionId } = await window.vault.connect({
  appMetadata: { name: 'My dApp', icon: 'data:image/png;base64,…' },
  requestedScopes: [{
    // `vault_getPermissions` is granted with every grant, asked for or not —
    // introspecting a grant you already hold tells you nothing new. List the
    // methods you actually call.
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
pnpm glue:smoke
# same as: npx tsx examples/freedom-browser-integration/test/glue-smoke.cjs
```

It exercises: origin→namespace, consent + per-field grants, real sealing to disk
(asserts the on-disk blob is ciphertext, not plaintext), per-field enforcement,
subscriptions, per-origin **isolation**, **session/tab binding** (one page can't
use another's `sessionId`), dweb namespaces, remembered grants (no re-prompt),
export/import round-trip, and revoke/locked **fail-closed**; plus the icon
validator (SVG, remote URLs, MIME/magic mismatch, size cap, dimension bomb, bidi
names), the launcher (icon pinning, monogram fallback, launch-by-namespace,
non-browsable scheme refused, locked leaks neither tiles nor a count), permission
store encryption, and sealed export of the site list — **78 checks**.
Run it after any change to the glue.

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

## Metadata at rest (the permission store)

`vault-permissions.json` used to sit in `userData` as plaintext at `0600`. What it
holds is a list of every site you hold data for, with grants, timestamps and now
pinned icons — browsing history, structurally — and `0600` does nothing about
backups (Time Machine, iCloud and OneDrive all sync app data), disk clones, or a
powered-off machine without full-disk encryption.

It is now `vault-permissions.enc`, encrypted with Electron **`safeStorage`** (OS
keychain: Keychain / DPAPI / libsecret), migrated automatically on first load with
the plaintext original deleted.

Why the OS keychain and not the vault DEK: the DEK only exists while the mnemonic
is unlocked, and this store must stay readable while the vault is **locked** — the
remembered-grant lookup in `_decideConsent` runs before the engine's unlock check,
and `openSite` resolves a launcher tile to the origin it was granted at.
`safeStorage` is keyed to the OS user session, so the encryption costs nothing in
locked-state behaviour.

That is separate from what the UI *shows*. While locked, both the Data pane and the
launcher render an unlock prompt and nothing else — no site list, no sizes, not
even a count — and `listPartitions`, `getUsage` and `listHomeTiles` return empty to
match, so there is no list to leak to whoever walks up to an unattended browser.

Honest about what it buys: it protects at-rest snapshots. It does **not** stop
malware running as you (unlocked it reads the plaintext or drives the IPC; locked
it waits). And the sealed-blob directory still leaks by shape — filenames are
`doc:<sha256(namespace)>.bin`, an unsalted hash of a low-entropy input, so anyone
with the folder can confirm guesses from a domain wordlist and read per-site sizes
from `stat`. Closing that needs key-derived filenames and size padding, which
would in turn stop the manifest detecting deletions while locked.

Two failure modes are handled explicitly: where no OS keyring is available
(`isEncryptionAvailable()` false — Linux without libsecret, where the `basic_text`
backend is not meaningfully encrypted) the file is written with a `VLT0` header so
it is honestly labelled rather than pretending; and a file that cannot be decrypted
(profile moved between machines, keychain entry lost) is preserved as
`.enc.unreadable` rather than silently overwritten, so grants are never destroyed
by a bad read.

## Export / import (decision #5)

`vault:export` returns a portable bundle of the **sealed** blobs (never decrypted)
plus the permission map **sealed under the DEK**. Both only open on a device with
the same mnemonic — the natural hook for future cloud sync.

The permission map used to ride along as cleartext JSON, which put the full site
list (and, once icons existed, the icons) in a file users drop into cloud storage.
Sealing it means **export now requires an unlock**, which matches the Data pane
already requiring one to read the same material.

`vault:import` writes the blobs back verbatim and restores the grants. That
restore is new and load-bearing: import previously wrote blobs but never grants,
so a restored vault re-prompted for every site *and* showed nothing in the Data
pane, which enumerates by grant. A bundle whose sealed map doesn't open (wrong
vault, tampered file) fails closed rather than half-restoring. Legacy `/1` bundles
still import their blobs; their cleartext permission map is ignored.

## Open decisions to confirm with the team

- **DEK source.** Deriving from the mnemonic gives "one unlock" but couples data
  re-keying to a seed change. A separate data-vault secret would decouple them at
  the cost of a second unlock. This reference takes the one-unlock path.
- **Consent UX.** `promptConsent` is a seam — the modal (per-field toggles,
  remember-this-site, write policy) is the browser team's design.
- **Auto-lock.** The data vault follows the identity vault's lock state; if you
  want a separate idle timeout for data access, add it in the keystore bridge.
