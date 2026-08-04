# VAULT

A **data vault built into the browser** — a fork of
[`solardev-xyz/freedom-browser`](https://github.com/solardev-xyz/freedom-browser)
([`0x-noad/freedom-browser`](https://github.com/0x-noad/freedom-browser) has the
vault wired) in which every website gets its own encrypted, per-origin slice of
storage that it can only touch with the user's explicit, per-field consent.
*A crypto wallet, but for data.*

A page calls `window.vault.connect({ fields })`; the user approves (or denies, or
downgrades the request field-by-field) in the wallet sidebar's **Data** tab; from
then on the site reads and writes its own namespaced JSON document. Everything is
sealed at rest with a key derived from the browser's already-unlocked seed — one
unlock covers both the wallet and the data vault — and the owner can list, inspect,
export, or delete any site's data at any time.

The headline guarantee: **a site can only ever touch the namespace derived from the
origin the browser itself observed — cross-namespace access is structurally
unrepresentable, not merely checked.** The page never gets to say who it is; the
Electron main process derives the namespace from `event.senderFrame.url`.

> Status (v0.5.0): the engine, crypto, and browser-integration glue are complete
> and tested (crypto cross-verified against `@noble/ciphers`; plus a 78-check
> headless smoke over the actual glue). The integration has been **validated live
> in Electron** — `window.vault` round-trips, blobs land sealed on disk, the
> "Data" management pane lists/views/exports/deletes real partitions, and
> `freedom://dapps` launches the site grid. See [per-milestone status](#status).

## Repo layout

This repo holds the vault engine plus the reference glue that lands in the
browser fork. Expected sibling checkout:

```
projects/
  vault3r-code-public/   # this repo
  freedom-browser/       # https://github.com/0x-noad/freedom-browser (vault wired)
```

| Package | What it is |
|---|---|
| [`examples/freedom-browser-integration`](examples/freedom-browser-integration) | **The product surface.** The Electron main-process host (`DataVaultManager`), the keystore/storage/permissions adapters, the `window.vault` provider injected into pages, the preload bridges, the renderer "Data" management pane, the `freedom://dapps` launcher, and a local test dApp. Copy into the fork's `src/`; see its README for wiring. |
| [`packages/vault-core`](packages/vault-core) | The platform-agnostic engine: origin→namespace derivation, the request **chokepoint**, grant scoping (incl. per-field), the replay guard, an **anti-rollback** encrypted document store, the session state machine, and the owner/admin plane the Data pane is built on. |
| [`packages/crypto-core`](packages/crypto-core) | Ed25519 / X25519, **XChaCha20-Poly1305**, HKDF, namespace derivation + homograph detection, and **Argon2id + BIP-39 recovery** (DEK wrap/unwrap). Pure JS via `@noble/*` — runs in Node and the browser. |
| [`packages/protocol`](packages/protocol) | The single source of wire truth: JSON-RPC method catalog, error registry, typed data, the deterministic **canonical signing encoder**, transport interface. No dependencies. |
| [`packages/sdk`](packages/sdk) · [`servers/relay`](servers/relay) · [`examples/demo-dapp`](examples/demo-dapp) | The **remote path** — see [below](#the-remote-path). Not part of the browser build. |

## Quick start

### Engine + headless glue

```bash
pnpm install          # Node >= 20
pnpm test             # unit / integration tests across packages
pnpm typecheck
pnpm glue:smoke       # 78 checks against the real Freedom glue (no Electron)
```

### Run Freedom Browser with the vault

Clone the vault-wired Freedom fork
([`0x-noad/freedom-browser`](https://github.com/0x-noad/freedom-browser) — based on
[`solardev-xyz/freedom-browser`](https://github.com/solardev-xyz/freedom-browser)).
It already has `src/main/vault/` and the Data / dApps UI. Reference glue for
re-applying to a clean upstream clone lives in
[`examples/freedom-browser-integration/README.md`](examples/freedom-browser-integration/README.md).

```bash
# 1) Clone as siblings (skip if you already have them)
git clone https://github.com/absolutions19/vault3r-code-public.git
git clone https://github.com/0x-noad/freedom-browser.git

# 2) (Optional) rebuild the vendored @vault/* bundle into the fork
cd vault3r-code-public
pnpm install
pnpm bundle:freedom                    # → ../freedom-browser/src/main/vault/vendor/
# or: pnpm bundle:freedom /path/to/freedom-browser

# 3) Install + launch Freedom
cd ../freedom-browser
npm install
# Cursor / VS Code agent terminals set ELECTRON_RUN_AS_NODE=1, which breaks Electron:
unset ELECTRON_RUN_AS_NODE
npm start
# Log should include: [App] Data vault registered
```

Ant / IPFS / Radicle binaries are **optional** for vault testing — skip
`npm run ant:download` etc. unless you also need dweb navigation.

### Live-test `window.vault`

In a second terminal, serve the included test dApp and open it under a
**hostname** origin (IP literals and bare `localhost` are rejected by namespace
derivation — Chromium maps `*.localhost` to loopback):

```bash
cd vault3r-code-public
pnpm serve:vault-test
# → http://127.0.0.1:8765/  (server bind)
```

In Freedom's address bar open:

**http://vault-test.localhost:8765/**

Then:

1. Unlock the wallet (one unlock covers the data vault).
2. Confirm the badge says `window.vault ready`.
3. **Connect** → sidebar **Data** tab shows per-field Allow/Deny.
4. **Write** / **Read** / **Subscribe**.
5. Toolbar **Your dApps** (`freedom://dapps`) — tile for the test site.
6. Wallet sidebar → **Data** — list / view / delete / export that partition.

## How a dApp uses the vault

Freedom injects `window.vault` into every page (same idea as `window.ethereum`).
Your site never proves its identity — the browser derives the namespace from the
tab's real origin — and you can only ever read/write paths the user granted.

A working example lives at
[`examples/freedom-browser-integration/test-page/`](examples/freedom-browser-integration/test-page/).

### Detect the provider

```js
function getVault() {
  if (window.vault?.isVault3r) return window.vault;
  return null;
}

// Inject can arrive slightly after DOMContentLoaded:
window.addEventListener('vault#initialized', () => { /* retry */ });
```

If `window.vault` is missing, the user is not in Freedom (or the vault is not
wired). Do not polyfill it.

### Connect (asks for consent once)

```js
const { sessionId } = await window.vault.connect({
  appMetadata: {
    name: 'My dApp',
    // Optional tile for freedom://dapps. PNG / JPEG / WebP as a data: URI only —
    // no SVG, ≤ 64 KB, 8×8–512×512. Main re-encodes to a 128×128 PNG and pins it
    // at consent (a later connect cannot silently restyle the tile).
    icon: 'data:image/png;base64,…',
  },
  requestedScopes: [{
    methods: [
      'vault_getData',
      'vault_setData',
      'vault_patchData',
      'vault_subscribe',
      'vault_unsubscribe',
    ],
    // Per-field grants. The user can downgrade or drop fields in the Data tab.
    fields: [
      { path: '/profile', read: true, write: true },
      { path: '/prefs',   read: true, write: true },
    ],
  }],
});
```

- First visit: Freedom opens the wallet **Data** tab with per-field Allow/Deny.
- Return visit with a grant that already covers the request: reconnects silently.
- Denied / locked / unsupported origin → `connect()` rejects.
- Origins must be a real hostname (FQDN) or a dweb scheme (`ipfs://`, `ens://`,
  `bzz://`, …). **`http://127.0.0.1` and bare `localhost` are rejected** — use
  `http://app.localhost:port/` for local dev (Chromium maps `*.localhost` → loopback).

Keep `sessionId` for subsequent calls. It is bound to this tab; another page
cannot drive it.

### Read / write / patch

Paths are JSON-pointer-style strings under the fields you were granted. Writes
outside a granted path fail closed.

```js
// Write one or more values (object map of path → JSON-serializable value).
await window.vault.set(sessionId, {
  '/profile/handle': '@alice',
  '/prefs/theme': 'dark',
});

// Optional optimistic concurrency: pass the version you last observed.
// await window.vault.set(sessionId, values, baseVersion);

const { values } = await window.vault.get(sessionId, [
  '/profile/handle',
  '/prefs/theme',
]);
// values['/profile/handle'] === '@alice'

// Patch with JSON-patch-style ops (add / replace / remove):
await window.vault.patch(sessionId, [
  { op: 'replace', path: '/profile/handle', value: '@bob' },
]);
```

### Subscribe to changes

```js
const { subscriptionId } = await window.vault.subscribe(sessionId, ['/profile']);

window.vault.on('change', (update) => {
  // update.changes — paths that changed under your subscription
  console.log('vault changed', update);
});

window.vault.on('permissionsRevoked', () => {
  // User revoked in the Data tab — tear down UI / drop sessionId
});

await window.vault.unsubscribe(sessionId, subscriptionId);
```

### Permissions, disconnect, and the EIP-1193-shaped `request`

```js
const perms = await window.vault.getPermissions(sessionId);
await window.vault.disconnect(sessionId); // ends this session (vault_revoke)

// Same surface via request() if you prefer a single entry point:
await window.vault.request({
  method: 'vault_getData',
  params: { sessionId, paths: ['/profile/handle'] },
});
```

| Helper | RPC method | Purpose |
|---|---|---|
| `connect(opts)` | `vault_connect` | Consent + session |
| `get(sessionId, paths)` | `vault_getData` | Read granted paths |
| `set(sessionId, values, baseVersion?)` | `vault_setData` | Write map of paths |
| `patch(sessionId, ops, baseVersion?)` | `vault_patchData` | Patch ops |
| `subscribe` / `unsubscribe` | `vault_subscribe` / `vault_unsubscribe` | Live updates |
| `getPermissions(sessionId)` | `vault_getPermissions` | Current grant |
| `disconnect(sessionId)` | `vault_revoke` | End session |

### What a dApp cannot do

- Name another site's namespace, or read another origin's data.
- Supply its own origin — the browser takes it from the tab URL.
- Reach the owner plane (`window.vaultData` / `freedom://dapps` site list).
- Depend on a network `.well-known` fetch for the tile icon — icons are in-band
  at `connect()` only.

## How it fits together

```
 ┌─ page (renderer) ──────────────┐
 │  window.vault.connect/get/set  │   provider injected as source-as-data
 └───────────────┬────────────────┘
                 │ preload bridge  (page may claim nothing)
 ┌───────────────▼────────────────────────────────────────────┐
 │ Electron main                                              │
 │   DataVaultManager                                         │
 │     ├ origin ← event.senderFrame.url  → deriveOriginNamespace
 │     ├ sessionId bound to its webContents                   │
 │     ├ promptConsent ─────────► "Data" tab (per-field toggles)
 │     └ VaultEngine  (chokepoint · grants · anti-rollback)   │
 │           ├ keystore  ← HKDF from the unlocked mnemonic    │
 │           └ storage   → userData/vault-data/*.sealed (0600)│
 └────────────────────────────────────────────────────────────┘
```

- **Isolation** comes from the transport itself: the main process knows the caller's
  origin authoritatively, so a site's namespace is not something it can influence.
  dweb origins (`ipfs://`, `ens://`, `bzz://`, …) get a `web:dweb:` prefix with
  case-preserving canonicalization, so distinct CIDs never alias.
- **Consent** is explicit and per-field on first connect, persisted per origin so a
  returning site reconnects silently; revoking in the Data tab tears down live
  sessions and drops the grant.
- **At rest**, the data-vault DEK is derived from the browser's already-unlocked
  mnemonic via domain-separated HKDF — cryptographically distinct from the wallet
  keys, but covered by the same unlock — and each namespace is sealed independently
  with XChaCha20-Poly1305 under a rolling manifest for rollback/deletion detection.
- **The owner** sees everything through the Data pane: per-site usage, decrypted
  contents, export of the sealed bundle, delete-one, and clear-all. That plane
  bypasses per-site grants **by design** — it's the owner reading their own data
  through trusted UI, never reachable from a page.
- **`freedom://dapps`** is a privileged internal page listing every site that holds
  data, as a launcher (toolbar **Your dApps**). It is a browser page rather than a
  bookmarked site because that list is a cross-origin aggregate — giving any web
  origin the ability to enumerate it would turn "structurally unrepresentable" into
  "allowlisted". Site icons arrive in-band at `connect()` and are pinned, so
  rendering the grid makes no network requests and can't beacon your vault list.

See [docs/SECURITY.md](docs/SECURITY.md) for the threat model and how each
red-team-critical fix maps to code, and [docs/PROTOCOL.md](docs/PROTOCOL.md) for
the wire reference.

## The remote path

The same engine also speaks a **signed, relay-mediated protocol** for hosts that
*don't* own the caller's origin: a domain-bound Ed25519 identity published at
`/.well-known/vault-identity.json`, an X25519 handshake bound into that signature,
a zero-knowledge WebSocket relay that sees only ciphertext, a delegation backend
(CSRF + Origin + proof-of-possession + scope-clamp), and per-request signatures.
It lives in [`packages/sdk`](packages/sdk), [`servers/relay`](servers/relay), and
[`examples/demo-dapp`](examples/demo-dapp), and is fully tested end-to-end
(`pnpm demo` runs the relay, a headless vault, and the backend together).

It is **not part of the browser build** and there is no shipping remote vault host.
It stays in-tree because both paths share one engine and one namespace derivation —
`https://app.example.com` maps to `web:example.com` either way, so a site's data is
identical across transports — and because the demo exercises the engine
end-to-end over a hostile transport. The two paths cannot cross: `local*` methods
only accept `local` sessions, and a local session carries no delegated key, so any
signed request against it fails.

## Status

| Milestone | State |
|---|---|
| M0 monorepo + tooling | ✅ |
| M1 protocol | ✅ tested |
| M2 crypto-core | ✅ tested (noble-verified) |
| M3 vault-core engine | ✅ tested |
| M4 relay | ✅ tested |
| M5 SDK | ✅ tested (e2e) |
| M6 end-to-end proof | ✅ tested |
| M7 reference backend (CSRF+PoP) | ✅ tested (full-stack capstone) |
| v0.2.0 browser SDK bundle + demo page | ✅ tested (headless demo-flow) |
| v0.2.0 Argon2id + BIP-39 recovery (crypto-core) | ✅ tested |
| v0.2.0 session-extend caps + subscription re-auth | ✅ tested |
| v0.2.2 input hardening (strict JSON parser, DoS caps, revocation TOCTOU, proto-pollution) | ✅ tested (red-team + Forge) |
| v0.3.0 trusted in-process host mode (`connectLocal` + `local*` data plane; origin→namespace, incl. dweb) | ✅ tested (isolation, per-field grants, method gating, caps, subscriptions) |
| v0.3.1 Freedom Browser glue ([`examples/freedom-browser-integration`](examples/freedom-browser-integration)) | ✅ headless smoke + validated live in Electron (`window.vault`, sealed to disk) |
| v0.4.0 owner/admin plane + browser "Data" management pane (list · view · delete · clear · export · per-field consent) | ✅ engine tested + glue smoke + live in Electron |
| v0.5.0 `freedom://dapps` launcher + in-band site icons (validated, re-encoded, pinned at consent) | ✅ glue smoke + live in Electron |
| v0.5.0 metadata at rest: permission store encrypted via OS keychain (`safeStorage`, migrated); export bundle seals the site list under the DEK | ✅ glue smoke (**78** checks total) |

## Limitations (honest)

- The glue is **reference code that targets the fork's tree** — it is versioned and
  reviewed here, then copied into `src/`. It is not yet vendored as a dependency of
  the browser build.
- The DEK is derived from the identity mnemonic ("one unlock"), which couples data
  re-keying to a seed change; a separate data-vault secret would decouple them at
  the cost of a second unlock. The open decisions are listed at the end of the
  integration README.
- The data vault follows the identity vault's lock state — there is no separate idle
  timeout for data access yet.
- **Recovery** (Argon2id + BIP-39 DEK wrap/unwrap) is implemented and tested in
  `crypto-core`, but is not yet surfaced in the browser UI.
- The permission store is encrypted under the **OS keychain**, which is device-bound
  and same-user: it defends backups, disk clones and other OS users, not malware
  running as you. Sealed blob **filenames** are still unsalted hashes of the
  namespace, so the site list remains confirmable by guessing.
- The remote path's relay is a single-process reference; a production deployment
  would use e.g. Cloudflare Durable Objects and traffic-metadata minimization.
- Homograph detection uses a compact confusables table, not the full Unicode
  confusables set.
