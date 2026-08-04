/**
 * VAULT HOME preload (Freedom Browser integration) — `window.vaultHome`.
 *
 * This is the bridge for the internal `vault://home` launcher page ONLY.
 *
 * ⚠️  WIRING RULE — the whole security argument for the home page rests on this:
 * attach this preload to the BrowserWindow/BrowserView that loads the internal
 * page and to nothing else. It must never appear in `webPreferences.preload` for
 * a webview or any window that can be navigated to web content. If a site could
 * reach `window.vaultHome.tiles()`, it would learn every origin you hold data
 * for — the exact cross-origin history leak the vault exists to prevent.
 *
 * Belt and braces (do all of these in the host):
 *  - Give the home page its own session/partition; deny it network access.
 *  - Refuse to load any URL but the internal one in that window (`will-navigate`).
 *  - Keep it top-level and unframeable so a page can't embed it for clickjacking.
 *
 * The surface is deliberately small and non-destructive: read the grid, launch a
 * site by NAMESPACE (never by URL), ask the host to unlock. Delete / revoke /
 * export live on `window.vaultData` in the wallet's "Data" pane.
 *
 * Channel strings must match src/main/vault/vault-ipc-channels.js.
 */

const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('vaultHome', {
  /** { unlocked: false } | { unlocked: true, count } — no count while locked. */
  status: () => ipcRenderer.invoke('datavault:home-status'),

  /** { locked, tiles: [{ namespace, name, host, icon, monogram: { letter, hue }, lastUsed }] } */
  tiles: () => ipcRenderer.invoke('datavault:home-tiles'),

  /**
   * Launch a tile. Takes the NAMESPACE, not a URL — main resolves it to the
   * origin the browser itself observed at grant time, so the launcher can never
   * be used to navigate somewhere arbitrary.
   * @returns {Promise<{ opened: boolean, url?: string, reason?: string }>}
   */
  open: (namespace) => ipcRenderer.invoke('datavault:home-open', namespace),

  /** Drives the locked-state button. { unlocked } */
  requestUnlock: () => ipcRenderer.invoke('datavault:home-unlock'),
});
