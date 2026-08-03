/**
 * MAIN-WINDOW preload additions for the "Data" pane (Freedom Browser integration).
 *
 * Merge this into the browser's main-window contextBridge preload
 * (`src/main/preload.js`) — the SAME file that already exposes `window.wallet`,
 * `window.dappPermissions`, etc. This is the OWNER/management surface and is
 * deliberately separate from the site-facing `window.vault` provider (which is
 * injected into web pages by `webview-preload.js`). A website can never reach
 * these channels.
 *
 * Channel strings must match src/main/vault/vault-ipc-channels.js (the browser
 * keeps preload strings and the shared constants in sync by hand — see the note
 * at the top of the existing preload.js).
 */

const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('vaultData', {
  /** [{ namespace, origin, appName, fields, methods, bytes, lastUsed, connectedAt }] */
  listPartitions: () => ipcRenderer.invoke('datavault:list-partitions'),
  /** { totalBytes, partitionCount, unlocked } */
  getUsage: () => ipcRenderer.invoke('datavault:usage'),
  /** { namespace, locked, data?, bytes? } — data present only when unlocked */
  getPartitionData: (namespace) => ipcRenderer.invoke('datavault:get-partition-data', namespace),
  /** { deleted, namespace, freedBytes } */
  deletePartition: (namespace) => ipcRenderer.invoke('datavault:delete-partition', namespace),
  /** { cleared, freedBytes } */
  clearAll: () => ipcRenderer.invoke('datavault:clear-all'),
  /** { saved, path?, canceled? } — main shows the save dialog */
  exportVault: () => ipcRenderer.invoke('datavault:export'),
});
