/**
 * Data-Vault IPC channel names (Freedom Browser integration).
 *
 * Merge these into `src/shared/ipc-channels.js` (keep the single exported object
 * there — this file is split out only to keep the reference self-contained).
 * Naming follows the existing `namespace:action` convention (see `dapp:*`,
 * `swarm:*`). The renderer↔main data-plane uses sendToHost/webview.send like the
 * ethereum/swarm providers, not ipcMain.handle — see the manager + preload.
 */

module.exports = {
  // Per-site provider data plane (page -> host -> main -> engine -> back).
  VAULT_PROVIDER_REQUEST: 'vault:provider-request', // sendToHost from preload
  VAULT_PROVIDER_RESPONSE: 'vault:provider-response', // webview.send back to preload
  VAULT_PROVIDER_EVENT: 'vault:provider-event', // subscription / permissions_changed pushes

  // Consent prompt (main -> renderer modal -> main).
  VAULT_CONSENT_REQUEST: 'vault:consent-request',
  VAULT_CONSENT_RESULT: 'vault:consent-result',

  // Management (browser settings UI -> main).
  VAULT_GET_ALL_PERMISSIONS: 'vault:get-all-permissions',
  VAULT_REVOKE_PERMISSION: 'vault:revoke-permission',
  VAULT_IMPORT: 'vault:import',

  // Owner-facing "Data" pane (trusted wallet UI only). Distinct `datavault:`
  // prefix so these can never be confused with the site-facing provider path.
  VAULT_LIST_PARTITIONS: 'datavault:list-partitions',
  VAULT_USAGE: 'datavault:usage',
  VAULT_GET_PARTITION_DATA: 'datavault:get-partition-data',
  VAULT_DELETE_PARTITION: 'datavault:delete-partition',
  VAULT_CLEAR_ALL: 'datavault:clear-all',
  VAULT_EXPORT: 'datavault:export', // integration decision #5

  // Vault home page (`vault://home`) — the dApp launcher. Same owner-plane trust
  // level as the `datavault:*` channels above: wired ONLY to the internal page's
  // preload, never to a webview. Read-only + navigate; nothing destructive lives
  // on the launcher (management stays in the "Data" pane).
  VAULT_HOME_STATUS: 'datavault:home-status',
  VAULT_HOME_TILES: 'datavault:home-tiles',
  VAULT_HOME_OPEN: 'datavault:home-open',
  VAULT_HOME_UNLOCK: 'datavault:home-unlock',

  // Preload bootstrap (sync): fetch the window.vault inject source.
  VAULT_GET_INJECT_SOURCE: 'internal:get-vault-inject-source',
};
