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
  VAULT_EXPORT: 'vault:export', // integration decision #5
  VAULT_IMPORT: 'vault:import',

  // Preload bootstrap (sync): fetch the window.vault inject source.
  VAULT_GET_INJECT_SOURCE: 'internal:get-vault-inject-source',
};
