/**
 * Preload additions for window.vault (Freedom Browser integration).
 *
 * These snippets are meant to be MERGED into `src/main/webview-preload.js`,
 * alongside the existing ethereum + swarm provider bridges. They mirror those
 * bridges exactly, with one deliberate difference that matters for security:
 *
 *   The vault data plane goes page -> preload -> MAIN via ipcRenderer.invoke,
 *   NOT via sendToHost to the shell renderer. This keeps the origin authoritative:
 *   the main process reads event.senderFrame.url and the page can never assert a
 *   different origin. (The ethereum provider routes through the shell because its
 *   trust model differs; VAULT's whole guarantee is per-origin isolation.)
 *
 * Do not copy this file wholesale — splice the three blocks below into the
 * corresponding regions of webview-preload.js and run `npm run lint` after.
 */

/* eslint-disable */
const { ipcRenderer } = require('electron');

// --- 1) Fetch + inject the window.vault source (near ETHEREUM_INJECT_SOURCE) ---
const VAULT_INJECT_SOURCE = ipcRenderer.sendSync('internal:get-vault-inject-source');

try {
  const vaultScript = document.createElement('script');
  vaultScript.textContent = VAULT_INJECT_SOURCE;
  const injectVault = () => {
    const head = document.head || document.documentElement;
    head.insertBefore(vaultScript, head.firstChild);
    vaultScript.remove();
  };
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', injectVault, { once: true });
  } else {
    injectVault();
  }
} catch (err) {
  console.error('[webview-preload] Failed to inject vault provider:', err);
}

// --- 2) Bridge page -> main (request) and main -> page (response) --------------
window.addEventListener('message', async (event) => {
  if (event.source !== window) return;
  if (!event.data || event.data.type !== 'FREEDOM_VAULT_REQUEST') return;
  const { id, method, params } = event.data;
  // Origin is derived in MAIN from event.senderFrame.url — we intentionally send
  // no origin here; anything the page put in params.origin is ignored.
  let payload;
  try {
    payload = await ipcRenderer.invoke('vault:provider-request', { method, params });
  } catch (err) {
    payload = { error: { code: err.code || -32603, message: err.message } };
  }
  window.postMessage(
    { type: 'FREEDOM_VAULT_RESPONSE', id, result: payload.result, error: payload.error },
    window.location.origin
  );
});

// --- 3) Bridge main -> page (subscription / permission events) ----------------
ipcRenderer.on('vault:provider-event', (_event, { notification }) => {
  window.postMessage(
    { type: 'FREEDOM_VAULT_EVENT', notification },
    window.location.origin
  );
});
