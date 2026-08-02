/**
 * window.vault provider injection SOURCE (Freedom Browser integration).
 *
 * IMPORTANT: source-as-data — like `webview-preload-ethereum-inject.js`, this
 * text is read by the main process and injected as a <script> into the page
 * realm. It runs in the PAGE, so: no require, no Node, no Electron, no preload
 * scope. It talks to the preload bridge only via window.postMessage.
 *
 * Mirrors the shape of the existing window.ethereum / window.swarm providers:
 * a request/response map over postMessage, plus an event emitter for
 * subscription updates and permission-revocation pushes.
 *
 * The main process serves this over the sync channel VAULT_GET_INJECT_SOURCE.
 */

module.exports = `
(function () {
  if (window.vault) return;
  const pending = new Map();
  let requestId = 0;
  const listeners = { change: [], permissionsRevoked: [] };

  function emit(event, data) {
    (listeners[event] || []).forEach(function (h) { try { h(data); } catch (e) {} });
  }

  function call(method, params) {
    const id = ++requestId;
    return new Promise(function (resolve, reject) {
      pending.set(id, { resolve: resolve, reject: reject });
      window.postMessage({ type: 'FREEDOM_VAULT_REQUEST', id: id, method: method, params: params || {} }, '*');
      setTimeout(function () {
        if (pending.has(id)) { pending.delete(id); const e = new Error('Vault request timed out'); e.code = -32603; reject(e); }
      }, 120000);
    });
  }

  // EIP-1193-shaped surface, scoped to VAULT's methods. A site connects once,
  // then reads/writes its own namespaced slice.
  window.vault = {
    isVault3r: true,

    request: function (args) {
      if (!args || !args.method) return Promise.reject(new Error('method is required'));
      return call(args.method, args.params);
    },

    // Convenience wrappers over request().
    connect: function (opts) { return call('vault_connect', opts || {}); },
    get: function (sessionId, paths) { return call('vault_getData', { sessionId: sessionId, paths: paths }); },
    set: function (sessionId, values, baseVersion) { return call('vault_setData', { sessionId: sessionId, values: values, baseVersion: baseVersion }); },
    patch: function (sessionId, ops, baseVersion) { return call('vault_patchData', { sessionId: sessionId, ops: ops, baseVersion: baseVersion }); },
    subscribe: function (sessionId, paths) { return call('vault_subscribe', { sessionId: sessionId, paths: paths }); },
    unsubscribe: function (sessionId, subscriptionId) { return call('vault_unsubscribe', { sessionId: sessionId, subscriptionId: subscriptionId }); },
    getPermissions: function (sessionId) { return call('vault_getPermissions', { sessionId: sessionId }); },
    disconnect: function (sessionId) { return call('vault_revoke', { sessionId: sessionId }); },

    on: function (event, handler) { if (listeners[event]) listeners[event].push(handler); return this; },
    removeListener: function (event, handler) {
      if (listeners[event]) { const i = listeners[event].indexOf(handler); if (i > -1) listeners[event].splice(i, 1); }
      return this;
    },
    removeAllListeners: function (event) {
      if (event && listeners[event]) listeners[event] = [];
      else if (!event) Object.keys(listeners).forEach(function (k) { listeners[k] = []; });
      return this;
    },
  };

  window.addEventListener('message', function (event) {
    if (event.source !== window) return;
    const d = event.data;
    if (!d || typeof d !== 'object') return;
    if (d.type === 'FREEDOM_VAULT_RESPONSE') {
      const p = pending.get(d.id);
      if (p) {
        pending.delete(d.id);
        if (d.error) { const e = new Error(d.error.message); e.code = d.error.code; p.reject(e); }
        else p.resolve(d.result);
      }
    } else if (d.type === 'FREEDOM_VAULT_EVENT') {
      // Subscription updates arrive as { method: 'vault_subscription', params }.
      // Permission revocations arrive as { method: 'vault_permissionsRevoked', params }.
      const n = d.notification || {};
      if (n.method === 'vault_permissionsRevoked') emit('permissionsRevoked', n.params);
      else emit('change', n.params);
    }
  });

  window.dispatchEvent(new Event('vault#initialized'));
})();
`;
