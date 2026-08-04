/**
 * "Data" pane — the VAULT (data vault) management screen in the wallet sidebar.
 *
 * Lists every site that has a data partition, its on-disk size, and total usage;
 * lets the owner view a partition's stored data, delete a partition, clear all,
 * and export. Talks only to the trusted `window.vaultData` bridge (owner plane) —
 * never the site-facing `window.vault` provider.
 *
 * Self-contained: the detail view is an inline sub-view of #tab-data (no subscreen
 * machinery), so this module has no coupling to the wallet-state screen stack.
 */

function fmtBytes(n) {
  if (!n) return '0 B';
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(2)} MB`;
}
function hostOf(origin) {
  try {
    return new URL(origin).host || origin;
  } catch {
    return origin || '—';
  }
}

export function initVaultData(opts = {}) {
  const panel = document.getElementById('tab-data');
  if (!panel) return { refresh: () => {} };
  const openAndFocus = typeof opts.openAndFocus === 'function' ? opts.openAndFocus : () => {};
  // Host seam: show whatever unlock UI the browser already owns (the data vault
  // has none of its own — one unlock covers the identity vault and this one).
  const requestUnlock = typeof opts.requestUnlock === 'function' ? opts.requestUnlock : null;

  const lockedView = document.getElementById('vault-locked-view');
  const unlockBtn = document.getElementById('vault-unlock-btn');
  const listView = document.getElementById('vault-list-view');
  const detailView = document.getElementById('vault-detail-view');
  const requestView = document.getElementById('vault-request-view');
  const listEl = document.getElementById('vault-partition-list');
  const usageText = document.getElementById('vault-usage-text');
  const usageFill = document.getElementById('vault-usage-bar-fill');
  const exportBtn = document.getElementById('vault-export-btn');
  const clearBtn = document.getElementById('vault-clear-btn');
  const backBtn = document.getElementById('vault-detail-back');
  const detailTitle = document.getElementById('vault-detail-title');
  const detailNs = document.getElementById('vault-detail-ns');
  const detailFields = document.getElementById('vault-detail-fields');
  const detailJson = document.getElementById('vault-detail-json');
  const detailDelete = document.getElementById('vault-detail-delete');
  // Consent request view
  const reqApp = document.getElementById('vault-request-app');
  const reqOrigin = document.getElementById('vault-request-origin');
  const reqFields = document.getElementById('vault-request-fields');
  const reqAllow = document.getElementById('vault-request-allow');
  const reqDeny = document.getElementById('vault-request-deny');
  let currentNs = null;

  function setView(name) {
    listView.classList.toggle('hidden', name !== 'list');
    detailView.classList.toggle('hidden', name !== 'detail');
    requestView.classList.toggle('hidden', name !== 'request');
  }

  async function refresh() {
    if (!window.vaultData) {
      listEl.innerHTML = '<div class="vault-empty">Vault unavailable.</div>';
      return;
    }
    let usage;
    let parts;
    try {
      usage = await window.vaultData.getUsage();
      parts = await window.vaultData.listPartitions();
    } catch (err) {
      listEl.innerHTML = `<div class="vault-empty">Error: ${err.message}</div>`;
      return;
    }

    // Locked: show the unlock prompt and NOTHING else. Not even the site count —
    // the list of sites you hold data for is history-shaped, and a locked vault
    // must not display it to whoever walks up to the browser.
    setLocked(!usage.unlocked);
    if (!usage.unlocked) return;

    const count = usage.partitionCount;
    usageText.textContent = `${fmtBytes(usage.totalBytes)} · ${count} site${count === 1 ? '' : 's'}`;
    const cap = Math.max(usage.totalBytes, 64 * 1024);
    usageFill.style.width = `${Math.min(100, Math.round((usage.totalBytes / cap) * 100))}%`;
    renderList(parts);
  }

  /** Swap the whole pane between its locked prompt and its normal content. */
  function setLocked(locked) {
    if (lockedView) lockedView.classList.toggle('hidden', !locked);
    // Hide every real view while locked, and drop any stale rows so nothing
    // survives behind the prompt.
    if (locked) {
      listView.classList.add('hidden');
      detailView.classList.add('hidden');
      requestView.classList.add('hidden');
      listEl.innerHTML = '';
      usageText.textContent = '';
      usageFill.style.width = '0%';
      currentNs = null;
    } else if (listView.classList.contains('hidden') && detailView.classList.contains('hidden') && requestView.classList.contains('hidden')) {
      listView.classList.remove('hidden');
    }
  }

  function renderList(parts) {
    listEl.innerHTML = '';
    if (!parts.length) {
      listEl.innerHTML = '<div class="vault-empty">No sites have stored data yet.</div>';
      return;
    }
    for (const p of parts) {
      const row = document.createElement('div');
      row.className = 'vault-row';

      const info = document.createElement('div');
      info.className = 'vault-row-info';
      const name = document.createElement('div');
      name.className = 'vault-row-host';
      name.textContent = hostOf(p.origin);
      const meta = document.createElement('div');
      meta.className = 'vault-row-meta';
      const nf = (p.fields || []).length;
      meta.textContent = `${fmtBytes(p.bytes)} · ${nf} field${nf === 1 ? '' : 's'}`;
      info.appendChild(name);
      info.appendChild(meta);
      info.addEventListener('click', () => showDetail(p));

      const del = document.createElement('button');
      del.className = 'vault-row-delete';
      del.title = 'Delete this site’s data';
      del.textContent = '🗑';
      del.addEventListener('click', async (e) => {
        e.stopPropagation();
        if (!window.confirm(`Delete all data for ${hostOf(p.origin)}? This cannot be undone.`)) return;
        await window.vaultData.deletePartition(p.namespace);
        refresh();
      });

      row.appendChild(info);
      row.appendChild(del);
      listEl.appendChild(row);
    }
  }

  async function showDetail(p) {
    currentNs = p.namespace;
    detailTitle.textContent = hostOf(p.origin);
    detailNs.textContent = p.namespace;
    detailFields.innerHTML = (p.fields || [])
      .map((f) => `<span class="vault-pill ${f.write ? 'rw' : 'ro'}">${f.path} ${f.write ? 'rw' : 'r'}</span>`)
      .join('');
    detailJson.textContent = 'Loading…';
    setView('detail');
    try {
      const res = await window.vaultData.getPartitionData(p.namespace);
      detailJson.textContent = res.locked
        ? '🔒 Vault locked — unlock to view stored data.'
        : JSON.stringify(res.data, null, 2);
    } catch (err) {
      detailJson.textContent = `Error: ${err.message}`;
    }
  }

  function showList() {
    setView('list');
    refresh();
  }

  // --- consent request (a site is asking for access) -------------------------
  function showRequest(req) {
    reqApp.textContent = (req.appMetadata && req.appMetadata.name) || 'A website';
    reqOrigin.textContent = req.origin || req.namespace || '';
    const fields = (req.requestedScopes || []).flatMap((s) => s.fields || []);
    reqFields.innerHTML = '';
    for (const f of fields) {
      const row = document.createElement('div');
      row.className = 'vault-req-field';
      const path = document.createElement('span');
      path.className = 'vault-req-path';
      path.textContent = f.path;
      row.appendChild(path);
      for (const mode of ['read', 'write']) {
        const wrap = document.createElement('label');
        wrap.className = 'vault-req-tog';
        const cb = document.createElement('input');
        cb.type = 'checkbox';
        cb.dataset.path = f.path;
        cb.dataset.mode = mode;
        cb.checked = mode === 'read' ? f.read !== false : f.write === true; // default to what was asked
        wrap.appendChild(cb);
        wrap.appendChild(document.createTextNode(mode));
        row.appendChild(wrap);
      }
      reqFields.appendChild(row);
    }
    // Surface it: open the sidebar + switch to the Data tab, then show the request.
    openAndFocus();
    setView('request');

    const methods = [...new Set((req.requestedScopes || []).flatMap((s) => s.methods || []))];
    reqAllow.onclick = () => {
      const byPath = new Map();
      reqFields.querySelectorAll('input[type=checkbox]').forEach((cb) => {
        const g = byPath.get(cb.dataset.path) || { path: cb.dataset.path, read: false, write: false };
        g[cb.dataset.mode] = cb.checked;
        byPath.set(cb.dataset.path, g);
      });
      const grantedFields = [...byPath.values()].filter((g) => g.read || g.write);
      window.vaultData.respondConsent(req.id, { approved: true, grantedMethods: methods, grantedFields, writePolicy: 'ask-once-per-session' });
      showList();
    };
    reqDeny.onclick = () => {
      window.vaultData.respondConsent(req.id, { approved: false, reason: 'user denied' });
      showList();
    };
  }

  backBtn.addEventListener('click', showList);
  detailDelete.addEventListener('click', async () => {
    if (!currentNs) return;
    if (!window.confirm('Delete all data for this site? This cannot be undone.')) return;
    await window.vaultData.deletePartition(currentNs);
    showList();
  });
  exportBtn.addEventListener('click', async () => {
    try {
      const r = await window.vaultData.exportVault();
      if (r && r.saved) {
        exportBtn.textContent = 'Exported ✓';
        setTimeout(() => {
          exportBtn.textContent = 'Export vault';
        }, 1500);
      }
    } catch (err) {
      console.error('[vault-data] export failed', err);
    }
  });
  clearBtn.addEventListener('click', async () => {
    if (!window.confirm('Delete ALL vault data for every site? This cannot be undone.')) return;
    await window.vaultData.clearAll();
    refresh();
  });

  if (unlockBtn && requestUnlock) {
    unlockBtn.addEventListener('click', async () => {
      unlockBtn.disabled = true;
      try {
        await requestUnlock();
      } catch {
        // cancelled — refresh re-reads the real lock state either way
      } finally {
        unlockBtn.disabled = false;
        refresh();
      }
    });
  }

  // Consent: main pushes a request when a site connects for the first time.
  if (window.vaultData && window.vaultData.onConsentRequest) {
    window.vaultData.onConsentRequest(showRequest);
    window.vaultData.signalReady();
  }

  return { refresh };
}
