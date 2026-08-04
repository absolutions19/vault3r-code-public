/**
 * VAULT HOME — launcher grid for `vault://home`.
 *
 * Renders one tile per site holding data in the vault: the site's pinned icon (or
 * a deterministic monogram when it shipped none), its name underneath, click to
 * launch. Read-only: management (view / delete / revoke / export) lives in the
 * wallet's "Data" pane, so nothing destructive sits on a surface people open all
 * the time.
 *
 * Talks ONLY to `window.vaultHome` (owner plane, internal page). Vanilla JS +
 * explicit DOM construction — matching the browser's existing renderer modules,
 * and avoiding innerHTML entirely because every name and icon on this page is
 * ultimately site-supplied.
 *
 * Copy to `src/renderer/lib/vault-home.js`.
 */

const els = {
  subtitle: document.getElementById('vh-subtitle'),
  locked: document.getElementById('vh-locked'),
  unlockBtn: document.getElementById('vh-unlock-btn'),
  grid: document.getElementById('vh-grid'),
  empty: document.getElementById('vh-empty'),
};

function show(el, visible) {
  if (el) el.classList.toggle('hidden', !visible);
}

/** The site's own icon, already validated + re-encoded by main. */
function iconEl(tile) {
  const img = document.createElement('img');
  img.className = 'vh-tile-icon';
  img.src = tile.icon;
  img.alt = '';
  img.draggable = false;
  // If the bytes still fail to decode in the renderer, fall back rather than
  // leaving a broken-image tile.
  img.addEventListener('error', () => img.replaceWith(monogramEl(tile)), { once: true });
  return img;
}

/** Deterministic fallback: first letter on a hue derived from the namespace. */
function monogramEl(tile) {
  const mono = document.createElement('div');
  mono.className = 'vh-tile-icon vh-tile-monogram';
  const { letter = '?', hue = 0 } = tile.monogram || {};
  mono.style.setProperty('--vh-hue', String(hue));
  mono.textContent = letter;
  mono.setAttribute('aria-hidden', 'true');
  return mono;
}

function tileEl(tile) {
  const btn = document.createElement('button');
  btn.className = 'vh-tile';
  btn.type = 'button';
  // The accessible name is the site's own claimed name plus the host it actually
  // resolves to, so a lookalike name can't stand alone unchallenged.
  btn.setAttribute('aria-label', tile.host ? `${tile.name} — ${tile.host}` : tile.name);
  btn.title = tile.host || tile.namespace;

  btn.appendChild(tile.icon ? iconEl(tile) : monogramEl(tile));

  const label = document.createElement('span');
  label.className = 'vh-tile-name';
  label.textContent = tile.name;
  btn.appendChild(label);

  btn.addEventListener('click', async () => {
    btn.disabled = true;
    try {
      // Pass the namespace, never a URL — main owns the destination.
      const res = await window.vaultHome.open(tile.namespace);
      if (!res || !res.opened) btn.disabled = false;
    } catch {
      btn.disabled = false;
    }
  });
  return btn;
}

function renderGrid(tiles) {
  els.grid.replaceChildren();
  for (const tile of tiles) els.grid.appendChild(tileEl(tile));
  show(els.grid, tiles.length > 0);
  show(els.empty, tiles.length === 0);
}

async function refresh() {
  if (!window.vaultHome) {
    els.subtitle.textContent = 'Vault unavailable.';
    return;
  }

  const status = await window.vaultHome.status();
  if (!status.unlocked) {
    // Locked shows the unlock prompt and nothing else — no tiles, no count.
    els.subtitle.textContent = '';
    show(els.locked, true);
    show(els.grid, false);
    show(els.empty, false);
    return;
  }
  show(els.locked, false);

  const { tiles } = await window.vaultHome.tiles();
  const n = tiles.length;
  els.subtitle.textContent = n ? `${n} site${n === 1 ? '' : 's'} with data in your vault` : '';
  renderGrid(tiles);
}

els.unlockBtn?.addEventListener('click', async () => {
  els.unlockBtn.disabled = true;
  try {
    await window.vaultHome.requestUnlock();
    await refresh();
  } finally {
    els.unlockBtn.disabled = false;
  }
});

// Re-check on focus: the vault may have been locked or unlocked, or a new site
// granted, while this tab sat in the background.
window.addEventListener('focus', () => {
  refresh().catch(() => {});
});

refresh().catch((err) => {
  els.subtitle.textContent = `Error: ${err && err.message}`;
});
