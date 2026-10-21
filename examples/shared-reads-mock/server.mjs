/**
 * Two mock sites for testing cross-partition vault reads.
 *
 * One server, two origins, routed by Host header:
 *   http://owner.localhost:8799   publishes under /shared
 *   http://owner2.localhost:8799  a second, independent owner
 *   http://reader.localhost:8799  asks to read one or both owners' /shared
 *
 * The port matters: the vault's namespace IS the origin
 * (`web:http://owner.localhost:8799`), port included, so the origin the reader
 * names must match the one the owner was served on exactly. It is baked into
 * the pages from PORT below rather than typed in two places.
 *
 * No dependencies. Run with: node server.mjs
 */

import http from 'node:http';

const PORT = 8799;
const OWNER_ORIGIN = `http://owner.localhost:${PORT}`;
const OWNER2_ORIGIN = `http://owner2.localhost:${PORT}`;
const READER_ORIGIN = `http://reader.localhost:${PORT}`;

const SHELL = (title, accent, body) => `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>${title}</title>
<style>
  :root { color-scheme: dark light; }
  body {
    font: 15px/1.5 system-ui, sans-serif;
    max-width: 44rem; margin: 2.5rem auto; padding: 0 1.25rem;
  }
  h1 { font-size: 1.3rem; margin: 0 0 .25rem; }
  h1 .tag {
    font-size: .7rem; font-weight: 600; letter-spacing: .08em; text-transform: uppercase;
    vertical-align: .3em; margin-left: .5rem; padding: .15rem .45rem;
    border-radius: 999px; background: ${accent}; color: #fff;
  }
  .origin { font-family: ui-monospace, Menlo, monospace; font-size: .8rem; opacity: .65; margin-bottom: 1.5rem; }
  section { border: 1px solid currentColor; border-radius: 10px; padding: 1rem 1.1rem; margin-bottom: 1rem; opacity: .95; }
  section h2 { font-size: .95rem; margin: 0 0 .3rem; }
  section p { margin: .2rem 0 .7rem; font-size: .86rem; opacity: .75; }
  button {
    font: inherit; font-size: .88rem; padding: .45rem .8rem; margin: .15rem .3rem .15rem 0;
    border-radius: 7px; border: 1px solid currentColor; background: transparent; color: inherit; cursor: pointer;
  }
  button.primary { background: ${accent}; border-color: ${accent}; color: #fff; }
  button:disabled { opacity: .4; cursor: default; }
  input { font: inherit; font-size: .88rem; padding: .4rem .55rem; border-radius: 7px; border: 1px solid currentColor; background: transparent; color: inherit; width: 14rem; }
  pre {
    font-family: ui-monospace, Menlo, monospace; font-size: .78rem; line-height: 1.55;
    white-space: pre-wrap; word-break: break-word;
    background: color-mix(in srgb, currentColor 7%, transparent);
    border-radius: 8px; padding: .7rem .8rem; margin: 0; max-height: 22rem; overflow: auto;
  }
  .no-vault { border-color: #e0245e; }
</style>
</head>
<body>
${body}
<section>
  <h2>Log</h2>
  <pre id="log">waiting for window.vault…</pre>
</section>
<script type="module">
const OWNER_ORIGIN = ${JSON.stringify(OWNER_ORIGIN)};
const OWNER2_ORIGIN = ${JSON.stringify(OWNER2_ORIGIN)};
const READER_ORIGIN = ${JSON.stringify(READER_ORIGIN)};
const logEl = document.getElementById('log');
let lines = [];
function log(...parts) {
  const text = parts
    .map((p) => (typeof p === 'string' ? p : JSON.stringify(p, null, 2)))
    .join(' ');
  lines.push(text);
  logEl.textContent = lines.join('\\n');
  logEl.scrollTop = logEl.scrollHeight;
}
function fail(err) {
  // Branch on the code, never the message: 4312 is a locked vault.
  log('✗ ' + (err && err.message), err && err.code ? '(code ' + err.code + ')' : '');
}
function whenReady() {
  if (window.vault) return Promise.resolve();
  return new Promise((r) => window.addEventListener('vault#initialized', r, { once: true }));
}
window.__mock = { log, fail, whenReady, OWNER_ORIGIN, OWNER2_ORIGIN, READER_ORIGIN };
</script>
<script type="module" src="/page.js"></script>
</body>
</html>`;

const OWNER_BODY = (origin, label) => `
<h1>${label} <span class="tag">publishes</span></h1>
<div class="origin">${origin} &nbsp;→&nbsp; web:${origin}</div>

<section>
  <h2>1 &middot; Connect</h2>
  <p>Asks for its own <code>/private/notes</code> and for <code>/shared</code>. Ticking
     <strong>write</strong> on the <code>/shared</code> row should raise the blue note
     on the consent sheet — that note is the only place the user learns
     <code>/shared</code> is the shareable area.</p>
  <button class="primary" id="connect">Connect</button>
</section>

<section>
  <h2>2 &middot; Publish</h2>
  <p>Writes to <code>/shared/displayName</code>, which is what the reader will ask for.</p>
  <input id="name" value="ada" aria-label="display name" />
  <button id="publish" disabled>Publish</button>
  <button id="write-private" disabled>Write something private</button>
  <button id="read-own" disabled>Read my own data</button>
</section>

<section>
  <h2>3 &middot; The publish gate</h2>
  <p>Connects a second time asking for the <em>whole document</em> instead, then tries to
     write under <code>/shared</code>. It should be refused: a grant that merely covers
     the subtree does not carry the right to publish, or a site could publish without the
     user ever seeing the word.</p>
  <button id="gate" disabled>Try publishing without an explicit grant</button>
</section>
`;

const READER_BODY = `
<h1>Reader site <span class="tag">reads</span></h1>
<div class="origin">${READER_ORIGIN} &nbsp;→&nbsp; web:${READER_ORIGIN}</div>

<section>
  <h2>1 &middot; Connect, naming the owner</h2>
  <p>One sheet covers both: this site's own field, then a separate group headed
     <code>${OWNER_ORIGIN}</code>. The foreign group should offer <strong>read only</strong> —
     no write checkbox at all.</p>
  <button class="primary" id="connect-named">Connect — one named pointer</button>
  <button id="connect-wholesale">Connect — all of /shared</button>
  <button id="connect-both">Connect — naming BOTH owners</button>
  <p style="margin-top:.6rem">The wholesale ask should render differently: one row saying it
     covers anything the owner adds later, rather than a list of fields.</p>
</section>

<section>
  <h2>2 &middot; Read the owner's published data</h2>
  <button id="read" disabled>Read /shared/displayName</button>
  <button id="read2" disabled>Read owner2's /shared/displayName</button>
  <button id="read-private" disabled>Try reading the owner's /private/notes</button>
  <p style="margin-top:.6rem">The second should come back <code>null</code>, not an error —
     nothing outside <code>/shared</code> can cross the boundary.</p>
</section>

<section>
  <h2>3 &middot; No existence oracle</h2>
  <p>Reads two origins this site was never approved for: one you have probably visited and
     one that does not exist. Both should answer identically, so neither tells the page
     which sites the user has data for.</p>
  <button id="oracle" disabled>Compare an unapproved owner with a nonexistent one</button>
</section>
`;

const OWNER_JS = `
const { log, fail, whenReady, OWNER_ORIGIN } = window.__mock;
let session = null;

const enable = (on) => {
  for (const id of ['publish', 'write-private', 'read-own', 'gate']) {
    document.getElementById(id).disabled = !on;
  }
};

whenReady().then(() => log('window.vault ready'), () => log('no vault'));

document.getElementById('connect').onclick = async () => {
  try {
    await whenReady();
    session = await window.vault.connect({
      requestedScopes: [
        {
          methods: ['vault_getData', 'vault_setData'],
          fields: [
            { path: '/private/notes', read: true, write: true },
            // Explicit: publishing needs a grant rooted at or below /shared.
            { path: '/shared', read: true, write: true },
          ],
        },
      ],
      appMetadata: { name: document.title },
    });
    log('connected', { namespace: session.namespace, granted: session.grant.fields });
    enable(true);
  } catch (err) { fail(err); }
};

document.getElementById('publish').onclick = async () => {
  try {
    const value = document.getElementById('name').value;
    const res = await window.vault.set(session.sessionId, { '/shared/displayName': value });
    log('published /shared/displayName =', JSON.stringify(value), res);
  } catch (err) { fail(err); }
};

document.getElementById('write-private').onclick = async () => {
  try {
    const res = await window.vault.set(session.sessionId, { '/private/notes': 'not for sharing' });
    log('wrote /private/notes (the reader must never see this)', res);
  } catch (err) { fail(err); }
};

document.getElementById('read-own').onclick = async () => {
  try {
    const res = await window.vault.get(session.sessionId, ['/shared/displayName', '/private/notes']);
    log('my own data', res.values);
  } catch (err) { fail(err); }
};

document.getElementById('gate').onclick = async () => {
  try {
    // A second session on the SAME partition, asking for the whole document.
    const whole = await window.vault.connect({
      requestedScopes: [
        { methods: ['vault_getData', 'vault_setData'], fields: [{ path: '', read: true, write: true }] },
      ],
      appMetadata: { name: 'Owner site (whole document)' },
    });
    log('second session, whole-document grant', { namespace: whole.namespace });
    try {
      await window.vault.set(whole.sessionId, { '/shared/sneaky': 'published without asking' });
      log('✗ UNEXPECTED: the publish gate let this through');
    } catch (err) {
      log('✓ refused, as it should be:', err.message, '(code ' + err.code + ')');
    }
    // The same grant still writes everywhere else.
    const ok = await window.vault.set(whole.sessionId, { '/elsewhere/fine': 1 });
    log('✓ and the same grant still writes outside /shared', ok);
  } catch (err) { fail(err); }
};
`;

const READER_JS = `
const { log, fail, whenReady, OWNER_ORIGIN, OWNER2_ORIGIN } = window.__mock;
let session = null;

const enable = (on) => {
  for (const id of ['read', 'read2', 'read-private', 'oracle']) {
    document.getElementById(id).disabled = !on;
  }
};

whenReady().then(() => log('window.vault ready'), () => log('no vault'));

async function connect(foreign, label) {
  try {
    await whenReady();
    session = await window.vault.connect({
      requestedScopes: [
        {
          methods: ['vault_getData', 'vault_setData', 'vault_getSharedData'],
          fields: [{ path: '/own/seen', read: true, write: true }],
          foreign,
        },
      ],
      appMetadata: { name: 'Reader site' },
    });
    log('connected (' + label + ')', {
      namespace: session.namespace,
      foreignReads: session.grant.foreignReads,
    });
    if (!session.grant.foreignReads || session.grant.foreignReads.length === 0) {
      log('note: no cross-origin read was granted — the row was unticked, or the sheet declined it');
    }
    enable(true);
  } catch (err) { fail(err); }
}

document.getElementById('connect-named').onclick = () =>
  connect([{ origin: OWNER_ORIGIN, paths: ['/shared/displayName'] }], 'one named pointer');
document.getElementById('connect-wholesale').onclick = () =>
  connect([{ origin: OWNER_ORIGIN, paths: ['/shared'] }], 'all of /shared');
// Asking for a SECOND owner is what forces a re-prompt when the first owner's
// read is already remembered: the sheet shows both, and both arrive ticked.
document.getElementById('connect-both').onclick = () =>
  connect(
    [
      { origin: OWNER_ORIGIN, paths: ['/shared/displayName'] },
      { origin: OWNER2_ORIGIN, paths: ['/shared/displayName'] },
    ],
    'both owners'
  );

document.getElementById('read').onclick = async () => {
  try {
    const res = await window.vault.readShared(session.sessionId, OWNER_ORIGIN, ['/shared/displayName']);
    log('readShared ->', res.values);
  } catch (err) { fail(err); }
};

document.getElementById('read2').onclick = async () => {
  try {
    const res = await window.vault.readShared(session.sessionId, OWNER2_ORIGIN, ['/shared/displayName']);
    log('readShared (owner2) ->', res.values);
  } catch (err) { fail(err); }
};

document.getElementById('read-private').onclick = async () => {
  try {
    const res = await window.vault.readShared(session.sessionId, OWNER_ORIGIN, ['/private/notes']);
    log('the owner\\'s private path ->', res.values, '(null, and no error)');
  } catch (err) { fail(err); }
};

document.getElementById('oracle').onclick = async () => {
  try {
    const visited = await window.vault.readShared(session.sessionId, 'http://owner.localhost:8765', ['/shared/displayName']);
    const nonexistent = await window.vault.readShared(session.sessionId, 'https://nothing-here.invalid', ['/shared/displayName']);
    log('an unapproved origin ->', visited.values);
    log('an origin that does not exist ->', nonexistent.values);
    log(
      JSON.stringify(visited) === JSON.stringify(nonexistent)
        ? '✓ identical — the page cannot tell which sites you have data for'
        : '✗ they differ, which would be an existence oracle'
    );
  } catch (err) { fail(err); }
};
`;

const hostOf = (req) => String(req.headers.host || '').split(':')[0].toLowerCase();

const server = http.createServer((req, res) => {
  const host = hostOf(req);
  const site = host === 'reader.localhost' ? 'reader' : host === 'owner2.localhost' ? 'owner2' : 'owner';
  const send = (type, body) => {
    res.writeHead(200, { 'content-type': type, 'cache-control': 'no-store' });
    res.end(body);
  };

  if (req.url === '/page.js') return send('text/javascript; charset=utf-8', site === 'reader' ? READER_JS : OWNER_JS);
  if (req.url === '/favicon.ico') {
    res.writeHead(404);
    return res.end();
  }
  if (site === 'reader') return send('text/html; charset=utf-8', SHELL('Reader site', '#5b7cfa', READER_BODY));
  if (site === 'owner2') {
    return send(
      'text/html; charset=utf-8',
      SHELL('Owner 2', '#b2761f', OWNER_BODY(OWNER2_ORIGIN, 'Owner site 2'))
    );
  }
  return send(
    'text/html; charset=utf-8',
    SHELL('Owner site', '#1f9d6b', OWNER_BODY(OWNER_ORIGIN, 'Owner site'))
  );
});

server.listen(PORT, '127.0.0.1', () => {
  console.log(`owner   ${OWNER_ORIGIN}`);
  console.log(`owner2  ${OWNER2_ORIGIN}`);
  console.log(`reader  ${READER_ORIGIN}`);
});
