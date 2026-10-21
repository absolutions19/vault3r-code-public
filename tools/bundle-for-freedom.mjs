#!/usr/bin/env node
/**
 * Bundle @vault/{protocol,crypto-core,vault-core} for Freedom Browser's
 * CommonJS main process, and write them under
 *   <freedom-browser>/src/main/vault/vendor/
 *
 * Both packages are bundled from their `browser.ts` entry, not their index:
 * Freedom uses only the BROWSER identity model, where the namespace is the
 * caller's origin read off the sender frame. The relay model's verification
 * pipeline, `.well-known` resolver and transport runtime are left out, and with
 * them the Public Suffix List (tldts, ~170 KB of trie data) that only that model
 * consults. Narrowing the entry is what drops it: tldts ships CommonJS without
 * `sideEffects: false`, so esbuild cannot tree-shake it out of any module that
 * stays reachable.
 *
 * Usage (from this repo root):
 *   node tools/bundle-for-freedom.mjs [path-to-freedom-browser]
 *
 * Defaults to ../freedom-browser (sibling checkout).
 */

import { build } from 'esbuild';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const FREEDOM = path.resolve(process.argv[2] || path.join(ROOT, '..', 'freedom-browser'));
const OUT = path.join(FREEDOM, 'src', 'main', 'vault', 'vendor');

/**
 * The revision this bundle was built from, stamped into the banner.
 *
 * Nothing else in the generated file says which engine it is: without this a
 * reader of `freedom-browser` has a quarter-megabyte of code, no version, and
 * no way back to the source — which an MPL-2.0 bundle has to be traceable to.
 * `+local` marks a bundle built over uncommitted work, so an untraceable one
 * says so.
 */
function sourceRevision() {
  try {
    const git = (...args) => execFileSync('git', args, { cwd: ROOT, encoding: 'utf8' }).trim();
    const sha = git('rev-parse', '--short=12', 'HEAD');
    const dirty = git('status', '--porcelain') !== '';
    return `${sha}${dirty ? '+local' : ''}`;
  } catch {
    return 'unknown';
  }
}

const REPO = 'https://github.com/absolutions19/vault3r-code-public';
const BANNER = [
  '/* GENERATED — do not edit by hand.',
  ' * @vault/{vault-core,crypto-core,protocol} bundled for Freedom Browser.',
  ` * Source:   ${REPO}`,
  ` * Revision: ${sourceRevision()}`,
  ' * License:  MPL-2.0 (same as Freedom Browser)',
  ' * Inlines:  @noble/ciphers, @noble/curves, @noble/hashes, @scure/base,',
  ' *           @scure/bip39 — all MIT. See the vendor README beside this',
  ' *           file, and NOTICES in the Freedom repo.',
  ' * Rebuild:  node tools/bundle-for-freedom.mjs <path-to-freedom-browser>',
  ' */',
].join('\n');

if (!fs.existsSync(path.join(FREEDOM, 'package.json'))) {
  console.error(`freedom-browser not found at ${FREEDOM}`);
  console.error('Pass the path: node tools/bundle-for-freedom.mjs /path/to/freedom-browser');
  process.exit(1);
}

fs.mkdirSync(OUT, { recursive: true });

const entry = path.join(OUT, '_entry.cjs');
fs.writeFileSync(
  entry,
  `
module.exports = {
  vaultCore: require(${JSON.stringify(path.join(ROOT, 'packages/vault-core/src/browser.ts'))}),
  cryptoCore: require(${JSON.stringify(path.join(ROOT, 'packages/crypto-core/src/browser.ts'))}),
};
`,
);

await build({
  entryPoints: [entry],
  outfile: path.join(OUT, 'vault-bundle.js'),
  bundle: true,
  platform: 'node',
  format: 'cjs',
  target: 'node18',
  // Keep Node builtins external; everything else (the @noble/@scure set) goes in.
  packages: 'bundle',
  logLevel: 'info',
  banner: { js: BANNER },
});

fs.unlinkSync(entry);

fs.writeFileSync(
  path.join(OUT, 'vault-core.js'),
  "/* Shim: the bundled @vault/vault-core browser surface. */\nmodule.exports = require('./vault-bundle.js').vaultCore;\n",
);
fs.writeFileSync(
  path.join(OUT, 'crypto-core.js'),
  "/* Shim: the bundled @vault/crypto-core browser surface. */\nmodule.exports = require('./vault-bundle.js').cryptoCore;\n",
);

console.log(`Wrote vendor bundle → ${OUT}`);
