#!/usr/bin/env node
/**
 * Bundle @vault/{protocol,crypto-core,vault-core} for Freedom Browser's
 * CommonJS main process, and write them under
 *   <freedom-browser>/src/main/vault/vendor/
 *
 * Usage (from this repo root):
 *   node tools/bundle-for-freedom.mjs [path-to-freedom-browser]
 *
 * Defaults to ../freedom-browser (sibling checkout).
 */

import { build } from 'esbuild';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const FREEDOM = path.resolve(process.argv[2] || path.join(ROOT, '..', 'freedom-browser'));
const OUT = path.join(FREEDOM, 'src', 'main', 'vault', 'vendor');

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
  vaultCore: require(${JSON.stringify(path.join(ROOT, 'packages/vault-core/src/index.ts'))}),
  cryptoCore: require(${JSON.stringify(path.join(ROOT, 'packages/crypto-core/src/index.ts'))}),
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
  // Keep Node builtins external; everything else (noble, tldts, …) goes in.
  packages: 'bundle',
  logLevel: 'info',
  banner: {
    js: '/* GENERATED — @vault/{vault-core,crypto-core,protocol} bundled from the vault3r repo. Do not edit by hand. */',
  },
});

fs.unlinkSync(entry);

fs.writeFileSync(
  path.join(OUT, 'vault-core.js'),
  "/* Shim: the bundled @vault/vault-core surface. */\nmodule.exports = require('./vault-bundle.js').vaultCore;\n",
);
fs.writeFileSync(
  path.join(OUT, 'crypto-core.js'),
  "/* Shim: the bundled @vault/crypto-core surface. */\nmodule.exports = require('./vault-bundle.js').cryptoCore;\n",
);

console.log(`Wrote vendor bundle → ${OUT}`);
