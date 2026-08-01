/**
 * Bundles @vault/sdk (+ @vault/crypto-core, @vault/protocol) into a single
 * browser ESM module. `ws` is marked external — it is only reached in Node; the
 * browser uses the global WebSocket. crypto-core is pure @noble/* JS, so the
 * whole thing bundles cleanly for the browser with no Node polyfills.
 */

import { build } from "esbuild";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../../../", import.meta.url));

const common = {
  bundle: true,
  format: "esm",
  platform: "browser",
  target: "es2022",
  sourcemap: true,
  external: ["ws"], // Node-only transport fallback; browser uses global WebSocket
  logLevel: "info",
};

// The standalone SDK bundle (for reference / other consumers).
await build({
  ...common,
  entryPoints: [`${root}packages/sdk/src/index.ts`],
  outfile: fileURLToPath(new URL("./dist/vault-sdk.mjs", import.meta.url)),
});

// The demo page app (SDK + QR generator + page logic).
await build({
  ...common,
  entryPoints: [fileURLToPath(new URL("./app.ts", import.meta.url))],
  outfile: fileURLToPath(new URL("./dist/app.js", import.meta.url)),
});

console.log("built examples/demo-dapp/web/dist/{vault-sdk.mjs, app.js}");
