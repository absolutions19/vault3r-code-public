/**
 * Bundles @vault/sdk (+ @vault/crypto-core, @vault/protocol) into a single
 * browser ESM module. `ws` is marked external — it is only reached in Node; the
 * browser uses the global WebSocket. crypto-core is pure @noble/* JS, so the
 * whole thing bundles cleanly for the browser with no Node polyfills.
 */

import { build } from "esbuild";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../../../", import.meta.url));

await build({
  entryPoints: [`${root}packages/sdk/src/index.ts`],
  outfile: fileURLToPath(new URL("./dist/vault-sdk.mjs", import.meta.url)),
  bundle: true,
  format: "esm",
  platform: "browser",
  target: "es2022",
  sourcemap: true,
  external: ["ws"], // Node-only transport fallback; browser uses global WebSocket
  logLevel: "info",
});

console.log("built examples/demo-dapp/web/dist/vault-sdk.mjs");
