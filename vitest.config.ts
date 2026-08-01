import { defineConfig } from "vitest/config";
import { fileURLToPath } from "node:url";

const r = (p: string) => fileURLToPath(new URL(p, import.meta.url));

export default defineConfig({
  resolve: {
    alias: {
      "@vault/protocol": r("./packages/protocol/src/index.ts"),
      "@vault/crypto-core": r("./packages/crypto-core/src/index.ts"),
      "@vault/vault-core": r("./packages/vault-core/src/index.ts"),
      "@vault/sdk": r("./packages/sdk/src/index.ts"),
      "@vault/relay": r("./servers/relay/src/index.ts"),
    },
  },
  test: {
    include: [
      "packages/**/*.test.ts",
      "servers/**/*.test.ts",
      "examples/**/*.test.ts",
      "tests/**/*.test.ts",
    ],
    environment: "node",
    testTimeout: 20000,
    hookTimeout: 20000,
  },
});
