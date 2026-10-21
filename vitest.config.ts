import { defineConfig } from "vitest/config";
import { fileURLToPath } from "node:url";

const r = (p: string) => fileURLToPath(new URL(p, import.meta.url));

export default defineConfig({
  resolve: {
    alias: {
      // The narrower `browser` entries, which omit the relay identity model and
      // the Public Suffix List with it. These must precede the bare package
      // aliases: the first matching prefix wins, so "@vault/crypto-core" would
      // otherwise swallow "@vault/crypto-core/browser".
      "@vault/crypto-core/browser": r("./packages/crypto-core/src/browser.ts"),
      "@vault/vault-core/browser": r("./packages/vault-core/src/browser.ts"),
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
