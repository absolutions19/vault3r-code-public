/**
 * Runnable reference backend. `pnpm demo:signer`.
 *
 * Serves the demo app's identity record and its delegation endpoint. The domain
 * key here is generated at startup for demo purposes; a real deployment loads a
 * persistent key from a KMS/HSM and never exposes it.
 */

import { ed25519Generate } from "@vault/crypto-core";
import { DelegateService } from "./src/delegate-service.js";
import { createDelegateServer } from "./src/http-server.js";

const domain = process.env.DEMO_DOMAIN ?? "demo.example";
const port = Number(process.env.DEMO_PORT ?? 4100);
const origin = process.env.DEMO_ORIGIN ?? `http://localhost:${port}`;

const domainKey = ed25519Generate();
const service = new DelegateService({
  domain,
  kid: "demo-key-1",
  domainSeed: domainKey.privateKey,
  allowedScopes: [
    {
      methods: ["vault_getData", "vault_setData", "vault_subscribe", "vault_unsubscribe", "vault_revoke", "vault_getPermissions"],
      fields: [{ path: "/profile", read: true, write: true }],
    },
  ],
  originAllowlist: [origin],
});

const server = createDelegateServer({ service, accountDomain: domain });
server.listen(port, () => {
  console.log(`Demo backend for ${domain} on http://localhost:${port}`);
  console.log(`  identity:  GET  /.well-known/vault-identity.json`);
  console.log(`  challenge: GET  /vault/delegate/challenge`);
  console.log(`  delegate:  POST /vault/delegate  (CSRF + Origin + PoP + scope-clamp)`);
});
