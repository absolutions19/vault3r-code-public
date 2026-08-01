/** Dev relay entry point. `pnpm relay` or `tsx servers/relay/src/bin.ts`. */

import { RelayServer } from "./server.js";

const port = Number(process.env.VAULT_RELAY_PORT ?? 4000);
const host = process.env.VAULT_RELAY_HOST ?? "127.0.0.1";

const relay = new RelayServer({
  onPush: (topic) => console.log(`[push] wake requested for topic ${topic.slice(0, 12)}…`),
});

relay.listen(port, host).then((actual) => {
  console.log(`VAULT relay listening on ws://${host}:${actual}`);
  console.log("Zero-knowledge: ciphertext + metadata only. Ctrl-C to stop.");
});

const shutdown = () => {
  relay.close().then(() => process.exit(0));
};
process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
