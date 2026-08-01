/**
 * Drives the running demo server exactly like the browser page (web/app.js):
 * obtain a delegation via PoP, "scan" the pairing URI into the headless vault,
 * connect, subscribe, write, read, and prove scope enforcement — printing each
 * step. Run against a live `pnpm demo` / demo-server instance.
 */

import { VaultClient, RelayTransport, HttpDelegationSigner } from "../packages/sdk/src/index.ts";

const BASE = process.env.DEMO_BASE ?? "http://127.0.0.1:4200";
const t0 = Date.now();
const log = (msg: string) => console.log(`  +${String(Date.now() - t0).padStart(4)}ms  ${msg}`);

const cfg = (await (await fetch(`${BASE}/config.json`)).json()) as { relayUrl: string; domain: string };
log(`loaded config — relay ${cfg.relayUrl}, app domain ${cfg.domain}`);

// Cookie jar so the challenge + mint calls share a first-party session (like a browser).
let cookie = "";
const jarFetch: typeof fetch = async (input, init) => {
  const headers = new Headers(init?.headers);
  if (cookie) headers.set("cookie", cookie);
  const res = await fetch(input, { ...init, headers });
  const sc = res.headers.get("set-cookie");
  if (sc) cookie = sc.split(";")[0]!;
  return res;
};

const client = new VaultClient({
  domain: cfg.domain,
  relayUrl: cfg.relayUrl,
  transport: new RelayTransport(cfg.relayUrl),
  appMetadata: { name: "Live Drive" },
  delegationSigner: new HttpDelegationSigner({
    challengeUrl: `${BASE}/vault/delegate/challenge`,
    mintUrl: `${BASE}/vault/delegate`,
    origin: BASE,
    fetchImpl: jarFetch,
  }),
  onPairingChallenge: (code) => log(`number-match code (confirm on vault): ${code.replace(/(\d{4})(\d{4})/, "$1 $2")}`),
  onDisplayUri: async (uri) => {
    log(`pairing URI generated: ${uri.slice(0, 64)}…`);
    await fetch(`${BASE}/vault-sim/scan`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ uri }) });
    log("vault scanned the code and sent its handshake");
  },
});

log("connecting (delegation via backend PoP → authenticated handshake)…");
const res = await client.connect([
  { methods: ["vault_getData", "vault_setData", "vault_subscribe", "vault_revoke"], fields: [{ path: "/profile", read: true, write: true }] },
]);
log(`CONNECTED — granted namespace ${res.namespace}`);

await client.subscribe(["/profile"], (changes) => log(`🔔 change notification: ${JSON.stringify(changes)}`));
log("subscribed to /profile");

const version = await client.set("/profile/name", "Ada Lovelace");
log(`wrote /profile/name = "Ada Lovelace"  (version ${version})`);

const values = await client.get("/profile/name");
log(`read back /profile/name = ${JSON.stringify(values["/profile/name"])}`);

try {
  await client.get("/billing/card");
  log("UNEXPECTED: read of /billing/card succeeded");
} catch (e) {
  log(`scope enforced — read of /billing/card rejected (${(e as { code?: number; message?: string }).code ?? (e as Error).message})`);
}

await new Promise((r) => setTimeout(r, 120)); // let the subscription notification arrive
await client.disconnect();
log("disconnected. ✅ live end-to-end OK");
process.exit(0);
