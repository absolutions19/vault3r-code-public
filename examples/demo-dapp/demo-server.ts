/**
 * All-in-one browser demo. One process wires up everything a real deployment
 * splits across machines, so you can open a page and watch a website pair with a
 * vault end to end:
 *
 *   - a zero-knowledge relay (WebSocket),
 *   - a HEADLESS VAULT (VaultEngine + VaultNode) standing in for the phone — it
 *     auto-approves consent (there is no on-screen device here) and "scans" the
 *     pairing URI the page posts to /vault-sim/scan,
 *   - the app's delegation backend (CSRF + Origin + PoP + scope-clamp),
 *   - static hosting for the page and the browser SDK bundle.
 *
 * Everything the browser touches is the REAL SDK and protocol; only the phone is
 * simulated. `startDemo` is exported so an integration test can drive it without
 * a browser.
 */

import { createServer, type IncomingMessage, type ServerResponse, type Server } from "node:http";
import { randomUUID } from "node:crypto";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import type { AddressInfo } from "node:net";
import { ed25519Generate } from "@vault/crypto-core";
import { RelayServer } from "@vault/relay";
import { VaultEngine, VaultNode, InMemoryKeystore, InMemoryStorage, StaticIdentityResolver, AutoConsent } from "@vault/vault-core";
import { RelayTransport } from "@vault/sdk";
import { DelegateService, type MintRequest } from "./src/delegate-service.js";

const WEB_DIR = fileURLToPath(new URL("./web/", import.meta.url));
const DOMAIN = "demo.example";
const ALLOWED_SCOPES = [
  {
    methods: ["vault_getData", "vault_setData", "vault_subscribe", "vault_unsubscribe", "vault_revoke", "vault_getPermissions"],
    fields: [{ path: "/profile", read: true, write: true }],
  },
];

export interface DemoHandle {
  httpPort: number;
  relayPort: number;
  pageUrl: string;
  close(): Promise<void>;
}

const CONTENT_TYPES: Record<string, string> = {
  ".html": "text/html; charset=utf-8",
  ".mjs": "text/javascript; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".map": "application/json; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".json": "application/json; charset=utf-8",
};

function parseCookies(header: string | undefined): Record<string, string> {
  const out: Record<string, string> = {};
  if (!header) return out;
  for (const part of header.split(";")) {
    const [k, ...v] = part.trim().split("=");
    if (k) out[k] = v.join("=");
  }
  return out;
}
function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    let d = "";
    req.on("data", (c) => {
      d += c;
      if (d.length > 256 * 1024) reject(new Error("body too large"));
    });
    req.on("end", () => resolve(d));
    req.on("error", reject);
  });
}
function json(res: ServerResponse, status: number, body: unknown, headers: Record<string, string> = {}): void {
  res.writeHead(status, { "content-type": "application/json", ...headers });
  res.end(JSON.stringify(body));
}

export async function startDemo(opts: { httpPort?: number; relayPort?: number } = {}): Promise<DemoHandle> {
  // 1. Relay.
  const relay = new RelayServer();
  const relayPort = await relay.listen(opts.relayPort ?? 0);

  // 2. Headless vault (the simulated phone). Auto-approves consent.
  const domainKey = ed25519Generate();
  // Origins allowed to mint delegations; the same array reference is populated
  // once the HTTP port is known below (before any request can arrive).
  const allowedOrigins: string[] = [];
  const service = new DelegateService({
    domain: DOMAIN,
    kid: "demo-key-1",
    domainSeed: domainKey.privateKey,
    allowedScopes: ALLOWED_SCOPES,
    originAllowlist: allowedOrigins,
  });

  const resolver = new StaticIdentityResolver();
  resolver.set(service.wellKnownRecord());
  const engine = new VaultEngine({
    keystore: new InMemoryKeystore({ vaultId: "demo-vault" }),
    storage: new InMemoryStorage(),
    resolver,
    consent: new AutoConsent(),
  });
  const node = new VaultNode(engine, new RelayTransport(`ws://127.0.0.1:${relayPort}`));

  // 3. HTTP: static files + delegation endpoints + the vault-scan bridge.
  const httpServer: Server = createServer(async (req, res) => {
    try {
      const url = new URL(req.url ?? "/", "http://localhost");
      const cookies = parseCookies(req.headers.cookie);

      if (req.method === "GET" && url.pathname === "/config.json") {
        return json(res, 200, { relayUrl: `ws://127.0.0.1:${relayPort}`, domain: DOMAIN });
      }
      if (req.method === "GET" && url.pathname === "/.well-known/vault-identity.json") {
        return json(res, 200, service.wellKnownRecord());
      }
      if (req.method === "GET" && url.pathname === "/vault/delegate/challenge") {
        const sid = cookies["sid"] ?? randomUUID();
        const headers: Record<string, string> = {};
        if (!cookies["sid"]) headers["set-cookie"] = `sid=${sid}; HttpOnly; SameSite=Strict; Path=/`;
        return json(res, 200, service.issueChallenge(sid), headers);
      }
      if (req.method === "POST" && url.pathname === "/vault/delegate") {
        const sid = cookies["sid"];
        if (!sid) return json(res, 401, { error: "not authenticated" });
        const origin = req.headers["origin"];
        const csrf = req.headers["x-csrf-token"];
        if (typeof origin !== "string" || typeof csrf !== "string") return json(res, 403, { error: "missing origin/csrf" });
        const body = JSON.parse(await readBody(req)) as MintRequest;
        const del = service.mintDelegation(sid, body, { origin, csrfToken: csrf, account: `user@${DOMAIN}` });
        return json(res, 200, del);
      }
      if (req.method === "POST" && url.pathname === "/vault-sim/scan") {
        const { uri } = JSON.parse(await readBody(req)) as { uri: string };
        await node.pair(uri); // the "phone" scans the QR
        return json(res, 200, { ok: true });
      }

      // Static files.
      if (req.method === "GET") {
        const rel = url.pathname === "/" ? "index.html" : url.pathname.replace(/^\/+/, "");
        if (rel.includes("..")) return json(res, 400, { error: "bad path" });
        try {
          const data = await readFile(`${WEB_DIR}${rel}`);
          const ext = rel.slice(rel.lastIndexOf("."));
          res.writeHead(200, { "content-type": CONTENT_TYPES[ext] ?? "application/octet-stream" });
          return res.end(data);
        } catch {
          return json(res, 404, { error: "not found" });
        }
      }
      return json(res, 404, { error: "not found" });
    } catch (err) {
      const e = err as { status?: number; message?: string };
      return json(res, e.status ?? 400, { error: e.message ?? "error" });
    }
  });

  const httpPort = await new Promise<number>((resolve) =>
    httpServer.listen(opts.httpPort ?? 0, "127.0.0.1", () => resolve((httpServer.address() as AddressInfo).port)),
  );
  allowedOrigins.push(`http://127.0.0.1:${httpPort}`, `http://localhost:${httpPort}`);

  return {
    httpPort,
    relayPort,
    pageUrl: `http://127.0.0.1:${httpPort}/`,
    close: async () => {
      await new Promise<void>((r) => httpServer.close(() => r()));
      await relay.close();
    },
  };
}

// Run directly: `pnpm demo`
if (import.meta.url === `file://${process.argv[1]}`) {
  startDemo({ httpPort: Number(process.env.DEMO_PORT ?? 4200), relayPort: Number(process.env.DEMO_RELAY_PORT ?? 4000) }).then(
    (h) => {
      console.log(`\n  VAULT browser demo ready`);
      console.log(`  Open:  ${h.pageUrl}`);
      console.log(`  Relay: ws://127.0.0.1:${h.relayPort}  ·  Vault: headless (auto-approves consent)\n`);
    },
  );
}
