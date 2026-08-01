/**
 * Minimal Node HTTP wrapper around DelegateService. Serves the identity record
 * and the challenge + delegate endpoints. Uses only node:http so the reference
 * has no framework dependency; a real app would mount these on its own server.
 */

import { createServer, type IncomingMessage, type ServerResponse, type Server } from "node:http";
import { randomBytes, toBase64Url } from "@vault/crypto-core";
import { DelegateError, DelegateService } from "./delegate-service.js";

export interface DelegateServerOptions {
  service: DelegateService;
  /** Resolve the authenticated account for a first-party session id. */
  accountForSession?: (sid: string) => string;
  accountDomain: string;
}

function parseCookies(header: string | undefined): Record<string, string> {
  const out: Record<string, string> = {};
  if (!header) return out;
  for (const part of header.split(";")) {
    const [k, ...v] = part.trim().split("=");
    if (k) out[k] = decodeURIComponent(v.join("="));
  }
  return out;
}

function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    let data = "";
    req.on("data", (c) => {
      data += c;
      if (data.length > 256 * 1024) reject(new Error("body too large"));
    });
    req.on("end", () => resolve(data));
    req.on("error", reject);
  });
}

function json(res: ServerResponse, status: number, body: unknown, headers: Record<string, string> = {}): void {
  res.writeHead(status, { "content-type": "application/json", ...headers });
  res.end(JSON.stringify(body));
}

export function createDelegateServer(opts: DelegateServerOptions): Server {
  const { service } = opts;
  const accountFor = opts.accountForSession ?? (() => `user@${opts.accountDomain}`);

  return createServer(async (req, res) => {
    try {
      const url = new URL(req.url ?? "/", "http://localhost");
      const cookies = parseCookies(req.headers.cookie);

      if (req.method === "GET" && url.pathname === "/.well-known/vault-identity.json") {
        return json(res, 200, service.wellKnownRecord());
      }

      if (req.method === "GET" && url.pathname === "/vault/delegate/challenge") {
        // Establish a first-party session cookie if absent (SameSite=Strict, HttpOnly).
        let sid = cookies["sid"];
        const headers: Record<string, string> = {};
        if (!sid) {
          sid = toBase64Url(randomBytes(18));
          headers["set-cookie"] = `sid=${sid}; HttpOnly; SameSite=Strict; Path=/`;
        }
        return json(res, 200, service.issueChallenge(sid), headers);
      }

      if (req.method === "POST" && url.pathname === "/vault/delegate") {
        const sid = cookies["sid"];
        if (!sid) return json(res, 401, { error: "not authenticated" });
        const origin = req.headers["origin"];
        const csrfToken = req.headers["x-csrf-token"];
        if (typeof origin !== "string") return json(res, 403, { error: "missing origin" });
        if (typeof csrfToken !== "string") return json(res, 403, { error: "missing csrf token" });
        const body = JSON.parse(await readBody(req));
        const delegation = service.mintDelegation(sid, body, { origin, csrfToken, account: accountFor(sid) });
        return json(res, 200, delegation);
      }

      return json(res, 404, { error: "not found" });
    } catch (err) {
      if (err instanceof DelegateError) return json(res, err.status, { error: err.message, code: err.code });
      return json(res, 400, { error: (err as Error).message });
    }
  });
}
