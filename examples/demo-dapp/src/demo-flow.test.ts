/**
 * Drives the all-in-one demo server exactly as the browser page does — obtain a
 * delegation over the PoP endpoint, "scan" the pairing URI into the headless
 * vault, connect, write, read, and confirm scope enforcement — but from Node, so
 * it runs in CI without a browser. Proves the demo wiring is correct end to end.
 */

import { afterEach, describe, expect, it } from "vitest";
import { startDemo, type DemoHandle } from "../demo-server.js";
import { VaultClient, RelayTransport, HttpDelegationSigner } from "@vault/sdk";
import { ErrorCode } from "@vault/protocol";

describe("browser demo (driven headlessly)", () => {
  let demo: DemoHandle | undefined;
  let client: VaultClient | undefined;

  afterEach(async () => {
    if (client) await client.disconnect().catch(() => {});
    if (demo) await demo.close();
    client = undefined;
    demo = undefined;
  });

  it("serves the page + config and completes pair→connect→write→read→scope-check", async () => {
    demo = await startDemo();
    const base = `http://127.0.0.1:${demo.httpPort}`;

    // Static + config, as the page loads them.
    const html = await (await fetch(`${base}/`)).text();
    expect(html).toContain("<title>Demo dApp");
    const cfg = (await (await fetch(`${base}/config.json`)).json()) as { relayUrl: string; domain: string };
    expect(cfg.relayUrl).toContain("ws://");
    expect(cfg.domain).toBe("demo.example");

    // Cookie jar so the challenge + mint share a first-party session (as a browser would).
    let cookie = "";
    const jarFetch: typeof fetch = async (input, init) => {
      const headers = new Headers(init?.headers);
      if (cookie) headers.set("cookie", cookie);
      const res = await fetch(input, { ...init, headers });
      const sc = res.headers.get("set-cookie");
      if (sc) cookie = sc.split(";")[0]!;
      return res;
    };

    client = new VaultClient({
      domain: cfg.domain,
      relayUrl: cfg.relayUrl,
      transport: new RelayTransport(cfg.relayUrl),
      delegationSigner: new HttpDelegationSigner({
        challengeUrl: `${base}/vault/delegate/challenge`,
        mintUrl: `${base}/vault/delegate`,
        origin: base, // in Node we set Origin explicitly (the browser sets it for us)
        fetchImpl: jarFetch,
      }),
      appMetadata: { name: "Demo dApp" },
      onDisplayUri: async (uri) => {
        // exactly what web/app.js does: post the URI to the simulated vault
        await fetch(`${base}/vault-sim/scan`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ uri }),
        });
      },
    });

    const res = await client.connect([
      { methods: ["vault_getData", "vault_setData", "vault_subscribe", "vault_revoke"], fields: [{ path: "/profile", read: true, write: true }] },
    ]);
    expect(res.namespace).toBe("web:demo.example");

    await client.set("/profile/name", "Ada Lovelace");
    const values = await client.get("/profile/name");
    expect(values["/profile/name"]).toBe("Ada Lovelace");

    await expect(client.get("/billing/card")).rejects.toMatchObject({ code: ErrorCode.FieldOutOfScope });
  });
});
