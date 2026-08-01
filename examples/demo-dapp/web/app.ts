import { VaultClient, HttpDelegationSigner } from "@vault/sdk";
import qrcode from "qrcode-generator";

const $ = (id: string) => document.getElementById(id)!;
const logEl = $("log");

function log(msg: string, cls = "info") {
  // Build nodes with textContent — never innerHTML — so user-controlled values
  // (e.g. the name field) can't inject markup (XSS).
  const row = document.createElement("div");
  row.className = "row";
  const time = document.createElement("span");
  time.className = "t";
  time.textContent = new Date().toLocaleTimeString();
  const body = document.createElement("span");
  body.className = cls;
  body.textContent = msg;
  row.append(time, document.createTextNode(" "), body);
  logEl.appendChild(row);
  logEl.scrollTop = logEl.scrollHeight;
}

function renderQr(uri: string) {
  const qr = qrcode(0, "L"); // type 0 = auto-size, error-correction L (max capacity)
  qr.addData(uri);
  qr.make();
  (($("qr") as HTMLImageElement)).src = qr.createDataURL(4, 12);
  $("qrWrap").style.display = "block";
}

const cfg = (await (await fetch("/config.json")).json()) as { relayUrl: string; domain: string };
log(`loaded config — relay ${cfg.relayUrl}, app domain ${cfg.domain}`);

$("connectBtn").addEventListener("click", async () => {
  const btn = $("connectBtn") as HTMLButtonElement;
  btn.disabled = true;
  try {
    const signer = new HttpDelegationSigner({
      challengeUrl: "/vault/delegate/challenge",
      mintUrl: "/vault/delegate",
      // Origin is set automatically by the browser — do not set it here.
    });

    const client = new VaultClient({
      domain: cfg.domain,
      relayUrl: cfg.relayUrl,
      delegationSigner: signer,
      appMetadata: { name: "Demo dApp" },
      onPairingChallenge: (code) => {
        $("challenge").textContent = code.replace(/(\d{4})(\d{4})/, "$1 $2");
      },
      onDisplayUri: async (uri) => {
        $("uri").textContent = uri;
        renderQr(uri);
        log("pairing URI generated; posting to the (simulated) vault to scan…");
        await fetch("/vault-sim/scan", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ uri }),
        });
        log("vault scanned the code and sent its handshake", "ok");
      },
    });

    log("connecting… (delegation via backend PoP, then authenticated handshake)");
    const res = await client.connect([
      { methods: ["vault_getData", "vault_setData", "vault_subscribe", "vault_revoke"], fields: [{ path: "/profile", read: true, write: true }] },
    ]);
    $("connDot").classList.add("on");
    $("connText").textContent = "connected";
    const pill = document.createElement("span");
    pill.className = "pill";
    pill.textContent = res.namespace;
    $("nsRow").replaceChildren(pill);
    log(`connected — granted namespace ${res.namespace}`, "ok");

    await client.subscribe(["/profile"], (changes) => {
      log(`change notification: ${JSON.stringify(changes)}`, "note");
    });
    log("subscribed to /profile");

    const name = ($("name") as HTMLInputElement).value || "Ada Lovelace";
    const version = await client.set("/profile/name", name);
    log(`wrote /profile/name = "${name}"  (version ${version})`, "ok");

    const values = await client.get("/profile/name");
    log(`read back /profile/name = ${JSON.stringify(values["/profile/name"])}`, "ok");

    try {
      await client.get("/billing/card");
      log("unexpected: read of /billing/card succeeded", "err");
    } catch (e) {
      const err = e as { code?: number; message?: string };
      log(`scope enforced — read of /billing/card rejected (${err.code ?? err.message})`, "note");
    }
    btn.textContent = "Done — reload to run again";
  } catch (e) {
    log(`error: ${(e as Error)?.message ?? e}`, "err");
    btn.disabled = false;
  }
});
