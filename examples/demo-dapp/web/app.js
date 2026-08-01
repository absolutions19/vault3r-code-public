import { VaultClient, HttpDelegationSigner } from "./dist/vault-sdk.mjs";

const $ = (id) => document.getElementById(id);
const logEl = $("log");

function log(msg, cls = "info") {
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

const cfg = await (await fetch("/config.json")).json();
log(`loaded config — relay ${cfg.relayUrl}, app domain ${cfg.domain}`, "info");

$("connectBtn").addEventListener("click", async () => {
  const btn = $("connectBtn");
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
        log("pairing URI generated; posting to the (simulated) vault to scan…", "info");
        await fetch("/vault-sim/scan", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ uri }),
        });
        log("vault scanned the code and sent its handshake", "ok");
      },
    });

    log("connecting… (delegation via backend PoP, then authenticated handshake)", "info");
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
    log("subscribed to /profile", "info");

    const name = $("name").value || "Ada Lovelace";
    const version = await client.set("/profile/name", name);
    log(`wrote /profile/name = "${name}"  (version ${version})`, "ok");

    const values = await client.get("/profile/name");
    log(`read back /profile/name = ${JSON.stringify(values["/profile/name"])}`, "ok");

    // Prove scope enforcement live: a field outside the grant is rejected.
    try {
      await client.get("/billing/card");
      log("unexpected: read of /billing/card succeeded", "err");
    } catch (e) {
      log(`scope enforced — read of /billing/card rejected (${e.code ?? e.message})`, "note");
    }
  } catch (err) {
    log(`error: ${err?.message ?? err}`, "err");
    btn.disabled = false;
  }
});
