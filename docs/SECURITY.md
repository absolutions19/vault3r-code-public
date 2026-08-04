# VAULT — security model

This document states the threat model and maps each security property to the code
that enforces it. File references are clickable.

## Trust boundaries

- **The target app / SDK is untrusted.** It can lie about anything on the wire. It never chooses a namespace, never holds the domain key, and enforces nothing.
- **The relay is untrusted for confidentiality and identity.** It routes ciphertext by topic and sees only metadata (topics, sizes, timing). It is trusted only for availability.
- **The target backend is trusted for exactly one thing:** its own domain identity (it holds the Ed25519 domain key and mints delegations).
- **The vault app + engine + hardware keystore is the sole authorization authority.**

## The anti-spoofing guarantee

> The caller never names its namespace. The vault derives it from an identity it
> verified itself, and there is no code path by which one site produces another
> site's namespace key.

Enforced by the verification pipeline in
[`identity-verify.ts`](../packages/vault-core/src/identity-verify.ts) and the
request chokepoint in [`engine.ts`](../packages/vault-core/src/engine.ts):

1. The claimed domain is normalized to a Punycode A-label ([`normalizeHost`](../packages/crypto-core/src/namespace.ts)).
2. The vault **fetches the identity record itself** over TLS ([`FetchIdentityResolver`](../packages/vault-core/src/fetch-resolver.ts)) — the caller never supplies it. SSRF guards reject IP literals, private hosts, and cross-host redirects.
3. The record's self-signature is checked ([`verifyIdentityRecordProof`](../packages/crypto-core/src/identity.ts)) and it must be authoritative for the claimed host.
4. The delegation must be signed by an active record key and bound to this vault + this pairing ([`verifyDelegation`](../packages/crypto-core/src/identity.ts) + pairing/vault checks in `identity-verify.ts`).
5. Proof-of-possession: the delegated session key must have signed the ConnectMessage ([`verifyTyped`](../packages/crypto-core/src/signing.ts)).
6. The namespace is **derived** from the verified host ([`deriveNamespace`](../packages/crypto-core/src/namespace.ts)); every subsequent request carries a claimed namespace that is only a **tripwire** — the engine acts on the derived namespace and rejects any mismatch with `4300 NamespaceMismatch`.

Tested in [`engine.test.ts`](../packages/vault-core/src/engine.test.ts) (anti-spoofing suite) and [`full-flow.test.ts`](../tests/e2e/full-flow.test.ts) (isolation across the wire).

## Red-team CRITICAL fixes, mapped to code

The four non-crypto critical gaps from the design red-team, and where each is closed:

| Fix | Where | Test |
|---|---|---|
| **Pairing-relay phishing** (WalletConnect-drainer): bind pairing to a user-confirmed number-match + the delegation's pairing challenge | number-match generated in [`client.ts`](../packages/sdk/src/client.ts) (`numberMatchCode`), surfaced by the host's consent UI; delegation `pairingChallenge` verified in [`identity-verify.ts`](../packages/vault-core/src/identity-verify.ts) | `engine.test.ts` "mismatched pairing challenge" |
| **Cross-origin delegation minting (CSRF/PoP)** | [`DelegateService`](../examples/demo-dapp/src/delegate-service.ts): Origin allow-list + CSRF token + single-use challenge + **proof-of-possession** (the browser signs a server challenge with `d_sess`) | [`delegate.test.ts`](../examples/demo-dapp/src/delegate.test.ts) (origin/csrf/pop/replay) |
| **Unverified colliding with the verified keyspace** | unverified connects are **rejected by default**; identity verification is a precondition for any `web:` namespace (`identity-verify.ts` throws `IdentityUnverified`) | `engine.test.ts` / `full-flow.test.ts` "unverified rejected" |
| **ECDH handshake not bound to identity** | both ephemeral pubkeys + a transcript hash are inside the identity-signed ConnectMessage; the vault re-derives the transcript and also **signs the settle** with its device key ([`handshake.ts`](../packages/crypto-core/src/handshake.ts), `identity-verify.ts`, settle verification in `client.ts`) | `engine.test.ts` "MITM responder key substitution" |

## Other enforced properties

- **Replay resistance** — time-bounded, fail-closed nonce cache ([`replay.ts`](../packages/vault-core/src/replay.ts)); tested for eviction-free rejection.
- **Domain separation** — every signature is over a domain-separated preimage (`vaultId` + protocol version) via the canonical encoder ([`typed-data.ts`](../packages/protocol/src/typed-data.ts), [`canonical.ts`](../packages/protocol/src/canonical.ts)); a signature can't be replayed against another vault or protocol version.
- **Value integrity** — writes carry a `valueHash` inside the signature; the engine re-hashes the actual value and rejects a mismatch, so "the bytes consented are the bytes applied" ([`engine.ts`](../packages/vault-core/src/engine.ts) `applyChanges`, [`value-hash.ts`](../packages/crypto-core/src/value-hash.ts)).
- **AEAD channel binding** — the session envelope's associated data binds `topic · tag · protocol · msgType · direction`, so a ciphertext can't be replayed on another topic or reflected ([`session-envelope.ts`](../packages/crypto-core/src/session-envelope.ts)).
- **At-rest isolation + anti-rollback** — per-namespace HKDF subkeys; a sealed manifest detects blob deletion and version rollback ([`document-store.ts`](../packages/vault-core/src/document-store.ts)); tested in [`storage.test.ts`](../packages/vault-core/src/storage.test.ts).
- **Unlock gating** — connect, sensitive reads, and writes are gated by the keystore's `authenticate` ([`engine.ts`](../packages/vault-core/src/engine.ts)); the `KeystoreAdapter` is the DEK boundary. In the browser host that adapter is [`data-vault-keystore.js`](../examples/freedom-browser-integration/main/data-vault-keystore.js), which derives the data-vault DEK from the already-unlocked identity mnemonic via domain-separated HKDF and fails closed while locked.
- **Least privilege** — the backend clamps requested scopes to a static allow-list before signing; the vault further narrows via per-field consent.
- **Metadata at rest** — the permission store (every site you hold data for, its grants, timestamps and pinned icon) is encrypted with Electron `safeStorage` under the OS keychain, not the vault DEK: the DEK exists only while the mnemonic is unlocked, and this store must stay readable while the vault is locked — the remembered-grant lookup runs before the engine's unlock check, and the launcher resolves a tile to its origin. Separately, and as a display rule rather than a cryptographic one, neither the Data pane nor the launcher renders anything but an unlock prompt while locked: the set of sites you hold data for is history-shaped and must not be shown at an unattended browser, so `listPartitions`/`getUsage`/`listHomeTiles` all return empty until unlocked. Where no keyring is available the file is written with an honest plaintext header rather than pretending; an undecryptable file is preserved, never overwritten. The export bundle seals the same map under the DEK, so a bundle saved to cloud storage carries no cleartext site list — at the cost of export requiring an unlock.
- **No cross-origin enumeration** — the set of sites holding data is a browsing-history-shaped aggregate, so it is never exposed to a page. `window.vaultHome` (the `vault://home` launcher) lives on its own preload, attached to the internal page only; tiles launch by **namespace**, so the launcher resolves destinations from grants rather than accepting URLs, and refuses any scheme outside the browsable allow-list.
- **Untrusted display bytes** — a site's tile icon is page-controlled input rendered on a privileged surface. [`data-vault-icon.js`](../examples/freedom-browser-integration/main/data-vault-icon.js) accepts `data:` URIs only (never a URL — that would put a network fetch, and thus a beacon of the user's vault list, on every render), rejects SVG, requires the magic bytes to match the declared MIME, enforces canonical base64 plus byte and dimension caps (the engine applies **no** cap to `appMetadata`), and re-encodes through `nativeImage` where available. Icons are pinned at consent, so a site cannot restyle its tile after the fact.

  Site-supplied artwork buys recognition, not verification: a lookalike origin can serve a convincing logo. Tiles therefore always carry the host the browser observed, and the launcher exposes no destructive action.

## Residual risks (accepted / out of scope here)

- A single field's plaintext transits the JS heap to be serialized to the caller (keys never do). In the browser host this is bounded to the main process and the IPC bridge.
- The DEK is derived from the identity mnemonic, so the data vault inherits the identity vault's lock state and re-keys with a seed change. Argon2id + BIP-39 recovery is implemented in `crypto-core` but not yet surfaced in the browser UI.
- The sealed-blob directory leaks by shape even with the permission store encrypted: filenames are `doc:<sha256(namespace)>.bin` — an unsalted hash of a low-entropy input — so anyone with the folder can confirm guesses against a domain wordlist, and `stat` gives per-site data volume. Closing it needs key-derived filenames and size padding, which would prevent the anti-rollback manifest from detecting deletions while locked.
- `safeStorage` is device-bound and same-user: it defends backups, clones and other OS users, not malware running as you (unlocked it reads the plaintext or drives the IPC; locked it waits).
- Relay metadata (topics, sizes, timing) survives E2E; traffic-shaping is a deployment option, off by default.
- A compromised main process — hostile native module, malicious Electron flag, an attacker with write access to the app bundle — is game-over once unlocked; the boundary defended here is the *page*, not the host.
- Homograph detection is a compact table, not the full Unicode confusables set.
