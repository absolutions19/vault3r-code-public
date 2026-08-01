# VAULT

A mobile, biometric-encrypted data vault with a crypto-wallet-style permission
protocol. Websites request scoped permission to their own slice of a namespaced
JSON document; every read and write is authenticated, end-to-end encrypted over a
WalletConnect-style relay, and sealed at rest behind hardware-backed,
biometric-gated keys.

The headline guarantee: **a site can only ever touch the namespace derived from
its own cryptographically verified identity — cross-namespace access is
structurally unrepresentable, not merely checked.**

> Status: the security core is complete and tested (88 passing tests, crypto
> cross-verified against `@noble/ciphers`). The React Native app is a working
> scaffold; the native Secure Enclave / Android Keystore key-unwrap and recovery
> paths are stubbed and flagged in-code (they need a physical device to build).
> See [per-milestone status](#status).

## Monorepo layout

| Package | What it is |
|---|---|
| [`packages/protocol`](packages/protocol) | The single source of wire truth: JSON-RPC method catalog, error registry, EIP-712-shaped typed data, the deterministic **canonical signing encoder**, pairing URI, transport interface. No dependencies. |
| [`packages/crypto-core`](packages/crypto-core) | Ed25519 / X25519, **XChaCha20-Poly1305** (built on Node's ChaCha20-Poly1305 + a from-scratch HChaCha20, cross-verified against `@noble/ciphers`), HKDF, the session handshake + AEAD envelope, namespace derivation + homograph detection, and identity/delegation attestation. Uses **only Node's built-in crypto** — no external crypto dependency. |
| [`packages/vault-core`](packages/vault-core) | The platform-agnostic engine: the **identity verification pipeline**, the request **chokepoint**, grant scoping, the replay guard, an **anti-rollback** encrypted document store, the session state machine, and the `VaultNode` transport runtime. Ships in-memory adapters for tests. |
| [`servers/relay`](servers/relay) | The **zero-knowledge relay**: WebSocket pub/sub routed by topic with a bounded TTL mailbox and content-free push-to-wake. Sees ciphertext + metadata only. |
| [`packages/sdk`](packages/sdk) | The client library apps embed: `VaultClient` (pairing, handshake, `get/set/patch/subscribe/disconnect`), the relay transport, and the delegation seam (`Local`/`Http` signers). |
| [`examples/demo-dapp`](examples/demo-dapp) | The reference backend: a `DelegateService` that enforces **CSRF + Origin + proof-of-possession + scope-clamp** before minting a delegation, plus an HTTP server and a full-stack capstone test. |
| [`apps/vault`](apps/vault) | The Expo / React Native vault app. Hosts the tested engine on-device; the `vault-keystore` native module is the only non-JS piece. Installed separately (see its README). |

## Quick start

```bash
pnpm install
pnpm test          # 88 tests across all packages
pnpm typecheck     # strict TS across all packages (excluding the RN app)
pnpm relay         # run the dev relay on ws://127.0.0.1:4000
pnpm demo:signer   # run the reference delegation backend on :4100
```

## How it fits together

```
  target app            relay (zero-knowledge)          vault (phone)
 ┌───────────┐  E2E ct  ┌────────────────────┐        ┌──────────────────────┐
 │ VaultClient│◄───────►│ pub/sub by topic   │◄──────►│ VaultNode ─ VaultEngine│
 │ (@vault/sdk)│        │ = sha256(sessionKey)│        │   identity verify      │
 └─────┬─────┘          │ ciphertext only    │        │   chokepoint + grants  │
       │ delegation      └────────────────────┘        │   sealed doc store     │
 ┌─────▼─────┐                                          ├──────────────────────┤
 │ app backend│  ── vault fetches /.well-known ────────►│ native keystore        │
 │ (holds Ed25519 domain key, /vault/delegate)          │ (Secure Enclave/       │
 └───────────┘                                          │  Keystore, biometric)  │
                                                        └──────────────────────┘
```

- **Confidentiality** comes from the relay session key (X25519 → HKDF) + XChaCha20-Poly1305; the relay only ever sees ciphertext.
- **Authenticity / anti-spoofing** comes from a domain-bound Ed25519 key published at `/.well-known/vault-identity.json` (the vault fetches it itself over TLS), with the ECDH handshake bound into the identity signature and every request individually signed.
- **At rest**, a biometric-gated hardware KEK wraps a DEK; per-namespace subkeys (HKDF) seal each site's document independently, with a rolling manifest for rollback/deletion detection.

See [docs/SECURITY.md](docs/SECURITY.md) for the threat model and how each
red-team-critical fix maps to code, and [docs/PROTOCOL.md](docs/PROTOCOL.md) for
the wire reference.

## Status

| Milestone | State |
|---|---|
| M0 monorepo + tooling | ✅ |
| M1 protocol | ✅ tested |
| M2 crypto-core | ✅ tested (noble-verified) |
| M3 vault-core engine | ✅ tested |
| M4 relay | ✅ tested |
| M5 SDK | ✅ tested (e2e) |
| M6 end-to-end proof | ✅ tested |
| M7 reference backend (CSRF+PoP) | ✅ tested (full-stack capstone) |
| M8 RN app | ⚠️ scaffold — not device-built; native key-unwrap + recovery stubbed |

## Limitations (honest)

- The native `vault-keystore` KEK-unwrap and Argon2id recovery paths are stubbed and marked in-code; they need a physical device + a vetted Argon2id provider.
- The RN app has not been compiled in this environment (no Xcode/Android toolchain).
- The relay is a single-process reference; a production deployment would use e.g. Cloudflare Durable Objects and traffic-metadata minimization.
- Homograph detection uses a compact confusables table, not the full Unicode confusables set.
