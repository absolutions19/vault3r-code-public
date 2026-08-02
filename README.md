# VAULT

A mobile, biometric-encrypted data vault with a crypto-wallet-style permission
protocol. Websites request scoped permission to their own slice of a namespaced
JSON document; every read and write is authenticated, end-to-end encrypted over a
WalletConnect-style relay, and sealed at rest behind hardware-backed,
biometric-gated keys.

The headline guarantee: **a site can only ever touch the namespace derived from
its own cryptographically verified identity — cross-namespace access is
structurally unrepresentable, not merely checked.**

> Status (v0.3.0, Forge-approved): the security core is complete and tested (175 passing tests,
> crypto cross-verified against `@noble/ciphers`). The crypto core is now pure JS
> and runs in the browser; a **browser SDK bundle + static demo page** lets a
> webpage pair with a vault, and **Argon2id + BIP-39 recovery** of the DEK is
> implemented and proven in JS. v0.3.0 adds a **trusted in-process host mode**
> (`connectLocal` + a `local*` data plane) so an embedding host — e.g. a browser
> that owns the caller's origin — can host the vault without the relay, identity
> proof, or per-request signatures, while keeping per-origin isolation, consent,
> per-field grants, and the input caps. The React Native app is a working scaffold;
> the native Secure Enclave / Android Keystore key-unwrap is stubbed and flagged
> in-code (it needs a physical device to build). See [per-milestone status](#status).

## Monorepo layout

| Package | What it is |
|---|---|
| [`packages/protocol`](packages/protocol) | The single source of wire truth: JSON-RPC method catalog, error registry, EIP-712-shaped typed data, the deterministic **canonical signing encoder**, pairing URI, transport interface. No dependencies. |
| [`packages/crypto-core`](packages/crypto-core) | Ed25519 / X25519, **XChaCha20-Poly1305**, HKDF, the session handshake + AEAD envelope, namespace derivation + homograph detection, identity/delegation attestation, and **Argon2id + BIP-39 recovery** (DEK wrap/unwrap). Pure JS via `@noble/*` — **runs in Node, the browser, and React Native**. |
| [`packages/vault-core`](packages/vault-core) | The platform-agnostic engine: the **identity verification pipeline**, the request **chokepoint**, grant scoping, the replay guard, an **anti-rollback** encrypted document store, the session state machine, and the `VaultNode` transport runtime. Ships in-memory adapters for tests. |
| [`servers/relay`](servers/relay) | The **zero-knowledge relay**: WebSocket pub/sub routed by topic with a bounded TTL mailbox and content-free push-to-wake. Sees ciphertext + metadata only. |
| [`packages/sdk`](packages/sdk) | The client library apps embed: `VaultClient` (pairing, handshake, `get/set/patch/subscribe/disconnect`), the relay transport, and the delegation seam (`Local`/`Http` signers). |
| [`examples/demo-dapp`](examples/demo-dapp) | The reference backend (`DelegateService`: **CSRF + Origin + proof-of-possession + scope-clamp**) **plus a browser demo** — a static page using the bundled SDK and an all-in-one `pnpm demo` server that runs the relay, a headless vault, and the backend so you can watch a webpage pair with a vault. |
| [`apps/vault`](apps/vault) | The Expo / React Native vault app. Hosts the tested engine on-device; the `vault-keystore` native module is the only non-JS piece. Installed separately (see its README). |

## Quick start

```bash
pnpm install
pnpm test          # 175 tests across all packages
pnpm typecheck     # strict TS across all packages (excluding the RN app)
pnpm relay         # run the dev relay on ws://127.0.0.1:4000
pnpm demo:signer   # run the reference delegation backend on :4100
pnpm demo          # ⭐ all-in-one browser demo — open the printed URL and watch
                   #    a webpage pair with a (headless) vault and round-trip data
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
| M8 RN app | ⚠️ scaffold — not device-built; native KEK-unwrap stubbed (fail-closed) |
| v0.2.0 browser SDK bundle + demo page | ✅ tested (headless demo-flow) |
| v0.2.0 Argon2id + BIP-39 recovery (crypto-core) | ✅ tested |
| v0.2.0 session-extend caps + subscription re-auth | ✅ tested |
| v0.2.2 input hardening (strict JSON parser, DoS caps, revocation TOCTOU, proto-pollution) | ✅ tested (red-team + Forge) |
| v0.3.0 trusted in-process host mode (`connectLocal` + `local*` data plane; origin→namespace, incl. dweb) | ✅ tested (isolation, per-field grants, method gating, caps, subscriptions) |

## Limitations (honest)

- The **recovery logic** (Argon2id + BIP-39 DEK wrap/unwrap) is implemented and tested in `crypto-core`; on device, only the native *storage/transport of the opaque blob* remains (the native module fails closed until wired).
- The native `vault-keystore` KEK-unwrap is stubbed and fail-closed; it needs a physical device (Secure Enclave / StrongBox) to implement.
- The RN app has not been compiled in this environment (no Xcode/Android toolchain).
- The browser demo simulates the phone with a headless vault; the SDK, relay, delegation backend, and protocol are all real.
- The relay is a single-process reference; a production deployment would use e.g. Cloudflare Durable Objects and traffic-metadata minimization.
- Homograph detection uses a compact confusables table, not the full Unicode confusables set.
