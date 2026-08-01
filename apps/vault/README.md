# @vault/app — VAULT mobile app (Expo / React Native)

The biometric-gated, on-device vault. This app hosts the tested
[`@vault/vault-core`](../../packages/vault-core) engine and
[`VaultNode`](../../packages/vault-core/src/node.ts) runtime, wired to real device
adapters.

## Why this package is not in the pnpm workspace

The vault app needs a native toolchain (Xcode / Android Studio) and — for the
Secure Enclave / StrongBox key operations — a **physical device** (the iOS
Simulator has no Secure Enclave; StrongBox requires real hardware). To keep the
Node/TypeScript packages installable and testable in CI without pulling the React
Native native toolchain, `apps/*` is intentionally excluded from the root
workspace. Install and run this app on its own.

## Architecture

```
App.tsx ─ Onboarding / Scan / Connections / ApprovalSheet   (React Native UI)
  │
  └─ VaultRuntime ─ VaultEngine + VaultNode  (from @vault/vault-core — the tested core)
        ├─ RnKeystore   → native vault-keystore module (Secure Enclave / Keystore)
        │                 with a pure-JS DEV fallback (@vault/crypto-core)
        ├─ RnStorage    → expo-file-system (sealed blobs) + expo-secure-store (manifest)
        ├─ FetchIdentityResolver → fetches /.well-known/vault-identity.json over TLS
        └─ UiConsentAdapter → drives the ApprovalSheet (the human trust boundary)
```

The `modules/vault-keystore` native module is the **only** part that must be
native. Everything else is JavaScript. Its `ios/` (Swift, Secure Enclave + ECIES
KEK→DEK) and `android/` (Kotlin, Keystore + BiometricPrompt + StrongBox)
implementations are reference scaffolds of the hardware boundary; the KEK unwrap
and Argon2id recovery paths are marked where a vetted crypto provider must be
wired in.

## Run

```bash
cd apps/vault
npm install
# point at your relay (defaults to wss://relay.vault.app)
EXPO_PUBLIC_RELAY_URL=ws://<your-machine>:4000 npx expo run:ios     # or run:android
```

Expo Go will not work (custom native module, associated domains, background
push). Use a Dev Client (`expo run:ios` / `expo run:android`) on a real device.

## What runs where

| Concern | JS | Native |
|---|---|---|
| Protocol, JSON-RPC, envelope crypto, identity verification, chokepoint | ✅ | |
| Per-namespace subkey derivation, at-rest AEAD, KEK/DEK | (dev fallback only) | ✅ |
| Biometric gate (Face ID / BiometricPrompt) | | ✅ |
| Camera / QR, deep links, push-to-wake | ✅ | (OS) |

## Status

The React Native layer is a working scaffold: the runtime wiring, adapters, and
the security-critical `ApprovalSheet` are complete; the native KEK-unwrap and
recovery paths and some secondary screens are stubbed and flagged in-code. It has
not been compiled here (no device toolchain in this environment).
