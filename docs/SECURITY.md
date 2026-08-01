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
2. The vault **fetches the identity record itself** over TLS ([`FetchIdentityResolver`](../apps/vault/src/runtime/resolver.ts)) — the caller never supplies it. SSRF guards reject IP literals, private hosts, and cross-host redirects.
3. The record's self-signature is checked ([`verifyIdentityRecordProof`](../packages/crypto-core/src/identity.ts)) and it must be authoritative for the claimed host.
4. The delegation must be signed by an active record key and bound to this vault + this pairing ([`verifyDelegation`](../packages/crypto-core/src/identity.ts) + pairing/vault checks in `identity-verify.ts`).
5. Proof-of-possession: the delegated session key must have signed the ConnectMessage ([`verifyTyped`](../packages/crypto-core/src/signing.ts)).
6. The namespace is **derived** from the verified host ([`deriveNamespace`](../packages/crypto-core/src/namespace.ts)); every subsequent request carries a claimed namespace that is only a **tripwire** — the engine acts on the derived namespace and rejects any mismatch with `4300 NamespaceMismatch`.

Tested in [`engine.test.ts`](../packages/vault-core/src/engine.test.ts) (anti-spoofing suite) and [`full-flow.test.ts`](../tests/e2e/full-flow.test.ts) (isolation across the wire).

## Red-team CRITICAL fixes, mapped to code

The four non-crypto critical gaps from the design red-team, and where each is closed:

| Fix | Where | Test |
|---|---|---|
| **Pairing-relay phishing** (WalletConnect-drainer): bind pairing to a user-confirmed number-match + the delegation's pairing challenge | number-match generated in [`client.ts`](../packages/sdk/src/client.ts) (`numberMatchCode`), shown in [`ApprovalSheet.tsx`](../apps/vault/src/screens/ApprovalSheet.tsx); delegation `pairingChallenge` verified in [`identity-verify.ts`](../packages/vault-core/src/identity-verify.ts) | `engine.test.ts` "mismatched pairing challenge" |
| **Cross-origin delegation minting (CSRF/PoP)** | [`DelegateService`](../examples/demo-dapp/src/delegate-service.ts): Origin allow-list + CSRF token + single-use challenge + **proof-of-possession** (the browser signs a server challenge with `d_sess`) | [`delegate.test.ts`](../examples/demo-dapp/src/delegate.test.ts) (origin/csrf/pop/replay) |
| **Unverified colliding with the verified keyspace** | unverified connects are **rejected by default**; identity verification is a precondition for any `web:` namespace (`identity-verify.ts` throws `IdentityUnverified`) | `engine.test.ts` / `full-flow.test.ts` "unverified rejected" |
| **ECDH handshake not bound to identity** | both ephemeral pubkeys + a transcript hash are inside the identity-signed ConnectMessage; the vault re-derives the transcript and also **signs the settle** with its device key ([`handshake.ts`](../packages/crypto-core/src/handshake.ts), `identity-verify.ts`, settle verification in `client.ts`) | `engine.test.ts` "MITM responder key substitution" |

## Other enforced properties

- **Replay resistance** — time-bounded, fail-closed nonce cache ([`replay.ts`](../packages/vault-core/src/replay.ts)); tested for eviction-free rejection.
- **Domain separation** — every signature is over a domain-separated preimage (`vaultId` + protocol version) via the canonical encoder ([`typed-data.ts`](../packages/protocol/src/typed-data.ts), [`canonical.ts`](../packages/protocol/src/canonical.ts)); a signature can't be replayed against another vault or protocol version.
- **Value integrity** — writes carry a `valueHash` inside the signature; the engine re-hashes the actual value and rejects a mismatch, so "the bytes consented are the bytes applied" ([`engine.ts`](../packages/vault-core/src/engine.ts) `applyChanges`, [`value-hash.ts`](../packages/crypto-core/src/value-hash.ts)).
- **AEAD channel binding** — the session envelope's associated data binds `topic · tag · protocol · msgType · direction`, so a ciphertext can't be replayed on another topic or reflected ([`session-envelope.ts`](../packages/crypto-core/src/session-envelope.ts)).
- **At-rest isolation + anti-rollback** — per-namespace HKDF subkeys; a sealed manifest detects blob deletion and version rollback ([`document-store.ts`](../packages/vault-core/src/document-store.ts)); tested in [`storage.test.ts`](../packages/vault-core/src/storage.test.ts).
- **Biometric gating** — connect, sensitive reads, and writes are gated by the keystore's `authenticate` ([`engine.ts`](../packages/vault-core/src/engine.ts)); the keystore is the DEK boundary ([`keystore.ts`](../apps/vault/src/runtime/keystore.ts) + the native module).
- **Least privilege** — the backend clamps requested scopes to a static allow-list before signing; the vault further narrows via per-field consent.

## Residual risks (accepted / out of scope here)

- A single field's plaintext transits the JS heap to be serialized to the caller (keys never do). On device this is bounded to the RN bridge; v2 moves serialization native.
- The native KEK-unwrap and Argon2id recovery paths are stubbed in this build.
- Relay metadata (topics, sizes, timing) survives E2E; traffic-shaping is a deployment option, off by default.
- A device with hostile root / a malicious accessibility service is largely game-over once unlocked; the app detects/degrades but does not claim to defend it fully.
- Homograph detection is a compact table, not the full Unicode confusables set.
