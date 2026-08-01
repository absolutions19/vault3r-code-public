# Review findings & resolutions

Tracks Forge review findings for the VAULT monorepo and their resolution.

## Round 1 (correctness + security reviewers)

| # | Sev | Finding | Status | Resolution |
|---|-----|---------|--------|------------|
| 1 | high (security) | `resolver.ts` `sameRegistrable` compared only the last two labels, so PSL siblings like `attacker.co.uk` / `victim.co.uk` could spoof an identity record. | RESOLVED | Replaced with `isAuthoritativeForHost` in `@vault/crypto-core` (tldts/PSL-aware); used in both `resolver.ts` and the engine `identity-verify.ts`. Tests added in `crypto-core/src/identity.test.ts` (exact-host, same-registrable, PSL siblings, parent-domain claims). |
| 2 | high (security) | JS keystore fallback could silently store the master DEK in a weaker path in production. | RESOLVED | `RnKeystore.create` now fails closed in release builds (`!__DEV__`) when no native keystore is present; the DEK requests biometric gating where the OS supports it. |
| 3 | medium (code) | base64url (JS) vs standard base64 (Swift decode) mismatch across the native bridge. | RESOLVED | Whole bridge standardized on base64url both directions; added `Data(base64URLEncoded:)` to the Swift module and switched all decodes/encodes to base64url. |
| 4 | high (tests) | `pnpm run typecheck` evidence not recorded. | RESOLVED | Added `lint: npm run typecheck` to `forge.config.json`; the pipeline runs and records it; passes. |

## Round 2 (correctness + security reviewers)

| # | Sev | Finding | Status | Resolution |
|---|-----|---------|--------|------------|
| 1 | high (security) | Android native module advertised `isAvailable=true` while returning placeholder key material. | RESOLVED | Both native modules (Kotlin + Swift) now fail closed: `isAvailable` returns `false` until fully implemented, and every stubbed op throws instead of returning placeholders. `isNativeKeystoreAvailable()` is therefore false in this build → dev uses the JS fallback, release aborts. |
| 2 | high (security) | JS boundary trusted native returns without validation. | RESOLVED | `RnKeystore` validates every native return (strict base64url alphabet + expected decoded lengths: 32-byte device key, 64-byte signature, non-empty ciphertext/vaultId); validation failure throws (`KeystoreError`, fail closed). |
| 3 | medium (code) | `VaultRuntime.pair` ignored the `unlock()` result. | RESOLVED | `pair` now aborts with an error if `unlock()` returns false, before calling `node.pair`. |
| 4 | medium (other) | Missing written review artifact. | RESOLVED | This file. |

## Round 3 (correctness + security reviewers)

| # | Sev | Finding | Status | Resolution |
|---|-----|---------|--------|------------|
| 1 | high (security) | iOS module still performed real ops while `isAvailable=false`. | RESOLVED | Every iOS operational method now throws `failClosed(op)`; real logic kept as private reference helpers only. |
| 2 | medium (code) | `provision().wrappedDek` was declared but unused/unvalidated at the JS boundary. | RESOLVED | Removed `wrappedDek` from `ProvisionResult`; DEK wrapping is native-internal. |
| 3 | medium (security) | Native boolean returns (unlock/authenticate) weren't strictly validated. | RESOLVED | `RnKeystore` requires `=== true`; anything else is failure. |
| 4 | medium (tests) | Standalone `pnpm run e2e` evidence missing. | RESOLVED | Forge test command now runs `npm run e2e && npm run test`; both pass. |

## Round 4 (correctness + security reviewers)

| # | Sev | Finding | Status | Resolution |
|---|-----|---------|--------|------------|
| 1 | medium (security) | Recovery methods still exposed wrapped-DEK material through the JS contract. | RESOLVED | Redesigned to `hasRecoveryBackup` / `createRecoveryBackup` / `restoreFromRecovery` (boolean-only); the wrapped blob is native-managed and never crosses to JS. |
| 2 | medium (code) | `VaultRuntime.pair` accepted truthy non-`true` unlock results. | RESOLVED | Changed to `if (unlocked !== true) throw`. (An automated RN unit test needs a device/RN test harness not present in this environment.) |
| 3 | low (code) | Android reported placeholder security-status values while unavailable. | RESOLVED | `hasHardwareBackedKeys → false`, `getSecurityLevel → "software"`; removed hard-coded `hasTee()`. |

## v0.2.0 review (diff since tag v0.1.0)

| # | Sev | Finding | Status | Resolution |
|---|-----|---------|--------|------------|
| 1 | medium (code) | `fromBase64Url` accepted non-canonical encodings (length%4===1, non-zero trailing pad bits) → signature malleability risk. | RESOLVED | Reject `length%4===1` and non-zero trailing bits; injective by construction. Regression tests: empty, arbitrary lengths, invalid chars/padding, `"A"`, `"AB"`, `"AAB"`. |
| 2 | medium (code) | `restoreDekFromRecovery` could throw (e.g. bad nonce length) instead of failing closed. | RESOLVED | Validates salt/nonce/tag lengths + KDF param ranges/types, wraps derive+open in try/catch → returns null. Tests mutate nonce/tag/params/ct to bad-but-valid-b64url. |
| 3 | medium (security) | Recovery blob had no vault/context binding. | RESOLVED | Added a required `context` (vault id) stored in the blob AND bound into the AEAD AAD; restore requires the expected context. Tests prove wrong/tampered context fails. RN keystore passes its `vaultId`. |
| 4 | medium (security) | Demo page `log()` used `innerHTML` with the user-controlled name field (DOM XSS). | RESOLVED | Rebuilt with `createElement` + `textContent`; no `innerHTML`. |
| 5 | low (security) | Demo session id used `Math.random()+Date.now()`. | RESOLVED | Uses `crypto.randomUUID()`. |

### v0.2.0 review — round 2 (then APPROVED, 0 findings)

| # | Sev | Finding | Status | Resolution |
|---|-----|---------|--------|------------|
| 1 | medium (code) | `restoreDekFromRecovery` didn't enforce ct/plaintext DEK length. | RESOLVED | Require `ct.length === 32` before open and decrypted `pt.length === 32` after; tests for short/long ct. |
| 2 | medium (ui) | One `innerHTML` remained (namespace pill). | RESOLVED | Built with `createElement` + `textContent` + `replaceChildren`; zero innerHTML in the demo. |
| 3 | medium (security) | esbuild `^0.24.0` on a vulnerable line. | RESOLVED | Bumped to `^0.25.12`; bundle rebuilds. |

**Tagged as v0.2.1 (Forge-approved).** v0.1.0 and v0.2.1 are the approved checkpoints.

## Notes

- The identity-spoofing guarantee is enforced in two independent places (the on-device resolver and the engine's `identity-verify` chokepoint), both PSL-aware.
- The native Secure Enclave / Android Keystore implementations remain reference scaffolds (KEK-unwrap and Argon2id recovery are intentionally unimplemented and fail closed); completing them requires a physical device and a vetted Argon2id provider.

- 2026-08-01: base64url decoder accepts non-canonical malformed encodings (seen 2×) — packages/crypto-core/src/encoding.ts: `export function fromBase64Url(s: string): Uint8Array { if (!/^[A-Za-z0-9_-]*$/.test(s)) throw new Error("invalid base64url"); ... return out; }`
