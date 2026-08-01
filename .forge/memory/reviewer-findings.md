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

## Notes

- The identity-spoofing guarantee is enforced in two independent places (the on-device resolver and the engine's `identity-verify` chokepoint), both PSL-aware.
- The native Secure Enclave / Android Keystore implementations remain reference scaffolds (KEK-unwrap and Argon2id recovery are intentionally unimplemented and fail closed); completing them requires a physical device and a vetted Argon2id provider.
