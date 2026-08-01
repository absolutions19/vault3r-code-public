# Accepted decisions

_Appended automatically after APPROVED runs._

- 2026-08-01: APPROVED: Fifth pass. All prior findings addressed: recovery is native-managed with boolean-only JS contract (no wrapped-DEK material crosses the boundary); VaultRuntime.pair aborts unless unlock returns literal true; both native keystores fail closed with honest status values; JS validates all native returns (base64url + lengths + literal-true booleans); PSL-aware identity authoritativeness with 

- 2026-08-01: APPROVED: Third pass on v0.2.0 (since v0.1.0). All prior findings addressed: restoreDekFromRecovery now enforces ciphertext==32 and decrypted DEK==32 (fails closed, tests added); the demo has zero innerHTML (namespace pill built with DOM APIs + textContent); esbuild bumped to 0.25.12. Plus earlier fixes: canonical base64url decode, recovery context binding + fail-closed, XSS-safe logging, crypto.r
