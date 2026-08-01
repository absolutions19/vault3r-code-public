# VAULT — native keystore boundary

The contract the on-device `vault-keystore` native module (iOS Swift / Android
Kotlin) must implement. Everything else in the vault is JavaScript; this module is
the only piece that must be native, because it owns the biometric-gated hardware
key and must keep key bytes off the JS heap.

**Conformance:** every cryptographic output below has a known-answer vector in
[`apps/vault/modules/vault-keystore/conformance/test-vectors.json`](../apps/vault/modules/vault-keystore/conformance/test-vectors.json)
(regenerate with `pnpm gen:vectors`). The native implementation should reproduce
each output **byte-for-byte** against those fixtures before it is trusted. Vectors
are generated from the audited `@vault/crypto-core` reference.

---

## ⚠️ The one gotcha: XChaCha, not CryptoKit ChaChaPoly

At-rest sealing uses **XChaCha20-Poly1305** — a 24-byte nonce variant (ChaCha20-
Poly1305 with an HChaCha20-derived subkey). iOS **CryptoKit `ChaChaPoly` is the
IETF variant with a 12-byte nonce — it is NOT compatible.** Use a vetted
implementation of `crypto_aead_xchacha20poly1305` (libsodium) on both platforms,
or build XChaCha from HChaCha20 + IETF ChaCha20-Poly1305 exactly as
[`packages/crypto-core/src/xchacha.ts`](../packages/crypto-core/src/xchacha.ts)
does. The `hchacha20` and `xchacha20poly1305` vectors let you verify parity.

---

## Encoding on the JS↔native bridge

All binary arguments/returns across the bridge are **base64url, unpadded**
(alphabet `A–Za–z0–9-_`). The JS side validates every native return with a strict
base64url decode and exact length checks, and treats malformed returns as a
keystore failure — so the native side must emit canonical base64url. Booleans must
be a literal `true`/`false`.

## Fail-closed rules (already enforced on the JS side; honor them natively)

- `isAvailable()` must return `false` until *every* operation below is fully
  implemented. While it is `false`, all operational methods must **throw** — never
  return placeholder keys/signatures/ciphertext/ids.
- Never expose raw key material (KEK, DEK, subkeys, recovery-wrapped DEK) to JS.
- On biometric failure/cancel, or a hardware key invalidation (biometric re-enroll),
  fail closed (throw / return `false`); do not fall back to a software key.

---

## Key hierarchy

```
Biometric (Class 3) gates USE of ─► KEK        iOS: Secure Enclave P-256, SecAccessControl
                                     │              [.privateKeyUsage, .biometryCurrentSet]
                                     │          Android: Keystore AES, setUserAuthenticationRequired(true),
                                     │              setInvalidatedByBiometricEnrollment(true), StrongBox if available
                                     │  wrap (public-key ECIES / AES-GCM) — unwrap needs biometric
                                     ▼
                                DEK (AES-256 / 32 random bytes, native memory only, zeroized on lock/background)
                                     │  HKDF-SHA256(salt = sha256("vault-ns-salt|"+storageKey),
                                     │              info = "vault-ns/v1|"+storageKey, len = 32)
                                     ▼
                          per-namespace subkey ─► XChaCha20-Poly1305 at-rest sealing
```

The KEK never leaves hardware. The DEK exists in native memory only while unlocked.
The device signing key is a separate **Ed25519** key (RFC 8032).

---

## Method contracts

| Method | Contract |
|---|---|
| `isAvailable(): boolean` | `false` until fully implemented (see fail-closed rules). |
| `hasHardwareBackedKeys(): Promise<boolean>` | true iff a TEE/StrongBox/Secure-Enclave-backed key can be created. |
| `getSecurityLevel(): Promise<"strongbox"\|"tee"\|"secure-enclave"\|"software">` | honest current level. |
| `provision(): Promise<{ deviceKeyPublic, vaultId }>` | Create the biometric-gated KEK + a random DEK wrapped by it (stored natively), and an Ed25519 device key. Return the device public key (base64url, 32 bytes) and a stable per-install `vaultId`. The wrapped DEK never crosses to JS. |
| `unlock(reason): Promise<boolean>` | Biometric prompt → unwrap the DEK into native session memory. `true` on success. |
| `lock(): Promise<void>` | Zeroize the in-memory DEK. |
| `isUnlocked(): Promise<boolean>` | Whether the DEK is currently held. |
| `authenticate(reason): Promise<boolean>` | Per-operation biometric (sensitive read/write, connect, extend). Only literal `true` authorizes. |
| `seal(storageKey, aadB64, plaintextB64): Promise<string>` | Derive the per-namespace subkey (HKDF above), XChaCha20-Poly1305 seal, return the packed blob (base64url; layout below). |
| `open(storageKey, aadB64, blobB64): Promise<string \| null>` | Reverse of `seal`; return `null` on any auth failure (never throw on a bad tag). |
| `deviceSign(bytesB64): Promise<string>` | Raw Ed25519 signature (64 bytes, base64url) by the device key over the given bytes. |
| `deviceKeyPublic(): Promise<string>` | The device Ed25519 public key (base64url, 32 bytes). |
| `hasRecoveryBackup(): Promise<boolean>` | Whether a recovery blob exists in the native-managed store. |
| `createRecoveryBackup(mnemonic): Promise<boolean>` | Argon2id-wrap the DEK under the mnemonic (bound to `vaultId` as context) and persist the opaque blob natively. Never return the blob to JS. |
| `restoreFromRecovery(mnemonic): Promise<boolean>` | Read the native recovery blob, unwrap with the mnemonic (+ vaultId context), re-provision the KEK, and re-wrap the DEK. `true` on success. |

---

## At-rest sealed blob format

`seal` produces (then base64url-encodes):

```
0x01 (version) || nonce(24) || tag(16) || ciphertext(...)
```

- AEAD: XChaCha20-Poly1305, key = the per-namespace subkey, nonce = 24 fresh random bytes, `aad` = the caller-supplied AAD bytes (the vault passes `"vault-doc/1|"+storageKey`).
- `open` slices the same layout, recomputes the subkey, and AEAD-opens (returns `null` on tag mismatch).
- See the `namespaceSubkey` and `atRestBlob` vectors for exact bytes.

## Signing (device key)

- `deviceSign` is raw Ed25519 over the exact bytes handed in. The vault uses it to sign the **session settle** and responses; the SDK pins `deviceKeyPublic` and verifies.
- The settle preimage is `settleSigningPreimage(...)` (deterministic canonical JSON with a `"vault-settle/v1"` tag). See the `signing.settle` vector for the preimage bytes and the expected signature for a fixed seed.
- Typed data-plane requests are signed by the delegated session key (in the SDK, not native); the `signing.typedWrite` vector shows a preimage for cross-checking the canonical encoder if you reimplement it.

## Recovery (Argon2id + BIP-39)

```
K_recovery = Argon2id( NFKD(mnemonic), salt, { t, m (KiB), p }, dkLen = 32 )
blob.ct/tag = XChaCha20-Poly1305( key = K_recovery, nonce = 24 random,
                                  plaintext = DEK,
                                  aad = canonicalJSON({tag:"vault-recovery/1", kdf:"argon2id",
                                                       context, t, m, p, salt: base64url(salt)}) )
```

- `context` is the `vaultId` (so a blob for one vault will not restore into another; also bound into the AAD).
- Blob is self-describing JSON: `{ v:1, kdf:"argon2id", context, t, m, p, salt, nonce, ct, tag }` (salt/nonce/ct/tag base64url), serialized as base64url of the JSON for export.
- Production Argon2id: default `t=3, m=65536 (64 MiB), p=1`; raise `m` toward 256 MiB for high assurance. The `recovery` vector uses FAST params (`t=2, m=8 MiB`) so the KAT runs quickly — match those params to reproduce it, then use production params in the app.
- Reference: [`packages/crypto-core/src/recovery.ts`](../packages/crypto-core/src/recovery.ts).

---

## Platform implementation notes

**iOS (Secure Enclave):** KEK = `SecureEnclave.P256.KeyAgreement.PrivateKey` with
`SecAccessControlCreateWithFlags(..., .biometryCurrentSet, .privateKeyUsage)` and
`kSecAttrAccessibleWhenUnlockedThisDeviceOnly`. The enclave holds P-256 only, so
wrap the DEK via ECIES/ECDH+HKDF to the KEK public key; unwrap requires a fresh
biometric (`LAContext`). Device key = `Curve25519.Signing`. XChaCha + Argon2id via
libsodium (Swift wrapper). There is no true `FLAG_SECURE`; use resign-active blur +
`UIScreen.isCaptured` on secret screens.

**Android (Keystore):** KEK = AndroidKeyStore AES key,
`setUserAuthenticationRequired(true)`, `setInvalidatedByBiometricEnrollment(true)`,
`setIsStrongBoxBacked(true)` when `FEATURE_STRONGBOX_KEYSTORE`. Gate use with a
`BiometricPrompt` + `CryptoObject`. XChaCha + Argon2id + Ed25519 via a vetted
provider (e.g. libsodium-jni / Tink). Set `FLAG_SECURE` on secret/consent/mnemonic
windows; use `filterTouchesWhenObscured` + `setHideOverlayWindows(true)` on consent.

## Decisions to confirm before implementing

- **Argon2id cost** for production recovery (64 MiB default vs ~256 MiB high-assurance) — trades unlock latency for brute-force resistance.
- **Assurance floor** — require StrongBox + Class-3 biometrics for the top tier, or warn-and-allow TEE/Class-2?
- **Attestation** — hard-gate `unlock` on App Attest / Play Integrity, or advisory?
