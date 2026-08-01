# vault-keystore conformance

Known-answer test vectors for validating the native (Swift / Kotlin)
implementation against the audited `@vault/crypto-core` reference.

- **`test-vectors.json`** — fixed inputs → expected outputs for every primitive
  the native module must reproduce (SHA-256, Ed25519, X25519, HKDF, HChaCha20,
  XChaCha20-Poly1305, namespace derivation, the per-namespace subkey, the at-rest
  blob layout, settle signing, and Argon2id recovery). Regenerate with
  `pnpm gen:vectors` (generator: [`tools/gen-native-vectors.mts`](../../../../../tools/gen-native-vectors.mts)).
- The full contract + formats + platform notes are in
  [`docs/NATIVE-BOUNDARY.md`](../../../../../docs/NATIVE-BOUNDARY.md).

Encoding: `hex` unless a field ends in `_b64url` (base64url, unpadded) or `_utf8`.
Nonces/salts are pinned for reproducibility — production must use fresh CSPRNG
randomness.

> Reminder: at-rest sealing is **XChaCha20-Poly1305** (24-byte nonce). iOS
> CryptoKit `ChaChaPoly` is the IETF 12-byte-nonce variant and will NOT match —
> use libsodium `crypto_aead_xchacha20poly1305`.
