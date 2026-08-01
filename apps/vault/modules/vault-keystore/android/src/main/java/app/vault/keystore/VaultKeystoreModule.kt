package app.vault.keystore

import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition
import java.security.KeyStore
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties

/**
 * Android hardware keystore.
 *
 * The KEK is an AndroidKeyStore AES key generated with
 * `setUserAuthenticationRequired(true)` (biometric-gated),
 * `setInvalidatedByBiometricEnrollment(true)` (invalidated when the biometric
 * set changes), and StrongBox when the device advertises it. A biometric
 * `BiometricPrompt` bound to a `CryptoObject` authorizes each KEK use; the KEK
 * unwraps a random DEK held in native memory for the unlocked session. The DEK
 * derives per-namespace subkeys (HKDF) that drive XChaCha20-Poly1305 at rest.
 *
 * NOTE: reference implementation of the native boundary; StrongBox/TEE-backed
 * keys require a real device.
 */
class VaultKeystoreModule : Module() {
  private var sessionDek: ByteArray? = null

  override fun definition() = ModuleDefinition {
    Name("VaultKeystore")

    // FAIL CLOSED: this module is a reference scaffold. It reports unavailable so
    // the JS side either uses the dev-only fallback (dev builds) or aborts
    // (release builds) — it never trusts placeholder key material. Flip
    // `isAvailable` to true ONLY once every operation below is fully implemented.
    Function("isAvailable") { false }

    AsyncFunction("hasHardwareBackedKeys") { hasStrongBoxOrTee() }

    AsyncFunction("getSecurityLevel") {
      when {
        hasStrongBox() -> "strongbox"
        hasTee() -> "tee"
        else -> "software"
      }
    }

    AsyncFunction("provision") { failNotImplemented("provision") }
    AsyncFunction("unlock") { reason: String -> failNotImplemented("unlock") }
    AsyncFunction("lock") { sessionDek?.fill(0); sessionDek = null }
    AsyncFunction("isUnlocked") { sessionDek != null }
    AsyncFunction("authenticate") { reason: String -> failNotImplemented("authenticate") }
    AsyncFunction("seal") { storageKey: String, aadB64: String, plaintextB64: String -> failNotImplemented("seal") }
    AsyncFunction("open") { storageKey: String, aadB64: String, blobB64: String -> failNotImplemented("open") }
    AsyncFunction("deviceSign") { bytesB64: String -> failNotImplemented("deviceSign") }
    AsyncFunction("deviceKeyPublic") { failNotImplemented("deviceKeyPublic") }
    AsyncFunction("exportRecoveryWrappedDek") { mnemonic: String -> failNotImplemented("exportRecoveryWrappedDek") }
    AsyncFunction("importRecoveryWrappedDek") { mnemonic: String, wrapped: String -> failNotImplemented("importRecoveryWrappedDek") }
  }

  private fun failNotImplemented(op: String): Nothing =
    throw NotImplementedError("VaultKeystore.$op is not yet implemented; module reports isAvailable=false")

  /**
   * Real implementation sketch (kept for reference; wire up before enabling):
   *  - KEK: AndroidKeyStore AES key, setUserAuthenticationRequired(true),
   *    setInvalidatedByBiometricEnrollment(true), setIsStrongBoxBacked when available.
   *  - unlock: BiometricPrompt + CryptoObject(cipher) → unwrap DEK into sessionDek.
   *  - seal/open: HKDF(sessionDek, storageKey) → XChaCha20-Poly1305 (vetted provider).
   *  - deviceSign: Ed25519 over the given bytes.
   */
  private fun provisionKek() {
    val spec = KeyGenParameterSpec.Builder(
      KEK_ALIAS,
      KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
    )
      .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
      .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
      .setUserAuthenticationRequired(true)
      .setInvalidatedByBiometricEnrollment(true)
      .apply { if (hasStrongBox()) setIsStrongBoxBacked(true) }
      .build()
    val kg = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
    kg.init(spec)
    kg.generateKey()
  }

  private fun keyStore(): KeyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
  private fun hasStrongBox(): Boolean = /* PackageManager.FEATURE_STRONGBOX_KEYSTORE */ false
  private fun hasTee(): Boolean = true
  private fun hasStrongBoxOrTee(): Boolean = hasStrongBox() || hasTee()
  private fun promptBiometric(reason: String): Boolean = false // wire BiometricPrompt
  private fun promptBiometricAndUnwrap(reason: String): Boolean = false

  companion object {
    private const val KEK_ALIAS = "app.vault.kek"
  }
}
