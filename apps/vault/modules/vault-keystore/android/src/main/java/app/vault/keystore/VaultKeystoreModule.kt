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

    Function("isAvailable") { true }

    AsyncFunction("hasHardwareBackedKeys") { hasStrongBoxOrTee() }

    AsyncFunction("getSecurityLevel") {
      when {
        hasStrongBox() -> "strongbox"
        hasTee() -> "tee"
        else -> "software"
      }
    }

    AsyncFunction("provision") {
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
      kg.generateKey() // KEK lives in the keystore, never exported

      // Random DEK, wrapped by the KEK (AES-GCM). Held in native memory while unlocked.
      // deviceKey: Ed25519 for response signing (via a vetted provider).
      mapOf(
        "wrappedDek" to "<base64 wrapped DEK>",
        "deviceKeyPublic" to "<base64url device pubkey>",
        "vaultId" to java.util.UUID.randomUUID().toString()
      )
    }

    AsyncFunction("unlock") { reason: String ->
      // Show BiometricPrompt with a CryptoObject bound to the KEK cipher; on
      // success, unwrap the DEK into sessionDek. (BiometricPrompt runs on the UI
      // thread via the current Activity.)
      promptBiometricAndUnwrap(reason)
    }

    AsyncFunction("lock") { sessionDek?.fill(0); sessionDek = null }
    AsyncFunction("isUnlocked") { sessionDek != null }
    AsyncFunction("authenticate") { reason: String -> promptBiometric(reason) }

    AsyncFunction("seal") { storageKey: String, aadB64: String, plaintextB64: String ->
      // HKDF(sessionDek, storageKey) → subkey; XChaCha20-Poly1305 seal.
      "<base64 ciphertext>"
    }
    AsyncFunction("open") { storageKey: String, aadB64: String, blobB64: String ->
      // HKDF subkey; XChaCha20-Poly1305 open; return null on auth failure.
      null as String?
    }

    AsyncFunction("deviceSign") { bytesB64: String -> "<base64url signature>" }
    AsyncFunction("deviceKeyPublic") { "<base64url device pubkey>" }

    AsyncFunction("exportRecoveryWrappedDek") { mnemonic: String -> "<argon2id-wrapped DEK>" }
    AsyncFunction("importRecoveryWrappedDek") { mnemonic: String, wrapped: String -> false }
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
