import ExpoModulesCore
import LocalAuthentication
import CryptoKit
import Security

/**
 * iOS hardware keystore.
 *
 * The KEK is a Secure Enclave P-256 key created with an access control of
 * `.biometryCurrentSet` + `.privateKeyUsage`, so it is (a) non-exportable and
 * (b) usable only after a fresh Face ID / Touch ID match, and is invalidated if
 * the enrolled biometric set changes. The KEK cannot do symmetric crypto, so we
 * use ECIES-style key agreement to wrap a random 256-bit DEK. The DEK is held in
 * memory only while unlocked and drives XChaCha20-Poly1305 at-rest sealing.
 *
 * NOTE: this is a reference implementation of the native boundary; it requires a
 * physical device (the Secure Enclave is unavailable on the simulator).
 */
public class VaultKeystoreModule: Module {
  private var sessionDek: SymmetricKey?
  private let kekTag = "app.vault.kek".data(using: .utf8)!
  private let deviceKeyTag = "app.vault.deviceKey".data(using: .utf8)!

  public func definition() -> ModuleDefinition {
    Name("VaultKeystore")

    // FAIL CLOSED: report unavailable until the KEK unwrap + Keychain persistence
    // paths below are fully implemented, so the JS side never trusts a
    // half-provisioned enclave (it uses the dev fallback in dev, or aborts in a
    // release build). Flip to `SecureEnclave.isAvailable` once complete.
    Function("isAvailable") { () -> Bool in
      return false
    }

    AsyncFunction("hasHardwareBackedKeys") { () -> Bool in
      return SecureEnclave.isAvailable
    }

    AsyncFunction("getSecurityLevel") { () -> String in
      return SecureEnclave.isAvailable ? "secure-enclave" : "software"
    }

    // FAIL CLOSED: every operational method throws while `isAvailable` is false,
    // so the module never hands the JS side usable key material, signatures,
    // ciphertext, vault ids, or a successful auth result. The real logic lives in
    // the private reference helpers below; wire them up, verify, and only then
    // implement these operations and flip `isAvailable`.
    AsyncFunction("provision") { () -> [String: String] in try self.failClosed("provision") }
    AsyncFunction("unlock") { (reason: String) -> Bool in try self.failClosed("unlock") }
    AsyncFunction("lock") { () in self.sessionDek = nil } // harmless; native memory only
    AsyncFunction("isUnlocked") { () -> Bool in return self.sessionDek != nil }
    AsyncFunction("authenticate") { (reason: String) -> Bool in try self.failClosed("authenticate") }
    AsyncFunction("seal") { (storageKey: String, aadB64: String, plaintextB64: String) -> String in try self.failClosed("seal") }
    AsyncFunction("open") { (storageKey: String, aadB64: String, blobB64: String) -> String? in try self.failClosed("open") }
    AsyncFunction("deviceSign") { (bytesB64: String) -> String in try self.failClosed("deviceSign") }
    AsyncFunction("deviceKeyPublic") { () -> String in try self.failClosed("deviceKeyPublic") }
    AsyncFunction("exportRecoveryWrappedDek") { (mnemonic: String) -> String in try self.failClosed("exportRecoveryWrappedDek") }
    AsyncFunction("importRecoveryWrappedDek") { (mnemonic: String, wrapped: String) -> Bool in
      return try self.failClosed("importRecoveryWrappedDek")
    }
  }

  // MARK: - helpers (KEK/DEK, per-namespace subkey, keychain persistence)

  /// Uniform fail-closed error for every unimplemented operation.
  private func failClosed<T>(_ op: String) throws -> T {
    throw Exception(name: "NotAvailable", description: "VaultKeystore.\(op) is not implemented; module reports isAvailable=false")
  }

  private func namespaceKey(_ storageKey: String) throws -> SymmetricKey {
    guard let dek = sessionDek else { throw Exception(name: "Locked", description: "vault is locked") }
    let info = "vault-ns/v1|\(storageKey)".data(using: .utf8)!
    let salt = Data(SHA256.hash(data: "vault-ns-salt|\(storageKey)".data(using: .utf8)!))
    return HKDF<SHA256>.deriveKey(inputKeyMaterial: dek, salt: salt, info: info, outputByteCount: 32)
  }

  private func wrapDek(_ dek: SymmetricKey, kekPublic: P256.KeyAgreement.PublicKey) throws -> Data {
    // Ephemeral ECDH to the KEK public key; HKDF → wrapping key; AEAD-wrap the DEK.
    let eph = P256.KeyAgreement.PrivateKey()
    let shared = try eph.sharedSecretFromKeyAgreement(with: kekPublic)
    let wrapKey = shared.hkdfDerivedSymmetricKey(using: SHA256.self, salt: Data(), sharedInfo: Data("vault-kek-wrap".utf8), outputByteCount: 32)
    let dekBytes = dek.withUnsafeBytes { Data($0) }
    let box = try ChaChaPoly.seal(dekBytes, using: wrapKey)
    return eph.publicKey.rawRepresentation + box.combined
  }

  private func unwrapDekWithKek() throws -> SymmetricKey {
    // Load KEK from keychain (usage triggers the biometric access control), run
    // ECDH with the stored ephemeral public key, HKDF, and AEAD-unwrap the DEK.
    // (Elided: symmetric to wrapDek.)
    throw Exception(name: "NotImplemented", description: "Load KEK + unwrap stored wrappedDek")
  }

  private func loadDeviceKey() throws -> Curve25519.Signing.PrivateKey {
    let raw = try self.load(self.deviceKeyTag)
    return try Curve25519.Signing.PrivateKey(rawRepresentation: raw)
  }

  private func persist(_ tag: Data, _ data: Data) throws { /* SecItemAdd, ThisDeviceOnly */ }
  private func load(_ tag: Data) throws -> Data { throw Exception(name: "NotImplemented", description: "SecItemCopyMatching") }
}

extension Data {
  func base64URLEncodedString() -> String {
    base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
  }

  /// Decode base64url (the encoding the JS bridge uses). The whole bridge is
  /// base64url in both directions, so we must not use `Data(base64Encoded:)`,
  /// which only accepts standard base64.
  init?(base64URLEncoded input: String) {
    var s = input.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
    while s.count % 4 != 0 { s.append("=") }
    self.init(base64Encoded: s)
  }
}
