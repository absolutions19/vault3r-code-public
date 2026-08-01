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

    AsyncFunction("provision") { () -> [String: String] in
      let access = SecAccessControlCreateWithFlags(
        nil,
        kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        [.privateKeyUsage, .biometryCurrentSet],
        nil
      )!
      let kek = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: access)
      try self.persist(self.kekTag, kek.dataRepresentation)

      // Random DEK, wrapped to the KEK's public key via ECDH + HKDF.
      let dek = SymmetricKey(size: .bits256)
      let wrapped = try self.wrapDek(dek, kekPublic: kek.publicKey)
      self.sessionDek = dek

      let deviceKey = Curve25519.Signing.PrivateKey()
      try self.persist(self.deviceKeyTag, deviceKey.rawRepresentation)

      return [
        "wrappedDek": wrapped.base64URLEncodedString(),
        "deviceKeyPublic": deviceKey.publicKey.rawRepresentation.base64URLEncodedString(),
        "vaultId": UUID().uuidString
      ]
    }

    AsyncFunction("unlock") { (reason: String) -> Bool in
      let context = LAContext()
      var err: NSError?
      guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &err) else { return false }
      let ok = try await context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: reason)
      guard ok else { return false }
      self.sessionDek = try self.unwrapDekWithKek()
      return true
    }

    AsyncFunction("lock") { () in
      self.sessionDek = nil // ARC releases; native memory is not on the JS heap
    }

    AsyncFunction("isUnlocked") { () -> Bool in
      return self.sessionDek != nil
    }

    AsyncFunction("authenticate") { (reason: String) -> Bool in
      let context = LAContext()
      return (try? await context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: reason)) ?? false
    }

    AsyncFunction("seal") { (storageKey: String, aadB64: String, plaintextB64: String) -> String in
      let key = try self.namespaceKey(storageKey)
      let aad = Data(base64URLEncoded: aadB64)!
      let pt = Data(base64URLEncoded: plaintextB64)!
      let sealed = try ChaChaPoly.seal(pt, using: key, authenticating: aad)
      return sealed.combined.base64URLEncodedString()
    }

    AsyncFunction("open") { (storageKey: String, aadB64: String, blobB64: String) -> String? in
      let key = try self.namespaceKey(storageKey)
      let aad = Data(base64URLEncoded: aadB64)!
      guard let blob = Data(base64URLEncoded: blobB64),
            let box = try? ChaChaPoly.SealedBox(combined: blob),
            let pt = try? ChaChaPoly.open(box, using: key, authenticating: aad) else { return nil }
      return pt.base64URLEncodedString()
    }

    AsyncFunction("deviceSign") { (bytesB64: String) -> String in
      let key = try self.loadDeviceKey()
      let sig = try key.signature(for: Data(base64URLEncoded: bytesB64)!)
      return sig.base64URLEncodedString()
    }

    AsyncFunction("deviceKeyPublic") { () -> String in
      return try self.loadDeviceKey().publicKey.rawRepresentation.base64URLEncodedString()
    }

    AsyncFunction("exportRecoveryWrappedDek") { (mnemonic: String) -> String in
      // Argon2id(mnemonic) → K_recovery → wrap DEK. (Argon2id via a vetted lib.)
      throw Exception(name: "NotImplemented", description: "Wire Argon2id + recovery wrap here")
    }
    AsyncFunction("importRecoveryWrappedDek") { (mnemonic: String, wrapped: String) -> Bool in
      throw Exception(name: "NotImplemented", description: "Wire Argon2id + recovery unwrap here")
    }
  }

  // MARK: - helpers (KEK/DEK, per-namespace subkey, keychain persistence)

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
