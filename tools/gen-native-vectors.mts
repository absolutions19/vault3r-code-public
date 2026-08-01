/**
 * Generates known-answer test vectors for the native vault-keystore module,
 * straight from the audited @vault/crypto-core reference. The iOS (Swift) and
 * Android (Kotlin) implementations should reproduce every output byte-for-byte.
 *
 *   Run:  pnpm gen:vectors    (writes apps/vault/modules/vault-keystore/conformance/test-vectors.json)
 *
 * Everything here uses FIXED inputs so the outputs are deterministic KATs. Nonces
 * and salts that are random in production are pinned to fixed values here so the
 * native side can assert equality; production code must still use fresh randomness.
 */

import { writeFile, mkdir } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import {
  sha256,
  hkdfSha256,
  hchacha20,
  xchachaSeal,
  xchachaOpen,
  ed25519PublicFromSeed,
  ed25519Sign,
  ed25519Verify,
  x25519PublicFromPrivate,
  x25519SharedSecret,
  deriveNamespace,
  deriveRecoveryKey,
  createRecoveryBlob,
  restoreDekFromRecovery,
  isValidRecoveryMnemonic,
  toHex,
  fromHex,
  toBase64Url,
  utf8ToBytes,
  concatBytes,
} from "../packages/crypto-core/src/index.ts";
import {
  makeDomain,
  typedSigningPreimage,
  settleSigningPreimage,
  canonicalBytes,
  PROTOCOL_VERSION,
  type TypedData,
} from "../packages/protocol/src/index.ts";

const assert = (cond: boolean, msg: string) => {
  if (!cond) throw new Error(`vector self-check FAILED: ${msg}`);
};

// ---- SHA-256 ----------------------------------------------------------------
const sha = { input_utf8: "abc", digest_hex: toHex(sha256(utf8ToBytes("abc"))) };
assert(sha.digest_hex === "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", "sha256(abc)");

// ---- Ed25519 (device + identity signatures) --------------------------------
const edSeed = fromHex("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20");
const edMsg = utf8ToBytes("vault native conformance");
const edPub = ed25519PublicFromSeed(edSeed);
const edSig = ed25519Sign(edMsg, edSeed);
assert(ed25519Verify(edMsg, edSig, edPub), "ed25519 verify");
const ed25519 = {
  note: "RFC 8032 Ed25519. seed = 32-byte private scalar seed.",
  seed_hex: toHex(edSeed),
  publicKey_hex: toHex(edPub),
  message_utf8: "vault native conformance",
  signature_hex: toHex(edSig),
};

// ---- X25519 (transport ECDH) — RFC 7748 vectors ----------------------------
const alicePriv = fromHex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
const bobPriv = fromHex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
const alicePub = x25519PublicFromPrivate(alicePriv);
const bobPub = x25519PublicFromPrivate(bobPriv);
const shared = x25519SharedSecret(alicePriv, bobPub);
assert(toHex(alicePub) === "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a", "x25519 alice pub (RFC 7748)");
assert(toHex(shared) === "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742", "x25519 shared (RFC 7748)");
assert(toHex(x25519SharedSecret(bobPriv, alicePub)) === toHex(shared), "x25519 symmetric");
const x25519 = {
  note: "RFC 7748 X25519. Matches the RFC test vectors.",
  alicePriv_hex: toHex(alicePriv),
  alicePub_hex: toHex(alicePub),
  bobPriv_hex: toHex(bobPriv),
  bobPub_hex: toHex(bobPub),
  sharedSecret_hex: toHex(shared),
};

// ---- HKDF-SHA256 ------------------------------------------------------------
const hkIkm = fromHex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
const hkSalt = fromHex("000102030405060708090a0b0c");
const hkInfo = utf8ToBytes("vault-hkdf-example");
const hkOut = hkdfSha256(hkIkm, hkSalt, hkInfo, 32);
const hkdf = {
  note: "HKDF-SHA256 (extract+expand).",
  ikm_hex: toHex(hkIkm),
  salt_hex: toHex(hkSalt),
  info_utf8: "vault-hkdf-example",
  length: 32,
  okm_hex: toHex(hkOut),
};

// ---- HChaCha20 (subkey core of XChaCha) — draft-irtf-cfrg-xchacha KAT -------
const hcKey = fromHex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
const hcNonce = fromHex("000000090000004a0000000031415927");
const hchacha20Kat = {
  note: "HChaCha20 core. Used to build XChaCha20 from IETF ChaCha20-Poly1305.",
  key_hex: toHex(hcKey),
  nonce16_hex: toHex(hcNonce),
  subkey_hex: toHex(hchacha20(hcKey, hcNonce)),
};

// ---- XChaCha20-Poly1305 (AEAD; at-rest + envelope) -------------------------
const xKey = fromHex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
const xNonce = fromHex("404142434445464748494a4b4c4d4e4f5051525354555657"); // 24 bytes
const xAad = utf8ToBytes("vault-doc/1|example");
const xPt = utf8ToBytes("the vault is sealed");
const xBox = xchachaSeal(xKey, xNonce, xPt, xAad);
assert(toHex(xchachaOpen(xKey, xNonce, xBox.ciphertext, xBox.tag, xAad)!) === toHex(xPt), "xchacha roundtrip");
const xchacha20poly1305 = {
  note: "XChaCha20-Poly1305 (24-byte nonce). NOTE: iOS CryptoKit ChaChaPoly is the IETF 12-byte-nonce variant, NOT this — use libsodium crypto_aead_xchacha20poly1305 on iOS.",
  key_hex: toHex(xKey),
  nonce24_hex: toHex(xNonce),
  aad_utf8: "vault-doc/1|example",
  plaintext_utf8: "the vault is sealed",
  ciphertext_hex: toHex(xBox.ciphertext),
  tag_hex: toHex(xBox.tag),
};

// ---- Namespace derivation ---------------------------------------------------
const nsHost = "app.example.com";
const derived = deriveNamespace(nsHost, "registrable-domain");
const namespace = {
  note: "namespace = 'web:' + registrable-domain(host); storageKey = sha256(namespace) hex.",
  host: nsHost,
  granularity: "registrable-domain",
  namespace: derived.namespace,
  storageKey_hex: derived.storageKey,
};

// ---- Per-namespace subkey (HKDF from the DEK) ------------------------------
const masterDek = fromHex("d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1");
const storageKey = derived.storageKey;
const nsSaltInput = `vault-ns-salt|${storageKey}`;
const nsSalt = sha256(utf8ToBytes(nsSaltInput));
const nsInfo = `vault-ns/v1|${storageKey}`;
const nsSubkey = hkdfSha256(masterDek, nsSalt, utf8ToBytes(nsInfo), 32);
const namespaceSubkey = {
  note: "Per-namespace AEAD key. salt = sha256('vault-ns-salt|'+storageKey); info = 'vault-ns/v1|'+storageKey.",
  masterDek_hex: toHex(masterDek),
  storageKey_hex: storageKey,
  hkdfSalt_input_utf8: nsSaltInput,
  hkdfSalt_hex: toHex(nsSalt),
  hkdfInfo_utf8: nsInfo,
  subkey_hex: toHex(nsSubkey),
};

// ---- At-rest sealed blob (pack layout) -------------------------------------
const arNonce = fromHex("101112131415161718191a1b1c1d1e1f2021222324252627"); // 24 bytes, fixed
const arAadStr = `vault-doc/1|${storageKey}`;
const arPt = utf8ToBytes('{"v":1,"doc":{"profile":{"name":"Ada"}}}');
const arBox = xchachaSeal(nsSubkey, arNonce, arPt, utf8ToBytes(arAadStr));
const arPack = concatBytes(new Uint8Array([0x01]), arBox.nonce, arBox.tag, arBox.ciphertext);
const atRestBlob = {
  note: "Sealed namespace blob. AEAD key = the per-namespace subkey above; AAD = 'vault-doc/1|'+storageKey.",
  pack_layout: "0x01 (version) || nonce(24) || tag(16) || ciphertext(...)",
  subkey_hex: toHex(nsSubkey),
  aad_utf8: arAadStr,
  nonce24_hex: toHex(arNonce),
  plaintext_utf8: '{"v":1,"doc":{"profile":{"name":"Ada"}}}',
  ciphertext_hex: toHex(arBox.ciphertext),
  tag_hex: toHex(arBox.tag),
  pack_hex: toHex(arPack),
  pack_b64url: toBase64Url(arPack),
};

// ---- Settle signing (device key authenticates the session) -----------------
const settleInput = {
  sessionId: "sess-1",
  namespace: "web:example.com",
  grantId: "grant-1",
  responderPublicKey: toBase64Url(alicePub),
  vaultDeviceKey: toBase64Url(edPub),
  expiresAt: 1760000000000,
  methods: ["vault_getData", "vault_setData"],
};
const settlePreimage = settleSigningPreimage(settleInput);
const settleSig = ed25519Sign(settlePreimage, edSeed);
const typedWrite: TypedData<"VaultWrite"> = {
  primaryType: "VaultWrite",
  domain: makeDomain("vault-1"),
  message: {
    namespace: "web:example.com",
    nonce: "n1",
    issuedAt: 1760000000000,
    expiry: 1760000200000,
    sessionId: "sess-1",
    changes: [{ op: "replace", path: "/profile/name", valueHash: "sha256:1b2c" }],
  },
};
const signing = {
  note: "deviceSign(bytes) is raw Ed25519 over these preimages (deterministic canonical bytes).",
  settle: {
    input: settleInput,
    preimage_utf8: new TextDecoder().decode(settlePreimage),
    preimage_hex: toHex(settlePreimage),
    deviceSeed_hex: toHex(edSeed),
    deviceSignature_hex: toHex(settleSig),
  },
  typedWrite: {
    primaryType: "VaultWrite",
    domainVersion: PROTOCOL_VERSION,
    preimage_utf8: new TextDecoder().decode(typedSigningPreimage(typedWrite)),
    preimage_hex: toHex(typedSigningPreimage(typedWrite)),
  },
};

// ---- Recovery (Argon2id + BIP-39) ------------------------------------------
// Fixed 24-word mnemonic (zero-entropy BIP-39 test phrase) for a reproducible KAT.
const mnemonic =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
assert(isValidRecoveryMnemonic(mnemonic), "test mnemonic is valid BIP-39");
const recContext = "vault-1";
const recParams = { t: 2, m: 8 * 1024, p: 1 }; // FAST params for a fast KAT; production defaults to 64 MiB.
const recSalt = fromHex("00112233445566778899aabbccddeeff");
const recDek = fromHex("2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40");
const recKey = deriveRecoveryKey(mnemonic, recSalt, recParams);
// AAD binds context + params + salt (mirrors recovery.ts recoveryAad).
const recAad = canonicalBytes({
  tag: "vault-recovery/1",
  kdf: "argon2id",
  context: recContext,
  t: recParams.t,
  m: recParams.m,
  p: recParams.p,
  salt: toBase64Url(recSalt),
});
const recNonce = fromHex("aabbccddeeff00112233445566778899aabbccddeeff0011"); // 24 bytes
const recBox = xchachaSeal(recKey, recNonce, recDek, recAad);
// End-to-end sanity via the real API (random salt/nonce), proving round-trip.
const liveBlob = createRecoveryBlob(recDek, mnemonic, recContext, recParams);
assert(toHex(restoreDekFromRecovery(liveBlob, mnemonic, recContext)!) === toHex(recDek), "recovery roundtrip");
assert(restoreDekFromRecovery(liveBlob, mnemonic, "other") === null, "recovery context binding");
const recovery = {
  note: "K_recovery = Argon2id(mnemonic NFKD, salt, {t,m KiB,p}, dkLen=32). Wrap DEK with XChaCha20-Poly1305; AAD = canonical JSON of {tag,kdf,context,t,m,p,salt_b64url}.",
  mnemonic,
  context: recContext,
  params_note: "m is memory in KiB. These KAT params are FAST (8 MiB); production default is 64 MiB (t=3).",
  params: recParams,
  salt_hex: toHex(recSalt),
  recoveryKey_hex: toHex(recKey),
  aad_utf8: new TextDecoder().decode(recAad),
  dek_hex: toHex(recDek),
  nonce24_hex: toHex(recNonce),
  wrappedCiphertext_hex: toHex(recBox.ciphertext),
  wrappedTag_hex: toHex(recBox.tag),
  blob_schema: { v: 1, kdf: "argon2id", context: "string", t: 0, m: 0, p: 0, salt: "b64url", nonce: "b64url", ct: "b64url", tag: "b64url" },
};

const vectors = {
  $schema: "vault-native-conformance/1",
  generatedBy: "@vault/crypto-core — regenerate with `pnpm gen:vectors`",
  encoding: "hex unless the field name ends _b64url (base64url, unpadded) or _utf8 (raw string)",
  warning: "Nonces/salts here are FIXED for reproducible KATs. Production must use fresh CSPRNG randomness.",
  sha256: sha,
  ed25519,
  x25519,
  hkdfSha256: hkdf,
  hchacha20: hchacha20Kat,
  xchacha20poly1305,
  namespace,
  namespaceSubkey,
  atRestBlob,
  signing,
  recovery,
};

const outDir = fileURLToPath(new URL("../apps/vault/modules/vault-keystore/conformance/", import.meta.url));
await mkdir(outDir, { recursive: true });
await writeFile(`${outDir}test-vectors.json`, JSON.stringify(vectors, null, 2) + "\n");
console.log("All self-checks passed. Wrote apps/vault/modules/vault-keystore/conformance/test-vectors.json");
console.log(`Sections: ${Object.keys(vectors).filter((k) => !k.startsWith("$") && !["generatedBy", "encoding", "warning"].includes(k)).join(", ")}`);
