/**
 * Thin, audited wrappers over Node's built-in crypto. Keeping every primitive
 * behind one module means there is a single place to review algorithm choices
 * and a single seam to swap in a native/RN provider later.
 *
 * Private keys are reconstructed from their raw 32-byte scalar/seed via the
 * fixed PKCS8 DER prefix for the curve — this needs only the private bytes (no
 * public component) and avoids brittle JWK round-tripping.
 */

import {
  createHash,
  hkdfSync,
  randomBytes as nodeRandomBytes,
  generateKeyPairSync,
  sign as nodeSign,
  verify as nodeVerify,
  diffieHellman,
  createPublicKey,
  createPrivateKey,
  type KeyObject,
} from "node:crypto";
import { toBase64Url, fromBase64Url, fromHex, concatBytes } from "./encoding.js";

export function randomBytes(n: number): Uint8Array {
  return new Uint8Array(nodeRandomBytes(n));
}

export function sha256(data: Uint8Array): Uint8Array {
  return new Uint8Array(createHash("sha256").update(data).digest());
}

export function hkdfSha256(
  ikm: Uint8Array,
  salt: Uint8Array,
  info: Uint8Array,
  length: number,
): Uint8Array {
  return new Uint8Array(hkdfSync("sha256", ikm, salt, info, length));
}

// Fixed PKCS8 DER prefixes: SEQ { version, AlgId { OID }, OCTET STRING { OCTET STRING { key } } }
const ED25519_PKCS8_PREFIX = fromHex("302e020100300506032b657004220420"); // OID 1.3.101.112
const X25519_PKCS8_PREFIX = fromHex("302e020100300506032b656e04220420"); // OID 1.3.101.110

export interface RawKeyPair {
  publicKey: Uint8Array; // 32 bytes
  privateKey: Uint8Array; // 32 bytes (seed / scalar)
}

// ---------------------------------------------------------------------------
// Ed25519 (identity + device signatures)
// ---------------------------------------------------------------------------

function ed25519PrivFromSeed(seed32: Uint8Array): KeyObject {
  if (seed32.length !== 32) throw new Error("ed25519 seed must be 32 bytes");
  return createPrivateKey({
    key: Buffer.from(concatBytes(ED25519_PKCS8_PREFIX, seed32)),
    format: "der",
    type: "pkcs8",
  });
}

function ed25519PubFromRaw(raw32: Uint8Array): KeyObject {
  return createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: toBase64Url(raw32) }, format: "jwk" });
}

function rawPubOf(priv: KeyObject): Uint8Array {
  const jwk = createPublicKey(priv).export({ format: "jwk" }) as { x: string };
  return fromBase64Url(jwk.x);
}

export function ed25519Generate(): RawKeyPair {
  const { privateKey } = generateKeyPairSync("ed25519");
  const jwkPriv = privateKey.export({ format: "jwk" }) as { d: string };
  const seed = fromBase64Url(jwkPriv.d);
  return { privateKey: seed, publicKey: rawPubOf(privateKey) };
}

export function ed25519PublicFromSeed(seed32: Uint8Array): Uint8Array {
  return rawPubOf(ed25519PrivFromSeed(seed32));
}

export function ed25519Sign(message: Uint8Array, seed32: Uint8Array): Uint8Array {
  return new Uint8Array(nodeSign(null, message, ed25519PrivFromSeed(seed32)));
}

export function ed25519Verify(
  message: Uint8Array,
  signature: Uint8Array,
  publicKey32: Uint8Array,
): boolean {
  if (publicKey32.length !== 32 || signature.length !== 64) return false;
  try {
    return nodeVerify(null, message, ed25519PubFromRaw(publicKey32), signature);
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// X25519 (transport key agreement)
// ---------------------------------------------------------------------------

function x25519PrivFromRaw(raw32: Uint8Array): KeyObject {
  if (raw32.length !== 32) throw new Error("x25519 private must be 32 bytes");
  return createPrivateKey({
    key: Buffer.from(concatBytes(X25519_PKCS8_PREFIX, raw32)),
    format: "der",
    type: "pkcs8",
  });
}

function x25519PubFromRaw(raw32: Uint8Array): KeyObject {
  return createPublicKey({ key: { kty: "OKP", crv: "X25519", x: toBase64Url(raw32) }, format: "jwk" });
}

export function x25519Generate(): RawKeyPair {
  const { privateKey } = generateKeyPairSync("x25519");
  const jwkPriv = privateKey.export({ format: "jwk" }) as { d: string };
  const raw = fromBase64Url(jwkPriv.d);
  return { privateKey: raw, publicKey: rawPubOf(privateKey) };
}

export function x25519PublicFromPrivate(private32: Uint8Array): Uint8Array {
  return rawPubOf(x25519PrivFromRaw(private32));
}

/** Raw X25519 ECDH shared secret (32 bytes). */
export function x25519SharedSecret(privateKey32: Uint8Array, peerPublicKey32: Uint8Array): Uint8Array {
  return new Uint8Array(
    diffieHellman({ privateKey: x25519PrivFromRaw(privateKey32), publicKey: x25519PubFromRaw(peerPublicKey32) }),
  );
}
