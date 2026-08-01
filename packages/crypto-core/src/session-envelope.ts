/**
 * Session envelope: encrypt a JSON body under the session key with AEAD, binding
 * the associated data (topic, tag, protocol version, message type, direction).
 * The relay only ever sees the packed ciphertext blob.
 *
 * Wire format of the packed payload (then base64url):
 *   0x01 | nonce(24) | tag(16) | ciphertext(...)
 */

import { canonicalBytes, type EnvelopeAad } from "@vault/protocol";
import { xchachaSeal, xchachaOpen, XCHACHA_NONCE_BYTES, XCHACHA_TAG_BYTES } from "./xchacha.js";
import { randomBytes } from "./primitives.js";
import { toBase64Url, fromBase64Url, utf8ToBytes, bytesToUtf8, concatBytes } from "./encoding.js";

const VERSION_BYTE = 0x01;

function aadBytes(aad: EnvelopeAad): Uint8Array {
  return canonicalBytes({
    topic: aad.topic,
    tag: aad.tag,
    pv: aad.pv,
    msgType: aad.msgType,
    dir: aad.dir,
  });
}

/** Encrypt a JSON-serializable body into a base64url payload. */
export function sealEnvelope(sessionKey: Uint8Array, aad: EnvelopeAad, body: unknown): string {
  const plaintext = utf8ToBytes(JSON.stringify(body));
  const nonce = randomBytes(XCHACHA_NONCE_BYTES);
  const box = xchachaSeal(sessionKey, nonce, plaintext, aadBytes(aad));
  const packed = concatBytes(new Uint8Array([VERSION_BYTE]), box.nonce, box.tag, box.ciphertext);
  return toBase64Url(packed);
}

/** Decrypt a base64url payload. Returns the parsed body, or throws on failure. */
export function openEnvelope<T = unknown>(sessionKey: Uint8Array, aad: EnvelopeAad, payload: string): T {
  const packed = fromBase64Url(payload);
  const headerLen = 1 + XCHACHA_NONCE_BYTES + XCHACHA_TAG_BYTES;
  if (packed.length < headerLen) throw new Error("envelope too short");
  if (packed[0] !== VERSION_BYTE) throw new Error("unsupported envelope version");
  const nonce = packed.subarray(1, 1 + XCHACHA_NONCE_BYTES);
  const tag = packed.subarray(1 + XCHACHA_NONCE_BYTES, headerLen);
  const ct = packed.subarray(headerLen);
  const pt = xchachaOpen(sessionKey, nonce, ct, tag, aadBytes(aad));
  if (pt === null) throw new Error("envelope authentication failed");
  return JSON.parse(bytesToUtf8(pt)) as T;
}
