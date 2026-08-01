import { describe, expect, it } from "vitest";
import {
  ed25519Generate,
  ed25519Sign,
  ed25519Verify,
  ed25519PublicFromSeed,
  x25519Generate,
  x25519SharedSecret,
  x25519PublicFromPrivate,
  sha256,
  hkdfSha256,
  randomBytes,
} from "./primitives.js";
import { hchacha20, xchachaSeal, xchachaOpen } from "./xchacha.js";
import { fromHex, toHex, fromBase64Url, toBase64Url, utf8ToBytes, timingSafeEqual } from "./encoding.js";
import { deriveSessionKey, transcriptHash } from "./handshake.js";
import { sealEnvelope, openEnvelope } from "./session-envelope.js";
import { MAX_ENVELOPE_BYTES, MAX_PLAINTEXT_BYTES, type EnvelopeAad } from "@vault/protocol";

describe("encoding", () => {
  it("base64url round-trips", () => {
    const b = randomBytes(33);
    expect(toBase64Url(b)).not.toContain("=");
    expect(fromBase64Url(toBase64Url(b))).toEqual(b);
  });
  it("base64url round-trips arbitrary byte lengths", () => {
    for (let n = 0; n <= 20; n++) {
      const b = randomBytes(n);
      expect(fromBase64Url(toBase64Url(b))).toEqual(b);
    }
  });
  it("decodes the empty string to empty bytes", () => {
    expect(fromBase64Url("")).toEqual(new Uint8Array(0));
  });
  it("rejects invalid characters and padding", () => {
    expect(() => fromBase64Url("AA==")).toThrow(); // '=' not in the url alphabet
    expect(() => fromBase64Url("a+b/")).toThrow(); // standard base64 chars
  });
  it("rejects a length-1 quantum ('A') — cannot encode a whole byte", () => {
    expect(() => fromBase64Url("A")).toThrow(/length/);
  });
  it("rejects non-canonical encodings with non-zero trailing pad bits", () => {
    // canonical for byte 0x00 is "AA"; "AB"/"AC"/… carry non-zero pad bits
    expect(() => fromBase64Url("AB")).toThrow(/non-canonical/);
    // canonical for [0,0] is "AAA"; "AAB" carries non-zero pad bits
    expect(() => fromBase64Url("AAB")).toThrow(/non-canonical/);
    // the canonical forms decode fine
    expect(fromBase64Url("AA")).toEqual(new Uint8Array([0]));
    expect(fromBase64Url("AAA")).toEqual(new Uint8Array([0, 0]));
  });
  it("is injective: every accepted string re-encodes to itself", () => {
    const b = randomBytes(17);
    const s = toBase64Url(b);
    expect(toBase64Url(fromBase64Url(s))).toBe(s);
  });
  it("exhaustive injectivity over all length-2 strings (no collisions, canonical only)", () => {
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    const seen = new Map<string, string>();
    let accepted = 0;
    for (const a of alphabet) {
      for (const b of alphabet) {
        const s = a + b;
        let bytes: Uint8Array | null = null;
        try {
          bytes = fromBase64Url(s);
        } catch {
          bytes = null;
        }
        if (!bytes) continue;
        accepted++;
        expect(toBase64Url(bytes), `${s} must be canonical`).toBe(s); // canonical => re-encodes to itself
        const key = toHex(bytes);
        expect(seen.has(key), `collision ${s} vs ${seen.get(key)}`).toBe(false);
        seen.set(key, s);
      }
    }
    // 256 canonical length-2 strings decode to the 256 distinct single bytes.
    expect(accepted).toBe(256);
  });
  it("timingSafeEqual", () => {
    expect(timingSafeEqual(fromHex("aabb"), fromHex("aabb"))).toBe(true);
    expect(timingSafeEqual(fromHex("aabb"), fromHex("aabc"))).toBe(false);
    expect(timingSafeEqual(fromHex("aa"), fromHex("aabb"))).toBe(false);
  });
});

describe("Ed25519", () => {
  it("generates, signs, verifies", () => {
    const kp = ed25519Generate();
    expect(kp.publicKey.length).toBe(32);
    expect(ed25519PublicFromSeed(kp.privateKey)).toEqual(kp.publicKey);
    const msg = utf8ToBytes("hello vault");
    const sig = ed25519Sign(msg, kp.privateKey);
    expect(sig.length).toBe(64);
    expect(ed25519Verify(msg, sig, kp.publicKey)).toBe(true);
  });
  it("rejects tampered message and wrong key", () => {
    const kp = ed25519Generate();
    const other = ed25519Generate();
    const sig = ed25519Sign(utf8ToBytes("a"), kp.privateKey);
    expect(ed25519Verify(utf8ToBytes("b"), sig, kp.publicKey)).toBe(false);
    expect(ed25519Verify(utf8ToBytes("a"), sig, other.publicKey)).toBe(false);
  });
});

describe("X25519", () => {
  it("agrees on a shared secret both ways", () => {
    const a = x25519Generate();
    const b = x25519Generate();
    expect(x25519PublicFromPrivate(a.privateKey)).toEqual(a.publicKey);
    const s1 = x25519SharedSecret(a.privateKey, b.publicKey);
    const s2 = x25519SharedSecret(b.privateKey, a.publicKey);
    expect(toHex(s1)).toBe(toHex(s2));
    expect(s1.length).toBe(32);
  });
});

describe("HChaCha20 KAT", () => {
  it("matches the audited @noble/ciphers hchacha for the draft key/nonce", () => {
    // Cross-verified byte-for-byte against @noble/ciphers v1 hchacha() and against
    // the RFC 8439 ChaCha20 block KAT (same round function).
    const key = fromHex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    const nonce = fromHex("000000090000004a0000000031415927");
    const expected = "82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc";
    expect(toHex(hchacha20(key, nonce))).toBe(expected);
  });
});

describe("XChaCha20-Poly1305", () => {
  it("seals and opens with AAD", () => {
    const key = randomBytes(32);
    const nonce = randomBytes(24);
    const pt = utf8ToBytes("the vault is sealed");
    const aad = utf8ToBytes("topic|rpc|1");
    const box = xchachaSeal(key, nonce, pt, aad);
    expect(box.tag.length).toBe(16);
    const opened = xchachaOpen(key, nonce, box.ciphertext, box.tag, aad);
    expect(opened).toEqual(pt);
  });
  it("fails on tampered ciphertext, tag, nonce, key, or AAD", () => {
    const key = randomBytes(32);
    const nonce = randomBytes(24);
    const aad = utf8ToBytes("aad");
    const box = xchachaSeal(key, nonce, utf8ToBytes("secret"), aad);
    const bad = new Uint8Array(box.ciphertext);
    bad[0] = (bad[0]! ^ 1) & 0xff;
    expect(xchachaOpen(key, nonce, bad, box.tag, aad)).toBeNull();
    const badTag = new Uint8Array(box.tag);
    badTag[0] = (badTag[0]! ^ 1) & 0xff;
    expect(xchachaOpen(key, nonce, box.ciphertext, badTag, aad)).toBeNull();
    expect(xchachaOpen(key, randomBytes(24), box.ciphertext, box.tag, aad)).toBeNull();
    expect(xchachaOpen(randomBytes(32), nonce, box.ciphertext, box.tag, aad)).toBeNull();
    expect(xchachaOpen(key, nonce, box.ciphertext, box.tag, utf8ToBytes("other"))).toBeNull();
  });
});

describe("hkdf + sha256", () => {
  it("hkdf produces the requested length deterministically", () => {
    const a = hkdfSha256(utf8ToBytes("ikm"), new Uint8Array(32), utf8ToBytes("info"), 32);
    const b = hkdfSha256(utf8ToBytes("ikm"), new Uint8Array(32), utf8ToBytes("info"), 32);
    expect(toHex(a)).toBe(toHex(b));
    expect(a.length).toBe(32);
  });
  it("sha256 known answer for empty input", () => {
    expect(toHex(sha256(new Uint8Array(0)))).toBe(
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    );
  });
});

describe("handshake + session envelope end to end", () => {
  it("two peers derive the same session key and exchange an authenticated message", () => {
    const proposer = x25519Generate();
    const responder = x25519Generate();
    const params = {
      proposerPublicKey: toBase64Url(proposer.publicKey),
      responderPublicKey: toBase64Url(responder.publicKey),
      protocolVersion: "1",
      pairingNonce: toBase64Url(randomBytes(16)),
    };
    const kProposer = deriveSessionKey(proposer.privateKey, responder.publicKey, params);
    const kResponder = deriveSessionKey(responder.privateKey, proposer.publicKey, params);
    expect(toHex(kProposer)).toBe(toHex(kResponder));
    expect(transcriptHash(params)).toBe(transcriptHash(params));

    const aad: EnvelopeAad = { topic: "t1", tag: "rpc", pv: "1", msgType: "rpc", dir: "c2v" };
    const payload = sealEnvelope(kProposer, aad, { jsonrpc: "2.0", id: "1", method: "vault_ping", params: {} });
    const body = openEnvelope<{ method: string }>(kResponder, aad, payload);
    expect(body.method).toBe("vault_ping");
  });

  it("envelope decryption fails if AAD (topic/direction) differs", () => {
    const k = randomBytes(32);
    const aad: EnvelopeAad = { topic: "t1", tag: "rpc", pv: "1", msgType: "rpc", dir: "c2v" };
    const payload = sealEnvelope(k, aad, { hello: 1 });
    expect(() => openEnvelope(k, { ...aad, topic: "t2" }, payload)).toThrow();
    expect(() => openEnvelope(k, { ...aad, dir: "v2c" }, payload)).toThrow();
  });

  it("rejects an over-large decrypted plaintext (DoS cap)", () => {
    const k = randomBytes(32);
    const aad: EnvelopeAad = { topic: "t1", tag: "rpc", pv: "1", msgType: "rpc", dir: "c2v" };
    // MAX_PLAINTEXT_BYTES is 128 KiB; a ~130 KB body must be rejected on open.
    const payload = sealEnvelope(k, aad, { big: "x".repeat(130 * 1024) });
    expect(() => openEnvelope(k, aad, payload)).toThrow(/size cap/);
  });

  it("rejects an oversized frame BEFORE decoding/decrypting (envelope cap)", () => {
    const k = randomBytes(32);
    const aad: EnvelopeAad = { topic: "t1", tag: "rpc", pv: "1", msgType: "rpc", dir: "c2v" };
    // A ~400 KB base64url string exceeds the MAX_ENVELOPE_BYTES (256 KiB) frame cap.
    expect(() => openEnvelope(k, aad, "A".repeat(400_000))).toThrow(/size cap/);
  });

  it("envelope frame cap boundary: MAX bytes not rejected by the size check, MAX+1 rejected", () => {
    const k = randomBytes(32);
    const aad: EnvelopeAad = { topic: "t1", tag: "rpc", pv: "1", msgType: "rpc", dir: "c2v" };
    const atMax = toBase64Url(new Uint8Array(MAX_ENVELOPE_BYTES)); // decodes to exactly MAX
    const overMax = toBase64Url(new Uint8Array(MAX_ENVELOPE_BYTES + 1)); // MAX + 1
    // At the cap: passes the size gate, then fails later on authentication (not a size error).
    expect(() => openEnvelope(k, aad, atMax)).toThrow(/authentication failed|too short|unsupported/);
    // Over the cap: rejected by the size gate.
    expect(() => openEnvelope(k, aad, overMax)).toThrow(/size cap/);
  });

  it("plaintext cap boundary: a body decrypting to > MAX_PLAINTEXT_BYTES is rejected", () => {
    const k = randomBytes(32);
    const aad: EnvelopeAad = { topic: "t1", tag: "rpc", pv: "1", msgType: "rpc", dir: "c2v" };
    // A JSON string body just over the plaintext cap (still under the envelope cap).
    const body = "y".repeat(MAX_PLAINTEXT_BYTES + 10);
    expect(() => openEnvelope(k, aad, sealEnvelope(k, aad, body))).toThrow(/size cap/);
  });
});
