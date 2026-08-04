/**
 * Data-Vault icon validation + monogram fallback (Freedom Browser integration).
 *
 * A site ships its own tile icon IN-BAND at connect time (`appMetadata.icon`, a
 * `data:` URI). That choice is what keeps the vault home page network-silent:
 * rendering the grid never touches the wire, so opening it can't beacon "here are
 * all the sites I hold data for" to anyone watching, and dweb origins work with
 * no gateway in the loop.
 *
 * The tradeoff is that we are now storing PAGE-CONTROLLED BYTES and decoding them
 * in the most privileged renderer in the browser. Everything below exists to make
 * that safe:
 *
 *  - `data:` URIs ONLY. No http/https/file/blob — a URL would reintroduce the
 *    fetch we just designed away.
 *  - PNG / JPEG / WebP only. **SVG is rejected**: it is script-capable, and the
 *    home page is a privileged surface where an <img> XSS would be catastrophic.
 *  - The declared MIME must match the actual magic bytes (labels are not trusted).
 *  - Canonical base64 only, hard byte cap, hard dimension cap — the engine applies
 *    NO cap to appMetadata, and this lands in a plaintext JSON file, so an
 *    unbounded icon would be both a disk-fill and a decompression bomb vector.
 *  - When Electron is available the image is re-encoded through `nativeImage`,
 *    which normalizes to a clean 128×128 PNG and drops EXIF/ICC/animation.
 *
 * A site that supplies nothing gets `monogramFor()` — a letter on a hue derived
 * from the namespace. Deterministic, needs no seed (so it renders identically on
 * every device), and never blank.
 *
 * Pure Node + Buffer: no Electron import, so the headless smoke test drives the
 * real validator. `nativeImage` is injected by the caller when present.
 *
 * REFERENCE glue — copy into `src/main/vault/`.
 */

/** Decoded-bytes cap. Generous for a 128px tile, hostile to anything else. */
const MAX_ICON_BYTES = 64 * 1024;
/** Reject decompression bombs: a 30KB PNG can claim 30000×30000. */
const MAX_DIM = 512;
const MIN_DIM = 8;
/** Normalized output edge, when a re-encoder is available. */
const NORMALIZED_DIM = 128;
/** Cap the claimed display name too — nothing upstream does. */
const MAX_NAME_CHARS = 128;

/** MIME -> magic-byte matcher. SVG is deliberately absent. */
const ALLOWED_TYPES = {
  'image/png': (b) =>
    b.length > 8 &&
    b[0] === 0x89 && b[1] === 0x50 && b[2] === 0x4e && b[3] === 0x47 &&
    b[4] === 0x0d && b[5] === 0x0a && b[6] === 0x1a && b[7] === 0x0a,
  'image/jpeg': (b) => b.length > 3 && b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff,
  'image/webp': (b) =>
    b.length > 12 && b.toString('ascii', 0, 4) === 'RIFF' && b.toString('ascii', 8, 12) === 'WEBP',
};

/** Strict: `data:<mime>;base64,<canonical base64>` and nothing else. */
const DATA_URI_RE = /^data:([a-z]+\/[a-z0-9.+-]+);base64,([A-Za-z0-9+/]+={0,2})$/;

/**
 * Validate a site-supplied icon and (when possible) re-encode it to a clean PNG.
 *
 * @param {unknown} input  The raw `appMetadata.icon` value from the page.
 * @param {{ nativeImage?: { createFromBuffer: Function } }} [opts]
 *   Pass Electron's `nativeImage` in the real browser; omit it in tests, where
 *   the validated original bytes are kept as-is.
 * @returns {{ ok: true, icon: { dataUri: string, mime: string, width: number, height: number, bytes: number } }
 *          | { ok: false, reason: string }}
 */
function normalizeIcon(input, opts = {}) {
  if (input === undefined || input === null) return { ok: false, reason: 'absent' };
  if (typeof input !== 'string') return { ok: false, reason: 'not a string' };
  // Bound the parse itself before touching a regex (base64 is ~4/3 of the bytes).
  if (input.length > Math.ceil((MAX_ICON_BYTES * 4) / 3) + 64) {
    return { ok: false, reason: 'icon too large' };
  }

  const m = DATA_URI_RE.exec(input);
  if (!m) return { ok: false, reason: 'not a base64 data: URI' };
  const mime = m[1].toLowerCase();
  const b64 = m[2];

  const sniff = ALLOWED_TYPES[mime];
  if (!sniff) return { ok: false, reason: `unsupported type: ${mime}` };

  const buf = Buffer.from(b64, 'base64');
  // Buffer's decoder is lenient; require the encoding to have been canonical so
  // two different strings can't decode to the same pinned icon.
  if (buf.toString('base64') !== b64) return { ok: false, reason: 'non-canonical base64' };
  if (buf.length === 0) return { ok: false, reason: 'empty' };
  if (buf.length > MAX_ICON_BYTES) return { ok: false, reason: 'icon too large' };
  if (!sniff(buf)) return { ok: false, reason: 'content does not match declared type' };

  const dims = readDimensions(mime, buf);
  if (!dims) return { ok: false, reason: 'unreadable image header' };
  if (dims.width < MIN_DIM || dims.height < MIN_DIM) return { ok: false, reason: 'image too small' };
  if (dims.width > MAX_DIM || dims.height > MAX_DIM) return { ok: false, reason: 'image too large' };

  // Re-encode through Chromium's decoder when we have it: this strips metadata,
  // flattens animation, and means the bytes we persist were produced by us.
  const ni = opts.nativeImage;
  if (ni && typeof ni.createFromBuffer === 'function') {
    try {
      const img = ni.createFromBuffer(buf);
      if (!img || img.isEmpty()) return { ok: false, reason: 'decoder rejected the image' };
      const png = img.resize({ width: NORMALIZED_DIM, height: NORMALIZED_DIM, quality: 'good' }).toPNG();
      if (!png || png.length === 0) return { ok: false, reason: 're-encode produced nothing' };
      if (png.length > MAX_ICON_BYTES) return { ok: false, reason: 're-encoded icon too large' };
      return {
        ok: true,
        icon: {
          dataUri: `data:image/png;base64,${png.toString('base64')}`,
          mime: 'image/png',
          width: NORMALIZED_DIM,
          height: NORMALIZED_DIM,
          bytes: png.length,
        },
      };
    } catch (err) {
      return { ok: false, reason: `decode failed: ${err && err.message}` };
    }
  }

  // No re-encoder (headless tests): keep the validated original.
  return {
    ok: true,
    icon: {
      dataUri: `data:${mime};base64,${b64}`,
      mime,
      width: dims.width,
      height: dims.height,
      bytes: buf.length,
    },
  };
}

/**
 * Deterministic fallback tile for a site that shipped no icon: a letter on a hue
 * derived from the namespace. Namespace-derived (not seed-derived) so it needs no
 * unlock and is stable across devices; the site name below the tile is always the
 * authoritative label.
 *
 * @param {string} namespace  e.g. "web:example.com"
 * @param {string|null} [name]  Claimed display name, if any.
 * @returns {{ letter: string, hue: number }}
 */
function monogramFor(namespace, name) {
  const source = (typeof name === 'string' && name.trim()) || stripNamespacePrefix(namespace) || '?';
  const letter = (source.match(/[a-z0-9]/i) || ['?'])[0].toUpperCase();
  return { letter, hue: fnv1a(String(namespace)) % 360 };
}

/**
 * Clamp the page's claimed display metadata to something safe to persist and
 * render. Strips control characters (including bidi overrides, which are a
 * classic display-spoofing trick) and caps the length.
 * @param {unknown} name
 * @returns {string|null}
 */
function sanitizeName(name) {
  if (typeof name !== 'string') return null;
  // C0/C1 controls, zero-width marks, and the bidi overrides used to make
  // "moc.live" render as "evil.com".
  // eslint-disable-next-line no-control-regex
  const cleaned = name.replace(/[\u0000-\u001F\u007F-\u009F\u200B-\u200F\u202A-\u202E\u2066-\u2069]/g, '').trim();
  if (!cleaned) return null;
  return cleaned.length > MAX_NAME_CHARS ? `${cleaned.slice(0, MAX_NAME_CHARS - 1)}…` : cleaned;
}

// --- helpers -----------------------------------------------------------------

function stripNamespacePrefix(ns) {
  if (typeof ns !== 'string') return '';
  return ns.replace(/^web:(dweb:)?/, '').replace(/^[a-z0-9]+:/, '');
}

function fnv1a(s) {
  let h = 0x811c9dc5;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return h >>> 0;
}

/** @returns {{width:number,height:number}|null} */
function readDimensions(mime, b) {
  if (mime === 'image/png') return pngDimensions(b);
  if (mime === 'image/jpeg') return jpegDimensions(b);
  if (mime === 'image/webp') return webpDimensions(b);
  return null;
}

function pngDimensions(b) {
  // 8-byte signature, then a length-prefixed IHDR whose payload starts at 16.
  if (b.length < 24) return null;
  if (b.toString('ascii', 12, 16) !== 'IHDR') return null;
  return { width: b.readUInt32BE(16), height: b.readUInt32BE(20) };
}

function jpegDimensions(b) {
  let i = 2; // past SOI
  while (i + 9 < b.length) {
    if (b[i] !== 0xff) return null;
    const marker = b[i + 1];
    // Standalone markers carry no length.
    if (marker === 0xd8 || marker === 0x01 || (marker >= 0xd0 && marker <= 0xd7)) {
      i += 2;
      continue;
    }
    const len = b.readUInt16BE(i + 2);
    if (len < 2) return null;
    // SOF0..SOF15, excluding DHT (c4), JPG (c8) and DAC (cc).
    const isSOF = marker >= 0xc0 && marker <= 0xcf && marker !== 0xc4 && marker !== 0xc8 && marker !== 0xcc;
    if (isSOF) return { height: b.readUInt16BE(i + 5), width: b.readUInt16BE(i + 7) };
    i += 2 + len;
  }
  return null;
}

function webpDimensions(b) {
  if (b.length < 30) return null;
  const chunk = b.toString('ascii', 12, 16);
  if (chunk === 'VP8 ') {
    if (b.toString('hex', 23, 26) !== '9d012a') return null; // keyframe sync code
    return { width: b.readUInt16LE(26) & 0x3fff, height: b.readUInt16LE(28) & 0x3fff };
  }
  if (chunk === 'VP8L') {
    if (b[20] !== 0x2f) return null; // lossless signature
    const bits = b.readUInt32LE(21);
    return { width: (bits & 0x3fff) + 1, height: ((bits >>> 14) & 0x3fff) + 1 };
  }
  if (chunk === 'VP8X') {
    const w = b[24] | (b[25] << 8) | (b[26] << 16);
    const h = b[27] | (b[28] << 8) | (b[29] << 16);
    return { width: w + 1, height: h + 1 };
  }
  return null;
}

module.exports = {
  normalizeIcon,
  monogramFor,
  sanitizeName,
  MAX_ICON_BYTES,
  MAX_DIM,
  MAX_NAME_CHARS,
};
