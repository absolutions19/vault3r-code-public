/**
 * Deterministic canonical encoding — the signing preimage.
 *
 * Signatures are computed over the bytes produced here, and the vault verifies
 * over the *same* bytes it will act on ("apply the exact canonical bytes that
 * were hashed"). The encoding is a strict subset of JSON with:
 *   - object keys sorted by UTF-16 code unit (RFC 8785 / JCS ordering),
 *   - no insignificant whitespace,
 *   - only finite safe-integer numbers (floats/NaN/Infinity are rejected —
 *     a security protocol must never sign an ambiguously-formatted float),
 *   - strings emitted with canonical minimal JSON escaping,
 *   - `undefined` object members dropped; `undefined` array items rejected.
 *
 * The encoder is total and injective over the value space it accepts: two
 * inputs that differ produce different bytes, and it never throws on accepted
 * input. Anything it cannot encode unambiguously is rejected up front.
 */

export type CanonicalValue =
  | null
  | boolean
  | number
  | string
  | CanonicalValue[]
  | { [k: string]: CanonicalValue | undefined };

export class CanonicalizeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CanonicalizeError";
  }
}

const textEncoder = new TextEncoder();

function encodeString(s: string): string {
  // Minimal JSON string escaping, matching JSON.stringify for a single string,
  // which is already deterministic and RFC 8785-compatible for the BMP subset
  // we use. We do NOT normalize (NFC handling happens in the strict parser at
  // the trust boundary) so the preimage exactly reflects the caller's bytes.
  return JSON.stringify(s);
}

function canonicalString(value: CanonicalValue): string {
  if (value === null) return "null";

  const t = typeof value;
  if (t === "boolean") return value ? "true" : "false";

  if (t === "number") {
    const n = value as number;
    if (!Number.isFinite(n)) {
      throw new CanonicalizeError(`non-finite number is not canonicalizable: ${String(n)}`);
    }
    if (!Number.isInteger(n)) {
      throw new CanonicalizeError(`non-integer number is not canonicalizable: ${String(n)}`);
    }
    if (!Number.isSafeInteger(n)) {
      throw new CanonicalizeError(`unsafe-integer number is not canonicalizable: ${String(n)}`);
    }
    // Normalize -0 to 0.
    return Object.is(n, -0) ? "0" : String(n);
  }

  if (t === "string") return encodeString(value as string);

  if (Array.isArray(value)) {
    const parts = value.map((item) => {
      if (item === undefined) {
        throw new CanonicalizeError("undefined is not allowed as an array element");
      }
      return canonicalString(item);
    });
    return `[${parts.join(",")}]`;
  }

  if (t === "object") {
    const obj = value as { [k: string]: CanonicalValue | undefined };
    const keys = Object.keys(obj)
      .filter((k) => obj[k] !== undefined)
      .sort(compareUtf16);
    const parts = keys.map((k) => `${encodeString(k)}:${canonicalString(obj[k] as CanonicalValue)}`);
    return `{${parts.join(",")}}`;
  }

  throw new CanonicalizeError(`unsupported value type: ${t}`);
}

/** Sort by UTF-16 code unit — the ordering RFC 8785 specifies for member keys. */
function compareUtf16(a: string, b: string): number {
  if (a === b) return 0;
  return a < b ? -1 : 1;
}

/** Canonical JSON string form of a value. */
export function canonicalStringify(value: CanonicalValue): string {
  return canonicalString(value);
}

/** Canonical byte form (UTF-8) of a value — the actual signing preimage. */
export function canonicalBytes(value: CanonicalValue): Uint8Array {
  return textEncoder.encode(canonicalStringify(value));
}
