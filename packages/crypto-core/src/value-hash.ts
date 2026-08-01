/**
 * Value hashing for write payloads. Distinct from the strict signing canonicalizer
 * (which only accepts safe integers): stored *values* may contain floats, so we
 * hash a relaxed but still deterministic stable-JSON encoding. The SDK computes
 * `valueHash` with this; the vault re-computes it over the actual value it will
 * store and compares — so "the bytes that were consented are the bytes applied."
 */

import { sha256 } from "./primitives.js";
import { toHex, utf8ToBytes } from "./encoding.js";

export type JsonValue = null | boolean | number | string | JsonValue[] | { [k: string]: JsonValue };

/** Deterministic JSON with object keys sorted; rejects non-finite numbers. */
export function stableJsonStringify(value: JsonValue): string {
  return serialize(value);
}

function serialize(value: JsonValue): string {
  if (value === null) return "null";
  const t = typeof value;
  if (t === "number") {
    if (!Number.isFinite(value as number)) throw new Error("non-finite number cannot be hashed");
    return JSON.stringify(value);
  }
  if (t === "boolean" || t === "string") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(serialize).join(",")}]`;
  if (t === "object") {
    const obj = value as { [k: string]: JsonValue };
    const keys = Object.keys(obj).sort();
    return `{${keys.map((k) => `${JSON.stringify(k)}:${serialize(obj[k] as JsonValue)}`).join(",")}}`;
  }
  throw new Error(`unsupported value type: ${t}`);
}

/** `sha256:<hex>` of the stable JSON encoding of a value. */
export function hashJsonValue(value: JsonValue): string {
  return `sha256:${toHex(sha256(utf8ToBytes(stableJsonStringify(value))))}`;
}
