/**
 * RFC 6901 JSON Pointer + a safe subset of RFC 6902 JSON Patch.
 *
 * All paths handled by the vault are namespace-relative. We reject anything that
 * is not a well-formed relative pointer here, before it can touch storage — no
 * `..`, no absolute filesystem-ish paths, no attempt to escape the namespace.
 */

import { VaultError, MAX_FIELD_PATH_LEN } from "@vault/protocol";

export type Json = null | boolean | number | string | Json[] | { [k: string]: Json };

const MAX_TOKENS = 64;

/** Parse a JSON Pointer into its reference tokens. */
const utf8 = new TextEncoder();

export function parsePointer(pointer: string): string[] {
  if (typeof pointer !== "string") throw VaultError.of("FieldOutOfScope", "pointer must be a string");
  // Measured in UTF-8 bytes, consistent with the other byte-denominated caps.
  if (utf8.encode(pointer).length > MAX_FIELD_PATH_LEN) throw VaultError.of("QuotaExceeded", "pointer too long");
  if (pointer === "") return [];
  if (!pointer.startsWith("/")) {
    throw VaultError.of("FieldOutOfScope", `pointer must be empty or start with '/': ${pointer}`);
  }
  const parts = pointer.split("/").slice(1);
  if (parts.length > MAX_TOKENS) {
    throw VaultError.of("QuotaExceeded", "pointer too deep");
  }
  return parts.map((p) => p.replace(/~1/g, "/").replace(/~0/g, "~"));
}

function isPlainObject(v: unknown): v is { [k: string]: Json } {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/** Read the value at a pointer, or undefined if the path does not exist. */
export function pointerGet(doc: Json, pointer: string): Json | undefined {
  const tokens = parsePointer(pointer);
  let cur: Json | undefined = doc;
  for (const t of tokens) {
    if (cur === undefined || cur === null) return undefined;
    if (Array.isArray(cur)) {
      const arr: Json[] = cur;
      const idx: number = t === "-" ? arr.length : Number(t);
      if (!Number.isInteger(idx) || idx < 0 || idx >= arr.length) return undefined;
      cur = arr[idx];
    } else if (isPlainObject(cur)) {
      if (!Object.prototype.hasOwnProperty.call(cur, t)) return undefined;
      cur = cur[t];
    } else {
      return undefined;
    }
  }
  return cur;
}

/** Return a deep clone of `doc` with `value` set at `pointer`. */
export function pointerSet(doc: Json, pointer: string, value: Json): Json {
  const tokens = parsePointer(pointer);
  if (tokens.length === 0) return value;
  const root: Json = doc === undefined || doc === null ? {} : structuredClone(doc);
  let cur: Json = root;
  for (let i = 0; i < tokens.length - 1; i++) {
    const t = tokens[i]!;
    if (isPlainObject(cur)) {
      const next = cur[t];
      if (!isPlainObject(next) && !Array.isArray(next)) cur[t] = {};
      cur = cur[t] as Json;
    } else if (Array.isArray(cur)) {
      // Bound the index to the existing array (append via '-'), exactly like the
      // leaf branch — otherwise a huge index materializes a multi-GB sparse array
      // (and OOMs inside the later JSON.stringify size check).
      const idx = t === "-" ? cur.length : Number(t);
      if (!Number.isInteger(idx) || idx < 0 || idx > cur.length) {
        throw VaultError.of("FieldOutOfScope", `bad array index: ${t}`);
      }
      if (!isPlainObject(cur[idx]) && !Array.isArray(cur[idx])) cur[idx] = {};
      cur = cur[idx] as Json;
    } else {
      throw VaultError.of("FieldOutOfScope", `cannot descend into non-container at '${t}'`);
    }
  }
  const last = tokens[tokens.length - 1]!;
  if (isPlainObject(cur)) {
    cur[last] = value;
  } else if (Array.isArray(cur)) {
    const idx = last === "-" ? cur.length : Number(last);
    if (!Number.isInteger(idx) || idx < 0 || idx > cur.length) {
      throw VaultError.of("FieldOutOfScope", `bad array index: ${last}`);
    }
    cur[idx] = value;
  } else {
    throw VaultError.of("FieldOutOfScope", "cannot set on a non-container");
  }
  return root;
}

/** Return a deep clone of `doc` with the value at `pointer` removed. */
export function pointerRemove(doc: Json, pointer: string): Json {
  const tokens = parsePointer(pointer);
  if (tokens.length === 0) return null;
  const root: Json = structuredClone(doc);
  let cur: Json | undefined = root;
  for (let i = 0; i < tokens.length - 1; i++) {
    const t = tokens[i]!;
    if (isPlainObject(cur)) cur = cur[t];
    else if (Array.isArray(cur)) cur = cur[Number(t)];
    else return root;
    if (cur === undefined) return root;
  }
  const last = tokens[tokens.length - 1]!;
  if (isPlainObject(cur)) {
    delete cur[last];
  } else if (Array.isArray(cur)) {
    const idx = Number(last);
    if (Number.isInteger(idx) && idx >= 0 && idx < cur.length) cur.splice(idx, 1);
  }
  return root;
}

/**
 * True iff the value nests no deeper than `maxDepth` container levels. Short-
 * circuits as soon as the budget is exceeded, so it is safe (bounded recursion)
 * even on adversarially deep input.
 */
export function withinDepth(v: Json, maxDepth: number): boolean {
  if (maxDepth < 0) return false;
  if (Array.isArray(v)) return v.every((x) => withinDepth(x, maxDepth - 1));
  if (isPlainObject(v)) return Object.values(v).every((x) => withinDepth(x as Json, maxDepth - 1));
  return true;
}

export interface PatchOp {
  op: "add" | "replace" | "remove" | "test";
  path: string;
  value?: Json;
}

/** Apply an RFC 6902-style patch (add/replace/remove/test) atomically. */
export function applyPatch(doc: Json, ops: PatchOp[]): Json {
  let cur = doc;
  for (const op of ops) {
    switch (op.op) {
      case "add":
      case "replace":
        cur = pointerSet(cur, op.path, op.value ?? null);
        break;
      case "remove":
        cur = pointerRemove(cur, op.path);
        break;
      case "test": {
        const got = pointerGet(cur, op.path);
        if (JSON.stringify(got) !== JSON.stringify(op.value ?? null)) {
          throw VaultError.of("VersionConflict", `patch test failed at ${op.path}`);
        }
        break;
      }
      default:
        throw VaultError.of("InvalidRequest", `unsupported patch op`);
    }
  }
  return cur;
}
