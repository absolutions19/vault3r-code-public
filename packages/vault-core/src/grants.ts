/**
 * Grant scope logic. A field rule's `path` is a JSON Pointer *prefix*: it covers
 * that path and any descendant, matched on token boundaries so `/profile` never
 * accidentally covers `/profiles`.
 */

import type { FieldRule, RequestedScope } from "@vault/protocol";
import { parsePointer } from "./json-pointer.js";

/** True if `rulePath` (a prefix) covers `path`, on pointer-token boundaries. */
export function pointerCovers(rulePath: string, path: string): boolean {
  const ruleTokens = parsePointer(rulePath);
  const pathTokens = parsePointer(path);
  if (ruleTokens.length > pathTokens.length) return false;
  for (let i = 0; i < ruleTokens.length; i++) {
    if (ruleTokens[i] !== pathTokens[i]) return false;
  }
  return true;
}

export type AccessMode = "read" | "write";

/** Does any granted field rule cover `path` with the requested access bit? */
export function fieldAllows(fields: FieldRule[], path: string, mode: AccessMode): boolean {
  return fields.some((r) => pointerCovers(r.path, path) && (mode === "read" ? r.read : r.write));
}

/** Is `path` covered by a rule marked sensitive (forces per-op biometric)? */
export function pathIsSensitive(fields: FieldRule[], path: string): boolean {
  return fields.some((r) => pointerCovers(r.path, path) && r.sensitive === true);
}

/**
 * Narrow requested scopes to what the identity record permits, then flatten to a
 * single method list + field-rule list. Optional scopes that aren't granted are
 * simply dropped.
 */
export function intersectScopes(
  requested: RequestedScope[],
  allowedMethods: string[],
): { methods: string[]; fields: FieldRule[] } {
  const methodSet = new Set<string>();
  const fields: FieldRule[] = [];
  for (const scope of requested) {
    for (const m of scope.methods) {
      if (allowedMethods.includes(m)) methodSet.add(m);
    }
    for (const f of scope.fields) fields.push(f);
  }
  return { methods: [...methodSet], fields };
}

/** Merge overlapping field rules, OR-ing read/write/sensitive bits per path. */
export function normalizeFields(fields: FieldRule[]): FieldRule[] {
  const byPath = new Map<string, FieldRule>();
  for (const f of fields) {
    const existing = byPath.get(f.path);
    if (existing) {
      existing.read = existing.read || f.read;
      existing.write = existing.write || f.write;
      existing.sensitive = existing.sensitive || f.sensitive;
    } else {
      byPath.set(f.path, { ...f });
    }
  }
  return [...byPath.values()];
}
