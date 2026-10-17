/**
 * Grant scope logic. A field rule's `path` is a JSON Pointer *prefix*: it covers
 * that path and any descendant, matched on token boundaries so `/profile` never
 * accidentally covers `/profiles`.
 */

import type { FieldRule, RequestedScope } from "@vault/protocol";
import { SHARED_POINTER } from "@vault/protocol";
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

/** Is `path` the shared subtree or inside it? `/sharedly` is not. */
export function isUnderShared(path: string): boolean {
  return pointerCovers(SHARED_POINTER, path);
}

/**
 * Does ONE approved cross-origin read cover `path`?
 *
 * Deliberately not `fieldAllows`, and deliberately not even the same SHAPE. A
 * `FieldRule[]` says what a reader may touch in ITS OWN document, where a rule
 * on the empty pointer — covering everything — is a normal ask. Authorising a
 * cross-origin read with `fieldAllows(session.grant.fields, …)` would hand every
 * site holding such a rule a read on every other site's published subtree. This
 * takes a single entry already keyed by owner namespace, so a `FieldRule[]`
 * cannot be passed here and `entry.paths` cannot be passed to `fieldAllows`.
 * That incompatibility is the only part of the guarantee that survives into the
 * browser, which runs the bundle with no typecheck.
 *
 * `SHARED_POINTER` is re-asserted here even though connect already clamped what
 * was stored: the host keeps grants in a file encrypted with the OS keychain but
 * NOT sealed under the vault key, so its contents are modifiable by anything
 * running as the user and must be re-clamped at the point of use. Without the
 * `isUnderShared(p)` arm one hand-edited `""` entry reopens the whole document.
 */
export function foreignReadAllows(entry: { paths: string[] }, path: string): boolean {
  if (!isUnderShared(path)) return false;
  // Fail closed on a malformed entry rather than throwing. The entry is read
  // back from the host's grant file, which is not sealed under the vault key, and
  // in the browser this code runs from a bundle with no typecheck — so "not the
  // shape I expected" has to mean "nothing approved". A throw here would also be
  // observably different from an empty answer, which is the oracle the uniform
  // empty result exists to avoid.
  if (!Array.isArray(entry?.paths)) return false;
  return entry.paths.some((p) => typeof p === "string" && isUnderShared(p) && pointerCovers(p, path));
}

/**
 * May this grant WRITE to `path` under the published subtree?
 *
 * Publishing is explicit. A rule on the empty pointer covers `/shared` the same
 * way it covers everything else, so without this a site granted the whole
 * document could publish without the word "public" ever appearing on the sheet
 * the user approved — and under "location is the mark" that is the entire
 * consent for making data readable by others. So publishing needs a rule rooted
 * at or below `/shared`: a whole-document grant carries every other right but
 * not this one.
 */
export function publishAllows(fields: FieldRule[], path: string): boolean {
  return fields.some((r) => r.write && isUnderShared(r.path) && pointerCovers(r.path, path));
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
