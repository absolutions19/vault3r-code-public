/**
 * Namespace derivation for the RELAY identity model — the Public Suffix List half.
 *
 * Split out of `namespace.ts` so the suffix list is reachable only from the
 * relay path that needs it. tldts ships CommonJS and declares no
 * `sideEffects: false`, so a bundler cannot tree-shake ~170 KB of trie data out
 * of a module that merely sits beside the code using it — keeping it in a module
 * of its own is the only thing that keeps it out of a browser host's bundle.
 *
 * The public surface of `@vault/crypto-core` is unchanged: the package index
 * re-exports both halves, so every consumer imports from the package as before.
 */

// ---------------------------------------------------------------------------
// TWO IDENTITY MODELS, and they key differently on purpose. This file is the
// RELAY half; the BROWSER half sits beside `deriveOriginNamespace` in
// `namespace.ts`.
//
// RELAY mode: a server proves who it is by serving a `.well-known` identity
// record that declares its own domain. Ownership of a DOMAIN is what was
// proven, so the namespace is the registrable domain (eTLD+1) and a record is
// authoritative for the subdomains beneath it. `normalizeHost`,
// `registrableDomain`, `isAuthoritativeForHost` and `deriveNamespace` below
// serve that model, and they are the only reason the Public Suffix List is
// needed at all.
// ---------------------------------------------------------------------------

import { getDomain, parse as tldParse } from "tldts";
import { NS_PREFIX_WEB, type Namespace, type NamespaceGranularity } from "@vault/protocol";

import { NamespaceError, storageKeyForNamespace, type DerivedNamespace } from "./namespace.js";

/** Normalize a host to a lowercase Punycode A-label; reject IPs and junk. */
export function normalizeHost(input: string): string {
  const raw = input.trim().toLowerCase().replace(/\.+$/, "");
  if (raw.length === 0) throw new NamespaceError("empty host");
  let hostname: string;
  try {
    hostname = new URL(`https://${raw}`).hostname;
  } catch {
    throw new NamespaceError(`invalid host: ${input}`);
  }
  const info = tldParse(hostname);
  // These three are the first thing a developer serving on 127.0.0.1 or bare
  // localhost hits, so each says what to do instead of only what is wrong.
  if (info.isIp) {
    throw new NamespaceError(
      "IP literals are not valid identities — serve on a name instead, e.g. http://app.localhost:9999",
    );
  }
  if (!hostname.includes(".")) {
    throw new NamespaceError(
      `host must be a fully-qualified domain — use a name like app.${hostname} (any *.localhost name resolves to loopback)`,
    );
  }
  if (hostname === "localhost") {
    throw new NamespaceError(
      "localhost is not a valid identity — use a subdomain of it, e.g. http://app.localhost:9999",
    );
  }
  return hostname;
}

/** The registrable domain (eTLD+1) of a host, or null if not derivable. */
export function registrableDomain(host: string): string | null {
  return getDomain(host);
}

/**
 * Whether an identity record's self-declared `domain` is authoritative for a host
 * the vault fetched the record from. True iff the host equals the record domain,
 * or both reduce to the SAME registrable domain (eTLD+1) using the Public Suffix
 * List — so `example.com` is authoritative for `app.example.com`, but
 * `attacker.co.uk` is NOT authoritative for `victim.co.uk` (distinct eTLD+1s,
 * which a naive "last two labels" check would wrongly accept).
 */
export function isAuthoritativeForHost(recordDomain: string, host: string): boolean {
  let normRecord: string;
  let normHost: string;
  try {
    normRecord = normalizeHost(recordDomain);
    normHost = normalizeHost(host);
  } catch {
    return false;
  }
  if (normRecord === normHost) return true;
  const rd = registrableDomain(normRecord);
  const hd = registrableDomain(normHost);
  return rd !== null && rd === hd;
}

/** Derive the namespace for a verified host at the given granularity. */
export function deriveNamespace(host: string, granularity: NamespaceGranularity): DerivedNamespace {
  const canonicalHost = normalizeHost(host);
  let canonicalKey: string;
  if (granularity === "host") {
    canonicalKey = canonicalHost;
  } else {
    const reg = registrableDomain(canonicalHost);
    if (!reg) throw new NamespaceError(`no registrable domain for ${canonicalHost}`);
    canonicalKey = reg;
  }
  const namespace = `${NS_PREFIX_WEB}:${canonicalKey}` as Namespace;
  return { namespace, canonicalKey, storageKey: storageKeyForNamespace(namespace) };
}
