/**
 * Namespace derivation and homograph detection.
 *
 * The namespace is derived from a verified host, never supplied by the caller.
 * We normalize to a Punycode A-label (via the WHATWG URL parser, ICU-backed),
 * reduce to the registrable domain (or keep the full host for `host`
 * granularity), and produce `web:<canonical>`. A separate storage key is the
 * SHA-256 of that string for on-disk keying.
 */

import { getDomain, parse as tldParse } from "tldts";
import { NS_PREFIX_WEB, type Namespace, type NamespaceGranularity } from "@vault/protocol";
import { sha256 } from "./primitives.js";
import { toHex, utf8ToBytes } from "./encoding.js";

export class NamespaceError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "NamespaceError";
  }
}

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
  if (info.isIp) throw new NamespaceError("IP literals are not valid identities");
  if (!hostname.includes(".")) throw new NamespaceError("host must be a fully-qualified domain");
  if (hostname === "localhost") throw new NamespaceError("localhost is not a valid identity");
  return hostname;
}

/** `localhost` or any `*.localhost` name — reserved for loopback by RFC 6761. */
export function isLoopbackName(hostname: string): boolean {
  const h = hostname.toLowerCase().replace(/\.+$/, "");
  return h === "localhost" || h.endsWith(".localhost");
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

export interface DerivedNamespace {
  namespace: Namespace;
  canonicalKey: string;
  storageKey: string; // hex sha256 of the namespace string
}

/** The on-disk key for a namespace: hex SHA-256 of the namespace string. */
export function storageKeyForNamespace(namespace: string): string {
  return toHex(sha256(utf8ToBytes(namespace)));
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

/**
 * The decentralized-web schemes the trusted host path recognizes. Anything else
 * (`file:`, `data:`, `javascript:`, `blob:`, `about:`, `ws:`, …) is rejected so a
 * non-web origin can never mint a namespace.
 */
export const DWEB_SCHEMES: ReadonlySet<string> = new Set([
  "bzz",
  "ipfs",
  "ipns",
  "hyper",
  "ens",
  "rad",
  "swarm",
  "ar",
]);

/**
 * Dweb schemes whose authority is case-INSENSITIVE — a name (`ens`) or a hex
 * reference (`bzz`/`swarm` Swarm refs, `hyper` keys). Their authority is folded to
 * lowercase so `bzz://DeadBEEF` and `bzz://deadbeef` share one namespace.
 *
 * Every other dweb scheme is treated as case-SENSITIVE and its authority is
 * preserved verbatim, because its identifier alphabet is case-significant:
 * `ipfs`/`ipns` (Base58btc CIDv0, Base36 libp2p keys), `ar` (Base64URL tx ids),
 * `rad` (Base58btc `z…` RIDs). Folding those would collapse distinct identities
 * into one namespace and break origin isolation.
 */
const CASE_INSENSITIVE_DWEB_SCHEMES: ReadonlySet<string> = new Set(["ens", "bzz", "swarm", "hyper"]);

/**
 * Derive a namespace from an *origin*, for the trusted in-process host path
 * (browser Option B) where the caller's origin is supplied authoritatively by
 * the host process rather than proven over the relay.
 *
 * The input must be an origin — `scheme://host[:port]` — not a full URL: any
 * userinfo, path, query, or fragment is rejected so two different display URLs
 * for the same site cannot be steered to different (or, worse, to *another*
 * site's) namespace. The scheme must be `http(s)` or a whitelisted dweb scheme.
 *
 * - `http(s)` origins reduce to the SAME `web:<registrable-domain>` namespace the
 *   relay path derives, so a site's data is identical whether it connects through
 *   the browser or over the network. Only the registrable domain of the host is
 *   used; port and (rejected) path never affect the result.
 * - Dweb origins (`bzz://`, `ipfs://`, `ipns://`, `hyper://`, `ens://`, `rad://`, …)
 *   have no DNS registrable domain, so they key on the full canonical
 *   `<scheme>:<authority>` under a `web:dweb:` prefix. The `dweb:` infix carries a
 *   colon, which an eTLD+1 never can, so a dweb namespace can never collide with an
 *   http(s) one.
 */
export function deriveOriginNamespace(
  origin: string,
  granularity: NamespaceGranularity = "registrable-domain",
): DerivedNamespace {
  if (typeof origin !== "string" || origin.trim().length === 0) {
    throw new NamespaceError("empty origin");
  }
  let url: URL;
  try {
    url = new URL(origin);
  } catch {
    throw new NamespaceError(`invalid origin: ${origin}`);
  }
  // An origin carries no userinfo, query, or fragment — reject anything that does
  // so a crafted URL cannot smuggle non-authoritative components past derivation.
  if (url.username.length > 0 || url.password.length > 0) {
    throw new NamespaceError("origin must not contain userinfo");
  }
  if (url.search.length > 0) throw new NamespaceError("origin must not contain a query");
  if (url.hash.length > 0) throw new NamespaceError("origin must not contain a fragment");
  // Only the root path is permitted (the URL parser normalizes a bare origin to
  // "" or "/"); a real path is rejected.
  if (url.pathname.length > 0 && url.pathname !== "/") {
    throw new NamespaceError("origin must not contain a path");
  }

  const scheme = url.protocol.replace(/:$/, "").toLowerCase();
  if (scheme === "http" || scheme === "https") {
    const derived = deriveNamespace(url.hostname, granularity);
    // RFC 6761 loopback names (`*.localhost`) are development hosts: several
    // servers routinely share one hostname and differ only by port, and two dev
    // servers must not share — and race on — one partition. The port is part of
    // the key for those hosts only; a real origin keeps it out so its namespace
    // stays stable across deployments. `url.port` is empty for a scheme's
    // default port, so `http://app.localhost` and `:80` still agree.
    if (url.port.length > 0 && isLoopbackName(url.hostname)) {
      const canonicalKey = `${derived.canonicalKey}:${url.port}`;
      const namespace = `${NS_PREFIX_WEB}:${canonicalKey}` as Namespace;
      return { namespace, canonicalKey, storageKey: storageKeyForNamespace(namespace) };
    }
    return derived;
  }
  if (!DWEB_SCHEMES.has(scheme)) throw new NamespaceError(`unsupported origin scheme: ${scheme}`);
  // A dweb origin must have a real scheme-relative authority (`scheme://authority`);
  // opaque forms with no authority are ambiguous and rejected. The WHATWG URL
  // parser preserves case for non-special (dweb) authorities, so we only fold the
  // schemes that are definitionally case-insensitive — content-address / key
  // schemes keep their exact case so distinct identifiers never alias.
  const rawAuthority = url.host;
  if (rawAuthority.length === 0) throw new NamespaceError(`dweb origin has no authority: ${origin}`);
  const authority = CASE_INSENSITIVE_DWEB_SCHEMES.has(scheme) ? rawAuthority.toLowerCase() : rawAuthority;
  const canonicalKey = `${scheme}:${authority}`;
  const namespace = `${NS_PREFIX_WEB}:dweb:${canonicalKey}` as Namespace;
  return { namespace, canonicalKey, storageKey: storageKeyForNamespace(namespace) };
}

// ---------------------------------------------------------------------------
// Homograph / confusable detection
// ---------------------------------------------------------------------------

/** A compact confusable fold table covering the most common attack glyphs. */
const CONFUSABLES: Record<string, string> = {
  // Cyrillic -> Latin
  а: "a", е: "e", о: "o", р: "p", с: "c", х: "x", у: "y", і: "i", ѕ: "s", ј: "j", "К": "k", "М": "m",
  // Greek -> Latin
  ο: "o", α: "a", ρ: "p", ν: "v", τ: "t", ι: "i", κ: "k", "Α": "a", "Β": "b", "Ε": "e", "Ο": "o",
  // digit / punctuation look-alikes
  "0": "o", "1": "l", "5": "s", "ʟ": "l", "ɩ": "i", "ⅼ": "l", "ｇ": "g",
};

/** Collapse a string to a skeleton for look-alike comparison. */
export function confusableSkeleton(s: string): string {
  const lowered = s.normalize("NFKC").toLowerCase();
  let out = "";
  for (const ch of lowered) out += CONFUSABLES[ch] ?? ch;
  return out;
}

const SCRIPT_RANGES: { name: string; test: (cp: number) => boolean }[] = [
  { name: "latin", test: (c) => (c >= 0x41 && c <= 0x5a) || (c >= 0x61 && c <= 0x7a) },
  { name: "cyrillic", test: (c) => c >= 0x0400 && c <= 0x04ff },
  { name: "greek", test: (c) => c >= 0x0370 && c <= 0x03ff },
];

/** True if the string mixes Latin with Cyrillic or Greek letters. */
export function isMixedScript(s: string): boolean {
  const scripts = new Set<string>();
  for (const ch of s.normalize("NFC")) {
    const cp = ch.codePointAt(0)!;
    for (const r of SCRIPT_RANGES) if (r.test(cp)) scripts.add(r.name);
  }
  return scripts.has("latin") && (scripts.has("cyrillic") || scripts.has("greek"));
}

export interface HomographResult {
  flag: boolean;
  reason?: string;
}

/**
 * Flag a host if it mixes scripts, is an IDN A-label, or its skeleton collides
 * with a known/previously-approved domain that it is not equal to.
 */
export function detectHomograph(displayHost: string, knownDomains: string[] = []): HomographResult {
  const host = displayHost.toLowerCase();
  if (isMixedScript(host)) return { flag: true, reason: "mixed-script host" };
  if (host.split(".").some((l) => l.startsWith("xn--"))) {
    return { flag: true, reason: "internationalized (punycode) host" };
  }
  const skel = confusableSkeleton(host);
  for (const known of knownDomains) {
    const k = known.toLowerCase();
    if (k !== host && confusableSkeleton(k) === skel) {
      return { flag: true, reason: `look-alike of previously-approved ${known}` };
    }
  }
  return { flag: false };
}
