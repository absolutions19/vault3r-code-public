/**
 * Namespace derivation for the BROWSER identity model, plus homograph detection.
 *
 * The namespace is derived from an attested origin, never from anything the
 * caller supplies. A separate storage key is the SHA-256 of the namespace
 * string, for on-disk keying.
 *
 * The RELAY model's host-and-suffix-list derivation lives in `namespace-psl.ts`.
 * Nothing in this file consults the Public Suffix List, which is what lets a
 * browser host bundle the vault without ~170 KB of trie data it never reads.
 */

// ---------------------------------------------------------------------------
// TWO IDENTITY MODELS, and they key differently on purpose. This file is the
// BROWSER half; the RELAY half is `namespace-psl.ts`.
//
// BROWSER mode (`deriveOriginNamespace`): the host process reads the caller's
// origin off the sender frame. Nothing was proven about a domain — the browser
// simply knows which origin it loaded — so the namespace IS the origin, the
// same boundary Chromium already enforces for localStorage, IndexedDB and
// service workers. No suffix list, no granularity, no per-scheme exceptions.
// ---------------------------------------------------------------------------

import { NS_PREFIX_WEB, type Namespace } from "@vault/protocol";

import { sha256 } from "./primitives.js";
import { toHex, utf8ToBytes } from "./encoding.js";

export class NamespaceError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "NamespaceError";
  }
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
 * Derive a namespace from an *origin*: the browser path, where the host process
 * supplies the caller's origin authoritatively from the sender frame.
 *
 * **The namespace is the origin — scheme, host and port, verbatim.** One rule
 * for every scheme, and deliberately the same boundary the browser already
 * enforces for localStorage, IndexedDB, cookies and service workers, so a site
 * author needs no vault-specific model of what "a site" means.
 *
 * What that means in practice, and why each is right rather than merely simple:
 *
 * - `http://site.example` and `https://site.example` are TWO partitions. An
 *   `http` origin is network-attackable and is not the same security principal
 *   as its `https` twin; every other storage API agrees.
 * - `site.example` and `app.site.example` are TWO partitions. Sharing across
 *   subdomains is what `/shared` plus consent is for; collapsing them silently
 *   lets a staging subdomain read and write production's document.
 * - `alice.pages.example` and `bob.pages.example` are TWO partitions. Under
 *   eTLD+1 keying every tenant of a shared host collapsed into one, which is a
 *   cross-tenant data leak that no amount of suffix-list tuning can make safe.
 * - A port is part of an origin, so two dev servers on one loopback name differ
 *   without needing a loopback special case — and `http://localhost:8765` and
 *   `http://127.0.0.1:8765` are perfectly good origins. Only the relay's model
 *   needs a provable *name*.
 * - The SCHEME is kept for dweb origins too, so `bzz://name.eth` and
 *   `ipfs://name.eth` are two partitions. Do NOT "fix" this by folding a name
 *   host to its bare name, however tempting the symmetry with a host's own
 *   permission model: a name is reachable through several resolution paths,
 *   under registries with different owners, and folding them makes every one
 *   of those paths an entrance to the same partition. A compromised resolution
 *   path would then reach data written over an honest one. Keeping the scheme
 *   contains it. Carrying data across a transport change is what the shared
 *   subtree plus user consent is for.
 *
 * The input must be an origin — `scheme://host[:port]` — not a full URL: any
 * userinfo, path, query or fragment is rejected so two different display URLs
 * for one site cannot be steered to different (or, worse, to *another* site's)
 * namespace. The scheme must be `http(s)` or a whitelisted dweb scheme.
 *
 * Case folds for the schemes whose authority is definitionally
 * case-insensitive; content- and key-addressed authorities keep their exact
 * case so distinct identifiers never alias.
 */
export function deriveOriginNamespace(origin: string): DerivedNamespace {
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
  if (scheme !== "http" && scheme !== "https" && !DWEB_SCHEMES.has(scheme)) {
    throw new NamespaceError(`unsupported origin scheme: ${scheme}`);
  }
  // An origin needs a real scheme-relative authority (`scheme://authority`);
  // opaque forms with none are ambiguous and rejected. `url.host` carries the
  // port when there is one, and is empty for a scheme's default port — so
  // `http://app.localhost` and `:80` agree, as they should.
  const rawAuthority = url.host;
  if (rawAuthority.length === 0) throw new NamespaceError(`origin has no authority: ${origin}`);
  // The WHATWG URL parser already lowercases a special (http/https) hostname;
  // it preserves case for non-special dweb authorities, so fold only the
  // schemes that are definitionally case-insensitive.
  const authority = CASE_INSENSITIVE_DWEB_SCHEMES.has(scheme) ? rawAuthority.toLowerCase() : rawAuthority;
  const canonicalKey = `${scheme}://${authority}`;
  const namespace = `${NS_PREFIX_WEB}:${canonicalKey}` as Namespace;
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
