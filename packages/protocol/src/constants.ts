/**
 * Protocol-wide constants. Anything that governs the shape or limits of the
 * wire protocol lives here so both the vault and the SDK read the same values.
 */

/** Semantic protocol version. Bumped on any breaking wire change. */
export const PROTOCOL_VERSION = "1" as const;

/** Namespace prefixes. A namespace is `<prefix>:<identifier>`. */
export const NS_PREFIX_WEB = "web" as const;
/**
 * Unverified callers are quarantined in a structurally separate keyspace and can
 * NEVER address a `web:` namespace. The identifier is a per-install random value,
 * so an unverified caller cannot even name another unverified caller's bucket.
 */
export const NS_PREFIX_UNVERIFIED = "unverified-tofu" as const;
/** Reserved internal namespace for the vault's own metadata. */
export const NS_META = "__vault_meta" as const;

/**
 * The reserved JSON Pointer subtree a site PUBLISHES for cross-origin reads.
 *
 * Location is the mark: there is no separate "shareable" flag, so whatever an
 * owner writes here is what another site can be granted, and nothing outside it
 * can ever be read across the origin boundary. A pointer, so the existing
 * token-boundary prefix rule gives subtree coverage for free — and so
 * `/sharedly` is not `/shared`.
 */
export const SHARED_POINTER = "/shared" as const;

/** Freshness / expiry windows (milliseconds). */
export const REQUEST_MAX_SKEW_MS = 30_000; // clock skew tolerance for issuedAt
export const REQUEST_DEFAULT_TTL_MS = 300_000; // 5 min: a request past this is rejected
export const PAIRING_TTL_MS = 60_000; // 60s single-use pairing secret
export const SESSION_DEFAULT_TTL_MS = 4 * 60 * 60_000; // 4 hours
export const SESSION_ABSOLUTE_MAX_TTL_MS = 7 * 24 * 60 * 60_000; // 7 days hard ceiling
export const DELEGATION_DEFAULT_TTL_MS = 5 * 60_000; // 5 min: short-lived bearer

/** Size caps enforced before any signature or parse work (DoS guards). */
export const MAX_ENVELOPE_BYTES = 256 * 1024; // relay ciphertext frame cap
export const MAX_PLAINTEXT_BYTES = 128 * 1024; // decrypted JSON-RPC message cap
export const MAX_JSON_DEPTH = 32;
export const MAX_PATHS_PER_REQUEST = 64;
export const MAX_PATCH_OPS = 128;
/**
 * Per-namespace stored document cap, on the UTF-8 serialization.
 *
 * Every write is a whole-document read-modify-write — load, decrypt, parse,
 * mutate, serialize, encrypt, save — so this number is also the worst-case
 * cost of a single `setData`, and the worst case a host has to hold in memory
 * per writing site. 16 MiB is room for a real application's own data
 * (documents, a cache, a small media blob as base64) while keeping that cycle
 * well inside a frame's worth of work on a cold partition.
 */
export const MAX_NAMESPACE_BYTES = 16 * 1024 * 1024;
export const MAX_FIELD_PATH_LEN = 512;
/**
 * Caps on a connect's cross-origin read declaration. These bound the consent
 * sheet's length — a user cannot meaningfully approve reads of fifty sites at
 * once — and the number of cross-site edges the host persists per grant.
 */
export const MAX_FOREIGN_ORIGINS = 8;
export const MAX_FOREIGN_PATHS_PER_ORIGIN = 16;

/** Cryptographic suite identifiers pinned into signed material and at-rest AAD. */
export const SIG_ALG = "Ed25519" as const;
export const KX_ALG = "X25519" as const;
export const AEAD_ALG = "XChaCha20-Poly1305" as const;
export const KDF_ALG = "HKDF-SHA256" as const;
export const HASH_ALG = "SHA-256" as const;

/** Typed-data domain name for approval structs (EIP-712-shaped). */
export const TYPED_DOMAIN_NAME = "Vault" as const;
