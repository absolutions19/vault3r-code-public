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
export const MAX_NAMESPACE_BYTES = 64 * 1024; // per-namespace stored document cap
export const MAX_FIELD_PATH_LEN = 512;

/** Cryptographic suite identifiers pinned into signed material and at-rest AAD. */
export const SIG_ALG = "Ed25519" as const;
export const KX_ALG = "X25519" as const;
export const AEAD_ALG = "XChaCha20-Poly1305" as const;
export const KDF_ALG = "HKDF-SHA256" as const;
export const HASH_ALG = "SHA-256" as const;

/** Typed-data domain name for approval structs (EIP-712-shaped). */
export const TYPED_DOMAIN_NAME = "Vault" as const;
