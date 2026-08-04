/**
 * Core domain types shared across the vault and the SDK. These describe the
 * *meaning* of the protocol; wire framing lives in jsonrpc.ts / envelope.ts.
 */

import type { NS_PREFIX_WEB, NS_PREFIX_UNVERIFIED } from "./constants.js";

/** base64url-encoded bytes (no padding). */
export type Base64Url = string;

/** A namespace string: `web:<host>` or `unverified-tofu:<random>`. */
export type Namespace = `${typeof NS_PREFIX_WEB}:${string}` | `${typeof NS_PREFIX_UNVERIFIED}:${string}`;

/** How a domain's namespace is scoped. */
export type NamespaceGranularity = "registrable-domain" | "host";

export type IdentityKeyStatus = "active" | "retired" | "revoked";

/** A published signing key in the identity record. */
export interface IdentityKey {
  kid: string;
  alg: "Ed25519";
  /** base64url of the 32-byte Ed25519 public key. */
  publicKey: Base64Url;
  created: string; // ISO 8601
  expires?: string; // ISO 8601
  status: IdentityKeyStatus;
}

/**
 * The `.well-known/vault-identity.json` document. The vault fetches this itself
 * over TLS; the caller never supplies it.
 */
export interface VaultIdentityRecord {
  schema: "vault-identity/1";
  domain: string; // the registrable domain or host this record is authoritative for
  namespaceGranularity: NamespaceGranularity;
  keys: IdentityKey[];
  statusEndpoint?: string;
  methods: string[]; // methods this app is permitted to call
  protocolVersions: string[];
  proof: {
    kid: string;
    /** base64url Ed25519 signature over canonicalBytes(record without `proof`). */
    sig: Base64Url;
  };
}

/** A single field-scope rule. `path` is a JSON Pointer prefix (RFC 6901). */
export interface FieldRule {
  path: string;
  read: boolean;
  write: boolean;
  /** Sensitive fields force per-operation biometric even for reads. */
  sensitive?: boolean;
}

/** Write-confirmation policy for a grant. */
export type WritePolicy = "ask-every" | "ask-once-per-session" | "auto";

/** A requested permission scope (mirrors WalletConnect namespaces). */
export interface RequestedScope {
  /** Methods the app wants to call within its namespace. */
  methods: string[];
  /** Field rules the app requests. */
  fields: FieldRule[];
  /** Optional scopes may be declined without failing the connection. */
  optional?: boolean;
}

/**
 * A settled permission grant, stored by the vault. Note there is no
 * caller-supplied namespace here — the vault derives it from verified identity.
 */
export interface Grant {
  id: string;
  namespace: Namespace;
  /** Verified domain (for `web:` namespaces) or `null` when unverified. */
  domain: string | null;
  /** Attested app display metadata (always shown as "claimed", never trusted). */
  appMetadata: AppMetadata;
  verified: boolean;
  methods: string[];
  fields: FieldRule[];
  writePolicy: WritePolicy;
  createdAt: number; // epoch ms
  expiresAt: number; // epoch ms
  /** The pinned identity key id that this grant authenticates against. */
  identityKid: string | null;
}

/** Untrusted, caller-supplied display metadata. Always rendered as "claimed". */
export interface AppMetadata {
  name?: string;
  description?: string;
  /**
   * A `data:` URI carrying the app's icon IN-BAND (png/jpeg/webp, no SVG).
   * Delivered at connect time so the vault never makes a network request to
   * display a site — which would leak "these are the sites I hold data for" to
   * the network on every render, and would not work for dweb origins at all.
   * The host MUST validate + re-encode this before storing it; see
   * `examples/freedom-browser-integration/main/data-vault-icon.js`.
   */
  icon?: string;
  /** Legacy display hint. The vault NEVER fetches this — see `icon`. */
  iconUrl?: string;
  url?: string;
}

/**
 * A SessionDelegation: the target app's backend delegates per-request signing to
 * an ephemeral, non-extractable browser key. Bound to a vault-issued challenge
 * and the pairing so it is not a free-floating bearer token.
 */
export interface SessionDelegation {
  domain: string;
  /** base64url X-or-Ed public key the delegation authorizes (the browser d_sess). */
  sessionPublicKey: Base64Url;
  scopes: RequestedScope[];
  /** Binds the delegation to a specific vault instance. */
  vaultId?: string;
  /** Binds the delegation to a specific pairing / challenge (anti-relay). */
  pairingChallenge?: string;
  /** The account/username the delegation asserts (shown to the user). */
  assertedAccount?: string;
  issuedAt: number;
  expiresAt: number;
  nonce: string;
  /** Which identity key signed this delegation. */
  keyId: string;
  /** base64url Ed25519 signature by the domain key over the delegation body. */
  sig: Base64Url;
}

/** Trust tier the vault UI shows on the approval sheet. */
export type TrustTier = "verified" | "look-alike" | "unverified" | "threat";

/** Result of the identity verification pipeline. */
export interface IdentityVerification {
  ok: boolean;
  tier: TrustTier;
  namespace: Namespace;
  domain: string | null;
  granularity: NamespaceGranularity | null;
  /** The pinned key id used, if verified. */
  identityKid: string | null;
  /** Set when a confusable / homograph condition is detected. */
  homographFlag: boolean;
  /** Methods the identity record permits (intersect with requested). */
  allowedMethods: string[];
  /** Reason code when `ok` is false. */
  reason?: string;
}
