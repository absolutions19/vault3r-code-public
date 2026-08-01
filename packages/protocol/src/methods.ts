/**
 * The JSON-RPC method catalog: every method name plus its params and result
 * types. Data-plane methods carry a signed typed struct; the vault verifies the
 * signature, derives the namespace, and enforces the grant before acting.
 */

import type {
  AppMetadata,
  Base64Url,
  FieldRule,
  Grant,
  RequestedScope,
  SessionDelegation,
} from "./types.js";
import type { PatchMessage, PrimaryType, ReadMessage, RevokeMessage, TypedData, WriteMessage } from "./typed-data.js";

export const Method = {
  SessionPropose: "vault_sessionPropose",
  SessionSettle: "vault_sessionSettle",
  SessionExtend: "vault_sessionExtend",
  SessionDelete: "vault_sessionDelete",
  SessionPing: "vault_sessionPing",
  GetData: "vault_getData",
  SetData: "vault_setData",
  PatchData: "vault_patchData",
  Subscribe: "vault_subscribe",
  Unsubscribe: "vault_unsubscribe",
  Subscription: "vault_subscription",
  GetPermissions: "vault_getPermissions",
  RequestPermissions: "vault_requestPermissions",
  Revoke: "vault_revoke",
  PermissionsChanged: "vault_permissionsChanged",
} as const;

export type MethodName = (typeof Method)[keyof typeof Method];

/** Wrapper for a signed data-plane request. */
export interface SignedRequest<P extends PrimaryType> {
  typed: TypedData<P>;
  identity: { keyId: string; algo: "Ed25519" };
  /** base64url signature by the delegated session key over typedSigningPreimage(typed). */
  sig: Base64Url;
}

/** vault_sessionPropose params — the connection request. */
export interface SessionProposeParams {
  /** The domain the caller claims; the vault verifies it independently. */
  domain: string;
  appMetadata: AppMetadata;
  requestedScopes: RequestedScope[];
  /** The delegation issued by the app's backend to the browser session key. */
  delegation: SessionDelegation;
  /** ECDH/session public key of the caller (bound into the ConnectMessage). */
  proposerPublicKey: Base64Url;
  protocolVersions: string[];
  /** Signed ConnectMessage proving control of the delegated key + handshake binding. */
  connect: SignedRequest<"VaultConnect">;
  /** Number-matching code the user must confirm (anti pairing-relay phishing). */
  pairingChallenge: string;
}

/** vault_sessionSettle result — returned by the vault after approval. */
export interface SessionSettleResult {
  sessionId: string;
  /** Scopes actually granted (may be narrower than requested). */
  granted: Grant;
  responderPublicKey: Base64Url;
  /** The vault's device public key; the SDK pins this and verifies responses. */
  vaultDeviceKey: Base64Url;
  expiresAt: number;
  /** base64url signature by the vault device key over the settle body. */
  vaultSig: Base64Url;
}

export interface GetDataParams extends SignedRequest<"VaultRead"> {}
export interface GetDataResult {
  values: Record<string, unknown>;
  version: string;
}

export interface SetDataParams extends SignedRequest<"VaultWrite"> {
  /** The actual values, keyed by path; vault re-hashes and compares to valueHash. */
  values: Record<string, unknown>;
}
export interface SetDataResult {
  applied: true;
  version: string;
}

export interface PatchDataParams extends SignedRequest<"VaultPatch"> {
  values: Record<string, unknown>;
}
export interface PatchDataResult {
  applied: true;
  version: string;
}

export interface SubscribeParams extends SignedRequest<"VaultRead"> {}
export interface SubscribeResult {
  subscriptionId: string;
}

export interface UnsubscribeParams {
  subscriptionId: string;
}
export interface UnsubscribeResult {
  ok: true;
}

export interface SubscriptionNotification {
  subscriptionId: string;
  /** Changed paths and their new values (scope re-checked on every emit). */
  changes: Record<string, unknown>;
  version: string;
}

export interface GetPermissionsParams {
  sessionId: string;
}
export interface GetPermissionsResult {
  grant: Grant | null;
}

export interface RequestPermissionsParams {
  sessionId: string;
  scopes: RequestedScope[];
  connect: SignedRequest<"VaultConnect">;
}
export interface RequestPermissionsResult {
  grant: Grant;
}

export interface RevokeParams extends SignedRequest<"VaultRevoke"> {}
export interface RevokeResult {
  ok: true;
}

export interface ExtendParams extends SignedRequest<"VaultExtend"> {}
export interface ExtendResult {
  expiresAt: number;
  /** True when the session has reached its absolute cap and cannot extend further. */
  atAbsoluteCap: boolean;
}

/** Notification the vault pushes when a grant is narrowed/revoked mid-session. */
export interface PermissionsChangedNotification {
  sessionId: string;
  fields: FieldRule[];
  /** Subscription ids torn down because they are no longer in scope. */
  revokedSubscriptions: string[];
}

// Re-export message aliases so the vault engine can name them succinctly.
export type { ReadMessage, WriteMessage, PatchMessage, RevokeMessage, FieldRule };
