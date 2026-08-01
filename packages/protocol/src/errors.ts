/**
 * Error registry. Codes live in the EIP-1193 provider space (4xxx) and never
 * collide with the JSON-RPC reserved range (-32768..-32000), so an SDK can tell
 * a transport/parse error apart from an authorization decision.
 */

export const ErrorCode = {
  /** User explicitly rejected the request at the vault. */
  UserRejected: 4001,
  /** No grant, or the grant does not cover this operation. */
  Unauthorized: 4100,
  /** Method not supported by this vault / not in the identity record. */
  UnsupportedMethod: 4200,
  /** The caller's derived namespace does not match the addressed namespace. */
  NamespaceMismatch: 4300,
  /** Identity could not be verified (well-known fetch / proof / signature). */
  IdentityUnverified: 4301,
  /** A request or delegation signature failed to verify. */
  BadSignature: 4302,
  /** Nonce already seen within the freshness window (replay). */
  NonceReplay: 4303,
  /** issuedAt/expiry outside the accepted window. */
  Expired: 4304,
  /** A path is outside the granted field scope. */
  FieldOutOfScope: 4305,
  /** Write attempted on a read-only field. */
  WriteForbidden: 4306,
  /** Biometric authentication failed or was cancelled. */
  BiometricFailed: 4310,
  /** Hardware key was invalidated (e.g. biometric re-enrollment). */
  KeyInvalidated: 4311,
  /** Vault is locked; unlock required before this operation. */
  VaultLocked: 4312,
  /** Optimistic-concurrency conflict: baseVersion is stale. */
  VersionConflict: 4321,
  /** A size/rate quota was exceeded. */
  QuotaExceeded: 4330,
  /** Protocol version not supported by the peer. */
  ProtocolUnsupported: 4400,
  /** Session/transport is not connected. */
  Disconnected: 4900,
  /** Malformed request that failed strict validation. */
  InvalidRequest: 4010,
} as const;

export type ErrorCodeName = keyof typeof ErrorCode;
export type ErrorCodeValue = (typeof ErrorCode)[ErrorCodeName];

const CODE_TO_NAME = new Map<number, ErrorCodeName>(
  (Object.entries(ErrorCode) as [ErrorCodeName, number][]).map(([k, v]) => [v, k]),
);

const DEFAULT_MESSAGE: Record<ErrorCodeName, string> = {
  UserRejected: "The user rejected the request.",
  Unauthorized: "The application is not authorized for this operation.",
  UnsupportedMethod: "The requested method is not supported.",
  NamespaceMismatch: "The addressed namespace does not match the verified caller identity.",
  IdentityUnverified: "The caller identity could not be cryptographically verified.",
  BadSignature: "A required signature failed to verify.",
  NonceReplay: "The request nonce has already been used (possible replay).",
  Expired: "The request timestamp is outside the accepted freshness window.",
  FieldOutOfScope: "A requested field path is outside the granted scope.",
  WriteForbidden: "Write access was not granted for this field path.",
  BiometricFailed: "Biometric authentication failed or was cancelled.",
  KeyInvalidated: "The device key was invalidated and must be re-provisioned.",
  VaultLocked: "The vault is locked.",
  VersionConflict: "The write conflicts with a newer version (stale baseVersion).",
  QuotaExceeded: "A size or rate limit was exceeded.",
  ProtocolUnsupported: "The protocol version is not supported.",
  Disconnected: "The session is not connected.",
  InvalidRequest: "The request failed strict validation.",
};

export interface VaultErrorJson {
  code: number;
  name: string;
  message: string;
  data?: unknown;
}

/**
 * The single error type carried across the wire and thrown internally. Never
 * leaks stack traces or secrets across the boundary — only { code, name,
 * message, data } is serialized.
 */
export class VaultError extends Error {
  readonly code: number;
  readonly codeName: string;
  readonly data?: unknown;

  constructor(code: ErrorCodeValue | number, message?: string, data?: unknown) {
    const name = CODE_TO_NAME.get(code);
    super(message ?? (name ? DEFAULT_MESSAGE[name] : `Vault error ${code}`));
    this.name = "VaultError";
    this.code = code;
    this.codeName = name ?? "Unknown";
    if (data !== undefined) this.data = data;
  }

  static of(name: ErrorCodeName, message?: string, data?: unknown): VaultError {
    return new VaultError(ErrorCode[name], message ?? DEFAULT_MESSAGE[name], data);
  }

  toJSON(): VaultErrorJson {
    const out: VaultErrorJson = { code: this.code, name: this.codeName, message: this.message };
    if (this.data !== undefined) out.data = this.data;
    return out;
  }

  /** JSON-RPC `error` member. */
  toRpcError(): { code: number; message: string; data?: unknown } {
    const out: { code: number; message: string; data?: unknown } = {
      code: this.code,
      message: this.message,
    };
    if (this.data !== undefined) out.data = this.data;
    return out;
  }

  static fromUnknown(err: unknown): VaultError {
    if (err instanceof VaultError) return err;
    if (err instanceof Error) return new VaultError(ErrorCode.InvalidRequest, err.message);
    return new VaultError(ErrorCode.InvalidRequest, String(err));
  }
}

export function isVaultError(x: unknown): x is VaultError {
  return x instanceof VaultError;
}
