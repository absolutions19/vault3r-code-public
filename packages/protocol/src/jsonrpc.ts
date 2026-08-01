/**
 * JSON-RPC 2.0 framing. This is the innermost layer, carried inside the E2E
 * session envelope. We use string ids only (no null-id notifications for
 * requests) and a strict, minimal validator.
 */

export const JSONRPC_VERSION = "2.0" as const;

export type JsonRpcId = string;

export interface JsonRpcRequest<M extends string = string, P = unknown> {
  jsonrpc: typeof JSONRPC_VERSION;
  id: JsonRpcId;
  method: M;
  params: P;
}

export interface JsonRpcNotification<M extends string = string, P = unknown> {
  jsonrpc: typeof JSONRPC_VERSION;
  method: M;
  params: P;
}

export interface JsonRpcError {
  code: number;
  message: string;
  data?: unknown;
}

export interface JsonRpcSuccess<R = unknown> {
  jsonrpc: typeof JSONRPC_VERSION;
  id: JsonRpcId;
  result: R;
}

export interface JsonRpcFailure {
  jsonrpc: typeof JSONRPC_VERSION;
  id: JsonRpcId;
  error: JsonRpcError;
}

export type JsonRpcResponse<R = unknown> = JsonRpcSuccess<R> | JsonRpcFailure;
export type JsonRpcMessage = JsonRpcRequest | JsonRpcNotification | JsonRpcResponse;

export function makeRequest<M extends string, P>(
  id: JsonRpcId,
  method: M,
  params: P,
): JsonRpcRequest<M, P> {
  return { jsonrpc: JSONRPC_VERSION, id, method, params };
}

export function makeNotification<M extends string, P>(
  method: M,
  params: P,
): JsonRpcNotification<M, P> {
  return { jsonrpc: JSONRPC_VERSION, method, params };
}

export function makeSuccess<R>(id: JsonRpcId, result: R): JsonRpcSuccess<R> {
  return { jsonrpc: JSONRPC_VERSION, id, result };
}

export function makeFailure(id: JsonRpcId, error: JsonRpcError): JsonRpcFailure {
  return { jsonrpc: JSONRPC_VERSION, id, error };
}

export function isJsonRpcRequest(m: JsonRpcMessage): m is JsonRpcRequest {
  return "method" in m && "id" in m;
}

export function isJsonRpcNotification(m: JsonRpcMessage): m is JsonRpcNotification {
  return "method" in m && !("id" in m);
}

export function isJsonRpcSuccess(m: JsonRpcMessage): m is JsonRpcSuccess {
  return "id" in m && "result" in m;
}

export function isJsonRpcFailure(m: JsonRpcMessage): m is JsonRpcFailure {
  return "id" in m && "error" in m;
}
