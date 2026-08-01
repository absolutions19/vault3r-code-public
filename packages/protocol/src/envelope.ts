/**
 * Two framing layers above JSON-RPC:
 *
 *  1. RelayFrame — what a client and the relay exchange. The relay routes by
 *     `topic` and never sees plaintext; the `payload` is an opaque base64url
 *     ciphertext blob.
 *
 *  2. SessionEnvelope — the encrypted-payload shape (pre-encryption / post-
 *     decryption view). The AEAD associated data binds topic, tag, protocol
 *     version, message type and direction so a ciphertext cannot be replayed on
 *     another topic or reflected back in the wrong direction.
 */

import type { Base64Url } from "./types.js";

/** Relay control + data frames (JSON over the relay WebSocket). */
export type RelayFrame =
  | RelayPublish
  | RelaySubscribe
  | RelayUnsubscribe
  | RelaySubscription
  | RelayAck
  | RelayError;

export interface RelayPublish {
  type: "publish";
  id: string;
  topic: string;
  /** Opaque ciphertext. */
  payload: Base64Url;
  /** Coarse message class for the relay (never reveals content). */
  tag: RelayTag;
  /** Ask the relay to emit a content-free push-to-wake for this topic. */
  prompt?: boolean;
  /** Mailbox time-to-live hint (ms), clamped by the relay. */
  ttlMs?: number;
}

export interface RelaySubscribe {
  type: "subscribe";
  id: string;
  topic: string;
}

export interface RelayUnsubscribe {
  type: "unsubscribe";
  id: string;
  topic: string;
}

export interface RelaySubscription {
  type: "subscription";
  topic: string;
  payload: Base64Url;
  tag: RelayTag;
}

export interface RelayAck {
  type: "ack";
  id: string;
}

export interface RelayError {
  type: "error";
  id?: string;
  code: number;
  message: string;
}

/** Coarse, content-free message classes visible to the relay. */
export type RelayTag = "pair" | "session" | "rpc" | "sub" | "ping";

/** Direction bound into AEAD associated data. */
export type Direction = "c2v" | "v2c"; // caller->vault, vault->caller

/** Envelope message-type used in AEAD associated data. */
export type EnvelopeMsgType = "handshake" | "rpc" | "notification" | "ack";

/** Fields folded into AEAD associated data (order fixed by canonical encoder). */
export interface EnvelopeAad {
  topic: string;
  tag: RelayTag;
  pv: string; // protocol version
  msgType: EnvelopeMsgType;
  dir: Direction;
}

/** The decrypted view of a session payload. */
export interface SessionEnvelope {
  msgType: EnvelopeMsgType;
  /** JSON-RPC message (request/response/notification) as the body. */
  body: unknown;
}
