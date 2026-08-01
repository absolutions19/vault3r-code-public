/** The transport seam. Both the SDK and the vault runtime talk to a relay
 * through this interface, so either can be swapped (relay WebSocket, in-memory
 * loopback for tests, same-device bridge) without touching the protocol logic. */

import type { RelayTag } from "./envelope.js";

export type TransportHandler = (topic: string, payload: string, tag: RelayTag) => void;

export interface Transport {
  connect(): Promise<void>;
  subscribe(topic: string): Promise<void>;
  unsubscribe(topic: string): Promise<void>;
  publish(topic: string, payload: string, tag: RelayTag, opts?: { prompt?: boolean }): Promise<void>;
  onMessage(handler: TransportHandler): void;
  isOpen(): boolean;
  close(): Promise<void>;
}
