/**
 * RelayTransport — a client transport over the relay WebSocket. Uses the global
 * WebSocket in browsers / React Native, and falls back to the `ws` package in
 * Node. Publish/subscribe await the relay ack; incoming `subscription` frames
 * are dispatched to the registered handler.
 */

import type { RelayFrame, RelayTag, Transport, TransportHandler } from "@vault/protocol";
import { VaultError } from "@vault/protocol";

interface WsLike {
  readyState: number;
  send(data: string): void;
  close(): void;
  addEventListener?(type: string, listener: (ev: unknown) => void): void;
  on?(type: string, listener: (arg: unknown) => void): void;
}
interface WsCtor {
  new (url: string): WsLike;
  OPEN: number;
}

async function resolveWebSocket(): Promise<WsCtor> {
  const g = globalThis as { WebSocket?: WsCtor };
  if (typeof g.WebSocket !== "undefined") return g.WebSocket;
  const mod = (await import("ws")) as unknown as { WebSocket: WsCtor; default?: WsCtor };
  return mod.WebSocket ?? (mod.default as WsCtor);
}

let idCounter = 0;
const nextId = () => `t${idCounter++}`;

export class RelayTransport implements Transport {
  private ws?: WsLike;
  private handler?: TransportHandler;
  private readonly pending = new Map<string, { resolve: () => void; reject: (e: Error) => void; timer: ReturnType<typeof setTimeout> }>();

  constructor(
    private readonly url: string,
    private readonly ackTimeoutMs = 10_000,
  ) {}

  async connect(): Promise<void> {
    if (this.isOpen()) return;
    const WS = await resolveWebSocket();
    await new Promise<void>((resolve, reject) => {
      const ws = new WS(this.url);
      this.ws = ws;
      const onOpen = () => resolve();
      const onError = () => reject(new VaultError(4900, "relay connection failed"));
      const onMessage = (data: unknown) => this.onFrame(data);
      const onClose = () => this.failAllPending("relay closed");
      if (ws.on) {
        ws.on("open", onOpen);
        ws.on("error", onError);
        ws.on("message", onMessage);
        ws.on("close", onClose);
      } else if (ws.addEventListener) {
        ws.addEventListener("open", onOpen);
        ws.addEventListener("error", onError);
        ws.addEventListener("message", (ev: unknown) => this.onFrame((ev as { data: unknown }).data));
        ws.addEventListener("close", onClose);
      }
    });
  }

  private onFrame(data: unknown): void {
    let frame: RelayFrame;
    try {
      frame = JSON.parse(typeof data === "string" ? data : String(data)) as RelayFrame;
    } catch {
      return;
    }
    if (frame.type === "ack") {
      this.settle(frame.id, null);
    } else if (frame.type === "error") {
      if (frame.id) this.settle(frame.id, new VaultError(frame.code, frame.message));
    } else if (frame.type === "subscription") {
      this.handler?.(frame.topic, frame.payload, frame.tag);
    }
  }

  private settle(id: string, err: Error | null): void {
    const p = this.pending.get(id);
    if (!p) return;
    clearTimeout(p.timer);
    this.pending.delete(id);
    if (err) p.reject(err);
    else p.resolve();
  }

  private failAllPending(reason: string): void {
    for (const [id, p] of this.pending) {
      clearTimeout(p.timer);
      p.reject(new VaultError(4900, reason));
      this.pending.delete(id);
    }
  }

  private sendAwaitAck(frame: RelayFrame & { id: string }): Promise<void> {
    if (!this.ws || !this.isOpen()) return Promise.reject(new VaultError(4900, "transport not open"));
    return new Promise<void>((resolve, reject) => {
      const timer = setTimeout(() => this.settle(frame.id, new VaultError(4900, "relay ack timeout")), this.ackTimeoutMs);
      this.pending.set(frame.id, { resolve, reject, timer });
      this.ws!.send(JSON.stringify(frame));
    });
  }

  subscribe(topic: string): Promise<void> {
    return this.sendAwaitAck({ type: "subscribe", id: nextId(), topic });
  }
  unsubscribe(topic: string): Promise<void> {
    return this.sendAwaitAck({ type: "unsubscribe", id: nextId(), topic });
  }
  publish(topic: string, payload: string, tag: RelayTag, opts?: { prompt?: boolean }): Promise<void> {
    const frame: Extract<RelayFrame, { type: "publish" }> = { type: "publish", id: nextId(), topic, payload, tag };
    if (opts?.prompt) frame.prompt = true;
    return this.sendAwaitAck(frame);
  }

  onMessage(handler: TransportHandler): void {
    this.handler = handler;
  }

  isOpen(): boolean {
    return !!this.ws && this.ws.readyState === 1; // WebSocket.OPEN === 1
  }

  async close(): Promise<void> {
    this.failAllPending("transport closed");
    this.ws?.close();
    this.ws = undefined as unknown as WsLike;
  }
}
