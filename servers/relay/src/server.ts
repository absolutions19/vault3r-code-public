/**
 * Zero-knowledge relay. Routes opaque ciphertext frames between peers by topic.
 * The relay can see topics, message classes (tag), sizes, and timing — never
 * plaintext, session keys, or domains. It store-and-forwards to an offline peer
 * via a bounded TTL mailbox and can fire a content-free push-to-wake.
 */

import { WebSocketServer, WebSocket, type RawData } from "ws";
import { MAX_ENVELOPE_BYTES, parseJsonStrict, type RelayFrame } from "@vault/protocol";
import { TopicMailbox } from "./mailbox.js";

export interface RelayServerOptions {
  maxPayloadBytes?: number;
  mailboxTtlMs?: number;
  maxMailboxPerTopic?: number;
  maxMailboxTotal?: number;
  /** Fired when a publish requests a content-free wake for a topic. */
  onPush?: (topic: string) => void;
  /** Max publishes per socket per rolling second (anti-abuse). */
  maxPublishPerSecond?: number;
}

interface SocketState {
  topics: Set<string>;
  windowStart: number;
  publishCount: number;
}

export class RelayServer {
  private wss?: WebSocketServer;
  private readonly subscribers = new Map<string, Set<WebSocket>>();
  private readonly state = new WeakMap<WebSocket, SocketState>();
  private readonly mailbox: TopicMailbox;
  private readonly maxPayload: number;
  private readonly maxPublishPerSecond: number;
  private readonly onPush: ((topic: string) => void) | undefined;
  private pruneTimer?: NodeJS.Timeout;
  private clock: () => number;

  constructor(opts: RelayServerOptions = {}, clock: () => number = () => Date.now()) {
    this.maxPayload = opts.maxPayloadBytes ?? MAX_ENVELOPE_BYTES;
    this.maxPublishPerSecond = opts.maxPublishPerSecond ?? 200;
    this.onPush = opts.onPush;
    this.clock = clock;
    this.mailbox = new TopicMailbox({
      ttlMs: opts.mailboxTtlMs ?? 5 * 60_000,
      maxPerTopic: opts.maxMailboxPerTopic ?? 200,
      maxTotal: opts.maxMailboxTotal ?? 100_000,
    });
  }

  listen(port = 0, host = "127.0.0.1"): Promise<number> {
    return new Promise((resolve, reject) => {
      this.wss = new WebSocketServer({ port, host, maxPayload: this.maxPayload });
      this.wss.on("connection", (ws) => this.onConnection(ws));
      this.wss.on("error", reject);
      this.wss.on("listening", () => {
        const addr = this.wss!.address();
        const actual = typeof addr === "object" && addr ? addr.port : port;
        this.pruneTimer = setInterval(() => this.mailbox.prune(this.clock()), 30_000);
        this.pruneTimer.unref?.();
        resolve(actual);
      });
    });
  }

  private onConnection(ws: WebSocket): void {
    this.state.set(ws, { topics: new Set(), windowStart: this.clock(), publishCount: 0 });
    ws.on("message", (data) => this.onMessage(ws, data));
    ws.on("close", () => this.cleanup(ws));
    ws.on("error", () => this.cleanup(ws));
  }

  private onMessage(ws: WebSocket, data: RawData): void {
    let frame: RelayFrame;
    try {
      const text = typeof data === "string" ? data : data.toString("utf8");
      if (text.length > this.maxPayload) return this.sendError(ws, undefined, 4330, "frame too large");
      frame = parseJsonStrict(text, { maxDepth: 8 }) as RelayFrame;
    } catch {
      return this.sendError(ws, undefined, 4010, "invalid frame");
    }

    switch (frame.type) {
      case "subscribe":
        return this.handleSubscribe(ws, frame.topic, frame.id);
      case "unsubscribe":
        return this.handleUnsubscribe(ws, frame.topic, frame.id);
      case "publish":
        return this.handlePublish(ws, frame);
      default:
        return this.sendError(ws, undefined, 4010, "unsupported frame type");
    }
  }

  private handleSubscribe(ws: WebSocket, topic: string, id: string): void {
    if (!isValidTopic(topic)) return this.sendError(ws, id, 4010, "invalid topic");
    let set = this.subscribers.get(topic);
    if (!set) {
      set = new Set();
      this.subscribers.set(topic, set);
    }
    set.add(ws);
    this.state.get(ws)?.topics.add(topic);
    this.send(ws, { type: "ack", id });
    // Drain any store-and-forwarded messages for this topic.
    for (const item of this.mailbox.drain(topic, this.clock())) {
      this.send(ws, { type: "subscription", topic, payload: item.payload, tag: item.tag as never });
    }
  }

  private handleUnsubscribe(ws: WebSocket, topic: string, id: string): void {
    this.subscribers.get(topic)?.delete(ws);
    this.state.get(ws)?.topics.delete(topic);
    this.send(ws, { type: "ack", id });
  }

  private handlePublish(ws: WebSocket, frame: Extract<RelayFrame, { type: "publish" }>): void {
    if (!isValidTopic(frame.topic)) return this.sendError(ws, frame.id, 4010, "invalid topic");
    if (frame.payload.length > this.maxPayload) return this.sendError(ws, frame.id, 4330, "payload too large");

    const st = this.state.get(ws);
    if (st) {
      const now = this.clock();
      if (now - st.windowStart >= 1000) {
        st.windowStart = now;
        st.publishCount = 0;
      }
      if (++st.publishCount > this.maxPublishPerSecond) {
        return this.sendError(ws, frame.id, 4330, "publish rate exceeded");
      }
    }

    const set = this.subscribers.get(frame.topic);
    const liveTargets = set ? [...set].filter((s) => s !== ws && s.readyState === WebSocket.OPEN) : [];

    if (liveTargets.length > 0) {
      for (const target of liveTargets) {
        this.send(target, { type: "subscription", topic: frame.topic, payload: frame.payload, tag: frame.tag });
      }
    } else {
      // No live peer: store-and-forward until it (re)subscribes or the TTL lapses.
      this.mailbox.enqueue(frame.topic, { id: frame.id, payload: frame.payload, tag: frame.tag }, this.clock());
    }

    if (frame.prompt) this.onPush?.(frame.topic);
    this.send(ws, { type: "ack", id: frame.id });
  }

  private cleanup(ws: WebSocket): void {
    const st = this.state.get(ws);
    if (st) for (const topic of st.topics) this.subscribers.get(topic)?.delete(ws);
    this.state.delete(ws);
  }

  private send(ws: WebSocket, frame: RelayFrame): void {
    if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(frame));
  }

  private sendError(ws: WebSocket, id: string | undefined, code: number, message: string): void {
    this.send(ws, id === undefined ? { type: "error", code, message } : { type: "error", id, code, message });
  }

  stats(): { topics: number; mailbox: number } {
    return { topics: this.subscribers.size, mailbox: this.mailbox.size() };
  }

  close(): Promise<void> {
    return new Promise((resolve) => {
      if (this.pruneTimer) clearInterval(this.pruneTimer);
      if (!this.wss) return resolve();
      for (const client of this.wss.clients) client.terminate();
      this.wss.close(() => resolve());
    });
  }
}

/** Topics are opaque hex/base64url-ish identifiers; reject anything wild. */
function isValidTopic(topic: string): boolean {
  return typeof topic === "string" && topic.length > 0 && topic.length <= 128 && /^[A-Za-z0-9_-]+$/.test(topic);
}
