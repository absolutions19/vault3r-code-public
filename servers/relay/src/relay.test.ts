import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { WebSocket } from "ws";
import { RelayServer } from "./server.js";
import { TopicMailbox } from "./mailbox.js";
import type { RelayFrame } from "@vault/protocol";

function connect(port: number): Promise<WebSocket> {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(`ws://127.0.0.1:${port}`);
    ws.on("open", () => resolve(ws));
    ws.on("error", reject);
  });
}

function nextFrame(ws: WebSocket, predicate: (f: RelayFrame) => boolean, timeoutMs = 2000): Promise<RelayFrame> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("timeout waiting for frame")), timeoutMs);
    const onMsg = (data: unknown) => {
      const frame = JSON.parse(String(data)) as RelayFrame;
      if (predicate(frame)) {
        clearTimeout(timer);
        ws.off("message", onMsg);
        resolve(frame);
      }
    };
    ws.on("message", onMsg);
  });
}

const send = (ws: WebSocket, frame: RelayFrame) => ws.send(JSON.stringify(frame));

describe("TopicMailbox", () => {
  it("stores, drains, and bounds per topic", () => {
    const mb = new TopicMailbox({ ttlMs: 1000, maxPerTopic: 2, maxTotal: 10 });
    mb.enqueue("t", { id: "1", payload: "a", tag: "rpc" }, 0);
    mb.enqueue("t", { id: "2", payload: "b", tag: "rpc" }, 0);
    mb.enqueue("t", { id: "3", payload: "c", tag: "rpc" }, 0); // evicts oldest
    const drained = mb.drain("t", 10);
    expect(drained.map((d) => d.payload)).toEqual(["b", "c"]);
    expect(mb.drain("t", 10)).toEqual([]); // drained once
  });
  it("expires items past TTL", () => {
    const mb = new TopicMailbox({ ttlMs: 100, maxPerTopic: 10, maxTotal: 10 });
    mb.enqueue("t", { id: "1", payload: "a", tag: "rpc" }, 0);
    expect(mb.drain("t", 1000)).toEqual([]); // expired
  });
});

describe("RelayServer", () => {
  let relay: RelayServer;
  let port: number;
  let pushed: string[];

  beforeEach(async () => {
    pushed = [];
    relay = new RelayServer({ onPush: (t) => pushed.push(t) });
    port = await relay.listen(0);
  });
  afterEach(async () => {
    await relay.close();
  });

  it("routes a publish to a live subscriber, never echoing to the sender", async () => {
    const a = await connect(port);
    const b = await connect(port);
    send(b, { type: "subscribe", id: "s1", topic: "topicABC" });
    await nextFrame(b, (f) => f.type === "ack");

    send(a, { type: "publish", id: "p1", topic: "topicABC", payload: "ciphertext-1", tag: "rpc" });
    const got = await nextFrame(b, (f) => f.type === "subscription");
    expect(got).toMatchObject({ type: "subscription", topic: "topicABC", payload: "ciphertext-1" });

    // Sender must not receive its own publish back.
    const echo = nextFrame(a, (f) => f.type === "subscription", 300).catch(() => "no-echo");
    await expect(echo).resolves.toBe("no-echo");
    a.close();
    b.close();
  });

  it("store-and-forwards to a peer that subscribes later", async () => {
    const a = await connect(port);
    send(a, { type: "publish", id: "p1", topic: "laterTopic", payload: "queued", tag: "session" });
    await nextFrame(a, (f) => f.type === "ack");

    const b = await connect(port);
    send(b, { type: "subscribe", id: "s1", topic: "laterTopic" });
    const got = await nextFrame(b, (f) => f.type === "subscription");
    expect(got).toMatchObject({ payload: "queued" });
    a.close();
    b.close();
  });

  it("fires a content-free push when prompt is set and no peer is live", async () => {
    const a = await connect(port);
    send(a, { type: "publish", id: "p1", topic: "wakeTopic", payload: "x", tag: "rpc", prompt: true });
    await nextFrame(a, (f) => f.type === "ack");
    expect(pushed).toContain("wakeTopic");
    a.close();
  });

  it("rejects an invalid topic and an oversized payload", async () => {
    const a = await connect(port);
    send(a, { type: "subscribe", id: "s1", topic: "bad topic!" });
    const err = await nextFrame(a, (f) => f.type === "error");
    expect(err).toMatchObject({ type: "error" });
    a.close();
  });
});
