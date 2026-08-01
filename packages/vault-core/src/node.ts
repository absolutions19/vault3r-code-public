/**
 * VaultNode — the mobile-side transport runtime. It ties a VaultEngine to a
 * Transport: it scans a pairing URI, runs the authenticated handshake (sending
 * its responder key + vault id), derives the session key, and then routes
 * decrypted JSON-RPC requests into the engine and seals the engine's responses
 * and subscription notifications back to the caller.
 *
 * All authorization lives in the engine; the node is pure plumbing.
 */

import {
  Method,
  VaultError,
  makeAad,
  makeSuccess,
  makeFailure,
  makeNotification,
  tagToMsgType,
  parsePairingUri,
  isJsonRpcRequest,
  type JsonRpcRequest,
  type RelayTag,
  type SessionProposeParams,
  type SubscriptionNotification,
  type Transport,
} from "@vault/protocol";
import {
  x25519Generate,
  deriveSessionKey,
  sealEnvelope,
  openEnvelope,
  sha256,
  toHex,
  toBase64Url,
  fromBase64Url,
  type RawKeyPair,
} from "@vault/crypto-core";
import type { VaultEngine } from "./engine.js";

interface PendingSession {
  sessionKey: Uint8Array;
  responderPublicKey: string;
  pairingNonce: string;
}
interface ActiveSession {
  sessionId: string;
  sessionKey: Uint8Array;
  topic: string;
}

function topicFromKey(key: Uint8Array): string {
  return toHex(sha256(key));
}

export class VaultNode {
  private readonly pending = new Map<string, PendingSession>(); // sessionTopic -> pending
  private readonly byTopic = new Map<string, ActiveSession>();
  private readonly byId = new Map<string, ActiveSession>();
  private wired = false;

  constructor(
    private readonly engine: VaultEngine,
    private readonly transport: Transport,
  ) {}

  /** Scan a pairing URI and complete the authenticated handshake. */
  async pair(uri: string): Promise<void> {
    const p = parsePairingUri(uri);
    await this.ensureWired();
    await this.transport.subscribe(p.topic);

    const responder: RawKeyPair = x25519Generate();
    const responderPublicKey = toBase64Url(responder.publicKey);
    const sessionKey = deriveSessionKey(responder.privateKey, fromBase64Url(p.proposerPublicKey), {
      proposerPublicKey: p.proposerPublicKey,
      responderPublicKey,
      protocolVersion: p.version,
      pairingNonce: p.pairingNonce,
    });
    const sessionTopic = topicFromKey(sessionKey);
    this.pending.set(sessionTopic, { sessionKey, responderPublicKey, pairingNonce: p.pairingNonce });
    await this.transport.subscribe(sessionTopic);

    // Send the authenticated handshake (responder key + vault id) over the pairing topic.
    const symKey = fromBase64Url(p.symKey);
    const handshake = sealEnvelope(symKey, makeAad(p.topic, "pair", "handshake", "v2c"), {
      responderPublicKey,
      vaultId: this.engine.vaultId(),
    });
    await this.transport.publish(p.topic, handshake, "pair");
  }

  private async ensureWired(): Promise<void> {
    if (this.wired) return;
    await this.transport.connect();
    this.transport.onMessage((t, payload, tag) => void this.onMessage(t, payload, tag));
    this.engine.setEmitter((sessionId, note) => this.emit(sessionId, note));
    this.wired = true;
  }

  private async onMessage(topic: string, payload: string, tag: RelayTag): Promise<void> {
    const pend = this.pending.get(topic);
    const active = this.byTopic.get(topic);
    const key = active?.sessionKey ?? pend?.sessionKey;
    if (!key) return;

    let body: unknown;
    try {
      body = openEnvelope(key, makeAad(topic, tag, tagToMsgType(tag), "c2v"), payload);
    } catch {
      return; // authentication failure — drop
    }
    if (!isJsonRpcRequest(body as never)) return;
    const req = body as JsonRpcRequest;

    if (req.method === Method.SessionPropose && pend) {
      await this.handleConnect(topic, pend, req);
    } else if (active) {
      const res = await this.engine.handleRequest(active.sessionId, req);
      await this.transport.publish(topic, sealEnvelope(key, makeAad(topic, "rpc", "rpc", "v2c"), res), "rpc");
    }
  }

  private async handleConnect(topic: string, pend: PendingSession, req: JsonRpcRequest): Promise<void> {
    try {
      const settle = await this.engine.connect(req.params as SessionProposeParams, {
        responderPublicKey: pend.responderPublicKey,
        pairingNonce: pend.pairingNonce,
      });
      const active: ActiveSession = { sessionId: settle.sessionId, sessionKey: pend.sessionKey, topic };
      this.byTopic.set(topic, active);
      this.byId.set(settle.sessionId, active);
      this.pending.delete(topic);
      await this.publishOn(topic, pend.sessionKey, makeSuccess(req.id, settle));
    } catch (err) {
      await this.publishOn(topic, pend.sessionKey, makeFailure(req.id, VaultError.fromUnknown(err).toRpcError()));
    }
  }

  private emit(sessionId: string, note: SubscriptionNotification): void {
    const active = this.byId.get(sessionId);
    if (!active) return;
    const payload = sealEnvelope(active.sessionKey, makeAad(active.topic, "sub", "notification", "v2c"), makeNotification(Method.Subscription, note));
    void this.transport.publish(active.topic, payload, "sub");
  }

  private async publishOn(topic: string, key: Uint8Array, body: unknown): Promise<void> {
    await this.transport.publish(topic, sealEnvelope(key, makeAad(topic, "rpc", "rpc", "v2c"), body), "rpc");
  }
}
