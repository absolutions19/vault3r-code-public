/**
 * VaultClient — the API target apps use. It drives pairing, runs the
 * authenticated handshake, obtains a delegation, opens a session, and exposes
 * get/set/patch/subscribe/disconnect. Every data-plane request is signed with the
 * ephemeral delegated key (d_sess) and sealed to the vault over the relay.
 *
 * The client is untrusted by design: it never chooses a namespace (it claims the
 * one derived from its own domain, which the vault re-derives and enforces), it
 * cannot forge identity (only the domain backend can mint a delegation), and it
 * pins the vault device key from settle to authenticate every response.
 */

import {
  Method,
  PROTOCOL_VERSION,
  VaultError,
  makeAad,
  makeRequest,
  makeDomain,
  tagToMsgType,
  formatPairingUri,
  settleSigningPreimage,
  isJsonRpcFailure,
  isJsonRpcSuccess,
  type AppMetadata,
  type Grant,
  type JsonRpcMessage,
  type JsonRpcRequest,
  type Namespace,
  type NamespaceGranularity,
  type RelayTag,
  type RequestedScope,
  type SessionProposeParams,
  type SessionSettleResult,
  type Transport,
  type TypedData,
  type PrimaryType,
} from "@vault/protocol";
import {
  ed25519Generate,
  x25519Generate,
  deriveSessionKey,
  transcriptHash,
  deriveNamespace,
  hashJsonValue,
  sealEnvelope,
  openEnvelope,
  signTyped,
  ed25519Sign,
  ed25519Verify,
  sha256,
  randomBytes,
  toBase64Url,
  fromBase64Url,
  toHex,
  utf8ToBytes,
  type RawKeyPair,
} from "@vault/crypto-core";
import type { DelegationSigner } from "./delegation.js";
import { RelayTransport } from "./transport.js";

export interface VaultClientConfig {
  /** The app's own domain (used to claim its namespace). */
  domain: string;
  relayUrl: string;
  delegationSigner: DelegationSigner;
  transport?: Transport;
  appMetadata?: AppMetadata;
  namespaceGranularity?: NamespaceGranularity;
  /** Render the pairing URI (QR / Universal Link). */
  onDisplayUri?: (uri: string) => void;
  /** Show the number-matching code the user confirms at the vault. */
  onPairingChallenge?: (code: string) => void;
  requestTimeoutMs?: number;
  clock?: () => number;
}

export interface ConnectResult {
  sessionId: string;
  namespace: Namespace;
  grant: Grant;
}

interface SessionState {
  id: string;
  key: Uint8Array;
  topic: string;
  vaultDeviceKey: string;
  namespace: Namespace;
  vaultId: string;
  grant: Grant;
}

interface HandshakeResponse {
  responderPublicKey: string;
  vaultId: string;
}

function topicFromKey(key: Uint8Array): string {
  return toHex(sha256(key));
}

export class VaultClient {
  private readonly transport: Transport;
  private readonly clock: () => number;
  private readonly requestTimeoutMs: number;
  private readonly granularity: NamespaceGranularity;

  private dsess?: RawKeyPair;
  private proposer?: RawKeyPair;
  private session?: SessionState;

  private readonly keys = new Map<string, Uint8Array>(); // topic -> decrypt key
  private readonly pending = new Map<string, { resolve: (v: unknown) => void; reject: (e: Error) => void; timer: ReturnType<typeof setTimeout> }>();
  private readonly subs = new Map<string, (changes: Record<string, unknown>, version: string) => void>();
  private handshakeResolve?: (h: HandshakeResponse) => void;
  private nonce = 0;
  private idc = 0;

  constructor(private readonly config: VaultClientConfig) {
    this.transport = config.transport ?? new RelayTransport(config.relayUrl);
    this.clock = config.clock ?? Date.now;
    this.requestTimeoutMs = config.requestTimeoutMs ?? 30_000;
    this.granularity = config.namespaceGranularity ?? "registrable-domain";
  }

  get namespace(): Namespace {
    return deriveNamespace(this.config.domain, this.granularity).namespace;
  }

  async connect(scopes: RequestedScope[]): Promise<ConnectResult> {
    this.dsess = ed25519Generate();
    this.proposer = x25519Generate();
    const symKey = randomBytes(32);
    const pairingNonce = toBase64Url(randomBytes(16));
    const pairingChallenge = numberMatchCode();
    const pairingTopic = topicFromKey(symKey);
    this.keys.set(pairingTopic, symKey);

    const uri = formatPairingUri({
      version: PROTOCOL_VERSION,
      topic: pairingTopic,
      symKey: toBase64Url(symKey),
      proposerPublicKey: toBase64Url(this.proposer.publicKey),
      pairingNonce,
      relayUrl: this.config.relayUrl,
      domain: this.config.domain,
      pairingChallenge,
    });

    await this.transport.connect();
    this.transport.onMessage((t, p, tag) => this.onMessage(t, p, tag));
    await this.transport.subscribe(pairingTopic);

    this.config.onDisplayUri?.(uri);
    this.config.onPairingChallenge?.(pairingChallenge);

    // Wait for the vault's authenticated handshake response.
    const handshake = await new Promise<HandshakeResponse>((resolve, reject) => {
      this.handshakeResolve = resolve;
      setTimeout(() => reject(new VaultError(4900, "handshake timeout")), this.requestTimeoutMs);
    });

    const responderPub = fromBase64Url(handshake.responderPublicKey);
    const sessionKey = deriveSessionKey(this.proposer.privateKey, responderPub, {
      proposerPublicKey: toBase64Url(this.proposer.publicKey),
      responderPublicKey: handshake.responderPublicKey,
      protocolVersion: PROTOCOL_VERSION,
      pairingNonce,
    });
    const sessionTopic = topicFromKey(sessionKey);
    this.keys.set(sessionTopic, sessionKey);
    await this.transport.subscribe(sessionTopic);

    // Obtain a delegation, now that we know the vault id. The signChallenge
    // callback lets the backend prove we control d_sess (proof-of-possession)
    // without the private key ever leaving this client.
    const dsessSeed = this.dsess.privateKey;
    const delegation = await this.config.delegationSigner.getDelegation({
      sessionPublicKey: toBase64Url(this.dsess.publicKey),
      scopes,
      pairingChallenge,
      vaultId: handshake.vaultId,
      signChallenge: (challenge: string) => toBase64Url(ed25519Sign(utf8ToBytes(challenge), dsessSeed)),
    });

    // Build and sign the ConnectMessage (binds both ECDH pubkeys + transcript).
    const th = transcriptHash({
      proposerPublicKey: toBase64Url(this.proposer.publicKey),
      responderPublicKey: handshake.responderPublicKey,
      protocolVersion: PROTOCOL_VERSION,
      pairingNonce,
    });
    const connectTyped: TypedData<"VaultConnect"> = {
      primaryType: "VaultConnect",
      domain: makeDomain(handshake.vaultId),
      message: {
        namespace: this.namespace,
        nonce: this.nextNonce(),
        issuedAt: this.clock(),
        expiry: this.clock() + 300_000,
        sessionId: pairingNonce,
        proposerPublicKey: toBase64Url(this.proposer.publicKey),
        responderPublicKey: handshake.responderPublicKey,
        transcriptHash: th,
      },
    };

    const proposeParams: SessionProposeParams = {
      domain: this.config.domain,
      appMetadata: this.config.appMetadata ?? {},
      requestedScopes: scopes,
      delegation,
      proposerPublicKey: toBase64Url(this.proposer.publicKey),
      protocolVersions: [PROTOCOL_VERSION],
      connect: {
        typed: connectTyped,
        identity: { keyId: delegation.keyId, algo: "Ed25519" },
        sig: signTyped(connectTyped, this.dsess.privateKey),
      },
      pairingChallenge,
    };

    const settle = (await this.sendRequest(
      sessionTopic,
      sessionKey,
      makeRequest(this.nextId(), Method.SessionPropose, proposeParams),
    )) as SessionSettleResult;

    // Verify the vault authenticated the settle, then pin its device key.
    const preimage = settleSigningPreimage({
      sessionId: settle.sessionId,
      namespace: settle.granted.namespace,
      grantId: settle.granted.id,
      responderPublicKey: settle.responderPublicKey,
      vaultDeviceKey: settle.vaultDeviceKey,
      expiresAt: settle.expiresAt,
      methods: settle.granted.methods,
    });
    if (!ed25519Verify(preimage, fromBase64Url(settle.vaultSig), fromBase64Url(settle.vaultDeviceKey))) {
      throw new VaultError(4302, "settle not authenticated by the vault device key");
    }

    this.session = {
      id: settle.sessionId,
      key: sessionKey,
      topic: sessionTopic,
      vaultDeviceKey: settle.vaultDeviceKey,
      namespace: settle.granted.namespace,
      vaultId: handshake.vaultId,
      grant: settle.granted,
    };
    return { sessionId: settle.sessionId, namespace: settle.granted.namespace, grant: settle.granted };
  }

  // --------------------------------------------------------------------------
  // Data-plane API
  // --------------------------------------------------------------------------

  async get(paths: string | string[]): Promise<Record<string, unknown>> {
    const s = this.requireSession();
    const list = Array.isArray(paths) ? paths : [paths];
    const signed = this.sign("VaultRead", { paths: list });
    const res = (await this.sendRequest(s.topic, s.key, makeRequest(this.nextId(), Method.GetData, signed))) as {
      values: Record<string, unknown>;
    };
    return res.values;
  }

  async set(path: string, value: unknown, baseVersion?: string): Promise<string> {
    const s = this.requireSession();
    const changes = [{ op: "replace" as const, path, valueHash: hashJsonValue(value as never) }];
    const signed = this.sign("VaultWrite", baseVersion ? { changes, baseVersion } : { changes });
    const res = (await this.sendRequest(
      s.topic,
      s.key,
      makeRequest(this.nextId(), Method.SetData, { ...signed, values: { [path]: value } }),
    )) as { version: string };
    return res.version;
  }

  async patch(ops: { op: "replace" | "add" | "remove"; path: string; value?: unknown }[], baseVersion?: string): Promise<string> {
    const s = this.requireSession();
    const values: Record<string, unknown> = {};
    const changes = ops.map((o) => {
      if (o.op !== "remove") values[o.path] = o.value;
      return o.op === "remove"
        ? { op: o.op, path: o.path }
        : { op: o.op, path: o.path, valueHash: hashJsonValue(o.value as never) };
    });
    const signed = this.sign("VaultPatch", baseVersion ? { changes, baseVersion } : { changes });
    const res = (await this.sendRequest(
      s.topic,
      s.key,
      makeRequest(this.nextId(), Method.PatchData, { ...signed, values }),
    )) as { version: string };
    return res.version;
  }

  async subscribe(paths: string[], cb: (changes: Record<string, unknown>, version: string) => void): Promise<string> {
    const s = this.requireSession();
    const signed = this.sign("VaultRead", { paths });
    const res = (await this.sendRequest(s.topic, s.key, makeRequest(this.nextId(), Method.Subscribe, signed))) as {
      subscriptionId: string;
    };
    this.subs.set(res.subscriptionId, cb);
    return res.subscriptionId;
  }

  async disconnect(): Promise<void> {
    if (this.session) {
      const signed = this.sign("VaultRevoke", {});
      try {
        await this.sendRequest(this.session.topic, this.session.key, makeRequest(this.nextId(), Method.Revoke, signed));
      } catch {
        /* best effort */
      }
    }
    await this.transport.close();
    this.session = undefined;
  }

  // --------------------------------------------------------------------------
  // Internals
  // --------------------------------------------------------------------------

  private requireSession(): SessionState {
    if (!this.session) throw new VaultError(4900, "not connected");
    return this.session;
  }

  private nextNonce(): string {
    return `${this.nonce++}-${toBase64Url(randomBytes(6))}`;
  }
  private nextId(): string {
    return `r${this.idc++}`;
  }

  private sign<P extends PrimaryType>(primaryType: P, extra: Record<string, unknown>) {
    const s = this.requireSession();
    const typed = {
      primaryType,
      domain: makeDomain(s.vaultId),
      message: {
        namespace: s.namespace,
        nonce: this.nextNonce(),
        issuedAt: this.clock(),
        expiry: this.clock() + 200_000,
        sessionId: s.id,
        ...extra,
      },
    } as TypedData<P>;
    return { typed, identity: { keyId: "d_sess", algo: "Ed25519" as const }, sig: signTyped(typed, this.dsess!.privateKey) };
  }

  private sendRequest(topic: string, key: Uint8Array, req: JsonRpcRequest, tag: RelayTag = "rpc"): Promise<unknown> {
    const payload = sealEnvelope(key, makeAad(topic, tag, tagToMsgType(tag), "c2v"), req);
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(req.id);
        reject(new VaultError(4900, `request ${req.method} timed out`));
      }, this.requestTimeoutMs);
      this.pending.set(req.id, { resolve, reject, timer });
      this.transport.publish(topic, payload, tag, { prompt: true }).catch((e) => {
        clearTimeout(timer);
        this.pending.delete(req.id);
        reject(e as Error);
      });
    });
  }

  private onMessage(topic: string, payload: string, tag: RelayTag): void {
    const key = this.keys.get(topic);
    if (!key) return;
    let body: unknown;
    try {
      body = openEnvelope(key, makeAad(topic, tag, tagToMsgType(tag), "v2c"), payload);
    } catch {
      return; // authentication failure — drop silently
    }
    if (tag === "pair") {
      const h = body as HandshakeResponse;
      this.handshakeResolve?.(h);
      this.handshakeResolve = undefined;
      return;
    }
    const msg = body as JsonRpcMessage;
    if (isJsonRpcSuccess(msg) || isJsonRpcFailure(msg)) {
      const p = this.pending.get(msg.id);
      if (!p) return;
      clearTimeout(p.timer);
      this.pending.delete(msg.id);
      if (isJsonRpcFailure(msg)) p.reject(new VaultError(msg.error.code, msg.error.message, msg.error.data));
      else p.resolve(msg.result);
    } else if ("method" in msg && msg.method === Method.Subscription) {
      const note = msg.params as { subscriptionId: string; changes: Record<string, unknown>; version: string };
      this.subs.get(note.subscriptionId)?.(note.changes, note.version);
    }
  }
}

/** 8-digit number-matching code (anti pairing-relay phishing). */
function numberMatchCode(): string {
  const b = randomBytes(4);
  const n = ((b[0]! << 24) | (b[1]! << 16) | (b[2]! << 8) | b[3]!) >>> 0;
  return (n % 100_000_000).toString().padStart(8, "0");
}
