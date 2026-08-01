/** Session state held by the vault after a connection settles. */

import type { Base64Url, Grant, Namespace, WritePolicy } from "@vault/protocol";

export interface Subscription {
  id: string;
  /** Read-scope paths this subscription watches. */
  paths: string[];
}

export interface Session {
  id: string;
  namespace: Namespace;
  storageKey: string;
  grant: Grant;
  /** The delegated session public key (d_sess) that signs data-plane requests. */
  delegatedKeyPub: Base64Url;
  proposerPublicKey: Base64Url;
  responderPublicKey: Base64Url;
  deviceKeyPub: Base64Url;
  createdAt: number;
  expiresAt: number;
  /** Pinned revocation-status endpoint + key id for data-plane re-checks. */
  statusEndpoint: string | null;
  identityKid: string | null;
  lastRevocationCheckAt: number;
  writePolicy: WritePolicy;
  /** For "ask-once-per-session": set once the user has approved a write. */
  writeApprovedThisSession: boolean;
  subscriptions: Map<string, Subscription>;
  domain: string | null;
  verified: boolean;
}

export class SessionStore {
  private readonly sessions = new Map<string, Session>();

  create(session: Session): void {
    this.sessions.set(session.id, session);
  }
  get(id: string): Session | undefined {
    return this.sessions.get(id);
  }
  delete(id: string): void {
    this.sessions.delete(id);
  }
  all(): Session[] {
    return [...this.sessions.values()];
  }
  /** Sessions addressing a namespace (for cross-session change fan-out). */
  forNamespace(namespace: Namespace): Session[] {
    return this.all().filter((s) => s.namespace === namespace);
  }
}
