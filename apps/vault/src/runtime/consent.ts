/**
 * UiConsentAdapter — bridges the engine's consent request to the React approval
 * screen. The engine calls `requestConnect` and awaits a decision; this adapter
 * pushes the request to a listener (the UI) and resolves the promise when the
 * user approves or rejects. The UI is where the human sees the *verified* domain
 * and grants field-by-field — the last line of defense against phishing.
 */

import type { ConsentAdapter, ConsentDecision, ConsentRequest } from "@vault/vault-core";

export interface PendingConsent {
  request: ConsentRequest;
  resolve: (decision: ConsentDecision) => void;
}

export class UiConsentAdapter implements ConsentAdapter {
  private listener?: (pending: PendingConsent) => void;

  /** The UI registers here to receive connection requests. */
  onRequest(listener: (pending: PendingConsent) => void): void {
    this.listener = listener;
  }

  requestConnect(request: ConsentRequest): Promise<ConsentDecision> {
    return new Promise((resolve) => {
      if (!this.listener) {
        resolve({ approved: false, reason: "no consent UI attached" });
        return;
      }
      this.listener({ request, resolve });
    });
  }
}
