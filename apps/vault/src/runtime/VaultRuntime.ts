/**
 * VaultRuntime — assembles the device runtime: the tested VaultEngine + VaultNode
 * wired to the on-device adapters (keystore, storage, identity resolver, consent
 * UI) and the relay transport. Screens talk to this object; it owns no security
 * logic of its own — that all lives in @vault/vault-core.
 */

import { VaultEngine, VaultNode } from "@vault/vault-core";
import { RelayTransport } from "@vault/sdk";
import { RnKeystore } from "./keystore";
import { RnStorage } from "./storage";
import { FetchIdentityResolver } from "./resolver";
import { UiConsentAdapter } from "./consent";

export interface VaultRuntimeOptions {
  relayUrl: string;
  knownDomains?: string[];
}

export class VaultRuntime {
  private constructor(
    readonly engine: VaultEngine,
    readonly node: VaultNode,
    readonly consent: UiConsentAdapter,
    readonly keystore: RnKeystore,
  ) {}

  static async create(opts: VaultRuntimeOptions): Promise<VaultRuntime> {
    const keystore = await RnKeystore.create();
    const consent = new UiConsentAdapter();
    const engine = new VaultEngine({
      keystore,
      storage: new RnStorage(),
      resolver: new FetchIdentityResolver(),
      consent,
      knownDomains: opts.knownDomains ?? [],
    });
    const node = new VaultNode(engine, new RelayTransport(opts.relayUrl));
    return new VaultRuntime(engine, node, consent, keystore);
  }

  /** Scan/handle a pairing URI (from the camera or a Universal Link). */
  async pair(uri: string): Promise<void> {
    if (!this.keystore.isUnlocked()) await this.keystore.unlock({ reason: "unlock", prompt: "Unlock to connect" });
    await this.node.pair(uri);
  }
}
