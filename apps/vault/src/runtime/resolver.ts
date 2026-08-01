/**
 * FetchIdentityResolver — the vault fetches `.well-known/vault-identity.json`
 * ITSELF over TLS. This is the load-bearing step of the anti-spoofing model: the
 * caller never supplies the record. SSRF guards reject non-HTTPS, IP-literal,
 * private/reserved hosts and cross-host redirects, and the body is size-capped.
 */

import type { IdentityResolver } from "@vault/vault-core";
import { normalizeHost, isAuthoritativeForHost, NamespaceError } from "@vault/crypto-core";
import type { VaultIdentityRecord } from "@vault/protocol";

const MAX_RECORD_BYTES = 128 * 1024;

export class FetchIdentityResolver implements IdentityResolver {
  constructor(private readonly fetchImpl: typeof fetch = fetch) {}

  async resolve(domain: string): Promise<VaultIdentityRecord | null> {
    let host: string;
    try {
      host = normalizeHost(domain); // rejects IPs, bare hosts, junk
    } catch (e) {
      if (e instanceof NamespaceError) return null;
      throw e;
    }
    const url = `https://${host}/.well-known/vault-identity.json`;
    try {
      const res = await this.fetchImpl(url, {
        method: "GET",
        redirect: "error", // no cross-host redirects
        headers: { accept: "application/json" },
      });
      if (!res.ok) return null;
      const ct = res.headers.get("content-type") ?? "";
      if (!ct.includes("application/json")) return null;
      const text = await res.text();
      if (text.length > MAX_RECORD_BYTES) return null;
      const record = JSON.parse(text) as VaultIdentityRecord;
      // The record must be authoritative for the host we fetched it from (PSL-aware).
      // The engine's identity-verify pipeline independently re-checks this.
      if (isAuthoritativeForHost(record.domain, host)) return record;
      return null;
    } catch {
      return null;
    }
  }
}
