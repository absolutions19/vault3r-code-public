/**
 * Pairing URI. The SDK generates this and renders it as a QR code / Universal
 * Link. It carries the transport bootstrap secret (symKey) and the proposer's
 * ephemeral public key — but note the symKey only grants *confidentiality* of
 * the pairing channel, never identity. Identity is established separately via
 * the domain-signed delegation, so a shoulder-surfed URI cannot impersonate the
 * site, and the number-matching challenge defeats passive relay of the URI.
 */

import { PROTOCOL_VERSION } from "./constants.js";

export interface PairingParams {
  version: string;
  topic: string;
  symKey: string; // base64url
  proposerPublicKey: string; // base64url X25519
  pairingNonce: string; // base64url
  relayUrl: string;
  domain: string;
  /** Human number-matching code shown in the browser and typed at the vault. */
  pairingChallenge: string;
}

export function formatPairingUri(p: PairingParams): string {
  const q = new URLSearchParams({
    symKey: p.symKey,
    proposerPub: p.proposerPublicKey,
    pairingNonce: p.pairingNonce,
    relay: p.relayUrl,
    domain: p.domain,
    challenge: p.pairingChallenge,
  });
  return `vault:${p.topic}@${p.version}?${q.toString()}`;
}

export function parsePairingUri(uri: string): PairingParams {
  const url = new URL(uri);
  if (url.protocol !== "vault:") throw new Error("not a vault: pairing URI");
  const [topic, version] = url.pathname.split("@");
  if (!topic || !version) throw new Error("malformed pairing URI path");
  const q = url.searchParams;
  const req = (k: string): string => {
    const v = q.get(k);
    if (v === null) throw new Error(`pairing URI missing ${k}`);
    return v;
  };
  return {
    version,
    topic,
    symKey: req("symKey"),
    proposerPublicKey: req("proposerPub"),
    pairingNonce: req("pairingNonce"),
    relayUrl: req("relay"),
    domain: req("domain"),
    pairingChallenge: req("challenge"),
  };
}

export function currentPairingVersion(): string {
  return PROTOCOL_VERSION;
}
