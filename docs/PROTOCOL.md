# VAULT — protocol reference

All types live in [`@vault/protocol`](../packages/protocol/src). This is a
summary; the source is authoritative.

## Layers

```
RelayFrame            (relay routing: publish / subscribe / subscription / ack / error)
  └─ SessionEnvelope  (XChaCha20-Poly1305, AAD = topic·tag·pv·msgType·dir; base64url)
       └─ JSON-RPC 2.0 (vault_* methods; string ids)
            └─ TypedData (EIP-712-shaped; the signed unit)
```

## Pairing URI

```
vault:<topic>@<version>?symKey=<b64u>&proposerPub=<b64u>&pairingNonce=<b64u>&relay=<url>&domain=<host>&challenge=<8-digits>
```

`topic = sha256(symKey)` (hex). The symKey grants pairing-channel confidentiality
only, never identity. The `challenge` is the number-match code shown in the app.

## Handshake

1. SDK generates `symKey`, an X25519 proposer key, `pairingNonce`, and the number-match `challenge`; renders the pairing URI.
2. Vault scans it, generates an X25519 responder key, and sends `{ responderPublicKey, vaultId }` over the pairing topic (sealed with `symKey`, tag `pair`).
3. Both derive `sessionKey = HKDF(ECDH, salt=H(proposerPub‖responderPub), info="vault-session/v1"‖transcriptHash)`; `sessionTopic = sha256(sessionKey)`.
4. SDK obtains a delegation (with proof-of-possession), signs the ConnectMessage (binding both pubkeys + `transcriptHash`), and sends `vault_sessionPropose`.
5. Vault verifies identity, shows consent + biometric, and returns a **device-key-signed** `SessionSettleResult`. The SDK verifies that signature and pins `vaultDeviceKey`.

## Methods

| Method | Params | Result |
|---|---|---|
| `vault_sessionPropose` | `SessionProposeParams` (domain, appMetadata, requestedScopes, delegation, proposerPublicKey, connect, pairingChallenge) | `SessionSettleResult` |
| `vault_getData` | signed `VaultRead` `{ paths[] }` | `{ values, version }` |
| `vault_setData` | signed `VaultWrite` `{ changes[], baseVersion? }` + `values` | `{ applied, version }` |
| `vault_patchData` | signed `VaultPatch` `{ changes[], baseVersion? }` + `values` | `{ applied, version }` |
| `vault_subscribe` / `vault_unsubscribe` | signed `VaultRead` `{ paths[] }` / `{ subscriptionId }` | `{ subscriptionId }` / `{ ok }` |
| `vault_subscription` (notification) | `{ subscriptionId, changes, version }` | — |
| `vault_getPermissions` | `{ sessionId }` | `{ grant }` |
| `vault_revoke` | signed `VaultRevoke` `{}` | `{ ok }` |

Every signed request carries `{ typed, identity, sig }` where `sig` is Ed25519 over
`typedSigningPreimage(typed)` by the delegated session key. Paths are RFC 6901
JSON Pointers, namespace-relative.

## Typed data (the signed unit)

```jsonc
{
  "primaryType": "VaultWrite",
  "domain": { "name": "Vault", "version": "1", "vaultId": "…", "verifyingKeyId": "…" },
  "message": {
    "namespace": "web:example.com",     // tripwire only — the vault uses its derived namespace
    "nonce": "…", "issuedAt": 0, "expiry": 0, "sessionId": "…",
    "changes": [{ "op": "replace", "path": "/profile/name", "valueHash": "sha256:…" }],
    "baseVersion": "etag:7"
  }
}
```

The domain separator (`vaultId` + `version`) binds a signature to one vault and one
protocol revision. `valueHash` binds the signed request to the exact value applied.

## Identity record (`/.well-known/vault-identity.json`)

```jsonc
{
  "schema": "vault-identity/1",
  "domain": "example.com",
  "namespaceGranularity": "registrable-domain",   // or "host" for multi-tenant isolation
  "keys": [{ "kid": "k1", "alg": "Ed25519", "publicKey": "b64u", "created": "…", "status": "active" }],
  "methods": ["vault_getData", "vault_setData", "…"],
  "protocolVersions": ["1"],
  "proof": { "kid": "k1", "sig": "b64u(Ed25519 over canonical(record without proof))" }
}
```

## Delegation

Minted by the app backend after CSRF + Origin + proof-of-possession checks; signed
by the domain key; binds `sessionPublicKey`, clamped `scopes`, `vaultId`,
`pairingChallenge`, and an `assertedAccount` taken from the authenticated session.

## Error codes (EIP-1193 4xxx space)

`4001` user-rejected · `4100` unauthorized · `4200` unsupported-method ·
`4300` namespace-mismatch · `4301` identity-unverified · `4302` bad-signature ·
`4303` nonce-replay · `4304` expired · `4305` field-out-of-scope ·
`4306` write-forbidden · `4310` biometric-failed · `4311` key-invalidated ·
`4312` vault-locked · `4321` version-conflict · `4330` quota-exceeded ·
`4400` protocol-unsupported · `4900` disconnected.
