/**
 * The browser-safe surface of `@vault/vault-core` — the engine without the
 * relay identity model.
 *
 * This is `index.ts` minus `identity-verify.js`, `fetch-resolver.js` and
 * `node.js`: the proposal-verification pipeline, the `.well-known` resolver and
 * the relay transport runtime. All three are the RELAY model, all three need
 * host-and-suffix-list derivation, and a browser host serves none of them — it
 * reads the caller's origin off its own sender frame (`connectLocal`).
 *
 * `VaultEngine` is exported here and is the same class either way: it takes the
 * verification pipeline as an injected `verifier` adapter rather than importing
 * it, so a host that omits one simply cannot serve `connect` (and fails closed
 * there). That injection is what makes this narrower entry possible at all.
 */

export * from "./adapters.js";
export * from "./in-memory.js";
export * from "./json-pointer.js";
export * from "./grants.js";
export * from "./replay.js";
export * from "./document-store.js";
export * from "./session.js";
export * from "./engine.js";
