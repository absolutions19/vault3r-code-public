/**
 * The browser-safe surface of `@vault/crypto-core` — everything except the
 * Public Suffix List half of namespace derivation.
 *
 * This is `index.ts` minus `namespace-psl.js`. The omission is the whole point:
 * a host that derives namespaces from attested ORIGINS (`deriveOriginNamespace`)
 * never consults the suffix list, and tldts ships CommonJS without
 * `sideEffects: false`, so a bundler cannot drop ~170 KB of trie data that any
 * reachable module imports. Importing this entry instead of the package root is
 * what keeps it out of such a host's bundle.
 *
 * Nothing here is exclusive to the browser; the name marks the identity model,
 * not the runtime. Relay-side code keeps importing `@vault/crypto-core`, whose
 * surface is unchanged.
 */

export * from "./encoding.js";
export * from "./primitives.js";
export * from "./xchacha.js";
export * from "./handshake.js";
export * from "./session-envelope.js";
export * from "./namespace.js";
export * from "./identity.js";
export * from "./signing.js";
export * from "./value-hash.js";
export * from "./recovery.js";
