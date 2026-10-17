/**
 * Cross-origin reads of a published subtree.
 *
 * One site may read another's data, but only what the owner wrote under
 * `SHARED_POINTER`, and only after the user approved that reader→owner pair.
 * Two properties carry the whole feature and most of this file tests them:
 *
 *  - A reader's own field rules confer NOTHING across the boundary. A grant on
 *    the empty pointer covers every path in the reader's own document; it must
 *    not reach one byte of anyone else's.
 *  - Absence is UNIFORM. A site never visited, an owner with nothing published,
 *    an owner the user declined, and a pointer outside the subtree all answer
 *    `null`. Any difference is an existence oracle over browsing history.
 */

import { describe, expect, it } from "vitest";
import { storageKeyForNamespace } from "@vault/crypto-core";
import {
  Method,
  MAX_FOREIGN_ORIGINS,
  MAX_FOREIGN_PATHS_PER_ORIGIN,
  MAX_PATHS_PER_REQUEST,
  SHARED_POINTER,
  type RequestedScope,
} from "@vault/protocol";
import { VaultEngine } from "./engine.js";
import { AutoConsent, InMemoryKeystore, InMemoryStorage, StaticIdentityResolver } from "./in-memory.js";

const FIXED_NOW = 1_760_000_000_000;
const clock = { now: () => FIXED_NOW };

const OWNER = "https://owner.example";
const READER = "https://reader.example";

/** Approve everything asked for, foreign reads included. */
const approveAll = () =>
  new AutoConsent((req) => ({ approved: true, grantedForeignReads: req.foreignReads }));

function newEngine(consent = approveAll()) {
  return new VaultEngine({
    keystore: new InMemoryKeystore({ vaultId: "vault-local" }),
    storage: new InMemoryStorage(),
    resolver: new StaticIdentityResolver(),
    consent,
    clock,
  });
}

/** The owner's scopes: it may write its own tree AND publish. */
function ownerScopes(): RequestedScope[] {
  return [
    {
      methods: [Method.GetData, Method.SetData],
      fields: [
        { path: "/profile", read: true, write: true },
        { path: SHARED_POINTER, read: true, write: true },
      ],
    },
  ];
}

/** The reader's scopes, declaring cross-origin reads on `owner`. */
function readerScopes(paths: string[], origin = OWNER): RequestedScope[] {
  return [
    {
      methods: [Method.GetData, Method.SetData, Method.GetSharedData],
      fields: [{ path: "/own", read: true, write: true }],
      foreign: [{ origin, paths }],
    },
  ];
}

async function expectCode(p: Promise<unknown>, codeName: string): Promise<void> {
  const err = await p.then(
    () => {
      throw new Error(`expected rejection with ${codeName}, but it resolved`);
    },
    (e) => e as { codeName?: string },
  );
  expect(err.codeName).toBe(codeName);
}

/** An engine where the owner has published `values`, plus a connected reader. */
async function withPublished(
  values: Record<string, unknown>,
  readerPaths: string[] = [SHARED_POINTER],
  consent = approveAll(),
) {
  const engine = newEngine(consent);
  const owner = await engine.connectLocal({ origin: OWNER, appMetadata: {}, requestedScopes: ownerScopes() });
  if (Object.keys(values).length > 0) {
    await engine.localSet(owner.sessionId, values as Parameters<typeof engine.localSet>[1]);
  }
  const reader = await engine.connectLocal({
    origin: READER,
    appMetadata: {},
    requestedScopes: readerScopes(readerPaths),
  });
  return { engine, owner, reader };
}

describe("cross-origin published reads", () => {
  describe("the happy paths", () => {
    it("reads a named pointer the owner published", async () => {
      const { engine, reader } = await withPublished(
        { "/shared/displayName": "ada" },
        ["/shared/displayName"],
      );

      const res = await engine.localGetShared(reader.sessionId, OWNER, ["/shared/displayName"]);
      expect(res.values["/shared/displayName"]).toBe("ada");
    });

    it("reads any leaf under a wholesale grant, and nulls one never written", async () => {
      const { engine, reader } = await withPublished({ "/shared/displayName": "ada" });

      const res = await engine.localGetShared(reader.sessionId, OWNER, [
        "/shared/displayName",
        "/shared/never",
      ]);
      expect(res.values).toEqual({ "/shared/displayName": "ada", "/shared/never": null });
    });

    it("collapses a declaration that names the subtree and a leaf", async () => {
      const { reader } = await withPublished({ "/shared/displayName": "ada" }, [
        SHARED_POINTER,
        "/shared/displayName",
      ]);
      expect(reader.grant.foreignReads).toEqual([
        { namespace: expect.any(String), origin: OWNER, paths: [SHARED_POINTER] },
      ]);
    });

    it("returns values and nothing else — no version to poll the owner with", async () => {
      const { engine, reader } = await withPublished({ "/shared/displayName": "ada" });

      const res = await engine.localGetShared(reader.sessionId, OWNER, ["/shared/displayName"]);
      expect(Object.keys(res)).toEqual(["values"]);
    });
  });

  describe("a reader's own grant confers nothing across the boundary", () => {
    it("gives a whole-document read grant no cross-origin access at all", async () => {
      const engine = newEngine(approveAll());
      const owner = await engine.connectLocal({ origin: OWNER, appMetadata: {}, requestedScopes: ownerScopes() });
      await engine.localSet(owner.sessionId, { "/shared/displayName": "ada" });

      // The lazy scope: read and write on the empty pointer, which covers every
      // path in the reader's OWN document — and declares no foreign read.
      const reader = await engine.connectLocal({
        origin: READER,
        appMetadata: {},
        requestedScopes: [
          {
            methods: [Method.GetData, Method.SetData, Method.GetSharedData],
            fields: [{ path: "", read: true, write: true }],
          },
        ],
      });

      const res = await engine.localGetShared(reader.sessionId, OWNER, ["/shared/displayName"]);
      expect(res.values["/shared/displayName"]).toBe(null);
      expect(reader.grant.foreignReads).toEqual([]);
    });

    it("cannot reach outside the published subtree even when approved", async () => {
      const engine = newEngine(approveAll());
      const owner = await engine.connectLocal({ origin: OWNER, appMetadata: {}, requestedScopes: ownerScopes() });
      await engine.localSet(owner.sessionId, { "/profile/secret": "private" });
      const reader = await engine.connectLocal({
        origin: READER,
        appMetadata: {},
        requestedScopes: readerScopes([SHARED_POINTER]),
      });

      const res = await engine.localGetShared(reader.sessionId, OWNER, ["/profile/secret"]);
      expect(res.values["/profile/secret"]).toBe(null);
    });

    it("does not treat /publicity as published", async () => {
      const engine = newEngine(approveAll());
      const owner = await engine.connectLocal({ origin: OWNER, appMetadata: {}, requestedScopes: ownerScopes() });
      // The owner can only write this if it holds a rule covering it; give it one.
      const owner2 = await engine.connectLocal({
        origin: OWNER,
        appMetadata: {},
        requestedScopes: [
          { methods: [Method.SetData], fields: [{ path: "/sharedly", read: true, write: true }] },
        ],
      });
      await engine.localSet(owner2.sessionId, { "/sharedly/x": "nope" });
      expect(owner.namespace).toBe(owner2.namespace);

      const reader = await engine.connectLocal({
        origin: READER,
        appMetadata: {},
        requestedScopes: readerScopes([SHARED_POINTER]),
      });
      const res = await engine.localGetShared(reader.sessionId, OWNER, ["/sharedly/x"]);
      expect(res.values["/sharedly/x"]).toBe(null);
    });
  });

  describe("absence is uniform (no existence oracle)", () => {
    it("answers identically for an unapproved owner and a site never visited", async () => {
      const { engine, reader } = await withPublished({ "/shared/displayName": "ada" });

      const unapproved = await engine.localGetShared(reader.sessionId, "https://other.example", [
        "/shared/displayName",
      ]);
      const neverSeen = await engine.localGetShared(reader.sessionId, "https://nobody.example", [
        "/shared/displayName",
      ]);

      // Asserted as an equality between the two results, not two separate shape
      // checks: the property is that they cannot be told apart.
      expect(unapproved).toEqual(neverSeen);
      expect(unapproved).toEqual({ values: { "/shared/displayName": null } });
    });

    it("answers identically for an approved owner that published nothing", async () => {
      const { engine, reader } = await withPublished({});

      const empty = await engine.localGetShared(reader.sessionId, OWNER, ["/shared/displayName"]);
      const neverSeen = await engine.localGetShared(reader.sessionId, "https://nobody.example", [
        "/shared/displayName",
      ]);
      expect(empty).toEqual(neverSeen);
    });

    it("does not reject a path outside the subtree at read time", async () => {
      const { engine, reader } = await withPublished({ "/shared/displayName": "ada" });

      // connect throws for the same path (see below); a read must not, or the
      // throw distinguishes "unapproved" from "nothing there".
      await expect(
        engine.localGetShared(reader.sessionId, OWNER, ["/profile/secret"]),
      ).resolves.toEqual({ values: { "/profile/secret": null } });
    });

    it("survives the owner's partition being deleted, without a distinct error", async () => {
      const { engine, owner, reader } = await withPublished({ "/shared/displayName": "ada" });

      await engine.adminDeletePartition(storageKeyForNamespace(owner.namespace));

      const res = await engine.localGetShared(reader.sessionId, OWNER, ["/shared/displayName"]);
      // Specifically NOT KeyInvalidated: deleteNamespace clears the manifest
      // entry, so a missing blob reads as "never existed" rather than rollback.
      expect(res).toEqual({ values: { "/shared/displayName": null } });
    });
  });

  describe("the declaration is validated at connect", () => {
    it("refuses a declared path outside the published subtree", async () => {
      const engine = newEngine(approveAll());
      await expectCode(
        engine.connectLocal({
          origin: READER,
          appMetadata: {},
          requestedScopes: readerScopes(["/profile"]),
        }),
        "FieldOutOfScope",
      );
    });

    it("refuses a whole-document declaration", async () => {
      const engine = newEngine(approveAll());
      await expectCode(
        engine.connectLocal({ origin: READER, appMetadata: {}, requestedScopes: readerScopes([""]) }),
        "FieldOutOfScope",
      );
    });

    it.each([
      ["a bare namespace", "web:owner.example"],
      ["a URL with a path", "https://owner.example/x"],
      ["userinfo", "https://user:pw@owner.example"],
      ["a query", "https://owner.example?q=1"],
      ["a fragment", "https://owner.example#f"],
      ["a file URL", "file:///etc/passwd"],
      ["a javascript URL", "javascript:1"],
      ["a raw storage key", storageKeyForNamespace("web:owner.example")],
      ["empty", ""],
    ])("refuses %s as an owner name", async (_label, origin) => {
      const engine = newEngine(approveAll());
      await expectCode(
        engine.connectLocal({
          origin: READER,
          appMetadata: {},
          requestedScopes: readerScopes([SHARED_POINTER], origin),
        }),
        "InvalidRequest",
      );
    });

    it("drops a reader naming itself", async () => {
      const engine = newEngine(approveAll());
      const reader = await engine.connectLocal({
        origin: READER,
        appMetadata: {},
        requestedScopes: readerScopes([SHARED_POINTER], READER),
      });
      expect(reader.grant.foreignReads).toEqual([]);
    });

    it("caps the number of owners named", async () => {
      const engine = newEngine(approveAll());
      const foreign = Array.from({ length: MAX_FOREIGN_ORIGINS + 1 }, (_, i) => ({
        origin: `https://owner${i}.example`,
        paths: [SHARED_POINTER],
      }));
      await expectCode(
        engine.connectLocal({
          origin: READER,
          appMetadata: {},
          requestedScopes: [{ methods: [Method.GetSharedData], fields: [], foreign }],
        }),
        "QuotaExceeded",
      );
    });

    it("caps the paths named for one owner", async () => {
      const engine = newEngine(approveAll());
      const paths = Array.from({ length: MAX_FOREIGN_PATHS_PER_ORIGIN + 1 }, (_, i) => `/shared/p${i}`);
      await expectCode(
        engine.connectLocal({ origin: READER, appMetadata: {}, requestedScopes: readerScopes(paths) }),
        "QuotaExceeded",
      );
    });
  });

  describe("consent decides, and the engine clamps what it decides", () => {
    it("grants nothing when the consent adapter says nothing (fail closed)", async () => {
      // AutoConsent's default: approved, with no grantedForeignReads at all.
      const { engine, reader } = await withPublished(
        { "/shared/displayName": "ada" },
        [SHARED_POINTER],
        new AutoConsent(),
      );
      expect(reader.grant.foreignReads).toEqual([]);

      const res = await engine.localGetShared(reader.sessionId, OWNER, ["/shared/displayName"]);
      expect(res.values["/shared/displayName"]).toBe(null);
    });

    it("honours a narrowed decision", async () => {
      const narrow = new AutoConsent(() => ({ approved: true, grantedForeignReads: [] }));
      const { engine, reader } = await withPublished({ "/shared/displayName": "ada" }, [SHARED_POINTER], narrow);

      expect(reader.grant.foreignReads).toEqual([]);
      const res = await engine.localGetShared(reader.sessionId, OWNER, ["/shared/displayName"]);
      expect(res.values["/shared/displayName"]).toBe(null);
    });

    it("drops an owner the consent UI invents", async () => {
      const inventive = new AutoConsent((req) => ({
        approved: true,
        grantedForeignReads: [
          ...(req.foreignReads ?? []),
          { namespace: "web:elsewhere.example", origin: "https://elsewhere.example", paths: [SHARED_POINTER] },
        ],
      }));
      const { reader } = await withPublished({}, [SHARED_POINTER], inventive);

      expect(reader.grant.foreignReads.map((e) => e.origin)).toEqual([OWNER]);
    });

    it("drops a path the consent UI widens beyond what was requested", async () => {
      const widening = new AutoConsent((req) => ({
        approved: true,
        grantedForeignReads: (req.foreignReads ?? []).map((e) => ({ ...e, paths: [SHARED_POINTER] })),
      }));
      const { engine, reader } = await withPublished(
        { "/shared/a": "A", "/shared/b": "B" },
        ["/shared/a"],
        widening,
      );

      // Requested only /public/a, so the widened /public is not covered by it.
      expect(reader.grant.foreignReads).toEqual([]);
      const res = await engine.localGetShared(reader.sessionId, OWNER, ["/shared/b"]);
      expect(res.values["/shared/b"]).toBe(null);
    });
  });

  describe("gating", () => {
    it("refuses the method before parsing anything the caller passed", async () => {
      const engine = newEngine(approveAll());
      const reader = await engine.connectLocal({
        origin: READER,
        appMetadata: {},
        // GetSharedData deliberately absent.
        requestedScopes: [{ methods: [Method.GetData], fields: [{ path: "/own", read: true, write: true }] }],
      });

      // Unauthorized, not InvalidRequest: the method gate runs before the
      // origin is resolved, so a reader without the grant learns nothing about
      // whether its garbage origin was even parseable.
      await expectCode(
        engine.localGetShared(reader.sessionId, "not a url", ["/shared/x"]),
        "Unauthorized",
      );
    });

    it("caps paths per request independently of the stored grant", async () => {
      const { engine, reader } = await withPublished({ "/shared/displayName": "ada" });
      const many = Array.from({ length: MAX_PATHS_PER_REQUEST + 1 }, (_, i) => `/shared/p${i}`);

      await expectCode(engine.localGetShared(reader.sessionId, OWNER, many), "QuotaExceeded");
    });

    it("allows a wholesale grant to serve many leaf reads in one call", async () => {
      const { engine, reader } = await withPublished({ "/shared/a": "A" });
      const many = Array.from({ length: MAX_PATHS_PER_REQUEST }, (_, i) => `/shared/p${i}`);

      await expect(engine.localGetShared(reader.sessionId, OWNER, many)).resolves.toBeTruthy();
    });

    it("refuses a locked vault", async () => {
      const keystore = new InMemoryKeystore({ vaultId: "vault-local" });
      const engine = new VaultEngine({
        keystore,
        storage: new InMemoryStorage(),
        resolver: new StaticIdentityResolver(),
        consent: approveAll(),
        clock,
      });
      const owner = await engine.connectLocal({ origin: OWNER, appMetadata: {}, requestedScopes: ownerScopes() });
      await engine.localSet(owner.sessionId, { "/shared/displayName": "ada" });
      const reader = await engine.connectLocal({
        origin: READER,
        appMetadata: {},
        requestedScopes: readerScopes([SHARED_POINTER]),
      });

      keystore.lock();
      await expectCode(engine.localGetShared(reader.sessionId, OWNER, ["/shared/displayName"]), "VaultLocked");
    });

    it("ends with the reader's session", async () => {
      const { engine, reader } = await withPublished({ "/shared/displayName": "ada" });

      await engine.adminRevoke(reader.sessionId);
      await expectCode(
        engine.localGetShared(reader.sessionId, OWNER, ["/shared/displayName"]),
        "Disconnected",
      );
    });
  });

  describe("publishing is explicit", () => {
    it("refuses a write under the subtree from a whole-document grant", async () => {
      const engine = newEngine(approveAll());
      const owner = await engine.connectLocal({
        origin: OWNER,
        appMetadata: {},
        requestedScopes: [
          { methods: [Method.SetData], fields: [{ path: "", read: true, write: true }] },
        ],
      });

      // fieldAllows says yes to this; publishAllows is what refuses it.
      await expectCode(
        engine.localSet(owner.sessionId, { "/shared/x": "leak" }),
        "WriteForbidden",
      );
      // The same grant still writes everywhere else.
      await expect(
        engine.localSet(owner.sessionId, { "/profile/x": "fine" }),
      ).resolves.toBeTruthy();
    });

    it("allows a write from an explicit subtree grant", async () => {
      const engine = newEngine(approveAll());
      const owner = await engine.connectLocal({ origin: OWNER, appMetadata: {}, requestedScopes: ownerScopes() });

      await expect(
        engine.localSet(owner.sessionId, { "/shared/x": "published" }),
      ).resolves.toBeTruthy();
    });
  });
});
