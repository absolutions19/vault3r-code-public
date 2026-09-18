import { describe, expect, it } from "vitest";
import { InMemoryKeystore, InMemoryStorage } from "./in-memory.js";
import { DocumentStore } from "./document-store.js";
import { pointerGet, pointerSet, pointerRemove, applyPatch, withinDepth } from "./json-pointer.js";
import { pointerCovers, fieldAllows } from "./grants.js";
import { isVaultError, ErrorCode } from "@vault/protocol";

describe("json pointer", () => {
  it("gets, sets, removes by RFC6901 pointer", () => {
    let doc: import("./json-pointer.js").Json = {};
    doc = pointerSet(doc, "/a/b", 1);
    expect(pointerGet(doc, "/a/b")).toBe(1);
    doc = pointerSet(doc, "/a/c", 2);
    expect(pointerGet(doc, "/a")).toEqual({ b: 1, c: 2 });
    doc = pointerRemove(doc, "/a/b");
    expect(pointerGet(doc, "/a/b")).toBeUndefined();
  });
  it("escapes ~ and / tokens", () => {
    const doc = pointerSet({}, "/a~1b/c~0d", 9); // key "a/b" then "c~d"
    expect(pointerGet(doc, "/a~1b/c~0d")).toBe(9);
  });

  it("rejects prototype-polluting pointer tokens and never mutates Object.prototype", () => {
    const before = Object.keys(Object.prototype).length;
    for (const p of ["/__proto__/polluted", "/constructor/prototype/x", "/a/__proto__/y", "/prototype"]) {
      expect(() => pointerSet({}, p, "evil"), p).toThrow();
      expect(() => pointerGet({}, p), p).toThrow();
      expect(() => pointerRemove({}, p), p).toThrow();
    }
    // Object.prototype is untouched, and no global pollution occurred.
    expect(({} as Record<string, unknown>)["polluted"]).toBeUndefined();
    expect(({} as Record<string, unknown>)["x"]).toBeUndefined();
    expect(Object.keys(Object.prototype).length).toBe(before);
  });
  it("rejects an intermediate array index past the array end (no sparse-array blowup)", () => {
    let doc: import("./json-pointer.js").Json = {};
    doc = pointerSet(doc, "/arr", []);
    // A huge intermediate index must be refused, not materialize a ~4e9 array.
    expect(() => pointerSet(doc, "/arr/4000000000/x", 1)).toThrow();
    expect(() => pointerSet(doc, "/arr/5/x", 1)).toThrow(); // past end (length 0)
    // Appending in-bounds still works.
    doc = pointerSet(doc, "/arr/0", { a: 1 });
    expect(pointerGet(doc, "/arr/0")).toEqual({ a: 1 });
  });

  it("withinDepth bounds nesting (short-circuits, no deep recursion)", () => {
    const deep = (n: number): import("./json-pointer.js").Json => (n === 0 ? 1 : { x: deep(n - 1) });
    expect(withinDepth(deep(10), 32)).toBe(true);
    expect(withinDepth(deep(40), 32)).toBe(false);
    expect(withinDepth({ a: 1, b: [1, 2] }, 2)).toBe(true);
  });

  it("withinDepth: EXACTLY maxDepth nested EMPTY containers accepted, +1 rejected", () => {
    const arr = (n: number): import("./json-pointer.js").Json => (n === 0 ? ([] as never) : [arr(n - 1)]);
    const obj = (n: number): import("./json-pointer.js").Json => (n === 0 ? ({} as never) : { x: obj(n - 1) });
    // n=8 makes 8 nested containers with an empty container at the bottom.
    expect(withinDepth(arr(7), 8)).toBe(true); // 8 containers
    expect(withinDepth(arr(8), 8)).toBe(false); // 9 containers
    expect(withinDepth(obj(7), 8)).toBe(true);
    expect(withinDepth(obj(8), 8)).toBe(false);
    // A bare value is depth 0 and always fits.
    expect(withinDepth(1, 0)).toBe(true);
    expect(withinDepth([], 0)).toBe(false); // an empty container still consumes a level
  });

  it("applies an RFC6902 patch with a test guard", () => {
    const doc = applyPatch({ n: 1 }, [
      { op: "test", path: "/n", value: 1 },
      { op: "replace", path: "/n", value: 2 },
      { op: "add", path: "/m", value: 3 },
    ]);
    expect(doc).toEqual({ n: 2, m: 3 });
  });
  it("fails a patch whose test guard does not hold", () => {
    try {
      applyPatch({ n: 1 }, [{ op: "test", path: "/n", value: 999 }]);
      throw new Error("should have thrown");
    } catch (e) {
      expect(isVaultError(e) && e.code).toBe(ErrorCode.VersionConflict);
    }
  });
});

describe("grant scope matching (pointer boundaries)", () => {
  it("covers descendants but not sibling prefixes", () => {
    expect(pointerCovers("/profile", "/profile")).toBe(true);
    expect(pointerCovers("/profile", "/profile/email")).toBe(true);
    expect(pointerCovers("/profile", "/profiles")).toBe(false); // not a token-boundary match
    expect(pointerCovers("/profile", "/profileX/y")).toBe(false);
  });
  it("root rule covers everything", () => {
    expect(pointerCovers("", "/anything/here")).toBe(true);
  });
  it("fieldAllows honors read/write bits", () => {
    const fields = [{ path: "/a", read: true, write: false }];
    expect(fieldAllows(fields, "/a/x", "read")).toBe(true);
    expect(fieldAllows(fields, "/a/x", "write")).toBe(false);
  });
});

describe("document store anti-rollback", () => {
  it("seals, loads, and versions per namespace", async () => {
    const ks = new InMemoryKeystore();
    const store = new DocumentStore(ks, new InMemoryStorage());
    await store.save("ns-a", { hello: "world" }, 1);
    const loaded = await store.load("ns-a");
    expect(loaded).toEqual({ doc: { hello: "world" }, version: 1 });
  });

  it("detects deletion of a namespace the manifest still expects", async () => {
    const ks = new InMemoryKeystore();
    const storage = new InMemoryStorage();
    const store = new DocumentStore(ks, storage);
    await store.save("ns-a", { x: 1 }, 1);
    await storage.delete("doc:ns-a"); // attacker deletes the sealed blob
    await expect(store.load("ns-a")).rejects.toMatchObject({ code: ErrorCode.KeyInvalidated });
  });

  it("detects a rolled-back (older) blob", async () => {
    const ks = new InMemoryKeystore();
    const storage = new InMemoryStorage();
    const store = new DocumentStore(ks, storage);
    await store.save("ns-a", { v: "old" }, 1);
    const oldBlob = await storage.get("doc:ns-a");
    await store.save("ns-a", { v: "new" }, 2); // manifest now expects version 2
    await storage.put("doc:ns-a", oldBlob!); // attacker restores the v1 blob
    await expect(store.load("ns-a")).rejects.toMatchObject({ code: ErrorCode.KeyInvalidated });
  });

  it("fails to open a blob sealed under a different keystore (wrong key)", async () => {
    const storage = new InMemoryStorage();
    await new DocumentStore(new InMemoryKeystore(), storage).save("ns-a", { x: 1 }, 1);
    // A fresh keystore has a different master DEK.
    await expect(new DocumentStore(new InMemoryKeystore(), storage).load("ns-a")).rejects.toMatchObject({
      code: ErrorCode.KeyInvalidated,
    });
  });

  describe("naming why a blob failed to authenticate", () => {
    // Wrong key and torn ciphertext fail identically at the AEAD; the owner
    // fingerprint recorded on save is the only thing that tells them apart.

    it("says 'different identity' when a different keystore sealed the store", async () => {
      const storage = new InMemoryStorage();
      await new DocumentStore(new InMemoryKeystore({ vaultId: "vault-A" }), storage).save("ns-a", { x: 1 }, 1);

      const other = new DocumentStore(new InMemoryKeystore({ vaultId: "vault-B" }), storage);
      await expect(other.load("ns-a")).rejects.toMatchObject({
        code: ErrorCode.KeyInvalidated,
        data: { reason: "wrong-identity" },
        message: expect.stringContaining("different identity"),
      });
    });

    it("says 'corrupt' when the right identity cannot open a torn blob", async () => {
      const ks = new InMemoryKeystore({ vaultId: "vault-A" });
      const storage = new InMemoryStorage();
      const store = new DocumentStore(ks, storage);
      await store.save("ns-a", { x: 1 }, 1);
      // Truncate the sealed blob the way an overlapping write used to.
      const blob = (await storage.get("doc:ns-a"))!;
      await storage.put("doc:ns-a", blob.slice(0, blob.length - 8));

      await expect(store.load("ns-a")).rejects.toMatchObject({
        code: ErrorCode.KeyInvalidated,
        data: { reason: "corrupt" },
        message: expect.stringContaining("corrupt"),
      });
    });

    it("falls back to 'unknown' for a store written before fingerprints existed", async () => {
      const ks = new InMemoryKeystore({ vaultId: "vault-A" });
      const storage = new InMemoryStorage();
      const store = new DocumentStore(ks, storage);
      await store.save("ns-a", { x: 1 }, 1);
      await storage.delete("manifest-owner"); // legacy store: no fingerprint
      const blob = (await storage.get("doc:ns-a"))!;
      await storage.put("doc:ns-a", blob.slice(0, blob.length - 8));

      await expect(store.load("ns-a")).rejects.toMatchObject({
        code: ErrorCode.KeyInvalidated,
        data: { reason: "unknown" },
      });
    });

    it("applies to the manifest as well as to namespace blobs", async () => {
      const storage = new InMemoryStorage();
      await new DocumentStore(new InMemoryKeystore({ vaultId: "vault-A" }), storage).save("ns-a", { x: 1 }, 1);

      const other = new DocumentStore(new InMemoryKeystore({ vaultId: "vault-B" }), storage);
      // load() opens the manifest first, so that is what fails here.
      await expect(other.load("ns-a")).rejects.toMatchObject({
        data: { reason: "wrong-identity" },
        message: expect.stringContaining("manifest"),
      });
    });

    it("records the fingerprint once and does not rewrite it on every save", async () => {
      const ks = new InMemoryKeystore({ vaultId: "vault-A" });
      const storage = new InMemoryStorage();
      const puts: string[] = [];
      const origPut = storage.put.bind(storage);
      storage.put = async (k, v) => {
        puts.push(k);
        return origPut(k, v);
      };
      const store = new DocumentStore(ks, storage);
      await store.save("ns-a", { x: 1 }, 1);
      await store.save("ns-a", { x: 2 }, 2);
      await store.save("ns-b", { y: 1 }, 1);

      expect(puts.filter((k) => k === "manifest-owner")).toHaveLength(1);
    });
  });

  it("deleteNamespace leaves the blob alone when the manifest cannot be opened", async () => {
    const ks = new InMemoryKeystore();
    const storage = new InMemoryStorage();
    const store = new DocumentStore(ks, storage);
    await store.save("ns-a", { x: 1 }, 1);
    // A torn or tampered manifest. Deleting the blob first would leave a manifest
    // that still expects it — the bricked state deleteNamespace exists to avoid.
    await storage.put("manifest", new Uint8Array([1, 2, 3, 4]));

    await expect(store.deleteNamespace("ns-a")).rejects.toMatchObject({ code: ErrorCode.KeyInvalidated });
    expect(await storage.get("doc:ns-a")).not.toBeNull();
  });

  it("deleteNamespace still removes blob and manifest entry on the happy path", async () => {
    const ks = new InMemoryKeystore();
    const storage = new InMemoryStorage();
    const store = new DocumentStore(ks, storage);
    await store.save("ns-a", { x: 1 }, 1);

    await store.deleteNamespace("ns-a");

    expect(await storage.get("doc:ns-a")).toBeNull();
    // Absent from the manifest too: a later load is "never existed", not rollback.
    expect(await store.load("ns-a")).toEqual({ doc: {}, version: 0 });
  });
});
