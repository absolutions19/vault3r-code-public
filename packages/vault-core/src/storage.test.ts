import { describe, expect, it } from "vitest";
import { InMemoryKeystore, InMemoryStorage } from "./in-memory.js";
import { DocumentStore } from "./document-store.js";
import { pointerGet, pointerSet, pointerRemove, applyPatch } from "./json-pointer.js";
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
});
