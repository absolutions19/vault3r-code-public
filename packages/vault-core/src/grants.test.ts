/**
 * Grant-scope units. These four functions decide, between them, what a site may
 * touch in its own document and what it may read in someone else's — so the
 * boundaries below (token-wise matching, and which pointer covers `/public`) are
 * the whole of the cross-origin rule.
 */

import { describe, expect, it } from "vitest";
import { PUBLIC_POINTER } from "@vault/protocol";
import type { FieldRule } from "@vault/protocol";
import { fieldAllows, foreignReadAllows, isUnderPublic, pointerCovers, publishAllows } from "./grants.js";

describe("pointerCovers", () => {
  it("covers a descendant but not a sibling with a shared prefix", () => {
    expect(pointerCovers("/profile", "/profile/name")).toBe(true);
    expect(pointerCovers("/profile", "/profiles")).toBe(false);
  });

  it("treats the EMPTY pointer, not '/', as the whole document", () => {
    // This is the distinction the publish gate turns on: `""` parses to zero
    // tokens and covers everything, while `"/"` is one empty-string token and
    // covers only the key named "".
    expect(pointerCovers("", "/anything/deep")).toBe(true);
    expect(pointerCovers("/", "/anything")).toBe(false);
    expect(pointerCovers("/", "/")).toBe(true);
  });
});

describe("isUnderPublic", () => {
  it("accepts the subtree root and its descendants", () => {
    expect(isUnderPublic(PUBLIC_POINTER)).toBe(true);
    expect(isUnderPublic("/public/profile/displayName")).toBe(true);
  });

  it("rejects a name that merely starts with the same letters", () => {
    expect(isUnderPublic("/publicity")).toBe(false);
    expect(isUnderPublic("/publ")).toBe(false);
  });

  it("rejects anything outside the subtree, including whole-document pointers", () => {
    expect(isUnderPublic("/profile")).toBe(false);
    expect(isUnderPublic("")).toBe(false);
    expect(isUnderPublic("/")).toBe(false);
  });
});

describe("foreignReadAllows", () => {
  it("covers a leaf under a wholesale grant", () => {
    const entry = { paths: [PUBLIC_POINTER] };
    expect(foreignReadAllows(entry, "/public/profile/displayName")).toBe(true);
  });

  it("does not let a leaf grant reach a sibling leaf", () => {
    const entry = { paths: ["/public/profile/displayName"] };
    expect(foreignReadAllows(entry, "/public/profile/email")).toBe(false);
    expect(foreignReadAllows(entry, "/public/profile/displayNameExtra")).toBe(false);
  });

  it("refuses a path outside the published subtree whatever was stored", () => {
    const entry = { paths: [PUBLIC_POINTER] };
    expect(foreignReadAllows(entry, "/profile/email")).toBe(false);
    expect(foreignReadAllows(entry, "")).toBe(false);
  });

  it("refuses a stored rule that escapes the subtree", () => {
    // The host keeps grants in a file encrypted with the OS keychain but NOT
    // sealed under the vault key, so a stored entry is modifiable by anything
    // running as the user. A hand-edited whole-document rule must not reopen
    // the owner's private data.
    expect(foreignReadAllows({ paths: [""] }, "/profile/email")).toBe(false);
    expect(foreignReadAllows({ paths: [""] }, "/public/x")).toBe(false);
    expect(foreignReadAllows({ paths: ["/"] }, "/public/x")).toBe(false);
    expect(foreignReadAllows({ paths: ["/profile"] }, "/profile/email")).toBe(false);
  });

  it("has a shape that cannot be confused with a field-rule list", () => {
    // The type system enforces this, but the runtime shape matters too: the
    // browser runs this code from a bundle with no typecheck. A FieldRule[] has
    // no `paths`, so it can only ever read as "nothing approved".
    const fields = [{ path: "", read: true, write: true }] as unknown as { paths: string[] };
    expect(foreignReadAllows(fields, "/public/x")).toBe(false);
  });
});

describe("publishAllows", () => {
  const rule = (path: string, write: boolean): FieldRule => ({ path, read: true, write });

  it("accepts a grant rooted at or below the published subtree", () => {
    expect(publishAllows([rule(PUBLIC_POINTER, true)], "/public/profile")).toBe(true);
    expect(publishAllows([rule("/public/profile", true)], "/public/profile/displayName")).toBe(true);
  });

  it("refuses a whole-document grant, which is the point of the gate", () => {
    // `fieldAllows` says yes to exactly this, so publishing must be checked
    // separately or a site granted everything publishes without the user ever
    // seeing the word "public".
    const whole = [rule("", true)];
    expect(fieldAllows(whole, "/public/x", "write")).toBe(true);
    expect(publishAllows(whole, "/public/x")).toBe(false);
  });

  it("refuses a read-only grant on the subtree", () => {
    expect(publishAllows([rule(PUBLIC_POINTER, false)], "/public/x")).toBe(false);
  });

  it("refuses a grant on a neighbouring path", () => {
    expect(publishAllows([rule("/publicity", true)], "/public/x")).toBe(false);
    expect(publishAllows([rule("/profile", true)], "/public/x")).toBe(false);
  });
});
