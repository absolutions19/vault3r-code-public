import { describe, expect, it } from "vitest";
import { parseJsonStrict, StrictJsonError } from "./strict-json.js";

describe("parseJsonStrict", () => {
  it("parses the standard JSON grammar", () => {
    expect(parseJsonStrict('{"a":1,"b":[true,false,null,"x"],"c":{"d":-2.5e3}}')).toEqual({
      a: 1,
      b: [true, false, null, "x"],
      c: { d: -2500 },
    });
    expect(parseJsonStrict("  []  ")).toEqual([]);
    expect(parseJsonStrict('"hi\\n\\u0041"')).toBe("hi\nA");
  });

  it("REJECTS duplicate object keys (parser-differential defense)", () => {
    expect(() => parseJsonStrict('{"a":1,"a":2}')).toThrow(/duplicate object key/);
    expect(() => parseJsonStrict('{"x":{"y":1,"y":2}}')).toThrow(/duplicate object key/);
  });

  it("enforces a maximum nesting depth", () => {
    const deep = "[".repeat(40) + "]".repeat(40);
    expect(() => parseJsonStrict(deep, { maxDepth: 8 })).toThrow(/nesting depth/);
    expect(parseJsonStrict("[[[[]]]]", { maxDepth: 8 })).toEqual([[[[]]]]);
  });

  it("rejects trailing content, control chars, and non-finite numbers", () => {
    expect(() => parseJsonStrict("{} garbage")).toThrow(/trailing content/);
    expect(() => parseJsonStrict('"ab"')).toThrow(/control character/);
    expect(() => parseJsonStrict("1e400")).toThrow(/non-finite/);
    expect(() => parseJsonStrict("")).toThrow(StrictJsonError);
    expect(() => parseJsonStrict("{")).toThrow(StrictJsonError);
    expect(() => parseJsonStrict('{"a":}')).toThrow(StrictJsonError);
  });

  it("does not use a prototype-polluting object", () => {
    const o = parseJsonStrict('{"__proto__":{"x":1}}') as Record<string, unknown>;
    // The key is stored as an own property, and Object.prototype is untouched.
    expect(Object.prototype.hasOwnProperty.call(o, "__proto__")).toBe(true);
    expect(({} as Record<string, unknown>)["x"]).toBeUndefined();
  });

  it("matches JSON.parse for a large random-ish structure (round-trip)", () => {
    const obj = { n: 42, s: "hello world", arr: [1, 2, 3, { k: "v" }], b: true, nil: null };
    expect(parseJsonStrict(JSON.stringify(obj))).toEqual(obj);
  });
});
