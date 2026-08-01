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

  // --- RFC 8259 number grammar (adversarial: parser-differential holes) ---
  it("rejects leading-zero integers", () => {
    for (const s of ["01", "00", "-01", "[01]", '{"a":01}', "007"]) {
      expect(() => parseJsonStrict(s), s).toThrow();
    }
  });
  it("rejects a trailing decimal point with no fractional digit", () => {
    for (const s of ["1.", "0.", "-1.", "[1.]"]) expect(() => parseJsonStrict(s), s).toThrow();
  });
  it("rejects missing fractional digit before an exponent, and leading-zero+exp", () => {
    for (const s of ["1.e5", "1.E5", "01e2"]) expect(() => parseJsonStrict(s), s).toThrow();
  });
  it("rejects a sign or exponent with no digit", () => {
    for (const s of ["-.5", ".5", "-", "1e", "1e+", "1E-"]) expect(() => parseJsonStrict(s), s).toThrow();
  });
  it("still accepts all valid JSON numbers", () => {
    for (const s of ["0", "-0", "1", "1.5", "1e5", "1E-5", "0.5", "-0.5", "1.5e+3", "12345", "-2500"]) {
      expect(parseJsonStrict(s), s).toBe(JSON.parse(s));
    }
  });
  it("differential fuzz: agrees with JSON.parse on accept/reject for numeric edge cases", () => {
    const corpus = [
      "0", "00", "01", "-0", "-00", "1", "10", "-1", "1.", ".1", "1.0", "1.00", "-.5", "1e", "1e5", "1e+5",
      "1e-5", "1.e5", "1.5e", "1.5e3", "01e2", "0.0", "0.", "+1", "1,", "1 2", "007", "1.2.3", "0x1", "Infinity",
      "NaN", "1E", "1E10", "-1.5E-10", "9007199254740993",
    ];
    for (const s of corpus) {
      let jsonOk = true;
      try { JSON.parse(s); } catch { jsonOk = false; }
      let strictOk = true;
      try { parseJsonStrict(s); } catch { strictOk = false; }
      expect(strictOk, `disagreement on ${JSON.stringify(s)}`).toBe(jsonOk);
    }
  });
});
