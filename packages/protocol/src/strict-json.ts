/**
 * Strict JSON parser — the parser-differential defense.
 *
 * `JSON.parse` silently accepts duplicate object keys (keeping the last) and has
 * no depth limit, so a producer and a consumer can disagree about what a message
 * "means" (one sees `{a:1}`, the other `{a:2}`) or a deeply-nested payload can
 * exhaust the stack. This parser rejects both: duplicate keys are an error, and
 * nesting is bounded. It accepts the standard JSON grammar otherwise (floats are
 * fine — value hashing handles those); numbers must be finite.
 *
 * Used at the trust boundary where an untrusted, decrypted peer message is turned
 * into an object, so the engine never acts on an ambiguous parse.
 */

import { MAX_JSON_DEPTH } from "./constants.js";

export class StrictJsonError extends Error {
  constructor(message: string, readonly position: number) {
    super(`${message} at position ${position}`);
    this.name = "StrictJsonError";
  }
}

export interface StrictJsonOptions {
  maxDepth?: number;
}

export function parseJsonStrict(text: string, opts: StrictJsonOptions = {}): unknown {
  const maxDepth = opts.maxDepth ?? MAX_JSON_DEPTH;
  let i = 0;
  const n = text.length;

  const err = (m: string): never => {
    throw new StrictJsonError(m, i);
  };

  const ws = (): void => {
    while (i < n) {
      const c = text.charCodeAt(i);
      if (c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d) i++;
      else break;
    }
  };

  const parseValue = (depth: number): unknown => {
    if (depth > maxDepth) err("maximum nesting depth exceeded");
    ws();
    if (i >= n) err("unexpected end of input");
    const c = text[i];
    if (c === "{") return parseObject(depth);
    if (c === "[") return parseArray(depth);
    if (c === '"') return parseString();
    if (c === "-" || (c! >= "0" && c! <= "9")) return parseNumber();
    if (text.startsWith("true", i)) return (i += 4), true;
    if (text.startsWith("false", i)) return (i += 5), false;
    if (text.startsWith("null", i)) return (i += 4), null;
    return err(`unexpected token '${c}'`);
  };

  const parseObject = (depth: number): Record<string, unknown> => {
    i++; // {
    const obj: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
    const seen = new Set<string>();
    ws();
    if (text[i] === "}") return i++, obj;
    for (;;) {
      ws();
      if (text[i] !== '"') err("expected object key string");
      const key = parseString();
      if (seen.has(key)) err(`duplicate object key '${key}'`);
      seen.add(key);
      ws();
      if (text[i] !== ":") err("expected ':'");
      i++;
      obj[key] = parseValue(depth + 1);
      ws();
      const ch = text[i];
      if (ch === ",") {
        i++;
        continue;
      }
      if (ch === "}") {
        i++;
        return obj;
      }
      err("expected ',' or '}'");
    }
  };

  const parseArray = (depth: number): unknown[] => {
    i++; // [
    const arr: unknown[] = [];
    ws();
    if (text[i] === "]") return i++, arr;
    for (;;) {
      arr.push(parseValue(depth + 1));
      ws();
      const ch = text[i];
      if (ch === ",") {
        i++;
        continue;
      }
      if (ch === "]") {
        i++;
        return arr;
      }
      err("expected ',' or ']'");
    }
  };

  const parseString = (): string => {
    i++; // opening quote
    let out = "";
    for (;;) {
      if (i >= n) err("unterminated string");
      const c = text[i]!;
      if (c === '"') {
        i++;
        return out;
      }
      if (c === "\\") {
        i++;
        const e = text[i];
        switch (e) {
          case '"': out += '"'; break;
          case "\\": out += "\\"; break;
          case "/": out += "/"; break;
          case "b": out += "\b"; break;
          case "f": out += "\f"; break;
          case "n": out += "\n"; break;
          case "r": out += "\r"; break;
          case "t": out += "\t"; break;
          case "u": {
            const hex = text.slice(i + 1, i + 5);
            if (!/^[0-9a-fA-F]{4}$/.test(hex)) err("invalid \\u escape");
            out += String.fromCharCode(parseInt(hex, 16));
            i += 4;
            break;
          }
          default:
            err("invalid escape");
        }
        i++;
      } else if (c.charCodeAt(0) < 0x20) {
        err("unescaped control character in string");
      } else {
        out += c;
        i++;
      }
    }
  };

  const isDigit = (c: string | undefined): boolean => c !== undefined && c >= "0" && c <= "9";

  const parseNumber = (): number => {
    // Enforce the RFC 8259 number grammar exactly, so we never diverge from a
    // JSON.parse-based peer: no leading zeros, a digit required after '.', and a
    // digit required in the exponent.  -?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?
    const start = i;
    if (text[i] === "-") i++;
    if (text[i] === "0") {
      i++;
    } else if (isDigit(text[i])) {
      i++;
      while (isDigit(text[i])) i++;
    } else {
      err("invalid number: expected a digit");
    }
    if (text[i] === ".") {
      i++;
      if (!isDigit(text[i])) err("invalid number: a digit is required after '.'");
      while (isDigit(text[i])) i++;
    }
    if (text[i] === "e" || text[i] === "E") {
      i++;
      if (text[i] === "+" || text[i] === "-") i++;
      if (!isDigit(text[i])) err("invalid number: a digit is required in the exponent");
      while (isDigit(text[i])) i++;
    }
    const num = Number(text.slice(start, i));
    if (!Number.isFinite(num)) err("non-finite number");
    return num;
  };

  const value = parseValue(1);
  ws();
  if (i !== n) err("trailing content after JSON value");
  return value;
}
