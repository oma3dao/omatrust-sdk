import { describe, expect, it } from "vitest";
import { OmaTrustError } from "../src/shared/errors";
import {
  parseJsonStrict,
  assertJsonSafe,
  canonicalizeJson,
  hashCanonicalizedJson,
} from "../src/identity/data";

describe("identity/data – strict JSON parsing and canonicalization", () => {
  describe("parseJsonStrict", () => {
    it("parses valid JSON correctly", () => {
      expect(parseJsonStrict('{"a":1,"b":2}')).toEqual({ a: 1, b: 2 });
    });

    it("parses nested objects", () => {
      const input = '{"outer":{"inner":"value"},"array":[1,2,3]}';
      expect(parseJsonStrict(input)).toEqual({ outer: { inner: "value" }, array: [1, 2, 3] });
    });

    it("rejects duplicate keys at top level", () => {
      const input = '{"a":1,"b":2,"a":3}';
      expect(() => parseJsonStrict(input)).toThrow(OmaTrustError);
      try {
        parseJsonStrict(input);
      } catch (err) {
        expect((err as OmaTrustError).code).toBe("INVALID_INPUT");
        expect((err as OmaTrustError).message).toContain('"a"');
      }
    });

    it("rejects duplicate keys in nested objects", () => {
      const input = '{"outer":{"x":1,"x":2}}';
      expect(() => parseJsonStrict(input)).toThrow(OmaTrustError);
    });

    it("reports multiple duplicate keys", () => {
      const input = '{"a":1,"b":2,"a":3,"b":4}';
      try {
        parseJsonStrict(input);
      } catch (err) {
        expect((err as OmaTrustError).message).toContain("keys");
        expect((err as OmaTrustError).message).toContain('"a"');
        expect((err as OmaTrustError).message).toContain('"b"');
      }
    });

    it("allows same key name in different objects", () => {
      const input = '{"a":{"name":"first"},"b":{"name":"second"}}';
      expect(parseJsonStrict(input)).toEqual({ a: { name: "first" }, b: { name: "second" } });
    });

    it("handles strings containing braces and colons", () => {
      const input = '{"key":"value with {braces} and :colons:"}';
      expect(parseJsonStrict(input)).toEqual({ key: "value with {braces} and :colons:" });
    });

    it("handles escaped quotes in strings", () => {
      const input = '{"key":"value with \\"quotes\\"","other":1}';
      expect(parseJsonStrict(input)).toEqual({ key: 'value with "quotes"', other: 1 });
    });

    it("handles backslashes in non-key string values", () => {
      const input = '{"path":"C:\\\\Users\\\\name"}';
      expect(parseJsonStrict(input)).toEqual({ path: "C:\\Users\\name" });
    });

    it("rejects non-string input", () => {
      expect(() => parseJsonStrict(42 as unknown as string)).toThrow(OmaTrustError);
    });

    it("rejects invalid JSON", () => {
      expect(() => parseJsonStrict("{not valid json}")).toThrow(OmaTrustError);
    });

    it("parses arrays at top level", () => {
      expect(parseJsonStrict("[1,2,3]")).toEqual([1, 2, 3]);
    });

    it("parses primitives", () => {
      expect(parseJsonStrict('"hello"')).toBe("hello");
      expect(parseJsonStrict("42")).toBe(42);
      expect(parseJsonStrict("true")).toBe(true);
      expect(parseJsonStrict("null")).toBe(null);
    });

    it("rejects JSON exceeding max nesting depth", () => {
      // 33 levels of nesting exceeds the limit of 32
      const deep = "{".repeat(33) + '"a":1' + "}".repeat(33);
      expect(() => parseJsonStrict(deep)).toThrow(OmaTrustError);
      try {
        parseJsonStrict(deep);
      } catch (err) {
        expect((err as OmaTrustError).message).toContain("nesting depth");
      }
    });

    it("accepts JSON at exactly max nesting depth", () => {
      // 32 levels should be fine
      let json = "";
      for (let i = 0; i < 32; i++) json += '{"a":';
      json += "1";
      for (let i = 0; i < 32; i++) json += "}";
      expect(() => parseJsonStrict(json)).not.toThrow();
    });
  });

  describe("assertJsonSafe – in-memory JSON safety", () => {
    it("accepts valid JSON-safe values", () => {
      expect(() => assertJsonSafe({ a: 1, b: "hello", c: true, d: null, e: [1, 2] })).not.toThrow();
    });

    it("accepts nested valid structures", () => {
      expect(() => assertJsonSafe({ deep: { nested: { array: [{ ok: true }] } } })).not.toThrow();
    });

    it("rejects undefined", () => {
      expect(() => assertJsonSafe(undefined)).toThrow(OmaTrustError);
    });

    it("rejects NaN", () => {
      expect(() => assertJsonSafe({ score: NaN })).toThrow(OmaTrustError);
      try { assertJsonSafe({ score: NaN }); } catch (err) {
        expect((err as OmaTrustError).message).toContain("$.score");
        expect((err as OmaTrustError).message).toContain("NaN");
      }
    });

    it("rejects Infinity", () => {
      expect(() => assertJsonSafe({ val: Infinity })).toThrow(OmaTrustError);
      expect(() => assertJsonSafe({ val: -Infinity })).toThrow(OmaTrustError);
    });

    it("rejects BigInt", () => {
      expect(() => assertJsonSafe({ id: BigInt(123) })).toThrow(OmaTrustError);
    });

    it("rejects functions", () => {
      expect(() => assertJsonSafe({ fn: () => {} })).toThrow(OmaTrustError);
    });

    it("rejects Symbols", () => {
      expect(() => assertJsonSafe({ s: Symbol("test") })).toThrow(OmaTrustError);
    });

    it("rejects Date objects", () => {
      expect(() => assertJsonSafe({ date: new Date() })).toThrow(OmaTrustError);
    });

    it("rejects RegExp", () => {
      expect(() => assertJsonSafe({ pattern: /abc/ })).toThrow(OmaTrustError);
    });

    it("accepts empty objects and arrays", () => {
      expect(() => assertJsonSafe({})).not.toThrow();
      expect(() => assertJsonSafe([])).not.toThrow();
    });

    it("rejects undefined inside arrays", () => {
      expect(() => assertJsonSafe({ items: [1, undefined, 3] })).toThrow(OmaTrustError);
      try { assertJsonSafe({ items: [1, undefined, 3] }); } catch (err) {
        expect((err as OmaTrustError).message).toContain("$.items[1]");
      }
    });

    it("rejects NaN in deeply nested structures", () => {
      expect(() => assertJsonSafe({ a: { b: { c: NaN } } })).toThrow(OmaTrustError);
      try { assertJsonSafe({ a: { b: { c: NaN } } }); } catch (err) {
        expect((err as OmaTrustError).message).toContain("$.a.b.c");
      }
    });

    it("canonicalizeJson rejects non-JSON-safe input", () => {
      expect(() => canonicalizeJson({ val: NaN })).toThrow(OmaTrustError);
      expect(() => canonicalizeJson({ fn: () => {} })).toThrow(OmaTrustError);
    });

    it("rejects objects exceeding max nesting depth", () => {
      // Build a 33-level deep object
      let obj: any = { leaf: 1 };
      for (let i = 0; i < 33; i++) obj = { nested: obj };
      expect(() => assertJsonSafe(obj)).toThrow(OmaTrustError);
      try { assertJsonSafe(obj); } catch (err) {
        expect((err as OmaTrustError).message).toContain("nesting depth");
      }
    });
  });

  describe("canonicalizeJson – key reordering", () => {
    it("produces same output regardless of key order", () => {
      const a = canonicalizeJson({ b: 2, a: 1 });
      const b = canonicalizeJson({ a: 1, b: 2 });
      expect(a).toBe(b);
      expect(a).toBe('{"a":1,"b":2}');
    });

    it("handles nested structures deterministically", () => {
      const result = canonicalizeJson({ z: { b: 2, a: 1 }, a: [3, 1, 2] });
      expect(result).toBe('{"a":[3,1,2],"z":{"a":1,"b":2}}');
    });
  });

  describe("hashCanonicalizedJson – runtime algorithm guard", () => {
    it("accepts keccak256", () => {
      const hash = hashCanonicalizedJson({ test: true }, "keccak256");
      expect(hash).toMatch(/^0x[0-9a-f]{64}$/);
    });

    it("accepts sha256", () => {
      const hash = hashCanonicalizedJson({ test: true }, "sha256");
      expect(hash).toMatch(/^0x[0-9a-f]{64}$/);
    });

    it("rejects unsupported algorithm at runtime", () => {
      expect(() =>
        hashCanonicalizedJson({ test: true }, "md5" as unknown as "keccak256" | "sha256")
      ).toThrow(OmaTrustError);
    });
  });

  describe("Appendix D test vectors — canonicalization + hashing", () => {
    it("vector 1: float normalization and escape sequence (newline)", () => {
      // Input: {"a": 1.0, "b": {"c": "\n"}}
      // \n is a newline character (U+000A) in the string value
      const obj = { a: 1.0, b: { c: "\n" } };
      const canonical = canonicalizeJson(obj);
      expect(canonical).toBe('{"a":1,"b":{"c":"\\n"}}');
      expect(hashCanonicalizedJson(obj, "keccak256")).toBe(
        "0x272619e60fdf0b8408352a24263ab5bd43e5c3873828556737960144deb08639"
      );
      expect(hashCanonicalizedJson(obj, "sha256")).toBe(
        "0xa14a36c545cf0d9cd10a13680775cb5b3c5e17d2d426c5a54b8af1d2d17d5351"
      );
    });

    it("vector 2: key reordering", () => {
      // Input: {"b":2,"a":1}
      const obj = { b: 2, a: 1 };
      const canonical = canonicalizeJson(obj);
      expect(canonical).toBe('{"a":1,"b":2}');
      expect(hashCanonicalizedJson(obj, "keccak256")).toBe(
        "0xb8ffb64722137f4b100665a52e3c943f8066e8ab8ba3b427e6f4b404defd82b0"
      );
      expect(hashCanonicalizedJson(obj, "sha256")).toBe(
        "0x43258cff783fe7036d8a43033f830adfc60ec037382473548ac742b888292777"
      );
    });

    it("vector 3: nested array with object", () => {
      // Input: {"x":[{"y":true}]}
      const obj = { x: [{ y: true }] };
      const canonical = canonicalizeJson(obj);
      expect(canonical).toBe('{"x":[{"y":true}]}');
      expect(hashCanonicalizedJson(obj, "keccak256")).toBe(
        "0x2645502e6bc76dd669aa0e22c68b99defe44dd5479159445656a693e57764097"
      );
      expect(hashCanonicalizedJson(obj, "sha256")).toBe(
        "0x01f868b03ac751f2fd0e87fbea94e729866312f476e8fe029c8959e94acd6889"
      );
    });
  });
});
