import { describe, expect, it } from "vitest";
import { OmaTrustError } from "../src/shared/errors";
import {
  normalizeSchema,
  schemaToString,
  encodeAttestationData,
  validateAttestationData,
  decodeAttestationData,
  extractExpirationTime
} from "../src/reputation/encode";

describe("reputation/encode", () => {
  describe("encodeAttestationData", () => {
    it("encodes valid attestation payloads with complex schema", () => {
      const complexSchema = "uint256 score, string subject, string[] proofs, bool active, address attester, bytes32 digest";
      const encoded = encodeAttestationData(complexSchema, {
        score: "42",
        subject: "did:web:example.com",
        proofs: ["proof-a", "proof-b"],
        active: true,
        attester: "0x1111111111111111111111111111111111111111",
        digest: "0x".padEnd(66, "a")
      });

      expect(encoded.startsWith("0x")).toBe(true);
      expect(encoded.length).toBeGreaterThan(2);
    });

    it("throws OmaTrustError when encoding invalid field value", () => {
      const complexSchema = "uint256 score, string subject, string[] proofs, bool active, address attester, bytes32 digest";
      expect(() =>
        encodeAttestationData(complexSchema, {
          score: "",
          subject: "did:web:example.com",
          proofs: [],
          active: true,
          attester: "0x1111111111111111111111111111111111111111",
          digest: "0x".padEnd(66, "a")
        })
      ).toThrowError(OmaTrustError);
    });

    it("throws for null or non-object data", () => {
      expect(() => encodeAttestationData("string x", null as never)).toThrow(OmaTrustError);
      expect(() => encodeAttestationData("string x", "not-object" as never)).toThrow(OmaTrustError);
      expect(() => encodeAttestationData("string x", [] as never)).toThrow(OmaTrustError);
    });
  });

  describe("normalizeSchema", () => {
    it("parses comma-separated schema string", () => {
      const fields = normalizeSchema("uint256 score, string name");
      expect(fields).toEqual([
        { type: "uint256", name: "score" },
        { type: "string", name: "name" }
      ]);
    });

    it("returns SchemaField array as-is", () => {
      const input = [{ type: "uint256", name: "score" }];
      expect(normalizeSchema(input)).toBe(input);
    });

    it("throws for empty array", () => {
      expect(() => normalizeSchema([])).toThrow(OmaTrustError);
    });

    it("throws for empty string", () => {
      expect(() => normalizeSchema("")).toThrow(OmaTrustError);
    });

    it("throws for whitespace-only string", () => {
      expect(() => normalizeSchema("   ")).toThrow(OmaTrustError);
    });

    it("throws for invalid schema field (missing name)", () => {
      expect(() => normalizeSchema("uint256")).toThrow(OmaTrustError);
    });

    it("handles extra whitespace in schema string", () => {
      const fields = normalizeSchema("  uint256   score  ,  string   name  ");
      expect(fields).toEqual([
        { type: "uint256", name: "score" },
        { type: "string", name: "name" }
      ]);
    });
  });

  describe("schemaToString", () => {
    it("converts SchemaField array to string", () => {
      const result = schemaToString([
        { type: "uint256", name: "score" },
        { type: "string", name: "name" }
      ]);
      expect(result).toBe("uint256 score, string name");
    });

    it("returns string schema as-is", () => {
      expect(schemaToString("uint256 score")).toBe("uint256 score");
    });
  });

  describe("decodeAttestationData", () => {
    const schema = "uint256 score, string subject";

    it("round-trips encode then decode", () => {
      const data = { score: 42, subject: "did:web:example.com" };
      const encoded = encodeAttestationData(schema, data);
      const decoded = decodeAttestationData(schema, encoded);
      expect(Number(decoded.score)).toBe(42);
      expect(decoded.subject).toBe("did:web:example.com");
    });

    it("throws for non-hex encoded data", () => {
      expect(() => decodeAttestationData(schema, "not-hex" as `0x${string}`)).toThrow(OmaTrustError);
    });

    it("round-trips with bool and address types", () => {
      const complexSchema = "bool active, address wallet";
      const data = {
        active: true,
        wallet: "0x1111111111111111111111111111111111111111"
      };
      const encoded = encodeAttestationData(complexSchema, data);
      const decoded = decodeAttestationData(complexSchema, encoded);
      expect(decoded.active).toBe(true);
      expect(String(decoded.wallet).toLowerCase()).toBe("0x1111111111111111111111111111111111111111");
    });

    it("round-trips with string array", () => {
      const arrSchema = "string[] tags";
      const data = { tags: ["a", "b", "c"] };
      const encoded = encodeAttestationData(arrSchema, data);
      const decoded = decodeAttestationData(arrSchema, encoded);
      expect(decoded.tags).toEqual(["a", "b", "c"]);
    });
  });

  describe("extractExpirationTime", () => {
    it("returns undefined for missing expiresAt", () => {
      expect(extractExpirationTime({})).toBeUndefined();
    });

    it("returns undefined for null expiresAt", () => {
      expect(extractExpirationTime({ expiresAt: null })).toBeUndefined();
    });

    it("returns bigint as-is", () => {
      expect(extractExpirationTime({ expiresAt: 12345n })).toBe(12345n);
    });

    it("returns number as-is", () => {
      expect(extractExpirationTime({ expiresAt: 12345 })).toBe(12345);
    });

    it("converts numeric string to bigint", () => {
      const result = extractExpirationTime({ expiresAt: "12345" });
      expect(result).toBe(12345n);
    });

    it("returns undefined for non-numeric string", () => {
      expect(extractExpirationTime({ expiresAt: "not-a-number" })).toBeUndefined();
    });

    it("returns undefined for boolean", () => {
      expect(extractExpirationTime({ expiresAt: true })).toBeUndefined();
    });

    it("returns undefined for object", () => {
      expect(extractExpirationTime({ expiresAt: {} })).toBeUndefined();
    });
  });

  describe("validateAttestationData – type coverage", () => {
    it("validates int types (allows negative)", () => {
      const errors = validateAttestationData("int256 val", { val: -42 });
      expect(errors).toHaveLength(0);
    });

    it("rejects negative for uint types", () => {
      const errors = validateAttestationData("uint256 val", { val: -1 });
      expect(errors).toHaveLength(1);
      expect(errors[0].schemaFieldName).toBe("val");
    });

    it("accepts bigint for uint types", () => {
      const errors = validateAttestationData("uint256 val", { val: 100n });
      expect(errors).toHaveLength(0);
    });

    it("accepts numeric string for uint types", () => {
      const errors = validateAttestationData("uint256 val", { val: "100" });
      expect(errors).toHaveLength(0);
    });

    it("rejects empty string for uint types", () => {
      const errors = validateAttestationData("uint256 val", { val: "" });
      expect(errors).toHaveLength(1);
    });

    it("rejects non-integer number for uint types", () => {
      const errors = validateAttestationData("uint256 val", { val: 3.14 });
      expect(errors).toHaveLength(1);
    });

    it("validates bool type", () => {
      expect(validateAttestationData("bool flag", { flag: true })).toHaveLength(0);
      expect(validateAttestationData("bool flag", { flag: false })).toHaveLength(0);
      expect(validateAttestationData("bool flag", { flag: "true" })).toHaveLength(1);
    });

    it("validates address type", () => {
      expect(validateAttestationData("address addr", {
        addr: "0x1111111111111111111111111111111111111111"
      })).toHaveLength(0);

      expect(validateAttestationData("address addr", {
        addr: "not-address"
      })).toHaveLength(1);
    });

    it("validates bytes type (dynamic)", () => {
      expect(validateAttestationData("bytes data", { data: "0xabcd" })).toHaveLength(0);
      expect(validateAttestationData("bytes data", { data: "0xabc" })).toHaveLength(1); // odd length
      expect(validateAttestationData("bytes data", { data: "not-hex" })).toHaveLength(1);
    });

    it("validates bytes32 type (fixed)", () => {
      expect(validateAttestationData("bytes32 digest", {
        digest: "0x" + "a".repeat(64)
      })).toHaveLength(0);

      expect(validateAttestationData("bytes32 digest", {
        digest: "0x" + "a".repeat(62)
      })).toHaveLength(1);
    });

    it("validates bytes1 type", () => {
      expect(validateAttestationData("bytes1 val", { val: "0xab" })).toHaveLength(0);
      expect(validateAttestationData("bytes1 val", { val: "0xabcd" })).toHaveLength(1);
    });

    it("accepts unknown schema types (fallback)", () => {
      const errors = validateAttestationData("bytes33 custom", { custom: "0x" + "a".repeat(66) });
      expect(errors).toHaveLength(0);
    });

    it("validates string[] type", () => {
      expect(validateAttestationData("string[] tags", { tags: ["a", "b"] })).toHaveLength(0);
      expect(validateAttestationData("string[] tags", { tags: [1, 2] })).toHaveLength(1);
      expect(validateAttestationData("string[] tags", { tags: "not-array" })).toHaveLength(1);
    });

    it("reports null and undefined as errors for typed fields", () => {
      const errors = validateAttestationData("string name, uint256 score", {
        name: null,
        score: undefined
      });
      expect(errors).toHaveLength(2);
      expect(errors[0].providedType).toBe("null");
      expect(errors[1].providedType).toBe("undefined");
    });

    it("returns data-level error for non-object data", () => {
      const errors = validateAttestationData("string name", null as unknown as Record<string, unknown>);
      expect(errors).toHaveLength(1);
      expect(errors[0].schemaFieldName).toBe("data");
    });
  });
});
