import { describe, expect, it } from "vitest";
import { OmaTrustError } from "../src/shared/errors";
import {
  ZERO_UID,
  toBigIntOrDefault,
  normalizeHex32,
  withAutoSubjectDidHash,
  resolveRecipientAddress,
  parseProofsField
} from "../src/reputation/internal";
import { computeDidHash, didToAddress } from "../src/identity/did";

describe("reputation/internal", () => {
  describe("ZERO_UID", () => {
    it("is 32-byte zero hex", () => {
      expect(ZERO_UID).toBe("0x0000000000000000000000000000000000000000000000000000000000000000");
      expect(ZERO_UID).toHaveLength(66);
    });
  });

  describe("toBigIntOrDefault", () => {
    it("returns fallback for undefined", () => {
      expect(toBigIntOrDefault(undefined, 42n)).toBe(42n);
    });

    it("returns fallback for null", () => {
      expect(toBigIntOrDefault(null as unknown as undefined, 42n)).toBe(42n);
    });

    it("returns bigint value directly", () => {
      expect(toBigIntOrDefault(100n, 42n)).toBe(100n);
    });

    it("converts number to bigint (floored)", () => {
      expect(toBigIntOrDefault(5, 0n)).toBe(5n);
      expect(toBigIntOrDefault(5.9, 0n)).toBe(5n);
    });

    it("handles zero", () => {
      expect(toBigIntOrDefault(0, 42n)).toBe(0n);
      expect(toBigIntOrDefault(0n, 42n)).toBe(0n);
    });
  });

  describe("normalizeHex32", () => {
    it("returns valid 32-byte hex prefixed string", () => {
      const hex = "0x" + "a".repeat(64);
      expect(normalizeHex32(hex, "test")).toBe(hex);
    });

    it("adds 0x prefix if missing", () => {
      const raw = "a".repeat(64);
      expect(normalizeHex32(raw, "test")).toBe("0x" + raw);
    });

    it("throws for too-short hex", () => {
      expect(() => normalizeHex32("0x1234", "test")).toThrow(OmaTrustError);
    });

    it("throws for too-long hex", () => {
      expect(() => normalizeHex32("0x" + "a".repeat(65), "test")).toThrow(OmaTrustError);
    });

    it("throws for non-hex characters", () => {
      expect(() => normalizeHex32("0x" + "g".repeat(64), "test")).toThrow(OmaTrustError);
    });

    it("includes field name in error", () => {
      try {
        normalizeHex32("0x1234", "myField");
      } catch (err) {
        expect((err as OmaTrustError).message).toContain("myField");
      }
    });
  });

  describe("withAutoSubjectDidHash", () => {
    const schemaWithSubjectDidHash = "string subject, bytes32 subjectDidHash, uint256 score";
    const schemaWithoutSubjectDidHash = "string subject, uint256 score";

    it("auto-computes subjectDidHash when schema has the field and subject is a DID", () => {
      const data = { subject: "did:web:example.com", score: 5 };
      const result = withAutoSubjectDidHash(schemaWithSubjectDidHash, data);
      expect(result.subjectDidHash).toBe(computeDidHash("did:web:example.com"));
    });

    it("does not modify data when schema lacks subjectDidHash field", () => {
      const data = { subject: "did:web:example.com", score: 5 };
      const result = withAutoSubjectDidHash(schemaWithoutSubjectDidHash, data);
      expect(result.subjectDidHash).toBeUndefined();
    });

    it("does not modify data when subject is not a DID string", () => {
      const data = { subject: "example.com", score: 5 };
      const result = withAutoSubjectDidHash(schemaWithSubjectDidHash, data);
      expect(result.subjectDidHash).toBeUndefined();
    });

    it("does not modify data when subject is missing", () => {
      const data = { score: 5 };
      const result = withAutoSubjectDidHash(schemaWithSubjectDidHash, data);
      expect(result.subjectDidHash).toBeUndefined();
    });

    it("returns a new object (does not mutate original)", () => {
      const data = { subject: "did:web:example.com", score: 5 };
      const result = withAutoSubjectDidHash(schemaWithSubjectDidHash, data);
      expect(result).not.toBe(data);
    });
  });

  describe("resolveRecipientAddress", () => {
    it("resolves from DID subject", () => {
      const data = { subject: "did:web:example.com" };
      const addr = resolveRecipientAddress(data);
      expect(addr).toBe(didToAddress("did:web:example.com"));
    });

    it("resolves from subjectDidHash (32-byte hex)", () => {
      const hash = computeDidHash("did:web:example.com");
      const data = { subjectDidHash: hash };
      const addr = resolveRecipientAddress(data);
      expect(addr).toMatch(/^0x[0-9a-f]{40}$/);
    });

    it("resolves from explicit recipient address", () => {
      const data = { recipient: "0x1111111111111111111111111111111111111111" };
      const addr = resolveRecipientAddress(data);
      expect(addr).toMatch(/^0x[0-9a-fA-F]{40}$/);
    });

    it("returns ZeroAddress when nothing is provided", () => {
      const addr = resolveRecipientAddress({});
      expect(addr).toBe("0x0000000000000000000000000000000000000000");
    });

    it("returns ZeroAddress for invalid recipient address", () => {
      const addr = resolveRecipientAddress({ recipient: "not-valid" });
      expect(addr).toBe("0x0000000000000000000000000000000000000000");
    });

    it("prefers subject DID over subjectDidHash over recipient", () => {
      const data = {
        subject: "did:web:example.com",
        subjectDidHash: "0x" + "b".repeat(64),
        recipient: "0x1111111111111111111111111111111111111111"
      };
      const addr = resolveRecipientAddress(data);
      expect(addr).toBe(didToAddress("did:web:example.com"));
    });
  });

  describe("parseProofsField", () => {
    it("returns empty array when proofs is not an array", () => {
      expect(parseProofsField({})).toEqual([]);
      expect(parseProofsField({ proofs: "not-array" })).toEqual([]);
      expect(parseProofsField({ proofs: 42 })).toEqual([]);
      expect(parseProofsField({ proofs: null })).toEqual([]);
    });

    it("returns objects as-is", () => {
      const obj = { proofType: "test" };
      const result = parseProofsField({ proofs: [obj] });
      expect(result).toEqual([obj]);
    });

    it("parses JSON strings into objects", () => {
      const json = '{"proofType":"test"}';
      const result = parseProofsField({ proofs: [json] });
      expect(result).toEqual([{ proofType: "test" }]);
    });

    it("returns unparseable strings as-is", () => {
      const result = parseProofsField({ proofs: ["not-json"] });
      expect(result).toEqual(["not-json"]);
    });

    it("handles mixed array of objects and JSON strings", () => {
      const result = parseProofsField({
        proofs: [
          { proofType: "a" },
          '{"proofType":"b"}',
          "invalid-json"
        ]
      });
      expect(result).toEqual([
        { proofType: "a" },
        { proofType: "b" },
        "invalid-json"
      ]);
    });
  });
});
