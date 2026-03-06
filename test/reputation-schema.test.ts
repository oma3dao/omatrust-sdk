import { describe, expect, it, vi } from "vitest";
import { OmaTrustError } from "../src/shared/errors";
import {
  verifySchemaExists,
  getSchemaDetails,
  formatSchemaUid
} from "../src/reputation/schema";

const VALID_UID = "0x" + "ab".repeat(32) as `0x${string}`;
const ZERO_UID = "0x" + "0".repeat(64);

describe("reputation/schema", () => {
  describe("formatSchemaUid", () => {
    it("lowercases and returns valid 32-byte hex", () => {
      const uid = "0x" + "AB".repeat(32);
      expect(formatSchemaUid(uid)).toBe("0x" + "ab".repeat(32));
    });

    it("adds 0x prefix if missing", () => {
      const raw = "ab".repeat(32);
      expect(formatSchemaUid(raw)).toBe("0x" + "ab".repeat(32));
    });

    it("throws for empty string", () => {
      expect(() => formatSchemaUid("")).toThrow(OmaTrustError);
    });

    it("throws for too-short hex", () => {
      expect(() => formatSchemaUid("0x1234")).toThrow(OmaTrustError);
    });

    it("throws for non-hex characters", () => {
      expect(() => formatSchemaUid("0x" + "gg".repeat(32))).toThrow(OmaTrustError);
    });
  });

  describe("verifySchemaExists", () => {
    it("returns true when schema exists with valid uid", async () => {
      const registry = {
        getSchema: vi.fn().mockResolvedValue({ uid: VALID_UID })
      };
      expect(await verifySchemaExists(registry, VALID_UID)).toBe(true);
    });

    it("returns false when schema is null", async () => {
      const registry = {
        getSchema: vi.fn().mockResolvedValue(null)
      };
      expect(await verifySchemaExists(registry, VALID_UID)).toBe(false);
    });

    it("returns false when uid is zero", async () => {
      const registry = {
        getSchema: vi.fn().mockResolvedValue({ uid: ZERO_UID })
      };
      expect(await verifySchemaExists(registry, VALID_UID)).toBe(false);
    });

    it("returns false when getSchema throws", async () => {
      const registry = {
        getSchema: vi.fn().mockRejectedValue(new Error("network error"))
      };
      expect(await verifySchemaExists(registry, VALID_UID)).toBe(false);
    });

    it("calls getSchema with correct uid param", async () => {
      const registry = {
        getSchema: vi.fn().mockResolvedValue({ uid: VALID_UID })
      };
      await verifySchemaExists(registry, VALID_UID);
      expect(registry.getSchema).toHaveBeenCalledWith({ uid: VALID_UID });
    });
  });

  describe("getSchemaDetails", () => {
    it("returns formatted schema details", async () => {
      const registry = {
        getSchema: vi.fn().mockResolvedValue({
          uid: "0x" + "AB".repeat(32),
          schema: "uint256 score, string name",
          resolver: "0x" + "cc".repeat(20),
          revocable: true
        })
      };
      const result = await getSchemaDetails(registry, VALID_UID);
      expect(result.uid).toBe("0x" + "ab".repeat(32)); // lowercased
      expect(result.schema).toBe("uint256 score, string name");
      expect(result.revocable).toBe(true);
    });

    it("throws SCHEMA_NOT_FOUND when schema is null", async () => {
      const registry = {
        getSchema: vi.fn().mockResolvedValue(null)
      };
      await expect(getSchemaDetails(registry, VALID_UID)).rejects.toThrow(OmaTrustError);
      try {
        await getSchemaDetails(registry, VALID_UID);
      } catch (err) {
        expect((err as OmaTrustError).code).toBe("SCHEMA_NOT_FOUND");
      }
    });

    it("throws SCHEMA_NOT_FOUND when uid is zero", async () => {
      const registry = {
        getSchema: vi.fn().mockResolvedValue({ uid: ZERO_UID })
      };
      await expect(getSchemaDetails(registry, VALID_UID)).rejects.toThrow(OmaTrustError);
    });

    it("throws SCHEMA_NOT_FOUND for EAS schema-not-found errors", async () => {
      const registry = {
        getSchema: vi.fn().mockRejectedValue(new Error("schema not found"))
      };
      await expect(getSchemaDetails(registry, VALID_UID)).rejects.toThrow(OmaTrustError);
    });

    it("re-throws OmaTrustError as-is", async () => {
      const customErr = new OmaTrustError("CUSTOM", "custom error");
      const registry = {
        getSchema: vi.fn().mockRejectedValue(customErr)
      };
      await expect(getSchemaDetails(registry, VALID_UID)).rejects.toBe(customErr);
    });

    it("wraps unknown errors as NETWORK_ERROR", async () => {
      const registry = {
        getSchema: vi.fn().mockRejectedValue(new TypeError("unexpected"))
      };
      try {
        await getSchemaDetails(registry, VALID_UID);
      } catch (err) {
        expect(err).toBeInstanceOf(OmaTrustError);
        expect((err as OmaTrustError).code).toBe("NETWORK_ERROR");
      }
    });
  });
});
