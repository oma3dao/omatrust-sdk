import { describe, expect, it, vi, beforeEach, afterEach } from "vitest";
import { OmaTrustError } from "../src/shared/errors";
import {
  computeDataHashFromUrl,
  verifyDataUrlHash
} from "../src/app-registry/data-hash";

describe("app-registry/data-hash", () => {
  let fetchMock: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  describe("computeDataHashFromUrl", () => {
    it("fetches JSON and returns keccak256 hash", async () => {
      fetchMock.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ name: "test", version: "1.0" })
      });

      const hash = await computeDataHashFromUrl("https://example.com/data.json", "keccak256");
      expect(hash).toMatch(/^0x[0-9a-f]{64}$/);
    });

    it("fetches JSON and returns sha256 hash", async () => {
      fetchMock.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ name: "test" })
      });

      const hash = await computeDataHashFromUrl("https://example.com/data.json", "sha256");
      expect(hash).toMatch(/^0x[0-9a-f]{64}$/);
    });

    it("produces deterministic hash for same content", async () => {
      const data = { b: 2, a: 1 };
      fetchMock.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve(data)
      });
      const hash1 = await computeDataHashFromUrl("https://example.com/1.json", "keccak256");

      // Same data, different key order → same JCS → same hash
      fetchMock.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ a: 1, b: 2 })
      });
      const hash2 = await computeDataHashFromUrl("https://example.com/2.json", "keccak256");

      expect(hash1).toBe(hash2);
    });

    it("throws for empty url", async () => {
      await expect(computeDataHashFromUrl("", "keccak256")).rejects.toThrow(OmaTrustError);
    });

    it("throws for non-string url", async () => {
      await expect(computeDataHashFromUrl(null as unknown as string, "keccak256")).rejects.toThrow(OmaTrustError);
    });

    it("throws NETWORK_ERROR when fetch fails", async () => {
      fetchMock.mockRejectedValueOnce(new Error("network failure"));
      try {
        await computeDataHashFromUrl("https://example.com/data.json", "keccak256");
      } catch (err) {
        expect(err).toBeInstanceOf(OmaTrustError);
        expect((err as OmaTrustError).code).toBe("NETWORK_ERROR");
      }
    });

    it("throws NETWORK_ERROR for non-ok response", async () => {
      fetchMock.mockResolvedValueOnce({
        ok: false,
        status: 404
      });
      try {
        await computeDataHashFromUrl("https://example.com/missing.json", "keccak256");
      } catch (err) {
        expect(err).toBeInstanceOf(OmaTrustError);
        expect((err as OmaTrustError).code).toBe("NETWORK_ERROR");
      }
    });

    it("throws INVALID_INPUT for non-JSON response", async () => {
      fetchMock.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.reject(new SyntaxError("invalid json"))
      });
      try {
        await computeDataHashFromUrl("https://example.com/bad.json", "keccak256");
      } catch (err) {
        expect(err).toBeInstanceOf(OmaTrustError);
        expect((err as OmaTrustError).code).toBe("INVALID_INPUT");
      }
    });
  });

  describe("verifyDataUrlHash", () => {
    it("returns true when computed hash matches expected", async () => {
      const data = { name: "test" };
      // Fetch twice: once for computeDataHashFromUrl (via verifyDataUrlHash), once to get expected
      fetchMock.mockResolvedValue({
        ok: true,
        json: () => Promise.resolve(data)
      });

      const expectedHash = await computeDataHashFromUrl("https://example.com/data.json", "keccak256");
      const result = await verifyDataUrlHash("https://example.com/data.json", expectedHash, "keccak256");
      expect(result).toBe(true);
    });

    it("returns false when hash does not match", async () => {
      fetchMock.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ name: "test" })
      });

      const wrongHash = "0x" + "ff".repeat(32) as `0x${string}`;
      const result = await verifyDataUrlHash("https://example.com/data.json", wrongHash, "keccak256");
      expect(result).toBe(false);
    });

    it("is case-insensitive on hash comparison", async () => {
      const data = { name: "test" };
      fetchMock.mockResolvedValue({
        ok: true,
        json: () => Promise.resolve(data)
      });

      const hash = await computeDataHashFromUrl("https://example.com/data.json", "keccak256");
      const upperHash = hash.toUpperCase() as `0x${string}`;
      const result = await verifyDataUrlHash("https://example.com/data.json", upperHash, "keccak256");
      expect(result).toBe(true);
    });
  });
});
