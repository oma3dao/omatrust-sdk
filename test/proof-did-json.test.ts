import { describe, expect, it, vi, beforeEach, afterEach } from "vitest";
import { OmaTrustError } from "../src/shared/errors";
import {
  extractAddressesFromDidDocument,
  fetchDidDocument,
  verifyDidDocumentControllerDid
} from "../src/reputation/proof/did-json";

describe("proof/did-json", () => {
  describe("extractAddressesFromDidDocument", () => {
    it("returns empty array when verificationMethod is missing", () => {
      expect(extractAddressesFromDidDocument({})).toEqual([]);
    });

    it("returns empty array when verificationMethod is not an array", () => {
      expect(extractAddressesFromDidDocument({ verificationMethod: "not-array" })).toEqual([]);
    });

    it("extracts address from blockchainAccountId (raw address)", () => {
      const doc = {
        verificationMethod: [
          { blockchainAccountId: "0x1111111111111111111111111111111111111111" }
        ]
      };
      const addresses = extractAddressesFromDidDocument(doc);
      expect(addresses).toHaveLength(1);
      expect(addresses[0].toLowerCase()).toBe("0x1111111111111111111111111111111111111111");
    });

    it("extracts address from blockchainAccountId (CAIP-10 format)", () => {
      const doc = {
        verificationMethod: [
          { blockchainAccountId: "eip155:1:0x1111111111111111111111111111111111111111" }
        ]
      };
      const addresses = extractAddressesFromDidDocument(doc);
      expect(addresses).toHaveLength(1);
    });

    it("extracts address from publicKeyHex", () => {
      const doc = {
        verificationMethod: [
          { publicKeyHex: "0x2222222222222222222222222222222222222222" }
        ]
      };
      const addresses = extractAddressesFromDidDocument(doc);
      expect(addresses).toHaveLength(1);
      expect(addresses[0].toLowerCase()).toBe("0x2222222222222222222222222222222222222222");
    });

    it("adds 0x prefix to publicKeyHex if missing", () => {
      const doc = {
        verificationMethod: [
          { publicKeyHex: "3333333333333333333333333333333333333333" }
        ]
      };
      const addresses = extractAddressesFromDidDocument(doc);
      expect(addresses).toHaveLength(1);
      expect(addresses[0].toLowerCase()).toBe("0x3333333333333333333333333333333333333333");
    });

    it("deduplicates addresses", () => {
      const doc = {
        verificationMethod: [
          { blockchainAccountId: "0x1111111111111111111111111111111111111111" },
          { publicKeyHex: "0x1111111111111111111111111111111111111111" }
        ]
      };
      const addresses = extractAddressesFromDidDocument(doc);
      expect(addresses).toHaveLength(1);
    });

    it("skips invalid entries gracefully", () => {
      const doc = {
        verificationMethod: [
          { blockchainAccountId: "not-a-valid-id" },
          { publicKeyHex: "not-hex" },
          { blockchainAccountId: "0x1111111111111111111111111111111111111111" }
        ]
      };
      const addresses = extractAddressesFromDidDocument(doc);
      expect(addresses).toHaveLength(1);
    });

    it("handles multiple valid methods", () => {
      const doc = {
        verificationMethod: [
          { blockchainAccountId: "0x1111111111111111111111111111111111111111" },
          { blockchainAccountId: "0x2222222222222222222222222222222222222222" }
        ]
      };
      const addresses = extractAddressesFromDidDocument(doc);
      expect(addresses).toHaveLength(2);
    });
  });

  describe("verifyDidDocumentControllerDid", () => {
    it("returns valid when controller address is in the document", () => {
      const doc = {
        verificationMethod: [
          { blockchainAccountId: "eip155:1:0x1111111111111111111111111111111111111111" }
        ]
      };
      const result = verifyDidDocumentControllerDid(
        doc,
        "did:pkh:eip155:1:0x1111111111111111111111111111111111111111"
      );
      expect(result.valid).toBe(true);
    });

    it("returns invalid when controller address is not in the document", () => {
      const doc = {
        verificationMethod: [
          { blockchainAccountId: "eip155:1:0x2222222222222222222222222222222222222222" }
        ]
      };
      const result = verifyDidDocumentControllerDid(
        doc,
        "did:pkh:eip155:1:0x1111111111111111111111111111111111111111"
      );
      expect(result.valid).toBe(false);
      expect(result.reason).toContain("No matching address");
    });

    it("returns invalid when expectedControllerDid cannot resolve to address", () => {
      const doc = {
        verificationMethod: [
          { blockchainAccountId: "eip155:1:0x1111111111111111111111111111111111111111" }
        ]
      };
      const result = verifyDidDocumentControllerDid(doc, "did:web:example.com");
      expect(result.valid).toBe(false);
      expect(result.reason).toContain("does not resolve to an EVM address");
    });

    it("returns invalid for empty document", () => {
      const result = verifyDidDocumentControllerDid(
        {},
        "did:pkh:eip155:1:0x1111111111111111111111111111111111111111"
      );
      expect(result.valid).toBe(false);
    });

    it("is case-insensitive on address comparison", () => {
      const doc = {
        verificationMethod: [
          { blockchainAccountId: "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" }
        ]
      };
      const result = verifyDidDocumentControllerDid(
        doc,
        "did:pkh:eip155:1:0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      );
      expect(result.valid).toBe(true);
    });
  });

  describe("fetchDidDocument", () => {
    let fetchMock: ReturnType<typeof vi.fn>;

    beforeEach(() => {
      fetchMock = vi.fn();
      vi.stubGlobal("fetch", fetchMock);
    });

    afterEach(() => {
      vi.unstubAllGlobals();
    });

    it("fetches from normalized URL and returns JSON body", async () => {
      const doc = { id: "did:web:example.com", verificationMethod: [] };
      fetchMock.mockResolvedValue({
        ok: true,
        json: () => Promise.resolve(doc)
      });

      const result = await fetchDidDocument("example.com");
      expect(result).toEqual(doc);
      expect(fetchMock).toHaveBeenCalledWith("https://example.com/.well-known/did.json", {
        headers: { Accept: "application/json" }
      });
    });

    it("normalizes domain (lowercase, strips trailing dot)", async () => {
      fetchMock.mockResolvedValue({ ok: true, json: () => Promise.resolve({}) });

      await fetchDidDocument("EXAMPLE.COM.");
      expect(fetchMock).toHaveBeenCalledWith("https://example.com/.well-known/did.json", expect.any(Object));
    });

    it("throws NETWORK_ERROR when fetch rejects", async () => {
      fetchMock.mockRejectedValue(new Error("connection refused"));

      await expect(fetchDidDocument("example.com")).rejects.toThrow(OmaTrustError);
      await expect(fetchDidDocument("example.com")).rejects.toMatchObject({
        code: "NETWORK_ERROR",
        message: "Failed to fetch DID document"
      });
    });

    it("throws NETWORK_ERROR when response is not ok", async () => {
      fetchMock.mockResolvedValue({ ok: false, status: 404 });

      await expect(fetchDidDocument("example.com")).rejects.toThrow(OmaTrustError);
      await expect(fetchDidDocument("example.com")).rejects.toMatchObject({
        code: "NETWORK_ERROR",
        message: "DID document fetch failed"
      });
    });
  });
});
