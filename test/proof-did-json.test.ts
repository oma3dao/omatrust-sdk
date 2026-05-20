import { describe, expect, it, vi, beforeEach, afterEach } from "vitest";
import { jwkToDidJwk } from "../src/identity/jwk";
import { OmaTrustError } from "../src/shared/errors";
import {
  extractEvmAddressesFromDidDocument,
  extractJwksFromDidDocument,
  fetchDidDocument,
  verifyDidJsonControllerDid,
  verifyDidDocumentControllerDid,
} from "../src/reputation/proof/did-json";

describe("proof/did-json", () => {
  describe("extractEvmAddressesFromDidDocument", () => {
    it("returns empty array when verificationMethod is missing", () => {
      expect(extractEvmAddressesFromDidDocument({})).toEqual([]);
    });

    it("returns empty array when verificationMethod is not an array", () => {
      expect(extractEvmAddressesFromDidDocument({ verificationMethod: "not-array" })).toEqual([]);
    });

    it("extracts address from blockchainAccountId (raw address)", () => {
      const doc = {
        verificationMethod: [
          { blockchainAccountId: "0x1111111111111111111111111111111111111111" }
        ]
      };
      const addresses = extractEvmAddressesFromDidDocument(doc);
      expect(addresses).toHaveLength(1);
      expect(addresses[0].toLowerCase()).toBe("0x1111111111111111111111111111111111111111");
    });

    it("extracts address from blockchainAccountId (CAIP-10 format)", () => {
      const doc = {
        verificationMethod: [
          { blockchainAccountId: "eip155:1:0x1111111111111111111111111111111111111111" }
        ]
      };
      const addresses = extractEvmAddressesFromDidDocument(doc);
      expect(addresses).toHaveLength(1);
    });

    it("extracts address from publicKeyHex", () => {
      const doc = {
        verificationMethod: [
          { publicKeyHex: "0x2222222222222222222222222222222222222222" }
        ]
      };
      const addresses = extractEvmAddressesFromDidDocument(doc);
      expect(addresses).toHaveLength(1);
      expect(addresses[0].toLowerCase()).toBe("0x2222222222222222222222222222222222222222");
    });

    it("adds 0x prefix to publicKeyHex if missing", () => {
      const doc = {
        verificationMethod: [
          { publicKeyHex: "3333333333333333333333333333333333333333" }
        ]
      };
      const addresses = extractEvmAddressesFromDidDocument(doc);
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
      const addresses = extractEvmAddressesFromDidDocument(doc);
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
      const addresses = extractEvmAddressesFromDidDocument(doc);
      expect(addresses).toHaveLength(1);
    });

    it("handles multiple valid methods", () => {
      const doc = {
        verificationMethod: [
          { blockchainAccountId: "0x1111111111111111111111111111111111111111" },
          { blockchainAccountId: "0x2222222222222222222222222222222222222222" }
        ]
      };
      const addresses = extractEvmAddressesFromDidDocument(doc);
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
      expect(result.reason).toContain("No matching address found");
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

  describe("extractJwksFromDidDocument", () => {
    it("returns empty array when verificationMethod is missing", () => {
      expect(extractJwksFromDidDocument({})).toEqual([]);
    });

    it("collects publicKeyJwk objects from verification methods", () => {
      const jwk = { kty: "EC", crv: "P-256", x: "a", y: "b" };
      expect(
        extractJwksFromDidDocument({
          verificationMethod: [{ publicKeyJwk: jwk }, { publicKeyJwk: "not-an-object" }],
        })
      ).toEqual([jwk]);
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
        message: "DID document fetch failed: 404"
      });
    });
  });

  describe("verifyDidJsonControllerDid", () => {
    it("verifies controller DID through a fetched DID document", async () => {
      const result = await verifyDidJsonControllerDid(
        "example.com",
        "did:pkh:eip155:1:0x1111111111111111111111111111111111111111",
        {
          fetchDidDocument: vi.fn().mockResolvedValue({
            verificationMethod: [
              { blockchainAccountId: "eip155:1:0x1111111111111111111111111111111111111111" }
            ]
          })
        }
      );

      expect(result.valid).toBe(true);
    });

    it("returns invalid when the DID document does not contain the controller address", async () => {
      const result = await verifyDidJsonControllerDid(
        "example.com",
        "did:pkh:eip155:1:0x1111111111111111111111111111111111111111",
        {
          fetchDidDocument: vi.fn().mockResolvedValue({
            verificationMethod: [
              { blockchainAccountId: "eip155:1:0x2222222222222222222222222222222222222222" }
            ]
          })
        }
      );

      expect(result.valid).toBe(false);
      expect(result.reason).toContain("No matching address found");
    });

    it("throws INVALID_INPUT for an empty domain", async () => {
      await expect(
        verifyDidJsonControllerDid(
          "",
          "did:pkh:eip155:1:0x1111111111111111111111111111111111111111"
        )
      ).rejects.toMatchObject({
        code: "INVALID_INPUT"
      });
    });
  });

  describe("verifyDidDocumentControllerDid — did:jwk", () => {
    const EC_P256_JWK = {
      kty: "EC",
      crv: "P-256",
      x: "f83OJ3D7xI1Yp1V2iFIYA7n5OYXc4K1Uo7jY14FKMC4",
      y: "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
    };

    it("returns valid when document publicKeyJwk matches did:jwk controller", () => {
      const controllerDid = jwkToDidJwk(EC_P256_JWK);
      const doc = {
        verificationMethod: [
          {
            id: "did:web:api.example.com#k1",
            type: "JsonWebKey2020",
            publicKeyJwk: EC_P256_JWK,
          },
        ],
      };
      const result = verifyDidDocumentControllerDid(doc, controllerDid);
      expect(result.valid).toBe(true);
    });

    it("returns invalid when did:jwk controller cannot be decoded", () => {
      const result = verifyDidDocumentControllerDid(
        { verificationMethod: [] },
        "did:jwk:!!!not-valid-base64url!!!"
      );
      expect(result.valid).toBe(false);
      expect(result.reason).toContain("Failed to decode did:jwk");
    });

    it("returns invalid when publicKeyJwk comparison throws", () => {
      const controllerDid = jwkToDidJwk(EC_P256_JWK);
      const doc = {
        verificationMethod: [
          {
            id: "did:web:api.example.com#k1",
            type: "JsonWebKey2020",
            publicKeyJwk: { kty: "EC", crv: "P-256", x: "!!!", y: "!!!" },
          },
        ],
      };
      const result = verifyDidDocumentControllerDid(doc, controllerDid);
      expect(result.valid).toBe(false);
      expect(result.reason).toContain("No matching publicKeyJwk");
    });

    it("returns invalid when no publicKeyJwk matches did:jwk", () => {
      const controllerDid = jwkToDidJwk(EC_P256_JWK);
      const otherKey = {
        kty: "OKP",
        crv: "Ed25519",
        x: "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
      };
      const doc = {
        verificationMethod: [
          {
            id: "did:web:api.example.com#k1",
            type: "JsonWebKey2020",
            publicKeyJwk: otherKey,
          },
        ],
      };
      const result = verifyDidDocumentControllerDid(doc, controllerDid);
      expect(result.valid).toBe(false);
      expect(result.reason).toContain("No matching publicKeyJwk");
    });
  });
});
