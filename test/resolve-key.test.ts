import { describe, expect, it } from "vitest";
import { OmaTrustError } from "../src/shared/errors";
import {
  resolveDidUrlToPublicKey,
  resolveDidUrlToControllerDid,
} from "../src/identity/resolve-key";

// ---------------------------------------------------------------------------
// Test Fixtures
// ---------------------------------------------------------------------------

const EC_P256_JWK = {
  kty: "EC",
  crv: "P-256",
  x: "f83OJ3D7xI1Yp1V2iFIYA7n5OYXc4K1Uo7jY14FKMC4",
  y: "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
};

const OKP_ED25519_JWK = {
  kty: "OKP",
  crv: "Ed25519",
  x: "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
};

/** Mock DID document with two verification methods */
const MOCK_DID_DOCUMENT = {
  "@context": ["https://www.w3.org/ns/did/v1"],
  id: "did:web:api.example.com",
  verificationMethod: [
    {
      id: "did:web:api.example.com#key-1",
      type: "JsonWebKey2020",
      controller: "did:web:api.example.com",
      publicKeyJwk: EC_P256_JWK,
    },
    {
      id: "did:web:api.example.com#key-2",
      type: "JsonWebKey2020",
      controller: "did:web:api.example.com",
      publicKeyJwk: OKP_ED25519_JWK,
    },
  ],
};

/** Mock DID document with fragment-only IDs */
const MOCK_DID_DOCUMENT_FRAGMENT_IDS = {
  "@context": ["https://www.w3.org/ns/did/v1"],
  id: "did:web:short.example.com",
  verificationMethod: [
    {
      id: "#signing-key",
      type: "JsonWebKey2020",
      controller: "did:web:short.example.com",
      publicKeyJwk: EC_P256_JWK,
    },
  ],
};

/** Mock DID document with no publicKeyJwk */
const MOCK_DID_DOCUMENT_NO_JWK = {
  "@context": ["https://www.w3.org/ns/did/v1"],
  id: "did:web:nojwk.example.com",
  verificationMethod: [
    {
      id: "did:web:nojwk.example.com#key-1",
      type: "EcdsaSecp256k1VerificationKey2019",
      controller: "did:web:nojwk.example.com",
      publicKeyHex: "0x1234567890abcdef",
    },
  ],
};

/** Mock DID document with private key material in JWK */
const MOCK_DID_DOCUMENT_PRIVATE_KEY = {
  "@context": ["https://www.w3.org/ns/did/v1"],
  id: "did:web:bad.example.com",
  verificationMethod: [
    {
      id: "did:web:bad.example.com#key-1",
      type: "JsonWebKey2020",
      controller: "did:web:bad.example.com",
      publicKeyJwk: { ...EC_P256_JWK, d: "secret-private-key" },
    },
  ],
};

/** Mock DID document with no verification methods */
const MOCK_DID_DOCUMENT_EMPTY = {
  "@context": ["https://www.w3.org/ns/did/v1"],
  id: "did:web:empty.example.com",
};

// ---------------------------------------------------------------------------
// Mock fetcher factory
// ---------------------------------------------------------------------------

function mockFetcher(documents: Record<string, Record<string, unknown>>) {
  return async (domain: string): Promise<Record<string, unknown>> => {
    const doc = documents[domain];
    if (!doc) {
      throw new OmaTrustError("NETWORK_ERROR", "DID document not found", { domain });
    }
    return doc;
  };
}

const defaultMockFetcher = mockFetcher({
  "api.example.com": MOCK_DID_DOCUMENT,
  "short.example.com": MOCK_DID_DOCUMENT_FRAGMENT_IDS,
  "nojwk.example.com": MOCK_DID_DOCUMENT_NO_JWK,
  "bad.example.com": MOCK_DID_DOCUMENT_PRIVATE_KEY,
  "empty.example.com": MOCK_DID_DOCUMENT_EMPTY,
});

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("identity/resolve-key", () => {
  describe("resolveDidUrlToPublicKey", () => {
    it("resolves public key from full DID URL", async () => {
      const result = await resolveDidUrlToPublicKey("did:web:api.example.com#key-1", {
        fetchDidDocument: defaultMockFetcher,
      });

      expect(result.didUrl).toBe("did:web:api.example.com#key-1");
      expect(result.did).toBe("did:web:api.example.com");
      expect(result.fragment).toBe("key-1");
      expect(result.publicKeyJwk).toEqual(EC_P256_JWK);
      expect(result.verificationMethodId).toBe("did:web:api.example.com#key-1");
    });

    it("resolves second key from same document", async () => {
      const result = await resolveDidUrlToPublicKey("did:web:api.example.com#key-2", {
        fetchDidDocument: defaultMockFetcher,
      });

      expect(result.publicKeyJwk).toEqual(OKP_ED25519_JWK);
      expect(result.verificationMethodId).toBe("did:web:api.example.com#key-2");
    });

    it("resolves by fragment when method IDs use fragment-only format", async () => {
      const result = await resolveDidUrlToPublicKey("did:web:short.example.com#signing-key", {
        fetchDidDocument: defaultMockFetcher,
      });

      expect(result.publicKeyJwk).toEqual(EC_P256_JWK);
      expect(result.verificationMethodId).toBe("#signing-key");
    });

    it("fails when verification method is missing", async () => {
      await expect(
        resolveDidUrlToPublicKey("did:web:api.example.com#nonexistent", {
          fetchDidDocument: defaultMockFetcher,
        })
      ).rejects.toThrow(OmaTrustError);

      try {
        await resolveDidUrlToPublicKey("did:web:api.example.com#nonexistent", {
          fetchDidDocument: defaultMockFetcher,
        });
      } catch (e) {
        expect((e as OmaTrustError).code).toBe("KEY_NOT_FOUND");
      }
    });

    it("fails when publicKeyJwk is absent", async () => {
      await expect(
        resolveDidUrlToPublicKey("did:web:nojwk.example.com#key-1", {
          fetchDidDocument: defaultMockFetcher,
        })
      ).rejects.toThrow(OmaTrustError);

      try {
        await resolveDidUrlToPublicKey("did:web:nojwk.example.com#key-1", {
          fetchDidDocument: defaultMockFetcher,
        });
      } catch (e) {
        expect((e as OmaTrustError).code).toBe("KEY_NOT_FOUND");
        expect((e as OmaTrustError).message).toContain("publicKeyJwk");
      }
    });

    it("fails when publicKeyJwk contains private key material", async () => {
      await expect(
        resolveDidUrlToPublicKey("did:web:bad.example.com#key-1", {
          fetchDidDocument: defaultMockFetcher,
        })
      ).rejects.toThrow(OmaTrustError);

      try {
        await resolveDidUrlToPublicKey("did:web:bad.example.com#key-1", {
          fetchDidDocument: defaultMockFetcher,
        });
      } catch (e) {
        expect((e as OmaTrustError).code).toBe("INVALID_JWK");
      }
    });

    it("fails when DID document has no verificationMethod array", async () => {
      await expect(
        resolveDidUrlToPublicKey("did:web:empty.example.com#key-1", {
          fetchDidDocument: defaultMockFetcher,
        })
      ).rejects.toThrow(OmaTrustError);
    });

    it("fails for unsupported DID methods", async () => {
      await expect(
        resolveDidUrlToPublicKey("did:pkh:eip155:1:0xabc#key-1", {
          fetchDidDocument: defaultMockFetcher,
        })
      ).rejects.toThrow(OmaTrustError);

      try {
        await resolveDidUrlToPublicKey("did:pkh:eip155:1:0xabc#key-1", {
          fetchDidDocument: defaultMockFetcher,
        });
      } catch (e) {
        expect((e as OmaTrustError).code).toBe("UNSUPPORTED_DID_METHOD");
      }
    });

    it("fails for empty input", async () => {
      await expect(resolveDidUrlToPublicKey("")).rejects.toThrow(OmaTrustError);
    });

    it("fails for malformed DID URL", async () => {
      await expect(resolveDidUrlToPublicKey("not-a-did#key")).rejects.toThrow(OmaTrustError);
    });

    it("fails when did:web has no domain segment", async () => {
      await expect(
        resolveDidUrlToPublicKey("did:web:#key-1", {
          fetchDidDocument: defaultMockFetcher,
        })
      ).rejects.toMatchObject({ code: "INVALID_DID_URL" });
    });
  });

  describe("resolveDidUrlToControllerDid", () => {
    it("resolves and derives did:jwk controller DID", async () => {
      const result = await resolveDidUrlToControllerDid("did:web:api.example.com#key-1", {
        fetchDidDocument: defaultMockFetcher,
      });

      expect(result.didUrl).toBe("did:web:api.example.com#key-1");
      expect(result.did).toBe("did:web:api.example.com");
      expect(result.fragment).toBe("key-1");
      expect(result.publicKeyJwk).toEqual(EC_P256_JWK);
      expect(result.controllerDid).toMatch(/^did:jwk:[A-Za-z0-9_-]+$/);
    });

    it("derived did:jwk is deterministic for same key", async () => {
      const result1 = await resolveDidUrlToControllerDid("did:web:api.example.com#key-1", {
        fetchDidDocument: defaultMockFetcher,
      });
      const result2 = await resolveDidUrlToControllerDid("did:web:api.example.com#key-1", {
        fetchDidDocument: defaultMockFetcher,
      });

      expect(result1.controllerDid).toBe(result2.controllerDid);
    });

    it("different keys produce different did:jwk values", async () => {
      const result1 = await resolveDidUrlToControllerDid("did:web:api.example.com#key-1", {
        fetchDidDocument: defaultMockFetcher,
      });
      const result2 = await resolveDidUrlToControllerDid("did:web:api.example.com#key-2", {
        fetchDidDocument: defaultMockFetcher,
      });

      expect(result1.controllerDid).not.toBe(result2.controllerDid);
    });

    it("propagates errors from resolveDidUrlToPublicKey", async () => {
      await expect(
        resolveDidUrlToControllerDid("did:web:api.example.com#nonexistent", {
          fetchDidDocument: defaultMockFetcher,
        })
      ).rejects.toThrow(OmaTrustError);
    });
  });
});
