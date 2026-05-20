import { describe, expect, it } from "vitest";
import { base64url } from "jose";
import { OmaTrustError } from "../src/shared/errors";
import {
  isPrivateKeyDid,
  normalizeDid,
  normalizeDidJwk,
  validatePrivateKeyDid,
} from "../src/identity/did";
import { jwkToDidJwk } from "../src/identity/jwk";

const EC_P256_JWK = {
  kty: "EC",
  crv: "P-256",
  x: "f83OJ3D7xI1Yp1V2iFIYA7n5OYXc4K1Uo7jY14FKMC4",
  y: "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
};

describe("identity/did – private-key validation", () => {
  describe("validatePrivateKeyDid", () => {
    it("rejects empty and non-string input", () => {
      expect(validatePrivateKeyDid("")).toEqual({
        valid: false,
        method: null,
        error: "DID must be a non-empty string",
      });
      expect(validatePrivateKeyDid("   ")).toEqual({
        valid: false,
        method: null,
        error: "DID must be a non-empty string",
      });
    });

    it("rejects unknown DID methods", () => {
      expect(validatePrivateKeyDid("did:web:example.com")).toEqual({
        valid: false,
        method: null,
        error: 'DID method "web" is not a recognized private-key method',
      });
      expect(validatePrivateKeyDid("not-a-did")).toEqual({
        valid: false,
        method: null,
        error: "Invalid DID format",
      });
    });

    describe("did:pkh", () => {
      const validPkh = "did:pkh:eip155:1:0x1111111111111111111111111111111111111111";

      it("accepts a valid eip155 did:pkh", () => {
        expect(validatePrivateKeyDid(validPkh)).toEqual({ valid: true, method: "pkh" });
        expect(isPrivateKeyDid(validPkh)).toBe(true);
      });

      it("rejects wrong part count", () => {
        const result = validatePrivateKeyDid("did:pkh:eip155:1");
        expect(result.valid).toBe(false);
        expect(result.method).toBe("pkh");
        expect(result.error).toContain("5 colon-separated parts");
      });

      it("rejects invalid CAIP-2 namespace", () => {
        const result = validatePrivateKeyDid(
          "did:pkh:INVALID_NS:1:0x1111111111111111111111111111111111111111"
        );
        expect(result.valid).toBe(false);
        expect(result.error).toContain("Invalid CAIP-2 namespace");
      });

      it("rejects missing namespace", () => {
        const result = validatePrivateKeyDid("did:pkh::1:0x1111111111111111111111111111111111111111");
        expect(result.valid).toBe(false);
        expect(result.error).toBe("Missing namespace");
      });

      it("rejects missing chain ID and address", () => {
        expect(validatePrivateKeyDid("did:pkh:eip155::0x1111111111111111111111111111111111111111")).toMatchObject({
          valid: false,
          error: "Missing chain ID (reference)",
        });
        expect(validatePrivateKeyDid("did:pkh:eip155:1:")).toMatchObject({
          valid: false,
          error: "Missing address",
        });
      });

      it("rejects non-numeric eip155 chain ID", () => {
        const result = validatePrivateKeyDid(
          "did:pkh:eip155:mainnet:0x1111111111111111111111111111111111111111"
        );
        expect(result.valid).toBe(false);
        expect(result.error).toContain("chain ID");
      });

      it("rejects invalid EVM address for eip155", () => {
        const result = validatePrivateKeyDid("did:pkh:eip155:1:not-an-address");
        expect(result.valid).toBe(false);
        expect(result.error).toContain("Invalid EVM address");
      });

      it("accepts non-eip155 namespaces with non-empty address (permissive)", () => {
        const result = validatePrivateKeyDid("did:pkh:solana:mainnet:7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuFoxokU4");
        expect(result).toEqual({ valid: true, method: "pkh" });
      });
    });

    describe("did:jwk", () => {
      it("accepts a valid did:jwk", () => {
        const did = jwkToDidJwk(EC_P256_JWK);
        expect(validatePrivateKeyDid(did)).toEqual({ valid: true, method: "jwk" });
      });

      it("rejects wrong part count", () => {
        const result = validatePrivateKeyDid("did:jwk:part1:part2");
        expect(result.valid).toBe(false);
        expect(result.method).toBe("jwk");
        expect(result.error).toContain("3 colon-separated parts");
      });

      it("rejects empty identifier", () => {
        expect(validatePrivateKeyDid("did:jwk:")).toMatchObject({
          valid: false,
          error: "Missing base64url-encoded JWK identifier",
        });
      });

      it("rejects invalid base64url characters", () => {
        const result = validatePrivateKeyDid("did:jwk:!!!invalid!!!");
        expect(result.valid).toBe(false);
        expect(result.error).toContain("invalid base64url");
      });

      it("rejects undecodable identifier", () => {
        const result = validatePrivateKeyDid("did:jwk:!!!not-valid-base64url!!!");
        expect(result.valid).toBe(false);
        expect(result.error).toContain("invalid base64url");
      });

      it("rejects non-JSON decoded payload", () => {
        const encoded = base64url.encode(new TextEncoder().encode("not-json"));
        const result = validatePrivateKeyDid(`did:jwk:${encoded}`);
        expect(result.valid).toBe(false);
        expect(result.error).toContain("not valid JSON");
      });

      it("rejects decoded JSON that is not an object", () => {
        const encoded = base64url.encode(new TextEncoder().encode("[1,2,3]"));
        const result = validatePrivateKeyDid(`did:jwk:${encoded}`);
        expect(result.valid).toBe(false);
        expect(result.error).toContain("must be a JSON object");
      });

      it("rejects invalid kty", () => {
        const encoded = base64url.encode(new TextEncoder().encode(JSON.stringify({ kty: "INVALID" })));
        const result = validatePrivateKeyDid(`did:jwk:${encoded}`);
        expect(result.valid).toBe(false);
        expect(result.error).toContain("kty");
      });

      it("rejects JWK with private key material", () => {
        const encoded = base64url.encode(
          new TextEncoder().encode(JSON.stringify({ ...EC_P256_JWK, d: "secret" }))
        );
        const result = validatePrivateKeyDid(`did:jwk:${encoded}`);
        expect(result.valid).toBe(false);
        expect(result.error).toContain("private key component");
      });
    });
  });

  describe("normalizeDidJwk", () => {
    it("returns a valid did:jwk unchanged", () => {
      const did = jwkToDidJwk(EC_P256_JWK);
      expect(normalizeDidJwk(did)).toBe(did);
    });

    it("throws for non-jwk input", () => {
      expect(() => normalizeDidJwk("did:web:example.com")).toThrow(OmaTrustError);
    });

    it("throws when structure is invalid", () => {
      expect(() => normalizeDidJwk("did:jwk:!!!")).toThrow(OmaTrustError);
    });
  });

  describe("normalizeDid – did:jwk routing", () => {
    it("routes did:jwk through normalizeDidJwk", () => {
      const did = jwkToDidJwk(EC_P256_JWK);
      expect(normalizeDid(did)).toBe(did);
    });
  });
});
