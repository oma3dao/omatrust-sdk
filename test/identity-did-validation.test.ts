import { describe, expect, it } from "vitest";
import { base64url } from "jose";
import { OmaTrustError } from "../src/shared/errors";
import {
  isPrivateKeyDid,
  normalizeDid,
  normalizeDidJwk,
  validatePrivateKeyDid,
  computeDidHash,
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

      it("rejects solana address with invalid base58 characters", () => {
        // 'O' and '0' are not valid base58 characters
        const result = validatePrivateKeyDid("did:pkh:solana:mainnet:0OIl1234567890abcdefghijkl");
        expect(result.valid).toBe(false);
        expect(result.error).toContain("Invalid Solana address");
      });

      it("rejects solana address that is too short", () => {
        const result = validatePrivateKeyDid("did:pkh:solana:mainnet:abc");
        expect(result.valid).toBe(false);
        expect(result.error).toContain("Invalid Solana address");
      });

      it("rejects solana address that is too long", () => {
        const result = validatePrivateKeyDid("did:pkh:solana:mainnet:" + "A".repeat(50));
        expect(result.valid).toBe(false);
        expect(result.error).toContain("Invalid Solana address");
      });

      it("accepts valid solana addresses of various lengths", () => {
        // 32-44 chars of valid base58
        expect(validatePrivateKeyDid("did:pkh:solana:mainnet:11111111111111111111111111111114")).toEqual({ valid: true, method: "pkh" });
        expect(validatePrivateKeyDid("did:pkh:solana:devnet:TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")).toEqual({ valid: true, method: "pkh" });
      });

      it("accepts non-eip155/non-solana namespaces with permissive check", () => {
        const result = validatePrivateKeyDid("did:pkh:bip122:000000000019d6689c085ae165831e93:128Lkh3S7CkDTBZ8W7BbpsN3YYizJMp8p6");
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
        expect(result.error).toContain("private key");
      });

      it("rejects EC JWK missing required public key fields", () => {
        const incompleteEc = { kty: "EC", crv: "P-256", x: "abc" }; // missing y
        const encoded = base64url.encode(new TextEncoder().encode(JSON.stringify(incompleteEc)));
        const result = validatePrivateKeyDid(`did:jwk:${encoded}`);
        expect(result.valid).toBe(false);
        expect(result.error).toContain('"y"');
      });

      it("rejects OKP JWK missing required public key fields", () => {
        const incompleteOkp = { kty: "OKP", crv: "Ed25519" }; // missing x
        const encoded = base64url.encode(new TextEncoder().encode(JSON.stringify(incompleteOkp)));
        const result = validatePrivateKeyDid(`did:jwk:${encoded}`);
        expect(result.valid).toBe(false);
        expect(result.error).toContain('"x"');
      });

      it("rejects RSA JWK missing required public key fields", () => {
        const incompleteRsa = { kty: "RSA", n: "abc" }; // missing e
        const encoded = base64url.encode(new TextEncoder().encode(JSON.stringify(incompleteRsa)));
        const result = validatePrivateKeyDid(`did:jwk:${encoded}`);
        expect(result.valid).toBe(false);
        expect(result.error).toContain('"e"');
      });

      it("accepts valid OKP did:jwk", () => {
        const okpJwk = { kty: "OKP", crv: "Ed25519", x: "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo" };
        const encoded = base64url.encode(new TextEncoder().encode(JSON.stringify(okpJwk)));
        const result = validatePrivateKeyDid(`did:jwk:${encoded}`);
        expect(result).toEqual({ valid: true, method: "jwk" });
      });

      it("accepts valid RSA did:jwk", () => {
        const rsaJwk = { kty: "RSA", n: "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM", e: "AQAB" };
        const encoded = base64url.encode(new TextEncoder().encode(JSON.stringify(rsaJwk)));
        const result = validatePrivateKeyDid(`did:jwk:${encoded}`);
        expect(result).toEqual({ valid: true, method: "jwk" });
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

  describe("normalizeDid – fragment stripping", () => {
    it("strips fragment from did:key before normalizing", () => {
      const bare = "did:key:z6MkpPanM5XyyGcp6HAwJSm7SmWmmb4MpfmBfgRSq4t7GokV";
      const withFragment = `${bare}#z6MkpPanM5XyyGcp6HAwJSm7SmWmmb4MpfmBfgRSq4t7GokV`;
      expect(normalizeDid(withFragment)).toBe(normalizeDid(bare));
    });

    it("strips fragment from did:web before normalizing", () => {
      expect(normalizeDid("did:web:example.com#key-1")).toBe(normalizeDid("did:web:example.com"));
    });

    it("strips fragment from did:pkh before normalizing", () => {
      const bare = "did:pkh:eip155:1:0x1234567890123456789012345678901234567890";
      const withFragment = `${bare}#controller`;
      expect(normalizeDid(withFragment)).toBe(normalizeDid(bare));
    });

    it("produces same computeDidHash with and without fragment", () => {
      const bare = "did:key:z6MkpPanM5XyyGcp6HAwJSm7SmWmmb4MpfmBfgRSq4t7GokV";
      const withFragment = `${bare}#z6MkpPanM5XyyGcp6HAwJSm7SmWmmb4MpfmBfgRSq4t7GokV`;
      expect(computeDidHash(withFragment)).toBe(computeDidHash(bare));
    });
  });
});
