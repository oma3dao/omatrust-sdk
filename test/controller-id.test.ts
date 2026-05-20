import { describe, expect, it } from "vitest";
import { isSameControllerId, extractControllerEvmAddress } from "../src/identity/controller-id";
import { jwkToDidJwk } from "../src/identity/jwk";

const EC_P256_JWK = {
  kty: "EC",
  crv: "P-256",
  x: "f83OJ3D7xI1Yp1V2iFIYA7n5OYXc4K1Uo7jY14FKMC4",
  y: "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
};

describe("identity/controller-id", () => {
  describe("isSameControllerId", () => {
    it("matches identical did:pkh DIDs", () => {
      const did = "did:pkh:eip155:1:0x1111111111111111111111111111111111111111";
      expect(isSameControllerId(did, did)).toBe(true);
    });

    it("matches did:pkh with different chain IDs (same EVM address)", () => {
      const chain1 = "did:pkh:eip155:1:0x1111111111111111111111111111111111111111";
      const chain137 = "did:pkh:eip155:137:0x1111111111111111111111111111111111111111";
      expect(isSameControllerId(chain1, chain137)).toBe(true);
    });

    it("matches did:pkh case-insensitively for EVM addresses", () => {
      const lower = "did:pkh:eip155:1:0x1111111111111111111111111111111111111111";
      const upper = "did:pkh:eip155:1:0x1111111111111111111111111111111111111111";
      expect(isSameControllerId(lower, upper)).toBe(true);
    });

    it("does not match different EVM addresses", () => {
      const a = "did:pkh:eip155:1:0x1111111111111111111111111111111111111111";
      const b = "did:pkh:eip155:1:0x2222222222222222222222222222222222222222";
      expect(isSameControllerId(a, b)).toBe(false);
    });

    it("matches identical did:jwk DIDs", () => {
      const did = jwkToDidJwk(EC_P256_JWK);
      expect(isSameControllerId(did, did)).toBe(true);
    });

    it("matches did:jwk with different property ordering (same key material)", () => {
      const jwk1 = { kty: "EC", crv: "P-256", x: "abc", y: "def" };
      const jwk2 = { y: "def", x: "abc", crv: "P-256", kty: "EC" };
      const did1 = jwkToDidJwk(jwk1);
      const did2 = jwkToDidJwk(jwk2);
      // Both should produce the same canonical did:jwk
      expect(isSameControllerId(did1, did2)).toBe(true);
    });

    it("does not match different did:jwk keys", () => {
      const jwk1 = { kty: "EC", crv: "P-256", x: "abc", y: "def" };
      const jwk2 = { kty: "EC", crv: "P-256", x: "xyz", y: "uvw" };
      const did1 = jwkToDidJwk(jwk1);
      const did2 = jwkToDidJwk(jwk2);
      expect(isSameControllerId(did1, did2)).toBe(false);
    });

    it("does not match did:pkh against did:jwk", () => {
      const pkh = "did:pkh:eip155:1:0x1111111111111111111111111111111111111111";
      const jwk = jwkToDidJwk(EC_P256_JWK);
      expect(isSameControllerId(pkh, jwk)).toBe(false);
    });

    it("returns false when did:jwk comparison throws during decode", () => {
      expect(
        isSameControllerId("did:jwk:!!!bad!!!", "did:jwk:!!!also-bad!!!")
      ).toBe(false);
    });

    it("handles malformed DIDs gracefully (returns false)", () => {
      expect(isSameControllerId("not-a-did", "also-not-a-did")).toBe(false);
      expect(isSameControllerId("did:pkh:eip155:1:0x1111111111111111111111111111111111111111", "garbage")).toBe(false);
    });
  });

  describe("extractControllerEvmAddress", () => {
    it("extracts address from did:pkh:eip155", () => {
      const addr = extractControllerEvmAddress("did:pkh:eip155:1:0x1111111111111111111111111111111111111111");
      expect(addr).toBe("0x1111111111111111111111111111111111111111");
    });

    it("returns null for did:jwk", () => {
      const did = jwkToDidJwk(EC_P256_JWK);
      expect(extractControllerEvmAddress(did)).toBeNull();
    });

    it("returns null for non-eip155 did:pkh", () => {
      expect(extractControllerEvmAddress("did:pkh:solana:mainnet:7xKXtest")).toBeNull();
    });

    it("returns null for malformed input", () => {
      expect(extractControllerEvmAddress("not-a-did")).toBeNull();
    });
  });
});
