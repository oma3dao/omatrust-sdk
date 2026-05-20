import { describe, expect, it } from "vitest";
import { OmaTrustError } from "../src/shared/errors";
import { base64url } from "jose";
import {
  validatePublicJwk,
  jwkToDidJwk,
  didJwkToJwk,
  publicJwkEquals,
} from "../src/identity/jwk";

// Sample EC P-256 public key
const EC_P256_JWK = {
  kty: "EC",
  crv: "P-256",
  x: "f83OJ3D7xI1Yp1V2iFIYA7n5OYXc4K1Uo7jY14FKMC4",
  y: "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
};

// Sample OKP Ed25519 public key
const OKP_ED25519_JWK = {
  kty: "OKP",
  crv: "Ed25519",
  x: "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
};

// Sample RSA public key (minimal)
const RSA_JWK = {
  kty: "RSA",
  n: "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM",
  e: "AQAB",
};

describe("identity/jwk", () => {
  describe("validatePublicJwk", () => {
    it("validates a valid EC P-256 JWK", () => {
      expect(validatePublicJwk(EC_P256_JWK)).toEqual({ valid: true });
    });

    it("validates a valid OKP Ed25519 JWK", () => {
      expect(validatePublicJwk(OKP_ED25519_JWK)).toEqual({ valid: true });
    });

    it("validates a valid RSA JWK", () => {
      expect(validatePublicJwk(RSA_JWK)).toEqual({ valid: true });
    });

    it("rejects null", () => {
      const result = validatePublicJwk(null);
      expect(result.valid).toBe(false);
      expect(result.error).toContain("non-null object");
    });

    it("rejects arrays", () => {
      const result = validatePublicJwk([]);
      expect(result.valid).toBe(false);
    });

    it("rejects missing kty", () => {
      const result = validatePublicJwk({ crv: "P-256", x: "abc", y: "def" });
      expect(result.valid).toBe(false);
      expect(result.error).toContain("kty");
    });

    it("rejects invalid kty", () => {
      const result = validatePublicJwk({ kty: "INVALID", x: "abc" });
      expect(result.valid).toBe(false);
      expect(result.error).toContain("kty");
    });

    it("rejects JWK with private key field 'd'", () => {
      const result = validatePublicJwk({ ...EC_P256_JWK, d: "secret" });
      expect(result.valid).toBe(false);
      expect(result.error).toContain("private key field");
      expect(result.error).toContain('"d"');
    });

    it("rejects JWK with RSA private fields", () => {
      const result = validatePublicJwk({ ...RSA_JWK, p: "prime1", q: "prime2" });
      expect(result.valid).toBe(false);
      expect(result.error).toContain("private key field");
    });

    it("rejects EC JWK missing required field 'y'", () => {
      const result = validatePublicJwk({ kty: "EC", crv: "P-256", x: "abc" });
      expect(result.valid).toBe(false);
      expect(result.error).toContain('"y"');
    });

    it("rejects OKP JWK missing required field 'x'", () => {
      const result = validatePublicJwk({ kty: "OKP", crv: "Ed25519" });
      expect(result.valid).toBe(false);
      expect(result.error).toContain('"x"');
    });

    it("rejects RSA JWK missing required field 'e'", () => {
      const result = validatePublicJwk({ kty: "RSA", n: "modulus" });
      expect(result.valid).toBe(false);
      expect(result.error).toContain('"e"');
    });
  });

  describe("jwkToDidJwk", () => {
    it("converts EC P-256 JWK to did:jwk", () => {
      const did = jwkToDidJwk(EC_P256_JWK);
      expect(did).toMatch(/^did:jwk:[A-Za-z0-9_-]+$/);
    });

    it("converts OKP Ed25519 JWK to did:jwk", () => {
      const did = jwkToDidJwk(OKP_ED25519_JWK);
      expect(did).toMatch(/^did:jwk:[A-Za-z0-9_-]+$/);
    });

    it("produces deterministic output regardless of property order", () => {
      const jwk1 = { kty: "EC", crv: "P-256", x: "abc", y: "def" };
      const jwk2 = { y: "def", x: "abc", crv: "P-256", kty: "EC" };
      expect(jwkToDidJwk(jwk1)).toBe(jwkToDidJwk(jwk2));
    });

    it("throws for JWK with private key material", () => {
      expect(() => jwkToDidJwk({ ...EC_P256_JWK, d: "secret" })).toThrow(OmaTrustError);
    });

    it("throws for invalid JWK (missing kty)", () => {
      expect(() => jwkToDidJwk({ crv: "P-256", x: "abc", y: "def" })).toThrow(OmaTrustError);
    });

    it("throws for non-object input", () => {
      expect(() => jwkToDidJwk("not-an-object" as unknown)).toThrow(OmaTrustError);
      expect(() => jwkToDidJwk(null as unknown)).toThrow(OmaTrustError);
    });
  });

  describe("didJwkToJwk", () => {
    it("round-trips EC P-256 JWK", () => {
      const did = jwkToDidJwk(EC_P256_JWK);
      const recovered = didJwkToJwk(did);
      // Should contain all the same key fields (sorted)
      expect(recovered.kty).toBe("EC");
      expect(recovered.crv).toBe("P-256");
      expect(recovered.x).toBe(EC_P256_JWK.x);
      expect(recovered.y).toBe(EC_P256_JWK.y);
    });

    it("round-trips OKP Ed25519 JWK", () => {
      const did = jwkToDidJwk(OKP_ED25519_JWK);
      const recovered = didJwkToJwk(did);
      expect(recovered.kty).toBe("OKP");
      expect(recovered.crv).toBe("Ed25519");
      expect(recovered.x).toBe(OKP_ED25519_JWK.x);
    });

    it("throws for non-did:jwk input", () => {
      expect(() => didJwkToJwk("did:web:example.com")).toThrow(OmaTrustError);
      expect(() => didJwkToJwk("not-a-did")).toThrow(OmaTrustError);
    });

    it("throws when did:jwk has wrong part count or empty identifier", () => {
      expect(() => didJwkToJwk("did:jwk:part1:part2")).toThrow(OmaTrustError);
      expect(() => didJwkToJwk("did:jwk:")).toThrow(OmaTrustError);
    });

    it("throws for malformed base64url", () => {
      expect(() => didJwkToJwk("did:jwk:!!!invalid!!!")).toThrow(OmaTrustError);
    });

    it("throws for valid base64url that is not JSON", () => {
      // "hello" in base64url
      const encoded = base64url.encode(new TextEncoder().encode("hello"));
      expect(() => didJwkToJwk(`did:jwk:${encoded}`)).toThrow(OmaTrustError);
    });

    it("throws for JSON that is not a plain object (array)", () => {
      const encoded = base64url.encode(new TextEncoder().encode(JSON.stringify([1, 2, 3])));
      expect(() => didJwkToJwk(`did:jwk:${encoded}`)).toThrow(OmaTrustError);
    });

    it("throws for JSON that is not a valid public JWK", () => {
      const encoded = base64url.encode(
        new TextEncoder().encode(JSON.stringify({ foo: "bar" }))
      );
      expect(() => didJwkToJwk(`did:jwk:${encoded}`)).toThrow(OmaTrustError);
    });

    it("throws for JWK containing private key material", () => {
      const privateJwk = { ...EC_P256_JWK, d: "secret" };
      const encoded = base64url.encode(
        new TextEncoder().encode(JSON.stringify(privateJwk))
      );
      expect(() => didJwkToJwk(`did:jwk:${encoded}`)).toThrow(OmaTrustError);
    });
  });

  describe("publicJwkEquals", () => {
    it("returns true for identical JWKs", () => {
      expect(publicJwkEquals(EC_P256_JWK, { ...EC_P256_JWK })).toBe(true);
    });

    it("returns true regardless of property order", () => {
      const a = { kty: "EC", crv: "P-256", x: "abc", y: "def" };
      const b = { y: "def", x: "abc", crv: "P-256", kty: "EC" };
      expect(publicJwkEquals(a, b)).toBe(true);
    });

    it("ignores metadata fields (kid, use, alg, key_ops, ext)", () => {
      const a = { ...EC_P256_JWK, kid: "key-1", use: "sig", alg: "ES256" };
      const b = { ...EC_P256_JWK, kid: "key-2", use: "enc", alg: "ES384" };
      expect(publicJwkEquals(a, b)).toBe(true);
    });

    it("returns false for different keys", () => {
      const a = { kty: "EC", crv: "P-256", x: "abc", y: "def" };
      const b = { kty: "EC", crv: "P-256", x: "xyz", y: "def" };
      expect(publicJwkEquals(a, b)).toBe(false);
    });

    it("returns false for different key types", () => {
      expect(publicJwkEquals(EC_P256_JWK, OKP_ED25519_JWK)).toBe(false);
    });

    it("throws if first JWK contains private key material", () => {
      expect(() =>
        publicJwkEquals({ ...EC_P256_JWK, d: "secret" }, EC_P256_JWK)
      ).toThrow(OmaTrustError);
    });

    it("throws if second JWK contains private key material", () => {
      expect(() =>
        publicJwkEquals(EC_P256_JWK, { ...EC_P256_JWK, d: "secret" })
      ).toThrow(OmaTrustError);
    });

    it("throws for non-object input", () => {
      expect(() => publicJwkEquals("string" as unknown, EC_P256_JWK)).toThrow(OmaTrustError);
      expect(() => publicJwkEquals(EC_P256_JWK, null as unknown)).toThrow(OmaTrustError);
    });
  });
});


describe("identity/jwk – thumbprint", () => {
  describe("computeJwkThumbprint", () => {
    it("returns a base64url string for a valid EC JWK", async () => {
      const { computeJwkThumbprint } = await import("../src/identity/jwk");
      const thumbprint = await computeJwkThumbprint(EC_P256_JWK);
      expect(thumbprint).toMatch(/^[A-Za-z0-9_-]+$/);
      expect(thumbprint.length).toBeGreaterThan(0);
    });

    it("returns the same thumbprint regardless of property order", async () => {
      const { computeJwkThumbprint } = await import("../src/identity/jwk");
      const a = { kty: "EC", crv: "P-256", x: "abc", y: "def" };
      const b = { y: "def", x: "abc", crv: "P-256", kty: "EC" };
      const ta = await computeJwkThumbprint(a);
      const tb = await computeJwkThumbprint(b);
      expect(ta).toBe(tb);
    });

    it("returns different thumbprints for different keys", async () => {
      const { computeJwkThumbprint } = await import("../src/identity/jwk");
      const ta = await computeJwkThumbprint(EC_P256_JWK);
      const tb = await computeJwkThumbprint(OKP_ED25519_JWK);
      expect(ta).not.toBe(tb);
    });

    it("throws for JWK with private key material", async () => {
      const { computeJwkThumbprint } = await import("../src/identity/jwk");
      await expect(
        computeJwkThumbprint({ ...EC_P256_JWK, d: "secret" })
      ).rejects.toThrow(OmaTrustError);
    });

    it("returns a sha384 thumbprint when requested", async () => {
      const { computeJwkThumbprint } = await import("../src/identity/jwk");
      const tp = await computeJwkThumbprint(EC_P256_JWK, "sha384");
      expect(tp).toMatch(/^[A-Za-z0-9_-]+$/);
      const tp256 = await computeJwkThumbprint(EC_P256_JWK, "sha256");
      expect(tp).not.toBe(tp256);
    });

    it("returns a sha512 thumbprint when requested", async () => {
      const { computeJwkThumbprint } = await import("../src/identity/jwk");
      const tp = await computeJwkThumbprint(EC_P256_JWK, "sha512");
      expect(tp).toMatch(/^[A-Za-z0-9_-]+$/);
    });

    it("throws for invalid JWK input to thumbprint", async () => {
      const { computeJwkThumbprint } = await import("../src/identity/jwk");
      await expect(computeJwkThumbprint(null)).rejects.toThrow(OmaTrustError);
    });
  });

  describe("formatJktValue", () => {
    it("returns jkt=S256:<thumbprint> format", async () => {
      const { formatJktValue } = await import("../src/identity/jwk");
      const jkt = await formatJktValue(EC_P256_JWK);
      expect(jkt).toMatch(/^jkt=S256:[A-Za-z0-9_-]+$/);
    });
  });
});
