import { describe, expect, it } from "vitest";
import { OmaTrustError } from "../src/shared/errors";
import { parseDidUrl, isDidUrl, assertBareDid } from "../src/identity/did-url";

describe("identity/did-url", () => {
  describe("parseDidUrl", () => {
    it("parses a DID URL with fragment", () => {
      const result = parseDidUrl("did:web:api.example.com#key-1");
      expect(result).toEqual({
        didUrl: "did:web:api.example.com#key-1",
        did: "did:web:api.example.com",
        fragment: "key-1",
      });
    });

    it("parses a DID URL without fragment", () => {
      const result = parseDidUrl("did:web:api.example.com");
      expect(result).toEqual({
        didUrl: "did:web:api.example.com",
        did: "did:web:api.example.com",
        fragment: null,
      });
    });

    it("parses did:key with fragment", () => {
      const result = parseDidUrl("did:key:z6MkTest#z6MkTest");
      expect(result).toEqual({
        didUrl: "did:key:z6MkTest#z6MkTest",
        did: "did:key:z6MkTest",
        fragment: "z6MkTest",
      });
    });

    it("parses did:jwk without fragment", () => {
      const result = parseDidUrl("did:jwk:eyJrdHkiOiJFQyJ9");
      expect(result).toEqual({
        didUrl: "did:jwk:eyJrdHkiOiJFQyJ9",
        did: "did:jwk:eyJrdHkiOiJFQyJ9",
        fragment: null,
      });
    });

    it("trims whitespace", () => {
      const result = parseDidUrl("  did:web:example.com#key-1  ");
      expect(result.didUrl).toBe("did:web:example.com#key-1");
      expect(result.did).toBe("did:web:example.com");
      expect(result.fragment).toBe("key-1");
    });

    it("handles fragment with special characters", () => {
      const result = parseDidUrl("did:web:example.com#key_2-abc");
      expect(result.fragment).toBe("key_2-abc");
    });

    it("rejects empty string", () => {
      expect(() => parseDidUrl("")).toThrow(OmaTrustError);
    });

    it("rejects whitespace-only string", () => {
      expect(() => parseDidUrl("   ")).toThrow(OmaTrustError);
    });

    it("rejects malformed DID (no method)", () => {
      expect(() => parseDidUrl("not-a-did")).toThrow(OmaTrustError);
      expect(() => parseDidUrl("example.com#key-1")).toThrow(OmaTrustError);
    });

    it("rejects DID URL with empty fragment (trailing #)", () => {
      expect(() => parseDidUrl("did:web:example.com#")).toThrow(OmaTrustError);
    });

    it("rejects did: with no method or identifier", () => {
      expect(() => parseDidUrl("did:")).toThrow(OmaTrustError);
    });
  });

  describe("isDidUrl", () => {
    it("returns true for DID URLs with fragments", () => {
      expect(isDidUrl("did:web:api.example.com#key-1")).toBe(true);
      expect(isDidUrl("did:key:z6MkTest#z6MkTest")).toBe(true);
    });

    it("returns false for bare DIDs without fragments", () => {
      expect(isDidUrl("did:web:api.example.com")).toBe(false);
      expect(isDidUrl("did:pkh:eip155:1:0xabc")).toBe(false);
    });

    it("returns false for non-DID strings with #", () => {
      expect(isDidUrl("not-a-did#fragment")).toBe(false);
      expect(isDidUrl("#just-fragment")).toBe(false);
    });

    it("returns false for non-string input", () => {
      expect(isDidUrl(null as unknown as string)).toBe(false);
      expect(isDidUrl(undefined as unknown as string)).toBe(false);
      expect(isDidUrl(123 as unknown as string)).toBe(false);
    });
  });

  describe("assertBareDid", () => {
    it("does not throw for bare DIDs", () => {
      expect(() => assertBareDid("did:web:example.com")).not.toThrow();
      expect(() => assertBareDid("did:pkh:eip155:1:0xabc")).not.toThrow();
      expect(() => assertBareDid("did:jwk:eyJrdHkiOiJFQyJ9")).not.toThrow();
    });

    it("throws for DID URLs with fragments", () => {
      expect(() => assertBareDid("did:web:example.com#key-1")).toThrow(OmaTrustError);
    });

    it("throws for empty string", () => {
      expect(() => assertBareDid("")).toThrow(OmaTrustError);
    });

    it("includes helpful error message", () => {
      try {
        assertBareDid("did:web:example.com#key-1");
      } catch (e) {
        expect((e as OmaTrustError).message).toContain("bare DID");
        expect((e as OmaTrustError).message).toContain("parseDidUrl");
      }
    });
  });
});
