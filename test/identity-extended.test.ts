import { describe, expect, it } from "vitest";
import { OmaTrustError } from "../src/shared/errors";
import {
  isValidDid,
  extractDidMethod,
  extractDidIdentifier,
  normalizeDomain,
  normalizeDidWeb,
  normalizeDidPkh,
  normalizeDidHandle,
  normalizeDidKey,
  normalizeDid,
  computeDidHash,
  computeDidAddress,
  didToAddress,
  validateDidAddress,
  buildDidWeb,
  buildDidPkh,
  buildEvmDidPkh,
  buildDidPkhFromCaip10,
  getChainIdFromDidPkh,
  getAddressFromDidPkh,
  getNamespaceFromDidPkh,
  isEvmDidPkh,
  getDomainFromDidWeb,
  extractAddressFromDid
} from "../src/identity/did";
import {
  parseCaip10,
  buildCaip10,
  normalizeCaip10,
  buildCaip2,
  parseCaip2
} from "../src/identity/caip";
import {
  canonicalizeJson,
  canonicalizeForHash,
  hashCanonicalizedJson
} from "../src/identity/data";

describe("identity/did – extended", () => {
  describe("isValidDid", () => {
    it("returns true for valid DIDs", () => {
      expect(isValidDid("did:web:example.com")).toBe(true);
      expect(isValidDid("did:pkh:eip155:1:0xabc")).toBe(true);
      expect(isValidDid("did:key:z6MkTest")).toBe(true);
      expect(isValidDid("did:handle:twitter:alice")).toBe(true);
    });

    it("returns false for invalid DIDs", () => {
      expect(isValidDid("")).toBe(false);
      expect(isValidDid("example.com")).toBe(false);
      expect(isValidDid("did:")).toBe(false);
      expect(isValidDid("did::missing")).toBe(false);
      expect(isValidDid("not-a-did")).toBe(false);
    });
  });

  describe("extractDidMethod", () => {
    it("extracts method from valid DIDs", () => {
      expect(extractDidMethod("did:web:example.com")).toBe("web");
      expect(extractDidMethod("did:pkh:eip155:1:0xabc")).toBe("pkh");
      expect(extractDidMethod("did:key:z6MkTest")).toBe("key");
      expect(extractDidMethod("did:handle:twitter:alice")).toBe("handle");
      expect(extractDidMethod("did:ethr:0xabc")).toBe("ethr");
    });

    it("returns null for invalid DIDs", () => {
      expect(extractDidMethod("example.com")).toBeNull();
      expect(extractDidMethod("")).toBeNull();
      expect(extractDidMethod("did:")).toBeNull();
    });
  });

  describe("extractDidIdentifier", () => {
    it("extracts identifier from valid DIDs", () => {
      expect(extractDidIdentifier("did:web:example.com")).toBe("example.com");
      expect(extractDidIdentifier("did:pkh:eip155:1:0xabc")).toBe("eip155:1:0xabc");
      expect(extractDidIdentifier("did:key:z6MkTest")).toBe("z6MkTest");
    });

    it("returns null for invalid input", () => {
      expect(extractDidIdentifier("example.com")).toBeNull();
      expect(extractDidIdentifier("")).toBeNull();
    });
  });

  describe("normalizeDomain", () => {
    it("lowercases and trims domains", () => {
      expect(normalizeDomain("Example.COM")).toBe("example.com");
      expect(normalizeDomain("  Example.COM  ")).toBe("example.com");
    });

    it("removes trailing dots", () => {
      expect(normalizeDomain("example.com.")).toBe("example.com");
    });

    it("throws for empty string", () => {
      expect(() => normalizeDomain("")).toThrow(OmaTrustError);
    });
  });

  describe("normalizeDidWeb", () => {
    it("normalizes full did:web identifiers", () => {
      expect(normalizeDidWeb("did:web:Example.COM")).toBe("did:web:example.com");
    });

    it("normalizes bare domains into did:web", () => {
      expect(normalizeDidWeb("Example.COM")).toBe("did:web:example.com");
    });

    it("preserves path components", () => {
      expect(normalizeDidWeb("did:web:Example.COM/path/to")).toBe("did:web:example.com/path/to");
    });

    it("throws for non-web DID prefixes", () => {
      expect(() => normalizeDidWeb("did:pkh:eip155:1:0xabc")).toThrow(OmaTrustError);
    });

    it("throws for empty input", () => {
      expect(() => normalizeDidWeb("")).toThrow(OmaTrustError);
    });
  });

  describe("normalizeDidPkh", () => {
    it("normalizes did:pkh to lowercase namespace and address", () => {
      expect(normalizeDidPkh("did:pkh:EIP155:1:0xABC")).toBe("did:pkh:eip155:1:0xabc");
    });

    it("throws for wrong prefix", () => {
      expect(() => normalizeDidPkh("did:web:example.com")).toThrow(OmaTrustError);
    });

    it("throws for wrong number of parts", () => {
      expect(() => normalizeDidPkh("did:pkh:eip155:1")).toThrow(OmaTrustError);
      expect(() => normalizeDidPkh("did:pkh:eip155:1:0xabc:extra")).toThrow(OmaTrustError);
    });
  });

  describe("normalizeDidHandle", () => {
    it("normalizes did:handle to lowercase platform", () => {
      expect(normalizeDidHandle("did:handle:Twitter:alice")).toBe("did:handle:twitter:alice");
    });

    it("preserves username case", () => {
      expect(normalizeDidHandle("did:handle:twitter:Alice")).toBe("did:handle:twitter:Alice");
    });

    it("throws for wrong prefix", () => {
      expect(() => normalizeDidHandle("did:web:example.com")).toThrow(OmaTrustError);
    });

    it("throws for wrong number of parts", () => {
      expect(() => normalizeDidHandle("did:handle:twitter")).toThrow(OmaTrustError);
      expect(() => normalizeDidHandle("did:handle:twitter:alice:extra")).toThrow(OmaTrustError);
    });
  });

  describe("normalizeDidKey", () => {
    it("returns trimmed did:key as-is", () => {
      expect(normalizeDidKey("did:key:z6MkTest")).toBe("did:key:z6MkTest");
      expect(normalizeDidKey("  did:key:z6MkTest  ")).toBe("did:key:z6MkTest");
    });

    it("throws for wrong prefix", () => {
      expect(() => normalizeDidKey("did:web:example.com")).toThrow(OmaTrustError);
    });

    it("throws for empty input", () => {
      expect(() => normalizeDidKey("")).toThrow(OmaTrustError);
    });
  });

  describe("normalizeDid – routing", () => {
    it("routes to normalizeDidWeb for did:web", () => {
      expect(normalizeDid("did:web:Example.COM")).toBe("did:web:example.com");
    });

    it("routes to normalizeDidPkh for did:pkh", () => {
      expect(normalizeDid("did:pkh:EIP155:1:0xABC")).toBe("did:pkh:eip155:1:0xabc");
    });

    it("routes to normalizeDidHandle for did:handle", () => {
      expect(normalizeDid("did:handle:Twitter:alice")).toBe("did:handle:twitter:alice");
    });

    it("routes to normalizeDidKey for did:key", () => {
      expect(normalizeDid("did:key:z6MkTest")).toBe("did:key:z6MkTest");
    });

    it("falls back to normalizeDidWeb for bare domains", () => {
      expect(normalizeDid("example.com")).toBe("did:web:example.com");
    });

    it("returns unknown methods trimmed", () => {
      expect(normalizeDid("did:ethr:0xabc")).toBe("did:ethr:0xabc");
    });

    it("throws for invalid DID format", () => {
      expect(() => normalizeDid("did:")).toThrow(OmaTrustError);
    });
  });

  describe("computeDidAddress", () => {
    it("extracts low-order 160 bits from hash", () => {
      const hash = "0x" + "a".repeat(64);
      const addr = computeDidAddress(hash as `0x${string}`);
      expect(addr).toBe("0x" + "a".repeat(40));
    });

    it("throws for non-32-byte hex", () => {
      expect(() => computeDidAddress("0x1234" as `0x${string}`)).toThrow(OmaTrustError);
      expect(() => computeDidAddress("not-hex" as `0x${string}`)).toThrow(OmaTrustError);
    });
  });

  describe("validateDidAddress", () => {
    it("returns true for matching did and address", () => {
      const did = "did:web:example.com";
      const addr = didToAddress(did);
      expect(validateDidAddress(did, addr)).toBe(true);
    });

    it("returns false for non-matching address", () => {
      expect(validateDidAddress("did:web:example.com", "0x0000000000000000000000000000000000000000")).toBe(false);
    });

    it("returns false on invalid input (catches error)", () => {
      expect(validateDidAddress("", "0x0000000000000000000000000000000000000000")).toBe(false);
    });
  });

  describe("buildDidPkhFromCaip10", () => {
    it("builds did:pkh from CAIP-10 string", () => {
      expect(buildDidPkhFromCaip10("eip155:1:0xABC")).toBe("did:pkh:eip155:1:0xabc");
    });
  });

  describe("buildDidPkh", () => {
    it("builds did:pkh with lowercase namespace and address", () => {
      expect(buildDidPkh("EIP155", "1", "0xABC")).toBe("did:pkh:eip155:1:0xabc");
    });

    it("handles numeric chainId", () => {
      expect(buildDidPkh("eip155", 137, "0xabc")).toBe("did:pkh:eip155:137:0xabc");
    });

    it("throws for empty namespace", () => {
      expect(() => buildDidPkh("", "1", "0xabc")).toThrow(OmaTrustError);
    });

    it("throws for empty address", () => {
      expect(() => buildDidPkh("eip155", "1", "")).toThrow(OmaTrustError);
    });

    it("throws for null/undefined chainId", () => {
      expect(() => buildDidPkh("eip155", null as unknown as string, "0xabc")).toThrow(OmaTrustError);
      expect(() => buildDidPkh("eip155", undefined as unknown as string, "0xabc")).toThrow(OmaTrustError);
    });

    it("throws for empty string chainId", () => {
      expect(() => buildDidPkh("eip155", "", "0xabc")).toThrow(OmaTrustError);
    });
  });

  describe("buildEvmDidPkh", () => {
    it("builds with eip155 namespace", () => {
      expect(buildEvmDidPkh(1, "0xABC")).toBe("did:pkh:eip155:1:0xabc");
    });
  });

  describe("parseDidPkh accessors", () => {
    const did = "did:pkh:eip155:1:0xabc";

    it("getChainIdFromDidPkh returns chainId", () => {
      expect(getChainIdFromDidPkh(did)).toBe("1");
    });

    it("getAddressFromDidPkh returns address", () => {
      expect(getAddressFromDidPkh(did)).toBe("0xabc");
    });

    it("getNamespaceFromDidPkh returns namespace", () => {
      expect(getNamespaceFromDidPkh(did)).toBe("eip155");
    });

    it("returns null for non-pkh DIDs", () => {
      expect(getChainIdFromDidPkh("did:web:example.com")).toBeNull();
      expect(getAddressFromDidPkh("did:web:example.com")).toBeNull();
      expect(getNamespaceFromDidPkh("did:web:example.com")).toBeNull();
    });

    it("returns null for malformed did:pkh", () => {
      expect(getChainIdFromDidPkh("did:pkh:eip155")).toBeNull();
    });
  });

  describe("isEvmDidPkh", () => {
    it("returns true for eip155 namespace", () => {
      expect(isEvmDidPkh("did:pkh:eip155:1:0xabc")).toBe(true);
    });

    it("returns false for non-eip155 namespace", () => {
      expect(isEvmDidPkh("did:pkh:solana:mainnet:SomeAddress")).toBe(false);
    });

    it("returns false for non-pkh DID", () => {
      expect(isEvmDidPkh("did:web:example.com")).toBe(false);
    });
  });

  describe("getDomainFromDidWeb", () => {
    it("extracts domain from did:web", () => {
      expect(getDomainFromDidWeb("did:web:example.com")).toBe("example.com");
    });

    it("extracts domain ignoring path", () => {
      expect(getDomainFromDidWeb("did:web:example.com/path/sub")).toBe("example.com");
    });

    it("returns null for non-web DIDs", () => {
      expect(getDomainFromDidWeb("did:pkh:eip155:1:0xabc")).toBeNull();
    });

    it("returns null for empty identifier", () => {
      expect(getDomainFromDidWeb("did:web:")).toBeNull();
    });
  });

  describe("extractAddressFromDid", () => {
    it("extracts address from did:pkh", () => {
      const addr = extractAddressFromDid("did:pkh:eip155:1:0xABc");
      expect(addr).toBe("0xabc");
    });

    it("extracts address from did:ethr (simple)", () => {
      const addr = extractAddressFromDid("did:ethr:0x1111111111111111111111111111111111111111");
      expect(addr).toMatch(/^0x[0-9a-fA-F]{40}$/);
    });

    it("extracts address from did:ethr with chain prefix", () => {
      const addr = extractAddressFromDid("did:ethr:mainnet:0x1111111111111111111111111111111111111111");
      expect(addr).toMatch(/^0x[0-9a-fA-F]{40}$/);
    });

    it("extracts address from CAIP-10 format", () => {
      const addr = extractAddressFromDid("eip155:1:0x1111111111111111111111111111111111111111");
      expect(addr).toBe("0x1111111111111111111111111111111111111111");
    });

    it("extracts address from raw Ethereum address", () => {
      const addr = extractAddressFromDid("0x1111111111111111111111111111111111111111");
      expect(addr).toMatch(/^0x[0-9a-fA-F]{40}$/);
    });

    it("throws for unsupported identifier format", () => {
      expect(() => extractAddressFromDid("not-an-address")).toThrow(OmaTrustError);
    });

    it("throws for empty string", () => {
      expect(() => extractAddressFromDid("")).toThrow(OmaTrustError);
    });

    it("throws for invalid did:ethr address", () => {
      expect(() => extractAddressFromDid("did:ethr:not-valid")).toThrow(OmaTrustError);
    });
  });

  describe("computeDidHash determinism", () => {
    it("produces same hash for same DID regardless of casing", () => {
      const hash1 = computeDidHash("did:web:Example.COM");
      const hash2 = computeDidHash("did:web:example.com");
      expect(hash1).toBe(hash2);
    });
  });
});

describe("identity/caip – extended", () => {
  describe("parseCaip10 – error cases", () => {
    it("throws for empty string", () => {
      expect(() => parseCaip10("")).toThrow(OmaTrustError);
    });

    it("throws for invalid format (too few parts)", () => {
      expect(() => parseCaip10("eip155:1")).toThrow(OmaTrustError);
    });

    it("throws for whitespace-only string", () => {
      expect(() => parseCaip10("   ")).toThrow(OmaTrustError);
    });

    it("trims input before parsing", () => {
      const result = parseCaip10("  eip155:1:0xABC  ");
      expect(result.namespace).toBe("eip155");
      expect(result.address).toBe("0xABC");
    });
  });

  describe("buildCaip10", () => {
    it("builds valid CAIP-10 string", () => {
      expect(buildCaip10("eip155", "1", "0xabc")).toBe("eip155:1:0xabc");
    });

    it("throws for empty namespace", () => {
      expect(() => buildCaip10("", "1", "0xabc")).toThrow(OmaTrustError);
    });

    it("throws for empty reference", () => {
      expect(() => buildCaip10("eip155", "", "0xabc")).toThrow(OmaTrustError);
    });

    it("throws for empty address", () => {
      expect(() => buildCaip10("eip155", "1", "")).toThrow(OmaTrustError);
    });
  });

  describe("normalizeCaip10", () => {
    it("lowercases address for eip155", () => {
      expect(normalizeCaip10("eip155:1:0xABC")).toBe("eip155:1:0xabc");
    });

    it("preserves address case for non-eip155", () => {
      expect(normalizeCaip10("solana:mainnet:SomeAddr")).toBe("solana:mainnet:SomeAddr");
    });

    it("throws for invalid CAIP-10", () => {
      expect(() => normalizeCaip10("invalid")).toThrow(OmaTrustError);
    });
  });

  describe("buildCaip2", () => {
    it("builds valid CAIP-2 string", () => {
      expect(buildCaip2("eip155", "1")).toBe("eip155:1");
    });

    it("throws for empty namespace", () => {
      expect(() => buildCaip2("", "1")).toThrow(OmaTrustError);
    });

    it("throws for empty reference", () => {
      expect(() => buildCaip2("eip155", "")).toThrow(OmaTrustError);
    });
  });

  describe("parseCaip2 – error cases", () => {
    it("throws for invalid CAIP-2", () => {
      expect(() => parseCaip2("invalid")).toThrow(OmaTrustError);
    });

    it("throws for empty string", () => {
      expect(() => parseCaip2("")).toThrow(OmaTrustError);
    });

    it("throws for CAIP-10 (too many parts)", () => {
      expect(() => parseCaip2("eip155:1:0xabc")).toThrow(OmaTrustError);
    });
  });
});

describe("identity/data – extended", () => {
  describe("canonicalizeJson", () => {
    it("canonicalizes objects with sorted keys", () => {
      expect(canonicalizeJson({ b: 1, a: 2 })).toBe('{"a":2,"b":1}');
    });

    it("handles nested objects", () => {
      const result = canonicalizeJson({ z: { b: 1, a: 2 }, a: 1 });
      expect(result).toBe('{"a":1,"z":{"a":2,"b":1}}');
    });

    it("handles arrays (preserves order)", () => {
      expect(canonicalizeJson([3, 1, 2])).toBe("[3,1,2]");
    });

    it("throws for undefined (not canonicalizable)", () => {
      expect(() => canonicalizeJson(undefined)).toThrow(OmaTrustError);
    });
  });

  describe("hashCanonicalizedJson", () => {
    it("produces keccak256 hash", () => {
      const hash = hashCanonicalizedJson({ a: 1 }, "keccak256");
      expect(hash).toMatch(/^0x[0-9a-f]{64}$/);
    });

    it("produces sha256 hash", () => {
      const hash = hashCanonicalizedJson({ a: 1 }, "sha256");
      expect(hash).toMatch(/^0x[0-9a-f]{64}$/);
    });

    it("produces different hashes for different algorithms", () => {
      const k = hashCanonicalizedJson({ a: 1 }, "keccak256");
      const s = hashCanonicalizedJson({ a: 1 }, "sha256");
      expect(k).not.toBe(s);
    });

    it("produces same hash for same input", () => {
      const h1 = hashCanonicalizedJson({ b: 1, a: 2 }, "keccak256");
      const h2 = hashCanonicalizedJson({ a: 2, b: 1 }, "keccak256");
      expect(h1).toBe(h2);
    });
  });
});
