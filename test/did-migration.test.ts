import { describe, expect, it } from "vitest";
import { base58btc } from "multiformats/bases/base58";
import { OmaTrustError } from "../src/shared/errors";
import { didEthrToDidPkh, didKeyToDidJwk } from "../src/identity/did-migration";
import { didJwkToJwk } from "../src/identity/jwk";

describe("identity/did-migration – DID method conversion", () => {
  describe("didEthrToDidPkh", () => {
    const validAddress = "0x1111111111111111111111111111111111111111";

    it("converts simple did:ethr (no chain) to did:pkh:eip155:1", () => {
      const result = didEthrToDidPkh(`did:ethr:${validAddress}`);
      expect(result).toBe(`did:pkh:eip155:1:${validAddress.toLowerCase()}`);
    });

    it("converts did:ethr with numeric chain ID", () => {
      const result = didEthrToDidPkh(`did:ethr:137:${validAddress}`);
      expect(result).toBe(`did:pkh:eip155:137:${validAddress.toLowerCase()}`);
    });

    it("converts did:ethr with hex chain ID", () => {
      const result = didEthrToDidPkh(`did:ethr:0x89:${validAddress}`);
      // 0x89 = 137
      expect(result).toBe(`did:pkh:eip155:137:${validAddress.toLowerCase()}`);
    });

    it("converts did:ethr with named network (mainnet)", () => {
      const result = didEthrToDidPkh(`did:ethr:mainnet:${validAddress}`);
      expect(result).toBe(`did:pkh:eip155:1:${validAddress.toLowerCase()}`);
    });

    it("converts did:ethr with named network (sepolia)", () => {
      const result = didEthrToDidPkh(`did:ethr:sepolia:${validAddress}`);
      expect(result).toBe(`did:pkh:eip155:11155111:${validAddress.toLowerCase()}`);
    });

    it("converts did:ethr with named network (polygon)", () => {
      const result = didEthrToDidPkh(`did:ethr:polygon:${validAddress}`);
      expect(result).toBe(`did:pkh:eip155:137:${validAddress.toLowerCase()}`);
    });

    it("converts did:ethr with named network (arbitrum)", () => {
      const result = didEthrToDidPkh(`did:ethr:arbitrum:${validAddress}`);
      expect(result).toBe(`did:pkh:eip155:42161:${validAddress.toLowerCase()}`);
    });

    it("converts did:ethr with named network (optimism)", () => {
      const result = didEthrToDidPkh(`did:ethr:optimism:${validAddress}`);
      expect(result).toBe(`did:pkh:eip155:10:${validAddress.toLowerCase()}`);
    });

    it("converts did:ethr with named network (base)", () => {
      const result = didEthrToDidPkh(`did:ethr:base:${validAddress}`);
      expect(result).toBe(`did:pkh:eip155:8453:${validAddress.toLowerCase()}`);
    });

    it("converts did:ethr with named network (goerli)", () => {
      const result = didEthrToDidPkh(`did:ethr:goerli:${validAddress}`);
      expect(result).toBe(`did:pkh:eip155:5:${validAddress.toLowerCase()}`);
    });

    it("handles checksummed addresses", () => {
      const checksummed = "0xAb5801a7D398351b8bE11C439e05C5B3259aeC9B";
      const result = didEthrToDidPkh(`did:ethr:${checksummed}`);
      expect(result).toBe(`did:pkh:eip155:1:${checksummed.toLowerCase()}`);
    });

    it("rejects non-string input", () => {
      expect(() => didEthrToDidPkh(42 as unknown as string)).toThrow(OmaTrustError);
    });

    it("rejects wrong DID prefix", () => {
      expect(() => didEthrToDidPkh("did:web:example.com")).toThrow(OmaTrustError);
      expect(() => didEthrToDidPkh("did:pkh:eip155:1:0xabc")).toThrow(OmaTrustError);
    });

    it("rejects empty identifier", () => {
      expect(() => didEthrToDidPkh("did:ethr:")).toThrow(OmaTrustError);
    });

    it("rejects invalid Ethereum address", () => {
      expect(() => didEthrToDidPkh("did:ethr:not-an-address")).toThrow(OmaTrustError);
      expect(() => didEthrToDidPkh("did:ethr:0x123")).toThrow(OmaTrustError);
    });

    it("rejects unknown named network", () => {
      expect(() =>
        didEthrToDidPkh(`did:ethr:unknownnet:${validAddress}`)
      ).toThrow(OmaTrustError);
    });

    it("rejects too many parts", () => {
      expect(() =>
        didEthrToDidPkh(`did:ethr:mainnet:extra:${validAddress}`)
      ).toThrow(OmaTrustError);
    });
  });

  describe("didKeyToDidJwk", () => {
    // Ed25519 test vector: well-known did:key for Ed25519
    // Multicodec 0xed01 + 32 bytes of public key
    const ED25519_DID_KEY =
      "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";

    it("converts a valid Ed25519 did:key to did:jwk", () => {
      const result = didKeyToDidJwk(ED25519_DID_KEY);
      expect(result).toMatch(/^did:jwk:/);

      // Verify the resulting did:jwk decodes to a valid OKP/Ed25519 JWK
      const jwk = didJwkToJwk(result);
      expect(jwk.kty).toBe("OKP");
      expect(jwk.crv).toBe("Ed25519");
      expect(typeof jwk.x).toBe("string");
    });

    it("produces deterministic output", () => {
      const a = didKeyToDidJwk(ED25519_DID_KEY);
      const b = didKeyToDidJwk(ED25519_DID_KEY);
      expect(a).toBe(b);
    });

    it("rejects non-string input", () => {
      expect(() => didKeyToDidJwk(42 as unknown as string)).toThrow(OmaTrustError);
    });

    it("rejects wrong DID prefix", () => {
      expect(() => didKeyToDidJwk("did:web:example.com")).toThrow(OmaTrustError);
      expect(() => didKeyToDidJwk("did:ethr:0xabc")).toThrow(OmaTrustError);
    });

    it("rejects missing 'z' multibase prefix", () => {
      expect(() => didKeyToDidJwk("did:key:abc123")).toThrow(OmaTrustError);
    });

    it("rejects invalid base58btc encoding", () => {
      // 'O', 'I', 'l' are not valid base58 characters
      expect(() => didKeyToDidJwk("did:key:zO0invalid")).toThrow(OmaTrustError);
    });

    it("rejects unknown multicodec prefix", () => {
      // Create a base58btc-encoded value with an unknown prefix
      // 0xFF 0x01 would be an unknown multicodec
      expect(() => didKeyToDidJwk("did:key:z3YQLs")).toThrow(OmaTrustError);
    });

    it("rejects secp256k1 compressed keys (unsupported EC decompression)", () => {
      // secp256k1 did:key — multicodec 0xe7 0x01 + 33 bytes compressed public key
      const SECP256K1_DID_KEY =
        "did:key:zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme";
      expect(() => didKeyToDidJwk(SECP256K1_DID_KEY)).toThrow(OmaTrustError);
      try {
        didKeyToDidJwk(SECP256K1_DID_KEY);
      } catch (err) {
        expect((err as OmaTrustError).code).toBe("UNSUPPORTED_KEY_TYPE");
        expect((err as OmaTrustError).message).toContain("compressed EC key");
      }
    });

    it("rejects did:key with too-short decoded bytes", () => {
      // 'z' + base58btc of just 2 bytes
      expect(() => didKeyToDidJwk("did:key:z3E")).toThrow(OmaTrustError);
    });

    it("rejects Ed25519 did:key with wrong key length", () => {
      // Craft a did:key with Ed25519 multicodec but wrong length
      // Multicodec 0xed 0x01 + only 16 bytes (should be 32)
      const badKey = new Uint8Array(18); // 2 bytes prefix + 16 bytes key
      badKey[0] = 0xed;
      badKey[1] = 0x01;
      const encoded = base58btc.encode(badKey);
      expect(() => didKeyToDidJwk(`did:key:${encoded}`)).toThrow(OmaTrustError);
    });

    it("rejects truncated varint (premature end of bytes)", () => {
      // Create bytes where all have continuation bits set but there aren't enough bytes
      // Need 3+ bytes to pass the length check, all with continuation bit set
      const truncated = new Uint8Array([0x80, 0x80, 0x80]);
      const encoded = base58btc.encode(truncated);
      expect(() => didKeyToDidJwk(`did:key:${encoded}`)).toThrow(OmaTrustError);
      try {
        didKeyToDidJwk(`did:key:${encoded}`);
      } catch (err) {
        expect((err as OmaTrustError).message).toContain("Truncated varint");
      }
    });

    it("rejects varint that is too long (more than 4 continuation bytes)", () => {
      // Create bytes with 5+ continuation bytes (shift > 28)
      const longVarint = new Uint8Array([0x80, 0x80, 0x80, 0x80, 0x80, 0x01, ...new Uint8Array(32)]);
      const encoded = base58btc.encode(longVarint);
      expect(() => didKeyToDidJwk(`did:key:${encoded}`)).toThrow(OmaTrustError);
      try {
        didKeyToDidJwk(`did:key:${encoded}`);
      } catch (err) {
        expect((err as OmaTrustError).message).toContain("Varint too long");
      }
    });
  });
});
