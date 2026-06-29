import { describe, expect, it } from "vitest";
import { OmaTrustError } from "../src/shared/errors";
import {
  artifactDidFromBytes,
  artifactDidFromJson,
  parseArtifactDid,
  verifyDidArtifact,
} from "../src/identity/artifact";

describe("identity/artifact – did:artifact construction, parsing, and verification", () => {
  describe("artifactDidFromBytes", () => {
    it("produces a valid did:artifact from raw bytes", async () => {
      const bytes = new TextEncoder().encode("hello world");
      const did = await artifactDidFromBytes(bytes);

      expect(did).toMatch(/^did:artifact:b[a-z2-7]+$/);
      // SHA-256 of "hello world" is known
      const parsed = parseArtifactDid(did);
      expect(parsed.digestHex).toBe(
        "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
      );
    });

    it("produces different DIDs for different content", async () => {
      const a = await artifactDidFromBytes(new TextEncoder().encode("aaa"));
      const b = await artifactDidFromBytes(new TextEncoder().encode("bbb"));
      expect(a).not.toBe(b);
    });

    it("produces the same DID for identical content", async () => {
      const bytes = new Uint8Array([1, 2, 3, 4, 5]);
      const a = await artifactDidFromBytes(bytes);
      const b = await artifactDidFromBytes(bytes);
      expect(a).toBe(b);
    });

    it("rejects empty Uint8Array", async () => {
      await expect(artifactDidFromBytes(new Uint8Array(0))).rejects.toThrow(OmaTrustError);
    });

    it("rejects non-Uint8Array input", async () => {
      await expect(artifactDidFromBytes("hello" as unknown as Uint8Array)).rejects.toThrow(
        OmaTrustError
      );
      await expect(artifactDidFromBytes(null as unknown as Uint8Array)).rejects.toThrow(
        OmaTrustError
      );
    });
  });

  describe("artifactDidFromJson", () => {
    it("produces a valid did:artifact from a JSON object", async () => {
      const did = await artifactDidFromJson({ hello: "world" });
      expect(did).toMatch(/^did:artifact:b[a-z2-7]+$/);
    });

    it("produces the same DID regardless of key order", async () => {
      const a = await artifactDidFromJson({ b: 2, a: 1 });
      const b = await artifactDidFromJson({ a: 1, b: 2 });
      expect(a).toBe(b);
    });

    it("produces the same DID from string and parsed equivalent", async () => {
      const obj = { name: "test", value: 42 };
      const fromObj = await artifactDidFromJson(obj);
      const fromStr = await artifactDidFromJson(JSON.stringify(obj));
      expect(fromObj).toBe(fromStr);
    });

    it("produces different DID from raw bytes vs JSON canonicalization", async () => {
      const jsonStr = '{"a":1,"b":2}';
      const fromJson = await artifactDidFromJson(jsonStr);
      const fromBytes = await artifactDidFromBytes(new TextEncoder().encode(jsonStr));
      // For already-canonical JSON, they should be the same
      expect(fromJson).toBe(fromBytes);
    });

    it("produces different DID for non-canonical JSON string vs bytes", async () => {
      // Non-canonical: spaces and different key order
      const jsonStr = '{ "b": 2,  "a": 1 }';
      const fromJson = await artifactDidFromJson(jsonStr);
      const fromBytes = await artifactDidFromBytes(new TextEncoder().encode(jsonStr));
      // These should differ because canonicalization removes whitespace and reorders keys
      expect(fromJson).not.toBe(fromBytes);
    });

    it("rejects malformed JSON string", async () => {
      await expect(artifactDidFromJson("{not valid json}")).rejects.toThrow(OmaTrustError);
    });

    it("rejects JSON with duplicate keys", async () => {
      await expect(artifactDidFromJson('{"a":1,"a":2}')).rejects.toThrow(OmaTrustError);
    });

    it("rejects non-JSON-safe values (NaN, undefined, etc.)", async () => {
      await expect(artifactDidFromJson({ val: NaN })).rejects.toThrow(OmaTrustError);
      await expect(artifactDidFromJson({ fn: () => {} })).rejects.toThrow(OmaTrustError);
    });

    it("handles nested structures", async () => {
      const obj = { outer: { inner: [1, 2, 3] }, flag: true };
      const did = await artifactDidFromJson(obj);
      expect(did).toMatch(/^did:artifact:b[a-z2-7]+$/);
    });

    it("handles primitive JSON values", async () => {
      const did = await artifactDidFromJson(42);
      expect(did).toMatch(/^did:artifact:b[a-z2-7]+$/);
    });
  });

  describe("parseArtifactDid", () => {
    it("parses a valid did:artifact DID", async () => {
      const bytes = new TextEncoder().encode("test content");
      const did = await artifactDidFromBytes(bytes);

      const parsed = parseArtifactDid(did);
      expect(parsed.did).toBe(did);
      expect(parsed.identifier).toMatch(/^b[a-z2-7]+$/);
      expect(parsed.digest).toBeInstanceOf(Uint8Array);
      expect(parsed.digest.length).toBe(32);
      expect(parsed.digestHex).toMatch(/^[0-9a-f]{64}$/);
    });

    it("rejects non-string input", () => {
      expect(() => parseArtifactDid(42 as unknown as string)).toThrow(OmaTrustError);
    });

    it("rejects wrong DID prefix", () => {
      expect(() => parseArtifactDid("did:web:example.com")).toThrow(OmaTrustError);
      expect(() => parseArtifactDid("did:pkh:eip155:1:0xabc")).toThrow(OmaTrustError);
    });

    it("rejects empty identifier", () => {
      expect(() => parseArtifactDid("did:artifact:")).toThrow(OmaTrustError);
    });

    it("rejects non-base32lower multibase prefix", () => {
      expect(() => parseArtifactDid("did:artifact:zabc123")).toThrow(OmaTrustError);
      expect(() => parseArtifactDid("did:artifact:Babc123")).toThrow(OmaTrustError);
    });

    it("rejects invalid base32 encoding", () => {
      expect(() => parseArtifactDid("did:artifact:b!!!invalid!!!")).toThrow(OmaTrustError);
    });

    it("rejects wrong CID version (detected during parse)", () => {
      // The CID version check is defensive — CIDv0 cannot be base32-encoded via multiformats.
      // Instead, test that the `bafybeig...` prefix (CIDv1 + dag-pb) fails on multicodec check
      expect(() =>
        parseArtifactDid(
          "did:artifact:bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi"
        )
      ).toThrow(OmaTrustError);
      try {
        parseArtifactDid(
          "did:artifact:bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi"
        );
      } catch (err) {
        // Should fail on multicodec (dag-pb instead of raw)
        expect((err as OmaTrustError).code).toBe("INVALID_DID");
      }
    });

    it("rejects wrong multicodec (not raw)", async () => {
      // Construct a CIDv1 with dag-pb codec (0x70) instead of raw (0x55)
      const { CID } = await import("multiformats/cid");
      const { sha256 } = await import("multiformats/hashes/sha2");
      const { base32 } = await import("multiformats/bases/base32");
      const digest = await sha256.digest(new TextEncoder().encode("test"));
      const cid = CID.createV1(0x70, digest); // dag-pb instead of raw
      const did = `did:artifact:${cid.toString(base32)}`;
      expect(() => parseArtifactDid(did)).toThrow(OmaTrustError);
      try {
        parseArtifactDid(did);
      } catch (err) {
        expect((err as OmaTrustError).message).toContain("Multicodec must be raw");
      }
    });

    it("rejects wrong multihash function (not sha2-256)", async () => {
      // Construct a CIDv1 with sha2-512 (code 0x13) instead of sha2-256 (code 0x12)
      const { CID } = await import("multiformats/cid");
      const { base32 } = await import("multiformats/bases/base32");
      const { create } = await import("multiformats/hashes/digest");
      // Create a fake multihash with code 0x13 (sha2-512) and a 64-byte digest
      const fakeDigest = create(0x13, new Uint8Array(64));
      const cid = CID.createV1(0x55, fakeDigest); // raw codec, wrong hash
      const did = `did:artifact:${cid.toString(base32)}`;
      expect(() => parseArtifactDid(did)).toThrow(OmaTrustError);
      try {
        parseArtifactDid(did);
      } catch (err) {
        expect((err as OmaTrustError).message).toContain("sha2-256");
      }
    });

    it("rejects wrong digest length", async () => {
      // Construct a CIDv1 with sha2-256 code but wrong digest length (16 bytes)
      const { CID } = await import("multiformats/cid");
      const { base32 } = await import("multiformats/bases/base32");
      const { create } = await import("multiformats/hashes/digest");
      // Create a fake multihash with sha2-256 code but only 16-byte digest
      const fakeDigest = create(0x12, new Uint8Array(16));
      const cid = CID.createV1(0x55, fakeDigest);
      const did = `did:artifact:${cid.toString(base32)}`;
      expect(() => parseArtifactDid(did)).toThrow(OmaTrustError);
      try {
        parseArtifactDid(did);
      } catch (err) {
        expect((err as OmaTrustError).message).toContain("32 bytes");
      }
    });

    it("round-trips with construction", async () => {
      const content = new TextEncoder().encode("round trip test");
      const did = await artifactDidFromBytes(content);
      const parsed = parseArtifactDid(did);
      expect(parsed.did).toBe(did);
    });
  });

  describe("verifyDidArtifact", () => {
    it("verifies raw bytes that match", async () => {
      const bytes = new TextEncoder().encode("verify me");
      const did = await artifactDidFromBytes(bytes);

      const result = await verifyDidArtifact(did, bytes);
      expect(result.valid).toBe(true);
      expect(result.matchedAs).toBe("binary");
    });

    it("verifies JSON object that matches via canonicalization", async () => {
      const obj = { name: "test", value: 123 };
      const did = await artifactDidFromJson(obj);

      const result = await verifyDidArtifact(did, obj);
      expect(result.valid).toBe(true);
      expect(result.matchedAs).toBe("json");
    });

    it("verifies JSON string that matches via canonicalization", async () => {
      const obj = { z: 1, a: 2 };
      const did = await artifactDidFromJson(obj);

      // Pass as string with different formatting
      const result = await verifyDidArtifact(did, '{"z": 1, "a": 2}');
      expect(result.valid).toBe(true);
      expect(result.matchedAs).toBe("json");
    });

    it("verifies string as binary fallback when JSON doesn't match", async () => {
      const raw = "not json {{{";
      const did = await artifactDidFromBytes(new TextEncoder().encode(raw));

      const result = await verifyDidArtifact(did, raw);
      expect(result.valid).toBe(true);
      expect(result.matchedAs).toBe("binary");
    });

    it("rejects content that doesn't match", async () => {
      const did = await artifactDidFromBytes(new TextEncoder().encode("original"));

      const result = await verifyDidArtifact(did, new TextEncoder().encode("different"));
      expect(result.valid).toBe(false);
      expect(result.reason).toContain("does not match");
    });

    it("rejects object content that doesn't match as JSON", async () => {
      const did = await artifactDidFromJson({ a: 1 });

      const result = await verifyDidArtifact(did, { a: 2 });
      expect(result.valid).toBe(false);
      expect(result.reason).toBeDefined();
    });

    it("returns invalid for malformed DID", async () => {
      const result = await verifyDidArtifact("not-a-did", new TextEncoder().encode("test"));
      expect(result.valid).toBe(false);
      expect(result.reason).toBeDefined();
    });

    it("returns invalid for wrong DID method", async () => {
      const result = await verifyDidArtifact(
        "did:web:example.com",
        new TextEncoder().encode("test")
      );
      expect(result.valid).toBe(false);
    });

    it("handles the case where content is a non-JSON-safe object", async () => {
      // Create a DID from raw bytes of a string
      const raw = "test string";
      const did = await artifactDidFromBytes(new TextEncoder().encode(raw));

      // Pass an object with NaN — JSON canonicalization will fail, falls through
      // Since it's an object (not Uint8Array or string), it returns the "not raw bytes" error
      const result = await verifyDidArtifact(did, { val: NaN });
      expect(result.valid).toBe(false);
      expect(result.reason).toContain("not raw bytes");
    });
  });
});
