import { describe, expect, it } from "vitest";
import { SignJWT, exportJWK, generateKeyPair } from "jose";
import {
  verifyX402JwsArtifact,
  verifyX402JwsOffer,
  verifyX402JwsReceipt,
  type X402JwsArtifact,
} from "../src/reputation/proof/x402-jws";
import type {
  JwsVerificationResult,
  JwsVerificationFailure,
} from "../src/identity/types";

// ---------------------------------------------------------------------------
// Test Helpers
// ---------------------------------------------------------------------------

async function generateEcKeyPair() {
  const { publicKey, privateKey } = await generateKeyPair("ES256", { extractable: true });
  const publicJwk = await exportJWK(publicKey);
  const privateJwk = await exportJWK(privateKey);
  return { publicJwk, privateJwk, privateKey, publicKey };
}

async function signPayload(
  payload: Record<string, unknown>,
  privateKey: CryptoKey | Uint8Array | unknown,
  headerOverrides?: Record<string, unknown>
): Promise<string> {
  let builder = new SignJWT(payload as any).setProtectedHeader({
    alg: "ES256",
    ...headerOverrides,
  });
  return builder.sign(privateKey as any);
}

function makeOfferPayload(overrides?: Record<string, unknown>): Record<string, unknown> {
  return {
    version: "1",
    resourceUrl: "https://api.example.com/resource",
    scheme: "exact",
    network: "base-sepolia",
    asset: "USDC",
    payTo: "0x1234567890abcdef1234567890abcdef12345678",
    amount: "1000000",
    ...overrides,
  };
}

function makeReceiptPayload(overrides?: Record<string, unknown>): Record<string, unknown> {
  return {
    version: "1",
    network: "base-sepolia",
    resourceUrl: "https://api.example.com/resource",
    payer: "0xabcdef1234567890abcdef1234567890abcdef12",
    issuedAt: "2025-01-15T10:00:00Z",
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("x402-jws verification", () => {
  describe("verifyX402JwsArtifact", () => {
    it("verifies a valid JWS with embedded jwk", async () => {
      const { publicJwk, privateKey } = await generateEcKeyPair();
      const payload = makeOfferPayload();
      const jws = await signPayload(payload, privateKey, { jwk: publicJwk });

      const artifact: X402JwsArtifact = { format: "jws", signature: jws };
      const result = await verifyX402JwsArtifact(artifact);

      expect(result.valid).toBe(true);
      const success = result as JwsVerificationResult;
      expect(success.publicKeySource).toBe("embedded-jwk");
      expect(success.publicKeyDid).toMatch(/^did:jwk:/);
      expect(success.payload).toEqual(payload);
      expect(success.kid).toBeNull();
    });

    it("rejects malformed compact JWS", async () => {
      const artifact: X402JwsArtifact = { format: "jws", signature: "not.valid" };
      const result = await verifyX402JwsArtifact(artifact);

      expect(result.valid).toBe(false);
      const fail = result as JwsVerificationFailure;
      expect(fail.error.code).toBe("MALFORMED_JWS");
    });

    it("rejects missing alg", async () => {
      // Manually construct a JWS with no alg — use a raw header
      const header = Buffer.from(JSON.stringify({ kid: "did:web:x.com#k1" })).toString("base64url");
      const payload = Buffer.from(JSON.stringify({})).toString("base64url");
      const fakeJws = `${header}.${payload}.fakesig`;

      const artifact: X402JwsArtifact = { format: "jws", signature: fakeJws };
      const result = await verifyX402JwsArtifact(artifact);

      expect(result.valid).toBe(false);
      const fail = result as JwsVerificationFailure;
      expect(fail.error.code).toBe("MISSING_ALG");
    });

    it("rejects header missing both kid and jwk", async () => {
      const header = Buffer.from(JSON.stringify({ alg: "ES256" })).toString("base64url");
      const payload = Buffer.from(JSON.stringify({})).toString("base64url");
      const fakeJws = `${header}.${payload}.fakesig`;

      const artifact: X402JwsArtifact = { format: "jws", signature: fakeJws };
      const result = await verifyX402JwsArtifact(artifact);

      expect(result.valid).toBe(false);
      const fail = result as JwsVerificationFailure;
      expect(fail.error.code).toBe("MISSING_KEY_MATERIAL");
    });

    it("rejects private key in embedded jwk", async () => {
      const { publicJwk, privateJwk, privateKey } = await generateEcKeyPair();
      // Embed the private JWK (has 'd' field)
      const payload = makeOfferPayload();
      const jws = await signPayload(payload, privateKey, { jwk: privateJwk });

      const artifact: X402JwsArtifact = { format: "jws", signature: jws };
      const result = await verifyX402JwsArtifact(artifact);

      expect(result.valid).toBe(false);
      const fail = result as JwsVerificationFailure;
      expect(fail.error.code).toBe("INVALID_EMBEDDED_JWK");
    });

    it("rejects invalid signature", async () => {
      const { publicJwk, privateKey } = await generateEcKeyPair();
      const payload = makeOfferPayload();
      const jws = await signPayload(payload, privateKey, { jwk: publicJwk });

      // Tamper with the signature part
      const parts = jws.split(".");
      parts[2] = parts[2].split("").reverse().join("");
      const tamperedJws = parts.join(".");

      const artifact: X402JwsArtifact = { format: "jws", signature: tamperedJws };
      const result = await verifyX402JwsArtifact(artifact);

      expect(result.valid).toBe(false);
      const fail = result as JwsVerificationFailure;
      expect(fail.error.code).toBe("SIGNATURE_INVALID");
    });

    it("rejects invalid artifact format", async () => {
      const artifact = { format: "eip712", signature: "abc" } as any;
      const result = await verifyX402JwsArtifact(artifact);

      expect(result.valid).toBe(false);
      const fail = result as JwsVerificationFailure;
      expect(fail.error.code).toBe("INVALID_ARTIFACT");
    });

    it("rejects empty signature string", async () => {
      const artifact: X402JwsArtifact = { format: "jws", signature: "" };
      const result = await verifyX402JwsArtifact(artifact);

      expect(result.valid).toBe(false);
      const fail = result as JwsVerificationFailure;
      expect(fail.error.code).toBe("INVALID_ARTIFACT");
    });

    it("returns kid when present in header", async () => {
      const { publicJwk, privateKey } = await generateEcKeyPair();
      const payload = makeOfferPayload();
      const jws = await signPayload(payload, privateKey, {
        jwk: publicJwk,
        kid: "did:web:api.example.com#key-1",
      });

      const artifact: X402JwsArtifact = { format: "jws", signature: jws };
      const result = await verifyX402JwsArtifact(artifact);

      expect(result.valid).toBe(true);
      const success = result as JwsVerificationResult;
      expect(success.kid).toBe("did:web:api.example.com#key-1");
      expect(success.publicKeySource).toBe("embedded-jwk");
    });
  });

  describe("verifyX402JwsOffer", () => {
    it("verifies a valid offer with all required fields", async () => {
      const { publicJwk, privateKey } = await generateEcKeyPair();
      const payload = makeOfferPayload();
      const jws = await signPayload(payload, privateKey, { jwk: publicJwk });

      const artifact: X402JwsArtifact = { format: "jws", signature: jws };
      const result = await verifyX402JwsOffer(artifact);

      expect(result.valid).toBe(true);
      const success = result as JwsVerificationResult;
      expect(success.payload.resourceUrl).toBe("https://api.example.com/resource");
    });

    it("rejects offer missing required field", async () => {
      const { publicJwk, privateKey } = await generateEcKeyPair();
      const payload = makeOfferPayload();
      delete payload.amount; // Remove required field
      const jws = await signPayload(payload, privateKey, { jwk: publicJwk });

      const artifact: X402JwsArtifact = { format: "jws", signature: jws };
      const result = await verifyX402JwsOffer(artifact);

      expect(result.valid).toBe(false);
      const fail = result as JwsVerificationFailure;
      expect(fail.error.code).toBe("INVALID_OFFER_PAYLOAD");
      expect(fail.error.message).toContain("amount");
    });

    it("rejects offer missing scheme", async () => {
      const { publicJwk, privateKey } = await generateEcKeyPair();
      const payload = makeOfferPayload();
      delete payload.scheme;
      const jws = await signPayload(payload, privateKey, { jwk: publicJwk });

      const artifact: X402JwsArtifact = { format: "jws", signature: jws };
      const result = await verifyX402JwsOffer(artifact);

      expect(result.valid).toBe(false);
      const fail = result as JwsVerificationFailure;
      expect(fail.error.code).toBe("INVALID_OFFER_PAYLOAD");
      expect(fail.error.message).toContain("scheme");
    });
  });

  describe("verifyX402JwsReceipt", () => {
    it("verifies a valid receipt with all required fields", async () => {
      const { publicJwk, privateKey } = await generateEcKeyPair();
      const payload = makeReceiptPayload();
      const jws = await signPayload(payload, privateKey, { jwk: publicJwk });

      const artifact: X402JwsArtifact = { format: "jws", signature: jws };
      const result = await verifyX402JwsReceipt(artifact);

      expect(result.valid).toBe(true);
      const success = result as JwsVerificationResult;
      expect(success.payload.payer).toBe("0xabcdef1234567890abcdef1234567890abcdef12");
    });

    it("rejects receipt missing required field", async () => {
      const { publicJwk, privateKey } = await generateEcKeyPair();
      const payload = makeReceiptPayload();
      delete payload.issuedAt; // Remove required field
      const jws = await signPayload(payload, privateKey, { jwk: publicJwk });

      const artifact: X402JwsArtifact = { format: "jws", signature: jws };
      const result = await verifyX402JwsReceipt(artifact);

      expect(result.valid).toBe(false);
      const fail = result as JwsVerificationFailure;
      expect(fail.error.code).toBe("INVALID_RECEIPT_PAYLOAD");
      expect(fail.error.message).toContain("issuedAt");
    });

    it("rejects receipt missing payer", async () => {
      const { publicJwk, privateKey } = await generateEcKeyPair();
      const payload = makeReceiptPayload();
      delete payload.payer;
      const jws = await signPayload(payload, privateKey, { jwk: publicJwk });

      const artifact: X402JwsArtifact = { format: "jws", signature: jws };
      const result = await verifyX402JwsReceipt(artifact);

      expect(result.valid).toBe(false);
      const fail = result as JwsVerificationFailure;
      expect(fail.error.code).toBe("INVALID_RECEIPT_PAYLOAD");
      expect(fail.error.message).toContain("payer");
    });
  });

  describe("kid resolution path", () => {
    it("fails when kid cannot be resolved and no jwk is present", async () => {
      const { publicJwk, privateKey } = await generateEcKeyPair();
      const payload = makeOfferPayload();
      // Sign with kid only (no embedded jwk)
      const jws = await signPayload(payload, privateKey, {
        kid: "did:web:unreachable.example.com#key-1",
      });

      const artifact: X402JwsArtifact = { format: "jws", signature: jws };
      const result = await verifyX402JwsArtifact(artifact);

      expect(result.valid).toBe(false);
      const fail = result as JwsVerificationFailure;
      expect(fail.error.code).toBe("KID_RESOLUTION_FAILED");
    });

    it("verifies with kid resolution using mock fetcher", async () => {
      const { publicJwk, privateKey } = await generateEcKeyPair();
      const payload = makeReceiptPayload();
      const jws = await signPayload(payload, privateKey, {
        kid: "did:web:api.example.com#key-1",
      });

      const mockDidDocument = {
        "@context": ["https://www.w3.org/ns/did/v1"],
        id: "did:web:api.example.com",
        verificationMethod: [
          {
            id: "did:web:api.example.com#key-1",
            type: "JsonWebKey2020",
            controller: "did:web:api.example.com",
            publicKeyJwk: publicJwk,
          },
        ],
      };

      const artifact: X402JwsArtifact = { format: "jws", signature: jws };
      const result = await verifyX402JwsReceipt(artifact, {
        resolveOptions: {
          fetchDidDocument: async () => mockDidDocument,
        },
      });

      expect(result.valid).toBe(true);
      const success = result as JwsVerificationResult;
      expect(success.publicKeySource).toBe("kid-resolution");
      expect(success.kid).toBe("did:web:api.example.com#key-1");
      expect(success.publicKeyDid).toMatch(/^did:jwk:/);
    });

    it("verifies JWS offer using kid resolution only", async () => {
      const { publicJwk, privateKey } = await generateEcKeyPair();
      const payload = makeOfferPayload();
      const jws = await signPayload(payload, privateKey, {
        kid: "did:web:api.example.com#key-1",
      });

      const mockDidDocument = {
        "@context": ["https://www.w3.org/ns/did/v1"],
        id: "did:web:api.example.com",
        verificationMethod: [
          {
            id: "did:web:api.example.com#key-1",
            type: "JsonWebKey2020",
            controller: "did:web:api.example.com",
            publicKeyJwk: publicJwk,
          },
        ],
      };

      const artifact: X402JwsArtifact = { format: "jws", signature: jws };
      const result = await verifyX402JwsOffer(artifact, {
        resolveOptions: {
          fetchDidDocument: async () => mockDidDocument,
        },
      });

      expect(result.valid).toBe(true);
      const success = result as JwsVerificationResult;
      expect(success.publicKeySource).toBe("kid-resolution");
      expect(success.publicKeyDid).toMatch(/^did:jwk:/);
    });

    it("rejects when kid resolves to different key than embedded jwk", async () => {
      const keys1 = await generateEcKeyPair();
      const keys2 = await generateEcKeyPair();

      const payload = makeOfferPayload();
      // Sign with keys1 private key, embed keys1 public jwk
      const jws = await signPayload(payload, keys1.privateKey, {
        jwk: keys1.publicJwk,
        kid: "did:web:api.example.com#key-1",
      });

      // But kid resolves to keys2 public key
      const mockDidDocument = {
        "@context": ["https://www.w3.org/ns/did/v1"],
        id: "did:web:api.example.com",
        verificationMethod: [
          {
            id: "did:web:api.example.com#key-1",
            type: "JsonWebKey2020",
            controller: "did:web:api.example.com",
            publicKeyJwk: keys2.publicJwk,
          },
        ],
      };

      const artifact: X402JwsArtifact = { format: "jws", signature: jws };
      const result = await verifyX402JwsArtifact(artifact, {
        resolveOptions: {
          fetchDidDocument: async () => mockDidDocument,
        },
      });

      expect(result.valid).toBe(false);
      const fail = result as JwsVerificationFailure;
      expect(fail.error.code).toBe("KEY_CONFLICT");
    });
  });

  describe("verifyProof integration", () => {
    it("x402-offer with format jws invokes JWS verification", async () => {
      const { verifyProof } = await import("../src/reputation/verify");
      const { publicJwk, privateKey } = await generateEcKeyPair();
      const payload = makeOfferPayload();
      const jws = await signPayload(payload, privateKey, { jwk: publicJwk });

      const result = await verifyProof({
        proof: {
          proofType: "x402-offer",
          proofObject: { format: "jws", signature: jws },
        },
      });

      expect(result.valid).toBe(true);
      expect(result.proofType).toBe("x402-offer");
    });

    it("x402-receipt with format jws invokes JWS verification", async () => {
      const { verifyProof } = await import("../src/reputation/verify");
      const { publicJwk, privateKey } = await generateEcKeyPair();
      const payload = makeReceiptPayload();
      const jws = await signPayload(payload, privateKey, { jwk: publicJwk });

      const result = await verifyProof({
        proof: {
          proofType: "x402-receipt",
          proofObject: { format: "jws", signature: jws },
        },
      });

      expect(result.valid).toBe(true);
      expect(result.proofType).toBe("x402-receipt");
    });

    it("x402-offer with invalid JWS fails via verifyProof", async () => {
      const { verifyProof } = await import("../src/reputation/verify");

      const result = await verifyProof({
        proof: {
          proofType: "x402-offer",
          proofObject: { format: "jws", signature: "invalid.jws.token" },
        },
      });

      expect(result.valid).toBe(false);
      expect(result.proofType).toBe("x402-offer");
    });

    it("x402-offer without format jws still passes (backward compat)", async () => {
      const { verifyProof } = await import("../src/reputation/verify");

      const result = await verifyProof({
        proof: {
          proofType: "x402-offer",
          proofObject: { someField: "value" },
        },
      });

      expect(result.valid).toBe(true);
      expect(result.proofType).toBe("x402-offer");
    });
  });
});
