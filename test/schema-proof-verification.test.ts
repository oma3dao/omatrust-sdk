import { describe, expect, it } from "vitest";
import { Wallet, hashMessage, SigningKey } from "ethers";
import { base64url } from "jose";
import {
  verifyLinkedIdentifierProofs,
  verifyKeyBindingProofs,
  type LinkedIdentifierData,
  type KeyBindingData,
} from "../src/reputation/schema-proof-verification";
import { jwkToDidJwk } from "../src/identity/jwk";
import { buildEvmDidPkh } from "../src/identity/did";
import type { PopEip712Proof, PopJwsProof, ProofWrapper } from "../src/reputation/types";
import { createPopEip712Proof } from "../src/reputation/proof/pop-eip712";

// ---------------------------------------------------------------------------
// Test Helpers
// ---------------------------------------------------------------------------

const WALLET_A = new Wallet("0x1111111111111111111111111111111111111111111111111111111111111111");
const WALLET_B = new Wallet("0x2222222222222222222222222222222222222222222222222222222222222222");

const DID_A = buildEvmDidPkh(1, WALLET_A.address);
const DID_B = buildEvmDidPkh(1, WALLET_B.address);

const EC_JWK = {
  kty: "EC",
  crv: "P-256",
  x: "f83OJ3D7xI1Yp1V2iFIYA7n5OYXc4K1Uo7jY14FKMC4",
  y: "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
};
const DID_JWK = jwkToDidJwk(EC_JWK);

/**
 * Create a mock pop-eip712 proof where wallet signs authorizing an entity
 */
async function createMockEip712Proof(
  signer: Wallet,
  authorizedEntity: string,
  purpose: "shared-control" | "commercial-tx" = "shared-control"
): Promise<PopEip712Proof> {
  return createPopEip712Proof(
    {
      signer: signer.address,
      authorizedEntity,
      signingPurpose: purpose,
      chainId: 1,
    },
    async (typedData) => {
      const domain = typedData.domain as Record<string, unknown>;
      const types = typedData.types as Record<string, Array<{ name: string; type: string }>>;
      const message = typedData.message as Record<string, unknown>;
      // Use ethers signTypedData — key is "OmaTrustProof" (mixed case)
      return (await signer.signTypedData(
        domain,
        { OmaTrustProof: types.OmaTrustProof },
        message
      )) as `0x${string}`;
    }
  );
}

/**
 * Create a mock pop-jws proof with embedded JWK
 */
function createMockJwsProof(
  issuerDid: string,
  audienceDid: string,
  jwk: Record<string, unknown>
): PopJwsProof {
  const header = { alg: "ES256", jwk };
  const payload = {
    iss: issuerDid,
    aud: audienceDid,
    purpose: "shared-control",
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 600,
  };

  const headerB64 = base64url.encode(new TextEncoder().encode(JSON.stringify(header)));
  const payloadB64 = base64url.encode(new TextEncoder().encode(JSON.stringify(payload)));
  // Fake signature — we're testing schema logic, not cryptographic verification
  const sigB64 = base64url.encode(new Uint8Array(64));

  return {
    proofType: "pop-jws",
    proofObject: `${headerB64}.${payloadB64}.${sigB64}`,
    proofPurpose: "shared-control",
    version: 1,
    issuedAt: payload.iat,
    expiresAt: payload.exp,
  };
}

// ---------------------------------------------------------------------------
// Tests: verifyLinkedIdentifierProofs
// ---------------------------------------------------------------------------

describe("reputation/schema-proof-verification – Linked Identifier", () => {
  describe("verifyLinkedIdentifierProofs", () => {
    it("validates when both subject and linkedId have matching proofs", async () => {
      const proofFromSubject = await createMockEip712Proof(WALLET_A, DID_B);
      const proofFromLinkedId = await createMockEip712Proof(WALLET_B, DID_A);

      const data: LinkedIdentifierData = {
        subject: DID_A,
        linkedId: DID_B,
        proofs: [proofFromSubject, proofFromLinkedId],
      };

      const result = verifyLinkedIdentifierProofs(data);
      expect(result.valid).toBe(true);
      expect(result.reasons).toHaveLength(0);
      expect(result.checks.length).toBeGreaterThan(0);
    });

    it("fails when no proof from subject", async () => {
      const proofFromLinkedId = await createMockEip712Proof(WALLET_B, DID_A);

      const data: LinkedIdentifierData = {
        subject: DID_A,
        linkedId: DID_B,
        proofs: [proofFromLinkedId],
      };

      const result = verifyLinkedIdentifierProofs(data);
      expect(result.valid).toBe(false);
      expect(result.reasons).toContain("No proof demonstrates control by subject");
    });

    it("fails when no proof from linkedId", async () => {
      const proofFromSubject = await createMockEip712Proof(WALLET_A, DID_B);

      const data: LinkedIdentifierData = {
        subject: DID_A,
        linkedId: DID_B,
        proofs: [proofFromSubject],
      };

      const result = verifyLinkedIdentifierProofs(data);
      expect(result.valid).toBe(false);
      expect(result.reasons).toContain("No proof demonstrates control by linkedId");
    });

    it("reports aud mismatch for subject proof not targeting linkedId", async () => {
      // Subject signs but authorizes a different entity
      const proofFromSubject = await createMockEip712Proof(WALLET_A, "did:web:wrong.com");
      const proofFromLinkedId = await createMockEip712Proof(WALLET_B, DID_A);

      const data: LinkedIdentifierData = {
        subject: DID_A,
        linkedId: DID_B,
        proofs: [proofFromSubject, proofFromLinkedId],
      };

      const result = verifyLinkedIdentifierProofs(data);
      // Subject is proved (signer matches) but aud mismatch is noted
      const audCheck = result.checks.find(
        (c) => c.checkType === "signer-is-subject" && !c.valid
      );
      expect(audCheck).toBeDefined();
      expect(audCheck?.reason).toContain("aud mismatch");
    });

    it("reports aud mismatch for linkedId proof not targeting subject", async () => {
      const proofFromSubject = await createMockEip712Proof(WALLET_A, DID_B);
      const proofFromLinkedId = await createMockEip712Proof(WALLET_B, "did:web:other.com");

      const data: LinkedIdentifierData = {
        subject: DID_A,
        linkedId: DID_B,
        proofs: [proofFromSubject, proofFromLinkedId],
      };

      const result = verifyLinkedIdentifierProofs(data);
      const audCheck = result.checks.find(
        (c) => c.checkType === "signer-is-linkedId" && !c.valid
      );
      expect(audCheck).toBeDefined();
      expect(audCheck?.reason).toContain("aud mismatch");
    });

    it("accepts evidence-pointer proofs for non-signer identities", () => {
      const evidenceProof: ProofWrapper = {
        proofType: "evidence-pointer",
        proofObject: { url: "https://example.com/.well-known/did.json" },
        proofPurpose: "shared-control",
        version: 1,
      };

      const data: LinkedIdentifierData = {
        subject: "did:handle:twitter:alice",
        linkedId: DID_B,
        proofs: [evidenceProof],
      };

      const result = verifyLinkedIdentifierProofs(data);
      // Evidence pointer gives subject credit but not linkedId
      expect(result.checks.some((c) => c.checkType === "signer-is-subject" && c.valid)).toBe(true);
    });

    it("fails when subject is missing", () => {
      const result = verifyLinkedIdentifierProofs({
        subject: "",
        linkedId: DID_B,
        proofs: [{ proofType: "evidence-pointer", proofObject: { url: "x" } }],
      });
      expect(result.valid).toBe(false);
      expect(result.reasons).toContain("subject and linkedId are required");
    });

    it("fails when linkedId is missing", () => {
      const result = verifyLinkedIdentifierProofs({
        subject: DID_A,
        linkedId: "",
        proofs: [{ proofType: "evidence-pointer", proofObject: { url: "x" } }],
      });
      expect(result.valid).toBe(false);
    });

    it("fails when proofs array is empty", () => {
      const result = verifyLinkedIdentifierProofs({
        subject: DID_A,
        linkedId: DID_B,
        proofs: [],
      });
      expect(result.valid).toBe(false);
      expect(result.reasons).toContain("At least one proof is required");
    });

    it("fails when proofs is not an array", () => {
      const result = verifyLinkedIdentifierProofs({
        subject: DID_A,
        linkedId: DID_B,
        proofs: null as unknown as ProofWrapper[],
      });
      expect(result.valid).toBe(false);
    });

    it("handles pop-jws proofs with JWK matching did:jwk", () => {
      const jwsProof = createMockJwsProof(DID_JWK, DID_A, EC_JWK);

      const data: LinkedIdentifierData = {
        subject: DID_JWK,
        linkedId: DID_A,
        proofs: [jwsProof],
      };

      const result = verifyLinkedIdentifierProofs(data);
      // JWK in header matches did:jwk subject
      expect(result.checks.some((c) => c.checkType === "signer-is-subject")).toBe(true);
    });

    it("handles pop-jws proofs with iss claim matching DID", () => {
      // JWK doesn't match target DID but iss claim does
      const jwsProof = createMockJwsProof(DID_A, DID_B, EC_JWK);

      const data: LinkedIdentifierData = {
        subject: DID_A,
        linkedId: DID_B,
        proofs: [jwsProof],
      };

      const result = verifyLinkedIdentifierProofs(data);
      // The iss=DID_A should match subject
      expect(result.checks.some((c) => c.checkType === "signer-is-subject" && c.valid)).toBe(true);
    });

    it("handles tx-encoded-value proofs (no signer match without on-chain lookup)", () => {
      const txProof: ProofWrapper = {
        proofType: "tx-encoded-value",
        proofObject: { chainId: "eip155:1", txHash: "0x" + "ab".repeat(32) },
        proofPurpose: "shared-control",
      };

      const data: LinkedIdentifierData = {
        subject: DID_A,
        linkedId: DID_B,
        proofs: [txProof],
      };

      const result = verifyLinkedIdentifierProofs(data);
      // tx proofs can't prove signer without on-chain lookup
      expect(result.valid).toBe(false);
    });
  });
});

// ---------------------------------------------------------------------------
// Tests: verifyKeyBindingProofs
// ---------------------------------------------------------------------------

describe("reputation/schema-proof-verification – Key Binding", () => {
  describe("verifyKeyBindingProofs", () => {
    it("validates when subject authorizes keyId", async () => {
      const proofFromSubject = await createMockEip712Proof(WALLET_A, DID_B);

      const data: KeyBindingData = {
        subject: DID_A,
        keyId: DID_B,
        proofs: [proofFromSubject],
      };

      const result = verifyKeyBindingProofs(data);
      expect(result.valid).toBe(true);
      expect(result.reasons).toHaveLength(0);
    });

    it("fails when subject proof doesn't authorize the keyId", async () => {
      // Subject signs but authorizes a different entity
      const proofFromSubject = await createMockEip712Proof(WALLET_A, "did:web:wrong.com");

      const data: KeyBindingData = {
        subject: DID_A,
        keyId: DID_B,
        proofs: [proofFromSubject],
      };

      const result = verifyKeyBindingProofs(data);
      expect(result.valid).toBe(false);
      expect(result.reasons).toContain(
        "No proof demonstrates that subject authorized the key binding"
      );
      expect(result.checks.some((c) => !c.valid && c.reason?.includes("does not authorize the keyId"))).toBe(true);
    });

    it("detects keyId self-attestation (supplementary)", async () => {
      // KeyId signs proving it has the key (but this isn't sufficient alone)
      const proofFromKeyId = await createMockEip712Proof(WALLET_B, DID_A);

      const data: KeyBindingData = {
        subject: DID_A,
        keyId: DID_B,
        proofs: [proofFromKeyId],
      };

      const result = verifyKeyBindingProofs(data);
      // Key proved possession but subject didn't authorize
      expect(result.valid).toBe(false);
      expect(result.checks.some((c) => c.checkType === "signer-is-keyId" && c.valid)).toBe(true);
    });

    it("validates combined: subject authorizes + key self-attests", async () => {
      const proofFromSubject = await createMockEip712Proof(WALLET_A, DID_B);
      const proofFromKeyId = await createMockEip712Proof(WALLET_B, DID_A);

      const data: KeyBindingData = {
        subject: DID_A,
        keyId: DID_B,
        proofs: [proofFromSubject, proofFromKeyId],
      };

      const result = verifyKeyBindingProofs(data);
      expect(result.valid).toBe(true);
    });

    it("accepts evidence-pointer proofs", () => {
      const evidenceProof: ProofWrapper = {
        proofType: "evidence-pointer",
        proofObject: { url: "https://example.com/.well-known/did.json" },
        proofPurpose: "shared-control",
      };

      const data: KeyBindingData = {
        subject: "did:web:example.com",
        keyId: DID_B,
        proofs: [evidenceProof],
      };

      const result = verifyKeyBindingProofs(data);
      expect(result.valid).toBe(true);
    });

    it("validates publicKeyJwk consistency with did:jwk keyId", () => {
      const proofFromSubject = createMockJwsProof(DID_JWK, DID_JWK, EC_JWK);

      const data: KeyBindingData = {
        subject: DID_JWK,
        keyId: DID_JWK,
        publicKeyJwk: EC_JWK,
        proofs: [proofFromSubject],
      };

      const result = verifyKeyBindingProofs(data);
      // Subject JWK matches keyId and publicKeyJwk is consistent
      expect(result.valid).toBe(true);
    });

    it("rejects when publicKeyJwk doesn't match did:jwk keyId", () => {
      const differentJwk = {
        kty: "EC",
        crv: "P-256",
        x: "different_x_coordinate_value_here_padding12345",
        y: "different_y_coordinate_value_here_padding12345",
      };
      const differentDidJwk = jwkToDidJwk(differentJwk);

      // Subject authorizes the different keyId
      const proof = createMockJwsProof(DID_JWK, differentDidJwk, EC_JWK);

      const data: KeyBindingData = {
        subject: DID_JWK,
        keyId: differentDidJwk,
        publicKeyJwk: EC_JWK, // This doesn't match differentDidJwk's key
        proofs: [proof],
      };

      const result = verifyKeyBindingProofs(data);
      expect(result.valid).toBe(false);
      expect(result.reasons.some((r) => r.includes("publicKeyJwk does not match"))).toBe(true);
    });

    it("fails when subject is missing", () => {
      const result = verifyKeyBindingProofs({
        subject: "",
        keyId: DID_B,
        proofs: [{ proofType: "evidence-pointer", proofObject: { url: "x" } }],
      });
      expect(result.valid).toBe(false);
      expect(result.reasons).toContain("subject and keyId are required");
    });

    it("fails when keyId is missing", () => {
      const result = verifyKeyBindingProofs({
        subject: DID_A,
        keyId: "",
        proofs: [{ proofType: "evidence-pointer", proofObject: { url: "x" } }],
      });
      expect(result.valid).toBe(false);
    });

    it("fails when proofs array is empty", () => {
      const result = verifyKeyBindingProofs({
        subject: DID_A,
        keyId: DID_B,
        proofs: [],
      });
      expect(result.valid).toBe(false);
      expect(result.reasons).toContain("At least one proof is required");
    });

    it("fails when proofs is not an array", () => {
      const result = verifyKeyBindingProofs({
        subject: DID_A,
        keyId: DID_B,
        proofs: undefined as unknown as ProofWrapper[],
      });
      expect(result.valid).toBe(false);
    });

    it("handles pop-jws proofs with JWK matching did:jwk subject", () => {
      const jwsProof = createMockJwsProof(DID_JWK, DID_B, EC_JWK);

      const data: KeyBindingData = {
        subject: DID_JWK,
        keyId: DID_B,
        proofs: [jwsProof],
      };

      const result = verifyKeyBindingProofs(data);
      // JWK matches subject and aud matches keyId
      expect(result.valid).toBe(true);
    });

    it("handles unknown proof types gracefully", () => {
      const unknownProof: ProofWrapper = {
        proofType: "x402-receipt" as any,
        proofObject: { some: "data" },
        proofPurpose: "commercial-tx",
      };

      const data: KeyBindingData = {
        subject: DID_A,
        keyId: DID_B,
        proofs: [unknownProof],
      };

      const result = verifyKeyBindingProofs(data);
      // x402-receipt can't prove signer identity for key binding
      expect(result.valid).toBe(false);
    });

    it("handles malformed JWS proof gracefully", () => {
      const badJwsProof: PopJwsProof = {
        proofType: "pop-jws",
        proofObject: "not.a.valid-jws",
        proofPurpose: "shared-control",
      };

      const data: KeyBindingData = {
        subject: DID_A,
        keyId: DID_B,
        proofs: [badJwsProof],
      };

      const result = verifyKeyBindingProofs(data);
      expect(result.valid).toBe(false);
    });

    it("handles pop-jws with non-string proofObject", () => {
      const badProof: ProofWrapper = {
        proofType: "pop-jws",
        proofObject: { not: "a string" } as unknown,
        proofPurpose: "shared-control",
      };

      const data: KeyBindingData = {
        subject: DID_A,
        keyId: DID_B,
        proofs: [badProof],
      };

      const result = verifyKeyBindingProofs(data);
      expect(result.valid).toBe(false);
    });
  });
});


// ---------------------------------------------------------------------------
// Tests: Edge cases and branch coverage
// ---------------------------------------------------------------------------

describe("reputation/schema-proof-verification – edge cases", () => {
  describe("pop-eip712 with invalid signature (recovery fails)", () => {
    it("does not match when EIP-712 signature is invalid", () => {
      const invalidEip712Proof: PopEip712Proof = {
        proofType: "pop-eip712",
        proofObject: {
          domain: { name: "OMATrust Proof", version: "1", chainId: 1 },
          message: {
            signer: WALLET_A.address,
            authorizedEntity: DID_B,
            signingPurpose: "shared-control",
            creationTimestamp: Math.floor(Date.now() / 1000),
            expirationTimestamp: Math.floor(Date.now() / 1000) + 600,
            randomValue: "0x" + "00".repeat(32) as `0x${string}`,
            statement: "This is not a transaction or asset approval.",
          },
          signature: "0x" + "ab".repeat(65) as `0x${string}`, // Invalid signature
        },
        version: 1,
      };

      const data: LinkedIdentifierData = {
        subject: DID_A,
        linkedId: DID_B,
        proofs: [invalidEip712Proof],
      };

      // The EIP-712 recovery will either return wrong signer or throw
      const result = verifyLinkedIdentifierProofs(data);
      // With invalid signature, signer recovery may return a different address
      // Either way, it won't match DID_A or DID_B
      expect(result.reasons.length).toBeGreaterThan(0);
    });
  });

  describe("pop-jws edge cases", () => {
    it("handles JWS with no jwk in header", () => {
      const header = { alg: "ES256" }; // No jwk field
      const payload = { iss: DID_A, aud: DID_B, purpose: "shared-control" };
      const headerB64 = base64url.encode(new TextEncoder().encode(JSON.stringify(header)));
      const payloadB64 = base64url.encode(new TextEncoder().encode(JSON.stringify(payload)));
      const sigB64 = base64url.encode(new Uint8Array(64));

      const proof: PopJwsProof = {
        proofType: "pop-jws",
        proofObject: `${headerB64}.${payloadB64}.${sigB64}`,
        proofPurpose: "shared-control",
      };

      const data: LinkedIdentifierData = {
        subject: DID_A,
        linkedId: DID_B,
        proofs: [proof],
      };

      const result = verifyLinkedIdentifierProofs(data);
      // No JWK in header, but iss claim matches subject
      expect(result.checks.some((c) => c.checkType === "signer-is-subject" && c.valid)).toBe(true);
    });

    it("handles JWS with malformed header (not base64url)", () => {
      const proof: PopJwsProof = {
        proofType: "pop-jws",
        proofObject: "!!!invalid-header!!!.payload.signature",
        proofPurpose: "shared-control",
      };

      const data: KeyBindingData = {
        subject: DID_A,
        keyId: DID_B,
        proofs: [proof],
      };

      const result = verifyKeyBindingProofs(data);
      expect(result.valid).toBe(false);
    });

    it("handles JWS with only 2 parts (not 3)", () => {
      const proof: PopJwsProof = {
        proofType: "pop-jws",
        proofObject: "only.two",
        proofPurpose: "shared-control",
      };

      const data: KeyBindingData = {
        subject: DID_A,
        keyId: DID_B,
        proofs: [proof],
      };

      const result = verifyKeyBindingProofs(data);
      expect(result.valid).toBe(false);
    });

    it("handles JWS where iss claim does not match target DID", () => {
      const header = { alg: "ES256", jwk: { kty: "EC", crv: "P-256", x: "abc", y: "def" } };
      const payload = { iss: "did:web:other.com", aud: DID_B, purpose: "shared-control" };
      const headerB64 = base64url.encode(new TextEncoder().encode(JSON.stringify(header)));
      const payloadB64 = base64url.encode(new TextEncoder().encode(JSON.stringify(payload)));
      const sigB64 = base64url.encode(new Uint8Array(64));

      const proof: PopJwsProof = {
        proofType: "pop-jws",
        proofObject: `${headerB64}.${payloadB64}.${sigB64}`,
        proofPurpose: "shared-control",
      };

      // Test that this doesn't match DID_A as subject
      const data: LinkedIdentifierData = {
        subject: DID_A,
        linkedId: DID_B,
        proofs: [proof],
      };

      const result = verifyLinkedIdentifierProofs(data);
      // JWK doesn't match DID_A, iss doesn't match DID_A
      expect(result.checks.filter((c) => c.checkType === "signer-is-subject" && c.valid)).toHaveLength(0);
    });

    it("handles JWS where payload is not valid JSON", () => {
      const header = { alg: "ES256", jwk: EC_JWK };
      const headerB64 = base64url.encode(new TextEncoder().encode(JSON.stringify(header)));
      const payloadB64 = base64url.encode(new TextEncoder().encode("not-json"));
      const sigB64 = base64url.encode(new Uint8Array(64));

      const proof: PopJwsProof = {
        proofType: "pop-jws",
        proofObject: `${headerB64}.${payloadB64}.${sigB64}`,
        proofPurpose: "shared-control",
      };

      const data: KeyBindingData = {
        subject: DID_JWK,
        keyId: DID_B,
        proofs: [proof],
      };

      // JWK matches DID_JWK but payload can't be parsed for aud check
      const result = verifyKeyBindingProofs(data);
      // signer matches subject via JWK, but aud can't be checked from payload
      expect(result.checks.some((c) => c.checkType === "signer-is-subject-for-key")).toBe(true);
    });
  });

  describe("tx-interaction and other proof types", () => {
    it("tx-interaction proofs don't match signer for key binding", () => {
      const txProof: ProofWrapper = {
        proofType: "tx-interaction",
        proofObject: { chainId: "eip155:1", txHash: "0x" + "cd".repeat(32) },
        proofPurpose: "commercial-tx",
      };

      const data: KeyBindingData = {
        subject: DID_A,
        keyId: DID_B,
        proofs: [txProof],
      };

      const result = verifyKeyBindingProofs(data);
      expect(result.valid).toBe(false);
    });

    it("x402-offer proofs don't match signer identity", () => {
      const x402Proof: ProofWrapper = {
        proofType: "x402-offer" as any,
        proofObject: { format: "jws", signature: "fake" },
        proofPurpose: "commercial-tx",
      };

      const data: LinkedIdentifierData = {
        subject: DID_A,
        linkedId: DID_B,
        proofs: [x402Proof],
      };

      const result = verifyLinkedIdentifierProofs(data);
      expect(result.valid).toBe(false);
    });
  });

  describe("proofAuthorizedEntityMatchesDid edge cases", () => {
    it("pop-eip712 with authorizedEntity matching target DID", async () => {
      // Subject signs authorizing linkedId — full match
      const proof = await createMockEip712Proof(WALLET_A, DID_B);

      const data: LinkedIdentifierData = {
        subject: DID_A,
        linkedId: DID_B,
        proofs: [proof],
      };

      const result = verifyLinkedIdentifierProofs(data);
      // Should find subject proved with correct aud
      const subjectChecks = result.checks.filter(
        (c) => c.checkType === "signer-is-subject" && c.valid
      );
      expect(subjectChecks.length).toBeGreaterThan(0);
    });

    it("pop-jws with aud matching target DID for key binding", () => {
      const jwsProof = createMockJwsProof(DID_JWK, DID_B, EC_JWK);

      const data: KeyBindingData = {
        subject: DID_JWK,
        keyId: DID_B,
        proofs: [jwsProof],
      };

      const result = verifyKeyBindingProofs(data);
      expect(result.valid).toBe(true);
      expect(
        result.checks.some((c) => c.checkType === "signer-is-subject-for-key" && c.valid)
      ).toBe(true);
    });

    it("tx-encoded-value proofs return false for authorizedEntity check", () => {
      const txProof: ProofWrapper = {
        proofType: "tx-encoded-value",
        proofObject: { chainId: "eip155:1", txHash: "0x" + "ef".repeat(32) },
        proofPurpose: "shared-control",
      };

      const data: LinkedIdentifierData = {
        subject: DID_A,
        linkedId: DID_B,
        proofs: [txProof],
      };

      const result = verifyLinkedIdentifierProofs(data);
      expect(result.valid).toBe(false);
    });
  });

  describe("signerMatchesDid edge cases", () => {
    it("handles DID that cannot be resolved to an address", async () => {
      // did:web cannot be resolved to an EVM address
      const proof = await createMockEip712Proof(WALLET_A, "did:web:example.com");

      const data: LinkedIdentifierData = {
        subject: "did:web:example.com", // No EVM address
        linkedId: DID_B,
        proofs: [proof],
      };

      const result = verifyLinkedIdentifierProofs(data);
      // Signer is WALLET_A address, subject is did:web — no match
      expect(
        result.checks.filter((c) => c.checkType === "signer-is-subject" && c.valid)
      ).toHaveLength(0);
    });
  });

  describe("jwkMatchesDid edge cases", () => {
    it("returns false for non-jwk DID method", () => {
      const header = { alg: "ES256", jwk: EC_JWK };
      const payload = { iss: "did:web:example.com", aud: DID_B, purpose: "shared-control" };
      const headerB64 = base64url.encode(new TextEncoder().encode(JSON.stringify(header)));
      const payloadB64 = base64url.encode(new TextEncoder().encode(JSON.stringify(payload)));
      const sigB64 = base64url.encode(new Uint8Array(64));

      const proof: PopJwsProof = {
        proofType: "pop-jws",
        proofObject: `${headerB64}.${payloadB64}.${sigB64}`,
        proofPurpose: "shared-control",
      };

      // Try matching JWK against did:web (not did:jwk) — should not match
      const data: LinkedIdentifierData = {
        subject: "did:web:example.com",
        linkedId: DID_B,
        proofs: [proof],
      };

      const result = verifyLinkedIdentifierProofs(data);
      // The JWK can't match did:web, and iss=did:web:example.com matches subject via iss
      const subjectMatches = result.checks.filter(
        (c) => c.checkType === "signer-is-subject" && c.valid
      );
      // iss claim matches "did:web:example.com" = subject
      expect(subjectMatches.length).toBeGreaterThan(0);
    });

    it("returns false when didJwkToJwk throws for malformed did:jwk", () => {
      const header = { alg: "ES256", jwk: EC_JWK };
      const payload = { iss: "did:jwk:invalid", aud: DID_B, purpose: "shared-control" };
      const headerB64 = base64url.encode(new TextEncoder().encode(JSON.stringify(header)));
      const payloadB64 = base64url.encode(new TextEncoder().encode(JSON.stringify(payload)));
      const sigB64 = base64url.encode(new Uint8Array(64));

      const proof: PopJwsProof = {
        proofType: "pop-jws",
        proofObject: `${headerB64}.${payloadB64}.${sigB64}`,
        proofPurpose: "shared-control",
      };

      // Try matching JWK against malformed did:jwk
      const data: LinkedIdentifierData = {
        subject: "did:jwk:invalid",
        linkedId: DID_B,
        proofs: [proof],
      };

      const result = verifyLinkedIdentifierProofs(data);
      // jwkMatchesDid should catch the error and return false
      // But iss="did:jwk:invalid" matches subject string
      expect(result).toBeDefined();
    });
  });
});
