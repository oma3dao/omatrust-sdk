import { describe, expect, it, vi, beforeEach, afterEach } from "vitest";
import { Wallet } from "ethers";
import { calculateTransferAmount, getOmaTrustProofEip712Types } from "../src/reputation";
import { verifyProof, verifyAttestation } from "../src/reputation/verify";
import type { AttestationQueryResult, ProofWrapper } from "../src/reputation/types";

function makeAttestation(overrides?: Partial<AttestationQueryResult>): AttestationQueryResult {
  return {
    uid: "0x" + "0".repeat(64) as `0x${string}`,
    schema: "0x" + "0".repeat(64) as `0x${string}`,
    attester: "0x1111111111111111111111111111111111111111" as `0x${string}`,
    recipient: "0x2222222222222222222222222222222222222222" as `0x${string}`,
    revocable: true,
    revocationTime: 0n,
    expirationTime: 0n,
    time: BigInt(Math.floor(Date.now() / 1000)),
    refUID: "0x" + "0".repeat(64) as `0x${string}`,
    data: {},
    ...overrides
  };
}

describe("reputation/verify", () => {
  describe("verifyProof", () => {
    describe("tx-encoded-value", () => {
      it("returns invalid when no provider", async () => {
        const proof: ProofWrapper = {
          proofType: "tx-encoded-value",
          proofObject: { chainId: "eip155:1", txHash: "0x" + "a".repeat(64) }
        };
        const result = await verifyProof({ proof });
        expect(result.valid).toBe(false);
        expect(result.reason).toContain("Provider is required");
      });

      it("returns invalid when expectedSubject or expectedController missing", async () => {
        const proof: ProofWrapper = {
          proofType: "tx-encoded-value",
          proofObject: { chainId: "eip155:1", txHash: "0x" + "a".repeat(64) }
        };
        const provider = { getTransaction: vi.fn() };
        const result = await verifyProof({ proof, provider });
        expect(result.valid).toBe(false);
        expect(result.reason).toContain("expectedSubject and expectedController are required");
      });

      it("returns invalid when transaction not found", async () => {
        const proof: ProofWrapper = {
          proofType: "tx-encoded-value",
          proofObject: { chainId: "eip155:1", txHash: "0x" + "a".repeat(64) }
        };
        const provider = { getTransaction: vi.fn().mockResolvedValue(null) };
        const result = await verifyProof({
          proof,
          provider,
          expectedSubject: "did:pkh:eip155:1:0x1111111111111111111111111111111111111111",
          expectedController: "did:pkh:eip155:1:0x2222222222222222222222222222222222222222"
        });
        expect(result.valid).toBe(false);
        expect(result.reason).toContain("Transaction not found");
      });

      it("returns invalid when sender mismatches", async () => {
        const proof: ProofWrapper = {
          proofType: "tx-encoded-value",
          proofObject: { chainId: "eip155:1", txHash: "0x" + "a".repeat(64) }
        };
        const provider = {
          getTransaction: vi.fn().mockResolvedValue({
            from: "0x3333333333333333333333333333333333333333",
            to: "0x2222222222222222222222222222222222222222",
            value: 0n
          })
        };
        const result = await verifyProof({
          proof,
          provider,
          expectedSubject: "did:pkh:eip155:1:0x1111111111111111111111111111111111111111",
          expectedController: "did:pkh:eip155:1:0x2222222222222222222222222222222222222222"
        });
        expect(result.valid).toBe(false);
        expect(result.reason).toContain("sender mismatch");
      });

      it("returns invalid when recipient mismatches", async () => {
        const proof: ProofWrapper = {
          proofType: "tx-encoded-value",
          proofObject: { chainId: "eip155:1", txHash: "0x" + "a".repeat(64) }
        };
        const provider = {
          getTransaction: vi.fn().mockResolvedValue({
            from: "0x1111111111111111111111111111111111111111",
            to: "0x3333333333333333333333333333333333333333",
            value: 0n
          })
        };
        const result = await verifyProof({
          proof,
          provider,
          expectedSubject: "did:pkh:eip155:1:0x1111111111111111111111111111111111111111",
          expectedController: "did:pkh:eip155:1:0x2222222222222222222222222222222222222222"
        });
        expect(result.valid).toBe(false);
        expect(result.reason).toContain("recipient mismatch");
      });

      it("returns invalid when amount mismatches", async () => {
        const proof: ProofWrapper = {
          proofType: "tx-encoded-value",
          proofObject: { chainId: "eip155:1", txHash: "0x" + "a".repeat(64) }
        };
        const provider = {
          getTransaction: vi.fn().mockResolvedValue({
            from: "0x1111111111111111111111111111111111111111",
            to: "0x2222222222222222222222222222222222222222",
            value: 999n // wrong amount
          })
        };
        const result = await verifyProof({
          proof,
          provider,
          expectedSubject: "did:pkh:eip155:1:0x1111111111111111111111111111111111111111",
          expectedController: "did:pkh:eip155:1:0x2222222222222222222222222222222222222222"
        });
        expect(result.valid).toBe(false);
        expect(result.reason).toContain("amount mismatch");
      });

      it("returns valid when tx matches expected subject, controller, and amount", async () => {
        const subject = "did:pkh:eip155:1:0x1111111111111111111111111111111111111111";
        const controller = "did:pkh:eip155:1:0x2222222222222222222222222222222222222222";
        const expectedAmount = calculateTransferAmount(subject, controller, 1, "shared-control");

        const proof: ProofWrapper = {
          proofType: "tx-encoded-value",
          proofPurpose: "shared-control",
          proofObject: { chainId: "eip155:1", txHash: "0x" + "a".repeat(64) }
        };
        const provider = {
          getTransaction: vi.fn().mockResolvedValue({
            from: "0x1111111111111111111111111111111111111111",
            to: "0x2222222222222222222222222222222222222222",
            value: expectedAmount
          })
        };
        const result = await verifyProof({
          proof,
          provider,
          expectedSubject: subject,
          expectedController: controller
        });
        expect(result.valid).toBe(true);
        expect(result.proofType).toBe("tx-encoded-value");
      });

      it("throws PROOF_VERIFICATION_FAILED when provider.getTransaction rejects", async () => {
        const proof: ProofWrapper = {
          proofType: "tx-encoded-value",
          proofObject: { chainId: "eip155:1", txHash: "0x" + "a".repeat(64) }
        };
        const provider = { getTransaction: vi.fn().mockRejectedValue(new Error("RPC failed")) };
        await expect(
          verifyProof({
            proof,
            provider,
            expectedSubject: "did:pkh:eip155:1:0x1111111111111111111111111111111111111111",
            expectedController: "did:pkh:eip155:1:0x2222222222222222222222222222222222222222"
          })
        ).rejects.toThrow("Proof verification failed");
      });

      it("accepts chainId as number in proofObject", async () => {
        const subject = "did:pkh:eip155:1:0x1111111111111111111111111111111111111111";
        const controller = "did:pkh:eip155:1:0x2222222222222222222222222222222222222222";
        const expectedAmount = calculateTransferAmount(subject, controller, 1, "shared-control");

        const proof: ProofWrapper = {
          proofType: "tx-encoded-value",
          proofPurpose: "shared-control",
          proofObject: { chainId: 1, txHash: "0x" + "a".repeat(64) } as unknown as { chainId: string; txHash: string }
        };
        const provider = {
          getTransaction: vi.fn().mockResolvedValue({
            from: "0x1111111111111111111111111111111111111111",
            to: "0x2222222222222222222222222222222222222222",
            value: expectedAmount
          })
        };
        const result = await verifyProof({
          proof,
          provider,
          expectedSubject: subject,
          expectedController: controller
        });
        expect(result.valid).toBe(true);
      });
    });

    describe("tx-interaction", () => {
      it("returns invalid when no provider", async () => {
        const proof: ProofWrapper = {
          proofType: "tx-interaction",
          proofObject: { txHash: "0x" + "a".repeat(64) }
        };
        const result = await verifyProof({ proof });
        expect(result.valid).toBe(false);
        expect(result.reason).toContain("Provider is required");
      });

      it("returns invalid when transaction not found", async () => {
        const proof: ProofWrapper = {
          proofType: "tx-interaction",
          proofObject: { txHash: "0x" + "a".repeat(64) }
        };
        const provider = { getTransaction: vi.fn().mockResolvedValue(null) };
        const result = await verifyProof({ proof, provider });
        expect(result.valid).toBe(false);
        expect(result.reason).toContain("Transaction not found");
      });

      it("returns invalid when transaction target missing", async () => {
        const proof: ProofWrapper = {
          proofType: "tx-interaction",
          proofObject: { txHash: "0x" + "a".repeat(64) }
        };
        const provider = { getTransaction: vi.fn().mockResolvedValue({ to: null }) };
        const result = await verifyProof({ proof, provider });
        expect(result.valid).toBe(false);
        expect(result.reason).toContain("target missing");
      });

      it("returns valid when transaction has target", async () => {
        const proof: ProofWrapper = {
          proofType: "tx-interaction",
          proofObject: { txHash: "0x" + "a".repeat(64) }
        };
        const provider = {
          getTransaction: vi.fn().mockResolvedValue({
            to: "0x1111111111111111111111111111111111111111"
          })
        };
        const result = await verifyProof({ proof, provider });
        expect(result.valid).toBe(true);
        expect(result.proofType).toBe("tx-interaction");
      });
    });

    describe("pop-jws", () => {
      // Create a valid non-expired JWS token (header.payload.signature)
      function makeJws(payload: Record<string, unknown>): string {
        const header = Buffer.from(JSON.stringify({ alg: "ES256K", typ: "JWT" })).toString("base64url");
        const body = Buffer.from(JSON.stringify(payload)).toString("base64url");
        return `${header}.${body}.fakesignature`;
      }

      it("returns invalid for non-string proofObject", async () => {
        const proof: ProofWrapper = {
          proofType: "pop-jws",
          proofObject: { invalid: true }
        };
        const result = await verifyProof({ proof });
        expect(result.valid).toBe(false);
        expect(result.reason).toContain("Invalid JWS proof payload");
      });

      it("returns invalid for expired JWS", async () => {
        const jws = makeJws({ iss: "did:web:a.com", exp: 1000 }); // expired in 1970
        const proof: ProofWrapper = { proofType: "pop-jws", proofObject: jws };
        const result = await verifyProof({ proof });
        expect(result.valid).toBe(false);
        expect(result.reason).toContain("expired");
      });

      it("returns valid for non-expired JWS", async () => {
        const futureExp = Math.floor(Date.now() / 1000) + 3600;
        const jws = makeJws({ iss: "did:web:a.com", exp: futureExp });
        const proof: ProofWrapper = { proofType: "pop-jws", proofObject: jws };
        const result = await verifyProof({ proof });
        expect(result.valid).toBe(true);
        expect(result.proofType).toBe("pop-jws");
      });

      it("returns valid when no exp claim is present", async () => {
        const jws = makeJws({ iss: "did:web:a.com" });
        const proof: ProofWrapper = { proofType: "pop-jws", proofObject: jws };
        const result = await verifyProof({ proof });
        expect(result.valid).toBe(true);
      });
    });

    describe("pop-eip712", () => {
      it("returns valid when signature matches message.signer", async () => {
        const wallet = Wallet.createRandom();
        const { types, primaryType } = getOmaTrustProofEip712Types();
        const now = Math.floor(Date.now() / 1000);
        const message = {
          signer: wallet.address,
          authorizedEntity: "did:web:example.com",
          signingPurpose: "shared-control",
          creationTimestamp: now,
          expirationTimestamp: now + 600,
          randomValue: "0x" + "a".repeat(64) as `0x${string}`,
          statement: "Test"
        };
        const domain = { name: "OMATrust Proof", version: "1", chainId: 1 };
        const typedData = { domain, types: { OmaTrustProof: types.OmaTrustProof }, message };
        const signature = await wallet.signTypedData(domain, { OmaTrustProof: types.OmaTrustProof }, message);

        const proof: ProofWrapper = {
          proofType: "pop-eip712",
          proofObject: { domain, message, signature }
        };
        const result = await verifyProof({ proof });
        expect(result.valid).toBe(true);
        expect(result.proofType).toBe("pop-eip712");
      });

      it("returns invalid when recovered signer does not match message.signer", async () => {
        const signerWallet = Wallet.createRandom();
        const otherAddress = Wallet.createRandom().address;
        const { types } = getOmaTrustProofEip712Types();
        const now = Math.floor(Date.now() / 1000);
        const message = {
          signer: otherAddress,
          authorizedEntity: "did:web:example.com",
          signingPurpose: "shared-control",
          creationTimestamp: now,
          expirationTimestamp: now + 600,
          randomValue: "0x" + "a".repeat(64) as `0x${string}`,
          statement: "Test"
        };
        const domain = { name: "OMATrust Proof", version: "1", chainId: 1 };
        const signature = await signerWallet.signTypedData(domain, { OmaTrustProof: types.OmaTrustProof }, message);

        const proof: ProofWrapper = {
          proofType: "pop-eip712",
          proofObject: { domain, message, signature }
        };
        const result = await verifyProof({ proof });
        expect(result.valid).toBe(false);
        expect(result.reason).toContain("Recovered signer mismatch");
      });
    });

    describe("x402-receipt / x402-offer", () => {
      it("returns valid for x402-receipt with object proofObject", async () => {
        const proof: ProofWrapper = {
          proofType: "x402-receipt",
          proofObject: { txHash: "0xabc", amount: "100" }
        };
        const result = await verifyProof({ proof });
        expect(result.valid).toBe(true);
        expect(result.proofType).toBe("x402-receipt");
      });

      it("returns invalid for x402-receipt with non-object proofObject", async () => {
        const proof: ProofWrapper = {
          proofType: "x402-receipt",
          proofObject: null
        };
        const result = await verifyProof({ proof });
        expect(result.valid).toBe(false);
        expect(result.reason).toContain("Invalid x402 proof object");
      });

      it("returns valid for x402-offer with object proofObject", async () => {
        const proof: ProofWrapper = {
          proofType: "x402-offer",
          proofObject: { price: "50" }
        };
        const result = await verifyProof({ proof });
        expect(result.valid).toBe(true);
        expect(result.proofType).toBe("x402-offer");
      });

      it("returns invalid for x402-offer with string proofObject", async () => {
        const proof: ProofWrapper = {
          proofType: "x402-offer",
          proofObject: "not-an-object"
        };
        const result = await verifyProof({ proof });
        expect(result.valid).toBe(false);
      });
    });

    describe("evidence-pointer", () => {
      let fetchMock: ReturnType<typeof vi.fn>;

      beforeEach(() => {
        fetchMock = vi.fn();
        vi.stubGlobal("fetch", fetchMock);
      });

      afterEach(() => {
        vi.unstubAllGlobals();
      });

      it("returns invalid when URL is missing", async () => {
        const proof: ProofWrapper = {
          proofType: "evidence-pointer",
          proofObject: {}
        };
        const result = await verifyProof({ proof });
        expect(result.valid).toBe(false);
        expect(result.reason).toContain("Missing evidence URL");
      });

      it("returns invalid when fetch returns non-ok", async () => {
        fetchMock.mockResolvedValue({ ok: false, status: 404 });

        const proof: ProofWrapper = {
          proofType: "evidence-pointer",
          proofObject: { url: "https://example.com/proof" }
        };
        const result = await verifyProof({
          proof,
          expectedController: "did:pkh:eip155:1:0x1111111111111111111111111111111111111111"
        });

        expect(result.valid).toBe(false);
        expect(result.reason).toContain("Evidence fetch failed");
      });

      it("returns valid for did.json URL when controller matches", async () => {
        const controllerDid = "did:pkh:eip155:1:0x1111111111111111111111111111111111111111";
        fetchMock.mockResolvedValue({
          ok: true,
          json: () =>
            Promise.resolve({
              verificationMethod: [{ blockchainAccountId: "eip155:1:0x1111111111111111111111111111111111111111" }]
            })
        });

        const proof: ProofWrapper = {
          proofType: "evidence-pointer",
          proofObject: { url: "https://example.com/.well-known/did.json" }
        };
        const result = await verifyProof({
          proof,
          expectedController: controllerDid
        });

        expect(result.valid).toBe(true);
      });

      it("returns invalid for did.json when controller does not match", async () => {
        fetchMock.mockResolvedValue({
          ok: true,
          json: () =>
            Promise.resolve({
              verificationMethod: [{ blockchainAccountId: "eip155:1:0x2222222222222222222222222222222222222222" }]
            })
        });

        const proof: ProofWrapper = {
          proofType: "evidence-pointer",
          proofObject: { url: "https://example.com/.well-known/did.json" }
        };
        const result = await verifyProof({
          proof,
          expectedController: "did:pkh:eip155:1:0x1111111111111111111111111111111111111111"
        });

        expect(result.valid).toBe(false);
      });

      it("returns valid when body contains expected controller", async () => {
        fetchMock.mockResolvedValue({
          ok: true,
          text: () => Promise.resolve("v=1;controller=did:pkh:eip155:1:0x1111111111111111111111111111111111111111")
        });

        const proof: ProofWrapper = {
          proofType: "evidence-pointer",
          proofObject: { url: "https://example.com/txt-record" }
        };
        const result = await verifyProof({
          proof,
          expectedController: "did:pkh:eip155:1:0x1111111111111111111111111111111111111111"
        });

        expect(result.valid).toBe(true);
      });

      it("returns invalid when body does not contain controller and parsed controller mismatches", async () => {
        fetchMock.mockResolvedValue({
          ok: true,
          text: () => Promise.resolve("v=1;controller=did:pkh:eip155:1:0x2222222222222222222222222222222222222222")
        });

        const proof: ProofWrapper = {
          proofType: "evidence-pointer",
          proofObject: { url: "https://example.com/txt-record" }
        };
        const result = await verifyProof({
          proof,
          expectedController: "did:pkh:eip155:1:0x1111111111111111111111111111111111111111"
        });

        expect(result.valid).toBe(false);
        expect(result.reason).toContain("does not include expected controller");
      });

      it("returns invalid when body lacks controller and parseDnsTxtRecord throws", async () => {
        fetchMock.mockResolvedValue({ ok: true, text: () => Promise.resolve("") });

        const proof: ProofWrapper = {
          proofType: "evidence-pointer",
          proofObject: { url: "https://example.com/bad-txt" }
        };
        const result = await verifyProof({
          proof,
          expectedController: "did:pkh:eip155:1:0x1111111111111111111111111111111111111111"
        });

        expect(result.valid).toBe(false);
        expect(result.reason).toContain("does not include expected controller");
      });
    });

    describe("unsupported proof type", () => {
      it("returns invalid for unknown proof type", async () => {
        const proof: ProofWrapper = {
          proofType: "unknown-type" as never,
          proofObject: {}
        };
        const result = await verifyProof({ proof });
        expect(result.valid).toBe(false);
        expect(result.reason).toContain("Unsupported proof type");
      });
    });
  });

  describe("verifyAttestation", () => {
    it("detects revoked attestation", async () => {
      const attestation = makeAttestation({
        revocationTime: 1000n,
        data: { proofs: [] }
      });
      const result = await verifyAttestation({ attestation });
      expect(result.valid).toBe(false);
      expect(result.checks.revocation).toBe(false);
      expect(result.reasons).toContain("attestation revoked");
    });

    it("detects expired attestation", async () => {
      const attestation = makeAttestation({
        expirationTime: 1n, // expired long ago
        data: { proofs: [] }
      });
      const result = await verifyAttestation({ attestation });
      expect(result.valid).toBe(false);
      expect(result.checks.expiration).toBe(false);
      expect(result.reasons).toContain("attestation expired");
    });

    it("detects no proofs", async () => {
      const attestation = makeAttestation({ data: {} });
      const result = await verifyAttestation({ attestation });
      expect(result.valid).toBe(false);
      expect(result.checks.proofs).toBe(false);
      expect(result.reasons).toContain("no proofs provided");
    });

    it("passes revocation and expiration checks for valid attestation", async () => {
      const futureExp = Math.floor(Date.now() / 1000) + 3600;
      const jws = (() => {
        const header = Buffer.from(JSON.stringify({ alg: "ES256K" })).toString("base64url");
        const body = Buffer.from(JSON.stringify({ iss: "did:web:a.com", exp: futureExp })).toString("base64url");
        return `${header}.${body}.fakesig`;
      })();
      const attestation = makeAttestation({
        revocationTime: 0n,
        expirationTime: BigInt(futureExp),
        data: {
          proofs: [
            { proofType: "pop-jws", proofObject: jws, version: 1 }
          ]
        }
      });
      const result = await verifyAttestation({ attestation });
      expect(result.checks.revocation).toBe(true);
      expect(result.checks.expiration).toBe(true);
      expect(result.checks["pop-jws"]).toBe(true);
      expect(result.valid).toBe(true);
    });

    it("verifies x402-receipt proofs within attestation", async () => {
      const attestation = makeAttestation({
        data: {
          proofs: [
            { proofType: "x402-receipt", proofObject: { txHash: "0xabc" }, version: 1 }
          ]
        }
      });
      const result = await verifyAttestation({ attestation });
      expect(result.checks.revocation).toBe(true);
      expect(result.checks["x402-receipt"]).toBe(true);
      expect(result.valid).toBe(true);
    });

    it("handles JSON-string proofs in data", async () => {
      const attestation = makeAttestation({
        data: {
          proofs: [
            JSON.stringify({ proofType: "x402-offer", proofObject: { offer: true }, version: 1 })
          ]
        }
      });
      const result = await verifyAttestation({ attestation });
      expect(result.checks["x402-offer"]).toBe(true);
    });

    it("skips invalid JSON-string proofs gracefully", async () => {
      const attestation = makeAttestation({
        data: {
          proofs: [
            "not-valid-json",
            { proofType: "x402-receipt", proofObject: { txHash: "0xabc" }, version: 1 }
          ]
        }
      });
      const result = await verifyAttestation({ attestation });
      expect(result.checks["x402-receipt"]).toBe(true);
      expect(result.valid).toBe(true);
    });

    it("skips proof entries without proofType", async () => {
      const attestation = makeAttestation({
        data: {
          proofs: [
            { proofObject: { txHash: "0xabc" }, version: 1 },
            { proofType: "x402-receipt", proofObject: { txHash: "0xdef" }, version: 1 }
          ]
        }
      });
      const result = await verifyAttestation({ attestation });
      expect(result.checks["x402-receipt"]).toBe(true);
    });

    it("filters proofs by checks parameter", async () => {
      const attestation = makeAttestation({
        data: {
          proofs: [
            { proofType: "x402-receipt", proofObject: { txHash: "0xabc" }, version: 1 },
            { proofType: "x402-offer", proofObject: { offer: true }, version: 1 }
          ]
        }
      });
      const result = await verifyAttestation({
        attestation,
        checks: ["x402-receipt"]
      });
      // only x402-receipt should be checked
      expect(result.checks["x402-receipt"]).toBe(true);
      expect(result.checks["x402-offer"]).toBeUndefined();
    });

    it("accumulates multiple failure reasons", async () => {
      const attestation = makeAttestation({
        revocationTime: 1000n,
        expirationTime: 1n,
        data: { proofs: [] }
      });
      const result = await verifyAttestation({ attestation });
      expect(result.valid).toBe(false);
      expect(result.reasons).toContain("attestation revoked");
      expect(result.reasons).toContain("attestation expired");
      expect(result.reasons).toContain("no proofs provided");
    });
  });
});
