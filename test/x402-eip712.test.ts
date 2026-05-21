import { describe, expect, it } from "vitest";
import { Wallet, HDNodeWallet, getAddress } from "ethers";
import {
  verifyX402Eip712Artifact,
  verifyX402Eip712Offer,
  verifyX402Eip712Receipt,
  type X402Eip712Artifact,
  type Eip712VerificationResult,
  type Eip712VerificationFailure,
} from "../src/reputation/proof/x402-eip712";

// ---------------------------------------------------------------------------
// Test Helpers
// ---------------------------------------------------------------------------

const OFFER_DOMAIN = {
  name: "x402 offer",
  version: "1",
  chainId: 1,
};

const RECEIPT_DOMAIN = {
  name: "x402 receipt",
  version: "1",
  chainId: 1,
};

const OFFER_TYPES = {
  Offer: [
    { name: "version", type: "uint256" },
    { name: "resourceUrl", type: "string" },
    { name: "scheme", type: "string" },
    { name: "network", type: "string" },
    { name: "asset", type: "string" },
    { name: "payTo", type: "string" },
    { name: "amount", type: "string" },
    { name: "validUntil", type: "uint256" },
  ],
};

const RECEIPT_TYPES = {
  Receipt: [
    { name: "version", type: "uint256" },
    { name: "network", type: "string" },
    { name: "resourceUrl", type: "string" },
    { name: "payer", type: "string" },
    { name: "issuedAt", type: "uint256" },
    { name: "transaction", type: "string" },
  ],
};

function makeOfferPayload(overrides?: Record<string, unknown>): Record<string, unknown> {
  return {
    version: 1,
    resourceUrl: "https://api.example.com/premium-data",
    scheme: "exact",
    network: "eip155:8453",
    asset: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
    payTo: "0x209693Bc6afc0C5328bA36FaF03C514EF312287C",
    amount: "10000",
    validUntil: 0,
    ...overrides,
  };
}

function makeReceiptPayload(overrides?: Record<string, unknown>): Record<string, unknown> {
  return {
    version: 1,
    network: "eip155:8453",
    resourceUrl: "https://api.example.com/premium-data",
    payer: "0x857b06519E91e3A54538791bDbb0E22373e36b66",
    issuedAt: 1703123456,
    transaction: "",
    ...overrides,
  };
}

async function signOffer(wallet: Wallet | HDNodeWallet, payload: Record<string, unknown>): Promise<string> {
  return wallet.signTypedData(OFFER_DOMAIN, OFFER_TYPES, payload);
}

async function signReceipt(wallet: Wallet | HDNodeWallet, payload: Record<string, unknown>): Promise<string> {
  return wallet.signTypedData(RECEIPT_DOMAIN, RECEIPT_TYPES, payload);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("x402-eip712 verification", () => {
  const wallet = Wallet.createRandom();
  const signerAddress = getAddress(wallet.address);

  describe("verifyX402Eip712Offer", () => {
    it("verifies a valid offer and recovers signer", async () => {
      const payload = makeOfferPayload();
      const signature = await signOffer(wallet, payload);

      const artifact: X402Eip712Artifact = { format: "eip712", payload, signature };
      const result = verifyX402Eip712Offer(artifact);

      expect(result.valid).toBe(true);
      const success = result as Eip712VerificationResult;
      expect(success.signer).toBe(signerAddress);
      expect(success.artifactType).toBe("offer");
      expect(success.payload.resourceUrl).toBe("https://api.example.com/premium-data");
    });

    it("verifies offer with validUntil set", async () => {
      const payload = makeOfferPayload({ validUntil: 1703123516 });
      const signature = await signOffer(wallet, payload);

      const artifact: X402Eip712Artifact = { format: "eip712", payload, signature };
      const result = verifyX402Eip712Offer(artifact);

      expect(result.valid).toBe(true);
      const success = result as Eip712VerificationResult;
      expect(success.signer).toBe(signerAddress);
    });

    it("rejects offer missing required field (amount)", async () => {
      const payload = makeOfferPayload();
      delete payload.amount;

      const artifact: X402Eip712Artifact = {
        format: "eip712",
        payload,
        signature: "0x" + "ab".repeat(65),
      };
      const result = verifyX402Eip712Offer(artifact);

      expect(result.valid).toBe(false);
      const fail = result as Eip712VerificationFailure;
      expect(fail.error.code).toBe("INVALID_OFFER_PAYLOAD");
      expect(fail.error.message).toContain("amount");
    });

    it("rejects offer missing required field (scheme)", async () => {
      const payload = makeOfferPayload();
      delete payload.scheme;

      const artifact: X402Eip712Artifact = {
        format: "eip712",
        payload,
        signature: "0x" + "ab".repeat(65),
      };
      const result = verifyX402Eip712Offer(artifact);

      expect(result.valid).toBe(false);
      const fail = result as Eip712VerificationFailure;
      expect(fail.error.code).toBe("INVALID_OFFER_PAYLOAD");
      expect(fail.error.message).toContain("scheme");
    });

    it("rejects invalid signature", () => {
      const payload = makeOfferPayload();
      const artifact: X402Eip712Artifact = {
        format: "eip712",
        payload,
        signature: "0xinvalidsignature",
      };
      const result = verifyX402Eip712Offer(artifact);

      expect(result.valid).toBe(false);
      const fail = result as Eip712VerificationFailure;
      expect(fail.error.code).toBe("SIGNATURE_INVALID");
    });

    it("defaults validUntil to 0 when absent", async () => {
      // Sign with validUntil: 0
      const payloadForSigning = makeOfferPayload({ validUntil: 0 });
      const signature = await signOffer(wallet, payloadForSigning);

      // Verify with payload that omits validUntil entirely
      const payloadWithout = makeOfferPayload();
      delete payloadWithout.validUntil;
      // Re-add required fields but not validUntil
      const artifact: X402Eip712Artifact = {
        format: "eip712",
        payload: payloadWithout,
        signature,
      };
      const result = verifyX402Eip712Offer(artifact);

      expect(result.valid).toBe(true);
      const success = result as Eip712VerificationResult;
      expect(success.signer).toBe(signerAddress);
    });
  });

  describe("verifyX402Eip712Receipt", () => {
    it("verifies a valid receipt and recovers signer", async () => {
      const payload = makeReceiptPayload();
      const signature = await signReceipt(wallet, payload);

      const artifact: X402Eip712Artifact = { format: "eip712", payload, signature };
      const result = verifyX402Eip712Receipt(artifact);

      expect(result.valid).toBe(true);
      const success = result as Eip712VerificationResult;
      expect(success.signer).toBe(signerAddress);
      expect(success.artifactType).toBe("receipt");
      expect(success.payload.payer).toBe("0x857b06519E91e3A54538791bDbb0E22373e36b66");
    });

    it("verifies receipt with transaction hash", async () => {
      const payload = makeReceiptPayload({
        transaction: "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
      });
      const signature = await signReceipt(wallet, payload);

      const artifact: X402Eip712Artifact = { format: "eip712", payload, signature };
      const result = verifyX402Eip712Receipt(artifact);

      expect(result.valid).toBe(true);
      const success = result as Eip712VerificationResult;
      expect(success.signer).toBe(signerAddress);
    });

    it("rejects receipt missing required field (issuedAt)", async () => {
      const payload = makeReceiptPayload();
      delete payload.issuedAt;

      const artifact: X402Eip712Artifact = {
        format: "eip712",
        payload,
        signature: "0x" + "ab".repeat(65),
      };
      const result = verifyX402Eip712Receipt(artifact);

      expect(result.valid).toBe(false);
      const fail = result as Eip712VerificationFailure;
      expect(fail.error.code).toBe("INVALID_RECEIPT_PAYLOAD");
      expect(fail.error.message).toContain("issuedAt");
    });

    it("rejects receipt missing required field (payer)", async () => {
      const payload = makeReceiptPayload();
      delete payload.payer;

      const artifact: X402Eip712Artifact = {
        format: "eip712",
        payload,
        signature: "0x" + "ab".repeat(65),
      };
      const result = verifyX402Eip712Receipt(artifact);

      expect(result.valid).toBe(false);
      const fail = result as Eip712VerificationFailure;
      expect(fail.error.code).toBe("INVALID_RECEIPT_PAYLOAD");
      expect(fail.error.message).toContain("payer");
    });

    it("defaults transaction to empty string when absent", async () => {
      // Sign with transaction: ""
      const payloadForSigning = makeReceiptPayload({ transaction: "" });
      const signature = await signReceipt(wallet, payloadForSigning);

      // Verify with payload that omits transaction entirely
      const payloadWithout = makeReceiptPayload();
      delete payloadWithout.transaction;
      const artifact: X402Eip712Artifact = {
        format: "eip712",
        payload: payloadWithout,
        signature,
      };
      const result = verifyX402Eip712Receipt(artifact);

      expect(result.valid).toBe(true);
      const success = result as Eip712VerificationResult;
      expect(success.signer).toBe(signerAddress);
    });
  });

  describe("verifyX402Eip712Artifact — envelope validation", () => {
    it("rejects missing payload", () => {
      const artifact = {
        format: "eip712",
        signature: "0x" + "ab".repeat(65),
      } as any;
      const result = verifyX402Eip712Artifact(artifact, "offer");

      expect(result.valid).toBe(false);
      const fail = result as Eip712VerificationFailure;
      expect(fail.error.code).toBe("MISSING_PAYLOAD");
    });

    it("rejects missing signature", () => {
      const artifact = {
        format: "eip712",
        payload: makeOfferPayload(),
        signature: "",
      } as X402Eip712Artifact;
      const result = verifyX402Eip712Artifact(artifact, "offer");

      expect(result.valid).toBe(false);
      const fail = result as Eip712VerificationFailure;
      expect(fail.error.code).toBe("MISSING_SIGNATURE");
    });

    it("rejects wrong format", () => {
      const artifact = {
        format: "jws",
        payload: makeOfferPayload(),
        signature: "0x" + "ab".repeat(65),
      } as any;
      const result = verifyX402Eip712Artifact(artifact, "offer");

      expect(result.valid).toBe(false);
      const fail = result as Eip712VerificationFailure;
      expect(fail.error.code).toBe("INVALID_ARTIFACT");
    });
  });

  describe("verifyProof integration", () => {
    it("x402-offer with format eip712 invokes EIP-712 verification", async () => {
      const { verifyProof } = await import("../src/reputation/verify");
      const payload = makeOfferPayload();
      const signature = await signOffer(wallet, payload);

      const result = await verifyProof({
        proof: {
          proofType: "x402-offer",
          proofObject: { format: "eip712", payload, signature },
        },
      });

      expect(result.valid).toBe(true);
      expect(result.proofType).toBe("x402-offer");
    });

    it("x402-receipt with format eip712 invokes EIP-712 verification", async () => {
      const { verifyProof } = await import("../src/reputation/verify");
      const payload = makeReceiptPayload();
      const signature = await signReceipt(wallet, payload);

      const result = await verifyProof({
        proof: {
          proofType: "x402-receipt",
          proofObject: { format: "eip712", payload, signature },
        },
      });

      expect(result.valid).toBe(true);
      expect(result.proofType).toBe("x402-receipt");
    });

    it("x402-offer with invalid EIP-712 signature fails via verifyProof", async () => {
      const { verifyProof } = await import("../src/reputation/verify");
      const payload = makeOfferPayload();

      const result = await verifyProof({
        proof: {
          proofType: "x402-offer",
          proofObject: { format: "eip712", payload, signature: "0xinvalid" },
        },
      });

      expect(result.valid).toBe(false);
      expect(result.proofType).toBe("x402-offer");
    });

    it("x402-receipt with missing payload still passes (backward compat, no format match)", async () => {
      const { verifyProof } = await import("../src/reputation/verify");

      const result = await verifyProof({
        proof: {
          proofType: "x402-receipt",
          proofObject: { someField: "value" },
        },
      });

      expect(result.valid).toBe(true);
      expect(result.proofType).toBe("x402-receipt");
    });
  });
});
