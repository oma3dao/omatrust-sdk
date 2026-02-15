import type { X402OfferProof, X402ReceiptProof } from "../types";

export function createX402ReceiptProof(receipt: Record<string, unknown>): X402ReceiptProof {
  return {
    proofType: "x402-receipt",
    proofPurpose: "commercial-tx",
    proofObject: receipt,
    version: 1,
    issuedAt: Math.floor(Date.now() / 1000)
  };
}

export function createX402OfferProof(offer: Record<string, unknown>): X402OfferProof {
  return {
    proofType: "x402-offer",
    proofPurpose: "commercial-tx",
    proofObject: offer,
    version: 1,
    issuedAt: Math.floor(Date.now() / 1000)
  };
}
