import { describe, expect, it } from "vitest";
import {
  calculateTransferAmount,
  calculateTransferAmountFromAddresses,
  constructSeed,
  createTxEncodedValueProof,
  formatTransferAmount,
  getChainConstants,
  getExplorerTxUrl,
  getSupportedChainIds,
  isChainSupported,
  createTxInteractionProof,
  createEvidencePointerProof,
  buildDnsTxtRecord,
  parseDnsTxtRecord,
  getOmaTrustProofEip712Types
} from "../src/reputation";

describe("reputation proof helpers", () => {
  it("calculates deterministic tx-encoded-value amounts", () => {
    const subject = "did:pkh:eip155:1:0x1111111111111111111111111111111111111111";
    const counterparty = "did:pkh:eip155:1:0x2222222222222222222222222222222222222222";
    const first = calculateTransferAmount(subject, counterparty, 1, "shared-control");
    const second = calculateTransferAmount(subject, counterparty, 1, "shared-control");
    expect(first).toBe(second);
  });

  it("supports address wrapper and chain constants", () => {
    const amount = calculateTransferAmountFromAddresses(
      "0x1111111111111111111111111111111111111111",
      "0x2222222222222222222222222222222222222222",
      1,
      "commercial-tx"
    );
    expect(amount > 0n).toBe(true);
    expect(getChainConstants(1, "commercial-tx").nativeSymbol).toBe("ETH");
  });

  it("constructs proof wrappers", () => {
    const proof = createTxEncodedValueProof(1, "0x".padEnd(66, "1") as `0x${string}`, "shared-control");
    expect(proof.proofType).toBe("tx-encoded-value");
    expect(createTxInteractionProof(1, "0x".padEnd(66, "2") as `0x${string}`).proofType).toBe("tx-interaction");
    expect(createEvidencePointerProof("https://example.com/proof").proofType).toBe("evidence-pointer");
  });

  it("formats helpers and metadata", () => {
    expect(formatTransferAmount(1000000000000000000n, 1)).toContain("ETH");
    expect(getExplorerTxUrl(1, "0x".padEnd(66, "3") as `0x${string}`)).toContain("etherscan.io");
    expect(getSupportedChainIds().length).toBeGreaterThan(0);
    expect(isChainSupported(1)).toBe(true);
  });

  it("handles DNS TXT helpers and EIP-712 types", () => {
    const txt = buildDnsTxtRecord("did:pkh:eip155:1:0x1111111111111111111111111111111111111111");
    expect(parseDnsTxtRecord(txt).controller).toBe("did:pkh:eip155:1:0x1111111111111111111111111111111111111111");
    expect(getOmaTrustProofEip712Types().primaryType).toBe("OmaTrustProof");
  });

  it("constructs canonical seed bytes", () => {
    const seed = constructSeed(
      "0x".padEnd(66, "a") as `0x${string}`,
      "0x".padEnd(66, "b") as `0x${string}`,
      "shared-control"
    );
    expect(seed.length).toBeGreaterThan(0);
  });
});
