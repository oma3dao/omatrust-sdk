import { OmaTrustError } from "../../shared/errors";
import type { Hex, TxInteractionProof } from "../types";

export function createTxInteractionProof(chainId: number, txHash: Hex): TxInteractionProof {
  if (!/^0x[0-9a-fA-F]{64}$/.test(txHash)) {
    throw new OmaTrustError("INVALID_INPUT", "txHash must be a 32-byte hex string", { txHash });
  }

  return {
    proofType: "tx-interaction",
    proofPurpose: "commercial-tx",
    proofObject: {
      chainId: `eip155:${chainId}`,
      txHash
    },
    version: 1,
    issuedAt: Math.floor(Date.now() / 1000)
  };
}
