import { verifyTypedData } from "ethers";
import { OmaTrustError } from "../../shared/errors";
import type { Hex } from "../types";

export function buildEip712Domain(
  name: string,
  version: string,
  chainId: number,
  verifyingContract: Hex
): { name: string; version: string; chainId: number; verifyingContract: Hex } {
  return { name, version, chainId, verifyingContract };
}

export function getOmaTrustProofEip712Types(): {
  primaryType: string;
  types: Record<string, Array<{ name: string; type: string }>>;
} {
  return {
    primaryType: "OmaTrustProof",
    types: {
      OmaTrustProof: [
        { name: "signer", type: "address" },
        { name: "authorizedEntity", type: "string" },
        { name: "signingPurpose", type: "string" },
        { name: "creationTimestamp", type: "uint256" },
        { name: "expirationTimestamp", type: "uint256" },
        { name: "randomValue", type: "bytes32" },
        { name: "statement", type: "string" }
      ]
    }
  };
}

export function verifyEip712Signature(
  typedData: {
    domain: Record<string, unknown>;
    types: Record<string, unknown>;
    message: Record<string, unknown>;
  },
  signature: Hex | string
): { valid: boolean; signer?: string } {
  try {
    const signer = verifyTypedData(
      typedData.domain,
      typedData.types as Record<string, Array<{ name: string; type: string }>>,
      typedData.message,
      signature
    );

    return { valid: true, signer };
  } catch (err) {
    throw new OmaTrustError("INVALID_INPUT", "Failed to verify EIP-712 signature", { err });
  }
}
