import { EAS } from "@ethereum-attestation-service/eas-sdk";
import { getEasTransactionHash, getEasTransactionReceipt } from "./eas-adapter";
import { toBigIntOrDefault, ZERO_UID } from "./internal";
import { OmaTrustError } from "../shared/errors";
import type { RevokeAttestationParams, RevokeAttestationResult } from "./types";

export async function revokeAttestation(
  params: RevokeAttestationParams
): Promise<RevokeAttestationResult> {
  if (!params || typeof params !== "object") {
    throw new OmaTrustError("INVALID_INPUT", "params must be provided");
  }

  if (!params.signer) {
    throw new OmaTrustError("INVALID_INPUT", "signer is required");
  }

  const eas = new EAS(params.easContractAddress);
  eas.connect(params.signer as never);

  try {
    const tx = await eas.revoke({
      schema: params.schemaUid,
      data: {
        uid: params.uid,
        value: toBigIntOrDefault(params.value, 0n)
      }
    });

    await tx.wait();
    const txHash = getEasTransactionHash(tx) ?? ZERO_UID;
    const receipt = getEasTransactionReceipt(tx);

    return {
      txHash,
      receipt
    };
  } catch (err) {
    throw new OmaTrustError("NETWORK_ERROR", "Failed to revoke attestation", { err });
  }
}
