import { EAS } from "@ethereum-attestation-service/eas-sdk";
import { ZeroAddress } from "ethers";
import { encodeAttestationData, extractExpirationTime } from "./encode";
import { withAutoSubjectDidHash, resolveRecipientAddress, toBigIntOrDefault, ZERO_UID } from "./internal";
import { getEasTransactionHash, getEasTransactionReceipt } from "./eas-adapter";
import { OmaTrustError } from "../shared/errors";
import type { SubmitAttestationParams, SubmitAttestationResult, Hex } from "./types";

export async function submitAttestation(
  params: SubmitAttestationParams
): Promise<SubmitAttestationResult> {
  if (!params || typeof params !== "object") {
    throw new OmaTrustError("INVALID_INPUT", "params must be provided");
  }

  if (!params.signer) {
    throw new OmaTrustError("INVALID_INPUT", "signer is required");
  }

  const dataWithHash = withAutoSubjectDidHash(params.schema, params.data);
  const encodedData = encodeAttestationData(params.schema, dataWithHash);
  const expiration = toBigIntOrDefault(
    params.expirationTime ?? extractExpirationTime(dataWithHash),
    0n
  );
  const recipient = resolveRecipientAddress(dataWithHash);

  const eas = new EAS(params.easContractAddress);
  eas.connect(params.signer as never);

  try {
    const tx = await eas.attest({
      schema: params.schemaUid,
      data: {
        recipient: recipient || ZeroAddress,
        expirationTime: expiration,
        revocable: params.revocable ?? true,
        refUID: params.refUid ?? ZERO_UID,
        data: encodedData,
        value: toBigIntOrDefault(params.value, 0n)
      }
    });

    const uid = (await tx.wait()) as Hex;
    const txHash = getEasTransactionHash(tx) ?? ZERO_UID;
    const receipt = getEasTransactionReceipt(tx);

    return {
      uid,
      txHash,
      receipt
    };
  } catch (err) {
    throw new OmaTrustError("NETWORK_ERROR", "Failed to submit attestation", { err });
  }
}
