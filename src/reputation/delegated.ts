import { Signature } from "ethers";
import { encodeAttestationData, extractExpirationTime } from "./encode";
import { resolveRecipientAddress, toBigIntOrDefault, withAutoSubjectDidHash, ZERO_UID } from "./internal";
import { OmaTrustError } from "../shared/errors";
import type {
  BuildDelegatedTypedDataFromEncodedParams,
  Hex,
  PrepareDelegatedAttestationParams,
  PrepareDelegatedAttestationResult,
  SubmitDelegatedAttestationParams,
  SubmitDelegatedAttestationResult
} from "./types";

type BuildDelegatedTypedDataParams = {
  chainId: number;
  easContractAddress: Hex;
  schemaUid: Hex;
  encodedData: Hex;
  recipient: string;
  attester: Hex;
  nonce: bigint | number;
  revocable?: boolean;
  expirationTime?: bigint | number;
  refUid?: Hex;
  value?: bigint | number;
  deadline?: bigint | number;
};

function buildDelegatedTypedData(
  params: BuildDelegatedTypedDataParams
): {
  domain: Record<string, unknown>;
  types: Record<string, unknown>;
  message: Record<string, unknown>;
} {
  return {
    domain: {
      name: "EAS",
      version: "1.4.0",
      chainId: params.chainId,
      verifyingContract: params.easContractAddress
    },
    types: {
      Attest: [
        { name: "attester", type: "address" },
        { name: "schema", type: "bytes32" },
        { name: "recipient", type: "address" },
        { name: "expirationTime", type: "uint64" },
        { name: "revocable", type: "bool" },
        { name: "refUID", type: "bytes32" },
        { name: "data", type: "bytes" },
        { name: "value", type: "uint256" },
        { name: "nonce", type: "uint256" },
        { name: "deadline", type: "uint64" }
      ]
    },
    message: {
      attester: params.attester,
      schema: params.schemaUid,
      recipient: params.recipient,
      expirationTime: toBigIntOrDefault(params.expirationTime, 0n),
      revocable: params.revocable ?? true,
      refUID: params.refUid ?? ZERO_UID,
      data: params.encodedData,
      value: toBigIntOrDefault(params.value, 0n),
      nonce: toBigIntOrDefault(params.nonce, 0n),
      deadline: toBigIntOrDefault(params.deadline, BigInt(Math.floor(Date.now() / 1000) + 600))
    }
  };
}

export function buildDelegatedAttestationTypedData(
  params: PrepareDelegatedAttestationParams
): {
  domain: Record<string, unknown>;
  types: Record<string, unknown>;
  message: Record<string, unknown>;
} {
  const dataWithHash = withAutoSubjectDidHash(params.schema, params.data);
  const encodedData = encodeAttestationData(params.schema, dataWithHash);
  const recipient = resolveRecipientAddress(dataWithHash);

  return buildDelegatedTypedData({
    chainId: params.chainId,
    easContractAddress: params.easContractAddress,
    schemaUid: params.schemaUid,
    encodedData,
    recipient,
    attester: params.attester,
    nonce: params.nonce,
    revocable: params.revocable,
    expirationTime: params.expirationTime ?? extractExpirationTime(dataWithHash),
    refUid: params.refUid,
    value: params.value,
    deadline: params.deadline
  });
}

export function buildDelegatedTypedDataFromEncoded(
  params: BuildDelegatedTypedDataFromEncodedParams
): {
  domain: Record<string, unknown>;
  types: Record<string, unknown>;
  message: Record<string, unknown>;
} {
  return buildDelegatedTypedData({
    chainId: params.chainId,
    easContractAddress: params.easContractAddress,
    schemaUid: params.schemaUid,
    encodedData: params.encodedData,
    recipient: params.recipient,
    attester: params.attester,
    nonce: params.nonce,
    revocable: params.revocable,
    expirationTime: params.expirationTime,
    refUid: params.refUid,
    value: params.value,
    deadline: params.deadline
  });
}

export function splitSignature(signature: Hex | string): { v: number; r: Hex; s: Hex } {
  try {
    const parsed = Signature.from(signature as string);
    return {
      v: parsed.v,
      r: parsed.r as Hex,
      s: parsed.s as Hex
    };
  } catch (err) {
    throw new OmaTrustError("INVALID_INPUT", "Invalid signature", { err });
  }
}

export async function prepareDelegatedAttestation(
  params: PrepareDelegatedAttestationParams
): Promise<PrepareDelegatedAttestationResult> {
  if (!params || typeof params !== "object") {
    throw new OmaTrustError("INVALID_INPUT", "params are required");
  }

  const typedData = buildDelegatedAttestationTypedData(params);

  return {
    delegatedRequest: {
      schema: params.schemaUid,
      attester: params.attester,
      easContractAddress: params.easContractAddress,
      chainId: params.chainId,
      ...typedData.message
    },
    typedData
  };
}

export async function submitDelegatedAttestation(
  params: SubmitDelegatedAttestationParams
): Promise<SubmitDelegatedAttestationResult> {
  if (!params.relayUrl || typeof params.relayUrl !== "string") {
    throw new OmaTrustError("INVALID_INPUT", "relayUrl is required");
  }

  let response: Response;
  try {
    const body = JSON.stringify(
      {
        prepared: params.prepared,
        signature: params.signature,
        attester: params.attester
      },
      (_key, value) => (typeof value === "bigint" ? value.toString() : value)
    );

    response = await fetch(params.relayUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body
    });
  } catch (err) {
    throw new OmaTrustError("NETWORK_ERROR", "Failed to submit delegated attestation", { err });
  }

  let payload: Record<string, unknown>;
  try {
    payload = (await response.json()) as Record<string, unknown>;
  } catch {
    payload = {};
  }

  if (!response.ok) {
    throw new OmaTrustError("NETWORK_ERROR", "Relay submission failed", {
      status: response.status,
      payload
    });
  }

  const uid = ((payload.uid as string | undefined) ?? ZERO_UID) as Hex;
  const txHash = payload.txHash as Hex | undefined;
  const status = (payload.status as "submitted" | "confirmed" | undefined) ?? "submitted";

  return {
    uid,
    txHash,
    status
  };
}
