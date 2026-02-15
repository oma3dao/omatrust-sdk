import { hexlify, randomBytes } from "ethers";
import type { Hex, PopEip712Proof, ProofPurpose } from "../types";
import { OmaTrustError } from "../../shared/errors";
import { getOmaTrustProofEip712Types } from "./eip712";

export type CreatePopEip712ProofParams = {
  signer: string;
  authorizedEntity: string;
  signingPurpose: ProofPurpose;
  chainId: number;
  creationTimestamp?: number;
  expirationTimestamp?: number;
  randomValue?: Hex;
  statement?: string;
};

export async function createPopEip712Proof(
  params: CreatePopEip712ProofParams,
  signFn: (typedData: Record<string, unknown>) => Promise<Hex>
): Promise<PopEip712Proof> {
  if (!params.signer || !params.authorizedEntity) {
    throw new OmaTrustError("INVALID_INPUT", "signer and authorizedEntity are required", { params });
  }

  const now = Math.floor(Date.now() / 1000);
  const creationTimestamp = params.creationTimestamp ?? now;
  const expirationTimestamp = params.expirationTimestamp ?? now + 600;
  const randomValue = params.randomValue ?? (hexlify(randomBytes(32)) as Hex);

  const message = {
    signer: params.signer,
    authorizedEntity: params.authorizedEntity,
    signingPurpose: params.signingPurpose,
    creationTimestamp,
    expirationTimestamp,
    randomValue,
    statement: params.statement ?? "This is not a transaction or asset approval."
  };

  const { types, primaryType } = getOmaTrustProofEip712Types();
  const typedData = {
    domain: {
      name: "OMATrust Proof",
      version: "1",
      chainId: params.chainId
    },
    types,
    primaryType,
    message
  };

  const signature = await signFn(typedData);

  return {
    proofType: "pop-eip712",
    proofObject: {
      domain: typedData.domain,
      message,
      signature
    },
    version: 1,
    issuedAt: creationTimestamp,
    expiresAt: expirationTimestamp
  };
}
