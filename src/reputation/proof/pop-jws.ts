import { OmaTrustError } from "../../shared/errors";
import type { Did, PopJwsProof, ProofPurpose } from "../types";

export type CreatePopJwsProofParams = {
  issuer: Did;
  audience: Did;
  purpose: ProofPurpose;
  issuedAt?: number;
  expiresAt?: number;
  nonce?: string;
};

export async function createPopJwsProof(
  params: CreatePopJwsProofParams,
  signFn: (
    payload: Record<string, unknown>,
    header: Record<string, unknown>
  ) => Promise<string>
): Promise<PopJwsProof> {
  if (!params.issuer || !params.audience) {
    throw new OmaTrustError("INVALID_INPUT", "issuer and audience are required", { params });
  }

  const now = Math.floor(Date.now() / 1000);
  const payload = {
    iss: params.issuer,
    aud: params.audience,
    purpose: params.purpose,
    iat: params.issuedAt ?? now,
    exp: params.expiresAt ?? now + 600,
    nonce:
      params.nonce ??
      (globalThis.crypto?.randomUUID ? globalThis.crypto.randomUUID() : `${Date.now()}-${Math.random()}`)
  };

  const header = {
    typ: "JWT",
    alg: "ES256K"
  };

  const jws = await signFn(payload, header);

  return {
    proofType: "pop-jws",
    proofObject: jws,
    proofPurpose: params.purpose,
    version: 1,
    issuedAt: payload.iat,
    expiresAt: payload.exp
  };
}
