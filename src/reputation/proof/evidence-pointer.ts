import { OmaTrustError } from "../../shared/errors";
import type { EvidencePointerProof } from "../types";

export function createEvidencePointerProof(url: string): EvidencePointerProof {
  if (!url || typeof url !== "string") {
    throw new OmaTrustError("INVALID_INPUT", "url must be a non-empty string", { url });
  }

  return {
    proofType: "evidence-pointer",
    proofPurpose: "shared-control",
    proofObject: { url },
    version: 1,
    issuedAt: Math.floor(Date.now() / 1000)
  };
}
