import { getAddress } from "ethers";
import { extractAddressFromDid } from "../identity/did";
import { OmaTrustError } from "../shared/errors";
import {
  calculateTransferAmount,
} from "./proof/tx-encoded-value";
import { verifyDidDocumentControllerDid } from "./proof/did-json";
import { verifyEip712Signature } from "./proof/eip712";
import { parseDnsTxtRecord } from "./proof/dns-txt";
import type {
  AttestationQueryResult,
  ProofPurpose,
  ProofWrapper,
  VerifyAttestationParams,
  VerifyAttestationResult,
  VerifyProofParams,
  VerifyProofResult
} from "./types";

function parseChainId(input: unknown): number {
  if (typeof input === "number") {
    return input;
  }

  if (typeof input === "string") {
    if (input.includes(":")) {
      const [, chainId] = input.split(":");
      return Number(chainId);
    }
    return Number(input);
  }

  return NaN;
}

function parseProofs(attestation: AttestationQueryResult): ProofWrapper[] {
  const rawProofs = attestation.data.proofs;
  if (!Array.isArray(rawProofs)) {
    return [];
  }

  return rawProofs
    .map((entry) => {
      if (typeof entry === "string") {
        try {
          return JSON.parse(entry) as ProofWrapper;
        } catch {
          return null;
        }
      }
      if (entry && typeof entry === "object") {
        return entry as ProofWrapper;
      }
      return null;
    })
    .filter((proof): proof is ProofWrapper => Boolean(proof?.proofType));
}

function getProofPurpose(proof: ProofWrapper): ProofPurpose {
  if (proof.proofPurpose === "commercial-tx") {
    return "commercial-tx";
  }
  return "shared-control";
}

function decodeJwtPayload(compactJws: string): Record<string, unknown> {
  const parts = compactJws.split(".");
  if (parts.length !== 3) {
    throw new OmaTrustError("PROOF_VERIFICATION_FAILED", "Invalid compact JWS format");
  }
  const payloadB64 = parts[1].replace(/-/g, "+").replace(/_/g, "/");
  const padded = payloadB64.padEnd(payloadB64.length + ((4 - (payloadB64.length % 4)) % 4), "=");
  let json: string;
  if (typeof atob === "function") {
    json = decodeURIComponent(
      Array.from(atob(padded))
        .map((char) => `%${char.charCodeAt(0).toString(16).padStart(2, "0")}`)
        .join("")
    );
  } else {
    json = Buffer.from(padded, "base64").toString("utf8");
  }
  return JSON.parse(json) as Record<string, unknown>;
}

export async function verifyProof(params: VerifyProofParams): Promise<VerifyProofResult> {
  const { proof, provider, expectedSubject, expectedController } = params;

  try {
    switch (proof.proofType) {
      case "tx-encoded-value": {
        if (!provider) {
          return { valid: false, proofType: proof.proofType, reason: "Provider is required" };
        }
        if (!expectedSubject || !expectedController) {
          return {
            valid: false,
            proofType: proof.proofType,
            reason: "expectedSubject and expectedController are required"
          };
        }

        const proofObject = proof.proofObject as { chainId: string; txHash: string };
        const chainId = parseChainId(proofObject.chainId);
        const tx = await (provider as { getTransaction: (hash: string) => Promise<any> }).getTransaction(
          proofObject.txHash
        );
        if (!tx) {
          return { valid: false, proofType: proof.proofType, reason: "Transaction not found" };
        }

        const expectedAmount = calculateTransferAmount(
          expectedSubject,
          expectedController,
          chainId,
          getProofPurpose(proof)
        );

        const subjectAddress = getAddress(extractAddressFromDid(expectedSubject));
        const controllerAddress = getAddress(extractAddressFromDid(expectedController));

        if (tx.from && getAddress(tx.from) !== subjectAddress) {
          return { valid: false, proofType: proof.proofType, reason: "Transaction sender mismatch" };
        }

        if (tx.to && getAddress(tx.to) !== controllerAddress) {
          return { valid: false, proofType: proof.proofType, reason: "Transaction recipient mismatch" };
        }

        if (BigInt(tx.value) !== expectedAmount) {
          return { valid: false, proofType: proof.proofType, reason: "Transaction amount mismatch" };
        }

        return { valid: true, proofType: proof.proofType };
      }

      case "tx-interaction": {
        if (!provider) {
          return { valid: false, proofType: proof.proofType, reason: "Provider is required" };
        }
        const proofObject = proof.proofObject as { txHash: string };
        const tx = await (provider as { getTransaction: (hash: string) => Promise<any> }).getTransaction(
          proofObject.txHash
        );
        if (!tx) {
          return { valid: false, proofType: proof.proofType, reason: "Transaction not found" };
        }

        if (!tx.to) {
          return { valid: false, proofType: proof.proofType, reason: "Transaction target missing" };
        }

        return { valid: true, proofType: proof.proofType };
      }

      case "pop-eip712": {
        const object = proof.proofObject as {
          domain: Record<string, unknown>;
          message: Record<string, unknown>;
          signature: string;
        };

        const typedData = {
          domain: object.domain,
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
          },
          message: object.message
        };

        const verification = verifyEip712Signature(typedData, object.signature);
        if (!verification.valid || !verification.signer) {
          return { valid: false, proofType: proof.proofType, reason: "Invalid EIP-712 signature" };
        }

        if (typeof object.message.signer === "string") {
          const expected = getAddress(object.message.signer);
          if (getAddress(verification.signer) !== expected) {
            return { valid: false, proofType: proof.proofType, reason: "Recovered signer mismatch" };
          }
        }

        return { valid: true, proofType: proof.proofType };
      }

      case "pop-jws": {
        if (typeof proof.proofObject !== "string") {
          return { valid: false, proofType: proof.proofType, reason: "Invalid JWS proof payload" };
        }

        const payload = decodeJwtPayload(proof.proofObject);
        const now = Math.floor(Date.now() / 1000);
        const exp = payload.exp;
        if (typeof exp === "number" && exp < now) {
          return { valid: false, proofType: proof.proofType, reason: "JWS proof expired" };
        }

        return { valid: true, proofType: proof.proofType };
      }

      case "x402-receipt":
      case "x402-offer": {
        if (!proof.proofObject || typeof proof.proofObject !== "object") {
          return { valid: false, proofType: proof.proofType, reason: "Invalid x402 proof object" };
        }
        return { valid: true, proofType: proof.proofType };
      }

      case "evidence-pointer": {
        const object = proof.proofObject as { url?: string };
        if (!object.url) {
          return { valid: false, proofType: proof.proofType, reason: "Missing evidence URL" };
        }

        const response = await fetch(object.url);
        if (!response.ok) {
          return { valid: false, proofType: proof.proofType, reason: `Evidence fetch failed (${response.status})` };
        }

        if (object.url.endsWith("/.well-known/did.json") && expectedController) {
          const didDoc = (await response.json()) as Record<string, unknown>;
          const didCheck = verifyDidDocumentControllerDid(didDoc, expectedController);
          return {
            valid: didCheck.valid,
            proofType: proof.proofType,
            reason: didCheck.reason
          };
        }

        const body = await response.text();
        if (expectedController && !body.includes(expectedController)) {
          try {
            const parsed = parseDnsTxtRecord(body);
            if (parsed.controller !== expectedController) {
              return {
                valid: false,
                proofType: proof.proofType,
                reason: "Evidence does not include expected controller DID"
              };
            }
          } catch {
            return {
              valid: false,
              proofType: proof.proofType,
              reason: "Evidence does not include expected controller DID"
            };
          }
        }

        return { valid: true, proofType: proof.proofType };
      }

      default:
        return { valid: false, proofType: proof.proofType, reason: "Unsupported proof type" };
    }
  } catch (err) {
    throw new OmaTrustError("PROOF_VERIFICATION_FAILED", "Proof verification failed", {
      proofType: proof.proofType,
      err
    });
  }
}

export async function verifyAttestation(
  params: VerifyAttestationParams
): Promise<VerifyAttestationResult> {
  const proofs = parseProofs(params.attestation);
  const checks: Record<string, boolean> = {};
  const reasons: string[] = [];

  const now = BigInt(Math.floor(Date.now() / 1000));
  if (params.attestation.revocationTime > 0n) {
    checks.revocation = false;
    reasons.push("attestation revoked");
  } else {
    checks.revocation = true;
  }

  if (params.attestation.expirationTime > 0n && params.attestation.expirationTime < now) {
    checks.expiration = false;
    reasons.push("attestation expired");
  } else {
    checks.expiration = true;
  }

  if (proofs.length === 0) {
    checks.proofs = false;
    reasons.push("no proofs provided");
  }

  const selectedProofTypes = params.checks ?? (proofs.map((proof) => proof.proofType) as Array<ProofWrapper["proofType"]>);

  for (const proof of proofs) {
    if (!selectedProofTypes.includes(proof.proofType)) {
      continue;
    }

    const result = await verifyProof({
      proof,
      provider: params.provider,
      expectedSubject: params.context?.subject as string | undefined,
      expectedController: params.context?.controller as string | undefined
    });

    checks[proof.proofType] = result.valid;
    if (!result.valid) {
      reasons.push(result.reason ?? `${proof.proofType} verification failed`);
    }
  }

  return {
    valid: reasons.length === 0,
    checks,
    reasons
  };
}
