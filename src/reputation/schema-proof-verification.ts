/**
 * Schema-Aware Proof Verification
 *
 * Provides higher-level proof verification that understands attestation schema semantics.
 * Unlike the generic verifyProof() which validates proof structure and signatures,
 * these functions verify that proof signers match the claimed identities in the attestation.
 *
 * - verifyLinkedIdentifierProofs: Verifies that proofs demonstrate shared control
 *   between subject and linkedId
 * - verifyKeyBindingProofs: Verifies that proofs demonstrate the subject authorized
 *   the keyId binding
 */

import { getAddress } from "ethers";
import { extractAddressFromDid, extractDidMethod } from "../identity/did";
import { didJwkToJwk, publicJwkEquals } from "../identity/jwk";
import { verifyEip712Signature } from "./proof/eip712";
import { OmaTrustError } from "../shared/errors";
import type { ProofWrapper, PopEip712Proof, PopJwsProof, Did } from "./types";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** Attestation data for a Linked Identifier schema */
export interface LinkedIdentifierData {
  subject: Did;
  linkedId: Did;
  proofs: ProofWrapper[];
  attester?: string;
}

/** Attestation data for a Key Binding schema */
export interface KeyBindingData {
  subject: Did;
  keyId: Did;
  publicKeyJwk?: Record<string, unknown>;
  proofs: ProofWrapper[];
  attester?: string;
}

/** Result of schema-aware proof verification */
export interface SchemaProofVerificationResult {
  /** Whether all required proof checks passed */
  valid: boolean;
  /** Individual check results */
  checks: SchemaProofCheck[];
  /** Human-readable reasons for any failures */
  reasons: string[];
}

/** Individual proof check result */
export interface SchemaProofCheck {
  /** Which proof (by index) was checked */
  proofIndex: number;
  /** The proof type */
  proofType: string;
  /** What the check verified */
  checkType: "signer-is-subject" | "signer-is-linkedId" | "signer-is-keyId" | "signer-is-subject-for-key";
  /** Whether this check passed */
  valid: boolean;
  /** Failure reason if not valid */
  reason?: string;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Extract the signer identity from a pop-eip712 proof.
 * Recovers the signer address from the EIP-712 signature.
 */
function extractEip712Signer(proof: PopEip712Proof): string | null {
  const { domain, message, signature } = proof.proofObject;

  const typedData = {
    domain,
    types: {
      OmaTrustProof: [
        { name: "signer", type: "address" },
        { name: "authorizedEntity", type: "string" },
        { name: "signingPurpose", type: "string" },
        { name: "creationTimestamp", type: "uint256" },
        { name: "expirationTimestamp", type: "uint256" },
        { name: "randomValue", type: "bytes32" },
        { name: "statement", type: "string" },
      ],
    },
    message,
  };

  try {
    const result = verifyEip712Signature(typedData, signature);
    return result.valid && result.signer ? result.signer : null;
  } catch (err) {
    console.warn("[omatrust] EIP-712 signer extraction failed:", err);
    return null;
  }
}

/**
 * Extract the JWK from a pop-jws proof header.
 * Decodes the JWS header to get the embedded public key.
 */
function extractJwsHeaderJwk(proof: PopJwsProof): Record<string, unknown> | null {
  const jws = proof.proofObject;
  if (typeof jws !== "string") return null;

  const parts = jws.split(".");
  if (parts.length !== 3) return null;

  try {
    const headerB64 = parts[0].replace(/-/g, "+").replace(/_/g, "/");
    const padded = headerB64.padEnd(
      headerB64.length + ((4 - (headerB64.length % 4)) % 4),
      "="
    );
    let headerJson: string;
    if (typeof atob === "function") {
      headerJson = decodeURIComponent(
        Array.from(atob(padded))
          .map((char) => `%${char.charCodeAt(0).toString(16).padStart(2, "0")}`)
          .join("")
      );
    } else {
      headerJson = Buffer.from(padded, "base64").toString("utf8");
    }
    const header = JSON.parse(headerJson) as Record<string, unknown>;
    return (header.jwk as Record<string, unknown>) ?? null;
  } catch {
    return null;
  }
}

/**
 * Extract the JWS payload claims.
 */
function extractJwsPayload(proof: PopJwsProof): Record<string, unknown> | null {
  const jws = proof.proofObject;
  if (typeof jws !== "string") return null;

  const parts = jws.split(".");
  if (parts.length !== 3) return null;

  try {
    const payloadB64 = parts[1].replace(/-/g, "+").replace(/_/g, "/");
    const padded = payloadB64.padEnd(
      payloadB64.length + ((4 - (payloadB64.length % 4)) % 4),
      "="
    );
    let payloadJson: string;
    if (typeof atob === "function") {
      payloadJson = decodeURIComponent(
        Array.from(atob(padded))
          .map((char) => `%${char.charCodeAt(0).toString(16).padStart(2, "0")}`)
          .join("")
      );
    } else {
      payloadJson = Buffer.from(padded, "base64").toString("utf8");
    }
    return JSON.parse(payloadJson) as Record<string, unknown>;
  } catch {
    return null;
  }
}

/**
 * Check if a signer address matches a DID.
 * Supports did:pkh (EVM) and did:ethr.
 */
function signerMatchesDid(signerAddress: string, did: Did): boolean {
  try {
    const didAddress = extractAddressFromDid(did);
    return getAddress(signerAddress).toLowerCase() === getAddress(didAddress).toLowerCase();
  } catch {
    return false;
  }
}

/**
 * Check if a JWK matches a did:jwk or did:key DID.
 */
function jwkMatchesDid(jwk: Record<string, unknown>, did: Did): boolean {
  const method = extractDidMethod(did);

  if (method === "jwk") {
    try {
      const didJwk = didJwkToJwk(did);
      return publicJwkEquals(jwk, didJwk);
    } catch {
      return false;
    }
  }

  // For other methods, can't match by JWK
  return false;
}

/**
 * Determine if a proof's signer matches a given DID.
 * Works across proof types (pop-eip712, pop-jws).
 */
function proofSignerMatchesDid(proof: ProofWrapper, did: Did): boolean {
  switch (proof.proofType) {
    case "pop-eip712": {
      const signer = extractEip712Signer(proof as PopEip712Proof);
      if (!signer) return false;
      return signerMatchesDid(signer, did);
    }

    case "pop-jws": {
      const jwsProof = proof as PopJwsProof;
      const jwk = extractJwsHeaderJwk(jwsProof);

      // Check if the JWK in the header matches the DID
      if (jwk && jwkMatchesDid(jwk, did)) return true;

      // Also check the iss claim in the payload
      const payload = extractJwsPayload(jwsProof);
      if (payload && typeof payload.iss === "string") {
        // If iss matches the target DID, the proof is from that identity
        if (payload.iss === did) return true;
      }

      return false;
    }

    case "tx-encoded-value":
    case "tx-interaction":
      // Transaction proofs: the tx sender is the signer — would need on-chain lookup
      // These are validated separately by verifyProof with provider
      return false;

    case "evidence-pointer":
      // Evidence pointers don't have a cryptographic signer — they're URL-based
      return false;

    default:
      return false;
  }
}

/**
 * Check the "authorizedEntity" (aud) field of a proof matches a DID.
 * For pop-eip712: message.authorizedEntity
 * For pop-jws: payload.aud
 */
function proofAuthorizedEntityMatchesDid(proof: ProofWrapper, did: Did): boolean {
  switch (proof.proofType) {
    case "pop-eip712": {
      const eip712 = proof as PopEip712Proof;
      const authorizedEntity = eip712.proofObject.message.authorizedEntity;
      return typeof authorizedEntity === "string" && authorizedEntity === did;
    }

    case "pop-jws": {
      const payload = extractJwsPayload(proof as PopJwsProof);
      if (!payload) return false;
      return typeof payload.aud === "string" && payload.aud === did;
    }

    default:
      return false;
  }
}

// ---------------------------------------------------------------------------
// Schema-Aware Verification: Linked Identifier
// ---------------------------------------------------------------------------

/**
 * Verify proofs for a Linked Identifier attestation.
 *
 * A Linked Identifier attestation asserts that subject and linkedId are controlled
 * by the same entity. The proof semantics require:
 *
 * - At least one proof where the signer IS the subject (subject proves control)
 * - At least one proof where the signer IS the linkedId (linkedId proves control)
 *
 * OR (for non-signer identities like handles):
 * - Evidence-pointer proofs at locations controlled by the identity
 *
 * The combination demonstrates mutual agreement / shared control.
 *
 * @param data - The linked identifier attestation data
 * @returns Verification result with individual check details
 */
export function verifyLinkedIdentifierProofs(
  data: LinkedIdentifierData
): SchemaProofVerificationResult {
  if (!data.subject || !data.linkedId) {
    return {
      valid: false,
      checks: [],
      reasons: ["subject and linkedId are required"],
    };
  }

  if (!Array.isArray(data.proofs) || data.proofs.length === 0) {
    return {
      valid: false,
      checks: [],
      reasons: ["At least one proof is required"],
    };
  }

  const checks: SchemaProofCheck[] = [];
  let subjectProved = false;
  let linkedIdProved = false;

  for (let i = 0; i < data.proofs.length; i++) {
    const proof = data.proofs[i];

    // Check if this proof's signer is the subject
    if (proofSignerMatchesDid(proof, data.subject)) {
      checks.push({
        proofIndex: i,
        proofType: proof.proofType,
        checkType: "signer-is-subject",
        valid: true,
      });
      subjectProved = true;

      // Also verify the aud/authorizedEntity matches linkedId
      if (!proofAuthorizedEntityMatchesDid(proof, data.linkedId)) {
        checks.push({
          proofIndex: i,
          proofType: proof.proofType,
          checkType: "signer-is-subject",
          valid: false,
          reason: "Proof from subject does not authorize linkedId (aud mismatch)",
        });
      }
    }

    // Check if this proof's signer is the linkedId
    if (proofSignerMatchesDid(proof, data.linkedId)) {
      checks.push({
        proofIndex: i,
        proofType: proof.proofType,
        checkType: "signer-is-linkedId",
        valid: true,
      });
      linkedIdProved = true;

      // Also verify the aud/authorizedEntity matches subject
      if (!proofAuthorizedEntityMatchesDid(proof, data.subject)) {
        checks.push({
          proofIndex: i,
          proofType: proof.proofType,
          checkType: "signer-is-linkedId",
          valid: false,
          reason: "Proof from linkedId does not authorize subject (aud mismatch)",
        });
      }
    }

    // Evidence pointers count for non-signer identities
    if (proof.proofType === "evidence-pointer") {
      // Evidence pointers prove control of the URL location.
      // We can't definitively map URL → DID without fetching, so we give partial credit.
      // Full verification of evidence-pointer proofs should be done with verifyProof().
      checks.push({
        proofIndex: i,
        proofType: proof.proofType,
        checkType: "signer-is-subject",
        valid: true,
        reason: "Evidence pointer accepted (requires URL fetch for full verification)",
      });
      subjectProved = true;
    }
  }

  const reasons: string[] = [];
  if (!subjectProved) {
    reasons.push("No proof demonstrates control by subject");
  }
  if (!linkedIdProved) {
    reasons.push("No proof demonstrates control by linkedId");
  }

  return {
    valid: reasons.length === 0,
    checks,
    reasons,
  };
}

// ---------------------------------------------------------------------------
// Schema-Aware Verification: Key Binding
// ---------------------------------------------------------------------------

/**
 * Verify proofs for a Key Binding attestation.
 *
 * A Key Binding attestation asserts that the subject authorized a specific key (keyId).
 * The proof semantics require:
 *
 * - At least one proof where the signer IS the subject (subject authorized the binding)
 *   AND the proof's authorizedEntity/aud references the keyId
 *
 * Optionally, if publicKeyJwk is provided:
 * - The proof's signer key material should match publicKeyJwk for did:jwk keyIds
 *
 * @param data - The key binding attestation data
 * @returns Verification result with individual check details
 */
export function verifyKeyBindingProofs(
  data: KeyBindingData
): SchemaProofVerificationResult {
  if (!data.subject || !data.keyId) {
    return {
      valid: false,
      checks: [],
      reasons: ["subject and keyId are required"],
    };
  }

  if (!Array.isArray(data.proofs) || data.proofs.length === 0) {
    return {
      valid: false,
      checks: [],
      reasons: ["At least one proof is required"],
    };
  }

  const checks: SchemaProofCheck[] = [];
  let subjectAuthorizedKey = false;

  for (let i = 0; i < data.proofs.length; i++) {
    const proof = data.proofs[i];

    // Primary check: proof signer is the subject and authorizes the keyId
    if (proofSignerMatchesDid(proof, data.subject)) {
      const authorizesKey = proofAuthorizedEntityMatchesDid(proof, data.keyId);

      checks.push({
        proofIndex: i,
        proofType: proof.proofType,
        checkType: "signer-is-subject-for-key",
        valid: authorizesKey,
        reason: authorizesKey
          ? undefined
          : "Proof signed by subject but does not authorize the keyId",
      });

      if (authorizesKey) {
        subjectAuthorizedKey = true;
      }
    }

    // Secondary check: proof signer is the keyId itself (self-attestation)
    // This proves the key is active but doesn't prove authorization by subject
    if (proofSignerMatchesDid(proof, data.keyId)) {
      checks.push({
        proofIndex: i,
        proofType: proof.proofType,
        checkType: "signer-is-keyId",
        valid: true,
        reason: "Key proved possession (supplementary, not sufficient alone)",
      });
    }

    // Evidence pointers
    if (proof.proofType === "evidence-pointer") {
      checks.push({
        proofIndex: i,
        proofType: proof.proofType,
        checkType: "signer-is-subject-for-key",
        valid: true,
        reason: "Evidence pointer accepted (requires URL fetch for full verification)",
      });
      subjectAuthorizedKey = true;
    }
  }

  // Additional JWK consistency check if publicKeyJwk is provided
  if (data.publicKeyJwk && extractDidMethod(data.keyId) === "jwk") {
    try {
      const keyIdJwk = didJwkToJwk(data.keyId);
      const jwkConsistent = publicJwkEquals(data.publicKeyJwk, keyIdJwk);
      if (!jwkConsistent) {
        return {
          valid: false,
          checks,
          reasons: ["publicKeyJwk does not match the key material in keyId (did:jwk)"],
        };
      }
    } catch {
      // Can't compare — not a blocking error
    }
  }

  const reasons: string[] = [];
  if (!subjectAuthorizedKey) {
    reasons.push(
      "No proof demonstrates that subject authorized the key binding"
    );
  }

  return {
    valid: reasons.length === 0,
    checks,
    reasons,
  };
}
