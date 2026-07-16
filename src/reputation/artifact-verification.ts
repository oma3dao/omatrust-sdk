/**
 * Artifact Verification
 *
 * Implements Responsibility Claim verification for did:artifact subjects.
 * Extracted from the rep-attestation-frontend in Phase 2.
 *
 * These functions verify that a Responsibility Claim attestation was issued
 * by an authorized controller of the claimed responsible party, within a valid
 * time window, and for the correct artifact subject.
 */

import { parseArtifactDid } from "../identity/artifact";
import { decodeAttestationData } from "./encode";
import { listAttestations } from "./query";
import { verifyAttestation } from "./verify";
import { getControllerAuthorization } from "./attester-authorization";
import type {
  AttestationQueryResult,
  ControllerAuthorizationResult,
  Hex,
  VerifyAttestationResult,
} from "./types";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type VerifyResponsibilityClaimParams = {
  /** The attestation to verify */
  attestation: AttestationQueryResult;
  /** If provided, cross-check that the attestation subject matches this DID */
  artifactDid?: string;
  /** ethers v6 Provider for on-chain reads */
  provider: unknown;
  /** EAS contract address */
  easContractAddress?: Hex;
  /** CAIP-2 chain identifier (e.g. "eip155:6623") */
  chain?: string;
  /** Chain ID as a number — used to derive the controller DID from the attester address */
  chainId: number;
  /** The EAS schema string for the Responsibility Claim schema */
  responsibilityClaimSchemaString: string;
};

export type VerifyResponsibilityClaimResult = {
  valid: boolean;
  responsibleParty: string;
  controllerDid: string;
  responsibilityTypes: string[];
  subjectLabel?: string;
  authorization: ControllerAuthorizationResult | null;
  checks: {
    schemaValid: boolean;
    subjectMatches: boolean;
    notRevoked: boolean;
    currentlyEffective: boolean;
    controllerAuthorized: boolean;
    issuedDuringAuthorizationWindow: boolean;
  };
  reasons: string[];
};

export type GetVerifiedArtifactAttestationsParams = {
  /** The did:artifact to query */
  artifactDid: string;
  /** ethers v6 Provider for on-chain reads */
  provider: unknown;
  /** EAS contract address */
  easContractAddress: Hex;
  /** CAIP-2 chain identifier (e.g. "eip155:6623") */
  chain?: string;
  /** Chain ID as a number */
  chainId: number;
  /** Schema UIDs to query for — all deployed schema UIDs on this chain */
  schemaUids: Hex[];
  /** The UID of the Responsibility Claim schema on this chain */
  responsibilityClaimSchemaUid: Hex;
  /** The EAS schema string for the Responsibility Claim schema */
  responsibilityClaimSchemaString: string;
  /** Optional schema UID for security-assessment attestations */
  securityAssessmentSchemaUid?: Hex;
  /** Optional schema UID for certification attestations */
  certificationSchemaUid?: Hex;
  /** Start block for event scanning */
  fromBlock?: number;
  /** Maximum number of attestations to retrieve */
  limit?: number;
};

export type VerifiedArtifactAttestation = {
  attestation: AttestationQueryResult;
  verification?: VerifyAttestationResult;
};

export type VerifiedResponsibilityClaim = {
  attestation: AttestationQueryResult;
  verification: VerifyResponsibilityClaimResult;
};

export type GetVerifiedArtifactAttestationsResult = {
  artifactDid: string;
  responsibilityClaims: VerifiedResponsibilityClaim[];
  securityAssessments: VerifiedArtifactAttestation[];
  certifications: VerifiedArtifactAttestation[];
  otherAttestations: VerifiedArtifactAttestation[];
};

export type IsArtifactClaimedByParams = {
  /** The did:artifact to check */
  artifactDid: string;
  /** The responsible party DID to check for */
  responsibleParty: string;
  /** ethers v6 Provider for on-chain reads */
  provider: unknown;
  /** EAS contract address */
  easContractAddress: Hex;
  /** CAIP-2 chain identifier */
  chain?: string;
  /** Chain ID as a number */
  chainId: number;
  /** Schema UIDs to query for */
  schemaUids: Hex[];
  /** The UID of the Responsibility Claim schema on this chain */
  responsibilityClaimSchemaUid: Hex;
  /** The EAS schema string for the Responsibility Claim schema */
  responsibilityClaimSchemaString: string;
  /** Optional schema UID for security-assessment attestations */
  securityAssessmentSchemaUid?: Hex;
  /** Optional schema UID for certification attestations */
  certificationSchemaUid?: Hex;
  /** Filter by specific responsibility types (e.g. ["creator", "maintainer"]) */
  responsibilityTypes?: string[];
};

export type IsArtifactClaimedByResult = {
  claimed: boolean;
  claims: VerifiedResponsibilityClaim[];
  matchedResponsibilityTypes: string[];
  reasons: string[];
};

// ---------------------------------------------------------------------------
// verifyResponsibilityClaim
// ---------------------------------------------------------------------------

export async function verifyResponsibilityClaim(
  params: VerifyResponsibilityClaimParams
): Promise<VerifyResponsibilityClaimResult> {
  const {
    attestation,
    artifactDid,
    provider,
    easContractAddress,
    chain,
    chainId,
    responsibilityClaimSchemaString,
  } = params;

  const reasons: string[] = [];
  const checks = {
    schemaValid: false,
    subjectMatches: false,
    notRevoked: false,
    currentlyEffective: false,
    controllerAuthorized: false,
    issuedDuringAuthorizationWindow: false,
  };

  // 1. Decode attestation data
  let decoded: Record<string, unknown>;
  try {
    if (attestation.raw) {
      decoded = decodeAttestationData(responsibilityClaimSchemaString, attestation.raw);
    } else if (attestation.data && typeof attestation.data === "object") {
      decoded = attestation.data as Record<string, unknown>;
    } else {
      reasons.push("No attestation data available to decode");
      return buildFailedResult(checks, reasons);
    }
  } catch (err) {
    reasons.push(
      `Failed to decode attestation data: ${err instanceof Error ? err.message : "unknown error"}`
    );
    return buildFailedResult(checks, reasons);
  }

  // 2. Validate required fields
  const responsibleParty = decoded.responsibleParty as string | undefined;
  const subject = decoded.subject as string | undefined;
  const responsibilityType = decoded.responsibilityType as string[] | undefined;
  const issuedAt = decoded.issuedAt as bigint | number | undefined;
  const effectiveAt = decoded.effectiveAt as bigint | number | undefined;
  const expiresAt = decoded.expiresAt as bigint | number | undefined;
  const subjectLabel = decoded.subjectLabel as string | undefined;

  if (!responsibleParty || !subject || !responsibilityType || !issuedAt) {
    if (!responsibleParty) reasons.push("Missing required field: responsibleParty");
    if (!subject) reasons.push("Missing required field: subject");
    if (!responsibilityType) reasons.push("Missing required field: responsibilityType");
    if (!issuedAt) reasons.push("Missing required field: issuedAt");
    return buildFailedResult(checks, reasons, {
      responsibleParty,
      subject,
      subjectLabel,
      responsibilityType,
    });
  }

  if (!Array.isArray(responsibilityType) || responsibilityType.length === 0) {
    reasons.push("responsibilityType must be a non-empty array");
    return buildFailedResult(checks, reasons, {
      responsibleParty,
      subject,
      subjectLabel,
      responsibilityType,
    });
  }

  checks.schemaValid = true;

  // 3. Subject match check
  if (artifactDid) {
    checks.subjectMatches = subject.toLowerCase() === artifactDid.toLowerCase();
    if (!checks.subjectMatches) {
      reasons.push(`Subject "${subject}" does not match expected artifact "${artifactDid}"`);
    }
  } else {
    // No cross-check requested
    checks.subjectMatches = true;
  }

  // 4. Revocation check
  checks.notRevoked = attestation.revocationTime === BigInt(0);
  if (!checks.notRevoked) {
    reasons.push("Attestation has been revoked");
  }

  // 5. Effective/expiration date check
  const now = BigInt(Math.floor(Date.now() / 1000));
  const effectiveTime = toBigInt(effectiveAt);
  const expirationTime = toBigInt(expiresAt);

  const isEffective = effectiveTime === BigInt(0) || effectiveTime <= now;
  const isNotExpired = expirationTime === BigInt(0) || expirationTime > now;
  checks.currentlyEffective = isEffective && isNotExpired;

  if (!isEffective) {
    reasons.push("Attestation is not yet effective");
  }
  if (!isNotExpired) {
    reasons.push("Attestation has expired");
  }

  // 6. Derive controller DID from attester
  const controllerDid = `did:pkh:eip155:${chainId}:${attestation.attester.toLowerCase()}`;

  // 7. Controller authorization
  let authorization: ControllerAuthorizationResult | null = null;
  try {
    const resolvedChain = chain ?? `eip155:${chainId}`;
    authorization = await getControllerAuthorization({
      subjectDid: responsibleParty,
      controllerDid,
      provider,
      chain: resolvedChain,
      easContractAddress,
    });

    // 8. Check authorized
    checks.controllerAuthorized = authorization.authorized;
    if (!checks.controllerAuthorized) {
      reasons.push(`Controller ${controllerDid} is not authorized for ${responsibleParty}`);
    }

    // 9. Check issuedAt within authorization window
    if (authorization.authorized && authorization.anchoredFrom !== null) {
      const issuedAtBigInt = toBigInt(issuedAt);
      const afterStart = issuedAtBigInt >= authorization.anchoredFrom;
      const beforeEnd =
        authorization.until === null || issuedAtBigInt <= authorization.until;
      checks.issuedDuringAuthorizationWindow = afterStart && beforeEnd;

      if (!afterStart) {
        reasons.push("Attestation was issued before the authorization window started");
      }
      if (!beforeEnd) {
        reasons.push("Attestation was issued after the authorization window ended");
      }
    } else if (authorization.authorized && authorization.anchoredFrom === null) {
      // Authorization is live-only (DNS/did.json), no anchored window — accept
      checks.issuedDuringAuthorizationWindow = true;
    } else {
      // Not authorized — window check is moot
      checks.issuedDuringAuthorizationWindow = false;
    }
  } catch (err) {
    reasons.push(
      `Controller authorization check failed: ${err instanceof Error ? err.message : "unknown error"}`
    );
    checks.controllerAuthorized = false;
    checks.issuedDuringAuthorizationWindow = false;
  }

  const valid = Object.values(checks).every(Boolean);

  return {
    valid,
    responsibleParty,
    controllerDid,
    responsibilityTypes: responsibilityType,
    subjectLabel: subjectLabel || undefined,
    authorization,
    checks,
    reasons,
  };
}

// ---------------------------------------------------------------------------
// getVerifiedArtifactAttestations
// ---------------------------------------------------------------------------

export async function getVerifiedArtifactAttestations(
  params: GetVerifiedArtifactAttestationsParams
): Promise<GetVerifiedArtifactAttestationsResult> {
  const {
    artifactDid,
    provider,
    easContractAddress,
    chain,
    chainId,
    schemaUids,
    responsibilityClaimSchemaUid,
    responsibilityClaimSchemaString,
    securityAssessmentSchemaUid,
    certificationSchemaUid,
    fromBlock,
    limit,
  } = params;

  // Validate did:artifact input
  parseArtifactDid(artifactDid); // throws if invalid

  if (schemaUids.length === 0) {
    return {
      artifactDid,
      responsibilityClaims: [],
      securityAssessments: [],
      certifications: [],
      otherAttestations: [],
    };
  }

  // Query all attestations for this artifact DID
  const results = await listAttestations({
    subjectDid: artifactDid,
    provider,
    easContractAddress,
    schemas: schemaUids,
    limit: limit ?? 100,
    fromBlock,
  });

  // Group by schema
  const responsibilityClaims: VerifiedResponsibilityClaim[] = [];
  const securityAssessments: VerifiedArtifactAttestation[] = [];
  const certifications: VerifiedArtifactAttestation[] = [];
  const otherAttestations: VerifiedArtifactAttestation[] = [];

  for (const att of results) {
    const schemaUidLower = att.schema.toLowerCase();

    if (schemaUidLower === responsibilityClaimSchemaUid.toLowerCase()) {
      // Verify responsibility claim
      const verification = await verifyResponsibilityClaim({
        attestation: att,
        artifactDid,
        provider,
        easContractAddress,
        chain,
        chainId,
        responsibilityClaimSchemaString,
      });
      responsibilityClaims.push({ attestation: att, verification });
    } else if (
      securityAssessmentSchemaUid &&
      schemaUidLower === securityAssessmentSchemaUid.toLowerCase()
    ) {
      const verification = await runStandardVerification(att, provider);
      securityAssessments.push({ attestation: att, verification });
    } else if (
      certificationSchemaUid &&
      schemaUidLower === certificationSchemaUid.toLowerCase()
    ) {
      const verification = await runStandardVerification(att, provider);
      certifications.push({ attestation: att, verification });
    } else {
      const verification = await runStandardVerification(att, provider);
      otherAttestations.push({ attestation: att, verification });
    }
  }

  return {
    artifactDid,
    responsibilityClaims,
    securityAssessments,
    certifications,
    otherAttestations,
  };
}

// ---------------------------------------------------------------------------
// isArtifactClaimedBy
// ---------------------------------------------------------------------------

export async function isArtifactClaimedBy(
  params: IsArtifactClaimedByParams
): Promise<IsArtifactClaimedByResult> {
  const { artifactDid, responsibleParty, responsibilityTypes } = params;

  const result = await getVerifiedArtifactAttestations({
    artifactDid,
    provider: params.provider,
    easContractAddress: params.easContractAddress,
    chain: params.chain,
    chainId: params.chainId,
    schemaUids: params.schemaUids,
    responsibilityClaimSchemaUid: params.responsibilityClaimSchemaUid,
    responsibilityClaimSchemaString: params.responsibilityClaimSchemaString,
    securityAssessmentSchemaUid: params.securityAssessmentSchemaUid,
    certificationSchemaUid: params.certificationSchemaUid,
  });

  // Filter to claims from the specified responsible party
  const matchingClaims = result.responsibilityClaims.filter(
    (claim) =>
      claim.verification.responsibleParty.toLowerCase() ===
      responsibleParty.toLowerCase()
  );

  // Only include claims that passed verification
  const validClaims = matchingClaims.filter((claim) => claim.verification.valid);

  // Filter by responsibility types if specified
  let finalClaims = validClaims;
  let matchedTypes: string[] = [];

  if (responsibilityTypes && responsibilityTypes.length > 0) {
    finalClaims = validClaims.filter((claim) =>
      claim.verification.responsibilityTypes.some((t) =>
        responsibilityTypes.includes(t)
      )
    );
    matchedTypes = [
      ...new Set(
        finalClaims.flatMap((claim) =>
          claim.verification.responsibilityTypes.filter((t) =>
            responsibilityTypes.includes(t)
          )
        )
      ),
    ];
  } else {
    matchedTypes = [
      ...new Set(
        validClaims.flatMap((claim) => claim.verification.responsibilityTypes)
      ),
    ];
  }

  const reasons: string[] = [];
  if (finalClaims.length === 0) {
    if (matchingClaims.length === 0) {
      reasons.push(
        `No responsibility claims found from ${responsibleParty} for this artifact`
      );
    } else if (validClaims.length === 0) {
      reasons.push(
        `Claims from ${responsibleParty} exist but none passed verification`
      );
    } else if (responsibilityTypes) {
      reasons.push(
        `No claims matched the requested responsibility types: ${responsibilityTypes.join(", ")}`
      );
    }
  }

  return {
    claimed: finalClaims.length > 0,
    claims: finalClaims,
    matchedResponsibilityTypes: matchedTypes,
    reasons,
  };
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function toBigInt(value: bigint | number | undefined): bigint {
  if (value === undefined || value === null) return BigInt(0);
  if (typeof value === "bigint") return value;
  return BigInt(value);
}

function buildFailedResult(
  checks: VerifyResponsibilityClaimResult["checks"],
  reasons: string[],
  decoded?: {
    responsibleParty?: string;
    subject?: string;
    subjectLabel?: string;
    responsibilityType?: string[];
  }
): VerifyResponsibilityClaimResult {
  return {
    valid: false,
    responsibleParty: decoded?.responsibleParty ?? "",
    controllerDid: "",
    responsibilityTypes: decoded?.responsibilityType ?? [],
    subjectLabel: decoded?.subjectLabel || undefined,
    authorization: null,
    checks,
    reasons,
  };
}

async function runStandardVerification(
  attestation: AttestationQueryResult,
  provider: unknown
): Promise<VerifyAttestationResult | undefined> {
  try {
    return await verifyAttestation({ attestation, provider });
  } catch {
    return undefined;
  }
}
