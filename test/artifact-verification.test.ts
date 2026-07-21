import { beforeEach, describe, expect, it, vi } from "vitest";
import type {
  AttestationQueryResult,
  ControllerAuthorizationResult,
  Hex,
  VerifyAttestationResult,
} from "../src/reputation/types";

// ---------------------------------------------------------------------------
// Mocks
// ---------------------------------------------------------------------------

const mockDecodeAttestationData = vi.fn();
const mockListAttestations = vi.fn();
const mockVerifyAttestation = vi.fn();
const mockGetControllerAuthorization = vi.fn();
const mockParseArtifactDid = vi.fn();

vi.mock("../src/reputation/encode", () => ({
  decodeAttestationData: (...args: unknown[]) => mockDecodeAttestationData(...args),
  normalizeSchema: vi.fn(),
  schemaToString: vi.fn(),
}));

vi.mock("../src/reputation/query", () => ({
  listAttestations: (...args: unknown[]) => mockListAttestations(...args),
}));

vi.mock("../src/reputation/verify", () => ({
  verifyAttestation: (...args: unknown[]) => mockVerifyAttestation(...args),
}));

vi.mock("../src/reputation/attester-authorization", () => ({
  getControllerAuthorization: (...args: unknown[]) =>
    mockGetControllerAuthorization(...args),
}));

vi.mock("../src/identity/artifact", () => ({
  parseArtifactDid: (...args: unknown[]) => mockParseArtifactDid(...args),
}));

import {
  verifyResponsibilityClaim,
  getVerifiedArtifactAttestations,
  isArtifactClaimedBy,
} from "../src/reputation/artifact-verification";

// ---------------------------------------------------------------------------
// Test Fixtures
// ---------------------------------------------------------------------------

const CHAIN_ID = 66238;
const SCHEMA_STRING =
  "string responsibleParty, string subject, string[] responsibilityType, uint256 issuedAt, uint256 effectiveAt, uint256 expiresAt, string subjectLabel";
const RESPONSIBILITY_CLAIM_UID = ("0x" + "aa".repeat(32)) as Hex;
const SECURITY_ASSESSMENT_UID = ("0x" + "bb".repeat(32)) as Hex;
const CERTIFICATION_UID = ("0x" + "cc".repeat(32)) as Hex;
const EAS_CONTRACT = "0x4200000000000000000000000000000000000021" as Hex;
const ATTESTER = "0x1111111111111111111111111111111111111111" as Hex;
const ARTIFACT_DID =
  "did:artifact:bafkreigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi";

function makeAttestation(overrides?: Partial<AttestationQueryResult>): AttestationQueryResult {
  return {
    uid: ("0x" + "dd".repeat(32)) as Hex,
    schema: RESPONSIBILITY_CLAIM_UID,
    attester: ATTESTER,
    recipient: ("0x" + "00".repeat(20)) as Hex,
    revocable: true,
    revocationTime: 0n,
    expirationTime: 0n,
    time: 1700000000n,
    refUID: ("0x" + "00".repeat(32)) as Hex,
    data: {},
    raw: "0xabcdef" as Hex,
    ...overrides,
  };
}

function makeDecodedClaim(overrides?: Record<string, unknown>) {
  return {
    responsibleParty: "did:web:example.com",
    subject: ARTIFACT_DID,
    responsibilityType: ["creator"],
    issuedAt: BigInt(1700000000),
    effectiveAt: BigInt(0),
    expiresAt: BigInt(0),
    subjectLabel: "My App v1.0",
    ...overrides,
  };
}

function makeAuthorization(overrides?: Partial<ControllerAuthorizationResult>): ControllerAuthorizationResult {
  return {
    authorized: true,
    anchoredFrom: 1600000000n,
    until: null,
    currentlyVerified: true,
    liveMethod: "dns",
    controllerWitnesses: [],
    keyBindingUid: null,
    keyPurposeStatus: "not-required",
    ...overrides,
  };
}

const mockProvider = { getBlockNumber: vi.fn().mockResolvedValue(1_000_000) };

// ---------------------------------------------------------------------------
// verifyResponsibilityClaim — Unit Tests
// ---------------------------------------------------------------------------

describe("verifyResponsibilityClaim", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockDecodeAttestationData.mockReturnValue(makeDecodedClaim());
    mockGetControllerAuthorization.mockResolvedValue(makeAuthorization());
  });

  // -------------------------------------------------------------------------
  // Happy paths
  // -------------------------------------------------------------------------

  it("returns valid: true with authorized attester and all checks passing", async () => {
    const result = await verifyResponsibilityClaim({
      attestation: makeAttestation(),
      artifactDid: ARTIFACT_DID,
      provider: mockProvider,
      easContractAddress: EAS_CONTRACT,
      chainId: CHAIN_ID,
      responsibilityClaimSchemaString: SCHEMA_STRING,
    });

    expect(result.valid).toBe(true);
    expect(result.responsibleParty).toBe("did:web:example.com");
    expect(result.controllerDid).toBe(
      `did:pkh:eip155:${CHAIN_ID}:${ATTESTER.toLowerCase()}`
    );
    expect(result.responsibilityTypes).toEqual(["creator"]);
    expect(result.subjectLabel).toBe("My App v1.0");
    expect(result.checks).toEqual({
      schemaValid: true,
      subjectMatches: true,
      notRevoked: true,
      currentlyEffective: true,
      controllerAuthorized: true,
      issuedDuringAuthorizationWindow: true,
    });
    expect(result.reasons).toEqual([]);
  });

  it("handles multiple responsibility types correctly", async () => {
    mockDecodeAttestationData.mockReturnValue(
      makeDecodedClaim({ responsibilityType: ["creator", "maintainer", "auditor"] })
    );

    const result = await verifyResponsibilityClaim({
      attestation: makeAttestation(),
      artifactDid: ARTIFACT_DID,
      provider: mockProvider,
      chainId: CHAIN_ID,
      responsibilityClaimSchemaString: SCHEMA_STRING,
    });

    expect(result.valid).toBe(true);
    expect(result.responsibilityTypes).toEqual(["creator", "maintainer", "auditor"]);
  });

  it("includes subjectLabel when present", async () => {
    mockDecodeAttestationData.mockReturnValue(
      makeDecodedClaim({ subjectLabel: "Super App" })
    );

    const result = await verifyResponsibilityClaim({
      attestation: makeAttestation(),
      artifactDid: ARTIFACT_DID,
      provider: mockProvider,
      chainId: CHAIN_ID,
      responsibilityClaimSchemaString: SCHEMA_STRING,
    });

    expect(result.subjectLabel).toBe("Super App");
  });

  it("accepts claim near authorization window start (issuedAt == anchoredFrom)", async () => {
    mockDecodeAttestationData.mockReturnValue(
      makeDecodedClaim({ issuedAt: BigInt(1600000000) })
    );
    mockGetControllerAuthorization.mockResolvedValue(
      makeAuthorization({ anchoredFrom: 1600000000n })
    );

    const result = await verifyResponsibilityClaim({
      attestation: makeAttestation(),
      artifactDid: ARTIFACT_DID,
      provider: mockProvider,
      chainId: CHAIN_ID,
      responsibilityClaimSchemaString: SCHEMA_STRING,
    });

    expect(result.valid).toBe(true);
    expect(result.checks.issuedDuringAuthorizationWindow).toBe(true);
  });

  it("accepts claim near authorization window end (issuedAt == until)", async () => {
    mockDecodeAttestationData.mockReturnValue(
      makeDecodedClaim({ issuedAt: BigInt(1800000000) })
    );
    mockGetControllerAuthorization.mockResolvedValue(
      makeAuthorization({ anchoredFrom: 1600000000n, until: 1800000000n })
    );

    const result = await verifyResponsibilityClaim({
      attestation: makeAttestation(),
      artifactDid: ARTIFACT_DID,
      provider: mockProvider,
      chainId: CHAIN_ID,
      responsibilityClaimSchemaString: SCHEMA_STRING,
    });

    expect(result.valid).toBe(true);
    expect(result.checks.issuedDuringAuthorizationWindow).toBe(true);
  });

  // -------------------------------------------------------------------------
  // Check isolation — each check fails independently
  // -------------------------------------------------------------------------

  it("fails schemaValid when responsibleParty is missing", async () => {
    mockDecodeAttestationData.mockReturnValue(
      makeDecodedClaim({ responsibleParty: undefined })
    );

    const result = await verifyResponsibilityClaim({
      attestation: makeAttestation(),
      artifactDid: ARTIFACT_DID,
      provider: mockProvider,
      chainId: CHAIN_ID,
      responsibilityClaimSchemaString: SCHEMA_STRING,
    });

    expect(result.valid).toBe(false);
    expect(result.checks.schemaValid).toBe(false);
    expect(result.reasons).toContain("Missing required field: responsibleParty");
  });

  it("fails schemaValid when subject is missing", async () => {
    mockDecodeAttestationData.mockReturnValue(
      makeDecodedClaim({ subject: undefined })
    );

    const result = await verifyResponsibilityClaim({
      attestation: makeAttestation(),
      artifactDid: ARTIFACT_DID,
      provider: mockProvider,
      chainId: CHAIN_ID,
      responsibilityClaimSchemaString: SCHEMA_STRING,
    });

    expect(result.valid).toBe(false);
    expect(result.checks.schemaValid).toBe(false);
    expect(result.reasons).toContain("Missing required field: subject");
  });

  it("fails schemaValid when responsibilityType is missing", async () => {
    mockDecodeAttestationData.mockReturnValue(
      makeDecodedClaim({ responsibilityType: undefined })
    );

    const result = await verifyResponsibilityClaim({
      attestation: makeAttestation(),
      artifactDid: ARTIFACT_DID,
      provider: mockProvider,
      chainId: CHAIN_ID,
      responsibilityClaimSchemaString: SCHEMA_STRING,
    });

    expect(result.valid).toBe(false);
    expect(result.checks.schemaValid).toBe(false);
    expect(result.reasons).toContain("Missing required field: responsibilityType");
  });

  it("fails schemaValid when responsibilityType is empty array", async () => {
    mockDecodeAttestationData.mockReturnValue(
      makeDecodedClaim({ responsibilityType: [] })
    );

    const result = await verifyResponsibilityClaim({
      attestation: makeAttestation(),
      artifactDid: ARTIFACT_DID,
      provider: mockProvider,
      chainId: CHAIN_ID,
      responsibilityClaimSchemaString: SCHEMA_STRING,
    });

    expect(result.valid).toBe(false);
    expect(result.reasons).toContain("responsibilityType must be a non-empty array");
  });

  it("fails schemaValid when issuedAt is missing", async () => {
    mockDecodeAttestationData.mockReturnValue(
      makeDecodedClaim({ issuedAt: undefined })
    );

    const result = await verifyResponsibilityClaim({
      attestation: makeAttestation(),
      artifactDid: ARTIFACT_DID,
      provider: mockProvider,
      chainId: CHAIN_ID,
      responsibilityClaimSchemaString: SCHEMA_STRING,
    });

    expect(result.valid).toBe(false);
    expect(result.checks.schemaValid).toBe(false);
    expect(result.reasons).toContain("Missing required field: issuedAt");
  });

  it("fails subjectMatches when subject does not match artifactDid", async () => {
    mockDecodeAttestationData.mockReturnValue(
      makeDecodedClaim({ subject: "did:artifact:bafkreidifferent" })
    );

    const result = await verifyResponsibilityClaim({
      attestation: makeAttestation(),
      artifactDid: ARTIFACT_DID,
      provider: mockProvider,
      chainId: CHAIN_ID,
      responsibilityClaimSchemaString: SCHEMA_STRING,
    });

    expect(result.valid).toBe(false);
    expect(result.checks.subjectMatches).toBe(false);
    expect(result.reasons).toContainEqual(
      expect.stringContaining("does not match expected artifact")
    );
  });

  it("fails notRevoked when revocationTime > 0", async () => {
    const result = await verifyResponsibilityClaim({
      attestation: makeAttestation({ revocationTime: 1700500000n }),
      artifactDid: ARTIFACT_DID,
      provider: mockProvider,
      chainId: CHAIN_ID,
      responsibilityClaimSchemaString: SCHEMA_STRING,
    });

    expect(result.valid).toBe(false);
    expect(result.checks.notRevoked).toBe(false);
    expect(result.reasons).toContain("Attestation has been revoked");
  });

  it("fails currentlyEffective when effectiveAt is in the future", async () => {
    const futureTime = BigInt(Math.floor(Date.now() / 1000) + 100000);
    mockDecodeAttestationData.mockReturnValue(
      makeDecodedClaim({ effectiveAt: futureTime })
    );

    const result = await verifyResponsibilityClaim({
      attestation: makeAttestation(),
      artifactDid: ARTIFACT_DID,
      provider: mockProvider,
      chainId: CHAIN_ID,
      responsibilityClaimSchemaString: SCHEMA_STRING,
    });

    expect(result.valid).toBe(false);
    expect(result.checks.currentlyEffective).toBe(false);
    expect(result.reasons).toContain("Attestation is not yet effective");
  });

  it("fails currentlyEffective when expiresAt is in the past", async () => {
    mockDecodeAttestationData.mockReturnValue(
      makeDecodedClaim({ expiresAt: BigInt(1000) })
    );

    const result = await verifyResponsibilityClaim({
      attestation: makeAttestation(),
      artifactDid: ARTIFACT_DID,
      provider: mockProvider,
      chainId: CHAIN_ID,
      responsibilityClaimSchemaString: SCHEMA_STRING,
    });

    expect(result.valid).toBe(false);
    expect(result.checks.currentlyEffective).toBe(false);
    expect(result.reasons).toContain("Attestation has expired");
  });

  it("passes currentlyEffective when expiresAt === 0 (no expiration)", async () => {
    mockDecodeAttestationData.mockReturnValue(
      makeDecodedClaim({ expiresAt: BigInt(0) })
    );

    const result = await verifyResponsibilityClaim({
      attestation: makeAttestation(),
      artifactDid: ARTIFACT_DID,
      provider: mockProvider,
      chainId: CHAIN_ID,
      responsibilityClaimSchemaString: SCHEMA_STRING,
    });

    expect(result.checks.currentlyEffective).toBe(true);
  });

  it("fails controllerAuthorized when controller is not authorized", async () => {
    mockGetControllerAuthorization.mockResolvedValue(
      makeAuthorization({ authorized: false })
    );

    const result = await verifyResponsibilityClaim({
      attestation: makeAttestation(),
      artifactDid: ARTIFACT_DID,
      provider: mockProvider,
      chainId: CHAIN_ID,
      responsibilityClaimSchemaString: SCHEMA_STRING,
    });

    expect(result.valid).toBe(false);
    expect(result.checks.controllerAuthorized).toBe(false);
    expect(result.reasons).toContainEqual(
      expect.stringContaining("is not authorized for")
    );
  });

  it("fails issuedDuringAuthorizationWindow when issuedAt is before anchoredFrom", async () => {
    mockDecodeAttestationData.mockReturnValue(
      makeDecodedClaim({ issuedAt: BigInt(1500000000) })
    );
    mockGetControllerAuthorization.mockResolvedValue(
      makeAuthorization({ anchoredFrom: 1600000000n })
    );

    const result = await verifyResponsibilityClaim({
      attestation: makeAttestation(),
      artifactDid: ARTIFACT_DID,
      provider: mockProvider,
      chainId: CHAIN_ID,
      responsibilityClaimSchemaString: SCHEMA_STRING,
    });

    expect(result.valid).toBe(false);
    expect(result.checks.issuedDuringAuthorizationWindow).toBe(false);
    expect(result.reasons).toContain(
      "Attestation was issued before the authorization window started"
    );
  });

  it("fails issuedDuringAuthorizationWindow when issuedAt is after until", async () => {
    mockDecodeAttestationData.mockReturnValue(
      makeDecodedClaim({ issuedAt: BigInt(1900000000) })
    );
    mockGetControllerAuthorization.mockResolvedValue(
      makeAuthorization({ anchoredFrom: 1600000000n, until: 1800000000n })
    );

    const result = await verifyResponsibilityClaim({
      attestation: makeAttestation(),
      artifactDid: ARTIFACT_DID,
      provider: mockProvider,
      chainId: CHAIN_ID,
      responsibilityClaimSchemaString: SCHEMA_STRING,
    });

    expect(result.valid).toBe(false);
    expect(result.checks.issuedDuringAuthorizationWindow).toBe(false);
    expect(result.reasons).toContain(
      "Attestation was issued after the authorization window ended"
    );
  });

  // -------------------------------------------------------------------------
  // Edge cases
  // -------------------------------------------------------------------------

  it("sets subjectMatches to true when artifactDid param is omitted (no cross-check)", async () => {
    const result = await verifyResponsibilityClaim({
      attestation: makeAttestation(),
      provider: mockProvider,
      chainId: CHAIN_ID,
      responsibilityClaimSchemaString: SCHEMA_STRING,
    });

    expect(result.checks.subjectMatches).toBe(true);
  });

  it("performs case-insensitive subject matching", async () => {
    mockDecodeAttestationData.mockReturnValue(
      makeDecodedClaim({ subject: ARTIFACT_DID.toUpperCase() })
    );

    const result = await verifyResponsibilityClaim({
      attestation: makeAttestation(),
      artifactDid: ARTIFACT_DID.toLowerCase(),
      provider: mockProvider,
      chainId: CHAIN_ID,
      responsibilityClaimSchemaString: SCHEMA_STRING,
    });

    expect(result.checks.subjectMatches).toBe(true);
  });

  it("treats effectiveAt === 0 as immediately effective", async () => {
    mockDecodeAttestationData.mockReturnValue(
      makeDecodedClaim({ effectiveAt: BigInt(0) })
    );

    const result = await verifyResponsibilityClaim({
      attestation: makeAttestation(),
      artifactDid: ARTIFACT_DID,
      provider: mockProvider,
      chainId: CHAIN_ID,
      responsibilityClaimSchemaString: SCHEMA_STRING,
    });

    expect(result.checks.currentlyEffective).toBe(true);
  });

  it("reports multiple failures simultaneously in reasons[]", async () => {
    mockDecodeAttestationData.mockReturnValue(
      makeDecodedClaim({ subject: "did:artifact:wrong", expiresAt: BigInt(1000) })
    );
    mockGetControllerAuthorization.mockResolvedValue(
      makeAuthorization({ authorized: false })
    );

    const result = await verifyResponsibilityClaim({
      attestation: makeAttestation({ revocationTime: 5000n }),
      artifactDid: ARTIFACT_DID,
      provider: mockProvider,
      chainId: CHAIN_ID,
      responsibilityClaimSchemaString: SCHEMA_STRING,
    });

    expect(result.valid).toBe(false);
    expect(result.reasons.length).toBeGreaterThanOrEqual(3);
    expect(result.checks.subjectMatches).toBe(false);
    expect(result.checks.notRevoked).toBe(false);
    expect(result.checks.currentlyEffective).toBe(false);
    expect(result.checks.controllerAuthorized).toBe(false);
  });

  it("handles decode failure gracefully", async () => {
    mockDecodeAttestationData.mockImplementation(() => {
      throw new Error("corrupt data");
    });

    const result = await verifyResponsibilityClaim({
      attestation: makeAttestation(),
      artifactDid: ARTIFACT_DID,
      provider: mockProvider,
      chainId: CHAIN_ID,
      responsibilityClaimSchemaString: SCHEMA_STRING,
    });

    expect(result.valid).toBe(false);
    expect(result.reasons).toContainEqual(
      expect.stringContaining("Failed to decode attestation data")
    );
  });

  it("uses attestation.data when raw is not available", async () => {
    const decodedData = makeDecodedClaim();

    const result = await verifyResponsibilityClaim({
      attestation: makeAttestation({ raw: undefined, data: decodedData }),
      artifactDid: ARTIFACT_DID,
      provider: mockProvider,
      chainId: CHAIN_ID,
      responsibilityClaimSchemaString: SCHEMA_STRING,
    });

    expect(result.valid).toBe(true);
    expect(mockDecodeAttestationData).not.toHaveBeenCalled();
  });

  it("returns failed result when no attestation data available", async () => {
    const result = await verifyResponsibilityClaim({
      attestation: makeAttestation({ raw: undefined, data: {} }),
      artifactDid: ARTIFACT_DID,
      provider: mockProvider,
      chainId: CHAIN_ID,
      responsibilityClaimSchemaString: SCHEMA_STRING,
    });

    // data is {}, which is truthy and typeof object — the function should try to
    // extract fields and fail because required fields are missing
    expect(result.valid).toBe(false);
  });

  it("handles getControllerAuthorization throwing an error", async () => {
    mockGetControllerAuthorization.mockRejectedValue(new Error("network timeout"));

    const result = await verifyResponsibilityClaim({
      attestation: makeAttestation(),
      artifactDid: ARTIFACT_DID,
      provider: mockProvider,
      chainId: CHAIN_ID,
      responsibilityClaimSchemaString: SCHEMA_STRING,
    });

    expect(result.valid).toBe(false);
    expect(result.checks.controllerAuthorized).toBe(false);
    expect(result.checks.issuedDuringAuthorizationWindow).toBe(false);
    expect(result.reasons).toContainEqual(
      expect.stringContaining("Controller authorization check failed")
    );
  });

  it("sets issuedDuringAuthorizationWindow to true when anchoredFrom is null (live-only)", async () => {
    mockGetControllerAuthorization.mockResolvedValue(
      makeAuthorization({ authorized: true, anchoredFrom: null })
    );

    const result = await verifyResponsibilityClaim({
      attestation: makeAttestation(),
      artifactDid: ARTIFACT_DID,
      provider: mockProvider,
      chainId: CHAIN_ID,
      responsibilityClaimSchemaString: SCHEMA_STRING,
    });

    expect(result.valid).toBe(true);
    expect(result.checks.issuedDuringAuthorizationWindow).toBe(true);
  });

  it("passes chain parameter to getControllerAuthorization", async () => {
    await verifyResponsibilityClaim({
      attestation: makeAttestation(),
      artifactDid: ARTIFACT_DID,
      provider: mockProvider,
      chainId: CHAIN_ID,
      chain: "eip155:1",
      responsibilityClaimSchemaString: SCHEMA_STRING,
    });

    expect(mockGetControllerAuthorization).toHaveBeenCalledWith(
      expect.objectContaining({ chain: "eip155:1" })
    );
  });

  it("defaults chain to eip155:{chainId} when not provided", async () => {
    await verifyResponsibilityClaim({
      attestation: makeAttestation(),
      artifactDid: ARTIFACT_DID,
      provider: mockProvider,
      chainId: CHAIN_ID,
      responsibilityClaimSchemaString: SCHEMA_STRING,
    });

    expect(mockGetControllerAuthorization).toHaveBeenCalledWith(
      expect.objectContaining({ chain: `eip155:${CHAIN_ID}` })
    );
  });
});

// ---------------------------------------------------------------------------
// getVerifiedArtifactAttestations — Unit Tests
// ---------------------------------------------------------------------------

describe("getVerifiedArtifactAttestations", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockParseArtifactDid.mockReturnValue({ did: ARTIFACT_DID });
    mockDecodeAttestationData.mockReturnValue(makeDecodedClaim());
    mockGetControllerAuthorization.mockResolvedValue(makeAuthorization());
    mockListAttestations.mockResolvedValue([]);
    mockVerifyAttestation.mockResolvedValue({
      valid: true,
      checks: { revocation: true, expiration: true },
      reasons: [],
    });
  });

  it("returns all-empty arrays when no attestations exist", async () => {
    mockListAttestations.mockResolvedValue([]);

    const result = await getVerifiedArtifactAttestations({
      artifactDid: ARTIFACT_DID,
      provider: mockProvider,
      easContractAddress: EAS_CONTRACT,
      chainId: CHAIN_ID,
      schemaUids: [RESPONSIBILITY_CLAIM_UID],
      responsibilityClaimSchemaUid: RESPONSIBILITY_CLAIM_UID,
      responsibilityClaimSchemaString: SCHEMA_STRING,
    });

    expect(result.artifactDid).toBe(ARTIFACT_DID);
    expect(result.responsibilityClaims).toEqual([]);
    expect(result.securityAssessments).toEqual([]);
    expect(result.certifications).toEqual([]);
    expect(result.otherAttestations).toEqual([]);
  });

  it("returns all-empty arrays when schemaUids is empty", async () => {
    const result = await getVerifiedArtifactAttestations({
      artifactDid: ARTIFACT_DID,
      provider: mockProvider,
      easContractAddress: EAS_CONTRACT,
      chainId: CHAIN_ID,
      schemaUids: [],
      responsibilityClaimSchemaUid: RESPONSIBILITY_CLAIM_UID,
      responsibilityClaimSchemaString: SCHEMA_STRING,
    });

    expect(result.responsibilityClaims).toEqual([]);
    expect(mockListAttestations).not.toHaveBeenCalled();
  });

  it("correctly groups attestations by schema", async () => {
    const responsibilityAtt = makeAttestation({ schema: RESPONSIBILITY_CLAIM_UID });
    const securityAtt = makeAttestation({
      schema: SECURITY_ASSESSMENT_UID,
      uid: ("0x" + "e1".repeat(32)) as Hex,
    });
    const certAtt = makeAttestation({
      schema: CERTIFICATION_UID,
      uid: ("0x" + "e2".repeat(32)) as Hex,
    });
    const otherAtt = makeAttestation({
      schema: ("0x" + "ff".repeat(32)) as Hex,
      uid: ("0x" + "e3".repeat(32)) as Hex,
    });

    mockListAttestations.mockResolvedValue([
      responsibilityAtt,
      securityAtt,
      certAtt,
      otherAtt,
    ]);

    const result = await getVerifiedArtifactAttestations({
      artifactDid: ARTIFACT_DID,
      provider: mockProvider,
      easContractAddress: EAS_CONTRACT,
      chainId: CHAIN_ID,
      schemaUids: [
        RESPONSIBILITY_CLAIM_UID,
        SECURITY_ASSESSMENT_UID,
        CERTIFICATION_UID,
      ],
      responsibilityClaimSchemaUid: RESPONSIBILITY_CLAIM_UID,
      responsibilityClaimSchemaString: SCHEMA_STRING,
      securityAssessmentSchemaUid: SECURITY_ASSESSMENT_UID,
      certificationSchemaUid: CERTIFICATION_UID,
    });

    expect(result.responsibilityClaims).toHaveLength(1);
    expect(result.securityAssessments).toHaveLength(1);
    expect(result.certifications).toHaveLength(1);
    expect(result.otherAttestations).toHaveLength(1);
  });

  it("verifies responsibility claims and runs standard verification on others", async () => {
    const responsibilityAtt = makeAttestation({ schema: RESPONSIBILITY_CLAIM_UID });
    const securityAtt = makeAttestation({
      schema: SECURITY_ASSESSMENT_UID,
      uid: ("0x" + "e1".repeat(32)) as Hex,
    });

    mockListAttestations.mockResolvedValue([responsibilityAtt, securityAtt]);

    const result = await getVerifiedArtifactAttestations({
      artifactDid: ARTIFACT_DID,
      provider: mockProvider,
      easContractAddress: EAS_CONTRACT,
      chainId: CHAIN_ID,
      schemaUids: [RESPONSIBILITY_CLAIM_UID, SECURITY_ASSESSMENT_UID],
      responsibilityClaimSchemaUid: RESPONSIBILITY_CLAIM_UID,
      responsibilityClaimSchemaString: SCHEMA_STRING,
      securityAssessmentSchemaUid: SECURITY_ASSESSMENT_UID,
    });

    // Responsibility claim gets deep verification
    expect(result.responsibilityClaims[0].verification.checks).toBeDefined();
    expect(result.responsibilityClaims[0].verification.controllerDid).toBeDefined();

    // Security assessment gets standard verification
    expect(mockVerifyAttestation).toHaveBeenCalled();
    expect(result.securityAssessments[0].verification).toBeDefined();
  });

  it("throws when artifactDid is invalid", async () => {
    mockParseArtifactDid.mockImplementation(() => {
      throw new Error("Expected a did:artifact DID");
    });

    await expect(
      getVerifiedArtifactAttestations({
        artifactDid: "invalid-did",
        provider: mockProvider,
        easContractAddress: EAS_CONTRACT,
        chainId: CHAIN_ID,
        schemaUids: [RESPONSIBILITY_CLAIM_UID],
        responsibilityClaimSchemaUid: RESPONSIBILITY_CLAIM_UID,
        responsibilityClaimSchemaString: SCHEMA_STRING,
      })
    ).rejects.toThrow("Expected a did:artifact DID");
  });

  it("returns empty responsibilityClaims when only non-responsibility attestations exist", async () => {
    const securityAtt = makeAttestation({ schema: SECURITY_ASSESSMENT_UID });
    mockListAttestations.mockResolvedValue([securityAtt]);

    const result = await getVerifiedArtifactAttestations({
      artifactDid: ARTIFACT_DID,
      provider: mockProvider,
      easContractAddress: EAS_CONTRACT,
      chainId: CHAIN_ID,
      schemaUids: [RESPONSIBILITY_CLAIM_UID, SECURITY_ASSESSMENT_UID],
      responsibilityClaimSchemaUid: RESPONSIBILITY_CLAIM_UID,
      responsibilityClaimSchemaString: SCHEMA_STRING,
      securityAssessmentSchemaUid: SECURITY_ASSESSMENT_UID,
    });

    expect(result.responsibilityClaims).toEqual([]);
    expect(result.securityAssessments).toHaveLength(1);
  });

  it("handles verifyAttestation failure gracefully for non-responsibility attestations", async () => {
    const otherAtt = makeAttestation({
      schema: ("0x" + "ff".repeat(32)) as Hex,
    });
    mockListAttestations.mockResolvedValue([otherAtt]);
    mockVerifyAttestation.mockRejectedValue(new Error("boom"));

    const result = await getVerifiedArtifactAttestations({
      artifactDid: ARTIFACT_DID,
      provider: mockProvider,
      easContractAddress: EAS_CONTRACT,
      chainId: CHAIN_ID,
      schemaUids: [RESPONSIBILITY_CLAIM_UID],
      responsibilityClaimSchemaUid: RESPONSIBILITY_CLAIM_UID,
      responsibilityClaimSchemaString: SCHEMA_STRING,
    });

    expect(result.otherAttestations).toHaveLength(1);
    expect(result.otherAttestations[0].verification).toBeUndefined();
  });

  it("passes limit and fromBlock to listAttestations", async () => {
    mockListAttestations.mockResolvedValue([]);

    await getVerifiedArtifactAttestations({
      artifactDid: ARTIFACT_DID,
      provider: mockProvider,
      easContractAddress: EAS_CONTRACT,
      chainId: CHAIN_ID,
      schemaUids: [RESPONSIBILITY_CLAIM_UID],
      responsibilityClaimSchemaUid: RESPONSIBILITY_CLAIM_UID,
      responsibilityClaimSchemaString: SCHEMA_STRING,
      limit: 50,
      fromBlock: 1000,
    });

    expect(mockListAttestations).toHaveBeenCalledWith(
      expect.objectContaining({
        subjectDid: ARTIFACT_DID,
        limit: 50,
        fromBlock: 1000,
      })
    );
  });
});

// ---------------------------------------------------------------------------
// isArtifactClaimedBy — Unit Tests
// ---------------------------------------------------------------------------

describe("isArtifactClaimedBy", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockParseArtifactDid.mockReturnValue({ did: ARTIFACT_DID });
    mockDecodeAttestationData.mockReturnValue(makeDecodedClaim());
    mockGetControllerAuthorization.mockResolvedValue(makeAuthorization());
    mockListAttestations.mockResolvedValue([]);
    mockVerifyAttestation.mockResolvedValue({
      valid: true,
      checks: {},
      reasons: [],
    });
  });

  it("returns claimed: true when responsible party has valid claim", async () => {
    const att = makeAttestation({ schema: RESPONSIBILITY_CLAIM_UID });
    mockListAttestations.mockResolvedValue([att]);

    const result = await isArtifactClaimedBy({
      artifactDid: ARTIFACT_DID,
      responsibleParty: "did:web:example.com",
      provider: mockProvider,
      easContractAddress: EAS_CONTRACT,
      chainId: CHAIN_ID,
      schemaUids: [RESPONSIBILITY_CLAIM_UID],
      responsibilityClaimSchemaUid: RESPONSIBILITY_CLAIM_UID,
      responsibilityClaimSchemaString: SCHEMA_STRING,
    });

    expect(result.claimed).toBe(true);
    expect(result.claims).toHaveLength(1);
    expect(result.matchedResponsibilityTypes).toEqual(["creator"]);
    expect(result.reasons).toEqual([]);
  });

  it("returns claimed: false when responsible party has no claims", async () => {
    mockListAttestations.mockResolvedValue([]);

    const result = await isArtifactClaimedBy({
      artifactDid: ARTIFACT_DID,
      responsibleParty: "did:web:nobody.com",
      provider: mockProvider,
      easContractAddress: EAS_CONTRACT,
      chainId: CHAIN_ID,
      schemaUids: [RESPONSIBILITY_CLAIM_UID],
      responsibilityClaimSchemaUid: RESPONSIBILITY_CLAIM_UID,
      responsibilityClaimSchemaString: SCHEMA_STRING,
    });

    expect(result.claimed).toBe(false);
    expect(result.claims).toEqual([]);
    expect(result.reasons).toContainEqual(
      expect.stringContaining("No responsibility claims found from")
    );
  });

  it("returns claimed: false when claims exist but verification fails", async () => {
    const att = makeAttestation({ schema: RESPONSIBILITY_CLAIM_UID });
    mockListAttestations.mockResolvedValue([att]);
    mockGetControllerAuthorization.mockResolvedValue(
      makeAuthorization({ authorized: false })
    );

    const result = await isArtifactClaimedBy({
      artifactDid: ARTIFACT_DID,
      responsibleParty: "did:web:example.com",
      provider: mockProvider,
      easContractAddress: EAS_CONTRACT,
      chainId: CHAIN_ID,
      schemaUids: [RESPONSIBILITY_CLAIM_UID],
      responsibilityClaimSchemaUid: RESPONSIBILITY_CLAIM_UID,
      responsibilityClaimSchemaString: SCHEMA_STRING,
    });

    expect(result.claimed).toBe(false);
    expect(result.reasons).toContainEqual(
      expect.stringContaining("none passed verification")
    );
  });

  it("filters by responsibilityTypes when specified", async () => {
    mockDecodeAttestationData.mockReturnValue(
      makeDecodedClaim({ responsibilityType: ["creator"] })
    );
    const att = makeAttestation({ schema: RESPONSIBILITY_CLAIM_UID });
    mockListAttestations.mockResolvedValue([att]);

    const result = await isArtifactClaimedBy({
      artifactDid: ARTIFACT_DID,
      responsibleParty: "did:web:example.com",
      provider: mockProvider,
      easContractAddress: EAS_CONTRACT,
      chainId: CHAIN_ID,
      schemaUids: [RESPONSIBILITY_CLAIM_UID],
      responsibilityClaimSchemaUid: RESPONSIBILITY_CLAIM_UID,
      responsibilityClaimSchemaString: SCHEMA_STRING,
      responsibilityTypes: ["auditor"],
    });

    expect(result.claimed).toBe(false);
    expect(result.reasons).toContainEqual(
      expect.stringContaining("No claims matched the requested responsibility types")
    );
  });

  it("returns only matching types when filtering", async () => {
    mockDecodeAttestationData.mockReturnValue(
      makeDecodedClaim({ responsibilityType: ["creator", "maintainer"] })
    );
    const att = makeAttestation({ schema: RESPONSIBILITY_CLAIM_UID });
    mockListAttestations.mockResolvedValue([att]);

    const result = await isArtifactClaimedBy({
      artifactDid: ARTIFACT_DID,
      responsibleParty: "did:web:example.com",
      provider: mockProvider,
      easContractAddress: EAS_CONTRACT,
      chainId: CHAIN_ID,
      schemaUids: [RESPONSIBILITY_CLAIM_UID],
      responsibilityClaimSchemaUid: RESPONSIBILITY_CLAIM_UID,
      responsibilityClaimSchemaString: SCHEMA_STRING,
      responsibilityTypes: ["creator"],
    });

    expect(result.claimed).toBe(true);
    expect(result.matchedResponsibilityTypes).toEqual(["creator"]);
  });

  it("returns multiple claims from same party", async () => {
    const att1 = makeAttestation({
      schema: RESPONSIBILITY_CLAIM_UID,
      uid: ("0x" + "d1".repeat(32)) as Hex,
    });
    const att2 = makeAttestation({
      schema: RESPONSIBILITY_CLAIM_UID,
      uid: ("0x" + "d2".repeat(32)) as Hex,
    });
    mockListAttestations.mockResolvedValue([att1, att2]);

    const result = await isArtifactClaimedBy({
      artifactDid: ARTIFACT_DID,
      responsibleParty: "did:web:example.com",
      provider: mockProvider,
      easContractAddress: EAS_CONTRACT,
      chainId: CHAIN_ID,
      schemaUids: [RESPONSIBILITY_CLAIM_UID],
      responsibilityClaimSchemaUid: RESPONSIBILITY_CLAIM_UID,
      responsibilityClaimSchemaString: SCHEMA_STRING,
    });

    expect(result.claimed).toBe(true);
    expect(result.claims).toHaveLength(2);
  });

  it("performs case-insensitive responsible party matching", async () => {
    const att = makeAttestation({ schema: RESPONSIBILITY_CLAIM_UID });
    mockListAttestations.mockResolvedValue([att]);

    const result = await isArtifactClaimedBy({
      artifactDid: ARTIFACT_DID,
      responsibleParty: "DID:WEB:EXAMPLE.COM",
      provider: mockProvider,
      easContractAddress: EAS_CONTRACT,
      chainId: CHAIN_ID,
      schemaUids: [RESPONSIBILITY_CLAIM_UID],
      responsibilityClaimSchemaUid: RESPONSIBILITY_CLAIM_UID,
      responsibilityClaimSchemaString: SCHEMA_STRING,
    });

    expect(result.claimed).toBe(true);
  });

  it("deduplicates matched responsibility types across multiple claims", async () => {
    // Both claims have "creator" — should only appear once in matchedTypes
    const att1 = makeAttestation({
      schema: RESPONSIBILITY_CLAIM_UID,
      uid: ("0x" + "d1".repeat(32)) as Hex,
    });
    const att2 = makeAttestation({
      schema: RESPONSIBILITY_CLAIM_UID,
      uid: ("0x" + "d2".repeat(32)) as Hex,
    });
    mockListAttestations.mockResolvedValue([att1, att2]);

    const result = await isArtifactClaimedBy({
      artifactDid: ARTIFACT_DID,
      responsibleParty: "did:web:example.com",
      provider: mockProvider,
      easContractAddress: EAS_CONTRACT,
      chainId: CHAIN_ID,
      schemaUids: [RESPONSIBILITY_CLAIM_UID],
      responsibilityClaimSchemaUid: RESPONSIBILITY_CLAIM_UID,
      responsibilityClaimSchemaString: SCHEMA_STRING,
    });

    expect(result.matchedResponsibilityTypes).toEqual(["creator"]);
  });
});
