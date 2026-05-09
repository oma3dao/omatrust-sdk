/**
 * Identity Types — Phase 4
 *
 * Types for JWS verification results and authorization metadata.
 * These define the contract between signature verification and
 * downstream authorization checks via getControllerAuthorization.
 */

import type { PublicJwk } from "./jwk";

// ---------------------------------------------------------------------------
// JWS Verification Result
// ---------------------------------------------------------------------------

/** Source of the public key used for JWS signature verification */
export type PublicKeySource = "embedded-jwk" | "kid-resolution";

/**
 * Structured result of JWS signature verification.
 *
 * This result is NOT an authorization result. It does not determine whether
 * the signing key was authorized to act for the service identified by resourceUrl.
 *
 * It provides enough information for callers to perform downstream authorization
 * checks via getControllerAuthorization:
 * - publicKeyDid (did:jwk) is the durable controller DID
 * - resourceUrl identifies the service subject
 * - issuedAt enables authorization-window checks for receipts
 */
export interface JwsVerificationResult {
  /** Whether the JWS signature is cryptographically valid */
  valid: boolean;

  /** Decoded JWS protected header */
  header: Record<string, unknown>;

  /** Decoded JWS payload */
  payload: Record<string, unknown>;

  /** kid from the JWS header (a key reference, NOT a controller DID) */
  kid: string | null;

  /** The public JWK used for signature verification */
  publicKeyJwk: PublicJwk;

  /** How the public key was obtained */
  publicKeySource: PublicKeySource;

  /**
   * The durable did:jwk derived from the public key.
   * This is the controller DID for downstream authorization checks.
   * Pass this as controllerDid to getControllerAuthorization.
   */
  publicKeyDid: string;

  /** Error details when valid is false */
  error?: JwsVerificationError;
}

/** Error details for failed JWS verification */
export interface JwsVerificationError {
  code: string;
  message: string;
}

/**
 * Failed JWS verification result.
 * Returned when parsing, decoding, or signature verification fails.
 */
export interface JwsVerificationFailure {
  valid: false;
  error: JwsVerificationError;
  header?: Record<string, unknown>;
  payload?: Record<string, unknown>;
  kid?: string | null;
  publicKeyJwk?: PublicJwk;
  publicKeySource?: PublicKeySource;
  publicKeyDid?: string;
}

// ---------------------------------------------------------------------------
// Authorization Metadata
// ---------------------------------------------------------------------------

/**
 * Authorization metadata extracted from a verified x402 artifact.
 *
 * This is the information a caller needs to perform an authorization check
 * after signature verification succeeds (JWS or EIP-712).
 *
 * Usage:
 * 1. Verify artifact → get JwsVerificationResult or Eip712VerificationResult
 * 2. Extract AuthorizationMetadata from the result
 * 3. Call getControllerAuthorization({ subjectDid, controllerDid, purpose })
 * 4. Evaluate the returned authorization window against policy
 */
export interface AuthorizationMetadata {
  /**
   * The durable controller DID derived from the verified key material.
   * - JWS: did:jwk derived from the public key
   * - EIP-712: did:pkh:eip155:1:<signer-address>
   * Pass this as controllerDid to getControllerAuthorization.
   */
  controllerDid: string;

  /**
   * The subject DID derived from resourceUrl.
   * For x402 artifacts, this is typically did:web:<domain-from-resourceUrl>.
   * Pass this as subjectDid to getControllerAuthorization.
   */
  subjectDid: string | null;

  /**
   * The resourceUrl from the signed payload.
   * Identifies the service/resource the artifact is associated with.
   */
  resourceUrl: string | null;

  /**
   * The issuedAt timestamp from the signed payload (receipts).
   * Used for authorization-window checks — was the controller authorized at this time?
   * May be a string (ISO) or number (unix seconds) depending on the payload.
   */
  issuedAt: string | number | null;

  /**
   * The kid from the JWS header (mutable key reference).
   * Useful for key-pinning lookups but NOT a controller DID.
   * Null for EIP-712 artifacts.
   */
  kid: string | null;

  /**
   * The public JWK used for signature verification.
   * Present for JWS artifacts, null for EIP-712.
   */
  publicKeyJwk: PublicJwk | null;

  /**
   * The recovered signer address (checksummed).
   * Present for EIP-712 artifacts, null for JWS.
   */
  signer: string | null;
}

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

/**
 * Input for extractAuthorizationMetadata.
 * Accepts either a JwsVerificationResult or an Eip712VerificationResult.
 */
export type VerificationResultInput =
  | JwsVerificationResult
  | { valid: true; payload: Record<string, unknown>; signer: string; artifactType: string };

/**
 * Extract authorization metadata from a successful verification result.
 *
 * Works with both JWS and EIP-712 verification results:
 * - JWS: controllerDid is did:jwk, publicKeyJwk is populated, kid may be present
 * - EIP-712: controllerDid is did:pkh:eip155:1:<signer>, signer is populated
 *
 * Derives the subject DID from resourceUrl when possible (assumes did:web
 * for HTTPS URLs). Returns null for subjectDid if resourceUrl is missing
 * or cannot be parsed.
 *
 * @param result - A successful verification result (valid === true)
 * @returns Authorization metadata for downstream getControllerAuthorization calls
 */
export function extractAuthorizationMetadata(
  result: VerificationResultInput
): AuthorizationMetadata {
  const payload = result.payload;

  const resourceUrl = typeof payload.resourceUrl === "string" ? payload.resourceUrl : null;
  const issuedAt =
    typeof payload.issuedAt === "string"
      ? payload.issuedAt
      : typeof payload.issuedAt === "number"
        ? payload.issuedAt
        : null;

  // Derive subject DID from resourceUrl
  let subjectDid: string | null = null;
  if (resourceUrl) {
    try {
      const url = new URL(resourceUrl);
      subjectDid = `did:web:${url.hostname}`;
    } catch {
      // Cannot parse URL — leave subjectDid null
    }
  }

  // Detect which result type we have
  if ("publicKeyDid" in result) {
    // JWS result
    const jwsResult = result as JwsVerificationResult;
    return {
      controllerDid: jwsResult.publicKeyDid,
      subjectDid,
      resourceUrl,
      issuedAt,
      kid: jwsResult.kid,
      publicKeyJwk: jwsResult.publicKeyJwk,
      signer: null,
    };
  }

  // EIP-712 result
  const eip712Result = result as { signer: string; payload: Record<string, unknown> };
  const signerAddress = eip712Result.signer.toLowerCase();
  return {
    controllerDid: `did:pkh:eip155:1:${signerAddress}`,
    subjectDid,
    resourceUrl,
    issuedAt,
    kid: null,
    publicKeyJwk: null,
    signer: eip712Result.signer,
  };
}
