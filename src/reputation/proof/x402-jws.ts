/**
 * x402 JWS Verification — Phase 5
 *
 * Verifies x402 signed offer and receipt artifacts using JWS Compact Serialization.
 *
 * Two verification paths:
 * 1. Embedded JWK: header contains `jwk` → validate, verify signature, derive did:jwk
 * 2. KID Resolution: header contains `kid` (no `jwk`) → resolve DID URL → verify → derive did:jwk
 *
 * If both `kid` and `jwk` are present and the resolved key conflicts with the
 * embedded key, verification fails.
 *
 * JWS verification is NOT authorization. It only proves the signature is valid
 * and returns the did:jwk for downstream authorization checks.
 */

import { compactVerify, decodeProtectedHeader, importJWK } from "jose";
import { OmaTrustError } from "../../shared/errors";
import {
  validatePublicJwk,
  jwkToDidJwk,
  publicJwkEquals,
  type PublicJwk,
} from "../../identity/jwk";
import {
  resolveDidUrlToPublicKey,
  type ResolveKeyOptions,
} from "../../identity/resolve-key";
import type {
  JwsVerificationResult,
  JwsVerificationFailure,
  PublicKeySource,
} from "../../identity/types";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** x402 JWS artifact envelope */
export interface X402JwsArtifact {
  format: "jws";
  signature: string;
}

/** Options for x402 JWS verification */
export interface X402JwsVerifyOptions {
  /**
   * Options for DID URL key resolution (used when kid is present).
   * Pass a custom fetchDidDocument for testing or non-standard resolution.
   */
  resolveOptions?: ResolveKeyOptions;
}

// ---------------------------------------------------------------------------
// Payload Validation
// ---------------------------------------------------------------------------

const REQUIRED_OFFER_FIELDS = [
  "version",
  "resourceUrl",
  "scheme",
  "network",
  "asset",
  "payTo",
  "amount",
] as const;

const REQUIRED_RECEIPT_FIELDS = [
  "version",
  "network",
  "resourceUrl",
  "payer",
  "issuedAt",
] as const;

function validateOfferPayload(
  payload: Record<string, unknown>
): { valid: true } | { valid: false; field: string } {
  for (const field of REQUIRED_OFFER_FIELDS) {
    if (!(field in payload) || payload[field] === undefined || payload[field] === null) {
      return { valid: false, field };
    }
  }
  return { valid: true };
}

function validateReceiptPayload(
  payload: Record<string, unknown>
): { valid: true } | { valid: false; field: string } {
  for (const field of REQUIRED_RECEIPT_FIELDS) {
    if (!(field in payload) || payload[field] === undefined || payload[field] === null) {
      return { valid: false, field };
    }
  }
  return { valid: true };
}

// ---------------------------------------------------------------------------
// Failure Helper
// ---------------------------------------------------------------------------

function failure(code: string, message: string, partial?: Partial<JwsVerificationFailure>): JwsVerificationFailure {
  return {
    valid: false,
    error: { code, message },
    ...partial,
  };
}

// ---------------------------------------------------------------------------
// Core JWS Verification
// ---------------------------------------------------------------------------

/**
 * Verify an x402 JWS artifact (offer or receipt).
 *
 * This is the core verification function. It:
 * 1. Parses the compact JWS
 * 2. Decodes the protected header
 * 3. Requires `alg` and at least one of `kid` or `jwk`
 * 4. Selects the public key (embedded jwk or resolved kid)
 * 5. Verifies the JWS signature
 * 6. Derives did:jwk from the verified public key
 * 7. Returns a structured result
 *
 * Does NOT validate payload shape — use verifyX402JwsOffer or verifyX402JwsReceipt
 * for payload validation.
 *
 * @param artifact - The x402 JWS artifact envelope
 * @param options - Optional verification options (resolver config, etc.)
 * @returns JwsVerificationResult on success, JwsVerificationFailure on failure
 */
export async function verifyX402JwsArtifact(
  artifact: X402JwsArtifact,
  options?: X402JwsVerifyOptions
): Promise<JwsVerificationResult | JwsVerificationFailure> {
  // Validate artifact envelope
  if (!artifact || typeof artifact !== "object") {
    return failure("INVALID_ARTIFACT", "Artifact must be a non-null object");
  }
  if (artifact.format !== "jws") {
    return failure("INVALID_ARTIFACT", `Expected format "jws", got "${artifact.format}"`);
  }
  if (typeof artifact.signature !== "string" || artifact.signature.length === 0) {
    return failure("INVALID_ARTIFACT", "Artifact signature must be a non-empty string");
  }

  const compactJws = artifact.signature;

  // Validate compact JWS structure (must have 3 dot-separated parts)
  const parts = compactJws.split(".");
  if (parts.length !== 3) {
    return failure("MALFORMED_JWS", "Invalid compact JWS format: expected 3 dot-separated parts");
  }

  // Decode protected header
  let header: Record<string, unknown>;
  try {
    header = decodeProtectedHeader(compactJws) as Record<string, unknown>;
  } catch {
    return failure("MALFORMED_JWS", "Failed to decode JWS protected header");
  }

  // Require alg
  if (!header.alg || typeof header.alg !== "string") {
    return failure("MISSING_ALG", "JWS header must include alg", { header });
  }

  // Require at least one of kid or jwk
  const kid = typeof header.kid === "string" ? header.kid : null;
  const embeddedJwk = header.jwk as Record<string, unknown> | undefined;

  if (!kid && !embeddedJwk) {
    return failure(
      "MISSING_KEY_MATERIAL",
      "JWS header must include at least one of kid or jwk",
      { header }
    );
  }

  // Determine public key and source
  let publicKeyJwk: PublicJwk;
  let publicKeySource: PublicKeySource;

  if (embeddedJwk) {
    // Embedded JWK path
    const validation = validatePublicJwk(embeddedJwk);
    if (!validation.valid) {
      return failure(
        "INVALID_EMBEDDED_JWK",
        `Embedded JWK is invalid: ${validation.error}`,
        { header }
      );
    }

    publicKeyJwk = embeddedJwk as PublicJwk;
    publicKeySource = "embedded-jwk";

    // If kid is also present, resolve and check for conflict
    if (kid) {
      try {
        const resolved = await resolveDidUrlToPublicKey(kid, options?.resolveOptions);
        if (!publicJwkEquals(publicKeyJwk, resolved.publicKeyJwk)) {
          return failure(
            "KEY_CONFLICT",
            "Embedded jwk conflicts with public key resolved from kid",
            { header, kid }
          );
        }
      } catch (err) {
        // If kid resolution fails but we have embedded jwk, we can still verify
        // with the embedded key. Only fail if the resolution succeeded but keys conflict.
        // Per spec: "the SDK may resolve kid if configured" — resolution failure
        // is not fatal when jwk is present.
      }
    }
  } else {
    // KID resolution path — kid must be present (guaranteed by earlier check)
    publicKeySource = "kid-resolution";
    try {
      const resolved = await resolveDidUrlToPublicKey(kid!, options?.resolveOptions);
      publicKeyJwk = resolved.publicKeyJwk;
    } catch (err) {
      const message =
        err instanceof OmaTrustError
          ? `Failed to resolve kid "${kid}": ${err.message}`
          : `Failed to resolve kid "${kid}"`;
      return failure("KID_RESOLUTION_FAILED", message, { header, kid });
    }
  }

  // Verify JWS signature
  let payload: Record<string, unknown>;
  try {
    const key = await importJWK(publicKeyJwk as Parameters<typeof importJWK>[0], header.alg as string);
    const result = await compactVerify(compactJws, key);

    // Decode payload
    const payloadText = new TextDecoder().decode(result.payload);
    payload = JSON.parse(payloadText) as Record<string, unknown>;
  } catch (err) {
    const message = err instanceof Error ? err.message : "Signature verification failed";
    return failure("SIGNATURE_INVALID", message, { header, kid });
  }

  // Derive did:jwk
  const publicKeyDid = jwkToDidJwk(publicKeyJwk);

  return {
    valid: true,
    header,
    payload,
    kid,
    publicKeyJwk,
    publicKeySource,
    publicKeyDid,
  };
}

// ---------------------------------------------------------------------------
// Offer Verification
// ---------------------------------------------------------------------------

/**
 * Verify an x402 JWS offer artifact.
 *
 * Performs full JWS signature verification and validates that the payload
 * contains required offer fields: version, resourceUrl, scheme, network,
 * asset, payTo, amount.
 *
 * @param artifact - The x402 JWS artifact envelope
 * @param options - Optional verification options
 * @returns JwsVerificationResult on success, JwsVerificationFailure on failure
 */
export async function verifyX402JwsOffer(
  artifact: X402JwsArtifact,
  options?: X402JwsVerifyOptions
): Promise<JwsVerificationResult | JwsVerificationFailure> {
  const result = await verifyX402JwsArtifact(artifact, options);
  if (!result.valid) return result;

  const payloadCheck = validateOfferPayload(result.payload);
  if (!payloadCheck.valid) {
    return failure(
      "INVALID_OFFER_PAYLOAD",
      `Missing required offer field: ${payloadCheck.field}`,
      {
        header: result.header,
        payload: result.payload,
        kid: result.kid,
        publicKeyJwk: result.publicKeyJwk,
        publicKeySource: result.publicKeySource,
        publicKeyDid: result.publicKeyDid,
      }
    );
  }

  return result;
}

// ---------------------------------------------------------------------------
// Receipt Verification
// ---------------------------------------------------------------------------

/**
 * Verify an x402 JWS receipt artifact.
 *
 * Performs full JWS signature verification and validates that the payload
 * contains required receipt fields: version, network, resourceUrl, payer,
 * issuedAt.
 *
 * @param artifact - The x402 JWS artifact envelope
 * @param options - Optional verification options
 * @returns JwsVerificationResult on success, JwsVerificationFailure on failure
 */
export async function verifyX402JwsReceipt(
  artifact: X402JwsArtifact,
  options?: X402JwsVerifyOptions
): Promise<JwsVerificationResult | JwsVerificationFailure> {
  const result = await verifyX402JwsArtifact(artifact, options);
  if (!result.valid) return result;

  const payloadCheck = validateReceiptPayload(result.payload);
  if (!payloadCheck.valid) {
    return failure(
      "INVALID_RECEIPT_PAYLOAD",
      `Missing required receipt field: ${payloadCheck.field}`,
      {
        header: result.header,
        payload: result.payload,
        kid: result.kid,
        publicKeyJwk: result.publicKeyJwk,
        publicKeySource: result.publicKeySource,
        publicKeyDid: result.publicKeyDid,
      }
    );
  }

  return result;
}
