/**
 * Unified x402 Artifact Verification
 *
 * Auto-detects format (JWS or EIP-712) and artifact type (offer or receipt),
 * then delegates to the appropriate verifier.
 *
 * This is the recommended entry point for callers who receive an x402 artifact
 * and don't want to branch on format themselves.
 */

import {
  verifyX402JwsOffer,
  verifyX402JwsReceipt,
  verifyX402JwsArtifact,
  type X402JwsArtifact,
  type X402JwsVerifyOptions,
} from "./x402-jws";
import {
  verifyX402Eip712Offer,
  verifyX402Eip712Receipt,
  type X402Eip712Artifact,
  type Eip712VerificationResult,
  type Eip712VerificationFailure,
} from "./x402-eip712";
import type {
  JwsVerificationResult,
  JwsVerificationFailure,
} from "../../identity/types";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** Any x402 artifact envelope (JWS or EIP-712) */
export type X402Artifact = X402JwsArtifact | X402Eip712Artifact | { format: string; [key: string]: unknown };

/** Options for unified x402 verification */
export interface VerifyX402Options {
  /**
   * Artifact type: "offer" or "receipt".
   * Required so the verifier knows which payload fields to validate.
   */
  artifactType: "offer" | "receipt";

  /**
   * Options for JWS DID URL key resolution (only used for JWS format with kid).
   */
  resolveOptions?: X402JwsVerifyOptions["resolveOptions"];
}

/** Successful result from unified verification */
export type X402VerificationSuccess = JwsVerificationResult | Eip712VerificationResult;

/** Failed result from unified verification */
export type X402VerificationFailure = JwsVerificationFailure | Eip712VerificationFailure;

/** Result from unified verification */
export type X402VerificationResult = X402VerificationSuccess | X402VerificationFailure;

// ---------------------------------------------------------------------------
// Unified Verification
// ---------------------------------------------------------------------------

/**
 * Verify an x402 artifact, auto-detecting format (JWS or EIP-712).
 *
 * This is the recommended single entry point for x402 verification.
 * It inspects the `format` field and delegates to the appropriate verifier.
 *
 * @param artifact - The x402 artifact object (must have a `format` field)
 * @param options - Must specify `artifactType` ("offer" or "receipt")
 * @returns Verification result (success or failure, format-specific)
 *
 * @example
 * ```ts
 * const result = await verifyX402Artifact(receiptFromServer, { artifactType: "receipt" });
 * if (result.valid) {
 *   // JWS: result.publicKeyDid is the did:jwk for authorization
 *   // EIP-712: result.signer is the recovered address
 * }
 * ```
 */
export async function verifyX402Artifact(
  artifact: X402Artifact,
  options: VerifyX402Options
): Promise<X402VerificationResult> {
  if (!artifact || typeof artifact !== "object") {
    return {
      valid: false,
      error: { code: "INVALID_ARTIFACT", message: "Artifact must be a non-null object" },
    };
  }

  const format = (artifact as Record<string, unknown>).format;

  switch (format) {
    case "jws": {
      const jwsArtifact = artifact as X402JwsArtifact;
      const jwsOptions: X402JwsVerifyOptions | undefined = options.resolveOptions
        ? { resolveOptions: options.resolveOptions }
        : undefined;

      if (options.artifactType === "offer") {
        return verifyX402JwsOffer(jwsArtifact, jwsOptions);
      }
      return verifyX402JwsReceipt(jwsArtifact, jwsOptions);
    }

    case "eip712": {
      const eip712Artifact = artifact as X402Eip712Artifact;
      if (options.artifactType === "offer") {
        return verifyX402Eip712Offer(eip712Artifact);
      }
      return verifyX402Eip712Receipt(eip712Artifact);
    }

    default:
      return {
        valid: false,
        error: {
          code: "UNSUPPORTED_FORMAT",
          message: `Unsupported x402 artifact format: "${format}"`,
        },
      };
  }
}
