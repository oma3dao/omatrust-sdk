/**
 * x402 EIP-712 Verification — Phase 5b
 *
 * Verifies x402 signed offer and receipt artifacts using EIP-712 typed data signatures.
 *
 * EIP-712 is the simpler verification path: the signer address is recovered directly
 * from the signature using ethers verifyTypedData. There is no DID URL resolution or
 * JWK handling — the recovered address is the verification output.
 *
 * EIP-712 verification is NOT authorization. It only proves the signature is valid
 * and returns the recovered signer address for downstream authorization checks.
 */

import { verifyTypedData, getAddress } from "ethers";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** x402 EIP-712 artifact envelope */
export interface X402Eip712Artifact {
  format: "eip712";
  payload: Record<string, unknown>;
  signature: string;
}

/** Successful EIP-712 verification result */
export interface Eip712VerificationResult {
  valid: true;
  /** Decoded payload from the artifact */
  payload: Record<string, unknown>;
  /** Recovered signer address (checksummed) */
  signer: string;
  /** Whether this is an offer or receipt */
  artifactType: "offer" | "receipt";
}

/** Failed EIP-712 verification result */
export interface Eip712VerificationFailure {
  valid: false;
  error: { code: string; message: string };
  payload?: Record<string, unknown>;
  signer?: string;
}

// ---------------------------------------------------------------------------
// Canonical EIP-712 Definitions
// ---------------------------------------------------------------------------

/**
 * Canonical EIP-712 domain for x402 offers.
 * Per the x402 Offer and Receipt Extension spec:
 * - chainId is hardcoded to 1 (off-chain signing format)
 * - The payment network is identified by the `network` field in the payload
 */
const OFFER_DOMAIN = {
  name: "x402 offer",
  version: "1",
  chainId: 1,
} as const;

/**
 * Canonical EIP-712 domain for x402 receipts.
 */
const RECEIPT_DOMAIN = {
  name: "x402 receipt",
  version: "1",
  chainId: 1,
} as const;

/**
 * Canonical EIP-712 types for x402 offers.
 * These are normative and MUST NOT be transmitted on the wire.
 */
const OFFER_TYPES = {
  Offer: [
    { name: "version", type: "uint256" },
    { name: "resourceUrl", type: "string" },
    { name: "scheme", type: "string" },
    { name: "network", type: "string" },
    { name: "asset", type: "string" },
    { name: "payTo", type: "string" },
    { name: "amount", type: "string" },
    { name: "validUntil", type: "uint256" },
  ],
} as const;

/**
 * Canonical EIP-712 types for x402 receipts.
 * These are normative and MUST NOT be transmitted on the wire.
 */
const RECEIPT_TYPES = {
  Receipt: [
    { name: "version", type: "uint256" },
    { name: "network", type: "string" },
    { name: "resourceUrl", type: "string" },
    { name: "payer", type: "string" },
    { name: "issuedAt", type: "uint256" },
    { name: "transaction", type: "string" },
  ],
} as const;

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

function failure(
  code: string,
  message: string,
  partial?: Partial<Eip712VerificationFailure>
): Eip712VerificationFailure {
  return {
    valid: false,
    error: { code, message },
    ...partial,
  };
}

// ---------------------------------------------------------------------------
// Core EIP-712 Verification
// ---------------------------------------------------------------------------

/**
 * Prepare the EIP-712 message from the artifact payload.
 *
 * For EIP-712, all fields must be present (fixed schema).
 * Optional fields use zero-values when absent:
 * - validUntil: 0 means absent
 * - transaction: "" means absent
 */
function prepareOfferMessage(payload: Record<string, unknown>): Record<string, unknown> {
  return {
    version: payload.version,
    resourceUrl: payload.resourceUrl,
    scheme: payload.scheme,
    network: payload.network,
    asset: payload.asset,
    payTo: payload.payTo,
    amount: payload.amount,
    validUntil: payload.validUntil ?? 0,
  };
}

function prepareReceiptMessage(payload: Record<string, unknown>): Record<string, unknown> {
  return {
    version: payload.version,
    network: payload.network,
    resourceUrl: payload.resourceUrl,
    payer: payload.payer,
    issuedAt: payload.issuedAt,
    transaction: payload.transaction ?? "",
  };
}

/**
 * Verify an x402 EIP-712 artifact (offer or receipt).
 *
 * This is the core verification function. It:
 * 1. Validates the artifact envelope (format, payload, signature)
 * 2. Validates payload shape for the artifact type
 * 3. Constructs EIP-712 typed data using canonical domain and types
 * 4. Verifies signature and recovers signer address
 * 5. Returns structured result with recovered signer
 *
 * @param artifact - The x402 EIP-712 artifact envelope
 * @param artifactType - Whether this is an "offer" or "receipt"
 * @returns Eip712VerificationResult on success, Eip712VerificationFailure on failure
 */
export function verifyX402Eip712Artifact(
  artifact: X402Eip712Artifact,
  artifactType: "offer" | "receipt"
): Eip712VerificationResult | Eip712VerificationFailure {
  // Validate artifact envelope
  if (!artifact || typeof artifact !== "object") {
    return failure("INVALID_ARTIFACT", "Artifact must be a non-null object");
  }
  if (artifact.format !== "eip712") {
    return failure("INVALID_ARTIFACT", `Expected format "eip712", got "${artifact.format}"`);
  }
  if (!artifact.payload || typeof artifact.payload !== "object" || Array.isArray(artifact.payload)) {
    return failure("MISSING_PAYLOAD", "EIP-712 artifact must include a payload object");
  }
  if (typeof artifact.signature !== "string" || artifact.signature.length === 0) {
    return failure("MISSING_SIGNATURE", "EIP-712 artifact must include a non-empty signature");
  }

  const payload = artifact.payload;

  // Validate payload shape
  if (artifactType === "offer") {
    const check = validateOfferPayload(payload);
    if (!check.valid) {
      return failure(
        "INVALID_OFFER_PAYLOAD",
        `Missing required offer field: ${check.field}`,
        { payload }
      );
    }
  } else {
    const check = validateReceiptPayload(payload);
    if (!check.valid) {
      return failure(
        "INVALID_RECEIPT_PAYLOAD",
        `Missing required receipt field: ${check.field}`,
        { payload }
      );
    }
  }

  // Select domain, types, and prepare message
  const domain = artifactType === "offer" ? OFFER_DOMAIN : RECEIPT_DOMAIN;
  const types = artifactType === "offer" ? OFFER_TYPES : RECEIPT_TYPES;
  const message =
    artifactType === "offer"
      ? prepareOfferMessage(payload)
      : prepareReceiptMessage(payload);

  // Verify signature and recover signer
  let signer: string;
  try {
    signer = verifyTypedData(
      domain,
      types as unknown as Record<string, Array<{ name: string; type: string }>>,
      message,
      artifact.signature
    );
    signer = getAddress(signer);
  } catch (err) {
    const message = err instanceof Error ? err.message : "EIP-712 signature verification failed";
    return failure("SIGNATURE_INVALID", message, { payload });
  }

  return {
    valid: true,
    payload,
    signer,
    artifactType,
  };
}

// ---------------------------------------------------------------------------
// Offer Verification
// ---------------------------------------------------------------------------

/**
 * Verify an x402 EIP-712 offer artifact.
 *
 * Recovers the signer address and validates that the payload contains
 * required offer fields: version, resourceUrl, scheme, network, asset, payTo, amount.
 *
 * @param artifact - The x402 EIP-712 artifact envelope
 * @returns Eip712VerificationResult on success, Eip712VerificationFailure on failure
 */
export function verifyX402Eip712Offer(
  artifact: X402Eip712Artifact
): Eip712VerificationResult | Eip712VerificationFailure {
  return verifyX402Eip712Artifact(artifact, "offer");
}

// ---------------------------------------------------------------------------
// Receipt Verification
// ---------------------------------------------------------------------------

/**
 * Verify an x402 EIP-712 receipt artifact.
 *
 * Recovers the signer address and validates that the payload contains
 * required receipt fields: version, network, resourceUrl, payer, issuedAt.
 *
 * @param artifact - The x402 EIP-712 artifact envelope
 * @returns Eip712VerificationResult on success, Eip712VerificationFailure on failure
 */
export function verifyX402Eip712Receipt(
  artifact: X402Eip712Artifact
): Eip712VerificationResult | Eip712VerificationFailure {
  return verifyX402Eip712Artifact(artifact, "receipt");
}
