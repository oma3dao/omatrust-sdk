/**
 * JWK and did:jwk Helpers — Phase 2
 *
 * Provides conversion between public JWKs and did:jwk DIDs,
 * deterministic JWK comparison, and public JWK validation.
 *
 * did:jwk is the preferred durable DID representation for JWS/JWK public key
 * material. It is immutable (the DID IS the key) and should be used as the
 * controllerDid for authorization checks.
 *
 * Uses the `jose` library for base64url encoding/decoding and JWK thumbprints.
 */

import { base64url, calculateJwkThumbprint } from "jose";
import { OmaTrustError } from "../shared/errors";
import { assertObject } from "../shared/assert";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** Minimal public JWK structure */
export interface PublicJwk {
  kty: string;
  [key: string]: unknown;
}

/** Result of JWK validation */
export interface JwkValidationResult {
  valid: boolean;
  error?: string;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const VALID_KTY = new Set(["EC", "OKP", "RSA"]);

/** Private key fields that must not appear in a public JWK */
const PRIVATE_KEY_FIELDS = new Set(["d", "p", "q", "dp", "dq", "qi", "oth"]);

/**
 * Required public key fields per key type.
 * Used for structural validation.
 */
const REQUIRED_PUBLIC_FIELDS: Record<string, string[]> = {
  EC: ["crv", "x", "y"],
  OKP: ["crv", "x"],
  RSA: ["n", "e"],
};

// ---------------------------------------------------------------------------
// Public JWK Validation
// ---------------------------------------------------------------------------

/**
 * Validate that a JWK object is a well-formed public key.
 *
 * Requirements:
 * - Must be a non-null object
 * - Must have a valid `kty` (EC, OKP, RSA)
 * - Must have required public key fields for its key type
 * - Must NOT contain private key material (d, p, q, dp, dq, qi, oth)
 */
export function validatePublicJwk(jwk: unknown): JwkValidationResult {
  if (!jwk || typeof jwk !== "object" || Array.isArray(jwk)) {
    return { valid: false, error: "JWK must be a non-null object" };
  }

  const obj = jwk as Record<string, unknown>;

  // Check kty
  const kty = obj.kty;
  if (typeof kty !== "string" || !VALID_KTY.has(kty)) {
    return {
      valid: false,
      error: `Invalid or missing kty (must be one of: ${[...VALID_KTY].join(", ")})`,
    };
  }

  // Reject private key material
  for (const field of PRIVATE_KEY_FIELDS) {
    if (field in obj) {
      return {
        valid: false,
        error: `JWK contains private key field "${field}" — only public keys are allowed`,
      };
    }
  }

  // Check required public fields
  const required = REQUIRED_PUBLIC_FIELDS[kty];
  if (required) {
    for (const field of required) {
      if (!(field in obj) || obj[field] === undefined || obj[field] === null || obj[field] === "") {
        return {
          valid: false,
          error: `Missing required public key field "${field}" for kty="${kty}"`,
        };
      }
    }
  }

  return { valid: true };
}

// ---------------------------------------------------------------------------
// did:jwk Conversion
// ---------------------------------------------------------------------------

/**
 * Deterministic JSON serialization for JWK.
 * Keys are sorted alphabetically to ensure canonical encoding.
 */
function canonicalizeJwkJson(jwk: Record<string, unknown>): string {
  const sorted = Object.keys(jwk).sort();
  const obj: Record<string, unknown> = {};
  for (const key of sorted) {
    obj[key] = jwk[key];
  }
  return JSON.stringify(obj);
}

/**
 * Convert a public JWK to a did:jwk DID.
 *
 * Uses deterministic (sorted-key) JSON serialization and base64url encoding.
 * Rejects JWKs containing private key material.
 *
 * @param jwk - A public JWK object
 * @returns The did:jwk DID string
 * @throws OmaTrustError if the JWK is invalid or contains private key material
 */
export function jwkToDidJwk(jwk: unknown): string {
  assertObject(jwk, "jwk", "INVALID_JWK");

  const validation = validatePublicJwk(jwk);
  if (!validation.valid) {
    throw new OmaTrustError("INVALID_JWK", validation.error ?? "Invalid public JWK", { jwk });
  }

  const canonical = canonicalizeJwkJson(jwk as Record<string, unknown>);
  const encoded = base64url.encode(new TextEncoder().encode(canonical));
  return `did:jwk:${encoded}`;
}

/**
 * Convert a did:jwk DID back to a public JWK object.
 *
 * Validates the DID structure, decodes the base64url payload,
 * parses JSON, and validates the resulting JWK.
 *
 * @param didJwk - A did:jwk DID string
 * @returns The decoded public JWK object
 * @throws OmaTrustError if the DID is malformed or contains private key material
 */
export function didJwkToJwk(didJwk: string): PublicJwk {
  if (typeof didJwk !== "string" || !didJwk.startsWith("did:jwk:")) {
    throw new OmaTrustError("INVALID_DID", "Expected a did:jwk DID", { input: didJwk });
  }

  const parts = didJwk.split(":");
  if (parts.length !== 3) {
    throw new OmaTrustError("INVALID_DID", "did:jwk must have exactly 3 colon-separated parts", {
      input: didJwk,
    });
  }

  const encoded = parts[2];
  if (!encoded || encoded.length === 0) {
    throw new OmaTrustError("INVALID_DID", "Missing base64url-encoded JWK identifier", {
      input: didJwk,
    });
  }

  // Decode using jose base64url
  let decoded: string;
  try {
    const bytes = base64url.decode(encoded);
    decoded = new TextDecoder().decode(bytes);
  } catch {
    throw new OmaTrustError("INVALID_DID", "Failed to base64url-decode did:jwk identifier", {
      input: didJwk,
    });
  }

  let jwk: Record<string, unknown>;
  try {
    jwk = JSON.parse(decoded);
  } catch {
    throw new OmaTrustError("INVALID_DID", "Decoded did:jwk identifier is not valid JSON", {
      input: didJwk,
    });
  }

  if (!jwk || typeof jwk !== "object" || Array.isArray(jwk)) {
    throw new OmaTrustError("INVALID_DID", "Decoded did:jwk must be a JSON object", {
      input: didJwk,
    });
  }

  // Validate as public JWK
  const validation = validatePublicJwk(jwk);
  if (!validation.valid) {
    throw new OmaTrustError("INVALID_DID", validation.error ?? "Invalid public JWK in did:jwk", {
      input: didJwk,
    });
  }

  return jwk as PublicJwk;
}

// ---------------------------------------------------------------------------
// Public JWK Comparison
// ---------------------------------------------------------------------------

/**
 * Extract only the public key fields from a JWK for comparison purposes.
 * Strips private fields and non-key metadata (kid, use, key_ops, alg, ext).
 */
function extractPublicKeyFields(jwk: Record<string, unknown>): Record<string, unknown> {
  const result: Record<string, unknown> = {};
  const metadataFields = new Set(["kid", "use", "key_ops", "alg", "ext"]);

  for (const [key, value] of Object.entries(jwk)) {
    if (PRIVATE_KEY_FIELDS.has(key)) continue;
    if (metadataFields.has(key)) continue;
    result[key] = value;
  }

  return result;
}

/**
 * Compare two public JWKs for equality.
 *
 * Compares only the public key material fields (kty, crv, x, y, n, e, etc.).
 * Ignores property order, metadata fields (kid, use, alg, key_ops, ext),
 * and rejects/strips private key fields before comparison.
 *
 * @param a - First public JWK
 * @param b - Second public JWK
 * @returns true if both JWKs represent the same public key
 * @throws OmaTrustError if either JWK contains private key material
 */
export function publicJwkEquals(a: unknown, b: unknown): boolean {
  assertObject(a, "a", "INVALID_JWK");
  assertObject(b, "b", "INVALID_JWK");

  const aObj = a as Record<string, unknown>;
  const bObj = b as Record<string, unknown>;

  // Reject if either contains private key material
  for (const field of PRIVATE_KEY_FIELDS) {
    if (field in aObj) {
      throw new OmaTrustError(
        "INVALID_JWK",
        `First JWK contains private key field "${field}"`,
        { field }
      );
    }
    if (field in bObj) {
      throw new OmaTrustError(
        "INVALID_JWK",
        `Second JWK contains private key field "${field}"`,
        { field }
      );
    }
  }

  const aPublic = extractPublicKeyFields(aObj);
  const bPublic = extractPublicKeyFields(bObj);

  // Compare via canonical JSON
  return canonicalizeJwkJson(aPublic) === canonicalizeJwkJson(bPublic);
}


// ---------------------------------------------------------------------------
// JWK Thumbprint (RFC 7638)
// ---------------------------------------------------------------------------

/**
 * Compute an RFC 7638 JWK Thumbprint for a public JWK.
 *
 * Returns the base64url-encoded SHA-256 thumbprint. This is a compact,
 * deterministic fingerprint of the public key material.
 *
 * Used in OMATrust DNS TXT records as: `jkt=S256:<thumbprint>`
 *
 * @param jwk - A public JWK object
 * @param digestAlgorithm - Hash algorithm (default: "sha256")
 * @returns base64url-encoded thumbprint string
 * @throws OmaTrustError if the JWK is invalid or contains private key material
 */
export async function computeJwkThumbprint(
  jwk: unknown,
  digestAlgorithm: "sha256" | "sha384" | "sha512" = "sha256"
): Promise<string> {
  assertObject(jwk, "jwk", "INVALID_JWK");

  const validation = validatePublicJwk(jwk);
  if (!validation.valid) {
    throw new OmaTrustError("INVALID_JWK", validation.error ?? "Invalid public JWK", { jwk });
  }

  // jose's calculateJwkThumbprint expects a JWK-like object and a digest algorithm
  const alg = digestAlgorithm === "sha256" ? "sha256"
    : digestAlgorithm === "sha384" ? "sha384"
    : "sha512";

  return calculateJwkThumbprint(jwk as Parameters<typeof calculateJwkThumbprint>[0], alg);
}

/**
 * Format a JWK thumbprint as an OMATrust DNS TXT `jkt` value.
 *
 * Format: `jkt=S256:<base64url-thumbprint>`
 *
 * @param jwk - A public JWK object
 * @returns Formatted jkt string for DNS TXT records
 */
export async function formatJktValue(jwk: unknown): Promise<string> {
  const thumbprint = await computeJwkThumbprint(jwk, "sha256");
  return `jkt=S256:${thumbprint}`;
}
