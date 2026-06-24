/**
 * did:artifact — Content-Addressed DID Method
 *
 * Implements construction, parsing, and verification for the did:artifact DID method.
 * A did:artifact DID names an immutable byte sequence by its SHA-256 content hash,
 * encoded as a CIDv1 with raw multicodec and base32-lower multibase.
 *
 * Construction:
 *   - artifactDidFromBytes: hash raw bytes (binary artifacts)
 *   - artifactDidFromJson: canonicalize JSON then hash (JSON artifacts)
 *
 * Verification:
 *   - verifyDidArtifact: verify content matches a did:artifact DID
 *     (tries canonical JSON first, then raw bytes)
 *
 * Spec: https://oma3dao.github.io/omatrust-docs/specification/did-artifact-method-spec.html
 */

import { CID } from "multiformats/cid";
import { sha256 } from "multiformats/hashes/sha2";
import * as raw from "multiformats/codecs/raw";
import { base32 } from "multiformats/bases/base32";
import { OmaTrustError } from "../shared/errors";
import { canonicalizeJson, parseJsonStrict } from "./data";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** Parsed components of a did:artifact DID */
export interface ParsedArtifactDid {
  /** The full DID string */
  did: string;
  /** The method-specific identifier (base32-encoded CIDv1) */
  identifier: string;
  /** The SHA-256 digest as a Uint8Array (32 bytes) */
  digest: Uint8Array;
  /** The SHA-256 digest as lowercase hex */
  digestHex: string;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const DID_ARTIFACT_PREFIX = "did:artifact:";

/** Expected binary CID length: 1 (version) + 1 (codec) + 2 (multihash header) + 32 (digest) */
const EXPECTED_CID_BYTES = 36;

/** CID version 1 */
const CID_VERSION = 1;

/** Multicodec for raw (0x55) */
const RAW_CODEC = raw.code; // 0x55

/** Multihash function code for sha2-256 (0x12) */
const SHA2_256_CODE = 0x12;

/** Expected digest length for SHA-256 */
const SHA2_256_DIGEST_LENGTH = 32;

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------

/**
 * Construct a did:artifact DID from raw bytes.
 *
 * Use this when the artifact is a binary blob (installer, archive, image, etc.)
 * where no canonicalization is needed. The bytes are hashed as-is.
 *
 * @param bytes - The artifact's raw octets
 * @returns The did:artifact DID string
 * @throws OmaTrustError if bytes is empty or not a Uint8Array
 */
export async function artifactDidFromBytes(bytes: Uint8Array): Promise<string> {
  if (!(bytes instanceof Uint8Array) || bytes.length === 0) {
    throw new OmaTrustError(
      "INVALID_INPUT",
      "bytes must be a non-empty Uint8Array"
    );
  }

  const digest = await sha256.digest(bytes);
  const cid = CID.createV1(RAW_CODEC, digest);
  return `${DID_ARTIFACT_PREFIX}${cid.toString(base32)}`;
}

/**
 * Construct a did:artifact DID from a JSON value.
 *
 * The input is canonicalized using JCS (RFC 8785), then the canonical UTF-8 bytes
 * are hashed with SHA-256. If the input is a string, it is parsed strictly
 * (rejecting duplicate keys, non-JSON-safe values, etc.) before canonicalization.
 *
 * Use this when the artifact is a JSON document and you want identity based on
 * the JSON *value* rather than the exact serialization.
 *
 * @param input - A parsed JSON value (object/array/primitive) or a JSON string
 * @returns The did:artifact DID string
 * @throws OmaTrustError if canonicalization fails (malformed JSON, duplicate keys, etc.)
 */
export async function artifactDidFromJson(input: unknown): Promise<string> {
  // If input is a string, parse it strictly first
  const value = typeof input === "string" ? parseJsonStrict(input) : input;

  // Canonicalize — this validates JSON safety and produces JCS output
  const jcs = canonicalizeJson(value);
  const bytes = new TextEncoder().encode(jcs);

  const digest = await sha256.digest(bytes);
  const cid = CID.createV1(RAW_CODEC, digest);
  return `${DID_ARTIFACT_PREFIX}${cid.toString(base32)}`;
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

/**
 * Parse and validate a did:artifact DID string.
 *
 * Validates:
 * - Correct prefix
 * - Valid base32-lower multibase encoding
 * - CID version 1
 * - Multicodec is raw (0x55)
 * - Multihash function is sha2-256 (0x12) with 32-byte digest
 *
 * @param did - The DID string to parse
 * @returns Parsed components including the SHA-256 digest
 * @throws OmaTrustError if the DID is malformed or uses unsupported parameters
 */
export function parseArtifactDid(did: string): ParsedArtifactDid {
  if (typeof did !== "string" || !did.startsWith(DID_ARTIFACT_PREFIX)) {
    throw new OmaTrustError("INVALID_DID", "Expected a did:artifact DID", { did });
  }

  const identifier = did.slice(DID_ARTIFACT_PREFIX.length);
  if (!identifier || identifier.length === 0) {
    throw new OmaTrustError("INVALID_DID", "Missing method-specific identifier", { did });
  }

  // Must start with 'b' (base32lower multibase prefix)
  if (identifier[0] !== "b") {
    throw new OmaTrustError(
      "INVALID_DID",
      `Invalid multibase prefix "${identifier[0]}", expected "b" (base32lower)`,
      { did }
    );
  }

  // Decode the CID from base32
  let cid: CID;
  try {
    cid = CID.parse(identifier, base32);
  } catch (err) {
    throw new OmaTrustError(
      "INVALID_DID",
      "Failed to decode base32 CID from did:artifact identifier",
      { did, cause: err }
    );
  }

  // Validate CID version
  if (cid.version !== CID_VERSION) {
    throw new OmaTrustError(
      "INVALID_DID",
      `CID version must be 1, got ${cid.version}`,
      { did }
    );
  }

  // Validate multicodec (raw = 0x55)
  if (cid.code !== RAW_CODEC) {
    throw new OmaTrustError(
      "INVALID_DID",
      `Multicodec must be raw (0x55), got 0x${cid.code.toString(16)}`,
      { did }
    );
  }

  // Validate multihash function (sha2-256 = 0x12)
  if (cid.multihash.code !== SHA2_256_CODE) {
    throw new OmaTrustError(
      "INVALID_DID",
      `Multihash function must be sha2-256 (0x12), got 0x${cid.multihash.code.toString(16)}`,
      { did }
    );
  }

  // Validate digest length
  if (cid.multihash.digest.length !== SHA2_256_DIGEST_LENGTH) {
    throw new OmaTrustError(
      "INVALID_DID",
      `SHA-256 digest must be 32 bytes, got ${cid.multihash.digest.length}`,
      { did }
    );
  }

  const digest = cid.multihash.digest;
  const digestHex = Array.from(digest)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");

  return { did, identifier, digest, digestHex };
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

/** Result of artifact verification */
export interface ArtifactVerificationResult {
  /** Whether the content matches the DID */
  valid: boolean;
  /** Which interpretation matched: "json" if canonical JSON matched, "binary" if raw bytes matched */
  matchedAs?: "json" | "binary";
  /** Error reason when valid is false */
  reason?: string;
}

/**
 * Verify that content matches a did:artifact DID.
 *
 * Verification strategy:
 * 1. Try to interpret the content as JSON: parse strictly, canonicalize, hash, compare.
 * 2. If JSON interpretation fails or doesn't match, hash the raw bytes and compare.
 * 3. If either matches, verification succeeds.
 *
 * This dual approach is necessary because the verifier doesn't know which path
 * (artifactDidFromJson vs artifactDidFromBytes) was used at construction time.
 *
 * @param did - The did:artifact DID to verify against
 * @param content - The candidate content (Uint8Array for binary, or string/object for JSON)
 * @returns Verification result indicating whether and how the content matched
 */
export async function verifyDidArtifact(
  did: string,
  content: Uint8Array | string | unknown
): Promise<ArtifactVerificationResult> {
  // Parse and validate the DID
  let parsed: ParsedArtifactDid;
  try {
    parsed = parseArtifactDid(did);
  } catch (err) {
    return {
      valid: false,
      reason: err instanceof OmaTrustError ? err.message : "Invalid did:artifact DID",
    };
  }

  const expectedHex = parsed.digestHex;

  // Strategy 1: Try JSON canonicalization
  if (typeof content === "string" || (typeof content === "object" && content !== null && !(content instanceof Uint8Array))) {
    try {
      const value = typeof content === "string" ? parseJsonStrict(content) : content;
      const jcs = canonicalizeJson(value);
      const jcsBytes = new TextEncoder().encode(jcs);
      const digest = await sha256.digest(jcsBytes);
      const digestHex = Array.from(digest.digest)
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");

      if (digestHex === expectedHex) {
        return { valid: true, matchedAs: "json" };
      }
    } catch {
      // JSON canonicalization failed — fall through to binary
    }
  }

  // Strategy 2: Try raw bytes
  let rawBytes: Uint8Array;
  if (content instanceof Uint8Array) {
    rawBytes = content;
  } else if (typeof content === "string") {
    rawBytes = new TextEncoder().encode(content);
  } else {
    // For objects that didn't match as JSON, we can't try binary
    return {
      valid: false,
      reason: "Content did not match as canonical JSON and is not raw bytes",
    };
  }

  const digest = await sha256.digest(rawBytes);
  const digestHex = Array.from(digest.digest)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");

  if (digestHex === expectedHex) {
    return { valid: true, matchedAs: "binary" };
  }

  return {
    valid: false,
    reason: "Content does not match the did:artifact identifier (neither as canonical JSON nor as raw bytes)",
  };
}
