/**
 * DID URL Parsing — Phase 1
 *
 * Parses DID URLs (e.g. did:web:api.example.com#key-1) into their components.
 * DID URLs are mutable key references / lookup handles, not durable controller DIDs.
 */

import { OmaTrustError } from "../shared/errors";
import { assertString } from "../shared/assert";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** Parsed DID URL components */
export interface ParsedDidUrl {
  /** The original full DID URL */
  didUrl: string;
  /** The base DID (without fragment) */
  did: string;
  /** The fragment identifier (without the '#'), or null if no fragment */
  fragment: string | null;
}

// ---------------------------------------------------------------------------
// DID URL Parser
// ---------------------------------------------------------------------------

const DID_URL_REGEX = /^did:[a-z0-9]+:.+$/i;

/**
 * Parse a DID URL into its components.
 *
 * A DID URL may include a fragment (e.g. `did:web:api.example.com#key-1`).
 * The fragment identifies a verification method, key reference, or other
 * resource under the DID.
 *
 * DID URLs are mutable key references. They should not be used as durable
 * controller DIDs. Use `resolveDidUrlControllerDid()` to derive a durable
 * `did:jwk` from a DID URL.
 *
 * @param input - A DID URL string
 * @returns Parsed components: didUrl, did, fragment
 * @throws OmaTrustError with code INVALID_DID_URL if input is malformed
 */
export function parseDidUrl(input: string): ParsedDidUrl {
  assertString(input, "input", "INVALID_DID_URL");
  const trimmed = input.trim();

  // Split on first '#' to separate DID from fragment
  const hashIndex = trimmed.indexOf("#");

  let did: string;
  let fragment: string | null;

  if (hashIndex === -1) {
    did = trimmed;
    fragment = null;
  } else {
    did = trimmed.slice(0, hashIndex);
    const rawFragment = trimmed.slice(hashIndex + 1);

    if (rawFragment.length === 0) {
      throw new OmaTrustError(
        "INVALID_DID_URL",
        "DID URL has empty fragment (trailing '#' with no identifier)",
        { input }
      );
    }

    fragment = rawFragment;
  }

  // Validate the base DID portion
  if (!DID_URL_REGEX.test(did)) {
    throw new OmaTrustError(
      "INVALID_DID_URL",
      "Invalid DID URL: base DID portion is malformed",
      { input, did }
    );
  }

  return {
    didUrl: trimmed,
    did,
    fragment,
  };
}

/**
 * Check whether a string is a DID URL (contains a fragment).
 * Useful for guards that need to reject DID URLs where a bare DID is expected.
 */
export function isDidUrl(input: string): boolean {
  if (typeof input !== "string") return false;
  const trimmed = input.trim();
  return trimmed.includes("#") && DID_URL_REGEX.test(trimmed.split("#")[0]);
}

/**
 * Assert that a string is a bare DID (not a DID URL with a fragment).
 * Throws if the input contains a fragment.
 *
 * Use this in functions that expect a subject DID and must reject DID URLs.
 */
export function assertBareDid(input: string, paramName = "did"): void {
  assertString(input, paramName, "INVALID_DID");
  if (isDidUrl(input)) {
    throw new OmaTrustError(
      "INVALID_DID",
      `Expected a bare DID but received a DID URL with a fragment. Use parseDidUrl() to handle DID URLs.`,
      { input }
    );
  }
}
