/**
 * Controller ID Comparison
 *
 * Determines whether two controller DIDs refer to the same entity.
 * Handles DID normalization and EVM address-based fallback (chain-agnostic).
 */

import { normalizeDid, extractDidMethod, extractAddressFromDid } from "./did";
import { didJwkToJwk, publicJwkEquals } from "./jwk";

/**
 * Check if two controller DIDs refer to the same entity.
 *
 * Matching strategies (tried in order):
 * 1. Exact normalized DID string match
 * 2. EVM address match (chain-agnostic): if both DIDs resolve to the same
 *    EVM address, they match regardless of chain ID. This handles cases like
 *    did:pkh:eip155:1:0xABC matching did:pkh:eip155:137:0xABC.
 * 3. JWK material match: if both are did:jwk, compare the decoded public key
 *    material directly (handles non-canonical encoding differences).
 *
 * @param a - First controller DID
 * @param b - Second controller DID
 * @returns true if both DIDs refer to the same controller
 */
export function isSameControllerId(a: string, b: string): boolean {
  // Strategy 1: Exact normalized DID string match
  let normalizedA: string | null = null;
  let normalizedB: string | null = null;

  try {
    normalizedA = normalizeDid(a);
  } catch {
    // a may not be normalizable
  }

  try {
    normalizedB = normalizeDid(b);
  } catch {
    // b may not be normalizable
  }

  if (normalizedA && normalizedB && normalizedA === normalizedB) {
    return true;
  }

  // Strategy 2: EVM address match (chain-agnostic)
  const evmA = extractControllerEvmAddress(a);
  const evmB = extractControllerEvmAddress(b);

  if (evmA && evmB && evmA.toLowerCase() === evmB.toLowerCase()) {
    return true;
  }

  // Strategy 3: JWK material match (for did:jwk with different encodings)
  const methodA = extractDidMethod(a);
  const methodB = extractDidMethod(b);

  if (methodA === "jwk" && methodB === "jwk") {
    try {
      const jwkA = didJwkToJwk(a);
      const jwkB = didJwkToJwk(b);
      return publicJwkEquals(jwkA, jwkB);
    } catch {
      return false;
    }
  }

  return false;
}

/**
 * Extract an EVM address from a controller DID, if possible.
 * Returns null for non-EVM controllers (did:jwk, non-eip155 did:pkh, etc.)
 */
export function extractControllerEvmAddress(controllerDid: string): string | null {
  try {
    const method = extractDidMethod(controllerDid);
    if (method === "pkh" && controllerDid.includes("eip155")) {
      return extractAddressFromDid(controllerDid);
    }
  } catch {
    // Not extractable
  }
  return null;
}
