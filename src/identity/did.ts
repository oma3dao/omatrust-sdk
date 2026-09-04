/**
 * DID utilities — full surface including ethers-dependent hashing/address functions.
 *
 * Re-exports everything from ./did-core (ethers-free) plus the ethers-dependent
 * functions for hashing DDOs, deriving addresses, and deep EVM validation.
 *
 * If you only need normalization/parsing and want to avoid pulling in ethers,
 * import from "@oma3/omatrust/identity/did" instead.
 */

import { getAddress, isAddress, keccak256, toUtf8Bytes } from "ethers";
import { OmaTrustError } from "../shared/errors";
import { assertString } from "../shared/assert";
import { parseCaip10 } from "./caip";

// Import what we need from did-core for internal use
import {
  type Hex,
  type Did,
  normalizeDid,
  normalizeDidPkh,
  extractDidMethod,
  parseDidPkh,
  computeDidAddress,
  validateDidJwk,
} from "./did-core";

// Re-export everything from the ethers-free module
export * from "./did-core";

// ---------------------------------------------------------------------------
// Ethers-dependent: Hashing and address derivation
// ---------------------------------------------------------------------------

export function computeDidHash(did: Did): Hex {
  const normalized = normalizeDid(did);
  return keccak256(toUtf8Bytes(normalized)) as Hex;
}

export function didToAddress(did: Did): Hex {
  return computeDidAddress(computeDidHash(did));
}

export function validateDidAddress(did: Did, address: Hex): boolean {
  try {
    return didToAddress(did).toLowerCase() === String(address).toLowerCase();
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// Ethers-dependent: Address extraction
// ---------------------------------------------------------------------------

/**
 * Extract an EVM address from a DID or address-like identifier.
 *
 * Supports:
 * - did:pkh (extracts the address portion — currently EVM only)
 * - did:ethr (extracts the Ethereum address)
 * - CAIP-10 format (e.g. eip155:1:0xABC)
 * - Raw EVM addresses (0x + 40 hex chars)
 *
 * NOTE: This function is EVM-specific. It does not support non-EVM chains
 * (e.g. Solana, Cosmos). Non-EVM did:pkh identifiers will throw.
 * A future version may generalize to support multiple chain families.
 *
 * @param identifier - A DID, CAIP-10 string, or raw EVM address
 * @returns The checksummed EVM address
 * @throws OmaTrustError if the identifier cannot be resolved to an EVM address
 */
export function extractAddressFromDid(identifier: string): string {
  assertString(identifier, "identifier", "INVALID_DID");

  if (identifier.startsWith("did:pkh:")) {
    const pkh = parseDidPkh(normalizeDidPkh(identifier));
    if (!pkh) {
      throw new OmaTrustError("INVALID_DID", "Invalid did:pkh identifier", { identifier });
    }
    return pkh.address;
  }

  if (identifier.startsWith("did:ethr:")) {
    const parts = identifier.replace("did:ethr:", "").split(":");
    const address = parts.length === 1 ? parts[0] : parts[1];
    if (!address || !isAddress(address)) {
      throw new OmaTrustError("INVALID_DID", "Invalid did:ethr identifier", { identifier });
    }
    return getAddress(address);
  }

  if (identifier.match(/^[a-z0-9-]+:[a-zA-Z0-9-]+:0x[a-fA-F0-9]{40}$/)) {
    const parsed = parseCaip10(identifier);
    return parsed.address;
  }

  if (isAddress(identifier)) {
    return getAddress(identifier);
  }

  throw new OmaTrustError("INVALID_DID", "Unsupported identifier format", { identifier });
}

// ---------------------------------------------------------------------------
// Ethers-dependent: Private-Key DID Validation
// ---------------------------------------------------------------------------

/** Result of private-key DID validation */
export interface PrivateKeyDidValidation {
  valid: boolean;
  method: "pkh" | "jwk" | null;
  error?: string;
}

// CAIP-2 namespace: lowercase alphanumeric + hyphens, 3-8 chars per spec
const CAIP2_NAMESPACE_REGEX = /^[a-z0-9-]{3,8}$/;

/**
 * Check if a DID uses a private-key method (can sign transactions/messages).
 * Quick boolean check — use validatePrivateKeyDid() for detailed errors.
 */
export function isPrivateKeyDid(did: string): boolean {
  return validatePrivateKeyDid(did).valid;
}

/**
 * Validate that a DID is a well-formed private-key DID.
 * Returns detailed validation result with method identification and error messages.
 *
 * Supported methods:
 * - did:pkh — CAIP-10 blockchain account (deep validation for eip155)
 * - did:jwk — JSON Web Key (structural validation)
 */
export function validatePrivateKeyDid(did: string): PrivateKeyDidValidation {
  if (typeof did !== "string" || did.trim().length === 0) {
    return { valid: false, method: null, error: "DID must be a non-empty string" };
  }

  const trimmed = did.trim();
  const method = extractDidMethod(trimmed);

  switch (method) {
    case "pkh":
      return validateDidPkh(trimmed);
    case "jwk":
      return validateDidJwk(trimmed);
    default:
      return {
        valid: false,
        method: null,
        error: method
          ? `DID method "${method}" is not a recognized private-key method`
          : "Invalid DID format"
      };
  }
}

/**
 * Validate a did:pkh DID with deep EVM address validation.
 */
function validateDidPkh(did: string): PrivateKeyDidValidation {
  const parts = did.split(":");
  if (parts.length !== 5) {
    return {
      valid: false,
      method: "pkh",
      error: `did:pkh must have exactly 5 colon-separated parts, got ${parts.length}`
    };
  }

  const [, , namespace, chainId, address] = parts;

  if (!namespace) {
    return { valid: false, method: "pkh", error: "Missing namespace" };
  }

  if (!CAIP2_NAMESPACE_REGEX.test(namespace)) {
    return {
      valid: false,
      method: "pkh",
      error: `Invalid CAIP-2 namespace "${namespace}" (must be 3-8 lowercase alphanumeric/hyphen chars)`
    };
  }

  if (!chainId) {
    return { valid: false, method: "pkh", error: "Missing chain ID (reference)" };
  }

  if (!address) {
    return { valid: false, method: "pkh", error: "Missing address" };
  }

  // Deep validation for eip155 (EVM) namespace
  if (namespace === "eip155") {
    // Chain ID should be numeric for eip155
    if (!/^\d+$/.test(chainId)) {
      return {
        valid: false,
        method: "pkh",
        error: `Invalid eip155 chain ID "${chainId}" (must be numeric)`
      };
    }

    // Address must be a valid EVM address
    if (!isAddress(address)) {
      return {
        valid: false,
        method: "pkh",
        error: `Invalid EVM address "${address}" (must be 0x + 40 hex chars)`
      };
    }
  }

  // Deep validation for solana namespace
  if (namespace === "solana") {
    // Solana addresses are base58-encoded public keys, 32-44 characters
    if (!/^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(address)) {
      return {
        valid: false,
        method: "pkh",
        error: `Invalid Solana address "${address}" (must be 32-44 base58 characters)`
      };
    }
  }

  return { valid: true, method: "pkh" };
}
