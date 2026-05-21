import { getAddress, isAddress, keccak256, toUtf8Bytes } from "ethers";
import { base64url } from "jose";
import { OmaTrustError } from "../shared/errors";
import { assertString } from "../shared/assert";
import { parseCaip10 } from "./caip";

export type Hex = `0x${string}`;
export type Did = string;

const DID_REGEX = /^did:[a-z0-9]+:.+$/i;

export function isValidDid(did: string): boolean {
  return DID_REGEX.test(did);
}

export function extractDidMethod(did: Did): string | null {
  const match = did.match(/^did:([a-z0-9]+):/i);
  return match ? match[1] : null;
}

export function extractDidIdentifier(did: Did): string | null {
  const match = did.match(/^did:[a-z0-9]+:(.+)$/i);
  return match ? match[1] : null;
}

export function normalizeDomain(domain: string): string {
  assertString(domain, "domain", "INVALID_DID");
  return domain.trim().toLowerCase().replace(/\.$/, "").replace(/^www\./, "");
}

export function normalizeDidWeb(input: string): Did {
  assertString(input, "input", "INVALID_DID");
  const trimmed = input.trim();

  if (trimmed.startsWith("did:") && !trimmed.startsWith("did:web:")) {
    throw new OmaTrustError("INVALID_DID", "Expected did:web DID", { input });
  }

  const identifier = trimmed.startsWith("did:web:")
    ? trimmed.slice("did:web:".length)
    : trimmed;

  const [host, ...pathParts] = identifier.split("/");
  if (!host) {
    throw new OmaTrustError("INVALID_DID", "Invalid did:web identifier", { input });
  }

  const normalizedHost = normalizeDomain(host);
  const path = pathParts.length > 0 ? `/${pathParts.join("/")}` : "";
  return `did:web:${normalizedHost}${path}`;
}

export function normalizeDidPkh(input: string): Did {
  assertString(input, "input", "INVALID_DID");
  const trimmed = input.trim();
  if (!trimmed.startsWith("did:pkh:")) {
    throw new OmaTrustError("INVALID_DID", "Expected did:pkh DID", { input });
  }

  const parts = trimmed.split(":");
  if (parts.length !== 5) {
    throw new OmaTrustError("INVALID_DID", "Invalid did:pkh format", { input });
  }

  const [, , namespace, chainId, address] = parts;
  if (!namespace || !chainId || !address) {
    throw new OmaTrustError("INVALID_DID", "Invalid did:pkh components", { input });
  }

  return `did:pkh:${namespace.toLowerCase()}:${chainId}:${address.toLowerCase()}`;
}

export function normalizeDidHandle(input: string): Did {
  assertString(input, "input", "INVALID_DID");
  const trimmed = input.trim();
  if (!trimmed.startsWith("did:handle:")) {
    throw new OmaTrustError("INVALID_DID", "Expected did:handle DID", { input });
  }

  const parts = trimmed.split(":");
  if (parts.length !== 4) {
    throw new OmaTrustError("INVALID_DID", "Invalid did:handle format", { input });
  }

  const [, , platform, username] = parts;
  if (!platform || !username) {
    throw new OmaTrustError("INVALID_DID", "Invalid did:handle components", { input });
  }

  return `did:handle:${platform.toLowerCase()}:${username}`;
}

export function normalizeDidKey(input: string): Did {
  assertString(input, "input", "INVALID_DID");
  const trimmed = input.trim();
  if (!trimmed.startsWith("did:key:")) {
    throw new OmaTrustError("INVALID_DID", "Expected did:key DID", { input });
  }

  return trimmed;
}

export function normalizeDid(input: string): Did {
  assertString(input, "input", "INVALID_DID");
  const trimmed = input.trim();

  if (!trimmed.startsWith("did:")) {
    return normalizeDidWeb(trimmed);
  }

  if (!isValidDid(trimmed)) {
    throw new OmaTrustError("INVALID_DID", "Invalid DID format", { input });
  }

  const method = extractDidMethod(trimmed);
  switch (method) {
    case "web":
      return normalizeDidWeb(trimmed);
    case "pkh":
      return normalizeDidPkh(trimmed);
    case "handle":
      return normalizeDidHandle(trimmed);
    case "key":
      return normalizeDidKey(trimmed);
    case "jwk":
      return normalizeDidJwk(trimmed);
    default:
      return trimmed;
  }
}

export function computeDidHash(did: Did): Hex {
  const normalized = normalizeDid(did);
  return keccak256(toUtf8Bytes(normalized)) as Hex;
}

export function computeDidAddress(didHash: Hex): Hex {
  assertString(didHash, "didHash", "INVALID_DID");
  if (!/^0x[0-9a-fA-F]{64}$/.test(didHash)) {
    throw new OmaTrustError("INVALID_DID", "didHash must be 32-byte hex", { didHash });
  }

  // Spec: low-order 160 bits of didHash, serialized as lowercase 0x-hex.
  return `0x${didHash.slice(-40).toLowerCase()}` as Hex;
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

export function buildDidWeb(domain: string): Did {
  return `did:web:${normalizeDomain(domain)}`;
}

export function buildDidPkh(
  namespace: string,
  chainId: string | number,
  address: string
): Did {
  assertString(namespace, "namespace", "INVALID_DID");
  assertString(address, "address", "INVALID_DID");
  if (chainId === "" || chainId === null || chainId === undefined) {
    throw new OmaTrustError("INVALID_DID", "chainId is required", { chainId });
  }
  return `did:pkh:${namespace.toLowerCase()}:${chainId}:${address.toLowerCase()}`;
}

export function buildEvmDidPkh(chainId: string | number, address: string): Did {
  return buildDidPkh("eip155", chainId, address);
}

export function buildDidPkhFromCaip10(caip10: string): Did {
  const parsed = parseCaip10(caip10);
  return buildDidPkh(parsed.namespace, parsed.reference, parsed.address);
}

function parseDidPkh(did: Did): { namespace: string; chainId: string; address: string } | null {
  if (!did.startsWith("did:pkh:")) {
    return null;
  }

  const parts = did.split(":");
  if (parts.length !== 5) {
    return null;
  }

  const [, , namespace, chainId, address] = parts;
  if (!namespace || !chainId || !address) {
    return null;
  }

  return { namespace, chainId, address };
}

export function getChainIdFromDidPkh(did: Did): string | null {
  return parseDidPkh(did)?.chainId ?? null;
}

export function getAddressFromDidPkh(did: Did): string | null {
  return parseDidPkh(did)?.address ?? null;
}

export function getNamespaceFromDidPkh(did: Did): string | null {
  return parseDidPkh(did)?.namespace ?? null;
}

export function isEvmDidPkh(did: Did): boolean {
  return getNamespaceFromDidPkh(did) === "eip155";
}

export function getDomainFromDidWeb(did: Did): string | null {
  if (!did.startsWith("did:web:")) {
    return null;
  }

  const identifier = did.slice("did:web:".length);
  const [domain] = identifier.split("/");
  return domain || null;
}

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
// Private-Key DID Validation
// ---------------------------------------------------------------------------

/** Result of private-key DID validation */
export interface PrivateKeyDidValidation {
  valid: boolean;
  method: "pkh" | "jwk" | null;
  error?: string;
}

// CAIP-2 namespace: lowercase alphanumeric + hyphens, 3-8 chars per spec
const CAIP2_NAMESPACE_REGEX = /^[a-z0-9-]{3,8}$/;

// Base64url character set (no padding required)
const BASE64URL_REGEX = /^[A-Za-z0-9_-]+$/;

const VALID_JWK_KTY = new Set(["EC", "OKP", "RSA"]);

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
 * Validate a did:pkh DID.
 *
 * Format: did:pkh:<namespace>:<chainId>:<address>
 * - Must have exactly 5 colon-separated parts
 * - namespace must be a valid CAIP-2 namespace (lowercase alphanumeric + hyphens, 3-8 chars)
 * - chainId must be non-empty
 * - address must be non-empty
 * - For eip155 namespace: address must be a valid EVM address (0x + 40 hex chars)
 * - For other namespaces: address must be non-empty (permissive fallback)
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

  return { valid: true, method: "pkh" };
}

/**
 * Validate a did:jwk DID.
 *
 * Format: did:jwk:<base64url-encoded-JWK>
 * - Must have exactly 3 colon-separated parts
 * - Identifier must be valid base64url
 * - Decoded value must be valid JSON
 * - Decoded JSON must contain a valid kty field (EC, OKP, RSA)
 * - Must NOT contain d (private key component)
 */
function validateDidJwk(did: string): PrivateKeyDidValidation {
  const parts = did.split(":");
  if (parts.length !== 3) {
    return {
      valid: false,
      method: "jwk",
      error: `did:jwk must have exactly 3 colon-separated parts, got ${parts.length}`
    };
  }

  const [, , encoded] = parts;

  if (!encoded || encoded.length === 0) {
    return { valid: false, method: "jwk", error: "Missing base64url-encoded JWK identifier" };
  }

  if (!BASE64URL_REGEX.test(encoded)) {
    return {
      valid: false,
      method: "jwk",
      error: "Identifier contains invalid base64url characters"
    };
  }

  // Decode base64url to JSON
  let decoded: string;
  try {
    const bytes = base64url.decode(encoded);
    decoded = new TextDecoder().decode(bytes);
  } catch {
    return { valid: false, method: "jwk", error: "Failed to base64url-decode identifier" };
  }

  let jwk: Record<string, unknown>;
  try {
    jwk = JSON.parse(decoded);
  } catch {
    return { valid: false, method: "jwk", error: "Decoded identifier is not valid JSON" };
  }

  if (!jwk || typeof jwk !== "object" || Array.isArray(jwk)) {
    return { valid: false, method: "jwk", error: "Decoded JWK must be a JSON object" };
  }

  // Must have kty
  const kty = jwk.kty;
  if (typeof kty !== "string" || !VALID_JWK_KTY.has(kty)) {
    return {
      valid: false,
      method: "jwk",
      error: `Invalid or missing kty field (must be one of: EC, OKP, RSA)`
    };
  }

  // Must NOT contain private key material
  if ("d" in jwk) {
    return {
      valid: false,
      method: "jwk",
      error: "DID must reference a public key — private key component (d) is not allowed"
    };
  }

  return { valid: true, method: "jwk" };
}

/**
 * Normalize a did:jwk DID.
 * Validates structure and returns the DID unchanged (did:jwk is already canonical).
 */
export function normalizeDidJwk(input: string): Did {
  assertString(input, "input", "INVALID_DID");
  const trimmed = input.trim();
  if (!trimmed.startsWith("did:jwk:")) {
    throw new OmaTrustError("INVALID_DID", "Expected did:jwk DID", { input });
  }

  const result = validateDidJwk(trimmed);
  if (!result.valid) {
    throw new OmaTrustError("INVALID_DID", result.error ?? "Invalid did:jwk", { input });
  }

  return trimmed;
}
