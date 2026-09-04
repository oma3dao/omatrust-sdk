/**
 * Dependency-free DID utilities.
 *
 * This module contains pure string-based DID parsing, normalization, and
 * construction functions that do NOT depend on ethers or any heavy runtime.
 *
 * Consumers who only need normalization / parsing (e.g. the MPAS Credential
 * Adapter) can import from "@oma3/omatrust/identity/did" to avoid pulling
 * in ethers (18 MB).
 *
 * For hashing and address derivation, import from "@oma3/omatrust/identity"
 * which re-exports everything including the ethers-dependent functions.
 */

import { base64url } from "jose";
import { OmaTrustError } from "../shared/errors";
import { assertString } from "../shared/assert";
import { parseCaip10 } from "./caip";
import { validatePublicJwk } from "./jwk";

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
  // Strip DID URL fragment (#...) — fragments are not part of the DID itself (W3C DID Core §3.5)
  const trimmed = input.trim().split("#")[0];

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

export function computeDidAddress(didHash: Hex): Hex {
  assertString(didHash, "didHash", "INVALID_DID");
  if (!/^0x[0-9a-fA-F]{64}$/.test(didHash)) {
    throw new OmaTrustError("INVALID_DID", "didHash must be 32-byte hex", { didHash });
  }

  // Spec: low-order 160 bits of didHash, serialized as lowercase 0x-hex.
  return `0x${didHash.slice(-40).toLowerCase()}` as Hex;
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

export function parseDidPkh(did: Did): { namespace: string; chainId: string; address: string } | null {
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

// ---------------------------------------------------------------------------
// did:jwk normalization (depends on jose, not ethers)
// ---------------------------------------------------------------------------

// Base64url character set (no padding required)
const BASE64URL_REGEX = /^[A-Za-z0-9_-]+$/;

const VALID_JWK_KTY = new Set(["EC", "OKP", "RSA"]);

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
export function validateDidJwk(did: string): { valid: boolean; method: "jwk"; error?: string } {
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

  // Validate required public key fields per kty (crv/x/y for EC, crv/x for OKP, n/e for RSA)
  const jwkValidation = validatePublicJwk(jwk);
  if (!jwkValidation.valid) {
    return { valid: false, method: "jwk", error: jwkValidation.error };
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
