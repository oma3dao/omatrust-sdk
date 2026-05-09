/**
 * DID URL Key Resolution — Phase 3
 *
 * Resolves DID URL key references (e.g. did:web:api.example.com#key-1) to
 * public key material and derives durable did:jwk controller DIDs.
 *
 * DID URLs are mutable key references. This module resolves them to the
 * actual public key material they currently point to, then converts that
 * material into an immutable did:jwk for use as a controller DID.
 */

import { OmaTrustError } from "../shared/errors";
import { assertString } from "../shared/assert";
import { fetchDidDocument } from "../shared/did-document";
import { parseDidUrl } from "./did-url";
import { extractDidMethod, getDomainFromDidWeb } from "./did";
import { validatePublicJwk, jwkToDidJwk, type PublicJwk } from "./jwk";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** Result of resolving a DID URL to public key material */
export interface ResolvedPublicKey {
  /** The original DID URL */
  didUrl: string;
  /** The base DID (without fragment) */
  did: string;
  /** The fragment identifier */
  fragment: string | null;
  /** The resolved public JWK */
  publicKeyJwk: PublicJwk;
  /** The verification method ID that matched */
  verificationMethodId: string;
}

/** Result of resolving a DID URL to a durable controller DID */
export interface ResolvedControllerDid extends ResolvedPublicKey {
  /** The durable did:jwk derived from the resolved public key */
  controllerDid: string;
}

/** Options for DID URL key resolution */
export interface ResolveKeyOptions {
  /**
   * Custom DID document fetcher. If not provided, uses the shared
   * fetchDidDocument which fetches from `/.well-known/did.json`.
   */
  fetchDidDocument?: (domain: string) => Promise<Record<string, unknown>>;
}

// ---------------------------------------------------------------------------
// Verification Method Search
// ---------------------------------------------------------------------------

interface VerificationMethod {
  id: string;
  type?: string;
  publicKeyJwk?: Record<string, unknown>;
  [key: string]: unknown;
}

/**
 * Find a verification method in a DID document by DID URL or fragment.
 */
function findVerificationMethod(
  didDocument: Record<string, unknown>,
  didUrl: string,
  fragment: string | null
): VerificationMethod | null {
  const methods = didDocument.verificationMethod;
  if (!Array.isArray(methods)) {
    return null;
  }

  for (const method of methods as VerificationMethod[]) {
    if (!method || typeof method !== "object") continue;
    const id = method.id;
    if (typeof id !== "string") continue;

    // Match by full DID URL
    if (id === didUrl) return method;

    // Match by fragment (e.g. "#key-1" matches "did:web:example.com#key-1")
    if (fragment && (id === `#${fragment}` || id.endsWith(`#${fragment}`))) {
      return method;
    }
  }

  return null;
}

/**
 * Extract verification method IDs from a DID document for error reporting.
 */
function extractMethodIdsFromDidDocument(didDocument: Record<string, unknown>): string[] {
  const methods = didDocument.verificationMethod;
  if (!Array.isArray(methods)) return [];
  return (methods as Array<Record<string, unknown>>)
    .filter((m) => m && typeof m.id === "string")
    .map((m) => m.id as string);
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Resolve a DID URL to public key material.
 *
 * Currently supports:
 * - did:web with fragment (e.g. did:web:api.example.com#key-1)
 *
 * Resolution steps:
 * 1. Parse the DID URL
 * 2. Resolve the base DID (fetch DID document)
 * 3. Find the matching verification method
 * 4. Extract and validate publicKeyJwk
 *
 * This function only obtains key material. It does not make authorization
 * decisions or check Controller Witness / Key Binding records.
 *
 * @param didUrl - A DID URL string (e.g. "did:web:api.example.com#key-1")
 * @param options - Optional configuration (custom fetcher, etc.)
 * @returns Resolved public key information
 * @throws OmaTrustError if resolution fails
 */
export async function resolveDidUrlToPublicKey(
  didUrl: string,
  options?: ResolveKeyOptions
): Promise<ResolvedPublicKey> {
  assertString(didUrl, "didUrl", "INVALID_DID_URL");

  const parsed = parseDidUrl(didUrl);
  const method = extractDidMethod(parsed.did);

  if (!method) {
    throw new OmaTrustError("INVALID_DID_URL", "Cannot extract DID method from DID URL", {
      didUrl,
      did: parsed.did,
    });
  }

  switch (method) {
    case "web":
      return resolveDidUrlKey(parsed.didUrl, parsed.did, parsed.fragment, options);
    default:
      throw new OmaTrustError(
        "UNSUPPORTED_DID_METHOD",
        `DID URL key resolution is not supported for method "${method}"`,
        { didUrl, method }
      );
  }
}

/**
 * Resolve a DID URL to a durable controller DID.
 *
 * This wraps resolveDidUrlToPublicKey and adds the did:jwk conversion step.
 * The returned controllerDid is the durable DID that callers should pass
 * to getControllerAuthorization.
 *
 * @param didUrl - A DID URL string (e.g. "did:web:api.example.com#key-1")
 * @param options - Optional configuration (custom fetcher, etc.)
 * @returns Resolved public key plus derived did:jwk controller DID
 * @throws OmaTrustError if resolution fails
 */
export async function resolveDidUrlToControllerDid(
  didUrl: string,
  options?: ResolveKeyOptions
): Promise<ResolvedControllerDid> {
  const resolved = await resolveDidUrlToPublicKey(didUrl, options);
  const controllerDid = jwkToDidJwk(resolved.publicKeyJwk);

  return {
    ...resolved,
    controllerDid,
  };
}

// ---------------------------------------------------------------------------
// did:web Resolution
// ---------------------------------------------------------------------------

async function resolveDidUrlKey(
  didUrl: string,
  did: string,
  fragment: string | null,
  options?: ResolveKeyOptions
): Promise<ResolvedPublicKey> {
  const domain = getDomainFromDidWeb(did);
  if (!domain) {
    throw new OmaTrustError("INVALID_DID_URL", "Cannot extract domain from did:web DID", {
      didUrl,
      did,
    });
  }

  // Fetch DID document
  const fetchFn = options?.fetchDidDocument ?? fetchDidDocument;
  const didDocument = await fetchFn(domain);

  // Find verification method
  const method = findVerificationMethod(didDocument, didUrl, fragment);
  if (!method) {
    throw new OmaTrustError(
      "KEY_NOT_FOUND",
      `No verification method found matching "${fragment ? `#${fragment}` : didUrl}"`,
      { didUrl, fragment, availableMethods: extractMethodIdsFromDidDocument(didDocument) }
    );
  }

  // Extract publicKeyJwk
  const publicKeyJwk = method.publicKeyJwk;
  if (!publicKeyJwk || typeof publicKeyJwk !== "object") {
    throw new OmaTrustError(
      "KEY_NOT_FOUND",
      `Verification method "${method.id}" does not contain publicKeyJwk`,
      { didUrl, verificationMethodId: method.id }
    );
  }

  // Validate the JWK is a valid public key
  const validation = validatePublicJwk(publicKeyJwk);
  if (!validation.valid) {
    throw new OmaTrustError(
      "INVALID_JWK",
      `publicKeyJwk in verification method "${method.id}" is invalid: ${validation.error}`,
      { didUrl, verificationMethodId: method.id }
    );
  }

  return {
    didUrl,
    did,
    fragment,
    publicKeyJwk: publicKeyJwk as PublicJwk,
    verificationMethodId: method.id,
  };
}
