import { getAddress, isAddress } from "ethers";
import { extractAddressFromDid, extractDidMethod } from "../../identity/did";
import { didJwkToJwk, publicJwkEquals } from "../../identity/jwk";
import type { Did } from "../types";
import { OmaTrustError } from "../../shared/errors";
import { fetchDidDocument } from "../../shared/did-document";

export { fetchDidDocument };

export interface VerifyDidJsonControllerDidOptions {
  fetchDidDocument?: (domain: string) => Promise<Record<string, unknown>>;
}

/**
 * Extract EVM addresses from a DID document's verification methods.
 * Looks at blockchainAccountId and publicKeyHex fields.
 */
export function extractEvmAddressesFromDidDocument(didDocument: Record<string, unknown>): string[] {
  const methods = didDocument.verificationMethod;
  if (!Array.isArray(methods)) {
    return [];
  }

  const addresses = new Set<string>();

  for (const method of methods as Array<Record<string, unknown>>) {
    // Extract from blockchainAccountId (CAIP-10 format, strip chain prefix)
    const blockchainAccountId = method.blockchainAccountId;
    if (typeof blockchainAccountId === "string") {
      try {
        addresses.add(getAddress(extractAddressFromDid(blockchainAccountId)));
      } catch {
        // ignore — not a valid EVM address
      }
    }

    // Extract from publicKeyHex
    const publicKeyHex = method.publicKeyHex;
    if (typeof publicKeyHex === "string") {
      const prefixed = publicKeyHex.startsWith("0x") ? publicKeyHex : `0x${publicKeyHex}`;
      if (isAddress(prefixed)) {
        addresses.add(getAddress(prefixed));
      }
    }
  }

  return [...addresses];
}

/**
 * Extract public JWKs from a DID document's verification methods.
 */
export function extractJwksFromDidDocument(
  didDocument: Record<string, unknown>
): Array<Record<string, unknown>> {
  const methods = didDocument.verificationMethod;
  if (!Array.isArray(methods)) {
    return [];
  }

  const jwks: Array<Record<string, unknown>> = [];

  for (const method of methods as Array<Record<string, unknown>>) {
    const publicKeyJwk = method.publicKeyJwk;
    if (publicKeyJwk && typeof publicKeyJwk === "object" && !Array.isArray(publicKeyJwk)) {
      jwks.push(publicKeyJwk as Record<string, unknown>);
    }
  }

  return jwks;
}

/**
 * Verify that a controller DID is present in a DID document.
 *
 * Matching strategies:
 * - did:pkh (EVM): extract address and compare against blockchainAccountId / publicKeyHex
 *   in verification methods. Chain ID is ignored (same address across all EVM chains).
 * - did:jwk: decode the JWK from the DID and compare against publicKeyJwk fields
 *   in verification methods.
 */
export function verifyDidDocumentControllerDid(
  didDocument: Record<string, unknown>,
  expectedControllerDid: Did
): { valid: boolean; reason?: string } {
  const method = extractDidMethod(expectedControllerDid);

  // did:jwk — match by public key material
  if (method === "jwk") {
    try {
      const expectedJwk = didJwkToJwk(expectedControllerDid);
      const documentJwks = extractJwksFromDidDocument(didDocument);

      for (const docJwk of documentJwks) {
        try {
          if (publicJwkEquals(docJwk, expectedJwk)) {
            return { valid: true };
          }
        } catch {
          // JWK comparison failed for this method — continue
        }
      }

      return {
        valid: false,
        reason: "No matching publicKeyJwk found in DID document verification methods",
      };
    } catch {
      return {
        valid: false,
        reason: "Failed to decode did:jwk controller DID",
      };
    }
  }

  // did:pkh and other address-based methods — match by EVM address
  let expectedAddress: string;
  try {
    expectedAddress = getAddress(extractAddressFromDid(expectedControllerDid));
  } catch {
    return { valid: false, reason: "Controller DID does not resolve to an EVM address and is not did:jwk" };
  }

  const addresses = extractEvmAddressesFromDidDocument(didDocument);
  if (addresses.some((address) => address.toLowerCase() === expectedAddress.toLowerCase())) {
    return { valid: true };
  }

  return {
    valid: false,
    reason: `No matching address found in DID document (expected ${expectedAddress})`,
  };
}

export async function verifyDidJsonControllerDid(
  domain: string,
  expectedControllerDid: Did,
  options: VerifyDidJsonControllerDidOptions = {}
): Promise<{ valid: boolean; reason?: string }> {
  if (!domain || typeof domain !== "string") {
    throw new OmaTrustError("INVALID_INPUT", "domain must be a non-empty string", { domain });
  }

  const didDocument = options.fetchDidDocument
    ? await options.fetchDidDocument(domain)
    : await fetchDidDocument(domain);

  return verifyDidDocumentControllerDid(didDocument, expectedControllerDid);
}
