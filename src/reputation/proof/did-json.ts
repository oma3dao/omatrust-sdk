import { getAddress, isAddress } from "ethers";
import { extractAddressFromDid } from "../../identity/did";
import type { Did } from "../types";
import { OmaTrustError } from "../../shared/errors";

export async function fetchDidDocument(
  domain: string
): Promise<Record<string, unknown>> {
  const normalized = domain.toLowerCase().replace(/\.$/, "");
  const url = `https://${normalized}/.well-known/did.json`;

  let response: Response;
  try {
    response = await fetch(url, { headers: { Accept: "application/json" } });
  } catch (err) {
    throw new OmaTrustError("NETWORK_ERROR", "Failed to fetch DID document", { domain, err });
  }

  if (!response.ok) {
    throw new OmaTrustError("NETWORK_ERROR", "DID document fetch failed", {
      domain,
      status: response.status
    });
  }

  const body = (await response.json()) as Record<string, unknown>;
  return body;
}

export function extractAddressesFromDidDocument(didDocument: Record<string, unknown>): string[] {
  const methods = didDocument.verificationMethod;
  if (!Array.isArray(methods)) {
    return [];
  }

  const addresses = new Set<string>();

  for (const method of methods as Array<Record<string, unknown>>) {
    const blockchainAccountId = method.blockchainAccountId;
    if (typeof blockchainAccountId === "string") {
      try {
        addresses.add(getAddress(extractAddressFromDid(blockchainAccountId)));
      } catch {
        // ignore
      }
    }

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

export function verifyDidDocumentControllerDid(
  didDocument: Record<string, unknown>,
  expectedControllerDid: Did
): { valid: boolean; reason?: string } {
  let expectedAddress: string;
  try {
    expectedAddress = getAddress(extractAddressFromDid(expectedControllerDid));
  } catch {
    return { valid: false, reason: "Expected controller DID does not resolve to an EVM address" };
  }

  const addresses = extractAddressesFromDidDocument(didDocument);
  if (addresses.some((address) => address.toLowerCase() === expectedAddress.toLowerCase())) {
    return { valid: true };
  }

  return {
    valid: false,
    reason: `No matching address found in DID document (expected ${expectedAddress})`
  };
}
