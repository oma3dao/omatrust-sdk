/**
 * DID Document Fetching — shared utility
 *
 * Fetches did:web DID documents from the well-known endpoint.
 * Used by identity/resolve-key and reputation/proof/did-json.
 */

import { OmaTrustError } from "./errors";

/**
 * Fetch a DID document for a did:web domain.
 *
 * Resolves `https://<domain>/.well-known/did.json` and returns the parsed JSON.
 *
 * @param domain - The domain to fetch the DID document from
 * @returns The parsed DID document
 * @throws OmaTrustError with code NETWORK_ERROR if fetch fails
 */
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
    throw new OmaTrustError("NETWORK_ERROR", `DID document fetch failed: ${response.status}`, {
      domain,
      status: response.status,
    });
  }

  return (await response.json()) as Record<string, unknown>;
}
