/**
 * Trust anchors: fetches the OMA3 allowlist of EAS contracts and schemas.
 *
 * Used by the widget signing bridge for request validation and by the
 * reputation module for chain/contract resolution.
 *
 * Chain keys use CAIP-2 identifiers (e.g., "eip155:66238").
 */

import { OmaTrustError } from "./errors";

const DEFAULT_TRUST_ANCHORS_URL = "https://api.omatrust.org/v1/trust-anchors";

export const TRUST_ANCHORS_URL = DEFAULT_TRUST_ANCHORS_URL;

export type ChainAnchors = {
  name: string;
  easContract: string;
  /** Schema name → schema UID mapping */
  schemas: Record<string, string>;
};

export type ApprovedIssuer = {
  address: string;
  label: string;
  schemas: string[];
  status: "active" | "revoked";
  validFrom: string;
  revokedAt?: string;
};

export type TrustAnchors = {
  version: number;
  updatedAt: string;
  widgetOrigins?: string[];
  /** CAIP-2 chain identifier → chain-specific trust anchors */
  chains: Record<string, ChainAnchors>;
  registries?: Array<{
    type: "approved-issuers";
    issuers: ApprovedIssuer[];
  }>;
};

let cachedAnchors: TrustAnchors | null = null;
let cacheTimestamp = 0;
const CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes

/**
 * Fetch the trust anchors from the OMA3 API gateway.
 * Caches the result for 5 minutes.
 *
 * @param url Override the trust anchors URL (for testing or custom deployments)
 */
export async function fetchTrustAnchors(url?: string): Promise<TrustAnchors> {
  const now = Date.now();
  if (cachedAnchors && now - cacheTimestamp < CACHE_TTL_MS) {
    return cachedAnchors;
  }

  let res: Response;
  try {
    res = await fetch(url ?? TRUST_ANCHORS_URL);
  } catch (err) {
    throw new OmaTrustError("NETWORK_ERROR", "Failed to fetch trust anchors", { err });
  }

  if (!res.ok) {
    throw new OmaTrustError("NETWORK_ERROR", `Failed to fetch trust anchors: ${res.status} ${res.statusText}`);
  }

  const anchors: TrustAnchors = await res.json();

  if (!anchors.version || !anchors.chains || typeof anchors.chains !== "object") {
    throw new OmaTrustError("INVALID_INPUT", "Invalid trust anchors format");
  }

  cachedAnchors = anchors;
  cacheTimestamp = now;
  return anchors;
}

/**
 * Look up chain anchors by CAIP-2 identifier.
 * Throws UNSUPPORTED_CHAIN if the chain is not in the trust anchors.
 */
export function getChainAnchors(anchors: TrustAnchors, caip2: string): ChainAnchors {
  const chain = anchors.chains[caip2];
  if (!chain) {
    throw new OmaTrustError("UNSUPPORTED_CHAIN", `Chain ${caip2} is not in the trust anchors`, {
      caip2,
      supportedChains: Object.keys(anchors.chains),
    });
  }
  return chain;
}

/**
 * Look up a schema UID by name for a given chain.
 * Throws UNSUPPORTED_CHAIN if the chain is not in the trust anchors.
 * Throws INVALID_INPUT if the schema is not deployed on this chain.
 */
export function getSchemaAnchor(anchors: TrustAnchors, caip2: string, schemaName: string): string {
  const chain = getChainAnchors(anchors, caip2);
  const uid = chain.schemas[schemaName];
  if (!uid) {
    throw new OmaTrustError("INVALID_INPUT", `Schema "${schemaName}" not found in trust anchors for chain ${caip2}`, {
      caip2,
      schemaName,
      availableSchemas: Object.keys(chain.schemas),
    });
  }
  return uid;
}

/**
 * Extract the allowed contracts and schema UIDs from trust anchors.
 * Returns all contracts and schema UIDs across all chains.
 */
export function extractAllowlists(anchors: TrustAnchors): {
  allowedContracts: string[];
  allowedSchemas: string[];
} {
  const contracts: string[] = [];
  const schemas: string[] = [];

  for (const chain of Object.values(anchors.chains)) {
    if (chain.easContract) contracts.push(chain.easContract);
    if (chain.schemas && typeof chain.schemas === "object") {
      schemas.push(...Object.values(chain.schemas));
    }
  }

  return {
    allowedContracts: [...new Set(contracts)],
    allowedSchemas: [...new Set(schemas)],
  };
}
