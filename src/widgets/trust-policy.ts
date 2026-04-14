/**
 * Trust policy: fetches the OMA3 allowlist of EAS contracts and schemas.
 *
 * The bridge uses this to validate signing requests automatically.
 * Developers don't need to maintain their own allowlists.
 */

const DEFAULT_TRUST_POLICY_URL = "https://api.omatrust.org/v1/trust-policy";

export const TRUST_POLICY_URL = DEFAULT_TRUST_POLICY_URL;

export type ChainPolicy = {
  name: string;
  easContract: string;
  schemas: string[];
};

export type TrustPolicy = {
  version: number;
  updatedAt: string;
  widgetOrigins?: string[];
  chains: Record<string, ChainPolicy>;
};

let cachedPolicy: TrustPolicy | null = null;
let cacheTimestamp = 0;
const CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes

/**
 * Fetch the trust policy from the OMA3 API gateway.
 * Caches the result for 5 minutes.
 *
 * @param url Override the trust policy URL (for testing or custom deployments)
 */
export async function fetchTrustPolicy(url?: string): Promise<TrustPolicy> {
  const now = Date.now();
  if (cachedPolicy && now - cacheTimestamp < CACHE_TTL_MS) {
    return cachedPolicy;
  }

  const res = await fetch(url ?? TRUST_POLICY_URL);
  if (!res.ok) {
    throw new Error(`Failed to fetch trust policy: ${res.status} ${res.statusText}`);
  }

  const policy: TrustPolicy = await res.json();

  if (!policy.version || !policy.chains || typeof policy.chains !== "object") {
    throw new Error("Invalid trust policy format");
  }

  cachedPolicy = policy;
  cacheTimestamp = now;
  return policy;
}

/**
 * Extract the allowed contracts and schemas from a trust policy.
 * Returns all contracts and schemas across all chains.
 */
export function extractAllowlists(policy: TrustPolicy): {
  allowedContracts: string[];
  allowedSchemas: string[];
} {
  const contracts: string[] = [];
  const schemas: string[] = [];

  for (const chain of Object.values(policy.chains)) {
    if (chain.easContract) contracts.push(chain.easContract);
    if (chain.schemas) schemas.push(...chain.schemas);
  }

  return {
    allowedContracts: [...new Set(contracts)],
    allowedSchemas: [...new Set(schemas)],
  };
}
