import { getAddress, isAddress, keccak256, toUtf8Bytes } from "ethers";
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
  return domain.trim().toLowerCase().replace(/\.$/, "");
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
