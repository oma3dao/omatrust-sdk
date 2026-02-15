import canonicalize from "canonicalize";
import { formatUnits, keccak256, sha256, toUtf8Bytes } from "ethers";
import { buildEvmDidPkh, computeDidHash } from "../../identity/did";
import { OmaTrustError } from "../../shared/errors";
import type { ChainConstants, Hex, ProofPurpose, TxEncodedValueProof } from "../types";

type ChainConfig = {
  decimals: number;
  nativeSymbol: string;
  explorer: string;
  base: Record<ProofPurpose, bigint>;
};

const CHAIN_CONFIGS: Record<number, ChainConfig> = {
  1: {
    decimals: 18,
    nativeSymbol: "ETH",
    explorer: "https://etherscan.io",
    base: {
      "shared-control": 100000000000000n,
      "commercial-tx": 1000000000000n
    }
  },
  10: {
    decimals: 18,
    nativeSymbol: "ETH",
    explorer: "https://optimistic.etherscan.io",
    base: {
      "shared-control": 100000000000000n,
      "commercial-tx": 1000000000000n
    }
  },
  137: {
    decimals: 18,
    nativeSymbol: "POL",
    explorer: "https://polygonscan.com",
    base: {
      "shared-control": 100000000000000n,
      "commercial-tx": 1000000000000n
    }
  },
  8453: {
    decimals: 18,
    nativeSymbol: "ETH",
    explorer: "https://basescan.org",
    base: {
      "shared-control": 100000000000000n,
      "commercial-tx": 1000000000000n
    }
  },
  42161: {
    decimals: 18,
    nativeSymbol: "ETH",
    explorer: "https://arbiscan.io",
    base: {
      "shared-control": 100000000000000n,
      "commercial-tx": 1000000000000n
    }
  },
  11155111: {
    decimals: 18,
    nativeSymbol: "ETH",
    explorer: "https://sepolia.etherscan.io",
    base: {
      "shared-control": 100000000000000n,
      "commercial-tx": 1000000000000n
    }
  },
  6623: {
    decimals: 18,
    nativeSymbol: "OMA",
    explorer: "https://explorer.chain.oma3.org",
    base: {
      "shared-control": 10000000000000000n,
      "commercial-tx": 100000000000000n
    }
  },
  66238: {
    decimals: 18,
    nativeSymbol: "OMA",
    explorer: "https://explorer.testnet.chain.oma3.org",
    base: {
      "shared-control": 10000000000000000n,
      "commercial-tx": 100000000000000n
    }
  }
};

const AMOUNT_DOMAIN = "OMATrust:Amount:v1";

function getConfig(chainId: number): ChainConfig {
  const config = CHAIN_CONFIGS[chainId];
  if (!config) {
    throw new OmaTrustError("UNSUPPORTED_CHAIN", "Chain is not supported", {
      chainId,
      supported: getSupportedChainIds()
    });
  }
  return config;
}

export function getSupportedChainIds(): number[] {
  return Object.keys(CHAIN_CONFIGS).map((id) => Number(id));
}

export function isChainSupported(chainId: number): boolean {
  return chainId in CHAIN_CONFIGS;
}

export function getChainConstants(chainId: number, purpose: ProofPurpose): ChainConstants {
  const config = getConfig(chainId);
  const base = config.base[purpose];
  const range = base / 10n;
  return {
    base,
    range,
    decimals: config.decimals,
    nativeSymbol: config.nativeSymbol
  };
}

export function constructSeed(
  subjectDidHash: Hex,
  counterpartyDidHash: Hex,
  purpose: ProofPurpose
): Uint8Array {
  const seed = {
    domain: AMOUNT_DOMAIN,
    subjectDidHash,
    counterpartyIdHash: counterpartyDidHash,
    proofPurpose: purpose
  };

  const canonical = canonicalize(seed);
  if (!canonical) {
    throw new OmaTrustError("INVALID_INPUT", "Failed to canonicalize seed");
  }

  return toUtf8Bytes(canonical);
}

export function hashSeed(seedBytes: Uint8Array, chainId: number): Hex {
  if (!isChainSupported(chainId)) {
    throw new OmaTrustError("UNSUPPORTED_CHAIN", "Chain is not supported", { chainId });
  }

  // OMATrust currently supports EVM chains in this SDK.
  if (chainId === 0) {
    return sha256(seedBytes) as Hex;
  }

  return keccak256(seedBytes) as Hex;
}

export function calculateTransferAmount(
  subject: string,
  counterparty: string,
  chainId: number,
  purpose: ProofPurpose
): bigint {
  const { base, range } = getChainConstants(chainId, purpose);
  const subjectDidHash = computeDidHash(subject);
  const counterpartyDidHash = computeDidHash(counterparty);
  const seed = constructSeed(subjectDidHash, counterpartyDidHash, purpose);
  const hashed = hashSeed(seed, chainId);
  const offset = BigInt(hashed) % range;
  return base + offset;
}

export function calculateTransferAmountFromAddresses(
  subjectAddress: string,
  counterpartyAddress: string,
  chainId: number,
  purpose: ProofPurpose
): bigint {
  return calculateTransferAmount(
    buildEvmDidPkh(chainId, subjectAddress),
    buildEvmDidPkh(chainId, counterpartyAddress),
    chainId,
    purpose
  );
}

export function createTxEncodedValueProof(
  chainId: number,
  txHash: Hex,
  purpose: ProofPurpose
): TxEncodedValueProof {
  if (!/^0x[0-9a-fA-F]{64}$/.test(txHash)) {
    throw new OmaTrustError("INVALID_INPUT", "txHash must be a 32-byte hex string", { txHash });
  }

  return {
    proofType: "tx-encoded-value",
    proofPurpose: purpose,
    proofObject: {
      chainId: `eip155:${chainId}`,
      txHash
    },
    version: 1,
    issuedAt: Math.floor(Date.now() / 1000)
  };
}

export function formatTransferAmount(amount: bigint | number, chainId: number): string {
  const config = getConfig(chainId);
  const normalized = typeof amount === "number" ? BigInt(Math.floor(amount)) : amount;
  return `${formatUnits(normalized, config.decimals)} ${config.nativeSymbol}`;
}

export function getExplorerTxUrl(chainId: number, txHash: Hex): string {
  return `${getConfig(chainId).explorer}/tx/${txHash}`;
}

export function getExplorerAddressUrl(chainId: number, address: string): string {
  return `${getConfig(chainId).explorer}/address/${address}`;
}
