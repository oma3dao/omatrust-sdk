import {
  Interface,
  ZeroAddress,
  getAddress,
  isAddress
} from "ethers";
import {
  buildEvmDidPkh,
  extractDidMethod,
  getAddressFromDidPkh,
  getChainIdFromDidPkh,
  getDomainFromDidWeb,
  isEvmDidPkh,
  normalizeDid
} from "../identity/did";
import { OmaTrustError } from "../shared/errors";
import type { Did, Hex } from "./types";
import { verifyDidJsonControllerDid } from "./proof/did-json";
import {
  verifyDnsTxtControllerDid,
  type VerifyDnsTxtControllerDidOptions
} from "./proof/dns-txt-shared";
import { calculateTransferAmount } from "./proof/tx-encoded-value";

const EIP1967_ADMIN_SLOT =
  "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103" as const;

const OWNERSHIP_PATTERNS = [
  { method: "owner", signature: "function owner() view returns (address)" },
  { method: "admin", signature: "function admin() view returns (address)" },
  { method: "getOwner", signature: "function getOwner() view returns (address)" }
] as const;

export type SubjectOwnershipVerificationMethod =
  | "dns"
  | "did-document"
  | "wallet"
  | "contract"
  | "minting-wallet"
  | "transfer";

export interface SubjectOwnershipVerificationResult {
  valid: boolean;
  method?: SubjectOwnershipVerificationMethod;
  reason?: string;
  details?: string;
  subjectDid: Did;
  connectedWalletDid: Did;
  controllingWalletDid?: Did;
}

export interface EvmOwnershipProvider {
  call(transaction: { to: string; data: string }): Promise<string>;
  getCode(address: string): Promise<string>;
  getStorage(address: string, slot: string): Promise<string>;
  getTransaction(hash: string): Promise<{
    from?: string | null;
    to?: string | null;
    value?: bigint | string | number | null;
    blockNumber?: number | null;
  } | null>;
  getTransactionReceipt(hash: string): Promise<{
    blockNumber: number;
  } | null>;
  getBlockNumber(): Promise<number>;
  getBlock(blockNumber: number): Promise<{ timestamp: number } | null>;
}

export interface VerifyDidWebOwnershipParams extends VerifyDnsTxtControllerDidOptions {
  subjectDid: Did;
  connectedWalletDid: Did;
  fetchDidDocument?: (domain: string) => Promise<Record<string, unknown>>;
}

export interface VerifyDidPkhOwnershipParams {
  subjectDid: Did;
  connectedWalletDid: Did;
  provider: EvmOwnershipProvider;
  txHash?: Hex | string;
}

export type VerifySubjectOwnershipParams =
  | VerifyDidWebOwnershipParams
  | (VerifyDidPkhOwnershipParams & VerifyDnsTxtControllerDidOptions);

function assertConnectedWalletDid(input: string): Did {
  const normalized = normalizeDid(input);
  if (extractDidMethod(normalized) !== "pkh") {
    throw new OmaTrustError("INVALID_INPUT", "connectedWalletDid must be a did:pkh DID", {
      connectedWalletDid: input
    });
  }
  return normalized;
}

function normalizeSubjectDid(input: string): Did {
  return normalizeDid(input);
}

async function readAddressFromContract(
  provider: EvmOwnershipProvider,
  contractAddress: string,
  signature: string,
  method: string
): Promise<string | null> {
  try {
    const iface = new Interface([signature]);
    const data = iface.encodeFunctionData(method, []);
    const result = await provider.call({ to: contractAddress, data });
    const [value] = iface.decodeFunctionResult(method, result);
    if (typeof value === "string" && isAddress(value) && value !== ZeroAddress) {
      return getAddress(value);
    }
  } catch {
    // ignore read failures and try the next ownership pattern
  }

  return null;
}

async function discoverControllingWallet(
  provider: EvmOwnershipProvider,
  contractAddress: string,
  chainId: number
): Promise<string | null> {
  for (const pattern of OWNERSHIP_PATTERNS) {
    const address = await readAddressFromContract(
      provider,
      contractAddress,
      pattern.signature,
      pattern.method
    );
    if (address) {
      return buildEvmDidPkh(chainId, address);
    }
  }

  try {
    const adminValue = await provider.getStorage(contractAddress, EIP1967_ADMIN_SLOT);
    if (
      adminValue &&
      adminValue !== "0x" &&
      adminValue !== "0x0000000000000000000000000000000000000000000000000000000000000000"
    ) {
      const adminAddress = getAddress(`0x${adminValue.slice(-40)}`);
      if (adminAddress !== ZeroAddress) {
        return buildEvmDidPkh(chainId, adminAddress);
      }
    }
  } catch {
    // ignore; this is just one fallback
  }

  return null;
}

export async function verifyDidWebOwnership(
  params: VerifyDidWebOwnershipParams
): Promise<SubjectOwnershipVerificationResult> {
  const subjectDid = normalizeSubjectDid(params.subjectDid);
  const connectedWalletDid = assertConnectedWalletDid(params.connectedWalletDid);
  const domain = getDomainFromDidWeb(subjectDid);

  if (!domain) {
    throw new OmaTrustError("INVALID_INPUT", "subjectDid must be a did:web DID", {
      subjectDid: params.subjectDid
    });
  }

  let dnsReason: string | undefined;
  try {
    const dnsResult = await verifyDnsTxtControllerDid(domain, connectedWalletDid, {
      resolveTxt: params.resolveTxt,
      recordPrefix: params.recordPrefix
    });
    if (dnsResult.valid) {
      return {
        valid: true,
        method: "dns",
        details: `Verified via DNS TXT record at ${(params.recordPrefix ?? "_controllers")}.${domain}`,
        subjectDid,
        connectedWalletDid
      };
    }
    dnsReason = dnsResult.reason;
  } catch (error) {
    dnsReason = error instanceof Error ? error.message : "DNS TXT verification failed";
  }

  let didDocReason: string | undefined;
  try {
    const didDocumentResult = await verifyDidJsonControllerDid(domain, connectedWalletDid, {
      fetchDidDocument: params.fetchDidDocument
    });
    if (didDocumentResult.valid) {
      return {
        valid: true,
        method: "did-document",
        details: `Verified via DID document at https://${domain}/.well-known/did.json`,
        subjectDid,
        connectedWalletDid
      };
    }
    didDocReason = didDocumentResult.reason;
  } catch (error) {
    didDocReason = error instanceof Error ? error.message : "DID document verification failed";
  }

  return {
    valid: false,
    reason: "DID ownership verification failed",
    details: `DNS check: ${dnsReason ?? "failed"}. DID document check: ${didDocReason ?? "failed"}.`,
    subjectDid,
    connectedWalletDid
  };
}

export async function verifyDidPkhOwnership(
  params: VerifyDidPkhOwnershipParams
): Promise<SubjectOwnershipVerificationResult> {
  const subjectDid = normalizeSubjectDid(params.subjectDid);
  const connectedWalletDid = assertConnectedWalletDid(params.connectedWalletDid);

  if (!isEvmDidPkh(subjectDid)) {
    throw new OmaTrustError("INVALID_INPUT", "subjectDid must be an EVM did:pkh DID", {
      subjectDid: params.subjectDid
    });
  }

  const subjectAddress = getAddressFromDidPkh(subjectDid);
  const connectedWalletAddress = getAddressFromDidPkh(connectedWalletDid);
  const chainIdRaw = getChainIdFromDidPkh(subjectDid);

  if (!subjectAddress || !connectedWalletAddress || !chainIdRaw) {
    throw new OmaTrustError("INVALID_INPUT", "Could not parse did:pkh ownership inputs", {
      subjectDid: params.subjectDid,
      connectedWalletDid: params.connectedWalletDid
    });
  }

  const chainId = Number(chainIdRaw);
  if (!Number.isFinite(chainId)) {
    throw new OmaTrustError("INVALID_INPUT", "Invalid chain id in subjectDid", {
      subjectDid: params.subjectDid
    });
  }

  const code = await params.provider.getCode(subjectAddress);
  const isContract = code !== "0x" && code !== "0x0";

  if (!isContract) {
    if (getAddress(subjectAddress) === getAddress(connectedWalletAddress)) {
      return {
        valid: true,
        method: "wallet",
        details: "Verified direct wallet ownership from matching did:pkh subject and connected wallet",
        subjectDid,
        connectedWalletDid
      };
    }

    return {
      valid: false,
      reason: "EOA did:pkh subject does not match connected wallet",
      details: "For direct wallet did:pkh subjects, connectedWalletDid must match the subject DID.",
      subjectDid,
      connectedWalletDid
    };
  }

  const controllingWalletDid = await discoverControllingWallet(params.provider, subjectAddress, chainId);

  if (params.txHash) {
    if (!controllingWalletDid) {
      return {
        valid: false,
        reason: "Could not discover controlling wallet",
        details:
          "Contract does not expose owner/admin/getOwner or a readable EIP-1967 admin slot for transfer verification.",
        subjectDid,
        connectedWalletDid
      };
    }

    const tx = await params.provider.getTransaction(params.txHash);
    if (!tx) {
      return {
        valid: false,
        reason: "Transaction not found",
        details: `Transaction ${params.txHash} was not found on chain ${chainId}.`,
        subjectDid,
        connectedWalletDid,
        controllingWalletDid
      };
    }

    const receipt = await params.provider.getTransactionReceipt(params.txHash);
    if (!receipt) {
      return {
        valid: false,
        reason: "Transaction not confirmed",
        details: "Transaction exists but is not yet confirmed.",
        subjectDid,
        connectedWalletDid,
        controllingWalletDid
      };
    }

    const controllingWalletAddress = getAddressFromDidPkh(controllingWalletDid);
    if (!tx.from || !controllingWalletAddress || getAddress(tx.from) !== getAddress(controllingWalletAddress)) {
      return {
        valid: false,
        reason: "Wrong sender",
        details: `Transfer must originate from controlling wallet ${controllingWalletDid}.`,
        subjectDid,
        connectedWalletDid,
        controllingWalletDid
      };
    }

    if (!tx.to || getAddress(tx.to) !== getAddress(connectedWalletAddress)) {
      return {
        valid: false,
        reason: "Wrong recipient",
        details: `Transfer must be sent to connected wallet ${connectedWalletDid}.`,
        subjectDid,
        connectedWalletDid,
        controllingWalletDid
      };
    }

    const expectedAmount = calculateTransferAmount(
      subjectDid,
      connectedWalletDid,
      chainId,
      "shared-control"
    );
    const actualValue = BigInt(tx.value ?? 0n);

    if (actualValue !== expectedAmount) {
      return {
        valid: false,
        reason: "Wrong amount",
        details: `Transfer amount ${actualValue.toString()} does not match expected proof amount ${expectedAmount.toString()}.`,
        subjectDid,
        connectedWalletDid,
        controllingWalletDid
      };
    }

    await params.provider.getBlockNumber();
    await params.provider.getBlock(receipt.blockNumber);

    return {
      valid: true,
      method: "transfer",
      details: `Verified via transfer proof ${params.txHash}.`,
      subjectDid,
      connectedWalletDid,
      controllingWalletDid
    };
  }

  for (const pattern of OWNERSHIP_PATTERNS) {
    const ownerAddress = await readAddressFromContract(
      params.provider,
      subjectAddress,
      pattern.signature,
      pattern.method
    );

    if (ownerAddress && getAddress(ownerAddress) === getAddress(connectedWalletAddress)) {
      return {
        valid: true,
        method: "contract",
        details: `Verified via ${pattern.method}() ownership check.`,
        subjectDid,
        connectedWalletDid,
        controllingWalletDid: controllingWalletDid ?? undefined
      };
    }
  }

  try {
    const adminValue = await params.provider.getStorage(subjectAddress, EIP1967_ADMIN_SLOT);
    if (
      adminValue &&
      adminValue !== "0x" &&
      adminValue !== "0x0000000000000000000000000000000000000000000000000000000000000000"
    ) {
      const adminAddress = getAddress(`0x${adminValue.slice(-40)}`);
      if (adminAddress === getAddress(connectedWalletAddress)) {
        return {
          valid: true,
          method: "contract",
          details: "Verified via EIP-1967 admin slot.",
          subjectDid,
          connectedWalletDid,
          controllingWalletDid: controllingWalletDid ?? buildEvmDidPkh(chainId, adminAddress)
        };
      }
    }
  } catch {
    // ignore; final fallback below returns a stable invalid result
  }

  if (
    getAddress(subjectAddress) === getAddress(connectedWalletAddress) &&
    controllingWalletDid
  ) {
    return {
      valid: true,
      method: "minting-wallet",
      details: `Verified because connected wallet matches the contract DID address. Controlling wallet is ${controllingWalletDid}.`,
      subjectDid,
      connectedWalletDid,
      controllingWalletDid
    };
  }

  return {
    valid: false,
    reason: "Contract ownership verification failed",
    details:
      controllingWalletDid
        ? `Connected wallet ${connectedWalletDid} does not match the controlling wallet ${controllingWalletDid} or the subject contract address ${subjectDid}.`
        : `Could not match connected wallet ${connectedWalletDid} to contract ownership for ${subjectDid}.`,
    subjectDid,
    connectedWalletDid,
    controllingWalletDid: controllingWalletDid ?? undefined
  };
}

export async function verifySubjectOwnership(
  params: VerifySubjectOwnershipParams
): Promise<SubjectOwnershipVerificationResult> {
  const subjectDid = normalizeSubjectDid(params.subjectDid);
  const method = extractDidMethod(subjectDid);

  if (method === "web") {
    return verifyDidWebOwnership(params as VerifyDidWebOwnershipParams);
  }

  if (method === "pkh") {
    const didPkhParams = params as VerifyDidPkhOwnershipParams;
    if (!didPkhParams.provider) {
      throw new OmaTrustError(
        "INVALID_INPUT",
        "provider is required for did:pkh ownership verification",
        { subjectDid }
      );
    }
    return verifyDidPkhOwnership(didPkhParams);
  }

  throw new OmaTrustError("INVALID_INPUT", "Unsupported DID type for ownership verification", {
    subjectDid
  });
}
