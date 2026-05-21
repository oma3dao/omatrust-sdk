/**
 * Contract Ownership — shared primitives for discovering contract owners
 * and verifying transfer proofs.
 *
 * Used by:
 * - subject-ownership.ts (full ownership verification flow)
 * - attester-authorization.ts (authorization checks for did:pkh subjects)
 */

import { Interface, ZeroAddress, getAddress, isAddress } from "ethers";
import { buildEvmDidPkh } from "../identity/did";
import { calculateTransferAmount } from "./proof/tx-encoded-value";
import type { Hex, Did } from "./types";

// ---------------------------------------------------------------------------
// Provider interface
// ---------------------------------------------------------------------------

/**
 * Minimal provider interface for contract ownership reads.
 * Compatible with ethers v6 providers — consumers can pass their provider directly.
 */
export interface ContractOwnershipProvider {
  call(transaction: { to: string; data: string }): Promise<string>;
  getCode(address: string): Promise<string>;
  getStorage(address: string, slot: string): Promise<string>;
  getTransaction(hash: string): Promise<{
    from?: string | null;
    to?: string | null;
    value?: bigint | string | number | null;
    blockNumber?: number | null;
  } | null>;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

export const EIP1967_ADMIN_SLOT =
  "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103" as const;

export const OWNERSHIP_PATTERNS = [
  { method: "owner", signature: "function owner() view returns (address)" },
  { method: "admin", signature: "function admin() view returns (address)" },
  { method: "getOwner", signature: "function getOwner() view returns (address)" },
] as const;

// ---------------------------------------------------------------------------
// Public functions
// ---------------------------------------------------------------------------

/**
 * Read a single address-returning function from a contract.
 * Returns the checksummed address or null if the call fails or returns zero.
 */
export async function readOwnerFromContract(
  provider: ContractOwnershipProvider,
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
    // Call failed — contract may not implement this method
  }
  return null;
}

/**
 * Discover the controlling wallet address of a contract.
 *
 * Tries, in order:
 * 1. `owner()` — OpenZeppelin Ownable
 * 2. `admin()` — common admin pattern
 * 3. `getOwner()` — alternative naming
 * 4. EIP-1967 admin storage slot
 *
 * Returns the checksummed owner address, or null if not discoverable.
 */
export async function discoverContractOwner(
  provider: ContractOwnershipProvider,
  contractAddress: string
): Promise<string | null> {
  // Verify it's actually a contract
  try {
    const code = await provider.getCode(contractAddress);
    if (code === "0x" || code === "0x0") {
      return null;
    }
  } catch {
    return null;
  }

  // Try standard ownership patterns
  for (const pattern of OWNERSHIP_PATTERNS) {
    const address = await readOwnerFromContract(
      provider,
      contractAddress,
      pattern.signature,
      pattern.method
    );
    if (address) {
      return address;
    }
  }

  // Try EIP-1967 admin slot
  try {
    const adminValue = await provider.getStorage(contractAddress, EIP1967_ADMIN_SLOT);
    if (
      adminValue &&
      adminValue !== "0x" &&
      adminValue !== "0x0000000000000000000000000000000000000000000000000000000000000000"
    ) {
      const adminAddress = getAddress(`0x${adminValue.slice(-40)}`);
      if (adminAddress !== ZeroAddress) {
        return adminAddress;
      }
    }
  } catch {
    // Slot not readable
  }

  return null;
}

/**
 * Discover the controlling wallet and return it as a did:pkh DID.
 * Convenience wrapper over discoverContractOwner for DID-based flows.
 */
export async function discoverControllingWalletDid(
  provider: ContractOwnershipProvider,
  contractAddress: string,
  chainId: number
): Promise<Did | null> {
  const owner = await discoverContractOwner(provider, contractAddress);
  return owner ? buildEvmDidPkh(chainId, owner) : null;
}

/**
 * Verify a transfer proof transaction.
 *
 * Checks:
 * - Transaction exists and has from/to
 * - Recipient matches the expected attester address
 * - Transfer amount matches the deterministic proof amount for the subject-attester pair
 *
 * Does NOT verify the sender is the current contract owner — that's a separate
 * concern (the sender may have been the owner at the time of transfer but not now).
 */
export async function verifyTransferProof(
  provider: ContractOwnershipProvider,
  txHash: Hex,
  subjectDid: Did,
  attesterAddress: string,
  chainId: number
): Promise<boolean> {
  try {
    const tx = await provider.getTransaction(txHash);
    if (!tx || !tx.from || !tx.to) {
      return false;
    }

    // Recipient must be the attester
    if (getAddress(tx.to) !== getAddress(attesterAddress)) {
      return false;
    }

    // Verify the amount matches the deterministic transfer proof amount
    const attesterDid = buildEvmDidPkh(chainId, attesterAddress);
    const expectedAmount = calculateTransferAmount(
      subjectDid,
      attesterDid,
      chainId,
      "shared-control"
    );
    const actualValue = BigInt(tx.value ?? 0n);

    return actualValue === expectedAmount;
  } catch {
    return false;
  }
}
