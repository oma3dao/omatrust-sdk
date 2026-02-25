import type { Hex } from "./types";

type UnknownRecord = Record<string, unknown>;

function isRecord(value: unknown): value is UnknownRecord {
  return Boolean(value) && typeof value === "object";
}

function isHex32(value: unknown): value is Hex {
  return typeof value === "string" && /^0x[0-9a-fA-F]{64}$/.test(value);
}

export function getEasTransactionReceipt(tx: unknown): UnknownRecord | undefined {
  if (!isRecord(tx)) {
    return undefined;
  }

  const candidates: unknown[] = [tx.receipt, tx.tx, tx.transaction];
  for (const candidate of candidates) {
    if (isRecord(candidate)) {
      return candidate;
    }
  }

  return undefined;
}

export function getEasTransactionHash(tx: unknown): Hex | undefined {
  const receipt = getEasTransactionReceipt(tx);
  if (receipt) {
    const receiptHash = receipt.hash;
    if (isHex32(receiptHash)) {
      return receiptHash;
    }
    const transactionHash = receipt.transactionHash;
    if (isHex32(transactionHash)) {
      return transactionHash;
    }
  }

  if (isRecord(tx) && isHex32(tx.hash)) {
    return tx.hash;
  }

  return undefined;
}

export function isEasSchemaNotFoundError(err: unknown): boolean {
  if (!isRecord(err)) {
    return false;
  }

  const message = err.message;
  if (typeof message !== "string" || message.length === 0) {
    return false;
  }

  return /schema not found/i.test(message);
}
