import { ZeroAddress, getAddress, isAddress } from "ethers";
import { computeDidAddress, computeDidHash, didToAddress } from "../identity/did";
import { OmaTrustError } from "../shared/errors";
import type { Hex, SchemaField } from "./types";
import { normalizeSchema } from "./encode";

export const ZERO_UID = "0x0000000000000000000000000000000000000000000000000000000000000000" as Hex;

export function toBigIntOrDefault(value: bigint | number | undefined, fallback: bigint): bigint {
  if (value === undefined || value === null) {
    return fallback;
  }
  return typeof value === "bigint" ? value : BigInt(Math.floor(value));
}

export function normalizeHex32(value: string, field: string): Hex {
  const normalized = value.startsWith("0x") ? value : `0x${value}`;
  if (!/^0x[0-9a-fA-F]{64}$/.test(normalized)) {
    throw new OmaTrustError("INVALID_INPUT", `${field} must be a 32-byte hex string`, { value });
  }
  return normalized as Hex;
}

export function withAutoSubjectDidHash(
  schema: SchemaField[] | string,
  data: Record<string, unknown>
): Record<string, unknown> {
  const fields = normalizeSchema(schema);
  const hasSubjectDidHash = fields.some((field) => field.name === "subjectDidHash");
  if (!hasSubjectDidHash) {
    return { ...data };
  }

  const subject = data.subject;
  if (typeof subject === "string" && subject.startsWith("did:")) {
    return {
      ...data,
      subjectDidHash: computeDidHash(subject)
    };
  }

  return { ...data };
}

export function resolveRecipientAddress(data: Record<string, unknown>): string {
  const subject = data.subject;
  if (typeof subject === "string" && subject.startsWith("did:")) {
    return didToAddress(subject);
  }

  const subjectDidHash = data.subjectDidHash;
  if (typeof subjectDidHash === "string" && /^0x[0-9a-fA-F]{64}$/.test(subjectDidHash)) {
    return computeDidAddress(subjectDidHash as Hex);
  }

  const recipient = data.recipient;
  if (typeof recipient === "string" && isAddress(recipient)) {
    return getAddress(recipient);
  }

  return ZeroAddress;
}

export function parseProofsField(data: Record<string, unknown>): unknown[] {
  const proofs = data.proofs;
  if (!Array.isArray(proofs)) {
    return [];
  }

  return proofs.map((entry) => {
    if (typeof entry === "string") {
      try {
        return JSON.parse(entry);
      } catch {
        return entry;
      }
    }
    return entry;
  });
}
