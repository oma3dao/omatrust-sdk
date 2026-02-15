import { resolveTxt } from "node:dns/promises";
import { normalizeDid } from "../../identity/did";
import { OmaTrustError } from "../../shared/errors";
import type { Did } from "../types";

export function parseDnsTxtRecord(
  record: string
): { version?: string; controller?: Did; [key: string]: string | undefined } {
  if (!record || typeof record !== "string") {
    throw new OmaTrustError("INVALID_INPUT", "record must be a non-empty string", { record });
  }

  const entries = record
    .split(/[;\s]+/)
    .map((entry) => entry.trim())
    .filter(Boolean);

  const parsed: Record<string, string | undefined> = {};
  for (const entry of entries) {
    const [key, ...valueParts] = entry.split("=");
    if (!key) {
      continue;
    }
    const value = valueParts.join("=");
    if (!value) {
      continue;
    }
    parsed[key.trim()] = value.trim();
  }

  return {
    version: parsed.v,
    controller: parsed.controller,
    ...parsed
  };
}

export function buildDnsTxtRecord(controllerDid: Did): string {
  const normalized = normalizeDid(controllerDid);
  return `v=1;controller=${normalized}`;
}

export async function verifyDnsTxtControllerDid(
  domain: string,
  expectedControllerDid: Did
): Promise<{ valid: boolean; record?: string; reason?: string }> {
  if (!domain || typeof domain !== "string") {
    throw new OmaTrustError("INVALID_INPUT", "domain must be a non-empty string", { domain });
  }

  const expected = normalizeDid(expectedControllerDid);
  const host = `_omatrust.${domain.toLowerCase().replace(/\.$/, "")}`;

  let records: string[][];
  try {
    records = await resolveTxt(host);
  } catch (err) {
    throw new OmaTrustError("NETWORK_ERROR", "Failed to resolve DNS TXT records", { domain, err });
  }

  for (const recordParts of records) {
    const record = recordParts.join("");
    const parsed = parseDnsTxtRecord(record);
    if (parsed.version === "1" && parsed.controller && normalizeDid(parsed.controller) === expected) {
      return { valid: true, record };
    }
  }

  return { valid: false, reason: "No TXT record matched expected controller DID" };
}
