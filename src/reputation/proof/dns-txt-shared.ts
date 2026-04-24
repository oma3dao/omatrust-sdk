import { normalizeDid } from "../../identity/did";
import { OmaTrustError } from "../../shared/errors";
import type { Did } from "../types";
import { parseDnsTxtRecord } from "./dns-txt-record";

export interface VerifyDnsTxtControllerDidOptions {
  resolveTxt?: (host: string) => Promise<string[][]>;
  recordPrefix?: string;
}

export async function verifyDnsTxtControllerDid(
  domain: string,
  expectedControllerDid: Did,
  options: VerifyDnsTxtControllerDidOptions = {}
): Promise<{ valid: boolean; record?: string; reason?: string }> {
  if (!domain || typeof domain !== "string") {
    throw new OmaTrustError("INVALID_INPUT", "domain must be a non-empty string", { domain });
  }

  if (!options.resolveTxt) {
    throw new OmaTrustError("NETWORK_ERROR", "No DNS TXT resolver was provided", { domain });
  }

  const expected = normalizeDid(expectedControllerDid);
  const prefix = options.recordPrefix ?? "_controllers";
  const host = `${prefix}.${domain.toLowerCase().replace(/\.$/, "")}`;

  let records: string[][];
  try {
    records = await options.resolveTxt(host);
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
