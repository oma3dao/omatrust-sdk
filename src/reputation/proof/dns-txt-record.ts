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
