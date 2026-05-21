import { normalizeDid } from "../../identity/did";
import { OmaTrustError } from "../../shared/errors";
import type { Did } from "../types";

export interface DnsTxtRecordResult {
  version?: string;
  /**
   * @deprecated Use `controllers` instead. This field only returns the first
   * controller value and will be removed in a future release.
   */
  controller?: Did;
  /**
   * All controller DIDs found in the record.
   * A DNS TXT record may contain multiple controller= entries.
   */
  controllers: Did[];
}

export function parseDnsTxtRecord(record: string): DnsTxtRecordResult {
  if (!record || typeof record !== "string") {
    throw new OmaTrustError("INVALID_INPUT", "record must be a non-empty string", { record });
  }

  const entries = record
    .split(/[;\s]+/)
    .map((entry) => entry.trim())
    .filter(Boolean);

  const parsed: Record<string, string | undefined> = {};
  const controllers: Did[] = [];

  for (const entry of entries) {
    const eqIndex = entry.indexOf("=");
    if (eqIndex === -1) continue;
    const key = entry.slice(0, eqIndex).trim();
    const value = entry.slice(eqIndex + 1).trim();
    if (!key || !value) continue;

    if (key === "controller") {
      controllers.push(value);
    } else {
      parsed[key] = value;
    }
  }

  return {
    version: parsed.v,
    controller: controllers[0],
    controllers,
  };
}

export function buildDnsTxtRecord(controllerDid: Did): string {
  const normalized = normalizeDid(controllerDid);
  return `v=1;controller=${normalized}`;
}
