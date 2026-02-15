import type { RegistryStatus } from "./types";
import { OmaTrustError } from "../shared/errors";

export function registryCodeToStatus(code: number): RegistryStatus {
  switch (code) {
    case 0:
      return "Active";
    case 1:
      return "Deprecated";
    case 2:
      return "Replaced";
    default:
      throw new OmaTrustError("INVALID_INPUT", "Invalid registry status code", { code });
  }
}

export function registryStatusToCode(status: RegistryStatus): number {
  switch (status) {
    case "Active":
      return 0;
    case "Deprecated":
      return 1;
    case "Replaced":
      return 2;
    default:
      throw new OmaTrustError("INVALID_INPUT", "Invalid registry status", { status });
  }
}

export function isValidRegistryStatus(status: string): status is RegistryStatus {
  return status === "Active" || status === "Deprecated" || status === "Replaced";
}
