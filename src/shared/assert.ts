import { OmaTrustError } from "./errors";

export function assertString(value: unknown, name: string, code = "INVALID_INPUT"): asserts value is string {
  if (typeof value !== "string" || value.trim().length === 0) {
    throw new OmaTrustError(code, `${name} must be a non-empty string`, { value });
  }
}

export function assertNumber(value: unknown, name: string, code = "INVALID_INPUT"): asserts value is number {
  if (typeof value !== "number" || Number.isNaN(value)) {
    throw new OmaTrustError(code, `${name} must be a valid number`, { value });
  }
}

export function assertObject(value: unknown, name: string, code = "INVALID_INPUT"): asserts value is Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new OmaTrustError(code, `${name} must be an object`, { value });
  }
}

export function asError(err: unknown): Error {
  if (err instanceof Error) {
    return err;
  }
  return new Error(String(err));
}
