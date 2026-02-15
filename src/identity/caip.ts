import { OmaTrustError } from "../shared/errors";
import { assertString } from "../shared/assert";

export type Caip10 = string;

export type ParsedCaip10 = {
  namespace: string;
  reference: string;
  address: string;
};

export type ParsedCaip2 = {
  namespace: string;
  reference: string;
};

const CAIP_10_REGEX = /^(?<namespace>[a-z0-9-]+):(?<reference>[a-zA-Z0-9-]+):(?<address>.+)$/;
const CAIP_2_REGEX = /^(?<namespace>[a-z0-9-]+):(?<reference>[a-zA-Z0-9-]+)$/;

export function parseCaip10(input: string): ParsedCaip10 {
  assertString(input, "input", "INVALID_CAIP");
  const trimmed = input.trim();
  const match = trimmed.match(CAIP_10_REGEX);
  if (!match?.groups) {
    throw new OmaTrustError("INVALID_CAIP", "Invalid CAIP-10 format", { input });
  }

  const namespace = match.groups.namespace;
  const reference = match.groups.reference;
  const address = match.groups.address;

  if (!namespace || !reference || !address) {
    throw new OmaTrustError("INVALID_CAIP", "Invalid CAIP-10 components", { input });
  }

  return { namespace, reference, address };
}

export function buildCaip10(namespace: string, reference: string, address: string): Caip10 {
  assertString(namespace, "namespace", "INVALID_CAIP");
  assertString(reference, "reference", "INVALID_CAIP");
  assertString(address, "address", "INVALID_CAIP");
  return `${namespace}:${reference}:${address}`;
}

export function normalizeCaip10(input: string): Caip10 {
  const parsed = parseCaip10(input);
  const namespace = parsed.namespace.toLowerCase();
  const reference = parsed.reference;

  let address = parsed.address;
  if (namespace === "eip155") {
    address = address.toLowerCase();
  }

  return buildCaip10(namespace, reference, address);
}

export function buildCaip2(namespace: string, reference: string): string {
  assertString(namespace, "namespace", "INVALID_CAIP");
  assertString(reference, "reference", "INVALID_CAIP");
  return `${namespace}:${reference}`;
}

export function parseCaip2(caip2: string): ParsedCaip2 {
  assertString(caip2, "caip2", "INVALID_CAIP");
  const trimmed = caip2.trim();
  const match = trimmed.match(CAIP_2_REGEX);
  if (!match?.groups) {
    throw new OmaTrustError("INVALID_CAIP", "Invalid CAIP-2 format", { caip2 });
  }

  const namespace = match.groups.namespace;
  const reference = match.groups.reference;
  if (!namespace || !reference) {
    throw new OmaTrustError("INVALID_CAIP", "Invalid CAIP-2 components", { caip2 });
  }

  return { namespace, reference };
}
