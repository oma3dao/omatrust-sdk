import canonicalize from "canonicalize";
import { keccak256, sha256, toUtf8Bytes } from "ethers";
import { OmaTrustError } from "../shared/errors";

type Hex = `0x${string}`;

export function canonicalizeJson(obj: unknown): string {
  const jcs = canonicalize(obj);
  if (!jcs) {
    throw new OmaTrustError("INVALID_INPUT", "Object cannot be canonicalized", { obj });
  }
  return jcs;
}

export function canonicalizeForHash(obj: unknown): { jcsJson: string; hash: Hex } {
  const jcsJson = canonicalizeJson(obj);
  return {
    jcsJson,
    hash: keccak256(toUtf8Bytes(jcsJson)) as Hex
  };
}

export function hashCanonicalizedJson(obj: unknown, algorithm: "keccak256" | "sha256"): Hex {
  const jcs = canonicalizeJson(obj);
  const bytes = toUtf8Bytes(jcs);
  return (algorithm === "keccak256" ? keccak256(bytes) : sha256(bytes)) as Hex;
}
