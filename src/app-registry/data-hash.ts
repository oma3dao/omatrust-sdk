import { keccak256, sha256, toUtf8Bytes } from "ethers";
import { canonicalizeJson } from "../identity/data";
import { OmaTrustError } from "../shared/errors";

type Hex = `0x${string}`;
export type DataHashAlgorithm = "keccak256" | "sha256";

async function fetchJson(url: string): Promise<unknown> {
  let response: Response;
  try {
    response = await fetch(url, { headers: { Accept: "application/json" } });
  } catch (err) {
    throw new OmaTrustError("NETWORK_ERROR", "Failed to fetch data URL", { url, err });
  }

  if (!response.ok) {
    throw new OmaTrustError("NETWORK_ERROR", "Failed to fetch data URL", {
      url,
      status: response.status
    });
  }

  try {
    return await response.json();
  } catch (err) {
    throw new OmaTrustError("INVALID_INPUT", "Response body is not valid JSON", { url, err });
  }
}

function hashJcs(jcsJson: string, algorithm: DataHashAlgorithm): Hex {
  const bytes = toUtf8Bytes(jcsJson);
  return (algorithm === "keccak256" ? keccak256(bytes) : sha256(bytes)) as Hex;
}

export async function computeDataHashFromUrl(
  url: string,
  algorithm: DataHashAlgorithm
): Promise<Hex> {
  if (!url || typeof url !== "string") {
    throw new OmaTrustError("INVALID_INPUT", "url must be a non-empty string", { url });
  }

  const json = await fetchJson(url);
  const jcsJson = canonicalizeJson(json);
  return hashJcs(jcsJson, algorithm);
}

export async function verifyDataUrlHash(
  url: string,
  expectedHash: Hex,
  algorithm: DataHashAlgorithm
): Promise<boolean> {
  const computedHash = await computeDataHashFromUrl(url, algorithm);
  return computedHash.toLowerCase() === expectedHash.toLowerCase();
}
