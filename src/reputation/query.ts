import { EAS } from "@ethereum-attestation-service/eas-sdk";
import { Contract } from "ethers";
import { didToAddress } from "../identity/did";
import { decodeAttestationData } from "./encode";
import { OmaTrustError } from "../shared/errors";
import type {
  AttestationQueryResult,
  GetAttestationParams,
  Hex,
  ListAttestationsParams,
  SchemaField
} from "./types";

const EAS_EVENT_ABI = [
  "event Attested(address indexed recipient, address indexed attester, bytes32 uid, bytes32 indexed schemaUID)"
];

function parseEventTxHash(event: unknown): Hex | undefined {
  const txHash = (event as { transactionHash?: unknown }).transactionHash;
  if (typeof txHash !== "string") {
    return undefined;
  }
  return /^0x[0-9a-fA-F]{64}$/.test(txHash) ? (txHash as Hex) : undefined;
}

function parseAttestation(
  attestation: Record<string, unknown>,
  schema?: SchemaField[] | string,
  txHash?: Hex
): AttestationQueryResult {
  const rawData = (attestation.data as Hex | undefined) ?? ("0x" as Hex);
  const decoded = schema ? decodeAttestationData(schema, rawData) : {};
  const toBigIntSafe = (value: unknown): bigint => {
    if (typeof value === "bigint") {
      return value;
    }
    if (typeof value === "number") {
      return BigInt(value);
    }
    if (typeof value === "string" && value.length > 0) {
      return BigInt(value);
    }
    return 0n;
  };

  return {
    uid: attestation.uid as Hex,
    schema: attestation.schema as Hex,
    attester: attestation.attester as Hex,
    recipient: attestation.recipient as Hex,
    txHash,
    revocable: Boolean(attestation.revocable),
    revocationTime: toBigIntSafe(attestation.revocationTime),
    expirationTime: toBigIntSafe(attestation.expirationTime),
    time: toBigIntSafe(attestation.time),
    refUID: attestation.refUID as Hex,
    data: decoded,
    raw: schema ? undefined : rawData
  };
}

export async function getAttestation(
  params: GetAttestationParams
): Promise<AttestationQueryResult> {
  try {
    const eas = new EAS(params.easContractAddress);
    eas.connect(params.provider as never);
    const attestation = (await eas.getAttestation(params.uid)) as unknown as Record<string, unknown> | null;

    if (!attestation || !attestation.uid || String(attestation.uid) === "0x".padEnd(66, "0")) {
      throw new OmaTrustError("ATTESTATION_NOT_FOUND", "Attestation not found", { uid: params.uid });
    }

    return parseAttestation(attestation, params.schema);
  } catch (err) {
    if (err instanceof OmaTrustError) {
      throw err;
    }
    throw new OmaTrustError("NETWORK_ERROR", "Failed to read attestation", { err });
  }
}

export async function getAttestationsForDid(
  params: ListAttestationsParams
): Promise<AttestationQueryResult[]> {
  const provider = params.provider as never;
  const contract = new Contract(params.easContractAddress, EAS_EVENT_ABI, provider);

  const toBlock = params.toBlock ?? (await (provider as { getBlockNumber: () => Promise<number> }).getBlockNumber());
  const fromBlock = params.fromBlock ?? Math.max(0, toBlock - 50_000);
  const filter = contract.filters.Attested(didToAddress(params.did));

  let events;
  try {
    events = await contract.queryFilter(filter, fromBlock, toBlock);
  } catch (err) {
    throw new OmaTrustError("NETWORK_ERROR", "Failed to query attestation events", { err });
  }

  const eas = new EAS(params.easContractAddress);
  eas.connect(provider);

  const schemaFilter = params.schemas?.map((schema) => schema.toLowerCase());
  const results: AttestationQueryResult[] = [];

  for (const event of events) {
    if (!(("args" in event) && Array.isArray(event.args))) {
      continue;
    }
    const args = event.args as unknown[];
    const uid = args?.[2] as Hex | undefined;
    const schemaUid = args?.[3] as Hex | undefined;

    if (!uid || !schemaUid) {
      continue;
    }

    if (schemaFilter && !schemaFilter.includes(schemaUid.toLowerCase())) {
      continue;
    }

    const attestation = (await eas.getAttestation(uid)) as unknown as Record<string, unknown> | null;
    if (!attestation || !attestation.uid) {
      continue;
    }

    results.push(parseAttestation(attestation, undefined, parseEventTxHash(event)));
  }

  results.sort((a, b) => Number(b.time - a.time));
  return results;
}

export async function listAttestations(
  params: ListAttestationsParams
): Promise<AttestationQueryResult[]> {
  const limit = params.limit ?? 20;
  if (limit <= 0) {
    return [];
  }

  const results = await getAttestationsForDid(params);
  return results.slice(0, limit);
}

export type GetLatestAttestationsParams = {
  provider: unknown;
  easContractAddress: Hex;
  schemas?: Hex[];
  limit?: number;
  fromBlock?: number;
};

export async function getLatestAttestations(
  params: GetLatestAttestationsParams
): Promise<AttestationQueryResult[]> {
  const provider = params.provider as never;
  const contract = new Contract(params.easContractAddress, EAS_EVENT_ABI, provider);

  const currentBlock = await (provider as { getBlockNumber: () => Promise<number> }).getBlockNumber();
  const fromBlock = params.fromBlock ?? Math.max(0, currentBlock - 50_000);
  const events = await contract.queryFilter(contract.filters.Attested(), fromBlock, currentBlock);

  const eas = new EAS(params.easContractAddress);
  eas.connect(provider);

  const schemaFilter = params.schemas?.map((schema) => schema.toLowerCase());
  const results: AttestationQueryResult[] = [];

  for (const event of events) {
    if (!(("args" in event) && Array.isArray(event.args))) {
      continue;
    }
    const args = event.args as unknown[];
    const uid = args?.[2] as Hex | undefined;
    const schemaUid = args?.[3] as Hex | undefined;
    if (!uid || !schemaUid) {
      continue;
    }

    if (schemaFilter && !schemaFilter.includes(schemaUid.toLowerCase())) {
      continue;
    }

    const attestation = (await eas.getAttestation(uid)) as unknown as Record<string, unknown> | null;
    if (!attestation || !attestation.uid) {
      continue;
    }

    results.push(parseAttestation(attestation, undefined, parseEventTxHash(event)));
  }

  results.sort((a, b) => Number(b.time - a.time));
  return results.slice(0, params.limit ?? 20);
}

export function deduplicateReviews(attestations: AttestationQueryResult[]): AttestationQueryResult[] {
  const seen = new Map<string, AttestationQueryResult>();

  for (const attestation of attestations) {
    const subject = String(attestation.data.subject ?? "");
    const version = String(attestation.data.version ?? "");
    const major = getMajorVersion(version);
    const key = `${attestation.attester.toLowerCase()}|${subject}|${major}`;

    if (!seen.has(key)) {
      seen.set(key, attestation);
      continue;
    }

    const current = seen.get(key)!;
    if (attestation.time > current.time) {
      seen.set(key, attestation);
    }
  }

  return [...seen.values()];
}

export function calculateAverageUserReviewRating(attestations: AttestationQueryResult[]): number {
  const deduped = deduplicateReviews(attestations);
  const ratings = deduped
    .map((attestation) => attestation.data.ratingValue)
    .filter((value) => typeof value === "number" || typeof value === "bigint")
    .map((value) => Number(value));

  if (ratings.length === 0) {
    return 0;
  }

  const total = ratings.reduce((sum, value) => sum + value, 0);
  return total / ratings.length;
}

export function getMajorVersion(version: string): number {
  const match = version.match(/^(\d+)/);
  if (!match) {
    throw new OmaTrustError("INVALID_INPUT", "Invalid semantic version", { version });
  }
  return Number(match[1]);
}
