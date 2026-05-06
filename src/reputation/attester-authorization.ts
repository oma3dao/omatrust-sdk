/**
 * Attester Authorization — verifies the time window during which an attester
 * was authorized to file subject-scoped attestations.
 *
 * This is the "read/verify" counterpart to requestControllerWitness (write).
 *
 * For did:web subjects:
 *   - Controller witness attestations (strongest durable evidence)
 *   - Key binding with purpose check
 *   - Live DNS TXT / did.json verification (current-point-in-time fallback)
 *
 * For did:pkh subjects (smart contracts):
 *   - Direct subject ownership check (owner/admin/EIP-1967)
 *   - Key binding with transfer proof verification
 */

import { didToAddress, getDomainFromDidWeb, extractDidMethod, extractAddressFromDid, isEvmDidPkh, getAddressFromDidPkh, getChainIdFromDidPkh } from "../identity/did";
import { parseCaip2 } from "../identity/caip";
import { EAS } from "@ethereum-attestation-service/eas-sdk";
import { Contract, getAddress } from "ethers";
import { OmaTrustError } from "../shared/errors";
import { fetchTrustAnchors, getChainAnchors } from "../shared/trust-anchors";
import { verifyDnsTxtControllerDid } from "./proof/dns-txt-shared";
import { verifyDidDocumentControllerDid } from "./proof/did-json";
import { discoverContractOwner, verifyTransferProof, type ContractOwnershipProvider } from "./contract-ownership";
import { decodeAttestationData } from "./encode";
import type {
  AttestationQueryResult,
  AttesterAuthorizationResult,
  ControllerWitnessEvidence,
  GetAttesterAuthorizationParams,
  Hex,
  W3CKeyPurpose,
} from "./types";

const DEFAULT_CHAIN = "eip155:6623";
const DEFAULT_PURPOSES: W3CKeyPurpose[] = ["authentication", "assertionMethod"];

/**
 * Determine the authorization window for an attester-subject pair.
 *
 * For did:web subjects, checks:
 * 1. On-chain controller-witness attestations (strongest evidence)
 * 2. On-chain key-binding revocation and purpose status
 * 3. Live DNS TXT / did.json verification (current-point-in-time fallback)
 *
 * For did:pkh subjects (smart contracts), checks:
 * 1. Direct subject ownership (attester is the contract owner/admin)
 * 2. Key binding with transfer proof verification
 *
 * Returns the authorization window so the consumer can filter attestations
 * by timestamp without repeated on-chain queries.
 */
export async function getAttesterAuthorization(
  params: GetAttesterAuthorizationParams
): Promise<AttesterAuthorizationResult> {
  const chain = params.chain ?? DEFAULT_CHAIN;
  const purposes = params.purpose && params.purpose.length > 0 ? params.purpose : DEFAULT_PURPOSES;

  // Fetch trust anchors once (cached after first call)
  const anchors = await fetchTrustAnchors();
  const chainAnchors = getChainAnchors(anchors, chain);

  // Resolve EAS contract address
  const easContractAddress = params.easContractAddress ?? (chainAnchors.easContract as Hex);

  // Resolve CAIP-2 reference for DID construction
  const parsed = parseCaip2(chain);

  const provider = params.provider as never;

  // Get schema UIDs from trust anchors (optional — chain may not have all schemas)
  const controllerWitnessSchemaUid = chainAnchors.schemas["controller-witness"] as Hex | undefined;
  const keyBindingSchemaUid = chainAnchors.schemas["key-binding"] as Hex | undefined;

  // Query controller-witness attestations where recipient = subject DID address
  const subjectAddress = didToAddress(params.subjectDid);
  const attesterLower = params.attester.toLowerCase();

  let relevantWitnesses: AttestationQueryResult[] = [];

  if (controllerWitnessSchemaUid) {
    const rawWitnesses = await queryByRecipientAndSchema(
      easContractAddress,
      provider,
      subjectAddress,
      [controllerWitnessSchemaUid],
      params.fromBlock ?? 0
    );

    // Filter to witnesses that reference this attester's address as the controller
    relevantWitnesses = rawWitnesses.filter((att) => {
      const controllerDid = att.data?.controller ?? att.data?.controllerDid;
      if (typeof controllerDid !== "string") return false;
      try {
        const controllerAddress = extractAddressFromDid(controllerDid);
        return controllerAddress.toLowerCase() === attesterLower;
      } catch {
        return false;
      }
    });

    // Sort by time ascending (oldest first)
    relevantWitnesses.sort((a, b) => Number(a.time - b.time));
  }

  // Build structured controller witness evidence
  const controllerWitnesses: ControllerWitnessEvidence[] = relevantWitnesses.map((att) => ({
    uid: att.uid,
    issuedAt: att.time,
    attester: att.attester,
    method: resolveWitnessMethod(att.data?.method),
  }));

  // Check key binding revocation and purpose
  let keyBindingUid: Hex | null = null;
  let until: bigint | null = null;
  let keyPurposeStatus: AttesterAuthorizationResult["keyPurposeStatus"] = "not-required";

  if (keyBindingSchemaUid) {
    const keyBindings = await queryByRecipientAndSchema(
      easContractAddress,
      provider,
      subjectAddress,
      [keyBindingSchemaUid],
      params.fromBlock ?? 0
    );

    // Find key bindings for this attester, take the latest one
    const relevantKeyBindings = keyBindings
      .filter((att) => {
        const boundAddress = att.data?.boundAddress ?? att.data?.wallet;
        if (typeof boundAddress === "string") {
          return boundAddress.toLowerCase() === attesterLower;
        }
        return att.attester.toLowerCase() === attesterLower;
      })
      .sort((a, b) => Number(b.time - a.time)); // newest first

    const relevantKeyBinding = relevantKeyBindings[0] ?? null;

    if (relevantKeyBinding) {
      keyBindingUid = relevantKeyBinding.uid;

      // Check revocation → sets `until`
      if (relevantKeyBinding.revocationTime > 0n) {
        until = relevantKeyBinding.revocationTime;
      }

      // Check key purpose (always an array)
      const keyPurposes = relevantKeyBinding.data?.keyPurpose;
      if (!Array.isArray(keyPurposes) || keyPurposes.length === 0) {
        keyPurposeStatus = "unknown";
      } else {
        const allMatched = purposes.every((p) => keyPurposes.includes(p));
        keyPurposeStatus = allMatched ? "matched" : "mismatch";
      }
    }
  }

  // Live DNS/did.json check (did:web) or contract ownership check (did:pkh)
  let currentlyVerified = false;
  let liveMethod: "dns" | "did-document" | "contract-ownership" | null = null;
  let transferProofVerified = false;
  let transferProofAnchor: bigint | null = null;

  const didMethod = extractDidMethod(params.subjectDid);
  if (didMethod === "web") {
    const domain = getDomainFromDidWeb(params.subjectDid);
    if (domain) {
      const controllerDid = `did:pkh:eip155:${parsed.reference}:${params.attester}`;

      // Try DNS TXT
      try {
        const dnsResult = await verifyDnsTxtControllerDid(domain, controllerDid, {
          resolveTxt: params.resolveTxt,
        });
        if (dnsResult.valid) {
          currentlyVerified = true;
          liveMethod = "dns";
        }
      } catch {
        // DNS check failed
      }

      // Try did.json if DNS didn't work
      if (!currentlyVerified) {
        try {
          const fetchDoc = params.fetchDidDocument ?? defaultFetchDidDocument;
          const didDoc = await fetchDoc(domain);
          const didJsonResult = verifyDidDocumentControllerDid(didDoc, controllerDid);
          if (didJsonResult.valid) {
            currentlyVerified = true;
            liveMethod = "did-document";
          }
        } catch {
          // did.json check failed
        }
      }
    }
  } else if (didMethod === "pkh" && isEvmDidPkh(params.subjectDid)) {
    // For did:pkh subjects: check direct contract ownership, then key binding transfer proof
    const subjectContractAddress = getAddressFromDidPkh(params.subjectDid);
    const chainIdStr = getChainIdFromDidPkh(params.subjectDid);
    const chainId = chainIdStr ? Number(chainIdStr) : null;

    if (subjectContractAddress && chainId) {
      // Check if the attester directly owns the contract (simple case)
      const ownerAddress = await discoverContractOwner(
        provider as unknown as ContractOwnershipProvider,
        subjectContractAddress
      );

      if (ownerAddress && getAddress(ownerAddress) === getAddress(params.attester)) {
        currentlyVerified = true;
        liveMethod = "contract-ownership";
      }

      // If not the direct owner, check key binding transfer proof
      if (!currentlyVerified && keyBindingUid) {
        // Find the key binding attestation data to look for a transfer proof
        const relevantKeyBinding = await findKeyBindingWithTransferProof(
          keyBindingSchemaUid!,
          easContractAddress,
          provider,
          subjectAddress,
          attesterLower,
          params.fromBlock ?? 0
        );

        if (relevantKeyBinding) {
          const proofTxHash = relevantKeyBinding.data?.proofTxHash as string | undefined;
          if (proofTxHash && /^0x[0-9a-fA-F]{64}$/.test(proofTxHash)) {
            // Verify the transfer proof: tx must be from the contract owner to the attester
            // with the deterministic proof amount
            const verified = await verifyTransferProof(
              provider as unknown as ContractOwnershipProvider,
              proofTxHash as Hex,
              params.subjectDid,
              params.attester,
              chainId
            );
            if (verified) {
              transferProofVerified = true;
              // Use the key binding attestation time as the anchor —
              // the transfer happened before the key binding was filed,
              // so this is a conservative (later) bound.
              transferProofAnchor = relevantKeyBinding.time;
            }
          }
        }
      }
    }
  }

  // Build result
  // anchoredFrom: earliest durable evidence timestamp
  // - Controller witnesses (did:web): time of first witness
  // - Transfer proof (did:pkh): time of key binding attestation (conservative bound)
  const witnessAnchor = relevantWitnesses.length > 0 ? relevantWitnesses[0].time : null;
  const anchoredFrom = witnessAnchor ?? transferProofAnchor;

  // Determine authorization:
  // - Has controller witnesses and window is not closed → authorized
  // - No witnesses but currently verified via DNS/did.json/contract-ownership → authorized
  // - Key binding with verified transfer proof and window not closed → authorized
  // - Key purpose mismatch disqualifies even if witnesses exist
  const purposeBlocks = keyPurposeStatus === "mismatch";
  const hasOpenWindow = relevantWitnesses.length > 0 && until === null;
  const hasKeyBindingWithProof = keyBindingUid !== null && transferProofVerified && until === null;
  const authorized = !purposeBlocks && (
    hasOpenWindow ||
    (currentlyVerified && until === null) ||
    hasKeyBindingWithProof
  );

  return {
    authorized,
    anchoredFrom,
    until,
    currentlyVerified,
    liveMethod,
    controllerWitnesses,
    keyBindingUid,
    keyPurposeStatus,
    transferProofVerified: transferProofVerified || undefined,
  };
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

const EAS_EVENT_ABI = [
  "event Attested(address indexed recipient, address indexed attester, bytes32 uid, bytes32 indexed schemaUID)",
];

function resolveWitnessMethod(
  value: unknown
): ControllerWitnessEvidence["method"] {
  if (typeof value !== "string") return undefined;
  switch (value) {
    case "dns":
    case "dns-txt":
      return "dns";
    case "did-document":
    case "did-json":
      return "did-document";
    case "manual":
      return "manual";
    default:
      return "other";
  }
}

async function queryByRecipientAndSchema(
  easContractAddress: Hex,
  provider: never,
  recipient: string,
  schemas: Hex[],
  fromBlock: number
): Promise<AttestationQueryResult[]> {
  const contract = new Contract(easContractAddress, EAS_EVENT_ABI, provider);
  const filter = contract.filters.Attested(recipient, null);

  const toBlock = await (
    provider as unknown as { getBlockNumber: () => Promise<number> }
  ).getBlockNumber();

  let events;
  try {
    events = await contract.queryFilter(filter, fromBlock, toBlock);
  } catch (err) {
    throw new OmaTrustError("NETWORK_ERROR", "Failed to query attestation events", { err });
  }

  const eas = new EAS(easContractAddress);
  eas.connect(provider);

  const schemaFilter = schemas.map((s) => s.toLowerCase());
  const results: AttestationQueryResult[] = [];

  for (const event of events) {
    if (!("args" in event) || !Array.isArray(event.args)) continue;
    const args = event.args as unknown[];
    const uid = args?.[2] as Hex | undefined;
    const schemaUid = args?.[3] as Hex | undefined;

    if (!uid || !schemaUid) continue;
    if (!schemaFilter.includes(schemaUid.toLowerCase())) continue;

    const attestation = (await eas.getAttestation(uid)) as unknown as Record<string, unknown> | null;
    if (!attestation || !attestation.uid) continue;

    // Decode attestation data
    let data: Record<string, unknown> = {};
    const rawData = attestation.data as Hex | undefined;
    if (rawData && rawData !== "0x") {
      try {
        data = decodeAttestationData(
          "string subject, string controller, string method",
          rawData
        );
      } catch {
        try {
          data = decodeAttestationData(
            "string subject, address boundAddress, string[] keyPurpose",
            rawData
          );
        } catch {
          try {
            data = decodeAttestationData(
              "string subject, address boundAddress",
              rawData
            );
          } catch {
            // Leave data empty
          }
        }
      }
    }

    const toBigIntSafe = (value: unknown): bigint => {
      if (typeof value === "bigint") return value;
      if (typeof value === "number") return BigInt(value);
      if (typeof value === "string" && value.length > 0) return BigInt(value);
      return 0n;
    };

    results.push({
      uid: attestation.uid as Hex,
      schema: attestation.schema as Hex,
      attester: attestation.attester as Hex,
      recipient: attestation.recipient as Hex,
      revocable: Boolean(attestation.revocable),
      revocationTime: toBigIntSafe(attestation.revocationTime),
      expirationTime: toBigIntSafe(attestation.expirationTime),
      time: toBigIntSafe(attestation.time),
      refUID: attestation.refUID as Hex,
      data,
    });
  }

  return results;
}

async function defaultFetchDidDocument(domain: string): Promise<Record<string, unknown>> {
  const url = `https://${domain}/.well-known/did.json`;
  let res: Response;
  try {
    res = await fetch(url);
  } catch (err) {
    throw new OmaTrustError("NETWORK_ERROR", "Failed to fetch DID document", { domain, err });
  }
  if (!res.ok) {
    throw new OmaTrustError("NETWORK_ERROR", `DID document fetch failed: ${res.status}`, { domain });
  }
  return (await res.json()) as Record<string, unknown>;
}

/**
 * Find the key binding attestation that includes a transfer proof for this attester.
 */
async function findKeyBindingWithTransferProof(
  keyBindingSchemaUid: Hex,
  easContractAddress: Hex,
  provider: never,
  subjectAddress: string,
  attesterLower: string,
  fromBlock: number
): Promise<AttestationQueryResult | null> {
  const keyBindings = await queryByRecipientAndSchema(
    easContractAddress,
    provider,
    subjectAddress,
    [keyBindingSchemaUid],
    fromBlock
  );

  // Find key bindings for this attester that have a proofTxHash
  const withProof = keyBindings
    .filter((att) => {
      const boundAddress = att.data?.boundAddress ?? att.data?.wallet;
      const matchesAttester = typeof boundAddress === "string"
        ? boundAddress.toLowerCase() === attesterLower
        : att.attester.toLowerCase() === attesterLower;
      return matchesAttester && typeof att.data?.proofTxHash === "string";
    })
    .sort((a, b) => Number(b.time - a.time)); // newest first

  return withProof[0] ?? null;
}
