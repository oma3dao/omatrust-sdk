/**
 * Controller Authorization — verifies the time window during which a controller
 * was authorized for a subject DID.
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
 *   - NOTE: Only EVM chains are currently supported for contract ownership checks.
 *     Non-EVM did:pkh subjects (e.g. Solana) will need chain-specific verification.
 */

import { didToAddress, getDomainFromDidWeb, extractDidMethod, isEvmDidPkh, getAddressFromDidPkh, getChainIdFromDidPkh, normalizeDid } from "../identity/did";
import { isSameControllerId, extractControllerEvmAddress } from "../identity/controller-id";
import { didJwkToJwk, publicJwkEquals } from "../identity/jwk";
import { EAS } from "@ethereum-attestation-service/eas-sdk";
import { Contract, getAddress } from "ethers";
import { OmaTrustError } from "../shared/errors";
import { fetchTrustAnchors, getChainAnchors } from "../shared/trust-anchors";
import { fetchDidDocument } from "../shared/did-document";
import { verifyDnsTxtControllerDid } from "./proof/dns-txt-shared";
import { verifyDidDocumentControllerDid } from "./proof/did-json";
import { discoverContractOwner, verifyTransferProof, type ContractOwnershipProvider } from "./contract-ownership";
import { decodeAttestationData } from "./encode";
import type {
  AttestationQueryResult,
  ControllerAuthorizationResult,
  ControllerWitnessEvidence,
  GetControllerAuthorizationParams,
  Hex,
  W3CKeyPurpose,
} from "./types";

const DEFAULT_CHAIN = "eip155:6623";
const DEFAULT_PURPOSES: W3CKeyPurpose[] = ["authentication", "assertionMethod"];

/**
 * Determine the authorization window for a controller-subject pair.
 *
 * For did:web subjects, checks:
 * 1. On-chain controller-witness attestations (strongest evidence)
 * 2. On-chain key-binding revocation and purpose status
 * 3. Live DNS TXT / did.json verification (current-point-in-time fallback)
 *
 * For did:pkh subjects (smart contracts), checks:
 * 1. Direct subject ownership (controller is the contract owner/admin)
 * 2. Key binding with transfer proof verification
 *
 * Returns the authorization window so the consumer can filter attestations
 * by timestamp without repeated on-chain queries.
 */
export async function getControllerAuthorization(
  params: GetControllerAuthorizationParams
): Promise<ControllerAuthorizationResult> {
  const chain = params.chain ?? DEFAULT_CHAIN;
  const purposes = params.purpose && params.purpose.length > 0 ? params.purpose : DEFAULT_PURPOSES;

  // Normalize the controller DID for consistent matching
  const controllerDid = normalizeDid(params.controllerDid);
  const controllerMethod = extractDidMethod(controllerDid);

  // Extract an EVM address from the controller DID when possible (did:pkh:eip155 only)
  const controllerEvmAddress = extractControllerEvmAddress(controllerDid);

  // Fetch trust anchors once (cached after first call)
  const anchors = await fetchTrustAnchors();
  const chainAnchors = getChainAnchors(anchors, chain);

  // Resolve EAS contract address
  const easContractAddress = params.easContractAddress ?? (chainAnchors.easContract as Hex);

  const provider = params.provider as never;

  // Get schema UIDs from trust anchors (optional — chain may not have all schemas)
  const controllerWitnessSchemaUid = chainAnchors.schemas["controller-witness"] as Hex | undefined;
  const keyBindingSchemaUid = chainAnchors.schemas["key-binding"] as Hex | undefined;

  // Query controller-witness attestations where recipient = subject DID address
  const subjectAddress = didToAddress(params.subjectDid);

  let relevantWitnesses: AttestationQueryResult[] = [];

  if (controllerWitnessSchemaUid) {
    const rawWitnesses = await queryByRecipientAndSchema(
      easContractAddress,
      provider,
      subjectAddress,
      [controllerWitnessSchemaUid],
      params.fromBlock ?? 0
    );

    // Filter to witnesses that reference this controller DID
    relevantWitnesses = rawWitnesses.filter((att) => {
      const witnessController = att.data?.controller;
      if (typeof witnessController !== "string") return false;
      return isSameControllerId(witnessController, controllerDid);
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
  let keyPurposeStatus: ControllerAuthorizationResult["keyPurposeStatus"] = "not-required";

  if (keyBindingSchemaUid) {
    const keyBindings = await queryByRecipientAndSchema(
      easContractAddress,
      provider,
      subjectAddress,
      [keyBindingSchemaUid],
      params.fromBlock ?? 0
    );

    // Find key bindings for this controller by matching keyId or publicKeyJwk
    const relevantKeyBindings = keyBindings
      .filter((att) => controllerMatchesKeyBinding(att, controllerDid, controllerMethod))
      .sort((a, b) => Number(b.time - a.time)); // newest first

    const relevantKeyBinding = relevantKeyBindings[0] ?? null;

    if (relevantKeyBinding) {
      keyBindingUid = relevantKeyBinding.uid;

      // Check revocation → sets `until`
      if (relevantKeyBinding.revocationTime > 0n) {
        until = relevantKeyBinding.revocationTime;
      }

      // Check key purpose
      const keyPurposes = relevantKeyBinding.data?.keyPurpose;
      if (!Array.isArray(keyPurposes) || keyPurposes.length === 0) {
        keyPurposeStatus = "unknown";
      } else {
        const allMatched = purposes.every((p) => keyPurposes.includes(p));
        keyPurposeStatus = allMatched ? "matched" : "mismatch";
      }
    }
  }

  // Live DNS/did.json check (did:web subjects) or contract ownership check (did:pkh subjects)
  let currentlyVerified = false;
  let liveMethod: "dns" | "did-document" | "contract-ownership" | null = null;
  let transferProofVerified = false;
  let transferProofAnchor: bigint | null = null;

  const subjectMethod = extractDidMethod(params.subjectDid);
  if (subjectMethod === "web") {
    const domain = getDomainFromDidWeb(params.subjectDid);
    if (domain) {
      // Try DNS TXT — pass the controllerDid directly
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
          const fetchDoc = params.fetchDidDocument ?? fetchDidDocument;
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
  } else if (subjectMethod === "pkh") {
    if (isEvmDidPkh(params.subjectDid) && controllerEvmAddress) {
      // EVM contract ownership check
      const subjectContractAddress = getAddressFromDidPkh(params.subjectDid);
      const subjectChainId = getChainIdFromDidPkh(params.subjectDid);
      const chainIdNum = subjectChainId ? Number(subjectChainId) : null;

      if (subjectContractAddress && chainIdNum) {
        // Check if the controller directly owns the contract
        const ownerAddress = await discoverContractOwner(
          provider as unknown as ContractOwnershipProvider,
          subjectContractAddress
        );

        if (ownerAddress && getAddress(ownerAddress) === getAddress(controllerEvmAddress)) {
          currentlyVerified = true;
          liveMethod = "contract-ownership";
        }

        // If not the direct owner, check key binding transfer proof
        if (!currentlyVerified && keyBindingUid) {
          const relevantKeyBinding = await findKeyBindingWithTransferProof(
            keyBindingSchemaUid!,
            easContractAddress,
            provider,
            subjectAddress,
            controllerDid,
            controllerMethod,
            params.fromBlock ?? 0
          );

          if (relevantKeyBinding) {
            const proofTxHash = relevantKeyBinding.data?.proofTxHash as string | undefined;
            if (proofTxHash && /^0x[0-9a-fA-F]{64}$/.test(proofTxHash)) {
              const verified = await verifyTransferProof(
                provider as unknown as ContractOwnershipProvider,
                proofTxHash as Hex,
                params.subjectDid,
                controllerEvmAddress,
                chainIdNum
              );
              if (verified) {
                transferProofVerified = true;
                transferProofAnchor = relevantKeyBinding.time;
              }
            }
          }
        }
      }
    } else {
      // TODO: Non-EVM did:pkh subjects (e.g. Solana) need chain-specific
      // ownership verification. For now, these subjects cannot be verified
      // via contract ownership or transfer proof. Controller witnesses and
      // key bindings still apply.
    }
  }

  // Build result
  const witnessAnchor = relevantWitnesses.length > 0 ? relevantWitnesses[0].time : null;
  const anchoredFrom = witnessAnchor ?? transferProofAnchor;

  // Authorization requires at least one of:
  // - Controller witnesses with open window
  // - Live verification (DNS/did.json/contract-ownership)
  // - Key binding with verified transfer proof
  // Key purpose mismatch blocks authorization regardless.
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

/**
 * Check if a key binding attestation matches the requested controller DID.
 *
 * Matches by:
 * 1. keyId field — uses isSameControllerId for DID comparison
 * 2. publicKeyJwk field — for did:jwk controllers, compare the JWK material
 */
function controllerMatchesKeyBinding(
  att: AttestationQueryResult,
  controllerDid: string,
  controllerMethod: string | null
): boolean {
  const keyId = att.data?.keyId;

  // Match by keyId (DID comparison via isSameControllerId)
  if (typeof keyId === "string") {
    if (isSameControllerId(keyId, controllerDid)) {
      return true;
    }
  }

  // Match by publicKeyJwk (for did:jwk controllers)
  if (controllerMethod === "jwk") {
    const publicKeyJwkRaw = att.data?.publicKeyJwk;
    if (publicKeyJwkRaw) {
      try {
        const onChainJwk = typeof publicKeyJwkRaw === "string"
          ? JSON.parse(publicKeyJwkRaw)
          : publicKeyJwkRaw;
        const controllerJwk = didJwkToJwk(controllerDid);
        return publicJwkEquals(onChainJwk, controllerJwk);
      } catch {
        // JWK parsing or comparison failed
      }
    }
  }

  return false;
}

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

    // Decode attestation data — try controller-witness schema first, then key-binding
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
            "string subject, string keyId, string publicKeyJwk, string[] keyPurpose, string[] proofs, uint256 issuedAt, uint256 effectiveAt, uint256 expiresAt",
            rawData
          );
        } catch {
          // Leave data empty — unknown schema format
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

/**
 * Find the key binding attestation that includes a transfer proof for this controller.
 */
async function findKeyBindingWithTransferProof(
  keyBindingSchemaUid: Hex,
  easContractAddress: Hex,
  provider: never,
  subjectAddress: string,
  controllerDid: string,
  controllerMethod: string | null,
  fromBlock: number
): Promise<AttestationQueryResult | null> {
  const keyBindings = await queryByRecipientAndSchema(
    easContractAddress,
    provider,
    subjectAddress,
    [keyBindingSchemaUid],
    fromBlock
  );

  // Find key bindings for this controller that have a proofTxHash in proofs
  const withProof = keyBindings
    .filter((att) => {
      if (!controllerMatchesKeyBinding(att, controllerDid, controllerMethod)) return false;
      // Check if proofs contain a transaction hash
      const proofs = att.data?.proofs;
      if (Array.isArray(proofs)) {
        return proofs.some((p) => typeof p === "string" && /^0x[0-9a-fA-F]{64}$/.test(p));
      }
      return typeof att.data?.proofTxHash === "string";
    })
    .sort((a, b) => Number(b.time - a.time)); // newest first

  return withProof[0] ?? null;
}
