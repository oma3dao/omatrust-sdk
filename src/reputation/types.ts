export type Hex = `0x${string}`;
export type Did = string;

export type ProofType =
  | "pop-jws"
  | "pop-eip712"
  | "x402-receipt"
  | "evidence-pointer"
  | "tx-encoded-value"
  | "tx-interaction"
  | "x402-offer";

export type ProofPurpose = "shared-control" | "commercial-tx";

export type SchemaField = {
  name: string;
  type: string;
  value?: unknown;
};

export type AttestationValidationError = {
  schemaFieldName: string;
  expectedType: string;
  providedType: string;
  providedValue: unknown;
};

export type AttestationQueryResult = {
  uid: Hex;
  schema: Hex;
  attester: Hex;
  recipient: Hex;
  txHash?: Hex;
  revocable: boolean;
  revocationTime: bigint;
  expirationTime: bigint;
  time: bigint;
  refUID: Hex;
  data: Record<string, unknown>;
  raw?: Hex;
};

export type ProofWrapper = {
  proofType: ProofType;
  proofObject: unknown;
  proofPurpose?: ProofPurpose;
  version?: number;
  issuedAt?: number;
  expiresAt?: number;
};

export type TxEncodedValueProof = ProofWrapper & {
  proofType: "tx-encoded-value";
  proofPurpose: ProofPurpose;
  proofObject: {
    chainId: string;
    txHash: Hex;
  };
};

export type TxInteractionProof = ProofWrapper & {
  proofType: "tx-interaction";
  proofPurpose: "commercial-tx";
  proofObject: {
    chainId: string;
    txHash: Hex;
  };
};

export type PopEip712Proof = ProofWrapper & {
  proofType: "pop-eip712";
  proofObject: {
    domain: { name: string; version: string; chainId: number; verifyingContract?: Hex };
    message: {
      signer: string;
      authorizedEntity: string;
      signingPurpose: string;
      creationTimestamp: number;
      expirationTimestamp: number;
      randomValue: Hex;
      statement: string;
    };
    signature: Hex;
  };
};

export type PopJwsProof = ProofWrapper & {
  proofType: "pop-jws";
  proofObject: string;
};

export type X402ReceiptProof = ProofWrapper & {
  proofType: "x402-receipt";
  proofPurpose: "commercial-tx";
  proofObject: Record<string, unknown>;
};

export type X402OfferProof = ProofWrapper & {
  proofType: "x402-offer";
  proofPurpose: "commercial-tx";
  proofObject: Record<string, unknown>;
};

export type EvidencePointerProof = ProofWrapper & {
  proofType: "evidence-pointer";
  proofPurpose: "shared-control";
  proofObject: {
    url: string;
  };
};

export type ChainConstants = {
  base: bigint;
  range: bigint;
  decimals: number;
  nativeSymbol: string;
};

export type SubmitAttestationParams = {
  signer: unknown;
  chainId: number;
  easContractAddress: Hex;
  schemaUid: Hex;
  schema: SchemaField[] | string;
  data: Record<string, unknown>;
  revocable?: boolean;
  expirationTime?: bigint | number;
  refUid?: Hex;
  value?: bigint | number;
};

export type SubmitAttestationResult = {
  uid: Hex;
  txHash: Hex;
  receipt?: unknown;
};

export type RevokeAttestationParams = {
  signer: unknown;
  easContractAddress: Hex;
  schemaUid: Hex;
  uid: Hex;
  value?: bigint | number;
};

export type RevokeAttestationResult = {
  txHash: Hex;
  receipt?: unknown;
};

export type PrepareDelegatedAttestationParams = {
  chainId: number;
  easContractAddress: Hex;
  schemaUid: Hex;
  schema: SchemaField[] | string;
  data: Record<string, unknown>;
  attester: Hex;
  nonce: bigint | number;
  revocable?: boolean;
  expirationTime?: bigint | number;
  refUid?: Hex;
  value?: bigint | number;
  deadline?: bigint | number;
};

export type PrepareDelegatedAttestationResult = {
  delegatedRequest: Record<string, unknown>;
  typedData: {
    domain: Record<string, unknown>;
    types: Record<string, unknown>;
    message: Record<string, unknown>;
  };
};

export type BuildDelegatedTypedDataFromEncodedParams = {
  chainId: number;
  easContractAddress: Hex;
  schemaUid: Hex;
  encodedData: Hex;
  recipient: Hex;
  attester: Hex;
  nonce: bigint | number;
  revocable?: boolean;
  expirationTime?: bigint | number;
  refUid?: Hex;
  value?: bigint | number;
  deadline?: bigint | number;
};

export type SubmitDelegatedAttestationParams = {
  relayUrl: string;
  prepared: PrepareDelegatedAttestationResult;
  signature: Hex | string;
  attester?: Hex;
};

export type SubmitDelegatedAttestationResult = {
  uid: Hex;
  txHash?: Hex;
  status: "submitted" | "confirmed";
};

export type GetAttestationParams = {
  uid: Hex;
  provider: unknown;
  easContractAddress: Hex;
  schema?: SchemaField[] | string;
};

export type ListAttestationsParams = {
  subjectDid: Did;
  provider: unknown;
  easContractAddress: Hex;
  schemas?: Hex[];
  limit?: number;
  fromBlock?: number;
  toBlock?: number;
};

export type GetAttestationsByAttesterParams = {
  attester: Hex;
  provider: unknown;
  easContractAddress: Hex;
  schemas?: Hex[];
  limit?: number;
  fromBlock?: number;
  toBlock?: number;
};

export type VerifyAttestationParams = {
  attestation: AttestationQueryResult;
  provider?: unknown;
  checks?: ProofType[];
  context?: Record<string, unknown>;
};

export type VerifyAttestationResult = {
  valid: boolean;
  checks: Record<string, boolean>;
  reasons: string[];
};

export type CallControllerWitnessParams = {
  gatewayUrl: string;
  attestationUid: Hex;
  chainId: number;
  easContract: Hex;
  schemaUid: Hex;
  subject: Did;
  controller: Did;
  timeoutMs?: number;
};

export type CallControllerWitnessResult = {
  ok: boolean;
  method: "dns-txt" | "did-json";
  details?: unknown;
};

export type VerifyProofParams = {
  proof: ProofWrapper;
  provider?: unknown;
  expectedSubjectDid?: Did;
  expectedControllerDid?: Did;
};

export type VerifyProofResult = {
  valid: boolean;
  proofType: ProofType;
  reason?: string;
};

export type RequestControllerWitnessParams = {
  /** Subject DID (e.g., did:web:example.com) */
  subjectDid: Did;
  /** Controller DID (e.g., did:pkh:eip155:66238:0xabc...) */
  controllerDid: Did;
  /** Override the default controller witness API URL. If omitted, uses the OMATrust production endpoint. */
  gatewayUrl?: string;
  /** Optional chain ID — defaults to the API's active chain if omitted */
  chainId?: number;
  /** Request timeout in milliseconds (default: 15000) */
  timeoutMs?: number;
};

export type RequestControllerWitnessResult = {
  success: boolean;
  uid: string | null;
  txHash: string;
  blockNumber: number;
  observedAt: number;
  method: string;
};

export type W3CKeyPurpose =
  | "authentication"
  | "assertionMethod"
  | "keyAgreement";

export type GetAttesterAuthorizationParams = {
  /** Attester wallet address */
  attester: Hex;
  /** Subject DID the attester claims to control */
  subjectDid: Did;
  /** ethers v6 Provider for on-chain reads */
  provider: unknown;
  /** CAIP-2 chain identifier. Defaults to "eip155:6623" (OMAChain). */
  chain?: string;
  /** EAS contract address. If omitted, resolved from trust anchors. */
  easContractAddress?: Hex;
  /** How far back to scan for controller witnesses. Defaults to 0 (full history). */
  fromBlock?: number;
  /** DNS resolution function for did:web live check */
  resolveTxt?: (host: string) => Promise<string[][]>;
  /** DID document fetcher for did:web live check */
  fetchDidDocument?: (domain: string) => Promise<Record<string, unknown>>;
  /**
   * W3C DID verification relationship purposes to require.
   * Key bindings are only considered valid if their keyPurpose includes all requested purposes.
   * Defaults to ["authentication", "assertionMethod"].
   */
  purpose?: W3CKeyPurpose[];
};

export type ControllerWitnessEvidence = {
  /** Attestation UID */
  uid: Hex;
  /** Timestamp when the controller witness was issued (unix seconds) */
  issuedAt: bigint;
  /** EAS-level attester address (typically the OMA3 server wallet) */
  attester: string;
  /** Verification method used by the witness service */
  method?: "dns" | "did-document" | "manual" | "other";
};

export type AttesterAuthorizationResult = {
  /** Whether the attester has any authorization for this subject */
  authorized: boolean;
  /**
   * Earliest timestamp of durable authorization evidence, usually the first
   * Controller Witness. Null when authorization is only currently verified
   * by live DNS/did.json.
   */
  anchoredFrom: bigint | null;
  /**
   * End of the authorization window. Set when a relevant key binding revocation
   * closes the window. Null if the window is still open.
   */
  until: bigint | null;
  /** Whether live DNS/did.json currently confirms control */
  currentlyVerified: boolean;
  /** Verification method for live check */
  liveMethod: "dns" | "did-document" | null;
  /** Controller witness attestations found (oldest first) */
  controllerWitnesses: ControllerWitnessEvidence[];
  /** Key binding attestation UID if one exists */
  keyBindingUid: Hex | null;
  /**
   * Whether the key binding's keyPurpose matched the requested purposes.
   * - "matched": key binding exists and its purposes satisfy the request
   * - "unknown": key binding exists but has no keyPurpose field
   * - "mismatch": key binding exists but does not satisfy the requested purposes
   * - "not-required": no key binding exists or no purpose filter was applied
   */
  keyPurposeStatus: "matched" | "unknown" | "mismatch" | "not-required";
};
