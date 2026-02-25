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
  did: Did;
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
  expectedSubject?: Did;
  expectedController?: Did;
};

export type VerifyProofResult = {
  valid: boolean;
  proofType: ProofType;
  reason?: string;
};
