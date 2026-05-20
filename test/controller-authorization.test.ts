import { afterAll, beforeAll, beforeEach, describe, expect, it, vi, type MockInstance } from "vitest";
import { didToAddress } from "../src/identity/did";
import { jwkToDidJwk } from "../src/identity/jwk";
import * as encodeModule from "../src/reputation/encode";
import type { Hex } from "../src/reputation/types";

const KB_DATA_SCHEMA =
  "string subject, string keyId, string publicKeyJwk, string[] keyPurpose, string[] proofs, uint256 issuedAt, uint256 effectiveAt, uint256 expiresAt";

/** Registry for key-binding payloads that must not decode as controller-witness first. */
const KB_PAYLOAD_HEX_GLOBAL = "__controllerAuthTestKbPayloadHexes__";
function kbPayloadHexSet(): Set<string> {
  const g = globalThis as unknown as Record<string, Set<string>>;
  if (!g[KB_PAYLOAD_HEX_GLOBAL]) g[KB_PAYLOAD_HEX_GLOBAL] = new Set();
  return g[KB_PAYLOAD_HEX_GLOBAL]!;
}

const mockQueryFilter = vi.fn();
const mockGetAttestation = vi.fn();
const mockFetchTrustAnchors = vi.fn();
const mockDiscoverContractOwner = vi.fn();
const mockVerifyTransferProof = vi.fn();

vi.mock("@ethereum-attestation-service/eas-sdk", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@ethereum-attestation-service/eas-sdk")>();
  return {
    ...actual,
    EAS: class {
      connect = vi.fn();
      getAttestation = mockGetAttestation;
      constructor(_: string) {}
    },
  };
});

vi.mock("ethers", async (importOriginal) => {
  const actual = await importOriginal<typeof import("ethers")>();
  return {
    ...actual,
    Contract: class {
      filters = {
        Attested: (recipient?: string | null, attester?: string | null) => ({ recipient, attester }),
      };
      queryFilter = mockQueryFilter;
      constructor(_: string, __: string[], ___: unknown) {}
    },
  };
});

vi.mock("../src/shared/trust-anchors", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../src/shared/trust-anchors")>();
  return {
    ...actual,
    fetchTrustAnchors: (...args: unknown[]) => mockFetchTrustAnchors(...(args as [])),
  };
});

vi.mock("../src/reputation/contract-ownership", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../src/reputation/contract-ownership")>();
  return {
    ...actual,
    discoverContractOwner: (...args: unknown[]) => mockDiscoverContractOwner(...(args as [])),
    verifyTransferProof: (...args: unknown[]) => mockVerifyTransferProof(...(args as [])),
  };
});


function mergeProofTxHashDecoded(decoded: Record<string, unknown>): Record<string, unknown> {
  const proofs = decoded.proofs;
  if (!Array.isArray(proofs) || proofs.length === 0) return decoded;
  const first = proofs[0];
  if (typeof first === "string" && /^0x[0-9a-fA-F]{64}$/.test(first)) {
    return { ...decoded, proofTxHash: first };
  }
  return decoded;
}

/** Capture before `vi.spyOn` replaces `encodeModule.decodeAttestationData`. */
const originalDecodeAttestationData = encodeModule.decodeAttestationData.bind(encodeModule);

const WITNESS_SCHEMA = ("0x" + "a".repeat(64)) as Hex;
const KEY_BINDING_SCHEMA = ("0x" + "b".repeat(64)) as Hex;

function anchorsFixture() {
  return {
    version: 1,
    updatedAt: "2026-01-01T00:00:00Z",
    chains: {
      "eip155:6623": {
        name: "Test",
        easContract: "0x4200000000000000000000000000000000000021",
        schemas: {
          "controller-witness": WITNESS_SCHEMA,
          "key-binding": KEY_BINDING_SCHEMA,
        },
      },
    },
  };
}

function installDecodeSpy(): MockInstance<typeof encodeModule.decodeAttestationData> {
  return vi.spyOn(encodeModule, "decodeAttestationData").mockImplementation((schema, data) => {
    const normalized = String(data).toLowerCase() as Hex;
    const schemaText = typeof schema === "string" ? schema : encodeModule.schemaToString(schema);
    const isWitnessFirstPassSchema =
      schemaText.includes("string controller") &&
      schemaText.includes("string method") &&
      !schemaText.includes("keyId");
    if (isWitnessFirstPassSchema && kbPayloadHexSet().has(normalized)) {
      throw new Error("not-controller-witness");
    }
    const decoded = originalDecodeAttestationData(schema, data) as Record<string, unknown>;
    if (typeof decoded.keyId === "string") {
      return mergeProofTxHashDecoded(decoded);
    }
    return decoded;
  });
}

describe("reputation/attester-authorization – getControllerAuthorization", () => {
  let getControllerAuthorization: typeof import("../src/reputation/attester-authorization")["getControllerAuthorization"];
  let decodeSpy: MockInstance<typeof encodeModule.decodeAttestationData>;

  beforeAll(async () => {
    decodeSpy = installDecodeSpy();
    const mod = await import("../src/reputation/attester-authorization");
    getControllerAuthorization = mod.getControllerAuthorization;
  });

  afterAll(() => {
    decodeSpy.mockRestore();
  });

  it("wires mocked decodeAttestationData so KB payloads registered in the witness-first path throw", () => {
    kbPayloadHexSet().clear();
    const h = encodeModule.encodeAttestationData(KB_DATA_SCHEMA, {
      subject: "did:web:x.test",
      keyId: "did:pkh:eip155:1:0x1",
      publicKeyJwk: "",
      keyPurpose: ["authentication"],
      proofs: [],
      issuedAt: 1,
      effectiveAt: 1,
      expiresAt: 0,
    });
    kbPayloadHexSet().add(String(h).toLowerCase());
    expect(() =>
      encodeModule.decodeAttestationData("string subject, string controller, string method", h)
    ).toThrow("not-controller-witness");
  });

  beforeEach(() => {
    decodeSpy.mockRestore();
    decodeSpy = installDecodeSpy();

    mockQueryFilter.mockReset();
    mockGetAttestation.mockReset();
    mockFetchTrustAnchors.mockReset();
    mockDiscoverContractOwner.mockReset();
    mockVerifyTransferProof.mockReset();
    kbPayloadHexSet().clear();

    mockFetchTrustAnchors.mockResolvedValue(anchorsFixture());
    mockQueryFilter.mockResolvedValue([]);
    mockDiscoverContractOwner.mockResolvedValue(null);
    mockVerifyTransferProof.mockResolvedValue(false);
  });

  it("marks did:web as authorized when DNS TXT matches controller", async () => {
    const controller = "did:pkh:eip155:1:0x1111111111111111111111111111111111111111";
    const result = await getControllerAuthorization({
      subjectDid: "did:web:example.com",
      controllerDid: controller,
      provider: { getBlockNumber: vi.fn().mockResolvedValue(1_000_000) },
      resolveTxt: vi.fn().mockResolvedValue([
        ["v=1;controller=did:pkh:eip155:1:0x1111111111111111111111111111111111111111"],
      ]),
    });

    expect(result.authorized).toBe(true);
    expect(result.currentlyVerified).toBe(true);
    expect(result.liveMethod).toBe("dns");
    expect(result.controllerWitnesses).toEqual([]);
  });

  it("marks did:web as authorized via did.json when DNS is absent", async () => {
    const controller = "did:pkh:eip155:1:0x2222222222222222222222222222222222222222";
    const result = await getControllerAuthorization({
      subjectDid: "did:web:acme.test",
      controllerDid: controller,
      provider: { getBlockNumber: vi.fn().mockResolvedValue(1_000_000) },
      resolveTxt: vi.fn().mockResolvedValue([]),
      fetchDidDocument: vi.fn().mockResolvedValue({
        verificationMethod: [
          {
            blockchainAccountId: "eip155:1:0x2222222222222222222222222222222222222222",
          },
        ],
      }),
    });

    expect(result.authorized).toBe(true);
    expect(result.liveMethod).toBe("did-document");
  });

  it("marks did:pkh contract as authorized when discoverContractOwner matches controller", async () => {
    mockDiscoverContractOwner.mockResolvedValue("0x3333333333333333333333333333333333333333");

    const result = await getControllerAuthorization({
      subjectDid: "did:pkh:eip155:1:0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      controllerDid: "did:pkh:eip155:1:0x3333333333333333333333333333333333333333",
      provider: { getBlockNumber: vi.fn().mockResolvedValue(1_000_000) },
    });

    expect(result.authorized).toBe(true);
    expect(result.liveMethod).toBe("contract-ownership");
    expect(mockDiscoverContractOwner).toHaveBeenCalled();
  });

  it("returns not authorized when no witness, no live match, and no transfer proof", async () => {
    const result = await getControllerAuthorization({
      subjectDid: "did:web:orphan.test",
      controllerDid: "did:pkh:eip155:1:0x4444444444444444444444444444444444444444",
      provider: { getBlockNumber: vi.fn().mockResolvedValue(1_000_000) },
      resolveTxt: vi.fn().mockResolvedValue([]),
      fetchDidDocument: vi.fn().mockRejectedValue(new Error("no doc")),
    });

    expect(result.authorized).toBe(false);
    expect(result.currentlyVerified).toBe(false);
  });

  const WITNESS_UID = ("0x" + "1".repeat(64)) as Hex;
  const KB_UID = ("0x" + "2".repeat(64)) as Hex;
  const ATTESTER = "0x9999999999999999999999999999999999999999";

  /** Avoid real DNS / did.json fetches for synthetic `did:web` subjects. */
  function didWebLiveOff() {
    return {
      resolveTxt: vi.fn().mockResolvedValue([] as string[][]),
      fetchDidDocument: vi.fn().mockRejectedValue(new Error("no live did.json")),
    };
  }

  function witnessDataHex(subjectDid: string, controllerDid: string, method: string) {
    return encodeModule.encodeAttestationData(
      "string subject, string controller, string method",
      { subject: subjectDid, controller: controllerDid, method }
    );
  }

  function keyBindingDataHex(
    subjectDid: string,
    controllerDid: string,
    keyPurpose: string[],
    proofs: string[] = []
  ) {
    const encoded = encodeModule.encodeAttestationData(KB_DATA_SCHEMA, {
      subject: subjectDid,
      keyId: controllerDid,
      publicKeyJwk: "",
      keyPurpose,
      proofs,
      issuedAt: 1,
      effectiveAt: 1,
      expiresAt: 0,
    });
    kbPayloadHexSet().add(String(encoded).toLowerCase());
    return encoded;
  }

  /** Key binding matched by `publicKeyJwk` for `did:jwk` controllers (empty keyId). */
  function keyBindingDataHexForJwkController(subjectDid: string, publicKeyJwkJson: string, keyPurpose: string[]) {
    const encoded = encodeModule.encodeAttestationData(KB_DATA_SCHEMA, {
      subject: subjectDid,
      keyId: "",
      publicKeyJwk: publicKeyJwkJson,
      keyPurpose,
      proofs: [],
      issuedAt: 1,
      effectiveAt: 1,
      expiresAt: 0,
    });
    kbPayloadHexSet().add(String(encoded).toLowerCase());
    return encoded;
  }

  function easAttestationRow(
    uid: Hex,
    schema: Hex,
    data: Hex,
    overrides: { revocationTime?: bigint; time?: bigint } = {}
  ) {
    const zero = ("0x" + "0".repeat(64)) as Hex;
    return {
      uid,
      schema,
      attester: ATTESTER,
      recipient: zero,
      revocable: true,
      revocationTime: overrides.revocationTime ?? 0n,
      expirationTime: 0n,
      time: overrides.time ?? 1000n,
      refUID: zero,
      data,
    };
  }

  it("authorizes did:web via on-chain controller witness (no live DNS)", async () => {
    const subjectDid = "did:web:witness-chain.test";
    const recipient = didToAddress(subjectDid);
    const controllerDid = "did:pkh:eip155:1:0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    const witnessRow = easAttestationRow(
      WITNESS_UID,
      WITNESS_SCHEMA,
      witnessDataHex(subjectDid, controllerDid, "dns-txt")
    );
    witnessRow.recipient = recipient;

    const kbRow = easAttestationRow(KB_UID, KEY_BINDING_SCHEMA, keyBindingDataHex(subjectDid, controllerDid, []));
    kbRow.recipient = recipient;

    mockQueryFilter
      .mockResolvedValueOnce([{ args: [recipient, ATTESTER, WITNESS_UID, WITNESS_SCHEMA] }])
      .mockResolvedValueOnce([{ args: [recipient, ATTESTER, KB_UID, KEY_BINDING_SCHEMA] }]);

    mockGetAttestation.mockImplementation(async (uid: string) => {
      const u = uid.toLowerCase();
      if (u === WITNESS_UID.toLowerCase()) return witnessRow;
      if (u === KB_UID.toLowerCase()) return kbRow;
      return null;
    });

    const result = await getControllerAuthorization({
      subjectDid,
      controllerDid,
      provider: { getBlockNumber: vi.fn().mockResolvedValue(1_000_000) },
      ...didWebLiveOff(),
    });

    expect(result.authorized).toBe(true);
    expect(result.controllerWitnesses).toHaveLength(1);
    expect(result.controllerWitnesses[0].uid).toBe(WITNESS_UID);
    expect(result.controllerWitnesses[0].method).toBe("dns");
    expect(result.anchoredFrom).toBe(1000n);
    expect(result.keyPurposeStatus).toBe("unknown");
  });

  it("maps witness method variants on controller witness evidence", async () => {
    const subjectDid = "did:web:witness-methods.test";
    const recipient = didToAddress(subjectDid);
    const controllerDid = "did:pkh:eip155:1:0xcccccccccccccccccccccccccccccccccccccccc";

    const witnessRow = easAttestationRow(
      WITNESS_UID,
      WITNESS_SCHEMA,
      witnessDataHex(subjectDid, controllerDid, "manual")
    );
    witnessRow.recipient = recipient;

    mockQueryFilter
      .mockResolvedValueOnce([{ args: [recipient, ATTESTER, WITNESS_UID, WITNESS_SCHEMA] }])
      .mockResolvedValueOnce([]);

    mockGetAttestation.mockImplementation(async (uid: string) =>
      uid.toLowerCase() === WITNESS_UID.toLowerCase() ? witnessRow : null
    );

    const r1 = await getControllerAuthorization({
      subjectDid,
      controllerDid,
      provider: { getBlockNumber: vi.fn().mockResolvedValue(1_000_000) },
      ...didWebLiveOff(),
    });
    expect(r1.controllerWitnesses[0].method).toBe("manual");

    const witnessRow2 = {
      ...witnessRow,
      data: witnessDataHex(subjectDid, controllerDid, "unknown-method"),
    };
    mockQueryFilter
      .mockResolvedValueOnce([{ args: [recipient, ATTESTER, WITNESS_UID, WITNESS_SCHEMA] }])
      .mockResolvedValueOnce([]);
    mockGetAttestation.mockImplementation(async (uid: string) =>
      uid.toLowerCase() === WITNESS_UID.toLowerCase() ? witnessRow2 : null
    );

    const r2 = await getControllerAuthorization({
      subjectDid,
      controllerDid,
      provider: { getBlockNumber: vi.fn().mockResolvedValue(1_000_000) },
      ...didWebLiveOff(),
    });
    expect(r2.controllerWitnesses[0].method).toBe("other");
  });

  it("blocks authorization when key binding keyPurpose mismatches default purposes", async () => {
    const subjectDid = "did:web:kb-mismatch.test";
    const recipient = didToAddress(subjectDid);
    const controllerDid = "did:pkh:eip155:1:0xdddddddddddddddddddddddddddddddddddddddd";

    const witnessRow = easAttestationRow(
      WITNESS_UID,
      WITNESS_SCHEMA,
      witnessDataHex(subjectDid, controllerDid, "dns")
    );
    witnessRow.recipient = recipient;

    const kbRow = easAttestationRow(
      KB_UID,
      KEY_BINDING_SCHEMA,
      keyBindingDataHex(subjectDid, controllerDid, ["authentication"])
    );
    kbRow.recipient = recipient;

    mockQueryFilter
      .mockResolvedValueOnce([{ args: [recipient, ATTESTER, WITNESS_UID, WITNESS_SCHEMA] }])
      .mockResolvedValueOnce([{ args: [recipient, ATTESTER, KB_UID, KEY_BINDING_SCHEMA] }]);

    mockGetAttestation.mockImplementation(async (uid: string) => {
      const u = uid.toLowerCase();
      if (u === WITNESS_UID.toLowerCase()) return witnessRow;
      if (u === KB_UID.toLowerCase()) return kbRow;
      return null;
    });

    const result = await getControllerAuthorization({
      subjectDid,
      controllerDid,
      provider: { getBlockNumber: vi.fn().mockResolvedValue(1_000_000) },
      ...didWebLiveOff(),
    });

    expect(result.keyPurposeStatus).toBe("mismatch");
    expect(result.authorized).toBe(false);
    expect(result.keyBindingUid).toBe(KB_UID);
  });

  it("sets keyPurposeStatus matched when key binding satisfies default purposes", async () => {
    const subjectDid = "did:web:kb-match.test";
    const recipient = didToAddress(subjectDid);
    const controllerDid = "did:pkh:eip155:1:0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";

    const witnessRow = easAttestationRow(
      WITNESS_UID,
      WITNESS_SCHEMA,
      witnessDataHex(subjectDid, controllerDid, "did-json")
    );
    witnessRow.recipient = recipient;

    const kbRow = easAttestationRow(
      KB_UID,
      KEY_BINDING_SCHEMA,
      keyBindingDataHex(subjectDid, controllerDid, ["authentication", "assertionMethod"])
    );
    kbRow.recipient = recipient;

    mockQueryFilter
      .mockResolvedValueOnce([{ args: [recipient, ATTESTER, WITNESS_UID, WITNESS_SCHEMA] }])
      .mockResolvedValueOnce([{ args: [recipient, ATTESTER, KB_UID, KEY_BINDING_SCHEMA] }]);

    mockGetAttestation.mockImplementation(async (uid: string) => {
      const u = uid.toLowerCase();
      if (u === WITNESS_UID.toLowerCase()) return witnessRow;
      if (u === KB_UID.toLowerCase()) return kbRow;
      return null;
    });

    const result = await getControllerAuthorization({
      subjectDid,
      controllerDid,
      provider: { getBlockNumber: vi.fn().mockResolvedValue(1_000_000) },
      ...didWebLiveOff(),
    });

    expect(result.keyPurposeStatus).toBe("matched");
    expect(result.authorized).toBe(true);
  });

  it("sets until from key binding revocationTime when present", async () => {
    const subjectDid = "did:web:kb-revoke.test";
    const recipient = didToAddress(subjectDid);
    const controllerDid = "did:pkh:eip155:1:0xffffffffffffffffffffffffffffffffffffffff";

    const witnessRow = easAttestationRow(
      WITNESS_UID,
      WITNESS_SCHEMA,
      witnessDataHex(subjectDid, controllerDid, "dns-txt")
    );
    witnessRow.recipient = recipient;

    const kbRow = easAttestationRow(
      KB_UID,
      KEY_BINDING_SCHEMA,
      keyBindingDataHex(subjectDid, controllerDid, ["authentication", "assertionMethod"]),
      { revocationTime: 5000n, time: 2000n }
    );
    kbRow.recipient = recipient;

    mockQueryFilter
      .mockResolvedValueOnce([{ args: [recipient, ATTESTER, WITNESS_UID, WITNESS_SCHEMA] }])
      .mockResolvedValueOnce([{ args: [recipient, ATTESTER, KB_UID, KEY_BINDING_SCHEMA] }]);

    mockGetAttestation.mockImplementation(async (uid: string) => {
      const u = uid.toLowerCase();
      if (u === WITNESS_UID.toLowerCase()) return witnessRow;
      if (u === KB_UID.toLowerCase()) return kbRow;
      return null;
    });

    const result = await getControllerAuthorization({
      subjectDid,
      controllerDid,
      provider: { getBlockNumber: vi.fn().mockResolvedValue(1_000_000) },
      ...didWebLiveOff(),
    });

    expect(result.until).toBe(5000n);
    expect(result.keyBindingUid).toBe(KB_UID);
    expect(result.authorized).toBe(false);
  });

  const PROOF_TX = ("0x" + "c".repeat(64)) as Hex;

  it("throws NETWORK_ERROR when attestation event query fails", async () => {
    mockQueryFilter.mockRejectedValueOnce(new Error("rpc unavailable"));

    await expect(
      getControllerAuthorization({
        subjectDid: "did:web:net-fail.test",
        controllerDid: "did:pkh:eip155:1:0x1111111111111111111111111111111111111111",
        provider: { getBlockNumber: vi.fn().mockResolvedValue(1_000_000) },
        ...didWebLiveOff(),
      })
    ).rejects.toMatchObject({ name: "OmaTrustError", code: "NETWORK_ERROR" });
  });

  it("uses custom purpose list for key binding purpose check", async () => {
    const subjectDid = "did:web:purpose-custom.test";
    const recipient = didToAddress(subjectDid);
    const controllerDid = "did:pkh:eip155:1:0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    const witnessRow = easAttestationRow(
      WITNESS_UID,
      WITNESS_SCHEMA,
      witnessDataHex(subjectDid, controllerDid, "dns")
    );
    witnessRow.recipient = recipient;

    const kbRow = easAttestationRow(
      KB_UID,
      KEY_BINDING_SCHEMA,
      keyBindingDataHex(subjectDid, controllerDid, ["authentication", "assertionMethod"])
    );
    kbRow.recipient = recipient;

    mockQueryFilter
      .mockResolvedValueOnce([{ args: [recipient, ATTESTER, WITNESS_UID, WITNESS_SCHEMA] }])
      .mockResolvedValueOnce([{ args: [recipient, ATTESTER, KB_UID, KEY_BINDING_SCHEMA] }]);

    mockGetAttestation.mockImplementation(async (uid: string) => {
      const u = uid.toLowerCase();
      if (u === WITNESS_UID.toLowerCase()) return witnessRow;
      if (u === KB_UID.toLowerCase()) return kbRow;
      return null;
    });

    const narrowPurpose = await getControllerAuthorization({
      subjectDid,
      controllerDid,
      purpose: ["authentication"],
      provider: { getBlockNumber: vi.fn().mockResolvedValue(1_000_000) },
      ...didWebLiveOff(),
    });
    expect(narrowPurpose.keyPurposeStatus).toBe("matched");

    const kbRowNarrow = easAttestationRow(
      KB_UID,
      KEY_BINDING_SCHEMA,
      keyBindingDataHex(subjectDid, controllerDid, ["authentication"])
    );
    kbRowNarrow.recipient = recipient;

    mockQueryFilter
      .mockResolvedValueOnce([{ args: [recipient, ATTESTER, WITNESS_UID, WITNESS_SCHEMA] }])
      .mockResolvedValueOnce([{ args: [recipient, ATTESTER, KB_UID, KEY_BINDING_SCHEMA] }]);
    mockGetAttestation.mockImplementation(async (uid: string) => {
      const u = uid.toLowerCase();
      if (u === WITNESS_UID.toLowerCase()) return witnessRow;
      if (u === KB_UID.toLowerCase()) return kbRowNarrow;
      return null;
    });

    const mismatchPurpose = await getControllerAuthorization({
      subjectDid,
      controllerDid,
      purpose: ["authentication", "assertionMethod"],
      provider: { getBlockNumber: vi.fn().mockResolvedValue(1_000_000) },
      ...didWebLiveOff(),
    });
    expect(mismatchPurpose.keyPurposeStatus).toBe("mismatch");
  });

  it("authorizes did:pkh via transfer proof when owner check fails and verifyTransferProof succeeds", async () => {
    const subjectDid = "did:pkh:eip155:1:0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const recipient = didToAddress(subjectDid);
    const controllerDid = "did:pkh:eip155:1:0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    mockDiscoverContractOwner.mockResolvedValue("0xcccccccccccccccccccccccccccccccccccccccc");

    const kbRow = easAttestationRow(
      KB_UID,
      KEY_BINDING_SCHEMA,
      keyBindingDataHex(subjectDid, controllerDid, ["authentication", "assertionMethod"], [PROOF_TX]),
      { time: 7777n }
    );
    kbRow.recipient = recipient;

    mockQueryFilter
      .mockResolvedValueOnce([])
      .mockResolvedValueOnce([{ args: [recipient, ATTESTER, KB_UID, KEY_BINDING_SCHEMA] }])
      .mockResolvedValueOnce([{ args: [recipient, ATTESTER, KB_UID, KEY_BINDING_SCHEMA] }]);

    mockGetAttestation.mockImplementation(async (uid: string) =>
      uid.toLowerCase() === KB_UID.toLowerCase() ? kbRow : null
    );
    mockVerifyTransferProof.mockResolvedValue(true);

    const result = await getControllerAuthorization({
      subjectDid,
      controllerDid,
      provider: { getBlockNumber: vi.fn().mockResolvedValue(2_000_000) },
    });

    expect(result.authorized).toBe(true);
    expect(result.transferProofVerified).toBe(true);
    expect(result.anchoredFrom).toBe(7777n);
    expect(mockVerifyTransferProof).toHaveBeenCalled();
  });

  it("does not authorize did:pkh when transfer proof verification fails", async () => {
    const subjectDid = "did:pkh:eip155:1:0xdddddddddddddddddddddddddddddddddddddddd";
    const recipient = didToAddress(subjectDid);
    const controllerDid = "did:pkh:eip155:1:0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";

    mockDiscoverContractOwner.mockResolvedValue("0xffffffffffffffffffffffffffffffffffffffff");

    const kbRow = easAttestationRow(
      KB_UID,
      KEY_BINDING_SCHEMA,
      keyBindingDataHex(subjectDid, controllerDid, ["authentication", "assertionMethod"], [PROOF_TX])
    );
    kbRow.recipient = recipient;

    mockQueryFilter
      .mockResolvedValueOnce([])
      .mockResolvedValueOnce([{ args: [recipient, ATTESTER, KB_UID, KEY_BINDING_SCHEMA] }])
      .mockResolvedValueOnce([{ args: [recipient, ATTESTER, KB_UID, KEY_BINDING_SCHEMA] }]);

    mockGetAttestation.mockImplementation(async (uid: string) =>
      uid.toLowerCase() === KB_UID.toLowerCase() ? kbRow : null
    );
    mockVerifyTransferProof.mockResolvedValue(false);

    const result = await getControllerAuthorization({
      subjectDid,
      controllerDid,
      provider: { getBlockNumber: vi.fn().mockResolvedValue(2_000_000) },
    });

    expect(result.authorized).toBe(false);
    expect(result.transferProofVerified).toBeUndefined();
  });

  it("authorizes non-EVM did:pkh subject via on-chain witness window", async () => {
    const subjectDid = "did:pkh:solana:101:TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
    const recipient = didToAddress(subjectDid);
    const controllerDid = "did:pkh:eip155:1:0x1212121212121212121212121212121212121212";

    const witnessRow = easAttestationRow(
      WITNESS_UID,
      WITNESS_SCHEMA,
      witnessDataHex(subjectDid, controllerDid, "manual")
    );
    witnessRow.recipient = recipient;

    mockQueryFilter.mockResolvedValueOnce([{ args: [recipient, ATTESTER, WITNESS_UID, WITNESS_SCHEMA] }]).mockResolvedValueOnce([]);

    mockGetAttestation.mockImplementation(async (uid: string) =>
      uid.toLowerCase() === WITNESS_UID.toLowerCase() ? witnessRow : null
    );

    const result = await getControllerAuthorization({
      subjectDid,
      controllerDid,
      provider: { getBlockNumber: vi.fn().mockResolvedValue(1_000_000) },
    });

    expect(result.authorized).toBe(true);
    expect(result.controllerWitnesses).toHaveLength(1);
    expect(result.controllerWitnesses[0].method).toBe("manual");
  });

  it("does not match did:jwk controller when on-chain publicKeyJwk JSON is invalid", async () => {
    const controllerDid = jwkToDidJwk({
      kty: "EC",
      crv: "P-256",
      x: "f83OJ3D7xI1Yp1V2iFIYA7n5OYXc4K1Uo7jY14FKMC4",
      y: "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
    });
    const subjectDid = "did:web:jwk-invalid-kb.test";
    const recipient = didToAddress(subjectDid);

    const encoded = encodeModule.encodeAttestationData(KB_DATA_SCHEMA, {
      subject: subjectDid,
      keyId: "",
      publicKeyJwk: "not-json",
      keyPurpose: ["authentication", "assertionMethod"],
      proofs: [],
      issuedAt: 1,
      effectiveAt: 1,
      expiresAt: 0,
    });
    kbPayloadHexSet().add(String(encoded).toLowerCase());

    const kbRow = easAttestationRow(KB_UID, KEY_BINDING_SCHEMA, encoded);
    kbRow.recipient = recipient;

    mockQueryFilter
      .mockResolvedValueOnce([])
      .mockResolvedValueOnce([{ args: [recipient, ATTESTER, KB_UID, KEY_BINDING_SCHEMA] }]);

    mockGetAttestation.mockImplementation(async (uid: string) =>
      uid.toLowerCase() === KB_UID.toLowerCase() ? kbRow : null
    );

    const result = await getControllerAuthorization({
      subjectDid,
      controllerDid,
      provider: { getBlockNumber: vi.fn().mockResolvedValue(1_000_000) },
      resolveTxt: vi.fn().mockResolvedValue([
        ["v=1;controller=" + controllerDid],
      ]),
    });

    expect(result.keyBindingUid).toBeNull();
    expect(result.authorized).toBe(true);
  });

  it("matches did:jwk controller via key binding publicKeyJwk", async () => {
    const ecP256 = {
      kty: "EC",
      crv: "P-256",
      x: "f83OJ3D7xI1Yp1V2iFIYA7n5OYXc4K1Uo7jY14FKMC4",
      y: "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
    };
    const controllerDid = jwkToDidJwk(ecP256);
    const subjectDid = "did:web:jwk-kb.test";
    const recipient = didToAddress(subjectDid);

    const witnessRow = easAttestationRow(
      WITNESS_UID,
      WITNESS_SCHEMA,
      witnessDataHex(subjectDid, controllerDid, "dns-txt")
    );
    witnessRow.recipient = recipient;

    const kbRow = easAttestationRow(
      KB_UID,
      KEY_BINDING_SCHEMA,
      keyBindingDataHexForJwkController(subjectDid, JSON.stringify(ecP256), ["authentication", "assertionMethod"])
    );
    kbRow.recipient = recipient;

    mockQueryFilter
      .mockResolvedValueOnce([{ args: [recipient, ATTESTER, WITNESS_UID, WITNESS_SCHEMA] }])
      .mockResolvedValueOnce([{ args: [recipient, ATTESTER, KB_UID, KEY_BINDING_SCHEMA] }]);

    mockGetAttestation.mockImplementation(async (uid: string) => {
      const u = uid.toLowerCase();
      if (u === WITNESS_UID.toLowerCase()) return witnessRow;
      if (u === KB_UID.toLowerCase()) return kbRow;
      return null;
    });

    const result = await getControllerAuthorization({
      subjectDid,
      controllerDid,
      provider: { getBlockNumber: vi.fn().mockResolvedValue(1_000_000) },
      ...didWebLiveOff(),
    });

    expect(result.keyPurposeStatus).toBe("matched");
    expect(result.keyBindingUid).toBe(KB_UID);
    expect(result.authorized).toBe(true);
  });

  it("drops controller witnesses whose on-chain controller does not match", async () => {
    const subjectDid = "did:web:witness-filter.test";
    const recipient = didToAddress(subjectDid);
    const controllerDid = "did:pkh:eip155:1:0xabababababababababababababababababababab";

    const witnessRow = easAttestationRow(
      WITNESS_UID,
      WITNESS_SCHEMA,
      witnessDataHex(subjectDid, "did:pkh:eip155:1:0x0101010101010101010101010101010101010101", "dns")
    );
    witnessRow.recipient = recipient;

    mockQueryFilter.mockResolvedValueOnce([{ args: [recipient, ATTESTER, WITNESS_UID, WITNESS_SCHEMA] }]).mockResolvedValueOnce([]);

    mockGetAttestation.mockImplementation(async (uid: string) =>
      uid.toLowerCase() === WITNESS_UID.toLowerCase() ? witnessRow : null
    );

    const result = await getControllerAuthorization({
      subjectDid,
      controllerDid,
      provider: { getBlockNumber: vi.fn().mockResolvedValue(1_000_000) },
      resolveTxt: vi.fn().mockResolvedValue([]),
      fetchDidDocument: vi.fn().mockRejectedValue(new Error("no doc")),
    });

    expect(result.controllerWitnesses).toEqual([]);
    expect(result.authorized).toBe(false);
  });

  it("skips malformed Attested logs and still processes valid events", async () => {
    const subjectDid = "did:web:event-skip.test";
    const recipient = didToAddress(subjectDid);
    const controllerDid = "did:pkh:eip155:1:0xb0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0";

    const witnessRow = easAttestationRow(
      WITNESS_UID,
      WITNESS_SCHEMA,
      witnessDataHex(subjectDid, controllerDid, "dns")
    );
    witnessRow.recipient = recipient;

    mockQueryFilter
      .mockResolvedValueOnce([
        { notArgs: true },
        { args: [recipient, ATTESTER, WITNESS_UID, WITNESS_SCHEMA] },
        { args: [recipient, ATTESTER] },
      ])
      .mockResolvedValueOnce([]);

    mockGetAttestation.mockImplementation(async (uid: string) =>
      uid.toLowerCase() === WITNESS_UID.toLowerCase() ? witnessRow : null
    );

    const result = await getControllerAuthorization({
      subjectDid,
      controllerDid,
      provider: { getBlockNumber: vi.fn().mockResolvedValue(1_000_000) },
      ...didWebLiveOff(),
    });

    expect(result.controllerWitnesses).toHaveLength(1);
    expect(result.authorized).toBe(true);
  });

  it("maps dns-txt and did-json witness methods and unknown methods to evidence enums", async () => {
    const subjectDid = "did:web:method-map.test";
    const recipient = didToAddress(subjectDid);
    const controllerDid = "did:pkh:eip155:1:0x1111111111111111111111111111111111111111";

    const witnessRow = easAttestationRow(
      WITNESS_UID,
      WITNESS_SCHEMA,
      witnessDataHex(subjectDid, controllerDid, "dns-txt")
    );
    witnessRow.recipient = recipient;

    mockQueryFilter
      .mockResolvedValueOnce([{ args: [recipient, ATTESTER, WITNESS_UID, WITNESS_SCHEMA] }])
      .mockResolvedValueOnce([]);

    mockGetAttestation.mockImplementation(async (uid: string) =>
      uid.toLowerCase() === WITNESS_UID.toLowerCase() ? witnessRow : null
    );

    const dnsTxt = await getControllerAuthorization({
      subjectDid,
      controllerDid,
      provider: { getBlockNumber: vi.fn().mockResolvedValue(1_000_000) },
      ...didWebLiveOff(),
    });
    expect(dnsTxt.controllerWitnesses[0]?.method).toBe("dns");

    const witnessDidJson = easAttestationRow(
      WITNESS_UID,
      WITNESS_SCHEMA,
      witnessDataHex(subjectDid, controllerDid, "did-json")
    );
    witnessDidJson.recipient = recipient;
    mockQueryFilter
      .mockResolvedValueOnce([{ args: [recipient, ATTESTER, WITNESS_UID, WITNESS_SCHEMA] }])
      .mockResolvedValueOnce([]);
    mockGetAttestation.mockImplementation(async (uid: string) =>
      uid.toLowerCase() === WITNESS_UID.toLowerCase() ? witnessDidJson : null
    );

    const didJson = await getControllerAuthorization({
      subjectDid,
      controllerDid,
      provider: { getBlockNumber: vi.fn().mockResolvedValue(1_000_000) },
      ...didWebLiveOff(),
    });
    expect(didJson.controllerWitnesses[0]?.method).toBe("did-document");

    const witnessOther = easAttestationRow(
      WITNESS_UID,
      WITNESS_SCHEMA,
      witnessDataHex(subjectDid, controllerDid, "custom-gateway")
    );
    witnessOther.recipient = recipient;
    mockQueryFilter
      .mockResolvedValueOnce([{ args: [recipient, ATTESTER, WITNESS_UID, WITNESS_SCHEMA] }])
      .mockResolvedValueOnce([]);
    mockGetAttestation.mockImplementation(async (uid: string) =>
      uid.toLowerCase() === WITNESS_UID.toLowerCase() ? witnessOther : null
    );

    const other = await getControllerAuthorization({
      subjectDid,
      controllerDid,
      provider: { getBlockNumber: vi.fn().mockResolvedValue(1_000_000) },
      ...didWebLiveOff(),
    });
    expect(other.controllerWitnesses[0]?.method).toBe("other");
  });

  it("reports unknown key purpose when binding omits keyPurpose", async () => {
    const subjectDid = "did:web:kb-unknown-purpose.test";
    const recipient = didToAddress(subjectDid);
    const controllerDid = "did:pkh:eip155:1:0x1212121212121212121212121212121212121212";

    const witnessRow = easAttestationRow(
      WITNESS_UID,
      WITNESS_SCHEMA,
      witnessDataHex(subjectDid, controllerDid, "manual")
    );
    witnessRow.recipient = recipient;

    const kbRow = easAttestationRow(
      KB_UID,
      KEY_BINDING_SCHEMA,
      keyBindingDataHex(subjectDid, controllerDid, [])
    );
    kbRow.recipient = recipient;

    mockQueryFilter
      .mockResolvedValueOnce([{ args: [recipient, ATTESTER, WITNESS_UID, WITNESS_SCHEMA] }])
      .mockResolvedValueOnce([{ args: [recipient, ATTESTER, KB_UID, KEY_BINDING_SCHEMA] }]);

    mockGetAttestation.mockImplementation(async (uid: string) => {
      const u = uid.toLowerCase();
      if (u === WITNESS_UID.toLowerCase()) return witnessRow;
      if (u === KB_UID.toLowerCase()) return kbRow;
      return null;
    });

    const result = await getControllerAuthorization({
      subjectDid,
      controllerDid,
      provider: { getBlockNumber: vi.fn().mockResolvedValue(1_000_000) },
      ...didWebLiveOff(),
    });

    expect(result.keyPurposeStatus).toBe("unknown");
    expect(result.authorized).toBe(true);
  });

  it("sets until when key binding is revoked", async () => {
    const subjectDid = "did:web:kb-revoked.test";
    const recipient = didToAddress(subjectDid);
    const controllerDid = "did:pkh:eip155:1:0x1313131313131313131313131313131313131313";

    const witnessRow = easAttestationRow(
      WITNESS_UID,
      WITNESS_SCHEMA,
      witnessDataHex(subjectDid, controllerDid, "manual")
    );
    witnessRow.recipient = recipient;

    const kbRow = easAttestationRow(
      KB_UID,
      KEY_BINDING_SCHEMA,
      keyBindingDataHex(subjectDid, controllerDid, ["authentication", "assertionMethod"]),
      { revocationTime: 9999n }
    );
    kbRow.recipient = recipient;

    mockQueryFilter
      .mockResolvedValueOnce([{ args: [recipient, ATTESTER, WITNESS_UID, WITNESS_SCHEMA] }])
      .mockResolvedValueOnce([{ args: [recipient, ATTESTER, KB_UID, KEY_BINDING_SCHEMA] }]);

    mockGetAttestation.mockImplementation(async (uid: string) => {
      const u = uid.toLowerCase();
      if (u === WITNESS_UID.toLowerCase()) return witnessRow;
      if (u === KB_UID.toLowerCase()) return kbRow;
      return null;
    });

    const result = await getControllerAuthorization({
      subjectDid,
      controllerDid,
      provider: { getBlockNumber: vi.fn().mockResolvedValue(1_000_000) },
      ...didWebLiveOff(),
    });

    expect(result.until).toBe(9999n);
    expect(result.authorized).toBe(false);
  });

  it("throws NETWORK_ERROR when event query fails", async () => {
    mockQueryFilter.mockRejectedValue(new Error("rpc unavailable"));

    await expect(
      getControllerAuthorization({
        subjectDid: "did:web:query-fail.test",
        controllerDid: "did:pkh:eip155:1:0x1414141414141414141414141414141414141414141",
        provider: { getBlockNumber: vi.fn().mockResolvedValue(1_000_000) },
        ...didWebLiveOff(),
      })
    ).rejects.toMatchObject({ code: "NETWORK_ERROR" });
  });

  it("filters witnesses when decoded controller is not a string", async () => {
    const subjectDid = "did:web:non-string-controller.test";
    const recipient = didToAddress(subjectDid);
    const controllerDid = "did:pkh:eip155:1:0x1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b";
    const witnessData = witnessDataHex(subjectDid, controllerDid, "dns");

    decodeSpy.mockImplementation((schema, data) => {
      const schemaText = typeof schema === "string" ? schema : encodeModule.schemaToString(schema);
      if (schemaText.includes("string controller") && String(data).toLowerCase() === String(witnessData).toLowerCase()) {
        return { subject: subjectDid, controller: 123, method: "dns" };
      }
      return originalDecodeAttestationData(schema, data) as Record<string, unknown>;
    });

    const witnessRow = easAttestationRow(WITNESS_UID, WITNESS_SCHEMA, witnessData);
    witnessRow.recipient = recipient;

    mockQueryFilter
      .mockResolvedValueOnce([{ args: [recipient, ATTESTER, WITNESS_UID, WITNESS_SCHEMA] }])
      .mockResolvedValueOnce([]);

    mockGetAttestation.mockImplementation(async (uid: string) =>
      uid.toLowerCase() === WITNESS_UID.toLowerCase() ? witnessRow : null
    );

    const result = await getControllerAuthorization({
      subjectDid,
      controllerDid,
      provider: { getBlockNumber: vi.fn().mockResolvedValue(1_000_000) },
      resolveTxt: vi.fn().mockResolvedValue([
        ["v=1;controller=did:pkh:eip155:1:0x1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b"],
      ]),
    });

    expect(result.controllerWitnesses).toEqual([]);
    expect(result.authorized).toBe(true);
  });

  it("uses default purposes when purpose is an empty array", async () => {
    const subjectDid = "did:web:default-purpose.test";
    const recipient = didToAddress(subjectDid);
    const controllerDid = "did:pkh:eip155:1:0x1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a";

    const witnessRow = easAttestationRow(
      WITNESS_UID,
      WITNESS_SCHEMA,
      witnessDataHex(subjectDid, controllerDid, "manual")
    );
    witnessRow.recipient = recipient;

    mockQueryFilter
      .mockResolvedValueOnce([{ args: [recipient, ATTESTER, WITNESS_UID, WITNESS_SCHEMA] }])
      .mockResolvedValueOnce([]);

    mockGetAttestation.mockImplementation(async (uid: string) =>
      uid.toLowerCase() === WITNESS_UID.toLowerCase() ? witnessRow : null
    );

    const result = await getControllerAuthorization({
      subjectDid,
      controllerDid,
      purpose: [],
      provider: { getBlockNumber: vi.fn().mockResolvedValue(1_000_000) },
      ...didWebLiveOff(),
    });

    expect(result.authorized).toBe(true);
  });

  it("ignores attestation logs when getAttestation returns null", async () => {
    const subjectDid = "did:web:missing-attestation.test";
    const recipient = didToAddress(subjectDid);
    const controllerDid = "did:pkh:eip155:1:0x1919191919191919191919191919191919191919";

    mockQueryFilter
      .mockResolvedValueOnce([{ args: [recipient, ATTESTER, WITNESS_UID, WITNESS_SCHEMA] }])
      .mockResolvedValueOnce([]);

    mockGetAttestation.mockResolvedValue(null);

    const result = await getControllerAuthorization({
      subjectDid,
      controllerDid,
      provider: { getBlockNumber: vi.fn().mockResolvedValue(1_000_000) },
      resolveTxt: vi.fn().mockResolvedValue([
        ["v=1;controller=did:pkh:eip155:1:0x1919191919191919191919191919191919191919"],
      ]),
    });

    expect(result.controllerWitnesses).toEqual([]);
    expect(result.authorized).toBe(true);
  });

  it("skips decoding when attestation data is empty hex", async () => {
    const subjectDid = "did:web:empty-attestation-data.test";
    const recipient = didToAddress(subjectDid);
    const controllerDid = "did:pkh:eip155:1:0x1818181818181818181818181818181818181818";

    const witnessRow = easAttestationRow(WITNESS_UID, WITNESS_SCHEMA, "0x" as Hex);
    witnessRow.recipient = recipient;

    mockQueryFilter
      .mockResolvedValueOnce([{ args: [recipient, ATTESTER, WITNESS_UID, WITNESS_SCHEMA] }])
      .mockResolvedValueOnce([]);

    mockGetAttestation.mockImplementation(async (uid: string) =>
      uid.toLowerCase() === WITNESS_UID.toLowerCase() ? witnessRow : null
    );

    const result = await getControllerAuthorization({
      subjectDid,
      controllerDid,
      provider: { getBlockNumber: vi.fn().mockResolvedValue(1_000_000) },
      resolveTxt: vi.fn().mockResolvedValue([
        ["v=1;controller=did:pkh:eip155:1:0x1818181818181818181818181818181818181818"],
      ]),
    });

    expect(result.controllerWitnesses).toEqual([]);
    expect(result.authorized).toBe(true);
  });

  it("skips key-binding lookup when key-binding schema is not configured", async () => {
    mockFetchTrustAnchors.mockResolvedValue({
      version: 1,
      updatedAt: "2026-01-01T00:00:00Z",
      chains: {
        "eip155:6623": {
          name: "Test",
          easContract: "0x4200000000000000000000000000000000000021",
          schemas: { "controller-witness": WITNESS_SCHEMA },
        },
      },
    });

    const subjectDid = "did:web:no-kb-schema.test";
    const recipient = didToAddress(subjectDid);
    const controllerDid = "did:pkh:eip155:1:0x1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c";

    const witnessRow = easAttestationRow(
      WITNESS_UID,
      WITNESS_SCHEMA,
      witnessDataHex(subjectDid, controllerDid, "manual")
    );
    witnessRow.recipient = recipient;

    mockQueryFilter.mockResolvedValueOnce([{ args: [recipient, ATTESTER, WITNESS_UID, WITNESS_SCHEMA] }]);

    mockGetAttestation.mockImplementation(async (uid: string) =>
      uid.toLowerCase() === WITNESS_UID.toLowerCase() ? witnessRow : null
    );

    const result = await getControllerAuthorization({
      subjectDid,
      controllerDid,
      provider: { getBlockNumber: vi.fn().mockResolvedValue(1_000_000) },
      ...didWebLiveOff(),
    });

    expect(result.keyBindingUid).toBeNull();
    expect(result.keyPurposeStatus).toBe("not-required");
    expect(result.authorized).toBe(true);
  });

  it("omits witness query when controller-witness schema is not in trust anchors", async () => {
    mockFetchTrustAnchors.mockResolvedValue({
      version: 1,
      updatedAt: "2026-01-01T00:00:00Z",
      chains: {
        "eip155:6623": {
          name: "Test",
          easContract: "0x4200000000000000000000000000000000000021",
          schemas: { "key-binding": KEY_BINDING_SCHEMA },
        },
      },
    });

    const result = await getControllerAuthorization({
      subjectDid: "did:web:no-witness-schema.test",
      controllerDid: "did:pkh:eip155:1:0x1717171717171717171717171717171717171717",
      provider: { getBlockNumber: vi.fn().mockResolvedValue(1_000_000) },
      resolveTxt: vi.fn().mockResolvedValue([
        ["v=1;controller=did:pkh:eip155:1:0x1717171717171717171717171717171717171717"],
      ]),
    });

    expect(result.controllerWitnesses).toEqual([]);
    expect(result.authorized).toBe(true);
  });

  it("processes attestations with undecodable data and numeric revocation times", async () => {
    const subjectDid = "did:web:undecodable-data.test";
    const recipient = didToAddress(subjectDid);
    const controllerDid = "did:pkh:eip155:1:0x1616161616161616161616161616161616161616161";

    const witnessRow = easAttestationRow(
      WITNESS_UID,
      WITNESS_SCHEMA,
      ("0x" + "ff".repeat(32)) as Hex
    );
    witnessRow.recipient = recipient;

    const kbRow = easAttestationRow(
      KB_UID,
      KEY_BINDING_SCHEMA,
      keyBindingDataHex(subjectDid, controllerDid, ["authentication", "assertionMethod"])
    );
    kbRow.recipient = recipient;

    mockQueryFilter
      .mockResolvedValueOnce([{ args: [recipient, ATTESTER, WITNESS_UID, WITNESS_SCHEMA] }])
      .mockResolvedValueOnce([{ args: [recipient, ATTESTER, KB_UID, KEY_BINDING_SCHEMA] }]);

    mockGetAttestation.mockImplementation(async (uid: string) => {
      const u = uid.toLowerCase();
      if (u === WITNESS_UID.toLowerCase()) return witnessRow;
      if (u === KB_UID.toLowerCase()) return { ...kbRow, revocationTime: 42 };
      return null;
    });

    const result = await getControllerAuthorization({
      subjectDid,
      controllerDid,
      provider: { getBlockNumber: vi.fn().mockResolvedValue(1_000_000) },
      ...didWebLiveOff(),
    });

    expect(result.controllerWitnesses).toEqual([]);
    expect(result.keyBindingUid).toBe(KB_UID);
    expect(result.until).toBe(42n);
  });

  it("still authorizes did:web when live DNS lookup throws", async () => {
    const subjectDid = "did:web:dns-throws.test";
    const recipient = didToAddress(subjectDid);
    const controllerDid = "did:pkh:eip155:1:0x1515151515151515151515151515151515151515";

    const witnessRow = easAttestationRow(
      WITNESS_UID,
      WITNESS_SCHEMA,
      witnessDataHex(subjectDid, controllerDid, "dns")
    );
    witnessRow.recipient = recipient;

    mockQueryFilter
      .mockResolvedValueOnce([{ args: [recipient, ATTESTER, WITNESS_UID, WITNESS_SCHEMA] }])
      .mockResolvedValueOnce([]);

    mockGetAttestation.mockImplementation(async (uid: string) =>
      uid.toLowerCase() === WITNESS_UID.toLowerCase() ? witnessRow : null
    );

    const result = await getControllerAuthorization({
      subjectDid,
      controllerDid,
      provider: { getBlockNumber: vi.fn().mockResolvedValue(1_000_000) },
      resolveTxt: vi.fn().mockRejectedValue(new Error("dns down")),
      fetchDidDocument: vi.fn().mockRejectedValue(new Error("no doc")),
    });

    expect(result.authorized).toBe(true);
    expect(result.currentlyVerified).toBe(false);
  });

  it("accepts custom easContractAddress without throwing", async () => {
    const customEas = "0x1234567890123456789012345678901234567890" as Hex;
    mockQueryFilter.mockResolvedValue([]);

    await expect(
      getControllerAuthorization({
        subjectDid: "did:web:eas-override.test",
        controllerDid: "did:pkh:eip155:1:0x1111111111111111111111111111111111111111",
        easContractAddress: customEas,
        provider: { getBlockNumber: vi.fn().mockResolvedValue(1) },
        resolveTxt: vi.fn().mockResolvedValue([
          ["v=1;controller=did:pkh:eip155:1:0x1111111111111111111111111111111111111111"],
        ]),
      })
    ).resolves.toMatchObject({ authorized: true });
  });
});
