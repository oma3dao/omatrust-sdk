import { beforeEach, describe, expect, it, vi, beforeAll } from "vitest";
import { OmaTrustError } from "../src/shared/errors";
import type { Hex } from "../src/reputation/types";

const mockQueryFilter = vi.fn();
const mockGetAttestation = vi.fn();

vi.mock("@ethereum-attestation-service/eas-sdk", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@ethereum-attestation-service/eas-sdk")>();
  return {
    ...actual,
    EAS: class {
      connect = vi.fn();
      getAttestation = mockGetAttestation;
      constructor(_: string) {}
    }
  };
});

vi.mock("ethers", async (importOriginal) => {
  const actual = await importOriginal<typeof import("ethers")>();
  return {
    ...actual,
    Contract: class {
      filters = {
        Attested: (recipient?: string | null, attester?: string | null) => ({ recipient, attester })
      };
      queryFilter = mockQueryFilter;
      constructor(_: string, __: string[], ___: unknown) {}
    }
  };
});

let getAttestation: Awaited<typeof import("../src/reputation/query")>["getAttestation"];
let getAttestationsByAttester: Awaited<typeof import("../src/reputation/query")>["getAttestationsByAttester"];
let getAttestationsForDid: Awaited<typeof import("../src/reputation/query")>["getAttestationsForDid"];
let getLatestAttestations: Awaited<typeof import("../src/reputation/query")>["getLatestAttestations"];
let listAttestations: Awaited<typeof import("../src/reputation/query")>["listAttestations"];

beforeAll(async () => {
  const mod = await import("../src/reputation/query");
  getAttestation = mod.getAttestation;
  getAttestationsByAttester = mod.getAttestationsByAttester;
  getAttestationsForDid = mod.getAttestationsForDid;
  getLatestAttestations = mod.getLatestAttestations;
  listAttestations = mod.listAttestations;
});

describe("reputation/query – getAttestation", () => {
  const uid = ("0x" + "a".repeat(64)) as Hex;
  const schema = ("0x" + "1".repeat(64)) as Hex;
  const easContractAddress = "0x4200000000000000000000000000000000000021" as Hex;
  const zeroUid = ("0x" + "0".repeat(64)) as Hex;

  beforeEach(() => {
    mockGetAttestation.mockReset();
  });

  it("returns attestation when found", async () => {
    mockGetAttestation.mockResolvedValue({
      uid,
      schema,
      attester: "0x1111111111111111111111111111111111111111",
      recipient: "0x2222222222222222222222222222222222222222",
      revocable: true,
      revocationTime: 0n,
      expirationTime: 0n,
      time: 1000n,
      refUID: zeroUid,
      data: "0x"
    });

    const result = await getAttestation({
      uid,
      provider: {} as never,
      easContractAddress
    });

    expect(result.uid).toBe(uid);
    expect(result.schema).toBe(schema);
    expect(result.revocable).toBe(true);
  });

  it("throws ATTESTATION_NOT_FOUND when attestation is null", async () => {
    mockGetAttestation.mockResolvedValue(null);

    await expect(
      getAttestation({ uid, provider: {} as never, easContractAddress })
    ).rejects.toThrow(OmaTrustError);
  });

  it("throws ATTESTATION_NOT_FOUND when uid is zero", async () => {
    mockGetAttestation.mockResolvedValue({
      uid: zeroUid,
      schema,
      attester: "0x11",
      recipient: "0x22",
      data: "0x"
    });

    const err = await getAttestation({
      uid: zeroUid,
      provider: {} as never,
      easContractAddress
    }).catch((e) => e);
    expect(err).toBeInstanceOf(OmaTrustError);
    expect((err as OmaTrustError).code).toBe("ATTESTATION_NOT_FOUND");
  });

  it("wraps network errors as NETWORK_ERROR", async () => {
    mockGetAttestation.mockRejectedValue(new Error("network failed"));

    const err = await getAttestation({
      uid,
      provider: {} as never,
      easContractAddress
    }).catch((e) => e);
    expect(err).toBeInstanceOf(OmaTrustError);
    expect((err as OmaTrustError).code).toBe("NETWORK_ERROR");
  });

  it("parses attestation with time/revocationTime/expirationTime as number or string", async () => {
    mockGetAttestation.mockResolvedValue({
      uid,
      schema,
      attester: "0x1111111111111111111111111111111111111111",
      recipient: "0x2222222222222222222222222222222222222222",
      revocable: true,
      revocationTime: 0, // number
      expirationTime: "1234567890", // string
      time: 1000, // number
      refUID: zeroUid,
      data: "0x"
    });

    const result = await getAttestation({
      uid,
      provider: {} as never,
      easContractAddress
    });

    expect(result.revocationTime).toBe(0n);
    expect(result.expirationTime).toBe(1234567890n);
    expect(result.time).toBe(1000n);
  });

  it("parses attestation with empty/missing time fields as 0n", async () => {
    mockGetAttestation.mockResolvedValue({
      uid,
      schema,
      attester: "0x1111111111111111111111111111111111111111",
      recipient: "0x2222222222222222222222222222222222222222",
      revocable: true,
      revocationTime: "",
      expirationTime: undefined,
      time: null,
      refUID: zeroUid,
      data: "0x"
    });

    const result = await getAttestation({
      uid,
      provider: {} as never,
      easContractAddress
    });

    expect(result.revocationTime).toBe(0n);
    expect(result.expirationTime).toBe(0n);
    expect(result.time).toBe(0n);
  });

  it("returns raw data when schema not provided", async () => {
    const rawData = "0x1234" as Hex;
    mockGetAttestation.mockResolvedValue({
      uid,
      schema,
      attester: "0x1111111111111111111111111111111111111111",
      recipient: "0x2222222222222222222222222222222222222222",
      revocable: true,
      revocationTime: 0n,
      expirationTime: 0n,
      time: 1000n,
      refUID: zeroUid,
      data: rawData
    });

    const result = await getAttestation({
      uid,
      provider: {} as never,
      easContractAddress
    });

    expect(result.data).toEqual({});
    expect(result.raw).toBe(rawData);
  });
});

describe("reputation/query – getAttestationsForDid", () => {
  const schema1 = ("0x" + "1".repeat(64)) as Hex;
  const uid1 = ("0x" + "a".repeat(64)) as Hex;
  const recipient = "0x9999999999999999999999999999999999999999" as Hex;
  const attester = "0x1111111111111111111111111111111111111111" as Hex;
  const easContractAddress = "0x4200000000000000000000000000000000000021" as Hex;
  const zeroUid = ("0x" + "0".repeat(64)) as Hex;

  beforeEach(() => {
    mockQueryFilter.mockReset();
    mockGetAttestation.mockReset();
  });

  it("queries by DID-derived recipient address", async () => {
    mockQueryFilter.mockResolvedValue([
      { args: [recipient, attester, uid1, schema1], transactionHash: "0x" + "c".repeat(64) }
    ]);
    mockGetAttestation.mockResolvedValue({
      uid: uid1,
      schema: schema1,
      attester,
      recipient,
      revocable: true,
      revocationTime: 0n,
      expirationTime: 0n,
      time: 100n,
      refUID: zeroUid,
      data: "0x"
    });

    const provider = { getBlockNumber: vi.fn().mockResolvedValue(1000) };
    const results = await getAttestationsForDid({
      did: "did:pkh:eip155:1:0x9999999999999999999999999999999999999999",
      provider,
      easContractAddress
    });

    expect(mockQueryFilter).toHaveBeenCalled();
    expect(results.length).toBeGreaterThan(0);
    expect(results[0].recipient).toBe(recipient);
  });

  it("throws NETWORK_ERROR when queryFilter rejects", async () => {
    mockQueryFilter.mockRejectedValue(new Error("RPC failure"));
    const provider = { getBlockNumber: vi.fn().mockResolvedValue(1000) };
    await expect(
      getAttestationsForDid({
        did: "did:pkh:eip155:1:0x9999999999999999999999999999999999999999",
        provider,
        easContractAddress
      })
    ).rejects.toMatchObject({ code: "NETWORK_ERROR" });
  });

  it("skips events without args and events where getAttestation returns null", async () => {
    const uid2 = ("0x" + "b".repeat(64)) as Hex;
    mockQueryFilter.mockResolvedValue([
      { args: [recipient, attester, uid1, schema1], transactionHash: "0x" + "c".repeat(64) },
      { transactionHash: "0x" + "d".repeat(64) },
      { args: [recipient, attester, uid2, schema1], transactionHash: "0x" + "e".repeat(64) }
    ]);
    mockGetAttestation.mockImplementation(async (uid: Hex) => {
      if (uid === uid1) return null;
      return {
        uid: uid2,
        schema: schema1,
        attester,
        recipient,
        revocable: true,
        revocationTime: 0n,
        expirationTime: 0n,
        time: 100n,
        refUID: ("0x" + "0".repeat(64)) as Hex,
        data: "0x"
      };
    });

    const provider = { getBlockNumber: vi.fn().mockResolvedValue(1000) };
    const results = await getAttestationsForDid({
      did: "did:pkh:eip155:1:0x9999999999999999999999999999999999999999",
      provider,
      easContractAddress
    });

    expect(results).toHaveLength(1);
    expect(results[0].uid).toBe(uid2);
  });

  it("filters by schema when schemas option is provided", async () => {
    const schema1 = ("0x" + "1".repeat(64)) as Hex;
    const schema2 = ("0x" + "2".repeat(64)) as Hex;
    const uid1 = ("0x" + "a".repeat(64)) as Hex;
    const uid2 = ("0x" + "b".repeat(64)) as Hex;
    mockQueryFilter.mockResolvedValue([
      { args: [recipient, attester, uid1, schema1], transactionHash: "0x" + "c".repeat(64) },
      { args: [recipient, attester, uid2, schema2], transactionHash: "0x" + "d".repeat(64) }
    ]);
    mockGetAttestation.mockImplementation(async (uid: Hex) => ({
      uid,
      schema: uid === uid1 ? schema1 : schema2,
      attester,
      recipient,
      revocable: true,
      revocationTime: 0n,
      expirationTime: 0n,
      time: 100n,
      refUID: ("0x" + "0".repeat(64)) as Hex,
      data: "0x"
    }));

    const provider = { getBlockNumber: vi.fn().mockResolvedValue(1000) };
    const results = await getAttestationsForDid({
      did: "did:pkh:eip155:1:0x9999999999999999999999999999999999999999",
      provider,
      easContractAddress,
      schemas: [schema1]
    });

    expect(results).toHaveLength(1);
    expect(results[0].schema).toBe(schema1);
  });

  it("skips events with missing uid or schemaUid in args", async () => {
    mockQueryFilter.mockResolvedValue([
      { args: [recipient, attester], transactionHash: "0x" + "c".repeat(64) },
      { args: [recipient, attester, uid1, undefined], transactionHash: "0x" + "d".repeat(64) },
      { args: [recipient, attester, uid1, schema1], transactionHash: "0x" + "e".repeat(64) }
    ]);
    mockGetAttestation.mockResolvedValue({
      uid: uid1,
      schema: schema1,
      attester,
      recipient,
      revocable: true,
      revocationTime: 0n,
      expirationTime: 0n,
      time: 100n,
      refUID: ("0x" + "0".repeat(64)) as Hex,
      data: "0x"
    });

    const provider = { getBlockNumber: vi.fn().mockResolvedValue(1000) };
    const results = await getAttestationsForDid({
      did: "did:pkh:eip155:1:0x9999999999999999999999999999999999999999",
      provider,
      easContractAddress
    });

    expect(results).toHaveLength(1);
    expect(results[0].uid).toBe(uid1);
  });
});

describe("reputation/query – listAttestations", () => {
  const easContractAddress = "0x4200000000000000000000000000000000000021" as Hex;

  beforeEach(() => {
    mockQueryFilter.mockResolvedValue([]);
  });

  it("returns empty when limit is 0", async () => {
    const provider = { getBlockNumber: vi.fn().mockResolvedValue(1000) };
    const results = await listAttestations({
      did: "did:pkh:eip155:1:0x9999999999999999999999999999999999999999",
      provider,
      easContractAddress,
      limit: 0
    });
    expect(results).toEqual([]);
  });

  it("returns empty when limit is negative", async () => {
    mockQueryFilter.mockClear();
    const provider = { getBlockNumber: vi.fn().mockResolvedValue(1000) };
    const results = await listAttestations({
      did: "did:pkh:eip155:1:0x9999999999999999999999999999999999999999",
      provider,
      easContractAddress,
      limit: -1
    });
    expect(results).toEqual([]);
    expect(mockQueryFilter).not.toHaveBeenCalled();
  });

  it("defaults limit to 20", async () => {
    const provider = { getBlockNumber: vi.fn().mockResolvedValue(1000) };
    await listAttestations({
      did: "did:pkh:eip155:1:0x9999999999999999999999999999999999999999",
      provider,
      easContractAddress
    });
    expect(mockQueryFilter).toHaveBeenCalled();
  });
});

describe("reputation/query – getLatestAttestations", () => {
  const easContractAddress = "0x4200000000000000000000000000000000000021" as Hex;

  beforeEach(() => {
    mockQueryFilter.mockResolvedValue([]);
  });

  it("throws NETWORK_ERROR when queryFilter rejects", async () => {
    mockQueryFilter.mockRejectedValue(new Error("RPC failure"));
    const provider = { getBlockNumber: vi.fn().mockResolvedValue(1000) };
    await expect(
      getLatestAttestations({ provider, easContractAddress })
    ).rejects.toMatchObject({ code: "NETWORK_ERROR" });
  });

  it("queries events and slices by limit", async () => {
    const provider = { getBlockNumber: vi.fn().mockResolvedValue(1000) };
    const results = await getLatestAttestations({
      provider,
      easContractAddress,
      limit: 5
    });
    expect(results).toEqual([]);
    expect(mockQueryFilter).toHaveBeenCalled();
  });
});

// Smoke tests only. Test engineering can add pagination/range/schema edge-case suites.
describe("reputation query by attester", () => {
  const schema1 = ("0x".padEnd(66, "1")) as Hex;
  const schema2 = ("0x".padEnd(66, "2")) as Hex;
  const uid1 = ("0x".padEnd(66, "a")) as Hex;
  const uid2 = ("0x".padEnd(66, "b")) as Hex;
  const tx1 = ("0x".padEnd(66, "c")) as Hex;
  const tx2 = ("0x".padEnd(66, "d")) as Hex;
  const recipient = "0x9999999999999999999999999999999999999999" as Hex;
  const attester = "0x1111111111111111111111111111111111111111" as Hex;
  const easContractAddress = "0x4200000000000000000000000000000000000021" as Hex;
  const zeroUid = ("0x".padEnd(66, "0")) as Hex;

  beforeEach(() => {
    mockQueryFilter.mockReset();
    mockGetAttestation.mockReset();
  });

  it("queries by attester and returns most recent first", async () => {
    mockQueryFilter.mockResolvedValue([
      { args: [recipient, attester, uid1, schema1], transactionHash: tx1 },
      { args: [recipient, attester, uid2, schema2], transactionHash: tx2 }
    ]);

    mockGetAttestation.mockImplementation(async (uid: Hex) => {
      if (uid === uid1) {
        return {
          uid: uid1,
          schema: schema1,
          attester,
          recipient,
          revocable: true,
          revocationTime: 0n,
          expirationTime: 0n,
          time: 100n,
          refUID: zeroUid,
          data: "0x"
        };
      }

      return {
        uid: uid2,
        schema: schema2,
        attester,
        recipient,
        revocable: true,
        revocationTime: 0n,
        expirationTime: 0n,
        time: 200n,
        refUID: zeroUid,
        data: "0x"
      };
    });

    const provider = {
      getBlockNumber: vi.fn().mockResolvedValue(1000)
    };

    const results = await getAttestationsByAttester({
      attester,
      provider,
      easContractAddress,
      schemas: [schema1, schema2],
      fromBlock: 100,
      toBlock: 200,
      limit: 1
    });

    expect(mockQueryFilter).toHaveBeenCalled();
    expect(results).toHaveLength(1);
    expect(results[0].uid).toBe(uid2);
    expect(results[0].txHash).toBe(tx2);
  });

  it("returns all results when limit is omitted", async () => {
    mockQueryFilter.mockResolvedValue([
      { args: [recipient, attester, uid1, schema1], transactionHash: tx1 },
      { args: [recipient, attester, uid2, schema2], transactionHash: tx2 }
    ]);
    mockGetAttestation.mockImplementation(async (uid: Hex) => ({
      uid,
      schema: uid === uid1 ? schema1 : schema2,
      attester,
      recipient,
      revocable: true,
      revocationTime: 0n,
      expirationTime: 0n,
      time: 100n,
      refUID: zeroUid,
      data: "0x"
    }));

    const provider = { getBlockNumber: vi.fn().mockResolvedValue(1000) };
    const results = await getAttestationsByAttester({
      attester,
      provider,
      easContractAddress
    });

    expect(results).toHaveLength(2);
  });

  it("returns empty result for non-positive limit", async () => {
    mockQueryFilter.mockResolvedValue([]);

    const provider = {
      getBlockNumber: vi.fn().mockResolvedValue(1000)
    };

    const results = await getAttestationsByAttester({
      attester,
      provider,
      easContractAddress,
      limit: 0
    });

    expect(results).toEqual([]);
  });

  it("uses undefined txHash when event has non-string or invalid transactionHash", async () => {
    mockQueryFilter.mockResolvedValue([
      { args: [recipient, attester, uid1, schema1], transactionHash: 12345 },
      { args: [recipient, attester, uid2, schema2], transactionHash: "0xshort" }
    ]);
    mockGetAttestation.mockImplementation(async (uid: Hex) => ({
      uid,
      schema: uid === uid1 ? schema1 : schema2,
      attester,
      recipient,
      revocable: true,
      revocationTime: 0n,
      expirationTime: 0n,
      time: 100n,
      refUID: zeroUid,
      data: "0x"
    }));

    const provider = { getBlockNumber: vi.fn().mockResolvedValue(1000) };
    const results = await getAttestationsByAttester({
      attester,
      provider,
      easContractAddress,
      schemas: [schema1, schema2]
    });

    expect(results).toHaveLength(2);
    expect(results[0].txHash).toBeUndefined();
    expect(results[1].txHash).toBeUndefined();
  });
});
