import { beforeEach, describe, expect, it, vi } from "vitest";
import type { Hex } from "../src/reputation";

const mockQueryFilter = vi.fn();
const mockGetAttestation = vi.fn();

vi.mock("@ethereum-attestation-service/eas-sdk", () => {
  class EAS {
    connect = vi.fn();
    getAttestation = mockGetAttestation;
    constructor(_: string) {}
  }

  return { EAS };
});

vi.mock("ethers", () => {
  class Contract {
    filters = {
      Attested: (recipient?: string | null, attester?: string | null) => ({ recipient, attester })
    };
    queryFilter = mockQueryFilter;
    constructor(_: string, __: string[], ___: unknown) {}
  }

  return { Contract };
});

import { getAttestationsByAttester } from "../src/reputation/query";

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
});
