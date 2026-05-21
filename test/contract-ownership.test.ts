import { describe, expect, it, vi } from "vitest";
import {
  discoverContractOwner,
  discoverControllingWalletDid,
  EIP1967_ADMIN_SLOT,
  readOwnerFromContract,
  verifyTransferProof,
  type ContractOwnershipProvider,
} from "../src/reputation/contract-ownership";
import { calculateTransferAmount } from "../src/reputation/proof/tx-encoded-value";

function provider(overrides: Partial<ContractOwnershipProvider> = {}): ContractOwnershipProvider {
  return {
    call: vi.fn(async () => {
      throw new Error("call not mocked");
    }),
    getCode: vi.fn(async () => "0x"),
    getStorage: vi.fn(async () => "0x"),
    getTransaction: vi.fn(async () => null),
    ...overrides,
  };
}

describe("reputation/contract-ownership", () => {
  const contract = "0x2222222222222222222222222222222222222222";
  const owner = "0x1111111111111111111111111111111111111111";

  describe("readOwnerFromContract", () => {
    it("returns checksummed owner when call succeeds", async () => {
      const encoded =
        "0x0000000000000000000000001111111111111111111111111111111111111111";
      const p = provider({
        call: vi.fn(async () => encoded),
      });

      const result = await readOwnerFromContract(
        p,
        contract,
        "function owner() view returns (address)",
        "owner"
      );
      expect(result).toBe(owner);
    });

    it("returns null when owner is zero address", async () => {
      const encoded =
        "0x0000000000000000000000000000000000000000000000000000000000000000";
      const p = provider({
        call: vi.fn(async () => encoded),
      });

      const result = await readOwnerFromContract(
        p,
        contract,
        "function owner() view returns (address)",
        "owner"
      );
      expect(result).toBeNull();
    });

    it("returns null when decoded value is not an address", async () => {
      const p = provider({
        call: vi.fn(async () => "0x" + "f".repeat(64)),
      });
      const result = await readOwnerFromContract(
        p,
        contract,
        "function owner() view returns (address)",
        "owner"
      );
      expect(result).toBeNull();
    });

    it("returns null when call reverts", async () => {
      const p = provider({
        call: vi.fn(async () => {
          throw new Error("revert");
        }),
      });

      const result = await readOwnerFromContract(
        p,
        contract,
        "function owner() view returns (address)",
        "owner"
      );
      expect(result).toBeNull();
    });
  });

  describe("discoverContractOwner", () => {
    it("returns null for EOAs (empty code)", async () => {
      const p = provider({
        getCode: vi.fn(async () => "0x"),
      });
      expect(await discoverContractOwner(p, contract)).toBeNull();
    });

    it("returns null when getCode throws", async () => {
      const p = provider({
        getCode: vi.fn(async () => {
          throw new Error("rpc down");
        }),
      });
      expect(await discoverContractOwner(p, contract)).toBeNull();
    });

    it("discovers owner via owner()", async () => {
      const encoded =
        "0x0000000000000000000000001111111111111111111111111111111111111111";
      const p = provider({
        getCode: vi.fn(async () => "0x6000"),
        call: vi.fn(async () => encoded),
      });
      expect(await discoverContractOwner(p, contract)).toBe(owner);
    });

    it("discovers owner via EIP-1967 admin slot", async () => {
      const p = provider({
        getCode: vi.fn(async () => "0x6000"),
        call: vi.fn(async () => {
          throw new Error("no method");
        }),
        getStorage: vi.fn(async (_addr, slot) => {
          if (slot === EIP1967_ADMIN_SLOT) {
            return "0x" + "0".repeat(24) + owner.slice(2);
          }
          return "0x";
        }),
      });
      expect(await discoverContractOwner(p, contract)).toBe(owner);
    });
  });

  describe("discoverControllingWalletDid", () => {
    it("returns did:pkh for discovered owner", async () => {
      const encoded =
        "0x0000000000000000000000001111111111111111111111111111111111111111";
      const p = provider({
        getCode: vi.fn(async () => "0x6000"),
        call: vi.fn(async () => encoded),
      });

      const did = await discoverControllingWalletDid(p, contract, 66238);
      expect(did).toBe(`did:pkh:eip155:66238:${owner.toLowerCase()}`);
    });

    it("returns null when owner cannot be discovered", async () => {
      const p = provider({
        getCode: vi.fn(async () => "0x6000"),
        call: vi.fn(async () => {
          throw new Error("revert");
        }),
        getStorage: vi.fn(async () => "0x"),
      });
      expect(await discoverControllingWalletDid(p, contract, 1)).toBeNull();
    });
  });

  describe("verifyTransferProof", () => {
    const subjectDid = "did:pkh:eip155:66238:0x2222222222222222222222222222222222222222";
    const attesterAddress = owner;
    const expectedAmount = calculateTransferAmount(
      subjectDid,
      `did:pkh:eip155:66238:${attesterAddress}`,
      66238,
      "shared-control"
    );

    it("returns true for a valid transfer proof transaction", async () => {
      const p = provider({
        getTransaction: vi.fn(async () => ({
          from: "0xaAaAaAaaAaAaAaaAaAAAAAAAAaaaAaAaAaaAaaAa",
          to: attesterAddress,
          value: expectedAmount,
        })),
      });

      expect(
        await verifyTransferProof(
          p,
          `0x${"ab".repeat(32)}`,
          subjectDid,
          attesterAddress,
          66238
        )
      ).toBe(true);
    });

    it("returns false when transaction is missing or incomplete", async () => {
      const p = provider({
        getTransaction: vi.fn(async () => null),
      });
      expect(
        await verifyTransferProof(p, `0x${"ab".repeat(32)}`, subjectDid, attesterAddress, 66238)
      ).toBe(false);
    });

    it("returns false when recipient does not match attester", async () => {
      const p = provider({
        getTransaction: vi.fn(async () => ({
          from: owner,
          to: "0x3333333333333333333333333333333333333333",
          value: expectedAmount,
        })),
      });
      expect(
        await verifyTransferProof(p, `0x${"ab".repeat(32)}`, subjectDid, attesterAddress, 66238)
      ).toBe(false);
    });

    it("returns false when amount does not match", async () => {
      const p = provider({
        getTransaction: vi.fn(async () => ({
          from: owner,
          to: attesterAddress,
          value: 1n,
        })),
      });
      expect(
        await verifyTransferProof(p, `0x${"ab".repeat(32)}`, subjectDid, attesterAddress, 66238)
      ).toBe(false);
    });

    it("returns false when provider throws", async () => {
      const p = provider({
        getTransaction: vi.fn(async () => {
          throw new Error("rpc");
        }),
      });
      expect(
        await verifyTransferProof(p, `0x${"ab".repeat(32)}`, subjectDid, attesterAddress, 66238)
      ).toBe(false);
    });

    it("returns false when transaction omits from or to", async () => {
      const p = provider({
        getTransaction: vi.fn(async () => ({ from: null, to: attesterAddress, value: expectedAmount })),
      });
      expect(
        await verifyTransferProof(p, `0x${"ab".repeat(32)}`, subjectDid, attesterAddress, 66238)
      ).toBe(false);
    });
  });

  describe("discoverContractOwner – edge cases", () => {
    it("returns null when EIP-1967 admin slot is zero", async () => {
      const p = provider({
        getCode: vi.fn(async () => "0x6000"),
        call: vi.fn(async () => {
          throw new Error("revert");
        }),
        getStorage: vi.fn(async () =>
          "0x0000000000000000000000000000000000000000000000000000000000000000"
        ),
      });
      expect(await discoverContractOwner(p, contract)).toBeNull();
    });

    it("returns null when EIP-1967 storage read throws", async () => {
      const p = provider({
        getCode: vi.fn(async () => "0x6000"),
        call: vi.fn(async () => {
          throw new Error("revert");
        }),
        getStorage: vi.fn(async () => {
          throw new Error("slot unreadable");
        }),
      });
      expect(await discoverContractOwner(p, contract)).toBeNull();
    });
  });
});
