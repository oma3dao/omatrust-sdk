import { describe, expect, it, vi } from "vitest";
import { OmaTrustError } from "../src/shared/errors";
import { calculateTransferAmount } from "../src/reputation/proof/tx-encoded-value";
import {
  verifyDidPkhOwnership,
  verifyDidWebOwnership,
  verifySubjectOwnership,
  type EvmOwnershipProvider
} from "../src/reputation/subject-ownership";

function createProvider(overrides: Partial<EvmOwnershipProvider> = {}): EvmOwnershipProvider {
  return {
    call: vi.fn(async () => {
      throw new Error("call not mocked");
    }),
    getCode: vi.fn(async () => "0x"),
    getStorage: vi.fn(async () => "0x"),
    getTransaction: vi.fn(async () => null),
    getTransactionReceipt: vi.fn(async () => null),
    getBlockNumber: vi.fn(async () => 100),
    getBlock: vi.fn(async () => ({ timestamp: Math.floor(Date.now() / 1000) })),
    ...overrides
  };
}

describe("reputation/proof/subject-ownership", () => {
  it("verifies did:web via DNS TXT", async () => {
    const result = await verifyDidWebOwnership({
      subjectDid: "did:web:example.com",
      connectedWalletDid: "did:pkh:eip155:66238:0x1111111111111111111111111111111111111111",
      resolveTxt: vi.fn().mockResolvedValue([
        ["v=1;controller=did:pkh:eip155:66238:0x1111111111111111111111111111111111111111"]
      ])
    });

    expect(result.valid).toBe(true);
    expect(result.method).toBe("dns");
  });

  it("falls back to DID document verification for did:web", async () => {
    const result = await verifyDidWebOwnership({
      subjectDid: "did:web:example.com",
      connectedWalletDid: "did:pkh:eip155:66238:0x1111111111111111111111111111111111111111",
      resolveTxt: vi.fn().mockResolvedValue([]),
      fetchDidDocument: vi.fn().mockResolvedValue({
        verificationMethod: [
          {
            blockchainAccountId: "eip155:66238:0x1111111111111111111111111111111111111111"
          }
        ]
      })
    });

    expect(result.valid).toBe(true);
    expect(result.method).toBe("did-document");
  });

  it("verifies direct EOA did:pkh ownership", async () => {
    const provider = createProvider({
      getCode: vi.fn(async () => "0x")
    });

    const result = await verifyDidPkhOwnership({
      subjectDid: "did:pkh:eip155:66238:0x1111111111111111111111111111111111111111",
      connectedWalletDid: "did:pkh:eip155:66238:0x1111111111111111111111111111111111111111",
      provider
    });

    expect(result.valid).toBe(true);
    expect(result.method).toBe("wallet");
  });

  it("verifies contract ownership via owner()", async () => {
    const encodedOwnerResult =
      "0x0000000000000000000000001111111111111111111111111111111111111111";
    const provider = createProvider({
      getCode: vi.fn(async () => "0x6000"),
      call: vi.fn(async () => encodedOwnerResult)
    });

    const result = await verifyDidPkhOwnership({
      subjectDid: "did:pkh:eip155:66238:0x2222222222222222222222222222222222222222",
      connectedWalletDid: "did:pkh:eip155:66238:0x1111111111111111111111111111111111111111",
      provider
    });

    expect(result.valid).toBe(true);
    expect(result.method).toBe("contract");
  });

  it("verifies did:pkh transfer proofs", async () => {
    const subjectDid = "did:pkh:eip155:66238:0x2222222222222222222222222222222222222222";
    const connectedWalletDid = "did:pkh:eip155:66238:0x1111111111111111111111111111111111111111";
    const expectedAmount = calculateTransferAmount(subjectDid, connectedWalletDid, 66238, "shared-control");

    const encodedOwnerResult =
      "0x000000000000000000000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const provider = createProvider({
      getCode: vi.fn(async () => "0x6000"),
      call: vi.fn(async () => encodedOwnerResult),
      getTransaction: vi.fn(async () => ({
        from: "0xaAaAaAaaAaAaAaaAaAAAAAAAAaaaAaAaAaaAaaAa",
        to: "0x1111111111111111111111111111111111111111",
        value: expectedAmount,
        blockNumber: 50
      })),
      getTransactionReceipt: vi.fn(async () => ({
        blockNumber: 50
      }))
    });

    const result = await verifyDidPkhOwnership({
      subjectDid,
      connectedWalletDid,
      provider,
      txHash: "0x1234"
    });

    expect(result.valid).toBe(true);
    expect(result.method).toBe("transfer");
  });

  it("dispatches from verifySubjectOwnership based on DID method", async () => {
    const result = await verifySubjectOwnership({
      subjectDid: "did:web:example.com",
      connectedWalletDid: "did:pkh:eip155:66238:0x1111111111111111111111111111111111111111",
      resolveTxt: vi.fn().mockResolvedValue([
        ["v=1;controller=did:pkh:eip155:66238:0x1111111111111111111111111111111111111111"]
      ])
    });

    expect(result.valid).toBe(true);
    expect(result.method).toBe("dns");
  });

  it("requires a provider for did:pkh ownership verification", async () => {
    await expect(
      verifySubjectOwnership({
        subjectDid: "did:pkh:eip155:66238:0x2222222222222222222222222222222222222222",
        connectedWalletDid: "did:pkh:eip155:66238:0x1111111111111111111111111111111111111111"
      } as never)
    ).rejects.toMatchObject({
      code: "INVALID_INPUT"
    });
  });
});
