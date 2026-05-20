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
    const resolveTxt = vi.fn().mockResolvedValue([
      ["v=1;controller=did:pkh:eip155:66238:0x1111111111111111111111111111111111111111"],
    ]);
    const result = await verifyDidWebOwnership({
      subjectDid: "did:web:example.com",
      connectedWalletDid: "did:pkh:eip155:66238:0x1111111111111111111111111111111111111111",
      resolveTxt,
      recordPrefix: "_custom",
    });
    expect(resolveTxt).toHaveBeenCalledWith("_custom.example.com");

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

  it("rejects unsupported subject DID methods", async () => {
    await expect(
      verifySubjectOwnership({
        subjectDid: "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2",
        connectedWalletDid: "did:pkh:eip155:66238:0x1111111111111111111111111111111111111111"
      } as never)
    ).rejects.toMatchObject({ code: "INVALID_INPUT" });
  });

  it("returns transaction not found when transfer proof tx is missing", async () => {
    const subjectDid = "did:pkh:eip155:66238:0x2222222222222222222222222222222222222222";
    const connectedWalletDid = "did:pkh:eip155:66238:0x1111111111111111111111111111111111111111";
    const encodedOwner =
      "0x000000000000000000000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const provider = createProvider({
      getCode: vi.fn(async () => "0x6000"),
      call: vi.fn(async () => encodedOwner),
      getTransaction: vi.fn(async () => null),
    });

    const result = await verifyDidPkhOwnership({
      subjectDid,
      connectedWalletDid,
      provider,
      txHash: "0x" + "ab".repeat(32),
    });

    expect(result.valid).toBe(false);
    expect(result.reason).toBe("Transaction not found");
  });

  it("accepts EIP-1967 admin slot when it matches the connected wallet", async () => {
    const { EIP1967_ADMIN_SLOT } = await import("../src/reputation/contract-ownership");
    const subjectDid = "did:pkh:eip155:66238:0x2222222222222222222222222222222222222222";
    const connectedWalletDid = "did:pkh:eip155:66238:0x1111111111111111111111111111111111111111";
    const provider = createProvider({
      getCode: vi.fn(async () => "0x6000"),
      call: vi.fn(async () => {
        throw new Error("revert");
      }),
      getStorage: vi.fn(async (_addr: string, slot: string) => {
        if (slot === EIP1967_ADMIN_SLOT) {
          return "0x" + "0".repeat(24) + "1111111111111111111111111111111111111111";
        }
        return "0x";
      }),
    });

    const result = await verifyDidPkhOwnership({
      subjectDid,
      connectedWalletDid,
      provider,
    });

    expect(result.valid).toBe(true);
    expect(result.method).toBe("contract");
    expect(result.details).toContain("EIP-1967");
  });

  it("returns invalid when DNS and DID document checks both fail", async () => {
    const result = await verifyDidWebOwnership({
      subjectDid: "did:web:example.com",
      connectedWalletDid: "did:pkh:eip155:66238:0x1111111111111111111111111111111111111111",
      resolveTxt: vi.fn().mockResolvedValue([]),
      fetchDidDocument: vi.fn().mockResolvedValue({ verificationMethod: [] }),
    });

    expect(result.valid).toBe(false);
    expect(result.reason).toBe("DID ownership verification failed");
    expect(result.details).toContain("DNS check:");
    expect(result.details).toContain("DID document check:");
  });

  it("surfaces DNS and DID document errors from thrown failures", async () => {
    const dnsDown = await verifyDidWebOwnership({
      subjectDid: "did:web:example.com",
      connectedWalletDid: "did:pkh:eip155:66238:0x1111111111111111111111111111111111111111",
      resolveTxt: vi.fn().mockRejectedValue(new Error("DNS down")),
      fetchDidDocument: vi.fn().mockRejectedValue(new Error("fetch failed")),
    });
    expect(dnsDown.valid).toBe(false);
    expect(dnsDown.details).toContain("Failed to resolve DNS TXT");
    expect(dnsDown.details).toContain("fetch failed");
  });

  it("throws when connectedWalletDid is not did:pkh", async () => {
    await expect(
      verifyDidWebOwnership({
        subjectDid: "did:web:example.com",
        connectedWalletDid: "did:web:example.com",
      })
    ).rejects.toMatchObject({ code: "INVALID_INPUT" });
  });

  it("throws when subjectDid is not a did:web identifier", async () => {
    await expect(
      verifyDidWebOwnership({
        subjectDid: "did:web:",
        connectedWalletDid: "did:pkh:eip155:66238:0x1111111111111111111111111111111111111111",
      })
    ).rejects.toMatchObject({ code: "INVALID_DID" });
  });

  it("returns invalid when EOA subject does not match connected wallet", async () => {
    const provider = createProvider({ getCode: vi.fn(async () => "0x") });
    const result = await verifyDidPkhOwnership({
      subjectDid: "did:pkh:eip155:66238:0x1111111111111111111111111111111111111111",
      connectedWalletDid: "did:pkh:eip155:66238:0x2222222222222222222222222222222222222222",
      provider,
    });
    expect(result.valid).toBe(false);
    expect(result.reason).toContain("EOA");
  });

  it("returns invalid when transfer proof cannot discover controlling wallet", async () => {
    const provider = createProvider({
      getCode: vi.fn(async () => "0x6000"),
      call: vi.fn(async () => {
        throw new Error("revert");
      }),
      getStorage: vi.fn(async () => "0x"),
    });

    const result = await verifyDidPkhOwnership({
      subjectDid: "did:pkh:eip155:66238:0x2222222222222222222222222222222222222222",
      connectedWalletDid: "did:pkh:eip155:66238:0x1111111111111111111111111111111111111111",
      provider,
      txHash: `0x${"cd".repeat(32)}`,
    });

    expect(result.valid).toBe(false);
    expect(result.reason).toBe("Could not discover controlling wallet");
  });

  it("returns invalid for transfer with wrong sender, recipient, amount, or unconfirmed tx", async () => {
    const subjectDid = "did:pkh:eip155:66238:0x2222222222222222222222222222222222222222";
    const connectedWalletDid = "did:pkh:eip155:66238:0x1111111111111111111111111111111111111111";
    const controlling = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const encodedOwner = `0x${"0".repeat(24)}${controlling.slice(2)}`;
    const expectedAmount = calculateTransferAmount(subjectDid, connectedWalletDid, 66238, "shared-control");
    const txHash = `0x${"ef".repeat(32)}`;

    const confirmedReceipt = { blockNumber: 50 };
    const baseProvider = {
      getCode: vi.fn(async () => "0x6000"),
      call: vi.fn(async () => encodedOwner),
      getTransactionReceipt: vi.fn(async () => confirmedReceipt),
    };

    const wrongSender = await verifyDidPkhOwnership({
      subjectDid,
      connectedWalletDid,
      provider: createProvider({
        ...baseProvider,
        getTransaction: vi.fn(async () => ({
          from: "0x3333333333333333333333333333333333333333",
          to: "0x1111111111111111111111111111111111111111",
          value: expectedAmount,
        })),
      }),
      txHash,
    });
    expect(wrongSender.reason).toBe("Wrong sender");

    const wrongRecipient = await verifyDidPkhOwnership({
      subjectDid,
      connectedWalletDid,
      provider: createProvider({
        ...baseProvider,
        getTransaction: vi.fn(async () => ({
          from: controlling,
          to: "0x3333333333333333333333333333333333333333",
          value: expectedAmount,
        })),
      }),
      txHash,
    });
    expect(wrongRecipient.reason).toBe("Wrong recipient");

    const wrongAmount = await verifyDidPkhOwnership({
      subjectDid,
      connectedWalletDid,
      provider: createProvider({
        ...baseProvider,
        getTransaction: vi.fn(async () => ({
          from: controlling,
          to: "0x1111111111111111111111111111111111111111",
          value: 1n,
        })),
      }),
      txHash,
    });
    expect(wrongAmount.reason).toBe("Wrong amount");

    const unconfirmed = await verifyDidPkhOwnership({
      subjectDid,
      connectedWalletDid,
      provider: createProvider({
        ...baseProvider,
        getTransaction: vi.fn(async () => ({
          from: controlling,
          to: "0x1111111111111111111111111111111111111111",
          value: expectedAmount,
        })),
        getTransactionReceipt: vi.fn(async () => null),
      }),
      txHash,
    });
    expect(unconfirmed.reason).toBe("Transaction not confirmed");
  });

  it("verifies minting-wallet when subject contract address matches connected wallet", async () => {
    const shared = "0x2222222222222222222222222222222222222222";
    const controlling = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const encodedOwner = `0x${"0".repeat(24)}${controlling.slice(2)}`;
    const provider = createProvider({
      getCode: vi.fn(async () => "0x6000"),
      call: vi.fn(async () => encodedOwner),
      getStorage: vi.fn(async () => "0x"),
    });

    const result = await verifyDidPkhOwnership({
      subjectDid: `did:pkh:eip155:66238:${shared}`,
      connectedWalletDid: `did:pkh:eip155:66238:${shared}`,
      provider,
    });

    expect(result.valid).toBe(true);
    expect(result.method).toBe("minting-wallet");
  });

  it("returns contract ownership failure with controlling wallet context", async () => {
    const subjectDid = "did:pkh:eip155:66238:0x2222222222222222222222222222222222222222";
    const connectedWalletDid = "did:pkh:eip155:66238:0x1111111111111111111111111111111111111111";
    const controlling = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const provider = createProvider({
      getCode: vi.fn(async () => "0x6000"),
      call: vi.fn(async () => `0x${"0".repeat(24)}${controlling.slice(2)}`),
    });

    const result = await verifyDidPkhOwnership({
      subjectDid,
      connectedWalletDid,
      provider,
    });

    expect(result.valid).toBe(false);
    expect(result.reason).toBe("Contract ownership verification failed");
    expect(result.details).toContain("does not match the controlling wallet");
    expect(result.controllingWalletDid).toContain(controlling.toLowerCase());
  });

  it("verifies contract ownership via getOwner() when earlier patterns fail", async () => {
    const encodedOwner =
      "0x0000000000000000000000001111111111111111111111111111111111111111";
    const provider = createProvider({
      getCode: vi.fn(async () => "0x6000"),
      call: vi.fn(async (tx: { data: string }) => {
        if (tx.data.startsWith("0x8da5cb5b") || tx.data.startsWith("0xf851a440")) {
          throw new Error("revert");
        }
        if (tx.data.startsWith("0x893d20e8")) return encodedOwner;
        throw new Error("revert");
      }),
    });

    const result = await verifyDidPkhOwnership({
      subjectDid: "did:pkh:eip155:66238:0x2222222222222222222222222222222222222222",
      connectedWalletDid: "did:pkh:eip155:66238:0x1111111111111111111111111111111111111111",
      provider,
    });

    expect(result.valid).toBe(true);
    expect(result.method).toBe("contract");
    expect(result.details).toContain("getOwner()");
  });

  it("verifies contract ownership via admin() when owner() is unavailable", async () => {
    const encodedAdmin =
      "0x0000000000000000000000001111111111111111111111111111111111111111";
    const provider = createProvider({
      getCode: vi.fn(async () => "0x6000"),
      call: vi.fn(async (tx: { data: string }) => {
        if (tx.data.startsWith("0x8da5cb5b")) throw new Error("no owner");
        if (tx.data.startsWith("0xf851a440")) return encodedAdmin;
        throw new Error("revert");
      }),
    });

    const result = await verifyDidPkhOwnership({
      subjectDid: "did:pkh:eip155:66238:0x2222222222222222222222222222222222222222",
      connectedWalletDid: "did:pkh:eip155:66238:0x1111111111111111111111111111111111111111",
      provider,
    });

    expect(result.valid).toBe(true);
    expect(result.method).toBe("contract");
    expect(result.details).toContain("admin()");
  });

  it("returns contract failure without controlling wallet when owner cannot be discovered", async () => {
    const provider = createProvider({
      getCode: vi.fn(async () => "0x6000"),
      call: vi.fn(async () => {
        throw new Error("revert");
      }),
      getStorage: vi.fn(async () => "0x"),
    });

    const result = await verifyDidPkhOwnership({
      subjectDid: "did:pkh:eip155:66238:0x2222222222222222222222222222222222222222",
      connectedWalletDid: "did:pkh:eip155:66238:0x1111111111111111111111111111111111111111",
      provider,
    });

    expect(result.valid).toBe(false);
    expect(result.controllingWalletDid).toBeUndefined();
    expect(result.details).toContain("Could not match connected wallet");
  });

  it("ignores EIP-1967 admin slot read failures and continues", async () => {
    const provider = createProvider({
      getCode: vi.fn(async () => "0x6000"),
      call: vi.fn(async () => {
        throw new Error("revert");
      }),
      getStorage: vi.fn(async () => {
        throw new Error("slot error");
      }),
    });

    const result = await verifyDidPkhOwnership({
      subjectDid: "did:pkh:eip155:66238:0x2222222222222222222222222222222222222222",
      connectedWalletDid: "did:pkh:eip155:66238:0x1111111111111111111111111111111111111111",
      provider,
    });

    expect(result.valid).toBe(false);
  });

  it("throws for invalid chain id in subjectDid", async () => {
    await expect(
      verifyDidPkhOwnership({
        subjectDid: "did:pkh:eip155:not-a-number:0x2222222222222222222222222222222222222222",
        connectedWalletDid: "did:pkh:eip155:66238:0x1111111111111111111111111111111111111111",
        provider: createProvider(),
      })
    ).rejects.toMatchObject({ code: "INVALID_INPUT" });
  });
});
