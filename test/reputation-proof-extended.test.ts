import { describe, expect, it, vi } from "vitest";
import { OmaTrustError } from "../src/shared/errors";
import {
  calculateTransferAmount,
  calculateTransferAmountFromAddresses,
  createTxEncodedValueProof,
  createTxInteractionProof,
  createEvidencePointerProof,
  createX402ReceiptProof,
  createX402OfferProof,
  createPopEip712Proof,
  createPopJwsProof,
  getExplorerTxUrl,
  getExplorerAddressUrl,
  formatTransferAmount,
  getSupportedChainIds,
  isChainSupported,
  getChainConstants,
  hashSeed,
  constructSeed,
  buildEip712Domain,
  getOmaTrustProofEip712Types,
  buildDnsTxtRecord,
  parseDnsTxtRecord,
  verifyEip712Signature
} from "../src/reputation";

const VALID_TX_HASH = "0x" + "a".repeat(64) as `0x${string}`;

describe("proof construction – extended", () => {
  describe("calculateTransferAmount", () => {
    it("calculates deterministic tx-encoded-value amounts", () => {
      const subject = "did:pkh:eip155:1:0x1111111111111111111111111111111111111111";
      const counterparty = "did:pkh:eip155:1:0x2222222222222222222222222222222222222222";
      const first = calculateTransferAmount(subject, counterparty, 1, "shared-control");
      const second = calculateTransferAmount(subject, counterparty, 1, "shared-control");
      expect(first).toBe(second);
    });
  });

  describe("calculateTransferAmountFromAddresses", () => {
    it("supports address wrapper and chain constants", () => {
      const amount = calculateTransferAmountFromAddresses(
        "0x1111111111111111111111111111111111111111",
        "0x2222222222222222222222222222222222222222",
        1,
        "commercial-tx"
      );
      expect(amount > 0n).toBe(true);
      expect(getChainConstants(1, "commercial-tx").nativeSymbol).toBe("ETH");
    });
  });

  describe("createTxEncodedValueProof – error cases", () => {
    it("throws for short txHash", () => {
      expect(() => createTxEncodedValueProof(1, "0x1234" as `0x${string}`, "shared-control"))
        .toThrow(OmaTrustError);
    });

    it("throws for non-hex txHash", () => {
      expect(() => createTxEncodedValueProof(1, "0x" + "g".repeat(64) as `0x${string}`, "shared-control"))
        .toThrow(OmaTrustError);
    });

    it("sets chainId as eip155 in proofObject", () => {
      const proof = createTxEncodedValueProof(137, VALID_TX_HASH, "commercial-tx");
      expect(proof.proofObject.chainId).toBe("eip155:137");
    });

    it("includes version and issuedAt", () => {
      const proof = createTxEncodedValueProof(1, VALID_TX_HASH, "shared-control");
      expect(proof.version).toBe(1);
      expect(proof.issuedAt).toBeGreaterThan(0);
    });
  });

  describe("createTxInteractionProof – error cases", () => {
    it("throws for invalid txHash", () => {
      expect(() => createTxInteractionProof(1, "0xshort" as `0x${string}`))
        .toThrow(OmaTrustError);
    });

    it("always sets proofPurpose to commercial-tx", () => {
      const proof = createTxInteractionProof(1, VALID_TX_HASH);
      expect(proof.proofPurpose).toBe("commercial-tx");
    });

    it("sets chainId as eip155 in proofObject", () => {
      const proof = createTxInteractionProof(42161, VALID_TX_HASH);
      expect(proof.proofObject.chainId).toBe("eip155:42161");
    });
  });

  describe("createEvidencePointerProof – error cases", () => {
    it("throws for empty URL", () => {
      expect(() => createEvidencePointerProof("")).toThrow(OmaTrustError);
    });

    it("throws for non-string URL", () => {
      expect(() => createEvidencePointerProof(null as unknown as string)).toThrow(OmaTrustError);
    });

    it("sets proofPurpose to shared-control", () => {
      const proof = createEvidencePointerProof("https://example.com/proof");
      expect(proof.proofPurpose).toBe("shared-control");
    });

    it("wraps URL in proofObject", () => {
      const proof = createEvidencePointerProof("https://example.com/proof");
      expect(proof.proofObject.url).toBe("https://example.com/proof");
    });
  });

  describe("createX402ReceiptProof", () => {
    it("creates x402-receipt proof wrapper", () => {
      const receipt = { txHash: "0xabc", amount: "100" };
      const proof = createX402ReceiptProof(receipt);
      expect(proof.proofType).toBe("x402-receipt");
      expect(proof.proofPurpose).toBe("commercial-tx");
      expect(proof.proofObject).toBe(receipt);
      expect(proof.version).toBe(1);
      expect(proof.issuedAt).toBeGreaterThan(0);
    });
  });

  describe("createX402OfferProof", () => {
    it("creates x402-offer proof wrapper", () => {
      const offer = { price: "50", currency: "USD" };
      const proof = createX402OfferProof(offer);
      expect(proof.proofType).toBe("x402-offer");
      expect(proof.proofPurpose).toBe("commercial-tx");
      expect(proof.proofObject).toBe(offer);
      expect(proof.version).toBe(1);
      expect(proof.issuedAt).toBeGreaterThan(0);
    });
  });

  describe("createPopEip712Proof", () => {
    it("creates a pop-eip712 proof with signing", async () => {
      const mockSignFn = async (_typedData: Record<string, unknown>) =>
        ("0x" + "ab".repeat(65)) as `0x${string}`;

      const proof = await createPopEip712Proof(
        {
          signer: "0x1111111111111111111111111111111111111111",
          authorizedEntity: "did:web:example.com",
          signingPurpose: "shared-control",
          chainId: 1
        },
        mockSignFn
      );

      expect(proof.proofType).toBe("pop-eip712");
      expect(proof.version).toBe(1);
      expect(proof.proofObject.signature).toBe("0x" + "ab".repeat(65));
      expect(proof.proofObject.message.signer).toBe("0x1111111111111111111111111111111111111111");
      expect(proof.proofObject.message.authorizedEntity).toBe("did:web:example.com");
      expect(proof.proofObject.domain.name).toBe("OMATrust Proof");
    });

    it("throws for missing signer", async () => {
      const mockSignFn = async () => "0xsig" as `0x${string}`;
      await expect(
        createPopEip712Proof(
          { signer: "", authorizedEntity: "did:web:a.com", signingPurpose: "shared-control", chainId: 1 },
          mockSignFn
        )
      ).rejects.toThrow(OmaTrustError);
    });

    it("throws for missing authorizedEntity", async () => {
      const mockSignFn = async () => "0xsig" as `0x${string}`;
      await expect(
        createPopEip712Proof(
          { signer: "0x1111111111111111111111111111111111111111", authorizedEntity: "", signingPurpose: "shared-control", chainId: 1 },
          mockSignFn
        )
      ).rejects.toThrow(OmaTrustError);
    });

    it("uses custom timestamps and randomValue when provided", async () => {
      const mockSignFn = async () => ("0x" + "cd".repeat(65)) as `0x${string}`;
      const randomValue = "0x" + "ff".repeat(32) as `0x${string}`;

      const proof = await createPopEip712Proof(
        {
          signer: "0x1111111111111111111111111111111111111111",
          authorizedEntity: "did:web:example.com",
          signingPurpose: "shared-control",
          chainId: 1,
          creationTimestamp: 1000,
          expirationTimestamp: 2000,
          randomValue,
          statement: "Custom statement"
        },
        mockSignFn
      );

      expect(proof.issuedAt).toBe(1000);
      expect(proof.expiresAt).toBe(2000);
      expect(proof.proofObject.message.randomValue).toBe(randomValue);
      expect(proof.proofObject.message.statement).toBe("Custom statement");
    });
  });

  describe("createPopJwsProof", () => {
    it("creates a pop-jws proof with signing", async () => {
      const mockSignFn = async (_payload: Record<string, unknown>, _header: Record<string, unknown>) =>
        "eyJhbGciOiJFUzI1NksifQ.eyJpc3MiOiJkaWQ6d2ViOmEuY29tIn0.fakesig";

      const proof = await createPopJwsProof(
        {
          issuer: "did:web:a.com",
          audience: "did:web:b.com",
          purpose: "shared-control"
        },
        mockSignFn
      );

      expect(proof.proofType).toBe("pop-jws");
      expect(proof.proofPurpose).toBe("shared-control");
      expect(proof.version).toBe(1);
      expect(typeof proof.proofObject).toBe("string");
      expect(proof.issuedAt).toBeDefined();
      expect(proof.expiresAt).toBeDefined();
      expect(proof.issuedAt!).toBeGreaterThan(0);
      expect(proof.expiresAt!).toBeGreaterThan(proof.issuedAt!);
    });

    it("throws for missing issuer", async () => {
      const mockSignFn = async () => "jws-token";
      await expect(
        createPopJwsProof(
          { issuer: "", audience: "did:web:b.com", purpose: "shared-control" },
          mockSignFn
        )
      ).rejects.toThrow(OmaTrustError);
    });

    it("throws for missing audience", async () => {
      const mockSignFn = async () => "jws-token";
      await expect(
        createPopJwsProof(
          { issuer: "did:web:a.com", audience: "", purpose: "shared-control" },
          mockSignFn
        )
      ).rejects.toThrow(OmaTrustError);
    });

    it("uses nonce fallback when crypto.randomUUID is unavailable", async () => {
      const originalCrypto = globalThis.crypto;
      const cryptoWithoutRandomUUID = { ...originalCrypto, randomUUID: undefined };
      vi.stubGlobal("crypto", cryptoWithoutRandomUUID);

      try {
        const mockSignFn = async (payload: Record<string, unknown>) => {
          expect(payload.nonce).toBeDefined();
          expect(typeof payload.nonce).toBe("string");
          expect(payload.nonce).toMatch(/^\d+-\d+\.\d+$/);
          return "jws-token";
        };
        const proof = await createPopJwsProof(
          {
            issuer: "did:web:a.com",
            audience: "did:web:b.com",
            purpose: "shared-control"
          },
          mockSignFn
        );
        expect(proof.proofType).toBe("pop-jws");
      } finally {
        vi.stubGlobal("crypto", originalCrypto);
      }
    });

    it("uses custom issuedAt and expiresAt when provided", async () => {
      const mockSignFn = async () => "jws-token";
      const proof = await createPopJwsProof(
        {
          issuer: "did:web:a.com",
          audience: "did:web:b.com",
          purpose: "commercial-tx",
          issuedAt: 5000,
          expiresAt: 6000,
          nonce: "custom-nonce"
        },
        mockSignFn
      );

      expect(proof.issuedAt).toBe(5000);
      expect(proof.expiresAt).toBe(6000);
    });
  });

  describe("verifyEip712Signature", () => {
    it("throws OmaTrustError for invalid signature", () => {
      const typedData = {
        domain: { name: "Test", version: "1", chainId: 1, verifyingContract: "0x" + "1".repeat(40) as `0x${string}` },
        types: { OmaTrustProof: [] },
        message: {}
      };
      expect(() => verifyEip712Signature(typedData, "0xinvalid")).toThrow(OmaTrustError);
      expect(() => verifyEip712Signature(typedData, "0xinvalid")).toThrow("Failed to verify EIP-712 signature");
    });
  });

  describe("getExplorerTxUrl", () => {
    it("returns correct URL for Ethereum mainnet", () => {
      expect(getExplorerTxUrl(1, VALID_TX_HASH)).toBe(`https://etherscan.io/tx/${VALID_TX_HASH}`);
    });

    it("returns correct URL for Polygon", () => {
      expect(getExplorerTxUrl(137, VALID_TX_HASH)).toBe(`https://polygonscan.com/tx/${VALID_TX_HASH}`);
    });

    it("returns correct URL for Base", () => {
      expect(getExplorerTxUrl(8453, VALID_TX_HASH)).toBe(`https://basescan.org/tx/${VALID_TX_HASH}`);
    });

    it("returns correct URL for Arbitrum", () => {
      expect(getExplorerTxUrl(42161, VALID_TX_HASH)).toBe(`https://arbiscan.io/tx/${VALID_TX_HASH}`);
    });

    it("returns correct URL for Optimism", () => {
      expect(getExplorerTxUrl(10, VALID_TX_HASH)).toBe(`https://optimistic.etherscan.io/tx/${VALID_TX_HASH}`);
    });

    it("returns correct URL for Sepolia", () => {
      expect(getExplorerTxUrl(11155111, VALID_TX_HASH)).toBe(`https://sepolia.etherscan.io/tx/${VALID_TX_HASH}`);
    });

    it("throws for unsupported chain", () => {
      expect(() => getExplorerTxUrl(999999, VALID_TX_HASH)).toThrow(OmaTrustError);
    });
  });

  describe("getExplorerAddressUrl", () => {
    it("returns correct address URL", () => {
      expect(getExplorerAddressUrl(1, "0xabc")).toBe("https://etherscan.io/address/0xabc");
    });

    it("throws for unsupported chain", () => {
      expect(() => getExplorerAddressUrl(999999, "0xabc")).toThrow(OmaTrustError);
    });
  });

  describe("formatTransferAmount", () => {
    it("formats bigint amount with symbol", () => {
      const result = formatTransferAmount(1000000000000000000n, 1);
      expect(result).toContain("ETH");
      expect(result).toContain("1.0");
    });

    it("formats number amount", () => {
      const result = formatTransferAmount(1000000000000000000, 1);
      expect(result).toContain("ETH");
    });

    it("uses correct symbol per chain", () => {
      expect(formatTransferAmount(1n, 137)).toContain("POL");
      expect(formatTransferAmount(1n, 6623)).toContain("OMA");
    });

    it("throws for unsupported chain", () => {
      expect(() => formatTransferAmount(1n, 999999)).toThrow(OmaTrustError);
    });
  });

  describe("getChainConstants – extended", () => {
    it("returns different base for shared-control vs commercial-tx", () => {
      const sc = getChainConstants(1, "shared-control");
      const ct = getChainConstants(1, "commercial-tx");
      expect(sc.base).not.toBe(ct.base);
    });

    it("includes range = base / 10", () => {
      const constants = getChainConstants(1, "shared-control");
      expect(constants.range).toBe(constants.base / 10n);
    });

    it("throws for unsupported chain", () => {
      expect(() => getChainConstants(999999, "shared-control")).toThrow(OmaTrustError);
    });
  });

  describe("hashSeed", () => {
    it("throws for unsupported chain", () => {
      const seed = constructSeed(
        "0x" + "a".repeat(64) as `0x${string}`,
        "0x" + "b".repeat(64) as `0x${string}`,
        "shared-control"
      );
      expect(() => hashSeed(seed, 999999)).toThrow(OmaTrustError);
    });

    it("produces 32-byte hex hash", () => {
      const seed = constructSeed(
        "0x" + "a".repeat(64) as `0x${string}`,
        "0x" + "b".repeat(64) as `0x${string}`,
        "shared-control"
      );
      const hash = hashSeed(seed, 1);
      expect(hash).toMatch(/^0x[0-9a-f]{64}$/);
    });
  });

  describe("getSupportedChainIds", () => {
    it("includes known chains", () => {
      const ids = getSupportedChainIds();
      expect(ids).toContain(1);
      expect(ids).toContain(137);
      expect(ids).toContain(8453);
      expect(ids).toContain(42161);
      expect(ids).toContain(10);
      expect(ids).toContain(11155111);
    });
  });

  describe("isChainSupported", () => {
    it("returns false for unsupported chain", () => {
      expect(isChainSupported(999999)).toBe(false);
    });
  });

  describe("buildEip712Domain", () => {
    it("constructs domain struct", () => {
      const domain = buildEip712Domain("Test", "1", 1, "0x" + "a".repeat(40) as `0x${string}`);
      expect(domain.name).toBe("Test");
      expect(domain.version).toBe("1");
      expect(domain.chainId).toBe(1);
      expect(domain.verifyingContract).toBe("0x" + "a".repeat(40));
    });
  });

  describe("getOmaTrustProofEip712Types", () => {
    it("returns OmaTrustProof type with all required fields", () => {
      const { primaryType, types } = getOmaTrustProofEip712Types();
      expect(primaryType).toBe("OmaTrustProof");
      expect(types.OmaTrustProof).toBeDefined();

      const fieldNames = types.OmaTrustProof.map((f) => f.name);
      expect(fieldNames).toContain("signer");
      expect(fieldNames).toContain("authorizedEntity");
      expect(fieldNames).toContain("signingPurpose");
      expect(fieldNames).toContain("creationTimestamp");
      expect(fieldNames).toContain("expirationTimestamp");
      expect(fieldNames).toContain("randomValue");
      expect(fieldNames).toContain("statement");
    });
  });

  describe("DNS TXT – extended", () => {
    it("parseDnsTxtRecord handles space-separated entries", () => {
      const parsed = parseDnsTxtRecord("v=1 controller=did:web:example.com");
      expect(parsed.version).toBe("1");
      expect(parsed.controller).toBe("did:web:example.com");
    });

    it("parseDnsTxtRecord handles entries with = in value", () => {
      const parsed = parseDnsTxtRecord("key=value=with=equals");
      expect(parsed["key"]).toBe("value=with=equals");
    });

    it("buildDnsTxtRecord normalizes the controller DID", () => {
      const record = buildDnsTxtRecord("did:web:Example.COM");
      expect(record).toBe("v=1;controller=did:web:example.com");
    });

    it("round-trips build then parse", () => {
      const did = "did:pkh:eip155:1:0x1111111111111111111111111111111111111111";
      const record = buildDnsTxtRecord(did);
      const parsed = parseDnsTxtRecord(record);
      expect(parsed.controller).toBe(did);
    });
  });
});
