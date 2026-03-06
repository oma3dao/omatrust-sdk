import { describe, expect, it, vi, beforeEach } from "vitest";
import { OmaTrustError } from "../src/shared/errors";

const mockAttest = vi.fn();
const mockConnect = vi.fn();
const mockWait = vi.fn();

vi.mock("@ethereum-attestation-service/eas-sdk", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@ethereum-attestation-service/eas-sdk")>();
  return {
    ...actual,
    EAS: class {
      connect = mockConnect;
      attest = mockAttest;
      constructor(_: string) {}
    }
  };
});

import { submitAttestation } from "../src/reputation/submit";
import type { Hex } from "../src/reputation/types";

const VALID_SCHEMA_UID = "0x" + "a".repeat(64) as Hex;
const VALID_EAS_ADDR = "0x4200000000000000000000000000000000000021" as Hex;
const VALID_TX_HASH = "0x" + "f".repeat(64) as Hex;
const VALID_UID = "0x" + "b".repeat(64) as Hex;

describe("reputation/submit", () => {
  beforeEach(() => {
    mockAttest.mockReset();
    mockConnect.mockReset();
    mockWait.mockReset();
  });

  it("throws for null params", async () => {
    await expect(submitAttestation(null as never)).rejects.toThrow(OmaTrustError);
  });

  it("throws for non-object params", async () => {
    await expect(submitAttestation("invalid" as never)).rejects.toThrow(OmaTrustError);
  });

  it("throws when signer is missing", async () => {
    await expect(
      submitAttestation({
        signer: undefined as never,
        chainId: 1,
        easContractAddress: VALID_EAS_ADDR,
        schemaUid: VALID_SCHEMA_UID,
        schema: "string subject",
        data: { subject: "test" }
      })
    ).rejects.toThrow(OmaTrustError);
  });

  it("submits attestation successfully", async () => {
    mockWait.mockResolvedValue(VALID_UID);
    mockAttest.mockResolvedValue({
      wait: mockWait,
      receipt: { hash: VALID_TX_HASH }
    });

    const result = await submitAttestation({
      signer: { signTransaction: vi.fn() } as unknown,
      chainId: 1,
      easContractAddress: VALID_EAS_ADDR,
      schemaUid: VALID_SCHEMA_UID,
      schema: "string subject",
      data: { subject: "did:web:example.com" }
    });

    expect(result.uid).toBe(VALID_UID);
    expect(result.txHash).toBe(VALID_TX_HASH);
    expect(mockConnect).toHaveBeenCalled();
    expect(mockAttest).toHaveBeenCalled();

    // Verify attest was called with correct shape
    const attestCall = mockAttest.mock.calls[0][0];
    expect(attestCall.schema).toBe(VALID_SCHEMA_UID);
    expect(attestCall.data.revocable).toBe(true); // default
    expect(attestCall.data.data).toMatch(/^0x/);
  });

  it("uses custom revocable, expirationTime, refUid, and value", async () => {
    mockWait.mockResolvedValue(VALID_UID);
    mockAttest.mockResolvedValue({
      wait: mockWait,
      hash: VALID_TX_HASH
    });

    const refUid = "0x" + "c".repeat(64) as Hex;
    await submitAttestation({
      signer: { signTransaction: vi.fn() } as unknown,
      chainId: 1,
      easContractAddress: VALID_EAS_ADDR,
      schemaUid: VALID_SCHEMA_UID,
      schema: "string subject",
      data: { subject: "test" },
      revocable: false,
      expirationTime: 1735689600n,
      refUid,
      value: 100n
    });

    const attestCall = mockAttest.mock.calls[0][0];
    expect(attestCall.data.revocable).toBe(false);
    expect(attestCall.data.expirationTime).toBe(1735689600n);
    expect(attestCall.data.refUID).toBe(refUid);
    expect(attestCall.data.value).toBe(100n);
  });

  it("wraps EAS errors as NETWORK_ERROR", async () => {
    mockAttest.mockRejectedValue(new Error("execution reverted"));

    try {
      await submitAttestation({
        signer: { signTransaction: vi.fn() } as unknown,
        chainId: 1,
        easContractAddress: VALID_EAS_ADDR,
        schemaUid: VALID_SCHEMA_UID,
        schema: "string subject",
        data: { subject: "test" }
      });
    } catch (err) {
      expect(err).toBeInstanceOf(OmaTrustError);
      expect((err as OmaTrustError).code).toBe("NETWORK_ERROR");
    }
  });

  it("auto-computes subjectDidHash when schema includes it", async () => {
    mockWait.mockResolvedValue(VALID_UID);
    mockAttest.mockResolvedValue({
      wait: mockWait,
      hash: VALID_TX_HASH
    });

    await submitAttestation({
      signer: { signTransaction: vi.fn() } as unknown,
      chainId: 1,
      easContractAddress: VALID_EAS_ADDR,
      schemaUid: VALID_SCHEMA_UID,
      schema: "string subject, bytes32 subjectDidHash",
      data: { subject: "did:web:example.com" }
    });

    const attestCall = mockAttest.mock.calls[0][0];
    // The encoded data should be valid hex (includes subjectDidHash)
    expect(attestCall.data.data).toMatch(/^0x/);
  });

  it("resolves recipient from DID subject", async () => {
    mockWait.mockResolvedValue(VALID_UID);
    mockAttest.mockResolvedValue({
      wait: mockWait,
      hash: VALID_TX_HASH
    });

    await submitAttestation({
      signer: { signTransaction: vi.fn() } as unknown,
      chainId: 1,
      easContractAddress: VALID_EAS_ADDR,
      schemaUid: VALID_SCHEMA_UID,
      schema: "string subject",
      data: { subject: "did:web:example.com" }
    });

    const attestCall = mockAttest.mock.calls[0][0];
    expect(attestCall.data.recipient).toMatch(/^0x[0-9a-fA-F]{40}$/);
    expect(attestCall.data.recipient).not.toBe("0x0000000000000000000000000000000000000000");
  });

  it("uses ZERO_UID for txHash when transaction has no receipt or hash", async () => {
    mockWait.mockResolvedValue(VALID_UID);
    mockAttest.mockResolvedValue({ wait: mockWait });

    const result = await submitAttestation({
      signer: { signTransaction: vi.fn() } as unknown,
      chainId: 1,
      easContractAddress: VALID_EAS_ADDR,
      schemaUid: VALID_SCHEMA_UID,
      schema: "string subject",
      data: { subject: "did:web:example.com" }
    });

    expect(result.uid).toBe(VALID_UID);
    expect(result.txHash).toBe("0x0000000000000000000000000000000000000000000000000000000000000000");
  });
});
