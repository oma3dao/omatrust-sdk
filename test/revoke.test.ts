import { describe, expect, it, vi, beforeEach } from "vitest";
import { OmaTrustError } from "../src/shared/errors";

const mockRevoke = vi.fn();
const mockConnect = vi.fn();
const mockWait = vi.fn();

vi.mock("@ethereum-attestation-service/eas-sdk", () => {
  class EAS {
    connect = mockConnect;
    revoke = mockRevoke;
    constructor(_: string) {}
  }
  return { EAS };
});

import { revokeAttestation } from "../src/reputation/revoke";
import type { Hex } from "../src/reputation/types";

const VALID_EAS_ADDR = "0x4200000000000000000000000000000000000021" as Hex;
const VALID_SCHEMA_UID = "0x" + "a".repeat(64) as Hex;
const VALID_UID = "0x" + "b".repeat(64) as Hex;
const VALID_TX_HASH = "0x" + "f".repeat(64) as Hex;

describe("reputation/revoke", () => {
  beforeEach(() => {
    mockRevoke.mockReset();
    mockConnect.mockReset();
    mockWait.mockReset();
  });

  it("throws for null params", async () => {
    await expect(revokeAttestation(null as never)).rejects.toThrow(OmaTrustError);
  });

  it("throws for non-object params", async () => {
    await expect(revokeAttestation("invalid" as never)).rejects.toThrow(OmaTrustError);
  });

  it("throws when signer is missing", async () => {
    await expect(
      revokeAttestation({
        signer: undefined as never,
        easContractAddress: VALID_EAS_ADDR,
        schemaUid: VALID_SCHEMA_UID,
        uid: VALID_UID
      })
    ).rejects.toThrow(OmaTrustError);
  });

  it("revokes attestation successfully", async () => {
    mockWait.mockResolvedValue(undefined);
    mockRevoke.mockResolvedValue({
      wait: mockWait,
      receipt: { hash: VALID_TX_HASH }
    });

    const result = await revokeAttestation({
      signer: { signTransaction: vi.fn() } as unknown,
      easContractAddress: VALID_EAS_ADDR,
      schemaUid: VALID_SCHEMA_UID,
      uid: VALID_UID
    });

    expect(result.txHash).toBe(VALID_TX_HASH);
    expect(mockConnect).toHaveBeenCalled();
    expect(mockRevoke).toHaveBeenCalled();

    const revokeCall = mockRevoke.mock.calls[0][0];
    expect(revokeCall.schema).toBe(VALID_SCHEMA_UID);
    expect(revokeCall.data.uid).toBe(VALID_UID);
    expect(revokeCall.data.value).toBe(0n);
  });

  it("uses custom value", async () => {
    mockWait.mockResolvedValue(undefined);
    mockRevoke.mockResolvedValue({
      wait: mockWait,
      hash: VALID_TX_HASH
    });

    await revokeAttestation({
      signer: { signTransaction: vi.fn() } as unknown,
      easContractAddress: VALID_EAS_ADDR,
      schemaUid: VALID_SCHEMA_UID,
      uid: VALID_UID,
      value: 500n
    });

    const revokeCall = mockRevoke.mock.calls[0][0];
    expect(revokeCall.data.value).toBe(500n);
  });

  it("wraps EAS errors as NETWORK_ERROR", async () => {
    mockRevoke.mockRejectedValue(new Error("execution reverted"));

    try {
      await revokeAttestation({
        signer: { signTransaction: vi.fn() } as unknown,
        easContractAddress: VALID_EAS_ADDR,
        schemaUid: VALID_SCHEMA_UID,
        uid: VALID_UID
      });
    } catch (err) {
      expect(err).toBeInstanceOf(OmaTrustError);
      expect((err as OmaTrustError).code).toBe("NETWORK_ERROR");
    }
  });

  it("returns receipt from transaction", async () => {
    const receiptObj = { blockNumber: 12345, status: 1 };
    mockWait.mockResolvedValue(undefined);
    mockRevoke.mockResolvedValue({
      wait: mockWait,
      receipt: receiptObj
    });

    const result = await revokeAttestation({
      signer: { signTransaction: vi.fn() } as unknown,
      easContractAddress: VALID_EAS_ADDR,
      schemaUid: VALID_SCHEMA_UID,
      uid: VALID_UID
    });

    expect(result.receipt).toEqual(receiptObj);
  });
});
