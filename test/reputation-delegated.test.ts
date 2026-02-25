import { describe, expect, it } from "vitest";
import {
  buildDelegatedAttestationTypedData,
  buildDelegatedTypedDataFromEncoded,
  type Hex
} from "../src/reputation";

describe("reputation delegated helpers", () => {
  it("builds delegated typed data directly from encoded payload", () => {
    const typedData = buildDelegatedTypedDataFromEncoded({
      chainId: 1,
      easContractAddress: "0x4200000000000000000000000000000000000021",
      schemaUid: "0x".padEnd(66, "1") as Hex,
      encodedData: "0x1234",
      recipient: "0x1111111111111111111111111111111111111111",
      attester: "0x2222222222222222222222222222222222222222",
      nonce: 7n,
      revocable: false,
      expirationTime: 1735689600n,
      refUid: "0x".padEnd(66, "3") as Hex,
      value: 0n,
      deadline: 1735690200n
    });

    expect(typedData.message.data).toBe("0x1234");
    expect(typedData.message.recipient).toBe("0x1111111111111111111111111111111111111111");
    expect(typedData.message.expirationTime).toBe(1735689600n);
    expect(typedData.message.revocable).toBe(false);
  });

  it("matches buildDelegatedAttestationTypedData output for equivalent input", () => {
    const params = {
      chainId: 1,
      easContractAddress: "0x4200000000000000000000000000000000000021" as Hex,
      schemaUid: "0x".padEnd(66, "a") as Hex,
      schema: "string subject, string comment",
      data: {
        subject: "did:pkh:eip155:1:0x1111111111111111111111111111111111111111",
        comment: "hello"
      },
      attester: "0x2222222222222222222222222222222222222222" as Hex,
      nonce: 3n,
      revocable: true,
      expirationTime: 1735689600n,
      refUid: "0x".padEnd(66, "b") as Hex,
      value: 0n,
      deadline: 1735690200n
    };

    const generated = buildDelegatedAttestationTypedData(params);
    const rebuilt = buildDelegatedTypedDataFromEncoded({
      chainId: params.chainId,
      easContractAddress: params.easContractAddress,
      schemaUid: params.schemaUid,
      encodedData: generated.message.data as Hex,
      recipient: generated.message.recipient as Hex,
      attester: params.attester,
      nonce: params.nonce,
      revocable: params.revocable,
      expirationTime: params.expirationTime,
      refUid: params.refUid,
      value: params.value,
      deadline: params.deadline
    });

    expect(rebuilt).toEqual(generated);
  });
});
