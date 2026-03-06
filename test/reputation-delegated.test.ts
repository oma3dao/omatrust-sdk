import { describe, expect, it, vi, beforeEach, afterEach } from "vitest";
import { Wallet } from "ethers";
import { OmaTrustError } from "../src/shared/errors";
import {
  splitSignature,
  prepareDelegatedAttestation,
  submitDelegatedAttestation,
  buildDelegatedAttestationTypedData,
  buildDelegatedTypedDataFromEncoded
} from "../src/reputation/delegated";
import type { Hex } from "../src/reputation/types";

const VALID_EAS_ADDR = "0x4200000000000000000000000000000000000021" as Hex;
const VALID_SCHEMA_UID = "0x" + "a".repeat(64) as Hex;

describe("reputation/delegated", () => {
  describe("buildDelegatedTypedDataFromEncoded", () => {
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
        easContractAddress: VALID_EAS_ADDR,
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

  describe("splitSignature", () => {
    it("splits a valid 65-byte signature into v, r, s", async () => {
      const wallet = new Wallet("0x".padEnd(66, "1"));
      const sig = (await wallet.signMessage("test")) as Hex;

      const result = splitSignature(sig);
      expect([27, 28]).toContain(result.v);
      expect(result.r).toMatch(/^0x[0-9a-fA-F]{64}$/);
      expect(result.s).toMatch(/^0x[0-9a-fA-F]{64}$/);
      // Round-trip: recombined hex should match original
      const recombined = "0x" + result.r.slice(2) + result.s.slice(2) + (result.v === 27 ? "1b" : "1c");
      expect(sig.toLowerCase()).toBe(recombined.toLowerCase());
    });

    it("throws for invalid signature", () => {
      expect(() => splitSignature("0xinvalid")).toThrow(OmaTrustError);
    });

    it("throws for empty string", () => {
      expect(() => splitSignature("")).toThrow(OmaTrustError);
    });
  });

  describe("prepareDelegatedAttestation", () => {
    it("throws for null params", async () => {
      await expect(prepareDelegatedAttestation(null as never)).rejects.toThrow(OmaTrustError);
    });

    it("throws for non-object params", async () => {
      await expect(prepareDelegatedAttestation("bad" as never)).rejects.toThrow(OmaTrustError);
    });

    it("returns delegatedRequest and typedData", async () => {
      const result = await prepareDelegatedAttestation({
        chainId: 1,
        easContractAddress: VALID_EAS_ADDR,
        schemaUid: VALID_SCHEMA_UID,
        schema: "string subject, string comment",
        data: { subject: "did:web:example.com", comment: "hello" },
        attester: "0x1111111111111111111111111111111111111111" as Hex,
        nonce: 0n
      });

      expect(result.delegatedRequest).toBeDefined();
      expect(result.delegatedRequest.schema).toBe(VALID_SCHEMA_UID);
      expect(result.delegatedRequest.attester).toBe("0x1111111111111111111111111111111111111111");
      expect(result.delegatedRequest.easContractAddress).toBe(VALID_EAS_ADDR);
      expect(result.delegatedRequest.chainId).toBe(1);

      expect(result.typedData).toBeDefined();
      expect(result.typedData.domain).toBeDefined();
      expect(result.typedData.types).toBeDefined();
      expect(result.typedData.message).toBeDefined();
    });

    it("typedData matches buildDelegatedAttestationTypedData", async () => {
      const params = {
        chainId: 1,
        easContractAddress: VALID_EAS_ADDR,
        schemaUid: VALID_SCHEMA_UID,
        schema: "string subject",
        data: { subject: "test" },
        attester: "0x1111111111111111111111111111111111111111" as Hex,
        nonce: 5n,
        revocable: false,
        expirationTime: 1735689600n,
        deadline: 1735690200n
      };

      const prepared = await prepareDelegatedAttestation(params);
      const typedData = buildDelegatedAttestationTypedData(params);

      expect(prepared.typedData).toEqual(typedData);
    });
  });

  describe("submitDelegatedAttestation", () => {
    let fetchMock: ReturnType<typeof vi.fn>;

    beforeEach(() => {
      fetchMock = vi.fn();
      vi.stubGlobal("fetch", fetchMock);
    });

    afterEach(() => {
      vi.unstubAllGlobals();
    });

    it("throws for missing relayUrl", async () => {
      await expect(
        submitDelegatedAttestation({
          relayUrl: "",
          prepared: {} as never,
          signature: "0xsig"
        })
      ).rejects.toThrow(OmaTrustError);
    });

    it("throws for non-string relayUrl", async () => {
      await expect(
        submitDelegatedAttestation({
          relayUrl: null as unknown as string,
          prepared: {} as never,
          signature: "0xsig"
        })
      ).rejects.toThrow(OmaTrustError);
    });

    it("submits successfully and returns uid, txHash, status", async () => {
      const uid = "0x" + "bb".repeat(32);
      const txHash = "0x" + "cc".repeat(32);
      fetchMock.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ uid, txHash, status: "confirmed" })
      });

      const result = await submitDelegatedAttestation({
        relayUrl: "https://relay.example.com/submit",
        prepared: { delegatedRequest: {}, typedData: { domain: {}, types: {}, message: {} } },
        signature: "0x" + "ab".repeat(65),
        attester: "0x1111111111111111111111111111111111111111" as Hex
      });

      expect(result.uid).toBe(uid);
      expect(result.txHash).toBe(txHash);
      expect(result.status).toBe("confirmed");
    });

    it("defaults status to 'submitted' when not provided", async () => {
      fetchMock.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ uid: "0x" + "aa".repeat(32) })
      });

      const result = await submitDelegatedAttestation({
        relayUrl: "https://relay.example.com/submit",
        prepared: { delegatedRequest: {}, typedData: { domain: {}, types: {}, message: {} } },
        signature: "0xsig"
      });

      expect(result.status).toBe("submitted");
    });

    it("defaults uid to ZERO_UID when not in response", async () => {
      fetchMock.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({})
      });

      const result = await submitDelegatedAttestation({
        relayUrl: "https://relay.example.com/submit",
        prepared: { delegatedRequest: {}, typedData: { domain: {}, types: {}, message: {} } },
        signature: "0xsig"
      });

      expect(result.uid).toBe("0x" + "0".repeat(64));
    });

    it("throws NETWORK_ERROR when fetch fails", async () => {
      fetchMock.mockRejectedValueOnce(new Error("connection refused"));

      try {
        await submitDelegatedAttestation({
          relayUrl: "https://relay.example.com/submit",
          prepared: { delegatedRequest: {}, typedData: { domain: {}, types: {}, message: {} } },
          signature: "0xsig"
        });
      } catch (err) {
        expect(err).toBeInstanceOf(OmaTrustError);
        expect((err as OmaTrustError).code).toBe("NETWORK_ERROR");
      }
    });

    it("throws NETWORK_ERROR for non-ok response", async () => {
      fetchMock.mockResolvedValueOnce({
        ok: false,
        status: 400,
        json: () => Promise.resolve({ error: "bad request" })
      });

      try {
        await submitDelegatedAttestation({
          relayUrl: "https://relay.example.com/submit",
          prepared: { delegatedRequest: {}, typedData: { domain: {}, types: {}, message: {} } },
          signature: "0xsig"
        });
      } catch (err) {
        expect(err).toBeInstanceOf(OmaTrustError);
        expect((err as OmaTrustError).code).toBe("NETWORK_ERROR");
      }
    });

    it("handles non-JSON response body gracefully", async () => {
      fetchMock.mockResolvedValueOnce({
        ok: false,
        status: 500,
        json: () => Promise.reject(new Error("invalid json"))
      });

      try {
        await submitDelegatedAttestation({
          relayUrl: "https://relay.example.com/submit",
          prepared: { delegatedRequest: {}, typedData: { domain: {}, types: {}, message: {} } },
          signature: "0xsig"
        });
      } catch (err) {
        expect(err).toBeInstanceOf(OmaTrustError);
        expect((err as OmaTrustError).code).toBe("NETWORK_ERROR");
      }
    });

    it("serializes bigint values in request body", async () => {
      fetchMock.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ uid: "0x" + "aa".repeat(32) })
      });

      await submitDelegatedAttestation({
        relayUrl: "https://relay.example.com/submit",
        prepared: {
          delegatedRequest: { nonce: 7n, value: 100n },
          typedData: { domain: {}, types: {}, message: {} }
        },
        signature: "0xsig"
      });

      const body = JSON.parse(fetchMock.mock.calls[0][1].body);
      expect(body.prepared.delegatedRequest.nonce).toBe("7");
      expect(body.prepared.delegatedRequest.value).toBe("100");
    });
  });
});
