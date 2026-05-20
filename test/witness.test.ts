import { describe, expect, it, vi, beforeEach, afterEach } from "vitest";
import { callControllerWitness, requestControllerWitness } from "../src/reputation/witness";
import type { CallControllerWitnessParams } from "../src/reputation/types";

describe("reputation/witness", () => {
  beforeEach(() => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({ ok: true }),
      } as Response)
    );
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  const baseParams: CallControllerWitnessParams = {
    gatewayUrl: "https://gw.example/witness",
    attestationUid: `0x${"a".repeat(64)}`,
    chainId: 1,
    easContract: `0x${"b".repeat(40)}`,
    schemaUid: `0x${"c".repeat(64)}`,
    subject: "did:web:example.com",
    controller: `did:pkh:eip155:1:0x${"1".repeat(40)}`,
    timeoutMs: 5000,
  };

  it("callControllerWitness returns dns-txt result when first POST succeeds", async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ via: "dns" }),
    } as Response);
    vi.stubGlobal("fetch", fetchMock);

    const result = await callControllerWitness(baseParams);
    expect(result?.ok).toBe(true);
    expect(result?.method).toBe("dns-txt");
    expect(result?.details).toEqual({ via: "dns" });
    expect(fetchMock).toHaveBeenCalled();
    const firstBody = JSON.parse((fetchMock.mock.calls[0][1] as RequestInit).body as string);
    expect(firstBody.method).toBe("dns-txt");
  });

  it("callControllerWitness falls back to did-json when dns-txt is not ok", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce({ ok: false, status: 404, json: async () => ({}) } as Response)
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({ via: "did" }),
      } as Response);
    vi.stubGlobal("fetch", fetchMock);

    const result = await callControllerWitness(baseParams);
    expect(result?.ok).toBe(true);
    expect(result?.method).toBe("did-json");
    const secondBody = JSON.parse((fetchMock.mock.calls[1][1] as RequestInit).body as string);
    expect(secondBody.method).toBe("did-json");
  });

  it("callControllerWitness returns ok false when both attempts fail", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({ ok: false, status: 500, json: async () => ({}) } as Response)
    );

    const result = await callControllerWitness(baseParams);
    expect(result).toEqual({ ok: false, method: "did-json" });
  });

  it("callControllerWitness returns ok false when fetch throws for both methods", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("offline")));

    const result = await callControllerWitness(baseParams);
    expect(result).toEqual({ ok: false, method: "did-json" });
  });

  it("requestControllerWitness posts subject and controller DIDs", async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ uid: "0x" + "d".repeat(64) }),
    } as Response);
    vi.stubGlobal("fetch", fetchMock);

    const out = await requestControllerWitness({
      subjectDid: "did:web:example.com",
      controllerDid: "did:pkh:eip155:1:0x" + "2".repeat(40),
      gatewayUrl: "https://gw.example/request",
    });

    expect(out).toEqual({ uid: "0x" + "d".repeat(64) });
    expect(fetchMock).toHaveBeenCalledWith(
      "https://gw.example/request",
      expect.objectContaining({
        method: "POST",
        credentials: "include",
      })
    );
    const body = JSON.parse((fetchMock.mock.calls[0][1] as RequestInit).body as string);
    expect(body.subjectDid).toBe("did:web:example.com");
    expect(body.controllerDid).toContain("did:pkh");
  });

  it("requestControllerWitness uses statusText when error JSON is unavailable", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: false,
        status: 500,
        statusText: "Internal Server Error",
        json: async () => {
          throw new Error("not json");
        },
      } as unknown as Response)
    );

    await expect(
      requestControllerWitness({
        subjectDid: "did:web:example.com",
        controllerDid: "did:pkh:eip155:1:0x" + "2".repeat(40),
      })
    ).rejects.toMatchObject({
      code: "API_ERROR",
      message: "Internal Server Error",
    });
  });

  it("requestControllerWitness throws API_ERROR on non-ok response", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: false,
        status: 403,
        statusText: "Forbidden",
        json: async () => ({ error: "quota exceeded" }),
      } as Response)
    );

    await expect(
      requestControllerWitness({
        subjectDid: "did:web:example.com",
        controllerDid: "did:pkh:eip155:1:0x" + "2".repeat(40),
      })
    ).rejects.toMatchObject({ code: "API_ERROR" });
  });

  it("includes optional chainId in request body", async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ ok: true }),
    } as Response);
    vi.stubGlobal("fetch", fetchMock);

    await requestControllerWitness({
      subjectDid: "did:web:x.com",
      controllerDid: "did:pkh:eip155:1:0x" + "4".repeat(40),
      chainId: 8453,
    });

    const body = JSON.parse((fetchMock.mock.calls[0][1] as RequestInit).body as string);
    expect(body.chainId).toBe(8453);
  });

  it("requestControllerWitness throws NETWORK_ERROR when fetch rejects", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("econnrefused")));

    await expect(
      requestControllerWitness({
        subjectDid: "did:web:x.com",
        controllerDid: "did:pkh:eip155:1:0x" + "3".repeat(40),
      })
    ).rejects.toMatchObject({ code: "NETWORK_ERROR" });
  });
});
