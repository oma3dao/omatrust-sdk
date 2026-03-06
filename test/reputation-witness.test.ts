import { describe, expect, it, vi, beforeEach, afterEach } from "vitest";
import { OmaTrustError } from "../src/shared/errors";
import { callControllerWitness } from "../src/reputation/witness";

const baseParams = {
  gatewayUrl: "https://gateway.example.com/verify",
  attestationUid: "0x" + "a".repeat(64) as `0x${string}`,
  chainId: 1,
  easContract: "0x" + "b".repeat(40) as `0x${string}`,
  schemaUid: "0x" + "c".repeat(64) as `0x${string}`,
  subject: "did:web:subject.com",
  controller: "did:web:controller.com"
};

describe("reputation/witness", () => {
  let fetchMock: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("returns dns-txt result when dns-txt method succeeds", async () => {
    fetchMock.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({ verified: true })
    });

    const result = await callControllerWitness(baseParams);
    expect(result.ok).toBe(true);
    expect(result.method).toBe("dns-txt");
    expect(result.details).toEqual({ verified: true });
  });

  it("sends correct POST body with method dns-txt first", async () => {
    fetchMock.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({})
    });

    await callControllerWitness(baseParams);

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const call = fetchMock.mock.calls[0];
    expect(call[0]).toBe("https://gateway.example.com/verify");
    const body = JSON.parse(call[1].body);
    expect(body.method).toBe("dns-txt");
    expect(body.attestationUid).toBe(baseParams.attestationUid);
    expect(body.chainId).toBe(1);
    expect(body.subject).toBe("did:web:subject.com");
    expect(body.controller).toBe("did:web:controller.com");
  });

  it("falls back to did-json when dns-txt fails (non-ok response)", async () => {
    // dns-txt returns non-ok
    fetchMock.mockResolvedValueOnce({
      ok: false,
      json: () => Promise.resolve({ error: "not found" })
    });
    // did-json returns ok
    fetchMock.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({ verified: true, method: "did-json" })
    });

    const result = await callControllerWitness(baseParams);
    expect(result.ok).toBe(true);
    expect(result.method).toBe("did-json");
    expect(fetchMock).toHaveBeenCalledTimes(2);

    // Check second call uses did-json
    const secondBody = JSON.parse(fetchMock.mock.calls[1][1].body);
    expect(secondBody.method).toBe("did-json");
  });

  it("falls back to did-json when dns-txt throws network error", async () => {
    // dns-txt throws
    fetchMock.mockRejectedValueOnce(new Error("DNS lookup failed"));
    // did-json succeeds
    fetchMock.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({ verified: true })
    });

    const result = await callControllerWitness(baseParams);
    expect(result.ok).toBe(true);
    expect(result.method).toBe("did-json");
  });

  it("returns ok:false when both methods fail", async () => {
    // dns-txt fails
    fetchMock.mockResolvedValueOnce({
      ok: false,
      json: () => Promise.resolve({})
    });
    // did-json also fails
    fetchMock.mockResolvedValueOnce({
      ok: false,
      json: () => Promise.resolve({})
    });

    const result = await callControllerWitness(baseParams);
    expect(result.ok).toBe(false);
    expect(result.method).toBe("did-json");
  });

  it("returns ok:false when both methods throw", async () => {
    fetchMock.mockRejectedValueOnce(new Error("network1"));
    fetchMock.mockRejectedValueOnce(new Error("network2"));

    const result = await callControllerWitness(baseParams);
    expect(result.ok).toBe(false);
    expect(result.method).toBe("did-json");
  });

  it("handles json parse failure in response gracefully", async () => {
    fetchMock.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.reject(new Error("invalid json"))
    });

    // dns-txt throws during json parse, falls back to did-json
    fetchMock.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({ verified: true })
    });

    // The callMethod catches the json error gracefully (details becomes undefined)
    // Actually looking at the code: `const details = await response.json().catch(() => undefined);`
    // So first call should succeed with details=undefined
    const result = await callControllerWitness({
      ...baseParams
    });

    expect(result.ok).toBe(true);
    expect(result.method).toBe("dns-txt");
    expect(result.details).toBeUndefined();
  });
});
