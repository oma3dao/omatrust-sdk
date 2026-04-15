// @vitest-environment jsdom
import { beforeEach, describe, expect, it, vi } from "vitest";

const mockPolicy = {
  version: 1,
  updatedAt: "2026-04-13T00:00:00Z",
  widgetOrigins: ["https://widget.example.com"],
  chains: {
    "1": {
      name: "Mainnet",
      easContract: "0x1234567890abcdef1234567890abcdef12345678",
      schemas: [`0x${"a".repeat(64)}`, `0x${"b".repeat(64)}`],
    },
    "10": {
      name: "Optimism",
      easContract: "0x1234567890abcdef1234567890abcdef12345678",
      schemas: [`0x${"b".repeat(64)}`, `0x${"c".repeat(64)}`],
    },
  },
};

describe("widgets/trust-policy", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    vi.useRealTimers();
  });

  it("fetches trust policy and caches it", async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => mockPolicy,
    } as Response);

    vi.resetModules();
    const mod = await import("../src/widgets/trust-policy");

    const first = await mod.fetchTrustPolicy();
    const second = await mod.fetchTrustPolicy();

    expect(first).toEqual(mockPolicy);
    expect(second).toEqual(mockPolicy);
    expect(globalThis.fetch).toHaveBeenCalledTimes(1);
  });

  it("throws when fetch returns non-ok response", async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 500,
      statusText: "Server Error",
    } as Response);

    vi.resetModules();
    const mod = await import("../src/widgets/trust-policy");

    await expect(mod.fetchTrustPolicy()).rejects.toThrow("Failed to fetch trust policy: 500 Server Error");
  });

  it("throws on invalid policy format", async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ version: 1 }),
    } as Response);

    vi.resetModules();
    const mod = await import("../src/widgets/trust-policy");

    await expect(mod.fetchTrustPolicy()).rejects.toThrow("Invalid trust policy format");
  });

  it("supports URL override for fetchTrustPolicy", async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => mockPolicy,
    } as Response);

    vi.resetModules();
    const mod = await import("../src/widgets/trust-policy");

    await mod.fetchTrustPolicy("https://custom.example/policy");
    expect(globalThis.fetch).toHaveBeenCalledWith("https://custom.example/policy");
  });

  it("re-fetches policy after cache TTL expires", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-04-15T00:00:00Z"));
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => mockPolicy,
    } as Response);

    vi.resetModules();
    const mod = await import("../src/widgets/trust-policy");

    await mod.fetchTrustPolicy();
    expect(globalThis.fetch).toHaveBeenCalledTimes(1);

    // CACHE_TTL_MS is 5 minutes; move beyond it to force a re-fetch.
    vi.setSystemTime(new Date("2026-04-15T00:06:00Z"));
    await mod.fetchTrustPolicy();
    expect(globalThis.fetch).toHaveBeenCalledTimes(2);
  });

  it("extractAllowlists returns deduplicated contracts and schemas", async () => {
    vi.resetModules();
    const mod = await import("../src/widgets/trust-policy");

    const lists = mod.extractAllowlists(mockPolicy);
    expect(lists.allowedContracts).toEqual(["0x1234567890abcdef1234567890abcdef12345678"]);
    expect(lists.allowedSchemas).toEqual([
      `0x${"a".repeat(64)}`,
      `0x${"b".repeat(64)}`,
      `0x${"c".repeat(64)}`,
    ]);
  });
});
