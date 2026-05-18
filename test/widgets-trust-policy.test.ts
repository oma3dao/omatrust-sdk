// @vitest-environment jsdom
import { beforeEach, describe, expect, it, vi } from "vitest";

const mockAnchors = {
  version: 1,
  updatedAt: "2026-04-13T00:00:00Z",
  widgetOrigins: ["https://widget.example.com"],
  chains: {
    "eip155:1": {
      name: "Mainnet",
      easContract: "0x1234567890abcdef1234567890abcdef12345678",
      schemas: { "user-review": `0x${"a".repeat(64)}`, "app-rating": `0x${"b".repeat(64)}` },
    },
    "eip155:10": {
      name: "Optimism",
      easContract: "0x1234567890abcdef1234567890abcdef12345678",
      schemas: { "app-rating": `0x${"b".repeat(64)}`, "safety-report": `0x${"c".repeat(64)}` },
    },
  },
};

describe("shared/trust-anchors", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    vi.useRealTimers();
  });

  it("fetches trust anchors and caches them", async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => mockAnchors,
    } as Response);

    vi.resetModules();
    const mod = await import("../src/shared/trust-anchors");

    const first = await mod.fetchTrustAnchors();
    const second = await mod.fetchTrustAnchors();

    expect(first).toEqual(mockAnchors);
    expect(second).toEqual(mockAnchors);
    expect(globalThis.fetch).toHaveBeenCalledTimes(1);
  });

  it("throws when fetch returns non-ok response", async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 500,
      statusText: "Server Error",
    } as Response);

    vi.resetModules();
    const mod = await import("../src/shared/trust-anchors");

    await expect(mod.fetchTrustAnchors()).rejects.toThrow("Failed to fetch trust anchors: 500 Server Error");
  });

  it("throws on invalid anchors format", async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ version: 1 }),
    } as Response);

    vi.resetModules();
    const mod = await import("../src/shared/trust-anchors");

    await expect(mod.fetchTrustAnchors()).rejects.toThrow("Invalid trust anchors format");
  });

  it("supports URL override for fetchTrustAnchors", async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => mockAnchors,
    } as Response);

    vi.resetModules();
    const mod = await import("../src/shared/trust-anchors");

    await mod.fetchTrustAnchors("https://custom.example/anchors");
    expect(globalThis.fetch).toHaveBeenCalledWith("https://custom.example/anchors");
  });

  it("re-fetches anchors after cache TTL expires", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-04-15T00:00:00Z"));
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => mockAnchors,
    } as Response);

    vi.resetModules();
    const mod = await import("../src/shared/trust-anchors");

    await mod.fetchTrustAnchors();
    expect(globalThis.fetch).toHaveBeenCalledTimes(1);

    // CACHE_TTL_MS is 5 minutes; move beyond it to force a re-fetch.
    vi.setSystemTime(new Date("2026-04-15T00:06:00Z"));
    await mod.fetchTrustAnchors();
    expect(globalThis.fetch).toHaveBeenCalledTimes(2);
  });

  it("extractAllowlists returns deduplicated contracts and schemas", async () => {
    globalThis.fetch = vi.fn() as unknown as typeof fetch;
    vi.resetModules();
    const mod = await import("../src/shared/trust-anchors");

    const lists = mod.extractAllowlists(mockAnchors);
    expect(lists.allowedContracts).toEqual(["0x1234567890abcdef1234567890abcdef12345678"]);
    expect(lists.allowedSchemas).toEqual([
      `0x${"a".repeat(64)}`,
      `0x${"b".repeat(64)}`,
      `0x${"c".repeat(64)}`,
    ]);
  });
});
