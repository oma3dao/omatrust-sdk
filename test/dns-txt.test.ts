import { describe, expect, it, vi, beforeEach } from "vitest";
import { OmaTrustError } from "../src/shared/errors";

const mockResolveTxt = vi.fn();

vi.mock("node:dns/promises", () => ({
  resolveTxt: (...args: unknown[]) => mockResolveTxt(...args)
}));

import {
  parseDnsTxtRecord,
  buildDnsTxtRecord,
  verifyDnsTxtControllerDid
} from "../src/reputation/proof/dns-txt";

describe("proof/dns-txt", () => {
  describe("parseDnsTxtRecord", () => {
    it("throws for empty string", () => {
      expect(() => parseDnsTxtRecord("")).toThrow(OmaTrustError);
      expect(() => parseDnsTxtRecord("")).toThrow("record must be a non-empty string");
    });

    it("throws for non-string", () => {
      expect(() => parseDnsTxtRecord(null as never)).toThrow(OmaTrustError);
    });

    it("parses v and controller from semicolon-separated record", () => {
      const result = parseDnsTxtRecord("v=1;controller=did:web:example.com");
      expect(result.version).toBe("1");
      expect(result.controller).toBe("did:web:example.com");
    });

    it("skips entries with empty key", () => {
      const result = parseDnsTxtRecord("=ignored;v=1;controller=did:web:a.com");
      expect(result.version).toBe("1");
      expect(result.controller).toBe("did:web:a.com");
    });

    it("skips entries with empty value", () => {
      const result = parseDnsTxtRecord("v=1;empty=;controller=did:web:a.com");
      expect(result.version).toBe("1");
      expect(result.controller).toBe("did:web:a.com");
    });
  });

  describe("verifyDnsTxtControllerDid", () => {
    beforeEach(() => {
      mockResolveTxt.mockReset();
    });

    it("throws for empty domain", async () => {
      await expect(verifyDnsTxtControllerDid("", "did:pkh:eip155:1:0x1111111111111111111111111111111111111111"))
        .rejects.toThrow(OmaTrustError);
      await expect(verifyDnsTxtControllerDid("", "did:pkh:eip155:1:0x1111111111111111111111111111111111111111"))
        .rejects.toThrow("domain must be a non-empty string");
    });

    it("throws for non-string domain", async () => {
      await expect(
        verifyDnsTxtControllerDid(null as never, "did:pkh:eip155:1:0x1111111111111111111111111111111111111111")
      ).rejects.toThrow(OmaTrustError);
    });

    it("throws NETWORK_ERROR when DNS resolution fails", async () => {
      mockResolveTxt.mockRejectedValue(new Error("ENOTFOUND"));

      const result = await verifyDnsTxtControllerDid(
        "example.com",
        "did:pkh:eip155:1:0x1111111111111111111111111111111111111111"
      ).catch((e) => e);

      expect(result).toBeInstanceOf(OmaTrustError);
      expect((result as OmaTrustError).code).toBe("NETWORK_ERROR");
      expect(mockResolveTxt).toHaveBeenCalledWith("_omatrust.example.com");
    });

    it("normalizes domain (lowercase, strips trailing dot)", async () => {
      mockResolveTxt.mockResolvedValue([]);

      await verifyDnsTxtControllerDid(
        "EXAMPLE.COM.",
        "did:pkh:eip155:1:0x1111111111111111111111111111111111111111"
      );

      expect(mockResolveTxt).toHaveBeenCalledWith("_omatrust.example.com");
    });

    it("returns valid when v=1 record matches controller", async () => {
      const controllerDid = "did:pkh:eip155:1:0x1111111111111111111111111111111111111111";
      mockResolveTxt.mockResolvedValue([["v=1;controller=" + controllerDid]]);

      const result = await verifyDnsTxtControllerDid("example.com", controllerDid);

      expect(result.valid).toBe(true);
      expect(result.record).toBe("v=1;controller=" + controllerDid);
    });

    it("returns invalid when no record matches", async () => {
      mockResolveTxt.mockResolvedValue([["v=1;controller=did:pkh:eip155:1:0x2222222222222222222222222222222222222222"]]);

      const result = await verifyDnsTxtControllerDid(
        "example.com",
        "did:pkh:eip155:1:0x1111111111111111111111111111111111111111"
      );

      expect(result.valid).toBe(false);
      expect(result.reason).toContain("No TXT record matched");
    });

    it("returns invalid when no records returned", async () => {
      mockResolveTxt.mockResolvedValue([]);

      const result = await verifyDnsTxtControllerDid(
        "example.com",
        "did:pkh:eip155:1:0x1111111111111111111111111111111111111111"
      );

      expect(result.valid).toBe(false);
      expect(result.reason).toContain("No TXT record matched");
    });

    it("handles multi-part TXT records (joined)", async () => {
      const controllerDid = "did:pkh:eip155:1:0x1111111111111111111111111111111111111111";
      mockResolveTxt.mockResolvedValue([["v=1;controller=", controllerDid]]);

      const result = await verifyDnsTxtControllerDid("example.com", controllerDid);

      expect(result.valid).toBe(true);
      expect(result.record).toBe("v=1;controller=" + controllerDid);
    });

    it("skips non-v1 records", async () => {
      mockResolveTxt.mockResolvedValue([
        ["v=2;controller=did:pkh:eip155:1:0x1111111111111111111111111111111111111111"],
        ["v=1;controller=did:pkh:eip155:1:0x1111111111111111111111111111111111111111"]
      ]);

      const result = await verifyDnsTxtControllerDid(
        "example.com",
        "did:pkh:eip155:1:0x1111111111111111111111111111111111111111"
      );

      expect(result.valid).toBe(true);
    });

    it("matches controller with did:web normalization", async () => {
      mockResolveTxt.mockResolvedValue([["v=1;controller=did:web:example.com"]]);

      const result = await verifyDnsTxtControllerDid("example.com", "did:web:example.com");

      expect(result.valid).toBe(true);
    });
  });
});
