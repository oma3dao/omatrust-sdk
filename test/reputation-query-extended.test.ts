import { describe, expect, it } from "vitest";
import { OmaTrustError } from "../src/shared/errors";
import {
  deduplicateReviews,
  calculateAverageUserReviewRating,
  getMajorVersion
} from "../src/reputation/query";
import type { AttestationQueryResult } from "../src/reputation/types";

function makeAttestation(overrides: Partial<AttestationQueryResult> & { data?: Record<string, unknown> }): AttestationQueryResult {
  return {
    uid: "0x" + "0".repeat(64) as `0x${string}`,
    schema: "0x" + "0".repeat(64) as `0x${string}`,
    attester: "0x1111111111111111111111111111111111111111" as `0x${string}`,
    recipient: "0x2222222222222222222222222222222222222222" as `0x${string}`,
    revocable: true,
    revocationTime: 0n,
    expirationTime: 0n,
    time: 0n,
    refUID: "0x" + "0".repeat(64) as `0x${string}`,
    data: {},
    ...overrides
  };
}

describe("reputation/query – deduplication and rating", () => {
  describe("getMajorVersion", () => {
    it("extracts major version from semver string", () => {
      expect(getMajorVersion("1.2.3")).toBe(1);
      expect(getMajorVersion("0.1.0")).toBe(0);
      expect(getMajorVersion("10.0.0")).toBe(10);
    });

    it("extracts major version from partial version", () => {
      expect(getMajorVersion("3")).toBe(3);
    });

    it("throws for empty string", () => {
      expect(() => getMajorVersion("")).toThrow(OmaTrustError);
    });

    it("throws for non-numeric string", () => {
      expect(() => getMajorVersion("abc")).toThrow(OmaTrustError);
    });

    it("throws for string starting with non-digit", () => {
      expect(() => getMajorVersion("v1.0.0")).toThrow(OmaTrustError);
    });
  });

  describe("deduplicateReviews", () => {
    it("returns empty array for empty input", () => {
      expect(deduplicateReviews([])).toEqual([]);
    });

    it("returns single attestation unchanged", () => {
      const att = makeAttestation({
        data: { subject: "did:web:example.com", version: "1.0.0" }
      });
      const result = deduplicateReviews([att]);
      expect(result).toHaveLength(1);
      expect(result[0]).toBe(att);
    });

    it("deduplicates by attester + subject + major version, keeping most recent", () => {
      const older = makeAttestation({
        attester: "0x1111111111111111111111111111111111111111" as `0x${string}`,
        time: 100n,
        data: { subject: "did:web:a.com", version: "1.0.0", ratingValue: 3 }
      });
      const newer = makeAttestation({
        attester: "0x1111111111111111111111111111111111111111" as `0x${string}`,
        time: 200n,
        data: { subject: "did:web:a.com", version: "1.1.0", ratingValue: 5 }
      });
      const result = deduplicateReviews([older, newer]);
      expect(result).toHaveLength(1);
      expect(result[0].time).toBe(200n);
    });

    it("keeps separate entries for different major versions", () => {
      const v1 = makeAttestation({
        time: 100n,
        data: { subject: "did:web:a.com", version: "1.0.0" }
      });
      const v2 = makeAttestation({
        time: 200n,
        data: { subject: "did:web:a.com", version: "2.0.0" }
      });
      const result = deduplicateReviews([v1, v2]);
      expect(result).toHaveLength(2);
    });

    it("keeps separate entries for different subjects", () => {
      const a = makeAttestation({
        time: 100n,
        data: { subject: "did:web:a.com", version: "1.0.0" }
      });
      const b = makeAttestation({
        time: 200n,
        data: { subject: "did:web:b.com", version: "1.0.0" }
      });
      const result = deduplicateReviews([a, b]);
      expect(result).toHaveLength(2);
    });

    it("keeps separate entries for different attesters", () => {
      const a = makeAttestation({
        attester: "0x1111111111111111111111111111111111111111" as `0x${string}`,
        time: 100n,
        data: { subject: "did:web:a.com", version: "1.0.0" }
      });
      const b = makeAttestation({
        attester: "0x2222222222222222222222222222222222222222" as `0x${string}`,
        time: 200n,
        data: { subject: "did:web:a.com", version: "1.0.0" }
      });
      const result = deduplicateReviews([a, b]);
      expect(result).toHaveLength(2);
    });

    it("is case-insensitive on attester address", () => {
      const upper = makeAttestation({
        attester: "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" as `0x${string}`,
        time: 100n,
        data: { subject: "did:web:a.com", version: "1.0.0" }
      });
      const lower = makeAttestation({
        attester: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" as `0x${string}`,
        time: 200n,
        data: { subject: "did:web:a.com", version: "1.0.0" }
      });
      const result = deduplicateReviews([upper, lower]);
      expect(result).toHaveLength(1);
      expect(result[0].time).toBe(200n);
    });
  });

  describe("calculateAverageUserReviewRating", () => {
    it("returns 0 for empty array", () => {
      expect(calculateAverageUserReviewRating([])).toBe(0);
    });

    it("returns 0 when no attestations have ratingValue", () => {
      const att = makeAttestation({ data: { subject: "did:web:a.com", version: "1.0.0" } });
      expect(calculateAverageUserReviewRating([att])).toBe(0);
    });

    it("calculates average of number ratingValues", () => {
      const a = makeAttestation({
        attester: "0x1111111111111111111111111111111111111111" as `0x${string}`,
        time: 100n,
        data: { subject: "did:web:a.com", version: "1.0.0", ratingValue: 4 }
      });
      const b = makeAttestation({
        attester: "0x2222222222222222222222222222222222222222" as `0x${string}`,
        time: 100n,
        data: { subject: "did:web:a.com", version: "1.0.0", ratingValue: 6 }
      });
      expect(calculateAverageUserReviewRating([a, b])).toBe(5);
    });

    it("handles bigint ratingValues", () => {
      const att = makeAttestation({
        time: 100n,
        data: { subject: "did:web:a.com", version: "1.0.0", ratingValue: 10n }
      });
      expect(calculateAverageUserReviewRating([att])).toBe(10);
    });

    it("ignores string ratingValues (non-numeric types)", () => {
      const withStr = makeAttestation({
        attester: "0x1111111111111111111111111111111111111111" as `0x${string}`,
        time: 100n,
        data: { subject: "did:web:a.com", version: "1.0.0", ratingValue: "five" }
      });
      const withNum = makeAttestation({
        attester: "0x2222222222222222222222222222222222222222" as `0x${string}`,
        time: 100n,
        data: { subject: "did:web:a.com", version: "1.0.0", ratingValue: 8 }
      });
      expect(calculateAverageUserReviewRating([withStr, withNum])).toBe(8);
    });

    it("deduplicates before averaging (same attester, same subject, same major)", () => {
      const old = makeAttestation({
        attester: "0x1111111111111111111111111111111111111111" as `0x${string}`,
        time: 100n,
        data: { subject: "did:web:a.com", version: "1.0.0", ratingValue: 2 }
      });
      const newer = makeAttestation({
        attester: "0x1111111111111111111111111111111111111111" as `0x${string}`,
        time: 200n,
        data: { subject: "did:web:a.com", version: "1.1.0", ratingValue: 8 }
      });
      // Should only use the newer rating (8), not average of (2, 8)
      expect(calculateAverageUserReviewRating([old, newer])).toBe(8);
    });
  });
});
