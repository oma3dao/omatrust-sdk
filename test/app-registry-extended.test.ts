import { describe, expect, it } from "vitest";
import { OmaTrustError } from "../src/shared/errors";
import {
  computeInterfacesBitmap,
  parseBitmapToFlags,
  hasInterface,
  getInterfaceTypes,
  registryCodeToStatus,
  registryStatusToCode,
  isValidRegistryStatus,
  parseVersion,
  formatVersion,
  compareVersions,
  isVersionGreater,
  isVersionEqual,
  getLatestVersion,
  hashTrait,
  hashTraits,
  METADATA_KEY_DID,
  METADATA_KEY_DID_HASH,
  METADATA_KEY_DATA_HASH,
  METADATA_KEY_DATA_HASH_ALGORITHM,
  METADATA_KEY_STATUS,
  METADATA_KEY_INTERFACES,
  METADATA_KEY_VERSION_MAJOR,
  METADATA_KEY_VERSION_MINOR,
  METADATA_KEY_VERSION_PATCH,
  METADATA_KEY_TRAIT_HASHES,
  METADATA_KEY_METADATA_JSON
} from "../src/app-registry";

describe("app-registry – extended", () => {
  describe("interfaces – edge cases", () => {
    it("all false produces bitmap 0", () => {
      expect(computeInterfacesBitmap({ human: false, api: false, smartContract: false })).toBe(0);
    });

    it("all true produces bitmap 7", () => {
      expect(computeInterfacesBitmap({ human: true, api: true, smartContract: true })).toBe(7);
    });

    it("smartContract only produces bitmap 4", () => {
      expect(computeInterfacesBitmap({ human: false, api: false, smartContract: true })).toBe(4);
    });

    it("parseBitmapToFlags(0) returns all false", () => {
      expect(parseBitmapToFlags(0)).toEqual({ human: false, api: false, smartContract: false });
    });

    it("parseBitmapToFlags(7) returns all true", () => {
      expect(parseBitmapToFlags(7)).toEqual({ human: true, api: true, smartContract: true });
    });

    it("round-trips all combinations", () => {
      for (let bitmap = 0; bitmap <= 7; bitmap++) {
        const flags = parseBitmapToFlags(bitmap);
        expect(computeInterfacesBitmap(flags)).toBe(bitmap);
      }
    });

    it("hasInterface checks individual types", () => {
      expect(hasInterface(7, "human")).toBe(true);
      expect(hasInterface(7, "api")).toBe(true);
      expect(hasInterface(7, "contract")).toBe(true);
      expect(hasInterface(2, "human")).toBe(false);
      expect(hasInterface(2, "api")).toBe(true);
    });

    it("hasInterface throws for unsupported type", () => {
      expect(() => hasInterface(7, "unknown" as never)).toThrow(OmaTrustError);
    });

    it("getInterfaceTypes returns correct types for bitmap 5", () => {
      expect(getInterfaceTypes(5)).toEqual(["human", "contract"]);
    });

    it("getInterfaceTypes returns empty for bitmap 0", () => {
      expect(getInterfaceTypes(0)).toEqual([]);
    });
  });

  describe("status – extended", () => {
    it("maps all valid codes to statuses", () => {
      expect(registryCodeToStatus(0)).toBe("Active");
      expect(registryCodeToStatus(1)).toBe("Deprecated");
      expect(registryCodeToStatus(2)).toBe("Replaced");
    });

    it("maps all valid statuses to codes", () => {
      expect(registryStatusToCode("Active")).toBe(0);
      expect(registryStatusToCode("Deprecated")).toBe(1);
      expect(registryStatusToCode("Replaced")).toBe(2);
    });

    it("throws for invalid code", () => {
      expect(() => registryCodeToStatus(3)).toThrow(OmaTrustError);
      expect(() => registryCodeToStatus(-1)).toThrow(OmaTrustError);
    });

    it("throws for invalid status string", () => {
      expect(() => registryStatusToCode("Invalid" as never)).toThrow(OmaTrustError);
    });

    it("isValidRegistryStatus validates correctly", () => {
      expect(isValidRegistryStatus("Active")).toBe(true);
      expect(isValidRegistryStatus("Deprecated")).toBe(true);
      expect(isValidRegistryStatus("Replaced")).toBe(true);
      expect(isValidRegistryStatus("Invalid")).toBe(false);
      expect(isValidRegistryStatus("")).toBe(false);
      expect(isValidRegistryStatus("active")).toBe(false); // case-sensitive
    });
  });

  describe("version – extended", () => {
    it("parseVersion parses valid semver", () => {
      expect(parseVersion("0.0.0")).toEqual({ major: 0, minor: 0, patch: 0 });
      expect(parseVersion("1.2.3")).toEqual({ major: 1, minor: 2, patch: 3 });
      expect(parseVersion("99.99.99")).toEqual({ major: 99, minor: 99, patch: 99 });
    });

    it("parseVersion throws for invalid format", () => {
      expect(() => parseVersion("1.2")).toThrow(OmaTrustError);
      expect(() => parseVersion("1")).toThrow(OmaTrustError);
      expect(() => parseVersion("a.b.c")).toThrow(OmaTrustError);
      expect(() => parseVersion("")).toThrow(OmaTrustError);
      expect(() => parseVersion("1.2.3.4")).toThrow(OmaTrustError);
    });

    it("formatVersion converts back to string", () => {
      expect(formatVersion({ major: 1, minor: 2, patch: 3 })).toBe("1.2.3");
      expect(formatVersion({ major: 0, minor: 0, patch: 0 })).toBe("0.0.0");
    });

    it("parseVersion and formatVersion round-trip", () => {
      expect(formatVersion(parseVersion("1.2.3"))).toBe("1.2.3");
    });

    it("compareVersions returns correct order", () => {
      expect(compareVersions({ major: 1, minor: 0, patch: 0 }, { major: 2, minor: 0, patch: 0 })).toBe(-1);
      expect(compareVersions({ major: 2, minor: 0, patch: 0 }, { major: 1, minor: 0, patch: 0 })).toBe(1);
      expect(compareVersions({ major: 1, minor: 0, patch: 0 }, { major: 1, minor: 0, patch: 0 })).toBe(0);
    });

    it("compareVersions compares minor when major is equal", () => {
      expect(compareVersions({ major: 1, minor: 1, patch: 0 }, { major: 1, minor: 2, patch: 0 })).toBe(-1);
      expect(compareVersions({ major: 1, minor: 2, patch: 0 }, { major: 1, minor: 1, patch: 0 })).toBe(1);
    });

    it("compareVersions compares patch when major and minor are equal", () => {
      expect(compareVersions({ major: 1, minor: 1, patch: 1 }, { major: 1, minor: 1, patch: 2 })).toBe(-1);
      expect(compareVersions({ major: 1, minor: 1, patch: 2 }, { major: 1, minor: 1, patch: 1 })).toBe(1);
    });

    it("isVersionGreater works", () => {
      expect(isVersionGreater({ major: 2, minor: 0, patch: 0 }, { major: 1, minor: 0, patch: 0 })).toBe(true);
      expect(isVersionGreater({ major: 1, minor: 0, patch: 0 }, { major: 2, minor: 0, patch: 0 })).toBe(false);
      expect(isVersionGreater({ major: 1, minor: 0, patch: 0 }, { major: 1, minor: 0, patch: 0 })).toBe(false);
    });

    it("isVersionEqual works", () => {
      expect(isVersionEqual({ major: 1, minor: 2, patch: 3 }, { major: 1, minor: 2, patch: 3 })).toBe(true);
      expect(isVersionEqual({ major: 1, minor: 2, patch: 3 }, { major: 1, minor: 2, patch: 4 })).toBe(false);
    });

    it("getLatestVersion returns highest version", () => {
      const versions = [
        { major: 1, minor: 0, patch: 0 },
        { major: 3, minor: 0, patch: 0 },
        { major: 2, minor: 0, patch: 0 }
      ];
      expect(getLatestVersion(versions)).toEqual({ major: 3, minor: 0, patch: 0 });
    });

    it("getLatestVersion with single version", () => {
      expect(getLatestVersion([{ major: 1, minor: 0, patch: 0 }])).toEqual({ major: 1, minor: 0, patch: 0 });
    });

    it("getLatestVersion throws for empty array", () => {
      expect(() => getLatestVersion([])).toThrow(OmaTrustError);
    });

    it("getLatestVersion handles minor/patch differences", () => {
      const versions = [
        { major: 1, minor: 2, patch: 0 },
        { major: 1, minor: 3, patch: 0 },
        { major: 1, minor: 1, patch: 5 }
      ];
      expect(getLatestVersion(versions)).toEqual({ major: 1, minor: 3, patch: 0 });
    });
  });

  describe("traits – extended", () => {
    it("hashTrait produces deterministic hash", () => {
      const hash1 = hashTrait("security");
      const hash2 = hashTrait("security");
      expect(hash1).toBe(hash2);
    });

    it("different traits produce different hashes", () => {
      expect(hashTrait("security")).not.toBe(hashTrait("privacy"));
    });

    it("hashTrait throws for empty string", () => {
      expect(() => hashTrait("")).toThrow();
    });

    it("hashTraits hashes array of traits", () => {
      const hashes = hashTraits(["security", "privacy"]);
      expect(hashes).toHaveLength(2);
      expect(hashes[0]).toBe(hashTrait("security"));
      expect(hashes[1]).toBe(hashTrait("privacy"));
    });

    it("hashTraits returns empty array for empty input", () => {
      expect(hashTraits([])).toEqual([]);
    });

    it("hashTraits throws for non-array", () => {
      expect(() => hashTraits("not-array" as unknown as string[])).toThrow(TypeError);
    });
  });

  describe("metadata keys", () => {
    it("exports all expected metadata key constants", () => {
      expect(METADATA_KEY_DID).toBe("omat.did");
      expect(METADATA_KEY_DID_HASH).toBe("omat.didHash");
      expect(METADATA_KEY_DATA_HASH).toBe("omat.dataHash");
      expect(METADATA_KEY_DATA_HASH_ALGORITHM).toBe("omat.dataHashAlgorithm");
      expect(METADATA_KEY_STATUS).toBe("omat.status");
      expect(METADATA_KEY_INTERFACES).toBe("omat.interfaces");
      expect(METADATA_KEY_VERSION_MAJOR).toBe("omat.versionMajor");
      expect(METADATA_KEY_VERSION_MINOR).toBe("omat.versionMinor");
      expect(METADATA_KEY_VERSION_PATCH).toBe("omat.versionPatch");
      expect(METADATA_KEY_TRAIT_HASHES).toBe("omat.traitHashes");
      expect(METADATA_KEY_METADATA_JSON).toBe("omat.metadataJson");
    });
  });
});
