import { describe, expect, it } from "vitest";
import {
  computeInterfacesBitmap,
  getInterfaceTypes,
  parseBitmapToFlags,
  registryCodeToStatus,
  registryStatusToCode,
  parseVersion,
  compareVersions,
  hashTrait,
  METADATA_KEY_DID
} from "../src/app-registry";

describe("app-registry module", () => {
  it("encodes and decodes interfaces bitmap", () => {
    const bitmap = computeInterfacesBitmap({ human: true, api: true, smartContract: false });
    expect(bitmap).toBe(3);
    expect(parseBitmapToFlags(bitmap)).toEqual({ human: true, api: true, smartContract: false });
    expect(getInterfaceTypes(bitmap)).toEqual(["human", "api"]);
  });

  it("maps status values", () => {
    expect(registryCodeToStatus(0)).toBe("Active");
    expect(registryStatusToCode("Replaced")).toBe(2);
  });

  it("handles semantic version helpers", () => {
    const v1 = parseVersion("1.0.0");
    const v2 = parseVersion("1.1.0");
    expect(compareVersions(v1, v2)).toBe(-1);
  });

  it("hashes traits and exports metadata keys", () => {
    expect(hashTrait("security")).toMatch(/^0x[0-9a-f]{64}$/i);
    expect(METADATA_KEY_DID).toBe("omat.did");
  });
});
