import type { Version } from "./types";
import { OmaTrustError } from "../shared/errors";

export function parseVersion(input: string): Version {
  const match = input.match(/^(\d+)\.(\d+)\.(\d+)$/);
  if (!match) {
    throw new OmaTrustError("INVALID_INPUT", "Invalid semantic version", { input });
  }

  return {
    major: Number(match[1]),
    minor: Number(match[2]),
    patch: Number(match[3])
  };
}

export function formatVersion(version: Version): string {
  return `${version.major}.${version.minor}.${version.patch}`;
}

export function compareVersions(a: Version, b: Version): -1 | 0 | 1 {
  if (a.major !== b.major) {
    return a.major < b.major ? -1 : 1;
  }
  if (a.minor !== b.minor) {
    return a.minor < b.minor ? -1 : 1;
  }
  if (a.patch !== b.patch) {
    return a.patch < b.patch ? -1 : 1;
  }
  return 0;
}

export function isVersionGreater(a: Version, b: Version): boolean {
  return compareVersions(a, b) === 1;
}

export function isVersionEqual(a: Version, b: Version): boolean {
  return compareVersions(a, b) === 0;
}

export function getLatestVersion(history: Version[]): Version {
  if (history.length === 0) {
    throw new OmaTrustError("INVALID_INPUT", "Version history cannot be empty");
  }

  return history.reduce((current, candidate) => {
    return compareVersions(candidate, current) === 1 ? candidate : current;
  });
}
