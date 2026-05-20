import { describe, expect, it } from "vitest";
import {
  extractAuthorizationMetadata,
  type JwsVerificationResult,
} from "../src/identity/types";

const EC_P256_JWK = {
  kty: "EC",
  crv: "P-256",
  x: "f83OJ3D7xI1Yp1V2iFIYA7n5OYXc4K1Uo7jY14FKMC4",
  y: "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
};

function makeResult(overrides: Partial<JwsVerificationResult> = {}): JwsVerificationResult {
  return {
    valid: true,
    header: { alg: "ES256", kid: "did:web:api.example.com#key-1" },
    payload: {
      version: "1",
      resourceUrl: "https://api.example.com/resource",
      issuedAt: "2025-01-15T10:00:00Z",
    },
    kid: "did:web:api.example.com#key-1",
    publicKeyJwk: EC_P256_JWK,
    publicKeySource: "embedded-jwk",
    publicKeyDid: "did:jwk:eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6ImY4M09KM0Q3eEkxWXAxVjJpRklZQTduNU9ZWGMkSzFVbzdqWTE0RktNQzQiLCJ5IjoieF9GRXpSdTltMzZITE5fdHVlNjU5TE5wWFc2cEN5U3Rpa1lqS0lXSTVhMCJ9",
    ...overrides,
  };
}

describe("identity/types – extractAuthorizationMetadata", () => {
  it("extracts controllerDid from publicKeyDid", () => {
    const result = makeResult();
    const meta = extractAuthorizationMetadata(result);
    expect(meta.controllerDid).toBe(result.publicKeyDid);
  });

  it("derives subjectDid from resourceUrl", () => {
    const meta = extractAuthorizationMetadata(makeResult());
    expect(meta.subjectDid).toBe("did:web:api.example.com");
  });

  it("extracts resourceUrl from payload", () => {
    const meta = extractAuthorizationMetadata(makeResult());
    expect(meta.resourceUrl).toBe("https://api.example.com/resource");
  });

  it("extracts issuedAt from payload", () => {
    const meta = extractAuthorizationMetadata(makeResult());
    expect(meta.issuedAt).toBe("2025-01-15T10:00:00Z");
  });

  it("extracts kid from result", () => {
    const meta = extractAuthorizationMetadata(makeResult());
    expect(meta.kid).toBe("did:web:api.example.com#key-1");
  });

  it("extracts publicKeyJwk from result", () => {
    const meta = extractAuthorizationMetadata(makeResult());
    expect(meta.publicKeyJwk).toEqual(EC_P256_JWK);
  });

  it("returns null subjectDid when resourceUrl is missing", () => {
    const result = makeResult({ payload: { version: "1" } });
    const meta = extractAuthorizationMetadata(result);
    expect(meta.subjectDid).toBeNull();
    expect(meta.resourceUrl).toBeNull();
  });

  it("returns null subjectDid when resourceUrl is not a valid URL", () => {
    const result = makeResult({ payload: { resourceUrl: "not-a-url" } });
    const meta = extractAuthorizationMetadata(result);
    expect(meta.subjectDid).toBeNull();
  });

  it("returns null issuedAt when not present in payload", () => {
    const result = makeResult({ payload: { resourceUrl: "https://example.com/r" } });
    const meta = extractAuthorizationMetadata(result);
    expect(meta.issuedAt).toBeNull();
  });

  it("returns null kid when not present", () => {
    const result = makeResult({ kid: null });
    const meta = extractAuthorizationMetadata(result);
    expect(meta.kid).toBeNull();
  });
});
