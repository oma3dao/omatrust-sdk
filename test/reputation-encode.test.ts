import { describe, expect, it } from "vitest";
import { OmaTrustError } from "../src/shared/errors";
import {
  encodeAttestationData,
  validateAttestationData
} from "../src/reputation/encode";

// Smoke tests only. Test engineering can expand with full type/error matrices.
describe("reputation encoding validation", () => {
  const schema = "uint256 score, string subject, string[] proofs, bool active, address attester, bytes32 digest";

  it("encodes valid attestation payloads", () => {
    const encoded = encodeAttestationData(schema, {
      score: "42",
      subject: "did:web:example.com",
      proofs: ["proof-a", "proof-b"],
      active: true,
      attester: "0x1111111111111111111111111111111111111111",
      digest: "0x".padEnd(66, "a")
    });

    expect(encoded.startsWith("0x")).toBe(true);
    expect(encoded.length).toBeGreaterThan(2);
  });

  it("reports structured validation errors for invalid payloads", () => {
    const errors = validateAttestationData(schema, {
      score: "",
      subject: null,
      proofs: "[\"proof-a\"]",
      active: "true",
      attester: "not-an-address",
      digest: "0x1234"
    });

    expect(errors.length).toBeGreaterThan(0);
    expect(errors[0]).toEqual(expect.objectContaining({
      schemaFieldName: expect.any(String),
      expectedType: expect.any(String),
      providedType: expect.any(String)
    }));
  });

  it("throws OmaTrustError when encoding invalid data", () => {
    expect(() =>
      encodeAttestationData(schema, {
        score: "",
        subject: "did:web:example.com",
        proofs: [],
        active: true,
        attester: "0x1111111111111111111111111111111111111111",
        digest: "0x".padEnd(66, "a")
      })
    ).toThrowError(OmaTrustError);
  });
});
