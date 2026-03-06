import { describe, expect, it } from "vitest";

describe("package index", () => {
  it("exports shared, identity, reputation, and appRegistry", async () => {
    const pkg = await import("../src/index");
    expect(pkg.OmaTrustError).toBeDefined();
    expect(pkg.identity).toBeDefined();
    expect(pkg.reputation).toBeDefined();
    expect(pkg.appRegistry).toBeDefined();
  });

  it("identity exports did utilities", async () => {
    const { identity } = await import("../src/index");
    expect(typeof identity.didToAddress).toBe("function");
    expect(typeof identity.parseCaip10).toBe("function");
  });

  it("reputation exports attestation utilities", async () => {
    const { reputation } = await import("../src/index");
    expect(typeof reputation.submitAttestation).toBe("function");
    expect(typeof reputation.verifyProof).toBe("function");
    expect(typeof reputation.getAttestation).toBe("function");
  });
});
