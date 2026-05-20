import { describe, expect, it } from "vitest";
import { SignJWT, exportJWK, generateKeyPair } from "jose";
import { verifyX402Artifact } from "../src/reputation/proof/x402-verify";
import type { X402Eip712Artifact } from "../src/reputation/proof/x402-eip712";
import type { X402JwsArtifact } from "../src/reputation/proof/x402-jws";

async function ecJwsPayload(payload: Record<string, unknown>) {
  const { publicKey, privateKey } = await generateKeyPair("ES256", { extractable: true });
  const publicJwk = await exportJWK(publicKey);
  const jws = await new SignJWT(payload as never)
    .setProtectedHeader({ alg: "ES256", jwk: publicJwk })
    .sign(privateKey);
  return jws;
}

describe("reputation/proof/x402-verify", () => {
  it("rejects null artifact", async () => {
    const result = await verifyX402Artifact(null as never, { artifactType: "offer" });
    expect(result).toMatchObject({
      valid: false,
      error: { code: "INVALID_ARTIFACT" },
    });
  });

  it("rejects non-object artifact", async () => {
    const result = await verifyX402Artifact("string" as never, { artifactType: "receipt" });
    expect(result).toMatchObject({
      valid: false,
      error: { code: "INVALID_ARTIFACT" },
    });
  });

  it("rejects unsupported format", async () => {
    const result = await verifyX402Artifact(
      { format: "unknown", signature: "x" } as never,
      { artifactType: "offer" }
    );
    expect(result).toMatchObject({
      valid: false,
      error: { code: "UNSUPPORTED_FORMAT", message: expect.stringContaining("unknown") },
    });
  });

  it("routes JWS offer to verifyX402JwsOffer", async () => {
    const jws = await ecJwsPayload({
      version: "1",
      resourceUrl: "https://api.example.com/r",
      scheme: "exact",
      network: "base",
      asset: "USDC",
      payTo: "0x" + "1".repeat(40),
      amount: "1",
    });
    const artifact: X402JwsArtifact = { format: "jws", signature: jws };
    const result = await verifyX402Artifact(artifact, { artifactType: "offer" });
    expect(result.valid).toBe(true);
  });

  it("routes JWS receipt to verifyX402JwsReceipt", async () => {
    const jws = await ecJwsPayload({
      version: "1",
      network: "base",
      resourceUrl: "https://api.example.com/r",
      payer: "0x" + "2".repeat(40),
      issuedAt: "2026-01-01T00:00:00Z",
    });
    const artifact: X402JwsArtifact = { format: "jws", signature: jws };
    const result = await verifyX402Artifact(artifact, { artifactType: "receipt" });
    expect(result.valid).toBe(true);
  });

  it("passes resolveOptions to JWS verification", async () => {
    const { publicKey, privateKey } = await generateKeyPair("ES256", { extractable: true });
    const publicJwk = await exportJWK(publicKey);
    const payload = {
      version: "1",
      network: "base",
      resourceUrl: "https://api.example.com/r",
      payer: "0x" + "2".repeat(40),
      issuedAt: "2026-01-01T00:00:00Z",
    };
    const jws = await new SignJWT(payload as never)
      .setProtectedHeader({ alg: "ES256", kid: "did:web:api.example.com#k1" })
      .sign(privateKey);
    const mockDoc = {
      "@context": ["https://www.w3.org/ns/did/v1"],
      id: "did:web:api.example.com",
      verificationMethod: [
        {
          id: "did:web:api.example.com#k1",
          type: "JsonWebKey2020",
          controller: "did:web:api.example.com",
          publicKeyJwk: publicJwk,
        },
      ],
    };
    const artifact: X402JwsArtifact = { format: "jws", signature: jws };
    const result = await verifyX402Artifact(artifact, {
      artifactType: "receipt",
      resolveOptions: { fetchDidDocument: async () => mockDoc },
    });
    expect(result.valid).toBe(true);
  });

  it("routes EIP-712 offer", async () => {
    const { Wallet } = await import("ethers");
    const wallet = Wallet.createRandom();
    const domain = { name: "x402 offer", version: "1", chainId: 1 };
    const types = {
      Offer: [
        { name: "version", type: "uint256" },
        { name: "resourceUrl", type: "string" },
        { name: "scheme", type: "string" },
        { name: "network", type: "string" },
        { name: "asset", type: "string" },
        { name: "payTo", type: "string" },
        { name: "amount", type: "string" },
        { name: "validUntil", type: "uint256" },
      ],
    };
    const message = {
      version: 1,
      resourceUrl: "https://x.example/p",
      scheme: "exact",
      network: "eip155:1",
      asset: "0x" + "3".repeat(40),
      payTo: wallet.address,
      amount: "1",
      validUntil: 0,
    };
    const signature = await wallet.signTypedData(domain, types, message);
    const artifact: X402Eip712Artifact = { format: "eip712", payload: message, signature };
    const result = await verifyX402Artifact(artifact, { artifactType: "offer" });
    expect(result.valid).toBe(true);
  });

  it("routes EIP-712 receipt", async () => {
    const { Wallet } = await import("ethers");
    const wallet = Wallet.createRandom();
    const domain = { name: "x402 receipt", version: "1", chainId: 1 };
    const types = {
      Receipt: [
        { name: "version", type: "uint256" },
        { name: "network", type: "string" },
        { name: "resourceUrl", type: "string" },
        { name: "payer", type: "string" },
        { name: "issuedAt", type: "uint256" },
        { name: "transaction", type: "string" },
      ],
    };
    const message = {
      version: 1,
      network: "eip155:1",
      resourceUrl: "https://x.example/p",
      payer: wallet.address,
      issuedAt: 1700000000,
      transaction: "",
    };
    const signature = await wallet.signTypedData(domain, types, message);
    const artifact: X402Eip712Artifact = { format: "eip712", payload: message, signature };
    const result = await verifyX402Artifact(artifact, { artifactType: "receipt" });
    expect(result.valid).toBe(true);
  });
});
