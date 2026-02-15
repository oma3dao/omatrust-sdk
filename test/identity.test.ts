import { describe, expect, it } from "vitest";
import {
  buildDidPkh,
  buildDidPkhFromCaip10,
  buildDidWeb,
  computeDidHash,
  didToAddress,
  normalizeDid,
  parseCaip10,
  parseCaip2,
  buildCaip2,
  validateDidAddress,
  canonicalizeForHash
} from "../src/identity";

describe("identity module", () => {
  it("normalizes did:web values", () => {
    expect(normalizeDid("did:web:Example.COM")).toBe("did:web:example.com");
    expect(normalizeDid("example.com")).toBe("did:web:example.com");
  });

  it("builds did:pkh from CAIP-10", () => {
    expect(buildDidPkhFromCaip10("eip155:1:0xABC")).toBe("did:pkh:eip155:1:0xabc");
    expect(buildDidPkh("eip155", 1, "0xABC")).toBe("did:pkh:eip155:1:0xabc");
  });

  it("computes deterministic DID hash and address", () => {
    const did = buildDidWeb("example.com");
    const hash = computeDidHash(did);
    const addr = didToAddress(did);
    expect(hash).toMatch(/^0x[0-9a-f]{64}$/i);
    expect(addr).toMatch(/^0x[0-9a-f]{40}$/i);
    expect(validateDidAddress(did, addr as `0x${string}`)).toBe(true);
  });

  it("parses CAIP-10 and CAIP-2", () => {
    const caip10 = parseCaip10("eip155:1:0x1234");
    expect(caip10.namespace).toBe("eip155");
    expect(caip10.reference).toBe("1");
    expect(caip10.address).toBe("0x1234");

    const caip2 = buildCaip2("eip155", "1");
    expect(parseCaip2(caip2)).toEqual({ namespace: "eip155", reference: "1" });
  });

  it("canonicalizes JSON for hash", () => {
    const first = canonicalizeForHash({ b: 1, a: 2 });
    const second = canonicalizeForHash({ a: 2, b: 1 });
    expect(first.jcsJson).toBe('{"a":2,"b":1}');
    expect(first.hash).toBe(second.hash);
  });
});
