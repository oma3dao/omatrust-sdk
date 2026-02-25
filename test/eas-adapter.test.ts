import { describe, expect, it } from "vitest";
import {
  getEasTransactionHash,
  getEasTransactionReceipt,
  isEasSchemaNotFoundError
} from "../src/reputation/eas-adapter";

describe("eas adapter", () => {
  it("extracts tx hash from receipt.hash", () => {
    const tx = {
      receipt: {
        hash: "0x".padEnd(66, "a")
      }
    };

    expect(getEasTransactionHash(tx)).toBe("0x".padEnd(66, "a"));
  });

  it("extracts tx hash from receipt.transactionHash", () => {
    const tx = {
      receipt: {
        transactionHash: "0x".padEnd(66, "b")
      }
    };

    expect(getEasTransactionHash(tx)).toBe("0x".padEnd(66, "b"));
  });

  it("falls back to legacy tx wrappers for receipt", () => {
    const tx = {
      tx: {
        hash: "0x".padEnd(66, "c")
      }
    };

    expect(getEasTransactionReceipt(tx)).toEqual(tx.tx);
    expect(getEasTransactionHash(tx)).toBe("0x".padEnd(66, "c"));
  });

  it("falls back to top-level tx hash", () => {
    const tx = {
      hash: "0x".padEnd(66, "d")
    };

    expect(getEasTransactionHash(tx)).toBe("0x".padEnd(66, "d"));
  });

  it("returns undefined when no transaction hash is available", () => {
    expect(getEasTransactionHash(null)).toBeUndefined();
    expect(getEasTransactionHash({})).toBeUndefined();
  });

  it("returns false for non-schema errors", () => {
    expect(isEasSchemaNotFoundError(new Error("network timeout"))).toBe(false);
  });

  it("detects schema-not-found errors", () => {
    expect(isEasSchemaNotFoundError(new Error("Schema not found"))).toBe(true);
  });
});
