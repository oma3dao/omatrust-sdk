import { describe, expect, it } from "vitest";
import {
  OMATRUST_HOST_READY,
  OMATRUST_READY,
  OMATRUST_SIGNATURE,
  OMATRUST_SIGNATURE_ERROR,
  OMATRUST_SIGN_TYPED_DATA,
} from "../src/widgets/protocol";

describe("widgets/protocol", () => {
  it("exports canonical omatrust message type constants", () => {
    expect(OMATRUST_READY).toBe("omatrust:ready");
    expect(OMATRUST_HOST_READY).toBe("omatrust:hostReady");
    expect(OMATRUST_SIGN_TYPED_DATA).toBe("omatrust:signTypedData");
    expect(OMATRUST_SIGNATURE).toBe("omatrust:signature");
    expect(OMATRUST_SIGNATURE_ERROR).toBe("omatrust:signatureError");
  });

  it("keeps all protocol constants in omatrust namespace", () => {
    const types = [
      OMATRUST_READY,
      OMATRUST_HOST_READY,
      OMATRUST_SIGN_TYPED_DATA,
      OMATRUST_SIGNATURE,
      OMATRUST_SIGNATURE_ERROR,
    ];

    for (const t of types) {
      expect(t.startsWith("omatrust:")).toBe(true);
    }
    expect(new Set(types).size).toBe(types.length);
  });
});
