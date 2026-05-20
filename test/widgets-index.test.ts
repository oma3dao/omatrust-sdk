import { describe, expect, it } from "vitest";
import * as widgets from "../src/widgets";

describe("widgets/index", () => {
  it("re-exports widget bridge, trust anchors helpers, and protocol symbols", () => {
    expect(typeof widgets.createSigningBridge).toBe("function");
    expect(typeof widgets.fetchTrustAnchors).toBe("function");
    expect(typeof widgets.extractAllowlists).toBe("function");
    expect(widgets.OMATRUST_READY).toBe("omatrust:ready");
    expect(widgets.OMATRUST_SIGNATURE_ERROR).toBe("omatrust:signatureError");
  });
});
