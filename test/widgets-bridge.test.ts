// @vitest-environment jsdom
import { beforeEach, describe, expect, it, vi } from "vitest";
import {
  OMATRUST_HOST_READY,
  OMATRUST_READY,
  OMATRUST_SIGNATURE,
  OMATRUST_SIGNATURE_ERROR,
  OMATRUST_SIGN_TYPED_DATA,
} from "../src/widgets/protocol";
import { createSigningBridge } from "../src/widgets/bridge";

const { mockFetchTrustPolicy, mockExtractAllowlists } = vi.hoisted(() => ({
  mockFetchTrustPolicy: vi.fn(),
  mockExtractAllowlists: vi.fn(),
}));

vi.mock("../src/widgets/trust-policy", () => ({
  TRUST_POLICY_URL: "https://api.omatrust.org/v1/trust-policy",
  fetchTrustPolicy: mockFetchTrustPolicy,
  extractAllowlists: mockExtractAllowlists,
}));

const allowedContract = "0x1234567890abcdef1234567890abcdef12345678";
const allowedSchema = `0x${"a".repeat(64)}`;
const attester = "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd";

function validSigningMessage(overrides: Record<string, unknown> = {}) {
  return {
    type: OMATRUST_SIGN_TYPED_DATA,
    id: "req-1",
    domain: {
      name: "EAS",
      version: "1.4.0",
      chainId: 66238,
      verifyingContract: allowedContract,
    },
    types: { Attest: [{ name: "schema", type: "bytes32" }] },
    message: {
      schema: allowedSchema,
      attester,
      deadline: Math.floor(Date.now() / 1000) + 600,
    },
    ...overrides,
  };
}

describe("widgets/bridge", () => {
  let iframe: HTMLIFrameElement;
  let source: { postMessage: ReturnType<typeof vi.fn> };

  beforeEach(() => {
    vi.restoreAllMocks();
    vi.clearAllMocks();

    mockFetchTrustPolicy.mockResolvedValue({
      version: 1,
      updatedAt: "2026-04-13T00:00:00Z",
      widgetOrigins: [],
      chains: {},
    });
    mockExtractAllowlists.mockReturnValue({
      allowedContracts: [allowedContract],
      allowedSchemas: [allowedSchema],
    });

    document.body.innerHTML = "";
    iframe = document.createElement("iframe");
    iframe.id = "widget-frame";
    iframe.src = "https://widget.omatrust.org/embed";
    document.body.appendChild(iframe);

    source = { postMessage: vi.fn() };
    Object.defineProperty(iframe, "contentWindow", {
      configurable: true,
      value: source,
    });
  });

  async function dispatchMessage(
    data: Record<string, unknown>,
    options: { origin?: string; eventSource?: unknown } = {}
  ) {
    const event = new MessageEvent("message", {
      data,
      origin: options.origin ?? "https://widget.omatrust.org",
      source: (options.eventSource ?? source) as WindowProxy,
    });
    window.dispatchEvent(event);
    // Allow async bridge handlers (including delayed signer mocks) to settle.
    await new Promise(resolve => setTimeout(resolve, 25));
  }

  it("responds to handshake with hostReady", async () => {
    const bridge = await createSigningBridge({
      iframeId: "widget-frame",
      signTypedData: vi.fn(),
    });

    await dispatchMessage({ type: OMATRUST_READY });

    expect(source.postMessage).toHaveBeenCalledWith({ type: OMATRUST_HOST_READY }, "https://widget.omatrust.org");
    bridge.destroy();
  });

  it("signs valid request and returns signature", async () => {
    const signTypedData = vi.fn().mockResolvedValue("0xsigned");
    const bridge = await createSigningBridge({
      iframeId: "widget-frame",
      signTypedData,
    });

    const request = validSigningMessage();
    await dispatchMessage(request);

    expect(signTypedData).toHaveBeenCalledWith(request.domain, request.types, request.message);
    expect(source.postMessage).toHaveBeenCalledWith(
      { type: OMATRUST_SIGNATURE, id: "req-1", signature: "0xsigned" },
      "https://widget.omatrust.org"
    );
    bridge.destroy();
  });

  it("returns signatureError when signer throws", async () => {
    const bridge = await createSigningBridge({
      iframeId: "widget-frame",
      signTypedData: vi.fn().mockRejectedValue(new Error("wallet failed")),
    });

    await dispatchMessage(validSigningMessage());

    expect(source.postMessage).toHaveBeenCalledWith(
      { type: OMATRUST_SIGNATURE_ERROR, id: "req-1", error: "wallet failed" },
      "https://widget.omatrust.org"
    );
    bridge.destroy();
  });

  it("ignores messages from untrusted origins unless override matches", async () => {
    const signTypedData = vi.fn();
    const bridge = await createSigningBridge({
      iframeId: "widget-frame",
      signTypedData,
    });

    await dispatchMessage(validSigningMessage(), { origin: "https://evil.example.com" });
    expect(signTypedData).not.toHaveBeenCalled();
    expect(source.postMessage).not.toHaveBeenCalled();

    const bridgeWithOverride = await createSigningBridge({
      iframeId: "widget-frame",
      signTypedData,
      devOriginOverride: "http://localhost:3000",
    });
    await dispatchMessage(validSigningMessage(), { origin: "http://localhost:3000" });
    expect(signTypedData).toHaveBeenCalledTimes(1);

    bridge.destroy();
    bridgeWithOverride.destroy();
  });

  it("ignores messages from wrong source window", async () => {
    const signTypedData = vi.fn();
    const bridge = await createSigningBridge({
      iframeId: "widget-frame",
      signTypedData,
    });

    await dispatchMessage(validSigningMessage(), {
      eventSource: { postMessage: vi.fn() },
    });

    expect(signTypedData).not.toHaveBeenCalled();
    expect(source.postMessage).not.toHaveBeenCalled();
    bridge.destroy();
  });

  it("ignores malformed and non-omatrust messages", async () => {
    const signTypedData = vi.fn();
    const bridge = await createSigningBridge({
      iframeId: "widget-frame",
      signTypedData,
    });

    await dispatchMessage({ type: "other:event" });
    await dispatchMessage({ foo: "bar" });

    expect(signTypedData).not.toHaveBeenCalled();
    expect(source.postMessage).not.toHaveBeenCalled();
    bridge.destroy();
  });

  it("ignores message when iframe cannot be resolved", async () => {
    const signTypedData = vi.fn();
    const bridge = await createSigningBridge({
      iframeId: "missing-frame",
      signTypedData,
    });

    await dispatchMessage(validSigningMessage());
    expect(signTypedData).not.toHaveBeenCalled();
    expect(source.postMessage).not.toHaveBeenCalled();
    bridge.destroy();
  });

  it("resolves iframe lazily and works after iframe remount", async () => {
    const signTypedData = vi.fn().mockResolvedValue("0xremounted");
    const bridge = await createSigningBridge({
      iframeId: "widget-frame",
      signTypedData,
    });

    const oldSource = source;
    const replacementIframe = document.createElement("iframe");
    replacementIframe.id = "widget-frame";
    replacementIframe.src = "https://widget.omatrust.org/new";
    const newSource = { postMessage: vi.fn() };
    Object.defineProperty(replacementIframe, "contentWindow", {
      configurable: true,
      value: newSource,
    });
    iframe.replaceWith(replacementIframe);

    await dispatchMessage(validSigningMessage(), { eventSource: oldSource });
    expect(signTypedData).not.toHaveBeenCalled();

    await dispatchMessage(validSigningMessage({ id: "req-remount" }), {
      eventSource: newSource,
    });
    expect(signTypedData).toHaveBeenCalledTimes(1);
    expect(newSource.postMessage).toHaveBeenCalledWith(
      { type: OMATRUST_SIGNATURE, id: "req-remount", signature: "0xremounted" },
      "https://widget.omatrust.org"
    );
    bridge.destroy();
  });

  it("rejects invalid EAS data with descriptive error", async () => {
    const bridge = await createSigningBridge({
      iframeId: "widget-frame",
      signTypedData: vi.fn(),
    });

    await dispatchMessage(
      validSigningMessage({
        id: 123,
      })
    );
    expect(source.postMessage).toHaveBeenLastCalledWith(
      expect.objectContaining({
        type: OMATRUST_SIGNATURE_ERROR,
        id: 123,
        error: expect.stringContaining("Missing or invalid request id"),
      }),
      "https://widget.omatrust.org"
    );

    await dispatchMessage(
      validSigningMessage({
        domain: null,
      })
    );
    expect(source.postMessage).toHaveBeenLastCalledWith(
      expect.objectContaining({
        type: OMATRUST_SIGNATURE_ERROR,
        id: "req-1",
        error: expect.stringContaining("Missing domain object"),
      }),
      "https://widget.omatrust.org"
    );

    await dispatchMessage(
      validSigningMessage({
        domain: {
          name: "BAD",
          version: "1.4.0",
          chainId: 66238,
          verifyingContract: allowedContract,
        },
      })
    );

    expect(source.postMessage).toHaveBeenCalledWith(
      expect.objectContaining({
        type: OMATRUST_SIGNATURE_ERROR,
        id: "req-1",
        error: expect.stringContaining("Signing request rejected"),
      }),
      "https://widget.omatrust.org"
    );

    await dispatchMessage(
      validSigningMessage({
        domain: {
          name: "EAS",
          version: "0.0.0",
          chainId: 66238,
          verifyingContract: allowedContract,
        },
      })
    );
    expect(source.postMessage).toHaveBeenLastCalledWith(
      expect.objectContaining({
        type: OMATRUST_SIGNATURE_ERROR,
        error: expect.stringContaining("Unexpected domain version"),
      }),
      "https://widget.omatrust.org"
    );

    await dispatchMessage(
      validSigningMessage({
        domain: {
          name: "EAS",
          version: "1.4.0",
          chainId: 0,
          verifyingContract: allowedContract,
        },
      })
    );
    expect(source.postMessage).toHaveBeenLastCalledWith(
      expect.objectContaining({
        type: OMATRUST_SIGNATURE_ERROR,
        error: expect.stringContaining("Invalid domain chainId"),
      }),
      "https://widget.omatrust.org"
    );

    await dispatchMessage(
      validSigningMessage({
        domain: {
          name: "EAS",
          version: "1.4.0",
          chainId: 66238,
          verifyingContract: "0x1234",
        },
      })
    );
    expect(source.postMessage).toHaveBeenLastCalledWith(
      expect.objectContaining({
        type: OMATRUST_SIGNATURE_ERROR,
        error: expect.stringContaining("Invalid verifyingContract"),
      }),
      "https://widget.omatrust.org"
    );

    bridge.destroy();
  });

  it("rejects non-positive deadlines", async () => {
    const bridge = await createSigningBridge({
      iframeId: "widget-frame",
      signTypedData: vi.fn(),
    });

    await dispatchMessage(
      validSigningMessage({
        message: {
          schema: allowedSchema,
          attester,
          deadline: 0,
        },
      })
    );

    expect(source.postMessage).toHaveBeenCalledWith(
      expect.objectContaining({
        type: OMATRUST_SIGNATURE_ERROR,
        error: expect.stringContaining("Invalid deadline"),
      }),
      "https://widget.omatrust.org"
    );
    bridge.destroy();
  });

  it("rejects invalid schema UID and attester", async () => {
    const bridge = await createSigningBridge({
      iframeId: "widget-frame",
      signTypedData: vi.fn(),
    });

    await dispatchMessage(
      validSigningMessage({
        message: {
          schema: "0x1234",
          attester,
          deadline: Math.floor(Date.now() / 1000) + 600,
        },
      })
    );
    expect(source.postMessage).toHaveBeenLastCalledWith(
      expect.objectContaining({
        type: OMATRUST_SIGNATURE_ERROR,
        error: expect.stringContaining("Invalid schema UID"),
      }),
      "https://widget.omatrust.org"
    );

    await dispatchMessage(
      validSigningMessage({
        message: {
          schema: allowedSchema,
          attester: "0x1234",
          deadline: Math.floor(Date.now() / 1000) + 600,
        },
      })
    );
    expect(source.postMessage).toHaveBeenLastCalledWith(
      expect.objectContaining({
        type: OMATRUST_SIGNATURE_ERROR,
        error: expect.stringContaining("Invalid attester address"),
      }),
      "https://widget.omatrust.org"
    );

    bridge.destroy();
  });

  it("rejects missing types and message objects", async () => {
    const bridge = await createSigningBridge({
      iframeId: "widget-frame",
      signTypedData: vi.fn(),
    });

    await dispatchMessage(
      validSigningMessage({
        types: null,
      })
    );
    expect(source.postMessage).toHaveBeenLastCalledWith(
      expect.objectContaining({
        type: OMATRUST_SIGNATURE_ERROR,
        error: expect.stringContaining("Missing types object"),
      }),
      "https://widget.omatrust.org"
    );

    await dispatchMessage(
      validSigningMessage({
        message: null,
      })
    );
    expect(source.postMessage).toHaveBeenLastCalledWith(
      expect.objectContaining({
        type: OMATRUST_SIGNATURE_ERROR,
        error: expect.stringContaining("Missing message object"),
      }),
      "https://widget.omatrust.org"
    );

    bridge.destroy();
  });

  it("rejects contract, schema and expired deadline not in policy", async () => {
    const bridge = await createSigningBridge({
      iframeId: "widget-frame",
      signTypedData: vi.fn(),
    });

    await dispatchMessage(
      validSigningMessage({
        domain: {
          name: "EAS",
          version: "1.4.0",
          chainId: 66238,
          verifyingContract: "0x9999999999999999999999999999999999999999",
        },
      })
    );
    expect(source.postMessage).toHaveBeenLastCalledWith(
      expect.objectContaining({
        type: OMATRUST_SIGNATURE_ERROR,
        error: expect.stringContaining("not in the OMA3 trust policy"),
      }),
      "https://widget.omatrust.org"
    );

    await dispatchMessage(
      validSigningMessage({
        message: {
          schema: `0x${"b".repeat(64)}`,
          attester,
          deadline: Math.floor(Date.now() / 1000) + 600,
        },
      })
    );
    expect(source.postMessage).toHaveBeenLastCalledWith(
      expect.objectContaining({
        type: OMATRUST_SIGNATURE_ERROR,
        error: expect.stringContaining("Schema"),
      }),
      "https://widget.omatrust.org"
    );

    await dispatchMessage(
      validSigningMessage({
        message: {
          schema: allowedSchema,
          attester,
          deadline: Math.floor(Date.now() / 1000) - 1,
        },
      })
    );
    expect(source.postMessage).toHaveBeenLastCalledWith(
      expect.objectContaining({
        type: OMATRUST_SIGNATURE_ERROR,
        error: expect.stringContaining("Deadline has passed"),
      }),
      "https://widget.omatrust.org"
    );

    bridge.destroy();
  });

  it("handles concurrent signing requests with correlated ids", async () => {
    const delayedSigner = vi
      .fn()
      .mockImplementationOnce(
        () => new Promise<string>(resolve => setTimeout(() => resolve("0xfirst"), 20))
      )
      .mockResolvedValueOnce("0xsecond");

    const bridge = await createSigningBridge({
      iframeId: "widget-frame",
      signTypedData: delayedSigner,
    });

    await Promise.all([
      dispatchMessage(validSigningMessage({ id: "req-a" })),
      dispatchMessage(validSigningMessage({ id: "req-b" })),
    ]);

    expect(delayedSigner).toHaveBeenCalledTimes(2);
    expect(source.postMessage).toHaveBeenCalledWith(
      { type: OMATRUST_SIGNATURE, id: "req-a", signature: "0xfirst" },
      "https://widget.omatrust.org"
    );
    expect(source.postMessage).toHaveBeenCalledWith(
      { type: OMATRUST_SIGNATURE, id: "req-b", signature: "0xsecond" },
      "https://widget.omatrust.org"
    );
    bridge.destroy();
  });

  it("throws when trust policy fetch fails or allowlists are empty", async () => {
    mockFetchTrustPolicy.mockRejectedValueOnce(new Error("policy unavailable"));

    await expect(
      createSigningBridge({
        iframeId: "widget-frame",
        signTypedData: vi.fn(),
      })
    ).rejects.toThrow("policy unavailable");

    mockFetchTrustPolicy.mockResolvedValueOnce({
      version: 1,
      updatedAt: "2026-04-13T00:00:00Z",
      widgetOrigins: [],
      chains: {},
    });
    mockExtractAllowlists.mockReturnValueOnce({
      allowedContracts: [],
      allowedSchemas: [],
    });

    await expect(
      createSigningBridge({
        iframeId: "widget-frame",
        signTypedData: vi.fn(),
      })
    ).rejects.toThrow("Trust policy contains no allowed contracts or schemas");
  });

  it("destroy removes the message listener", async () => {
    const removeSpy = vi.spyOn(window, "removeEventListener");
    const bridge = await createSigningBridge({
      iframeId: "widget-frame",
      signTypedData: vi.fn(),
    });

    bridge.destroy();

    expect(removeSpy).toHaveBeenCalledWith("message", expect.any(Function));
  });

  it("falls back to wildcard reply origin when iframe src cannot be parsed", async () => {
    Object.defineProperty(iframe, "src", {
      configurable: true,
      get() {
        throw new Error("bad iframe src");
      },
    });

    const bridge = await createSigningBridge({
      iframeId: "widget-frame",
      signTypedData: vi.fn(),
    });

    await dispatchMessage({ type: OMATRUST_READY });
    expect(source.postMessage).toHaveBeenCalledWith({ type: OMATRUST_HOST_READY }, "*");
    bridge.destroy();
  });
});
