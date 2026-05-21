/**
 * Host-side signing bridge for OMATrust widget iframes.
 *
 * Handles the postMessage protocol between a host page and an embedded
 * OMATrust widget. Validates incoming EAS signing requests against the
 * OMA3 trust anchors before forwarding to the host's wallet.
 *
 * The bridge resolves the iframe element lazily by ID when messages arrive,
 * avoiding React ref timing issues with conditionally rendered iframes.
 *
 * Usage:
 *   import { createSigningBridge } from "@oma3/omatrust/widgets";
 *
 *   const bridge = await createSigningBridge({
 *     iframeId: "omatrust-widget",
 *     signTypedData: async (domain, types, message) => {
 *       return await signer.signTypedData(domain, types, message);
 *     },
 *   });
 *
 *   bridge.destroy();
 */

import {
  OMATRUST_READY,
  OMATRUST_HOST_READY,
  OMATRUST_SIGN_TYPED_DATA,
  OMATRUST_SIGNATURE,
  OMATRUST_SIGNATURE_ERROR,
} from "./protocol";
import { fetchTrustAnchors, extractAllowlists, TRUST_ANCHORS_URL } from "../shared/trust-anchors";

export type SigningBridgeOptions = {
  /**
   * The ID of the iframe element containing the widget.
   * The bridge looks up the element by ID when messages arrive,
   * so the iframe doesn't need to exist when the bridge is created.
   */
  iframeId: string;

  /**
   * Callback to sign EIP-712 typed data using the host's wallet.
   * Must return the hex-encoded signature string.
   */
  signTypedData: (
    domain: Record<string, unknown>,
    types: Record<string, unknown>,
    message: Record<string, unknown>
  ) => Promise<string>;

  /**
   * Override the allowed widget origin for local development.
   * In production, the origin is derived from the trust anchors domain
   * (*.omatrust.org) plus any widgetOrigins in the trust anchors.
   * Only set this for local dev (e.g., "http://localhost:3000").
   */
  devOriginOverride?: string;
};

export type SigningBridge = {
  /** Remove all event listeners and stop the bridge. */
  destroy: () => void;
};

// ---------------------------------------------------------------------------
// Origin resolution
// ---------------------------------------------------------------------------

function getTrustedBaseDomain(): string {
  try {
    const hostname = new URL(TRUST_ANCHORS_URL).hostname;
    const parts = hostname.split(".");
    return parts.length >= 2 ? parts.slice(-2).join(".") : hostname;
  } catch {
    return "omatrust.org";
  }
}

function isOriginTrusted(
  messageOrigin: string,
  baseDomain: string,
  policyOrigins: string[],
  devOverride?: string
): boolean {
  if (devOverride && messageOrigin === devOverride) return true;

  try {
    const hostname = new URL(messageOrigin).hostname;
    if (hostname === baseDomain || hostname.endsWith(`.${baseDomain}`)) return true;
  } catch {
    // Invalid origin
  }

  if (policyOrigins.includes(messageOrigin)) return true;

  return false;
}

// ---------------------------------------------------------------------------
// EAS request validation
// ---------------------------------------------------------------------------

const HEX_ADDRESS_RE = /^0x[a-fA-F0-9]{40}$/;
const BYTES32_RE = /^0x[a-fA-F0-9]{64}$/;

type ValidationResult =
  | { valid: true }
  | { valid: false; reason: string };

function validateEasSigningRequest(
  data: Record<string, unknown>,
  allowedSchemas: string[],
  allowedContracts: string[]
): ValidationResult {
  const { id, domain, types, message } = data;

  if (!id || typeof id !== "string") {
    return { valid: false, reason: "Missing or invalid request id" };
  }
  if (!domain || typeof domain !== "object") {
    return { valid: false, reason: "Missing domain object" };
  }

  const d = domain as Record<string, unknown>;

  if (d.name !== "EAS") {
    return { valid: false, reason: `Unexpected domain name: "${d.name}" (expected "EAS")` };
  }
  if (d.version !== "1.4.0") {
    return { valid: false, reason: `Unexpected domain version: "${d.version}" (expected "1.4.0")` };
  }
  const chainId = Number(d.chainId);
  if (!Number.isInteger(chainId) || chainId <= 0) {
    return { valid: false, reason: `Invalid domain chainId: ${d.chainId}` };
  }
  if (typeof d.verifyingContract !== "string" || !HEX_ADDRESS_RE.test(d.verifyingContract)) {
    return { valid: false, reason: `Invalid verifyingContract: ${d.verifyingContract}` };
  }

  const contractLower = (d.verifyingContract as string).toLowerCase();
  if (!allowedContracts.some(c => c.toLowerCase() === contractLower)) {
    return { valid: false, reason: `Contract ${d.verifyingContract} is not in the OMA3 trust anchors` };
  }

  if (!types || typeof types !== "object") {
    return { valid: false, reason: "Missing types object" };
  }
  if (!message || typeof message !== "object") {
    return { valid: false, reason: "Missing message object" };
  }

  const m = message as Record<string, unknown>;

  if (typeof m.schema !== "string" || !BYTES32_RE.test(m.schema)) {
    return { valid: false, reason: `Invalid schema UID: ${m.schema}` };
  }

  const schemaLower = m.schema.toLowerCase();
  if (!allowedSchemas.some(s => s.toLowerCase() === schemaLower)) {
    return { valid: false, reason: `Schema ${m.schema} is not in the OMA3 trust anchors` };
  }

  if (typeof m.attester !== "string" || !HEX_ADDRESS_RE.test(m.attester)) {
    return { valid: false, reason: `Invalid attester address: ${m.attester}` };
  }

  const deadline = Number(m.deadline);
  if (!Number.isFinite(deadline) || deadline <= 0) {
    return { valid: false, reason: `Invalid deadline: ${m.deadline}` };
  }
  const now = Math.floor(Date.now() / 1000);
  if (deadline <= now) {
    return { valid: false, reason: `Deadline has passed: ${deadline} <= ${now}` };
  }

  return { valid: true };
}

// ---------------------------------------------------------------------------
// Bridge implementation
// ---------------------------------------------------------------------------

/**
 * Create a signing bridge between the host page and an OMATrust widget iframe.
 *
 * The bridge resolves the iframe element by ID when messages arrive, not at
 * creation time. This avoids React ref timing issues — the bridge can be
 * created before the iframe is in the DOM.
 *
 * Fetches the OMA3 trust anchors on creation. Fails closed if unavailable.
 */
export async function createSigningBridge(options: SigningBridgeOptions): Promise<SigningBridge> {
  const { iframeId, signTypedData, devOriginOverride } = options;

  // Fetch the trust anchors: fail closed if unavailable.
  const anchors = await fetchTrustAnchors();
  const { allowedContracts, allowedSchemas } = extractAllowlists(anchors);

  if (allowedContracts.length === 0 || allowedSchemas.length === 0) {
    throw new Error("Trust anchors contain no allowed contracts or schemas");
  }

  const baseDomain = getTrustedBaseDomain();
  const anchorOrigins = anchors.widgetOrigins ?? [];

  async function handleMessage(event: MessageEvent) {
    const data = event.data;
    if (!data || typeof data !== "object" || typeof data.type !== "string") return;
    if (!String(data.type).startsWith("omatrust:")) return;

    // Origin check
    if (!isOriginTrusted(event.origin, baseDomain, anchorOrigins, devOriginOverride)) {
      return;
    }

    // Resolve the iframe element lazily by ID.
    // This works even if the iframe was mounted after the bridge was created.
    const iframe = document.getElementById(iframeId) as HTMLIFrameElement | null;
    if (!iframe) return;

    // Source check — must come from this specific iframe
    if (event.source !== iframe.contentWindow) {
      return;
    }

    const source = event.source as WindowProxy;

    // Determine reply origin from the iframe's current src
    const replyOrigin = devOriginOverride ?? (() => {
      try { return new URL(iframe.src).origin; }
      catch { return "*"; }
    })();

    function reply(msg: Record<string, unknown>) {
      source.postMessage(msg, replyOrigin);
    }

    // Handshake
    if (data.type === OMATRUST_READY) {
      reply({ type: OMATRUST_HOST_READY });
      return;
    }

    // Signing request
    if (data.type === OMATRUST_SIGN_TYPED_DATA) {
      const { id, domain, types, message } = data;

      const validation = validateEasSigningRequest(data, allowedSchemas, allowedContracts);
      if (!validation.valid) {
        reply({
          type: OMATRUST_SIGNATURE_ERROR,
          id: id ?? "unknown",
          error: `Signing request rejected: ${validation.reason}`,
        });
        return;
      }

      try {
        const signature = await signTypedData(domain, types, message);
        reply({ type: OMATRUST_SIGNATURE, id, signature });
      } catch (err) {
        const error = err instanceof Error ? err.message : "Signing failed";
        reply({ type: OMATRUST_SIGNATURE_ERROR, id, error });
      }
    }
  }

  window.addEventListener("message", handleMessage);

  return {
    destroy() {
      window.removeEventListener("message", handleMessage);
    },
  };
}
