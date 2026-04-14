/**
 * postMessage protocol constants and types for the OMATrust widget bridge.
 *
 * Widget (iframe) → Host:
 *   omatrust:ready           — widget loaded, requesting handshake
 *   omatrust:signTypedData   — widget requests EIP-712 signature
 *
 * Host → Widget (iframe):
 *   omatrust:hostReady        — host acknowledges the widget
 *   omatrust:signature        — host returns a signature
 *   omatrust:signatureError   — host reports a signing failure
 */

export const OMATRUST_READY = "omatrust:ready" as const;
export const OMATRUST_HOST_READY = "omatrust:hostReady" as const;
export const OMATRUST_SIGN_TYPED_DATA = "omatrust:signTypedData" as const;
export const OMATRUST_SIGNATURE = "omatrust:signature" as const;
export const OMATRUST_SIGNATURE_ERROR = "omatrust:signatureError" as const;

export type OmaTrustReadyMessage = {
  type: typeof OMATRUST_READY;
};

export type OmaTrustHostReadyMessage = {
  type: typeof OMATRUST_HOST_READY;
};

export type OmaTrustSignTypedDataMessage = {
  type: typeof OMATRUST_SIGN_TYPED_DATA;
  id: string;
  domain: Record<string, unknown>;
  types: Record<string, unknown>;
  message: Record<string, unknown>;
};

export type OmaTrustSignatureMessage = {
  type: typeof OMATRUST_SIGNATURE;
  id: string;
  signature: string;
};

export type OmaTrustSignatureErrorMessage = {
  type: typeof OMATRUST_SIGNATURE_ERROR;
  id: string;
  error: string;
};

export type OmaTrustMessage =
  | OmaTrustReadyMessage
  | OmaTrustHostReadyMessage
  | OmaTrustSignTypedDataMessage
  | OmaTrustSignatureMessage
  | OmaTrustSignatureErrorMessage;
