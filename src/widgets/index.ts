export { createSigningBridge, type SigningBridgeOptions, type SigningBridge } from "./bridge";
export {
  fetchTrustAnchors,
  extractAllowlists,
  getChainAnchors,
  getSchemaAnchor,
  TRUST_ANCHORS_URL,
  type TrustAnchors,
  type ChainAnchors,
  type ApprovedIssuer,
} from "../shared/trust-anchors";
export {
  OMATRUST_READY,
  OMATRUST_HOST_READY,
  OMATRUST_SIGN_TYPED_DATA,
  OMATRUST_SIGNATURE,
  OMATRUST_SIGNATURE_ERROR,
  type OmaTrustReadyMessage,
  type OmaTrustHostReadyMessage,
  type OmaTrustSignTypedDataMessage,
  type OmaTrustSignatureMessage,
  type OmaTrustSignatureErrorMessage,
  type OmaTrustMessage,
} from "./protocol";
