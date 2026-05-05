import { OmaTrustError } from "../shared/errors";
import type { CallControllerWitnessParams, CallControllerWitnessResult } from "./types";

async function callMethod(
  params: CallControllerWitnessParams,
  method: "dns-txt" | "did-json"
): Promise<CallControllerWitnessResult | null> {
  let response: Response;
  try {
    response = await fetch(params.gatewayUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        attestationUid: params.attestationUid,
        chainId: params.chainId,
        easContract: params.easContract,
        schemaUid: params.schemaUid,
        subject: params.subject,
        controller: params.controller,
        method
      }),
      signal: AbortSignal.timeout(params.timeoutMs ?? 15_000)
    });
  } catch (err) {
    throw new OmaTrustError("NETWORK_ERROR", "Controller witness request failed", { method, err });
  }

  const details = await response.json().catch(() => undefined);
  if (!response.ok) {
    return null;
  }

  return {
    ok: true,
    method,
    details
  };
}

export async function callControllerWitness(
  params: CallControllerWitnessParams
): Promise<CallControllerWitnessResult> {
  const dnsResult = await callMethod(params, "dns-txt").catch(() => null);
  if (dnsResult) {
    return dnsResult;
  }

  const didJsonResult = await callMethod(params, "did-json").catch(() => null);
  if (didJsonResult) {
    return didJsonResult;
  }

  return {
    ok: false,
    method: "did-json"
  };
}

import type { RequestControllerWitnessParams, RequestControllerWitnessResult } from "./types";

const DEFAULT_CONTROLLER_WITNESS_URL = "https://api.omatrust.org/v1/controller-witness";

/**
 * Request a controller witness attestation from the OMATrust backend.
 *
 * This is the recommended function for requesting controller witnesses.
 * It makes a single API call with the subject and controller DIDs.
 * The backend handles evidence discovery, attestation submission, and
 * write quota deduction.
 *
 * Requires an authenticated session (cookie-based for web clients).
 * Future versions will support x402 and OAuth DCR 2.0 for agents.
 *
 * @deprecated callControllerWitness — use requestControllerWitness instead.
 * callControllerWitness uses the legacy multi-call pattern and will be
 * removed in a future SDK version.
 */
export async function requestControllerWitness(
  params: RequestControllerWitnessParams
): Promise<RequestControllerWitnessResult> {
  const url = params.gatewayUrl ?? DEFAULT_CONTROLLER_WITNESS_URL;

  const body: Record<string, unknown> = {
    subjectDid: params.subjectDid,
    controllerDid: params.controllerDid,
  };

  if (params.chainId !== undefined) {
    body.chainId = params.chainId;
  }

  let response: Response;
  try {
    response = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "include",
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(params.timeoutMs ?? 15_000),
    });
  } catch (err) {
    throw new OmaTrustError("NETWORK_ERROR", "Controller witness request failed", { err });
  }

  if (!response.ok) {
    const errorBody = await response.json().catch(() => ({ error: response.statusText }));
    throw new OmaTrustError(
      "API_ERROR",
      (errorBody as Record<string, string>).error ?? `Controller witness failed: ${response.status}`,
      { status: response.status, ...errorBody }
    );
  }

  return (await response.json()) as RequestControllerWitnessResult;
}
