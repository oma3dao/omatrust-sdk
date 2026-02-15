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
