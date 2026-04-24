import { OmaTrustError } from "../../shared/errors";
import type { Did } from "../types";

export { parseDnsTxtRecord, buildDnsTxtRecord } from "./dns-txt-record";

export interface VerifyDnsTxtControllerDidOptions {
  resolveTxt?: (host: string) => Promise<string[][]>;
  recordPrefix?: string;
}

export async function verifyDnsTxtControllerDid(
  domain: string,
  expectedControllerDid: Did,
  options: VerifyDnsTxtControllerDidOptions = {}
): Promise<{ valid: boolean; record?: string; reason?: string }> {
  if (options.resolveTxt) {
    const { verifyDnsTxtControllerDid: verifyWithResolver } = await import("./dns-txt-shared");
    return verifyWithResolver(domain, expectedControllerDid, options);
  }

  throw new OmaTrustError(
    "NETWORK_ERROR",
    "verifyDnsTxtControllerDid is not available in browser runtimes",
    {
      domain,
      expectedControllerDid
    }
  );
}
