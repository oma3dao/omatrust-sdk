import { OmaTrustError } from "../../shared/errors";
import type { Did } from "../types";

export { parseDnsTxtRecord, buildDnsTxtRecord } from "./dns-txt-record";

export async function verifyDnsTxtControllerDid(
  domain: string,
  expectedControllerDid: Did
): Promise<{ valid: boolean; record?: string; reason?: string }> {
  throw new OmaTrustError(
    "NETWORK_ERROR",
    "verifyDnsTxtControllerDid is not available in browser runtimes",
    {
      domain,
      expectedControllerDid
    }
  );
}
