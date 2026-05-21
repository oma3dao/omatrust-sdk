import { resolveTxt } from "node:dns/promises";
import {
  verifyDnsTxtControllerDid as verifyShared,
  type VerifyDnsTxtControllerDidOptions,
} from "./dns-txt-shared";
import type { Did } from "../types";

export { parseDnsTxtRecord, buildDnsTxtRecord } from "./dns-txt-record";
export type { DnsTxtRecordResult } from "./dns-txt-record";
export type { VerifyDnsTxtControllerDidOptions };

export function verifyDnsTxtControllerDid(
  domain: string,
  expectedControllerDid: Did,
  options: VerifyDnsTxtControllerDidOptions = {}
) {
  return verifyShared(domain, expectedControllerDid, {
    ...options,
    resolveTxt: options.resolveTxt ?? resolveTxt,
  });
}
