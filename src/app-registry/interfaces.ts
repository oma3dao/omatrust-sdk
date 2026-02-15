import type { InterfaceFlags, InterfaceType } from "./types";
import { OmaTrustError } from "../shared/errors";

const BIT_HUMAN = 1;
const BIT_API = 2;
const BIT_CONTRACT = 4;

export function computeInterfacesBitmap(flags: InterfaceFlags): number {
  return (flags.human ? BIT_HUMAN : 0) +
    (flags.api ? BIT_API : 0) +
    (flags.smartContract ? BIT_CONTRACT : 0);
}

export function parseBitmapToFlags(bitmap: number): InterfaceFlags {
  return {
    human: (bitmap & BIT_HUMAN) !== 0,
    api: (bitmap & BIT_API) !== 0,
    smartContract: (bitmap & BIT_CONTRACT) !== 0
  };
}

export function hasInterface(bitmap: number, type: InterfaceType): boolean {
  switch (type) {
    case "human":
      return (bitmap & BIT_HUMAN) !== 0;
    case "api":
      return (bitmap & BIT_API) !== 0;
    case "contract":
      return (bitmap & BIT_CONTRACT) !== 0;
    default:
      throw new OmaTrustError("INVALID_INPUT", "Unsupported interface type", { type });
  }
}

export function getInterfaceTypes(bitmap: number): InterfaceType[] {
  const results: InterfaceType[] = [];
  if (hasInterface(bitmap, "human")) {
    results.push("human");
  }
  if (hasInterface(bitmap, "api")) {
    results.push("api");
  }
  if (hasInterface(bitmap, "contract")) {
    results.push("contract");
  }
  return results;
}
