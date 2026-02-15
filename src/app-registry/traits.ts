import { id } from "ethers";
import { assertString } from "../shared/assert";

type Hex = `0x${string}`;

export function hashTrait(trait: string): Hex {
  assertString(trait, "trait");
  return id(trait) as Hex;
}

export function hashTraits(traits: string[]): Hex[] {
  if (!Array.isArray(traits)) {
    throw new TypeError("traits must be an array");
  }
  return traits.map((trait) => hashTrait(trait));
}
