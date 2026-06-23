import canonicalize from "canonicalize";
import { keccak256, sha256, toUtf8Bytes } from "ethers";
import { OmaTrustError } from "../shared/errors";

type Hex = `0x${string}`;

const VALID_ALGORITHMS = new Set(["keccak256", "sha256"]);

/** Maximum JSON nesting depth allowed. */
const MAX_JSON_DEPTH = 32;

function assertDepthLimit(depth: number, context?: string): void {
  if (depth > MAX_JSON_DEPTH) {
    const msg = context
      ? `JSON nesting depth exceeds maximum of ${MAX_JSON_DEPTH} at ${context}`
      : `JSON nesting depth exceeds maximum of ${MAX_JSON_DEPTH}`;
    throw new OmaTrustError("INVALID_INPUT", msg);
  }
}

/**
 * Parse JSON strictly, rejecting duplicate keys.
 * Standard JSON.parse() silently accepts duplicates (last-wins).
 * This function detects duplicates at any nesting depth and throws.
 */
export function parseJsonStrict(input: string): unknown {
  if (typeof input !== "string") {
    throw new OmaTrustError("INVALID_INPUT", "Input must be a string");
  }

  // First pass: detect duplicate keys by scanning object literals
  const seen = new Map<string, Set<string>>();
  let pathStack: string[] = [];
  let depth = 0;

  // Use a reviver to track keys at each depth
  const keyTracker = new Map<number, Set<string>>();

  // Parse with a reviver that tracks keys per object depth
  // JSON.parse calls the reviver bottom-up, so we use a different approach:
  // scan the raw string for duplicate keys using a state machine.
  const duplicateKeys = detectDuplicateKeys(input);
  if (duplicateKeys.length > 0) {
    throw new OmaTrustError(
      "INVALID_INPUT",
      `Duplicate JSON key${duplicateKeys.length > 1 ? "s" : ""} detected: ${duplicateKeys.map(k => `"${k}"`).join(", ")}`,
      { duplicateKeys }
    );
  }

  try {
    return JSON.parse(input);
  } catch {
    throw new OmaTrustError("INVALID_INPUT", "Input is not valid JSON");
  }
}

/**
 * Detect duplicate keys in a JSON string.
 * Returns an array of key names that appear more than once in any single object.
 */
function detectDuplicateKeys(input: string): string[] {
  const duplicates: string[] = [];
  // Stack of sets — each set tracks keys for the current object nesting level
  const objectKeyStack: Set<string>[] = [];
  let inString = false;
  let escaped = false;
  let currentKey = "";
  let collectingKey = false;
  let afterColon = false;
  let i = 0;

  while (i < input.length) {
    const ch = input[i];

    if (escaped) {
      if (collectingKey) currentKey += ch;
      escaped = false;
      i++;
      continue;
    }

    if (ch === "\\") {
      escaped = true;
      if (collectingKey) currentKey += ch;
      i++;
      continue;
    }

    if (ch === '"') {
      if (!inString) {
        inString = true;
        // If we're in an object context and not after a colon, this is a key
        if (objectKeyStack.length > 0 && !afterColon) {
          collectingKey = true;
          currentKey = "";
        }
      } else {
        inString = false;
        if (collectingKey) {
          collectingKey = false;
          const keySet = objectKeyStack[objectKeyStack.length - 1];
          if (keySet.has(currentKey)) {
            if (!duplicates.includes(currentKey)) {
              duplicates.push(currentKey);
            }
          } else {
            keySet.add(currentKey);
          }
        }
      }
      i++;
      continue;
    }

    if (inString) {
      if (collectingKey) currentKey += ch;
      i++;
      continue;
    }

    // Outside string
    if (ch === "{") {
      objectKeyStack.push(new Set());
      assertDepthLimit(objectKeyStack.length);
      afterColon = false;
    } else if (ch === "}") {
      objectKeyStack.pop();
      afterColon = objectKeyStack.length > 0; // restore parent context
    } else if (ch === "[") {
      // Arrays don't have keys — push a sentinel
      objectKeyStack.push(new Set(["__array__"]));
      assertDepthLimit(objectKeyStack.length);
      afterColon = false;
    } else if (ch === "]") {
      objectKeyStack.pop();
      afterColon = objectKeyStack.length > 0;
    } else if (ch === ":") {
      afterColon = true;
    } else if (ch === ",") {
      afterColon = false;
    }

    i++;
  }

  return duplicates;
}

/**
 * Assert that a value is JSON-safe (representable in JSON without lossy conversion).
 * Rejects: undefined, NaN, Infinity, -Infinity, BigInt, functions, symbols, Date objects.
 * These values would be silently coerced or dropped by JSON.stringify / canonicalize.
 */
export function assertJsonSafe(value: unknown, path: string = "$", depth: number = 0): void {
  assertDepthLimit(depth, path);

  if (value === undefined) {
    throw new OmaTrustError("INVALID_INPUT", `Non-JSON-safe value at ${path}: undefined`);
  }

  if (value === null) return;

  switch (typeof value) {
    case "string":
    case "boolean":
      return;
    case "number":
      if (!Number.isFinite(value)) {
        throw new OmaTrustError("INVALID_INPUT", `Non-JSON-safe value at ${path}: ${value} (must be finite number)`);
      }
      return;
    case "bigint":
      throw new OmaTrustError("INVALID_INPUT", `Non-JSON-safe value at ${path}: BigInt (use number or string)`);
    case "function":
      throw new OmaTrustError("INVALID_INPUT", `Non-JSON-safe value at ${path}: function`);
    case "symbol":
      throw new OmaTrustError("INVALID_INPUT", `Non-JSON-safe value at ${path}: Symbol`);
    case "object":
      if (value instanceof Date) {
        throw new OmaTrustError("INVALID_INPUT", `Non-JSON-safe value at ${path}: Date (use ISO string or timestamp)`);
      }
      if (value instanceof RegExp) {
        throw new OmaTrustError("INVALID_INPUT", `Non-JSON-safe value at ${path}: RegExp`);
      }
      if (Array.isArray(value)) {
        for (let i = 0; i < value.length; i++) {
          assertJsonSafe(value[i], `${path}[${i}]`, depth + 1);
        }
        return;
      }
      // Plain object
      for (const [key, val] of Object.entries(value)) {
        assertJsonSafe(val, `${path}.${key}`, depth + 1);
      }
      return;
    default:
      throw new OmaTrustError("INVALID_INPUT", `Non-JSON-safe value at ${path}: unknown type "${typeof value}"`);
  }
}

export function canonicalizeJson(obj: unknown): string {
  assertJsonSafe(obj);
  const jcs = canonicalize(obj);
  if (!jcs) {
    throw new OmaTrustError("INVALID_INPUT", "Object cannot be canonicalized", { obj });
  }
  return jcs;
}

/**
 * Canonicalize a JSON object (JCS / RFC 8785) and compute its keccak256 hash.
 * Returns both the canonical JCS string and the 0x-prefixed hash.
 */
export function canonicalizeAndKeccak256(obj: unknown): { jcsJson: string; hash: Hex } {
  const jcsJson = canonicalizeJson(obj);
  return {
    jcsJson,
    hash: keccak256(toUtf8Bytes(jcsJson)) as Hex
  };
}

/** @deprecated Use canonicalizeAndKeccak256 instead. */
export function canonicalizeForHash(obj: unknown): { jcsJson: string; hash: Hex } {
  return canonicalizeAndKeccak256(obj);
}

export function hashCanonicalizedJson(obj: unknown, algorithm: "keccak256" | "sha256"): Hex {
  if (!VALID_ALGORITHMS.has(algorithm)) {
    throw new OmaTrustError("INVALID_INPUT", `Unsupported hash algorithm: "${algorithm}". Must be "keccak256" or "sha256".`, { algorithm });
  }
  const jcs = canonicalizeJson(obj);
  const bytes = toUtf8Bytes(jcs);
  return (algorithm === "keccak256" ? keccak256(bytes) : sha256(bytes)) as Hex;
}
