import { SchemaEncoder } from "@ethereum-attestation-service/eas-sdk";
import type { SchemaItem } from "@ethereum-attestation-service/eas-sdk";
import { isAddress } from "ethers";
import { OmaTrustError } from "../shared/errors";
import type { AttestationValidationError, Hex, SchemaField } from "./types";

export function normalizeSchema(schema: SchemaField[] | string): SchemaField[] {
  if (Array.isArray(schema)) {
    if (schema.length === 0) {
      throw new OmaTrustError("INVALID_INPUT", "schema array cannot be empty");
    }
    return schema;
  }

  if (typeof schema !== "string" || schema.trim().length === 0) {
    throw new OmaTrustError("INVALID_INPUT", "schema must be a non-empty string or SchemaField[]");
  }

  const fields = schema
    .split(",")
    .map((part) => part.trim())
    .filter((part) => part.length > 0)
    .map((part) => {
      const pieces = part.split(/\s+/);
      if (pieces.length < 2) {
        throw new OmaTrustError("INVALID_INPUT", "Invalid schema field", { part });
      }
      const type = pieces[0];
      const name = pieces.slice(1).join(" ");
      return { type, name };
    });

  if (fields.length === 0) {
    throw new OmaTrustError("INVALID_INPUT", "No schema fields found");
  }

  return fields;
}

export function schemaToString(schema: SchemaField[] | string): string {
  if (typeof schema === "string") {
    return schema;
  }

  return schema.map((field) => `${field.type} ${field.name}`).join(", ");
}

export function encodeAttestationData(
  schema: SchemaField[] | string,
  data: Record<string, unknown>
): Hex {
  if (!data || typeof data !== "object") {
    throw new OmaTrustError("INVALID_INPUT", "data must be an object");
  }

  const validationErrors = validateAttestationData(schema, data);
  if (validationErrors.length > 0) {
    const summary = validationErrors
      .map((error) => `Field "${error.schemaFieldName}" (${error.expectedType}) got ${error.providedType}`)
      .join("; ");
    throw new OmaTrustError("INVALID_INPUT", `Attestation data validation failed: ${summary}`, {
      errors: validationErrors
    });
  }

  const fields = normalizeSchema(schema);
  const schemaString = schemaToString(fields);
  const encoder = new SchemaEncoder(schemaString);

  const encoded = encoder.encodeData(
    fields.map((field) => ({
      name: field.name,
      type: field.type,
      value: data[field.name]
    })) as SchemaItem[]
  );

  return encoded as Hex;
}

function getActualType(value: unknown): string {
  if (value === null) {
    return "null";
  }
  if (value === undefined) {
    return "undefined";
  }
  if (Array.isArray(value)) {
    return "array";
  }
  if (typeof value === "number") {
    return Number.isFinite(value) ? "number" : "non-finite-number";
  }
  return typeof value;
}

function isNumericValue(value: unknown, allowNegative: boolean): boolean {
  if (typeof value === "bigint") {
    return allowNegative || value >= 0n;
  }

  if (typeof value === "number") {
    if (!Number.isFinite(value) || !Number.isInteger(value)) {
      return false;
    }
    return allowNegative || value >= 0;
  }

  if (typeof value === "string") {
    if (value.length === 0) {
      return false;
    }
    const pattern = allowNegative ? /^-?\d+$/ : /^\d+$/;
    return pattern.test(value);
  }

  return false;
}

function isHex(value: unknown): value is string {
  return typeof value === "string" && /^0x[0-9a-fA-F]*$/.test(value);
}

function validateFieldValue(type: string, value: unknown): boolean {
  const normalizedType = type.trim().toLowerCase();
  const bytesNMatch = normalizedType.match(/^bytes([1-9]|[12]\d|3[0-2])$/);

  if (/^uint\d*$/.test(normalizedType)) {
    return isNumericValue(value, false);
  }

  if (/^int\d*$/.test(normalizedType)) {
    return isNumericValue(value, true);
  }

  if (normalizedType === "string") {
    return typeof value === "string";
  }

  if (normalizedType === "string[]") {
    return Array.isArray(value) && value.every((entry) => typeof entry === "string");
  }

  if (normalizedType === "bool") {
    return typeof value === "boolean";
  }

  if (normalizedType === "address") {
    return typeof value === "string" && isAddress(value);
  }

  if (normalizedType === "bytes") {
    return isHex(value) && (value.length - 2) % 2 === 0;
  }

  if (bytesNMatch) {
    const expectedBytes = Number(bytesNMatch[1]);
    return isHex(value) && value.length === 2 + expectedBytes * 2;
  }

  return true;
}

export function validateAttestationData(
  schema: SchemaField[] | string,
  data: Record<string, unknown>
): AttestationValidationError[] {
  if (!data || typeof data !== "object") {
    return [{
      schemaFieldName: "data",
      expectedType: "object",
      providedType: getActualType(data),
      providedValue: data
    }];
  }

  const fields = normalizeSchema(schema);
  const errors: AttestationValidationError[] = [];

  for (const field of fields) {
    const value = data[field.name];
    const isValid = validateFieldValue(field.type, value);
    if (isValid) {
      continue;
    }

    errors.push({
      schemaFieldName: field.name,
      expectedType: field.type,
      providedType: getActualType(value),
      providedValue: value
    });
  }

  return errors;
}

export function decodeAttestationData(
  schema: SchemaField[] | string,
  encodedData: Hex
): Record<string, unknown> {
  if (typeof encodedData !== "string" || !encodedData.startsWith("0x")) {
    throw new OmaTrustError("INVALID_INPUT", "encodedData must be a hex string");
  }

  const fields = normalizeSchema(schema);
  const schemaString = schemaToString(fields);
  const encoder = new SchemaEncoder(schemaString);
  const decoded = encoder.decodeData(encodedData);

  const result: Record<string, unknown> = {};
  for (const item of decoded as Array<{ name: string; value: unknown }>) {
    const value = item.value as { value?: unknown } | unknown;
    if (value && typeof value === "object" && "value" in (value as Record<string, unknown>)) {
      result[item.name] = (value as { value: unknown }).value;
    } else {
      result[item.name] = value;
    }
  }

  return result;
}

export function extractExpirationTime(
  data: Record<string, unknown>
): bigint | number | undefined {
  const value = data["expiresAt"];
  if (value === undefined || value === null) return undefined;
  if (typeof value === "bigint") return value;
  if (typeof value === "number") return value;
  if (typeof value === "string" && /^\d+$/.test(value)) return BigInt(value);
  return undefined;
}
