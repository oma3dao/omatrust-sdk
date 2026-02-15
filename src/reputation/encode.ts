import { SchemaEncoder } from "@ethereum-attestation-service/eas-sdk";
import { OmaTrustError } from "../shared/errors";
import type { Hex, SchemaField } from "./types";

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

  const fields = normalizeSchema(schema);
  const schemaString = schemaToString(fields);
  const encoder = new SchemaEncoder(schemaString);

  const encoded = encoder.encodeData(
    fields.map((field) => ({
      name: field.name,
      type: field.type,
      value: (data as Record<string, unknown>)[field.name]
    })) as never
  );

  return encoded as Hex;
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
  const keys = ["expirationTime", "expiration", "validUntil", "expiresAt", "expires"];
  for (const key of keys) {
    const value = data[key];
    if (value === undefined || value === null) {
      continue;
    }

    if (typeof value === "bigint") {
      return value;
    }
    if (typeof value === "number") {
      return value;
    }
    if (typeof value === "string" && /^\d+$/.test(value)) {
      return BigInt(value);
    }
  }
  return undefined;
}
