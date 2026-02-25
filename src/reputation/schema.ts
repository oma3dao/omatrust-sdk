import { OmaTrustError } from "../shared/errors";
import { isEasSchemaNotFoundError } from "./eas-adapter";
import type { Hex } from "./types";

export async function verifySchemaExists(
  schemaRegistry: unknown,
  schemaUid: Hex
): Promise<boolean> {
  const registry = schemaRegistry as {
    getSchema: (params: { uid: string }) => Promise<{ uid: string } | null>;
  };

  try {
    const schema = await registry.getSchema({ uid: schemaUid });
    return Boolean(schema && schema.uid && schema.uid !== "0x".padEnd(66, "0"));
  } catch {
    return false;
  }
}

export async function getSchemaDetails(
  schemaRegistry: unknown,
  schemaUid: Hex
): Promise<{ uid: Hex; schema: string; resolver: Hex; revocable: boolean }> {
  const registry = schemaRegistry as {
    getSchema: (params: { uid: string }) => Promise<{
      uid: string;
      schema: string;
      resolver: string;
      revocable: boolean;
    } | null>;
  };

  try {
    const details = await registry.getSchema({ uid: schemaUid });
    if (!details || !details.uid || details.uid === "0x".padEnd(66, "0")) {
      throw new OmaTrustError("SCHEMA_NOT_FOUND", "Schema was not found", { schemaUid });
    }

    return {
      uid: formatSchemaUid(details.uid),
      schema: details.schema,
      resolver: details.resolver as Hex,
      revocable: Boolean(details.revocable)
    };
  } catch (err) {
    if (isEasSchemaNotFoundError(err)) {
      throw new OmaTrustError("SCHEMA_NOT_FOUND", "Schema was not found", { schemaUid });
    }
    if (err instanceof OmaTrustError) {
      throw err;
    }
    throw new OmaTrustError("NETWORK_ERROR", "Failed to read schema details", { schemaUid, err });
  }
}

export function formatSchemaUid(schemaUid: string): Hex {
  if (!schemaUid) {
    throw new OmaTrustError("INVALID_INPUT", "schemaUid is required");
  }
  const value = schemaUid.startsWith("0x") ? schemaUid.toLowerCase() : `0x${schemaUid.toLowerCase()}`;
  if (!/^0x[0-9a-f]{64}$/.test(value)) {
    throw new OmaTrustError("INVALID_INPUT", "schemaUid must be a 32-byte hex string", { schemaUid });
  }
  return value as Hex;
}
