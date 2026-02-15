export class OmaTrustError extends Error {
  code: string;
  details?: unknown;

  constructor(code: string, message: string, details?: unknown) {
    super(message);
    this.name = "OmaTrustError";
    this.code = code;
    this.details = details;
  }
}

export function toOmaTrustError(
  code: string,
  message: string,
  details?: unknown
): OmaTrustError {
  return new OmaTrustError(code, message, details);
}
