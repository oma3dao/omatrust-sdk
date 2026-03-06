import { describe, expect, it } from "vitest";
import { OmaTrustError, toOmaTrustError } from "../src/shared/errors";
import { assertString, assertNumber, assertObject, asError } from "../src/shared/assert";

describe("shared/errors", () => {
  describe("OmaTrustError", () => {
    it("creates error with code, message, and details", () => {
      const err = new OmaTrustError("TEST_CODE", "test message", { key: "value" });
      expect(err).toBeInstanceOf(Error);
      expect(err).toBeInstanceOf(OmaTrustError);
      expect(err.name).toBe("OmaTrustError");
      expect(err.code).toBe("TEST_CODE");
      expect(err.message).toBe("test message");
      expect(err.details).toEqual({ key: "value" });
    });

    it("creates error without details", () => {
      const err = new OmaTrustError("NO_DETAILS", "no details");
      expect(err.details).toBeUndefined();
    });

    it("is catchable as Error", () => {
      try {
        throw new OmaTrustError("CATCH_TEST", "catch me");
      } catch (err) {
        expect(err).toBeInstanceOf(Error);
        expect((err as OmaTrustError).code).toBe("CATCH_TEST");
      }
    });
  });

  describe("toOmaTrustError", () => {
    it("creates OmaTrustError with all params", () => {
      const err = toOmaTrustError("CODE", "msg", { detail: 1 });
      expect(err).toBeInstanceOf(OmaTrustError);
      expect(err.code).toBe("CODE");
      expect(err.message).toBe("msg");
      expect(err.details).toEqual({ detail: 1 });
    });

    it("creates OmaTrustError without details", () => {
      const err = toOmaTrustError("CODE", "msg");
      expect(err.details).toBeUndefined();
    });
  });
});

describe("shared/assert", () => {
  describe("assertString", () => {
    it("passes for non-empty strings", () => {
      expect(() => assertString("hello", "field")).not.toThrow();
      expect(() => assertString("  a  ", "field")).not.toThrow();
    });

    it("throws for empty string", () => {
      expect(() => assertString("", "myField")).toThrow(OmaTrustError);
      expect(() => assertString("", "myField")).toThrow("myField must be a non-empty string");
    });

    it("throws for whitespace-only string", () => {
      expect(() => assertString("   ", "myField")).toThrow(OmaTrustError);
    });

    it("throws for non-string types", () => {
      expect(() => assertString(null, "field")).toThrow(OmaTrustError);
      expect(() => assertString(undefined, "field")).toThrow(OmaTrustError);
      expect(() => assertString(123, "field")).toThrow(OmaTrustError);
      expect(() => assertString(true, "field")).toThrow(OmaTrustError);
      expect(() => assertString({}, "field")).toThrow(OmaTrustError);
      expect(() => assertString([], "field")).toThrow(OmaTrustError);
    });

    it("uses default code INVALID_INPUT", () => {
      try {
        assertString("", "field");
      } catch (err) {
        expect((err as OmaTrustError).code).toBe("INVALID_INPUT");
      }
    });

    it("uses custom code when provided", () => {
      try {
        assertString("", "field", "CUSTOM_CODE");
      } catch (err) {
        expect((err as OmaTrustError).code).toBe("CUSTOM_CODE");
      }
    });
  });

  describe("assertNumber", () => {
    it("passes for valid numbers", () => {
      expect(() => assertNumber(42, "field")).not.toThrow();
      expect(() => assertNumber(0, "field")).not.toThrow();
      expect(() => assertNumber(-1, "field")).not.toThrow();
      expect(() => assertNumber(3.14, "field")).not.toThrow();
    });

    it("throws for NaN", () => {
      expect(() => assertNumber(NaN, "field")).toThrow(OmaTrustError);
      expect(() => assertNumber(NaN, "field")).toThrow("field must be a valid number");
    });

    it("passes for Infinity (not NaN)", () => {
      // Note: assertNumber only checks for NaN, not Infinity
      expect(() => assertNumber(Infinity, "field")).not.toThrow();
    });

    it("throws for non-number types", () => {
      expect(() => assertNumber("42", "field")).toThrow(OmaTrustError);
      expect(() => assertNumber(null, "field")).toThrow(OmaTrustError);
      expect(() => assertNumber(undefined, "field")).toThrow(OmaTrustError);
      expect(() => assertNumber(true, "field")).toThrow(OmaTrustError);
      expect(() => assertNumber({}, "field")).toThrow(OmaTrustError);
    });

    it("uses custom code when provided", () => {
      try {
        assertNumber("x", "field", "MY_CODE");
      } catch (err) {
        expect((err as OmaTrustError).code).toBe("MY_CODE");
      }
    });
  });

  describe("assertObject", () => {
    it("passes for plain objects", () => {
      expect(() => assertObject({}, "field")).not.toThrow();
      expect(() => assertObject({ key: "value" }, "field")).not.toThrow();
    });

    it("throws for null", () => {
      expect(() => assertObject(null, "field")).toThrow(OmaTrustError);
      expect(() => assertObject(null, "field")).toThrow("field must be an object");
    });

    it("throws for arrays", () => {
      expect(() => assertObject([], "field")).toThrow(OmaTrustError);
      expect(() => assertObject([1, 2], "field")).toThrow(OmaTrustError);
    });

    it("throws for primitives", () => {
      expect(() => assertObject("string", "field")).toThrow(OmaTrustError);
      expect(() => assertObject(42, "field")).toThrow(OmaTrustError);
      expect(() => assertObject(true, "field")).toThrow(OmaTrustError);
      expect(() => assertObject(undefined, "field")).toThrow(OmaTrustError);
    });

    it("uses custom code when provided", () => {
      try {
        assertObject(null, "field", "MY_CODE");
      } catch (err) {
        expect((err as OmaTrustError).code).toBe("MY_CODE");
      }
    });
  });

  describe("asError", () => {
    it("returns Error instances unchanged", () => {
      const original = new Error("original");
      const result = asError(original);
      expect(result).toBe(original);
      expect(result.message).toBe("original");
    });

    it("returns OmaTrustError instances unchanged", () => {
      const original = new OmaTrustError("CODE", "msg");
      const result = asError(original);
      expect(result).toBe(original);
    });

    it("wraps string into Error", () => {
      const result = asError("some string error");
      expect(result).toBeInstanceOf(Error);
      expect(result.message).toBe("some string error");
    });

    it("wraps number into Error", () => {
      const result = asError(42);
      expect(result).toBeInstanceOf(Error);
      expect(result.message).toBe("42");
    });

    it("wraps null into Error", () => {
      const result = asError(null);
      expect(result).toBeInstanceOf(Error);
      expect(result.message).toBe("null");
    });

    it("wraps undefined into Error", () => {
      const result = asError(undefined);
      expect(result).toBeInstanceOf(Error);
      expect(result.message).toBe("undefined");
    });

    it("wraps object into Error", () => {
      const result = asError({ foo: "bar" });
      expect(result).toBeInstanceOf(Error);
      expect(result.message).toBe("[object Object]");
    });
  });
});
