import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "node",
    include: ["test/**/*.test.ts"],
    coverage: {
      enabled: true,
      provider: "v8",
      reporter: ["text", "text-summary", "html"],
      include: ["src/**/*.ts"],
      exclude: [
        "**/*.browser.ts",
        "**/*.d.ts",
        "**/types.ts",
        // TEMPORARY: widgets module uses browser APIs (window, postMessage,
        // HTMLIFrameElement) that require jsdom test environment.
        // Tests to be added by test engineer — see omatrust-docs issue #4.
        // Remove this exclusion once widget module tests are in place.
        // Added: 2026-04-14 by @atom
        "src/widgets/**",
      ],
      thresholds: {
        statements: 97,
        branches: 94,
        functions: 98,
        lines: 97
      }
    }
  }
});
