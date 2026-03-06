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
      exclude: ["**/*.browser.ts", "**/*.d.ts", "**/types.ts"],
      thresholds: {
        statements: 97,
        branches: 94,
        functions: 98,
        lines: 97
      }
    }
  }
});
