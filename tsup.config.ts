import { defineConfig } from "tsup";

export default defineConfig({
  entry: [
    "src/index.ts",
    "src/identity/index.ts",
    "src/identity/did-core.ts",
    "src/reputation/index.ts",
    "src/reputation/index.browser.ts",
    "src/app-registry/index.ts",
    "src/widgets/index.ts"
  ],
  format: ["esm", "cjs"],
  dts: true,
  sourcemap: true,
  clean: true,
  splitting: false,
  treeshake: true,
  minify: false,
  outDir: "dist"
});
