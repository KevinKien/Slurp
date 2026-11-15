import { defineConfig } from "vitest/config";
import path from "node:path";
import { slurpVersion } from "./slurp-version";

// The scan benchmark runs the real scan engine against a local lab; it is not part of `npm test`.
export default defineConfig({
  define: { "import.meta.env.VITE_SLURP_VERSION": JSON.stringify(slurpVersion) },
  test: {
    environment: "node",
    include: ["benchmark/**/*.bench.ts"],
    testTimeout: 3_600_000,
    hookTimeout: 120_000,
  },
  resolve: { alias: { "@": path.resolve(__dirname, "./src") } },
});
