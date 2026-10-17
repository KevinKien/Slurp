// @lovable.dev/vite-tanstack-config already includes the following — do NOT add them manually
// or the app will break with duplicate plugins:
//   - TanStack devtools (dev-only, first), tanstackStart, viteReact, tailwindcss, tsConfigPaths,
//     nitro (build-only using cloudflare as a default target), VITE_* env injection, @ path alias,
//     React/TanStack dedupe, error logger plugins, and sandbox detection (port/host/strictPort).
// You can pass additional config via defineConfig({ vite: { ... }, etc... }) if needed.
import { slurpVersion } from "./slurp-version";
import { defineConfig } from "@lovable.dev/vite-tanstack-config";

export default defineConfig({
  vite: { define: { "import.meta.env.VITE_SLURP_VERSION": JSON.stringify(slurpVersion) } },
  ...(process.env['SLURP_BUILD_PRESET']
    ? { nitro: { preset: process.env['SLURP_BUILD_PRESET'] } }
    : {}),
  tanstackStart: {
    // Redirect TanStack Start's bundled server entry to src/server.ts (our SSR error wrapper).
    // nitro/vite builds from this
    server: { entry: "server" },
  },
});
