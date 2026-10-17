// Standalone browser build served and embedded by Rust. The Start dev build remains available.
import { slurpVersion } from './slurp-version';
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';
import { tanstackRouter } from '@tanstack/router-plugin/vite';
import { fileURLToPath } from 'node:url';
import { renameSync } from 'node:fs';
export default defineConfig({
  plugins: [{ name: 'slurp-html-entry', closeBundle() { renameSync(fileURLToPath(new URL('./dist-rust/standalone.html', import.meta.url)), fileURLToPath(new URL('./dist-rust/index.html', import.meta.url))); } }, tanstackRouter({ target: 'react', autoCodeSplitting: true }), react(), tailwindcss()],
  resolve: { alias: { '@': fileURLToPath(new URL('./src', import.meta.url)) } },
  define: { 'import.meta.env.VITE_SLURP_VERSION': JSON.stringify(slurpVersion), 'import.meta.env.VITE_SLURP_SAME_ORIGIN': JSON.stringify('true') },
  build: { outDir: 'dist-rust', rollupOptions: { input: fileURLToPath(new URL('./standalone.html', import.meta.url)) } },
});
