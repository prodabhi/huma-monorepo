import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { fileURLToPath } from 'node:url';
export default defineConfig({ root: fileURLToPath(new URL('./', import.meta.url)), base: '/share/', plugins: [react()],
  build: { outDir: '../dist/share', emptyOutDir: true, sourcemap: false, manifest: true } });
