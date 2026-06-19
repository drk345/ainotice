import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { resolve } from 'path';

// AG-PROMPT-FIREFOX-DIST-SAFETY-011: Separate dist outputs per browser
const target = process.env.BUILD_TARGET || 'chrome';
const outDir = `dist/${target}`;

export default defineConfig({
  // AG-056: Disable publicDir so Vite doesn't copy public/manifest.json (Chrome MV3)
  // into the Firefox dist. Static files are copied by vite.background.config.ts instead.
  // Manifest is handled exclusively by scripts/copy-manifest.ts.
  publicDir: false,
  plugins: [react()],
  build: {
    outDir,
    emptyOutDir: true,
    sourcemap: target !== 'chrome',
    // AG-AUDIT-FIX-004: Strip console.log/debug in production (keep warn/error)
    minify: 'terser',
    terserOptions: {
      compress: {
        pure_funcs: ['console.log', 'console.debug'],
      },
    },
    rollupOptions: {
      input: {
        content: resolve(__dirname, 'src/content/index.ts')
      },
      output: {
        format: 'iife',
        entryFileNames: 'content.js',
        inlineDynamicImports: true,
        manualChunks: undefined
      }
    }
  },
  resolve: {
    alias: {
      '@': resolve(__dirname, 'src')
    }
  }
});
