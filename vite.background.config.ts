import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { resolve } from 'path';
import { viteStaticCopy } from 'vite-plugin-static-copy';

// AG-PROMPT-FIREFOX-DIST-SAFETY-011: Separate dist outputs per browser
const target = process.env.BUILD_TARGET || 'chrome';
const outDir = `dist/${target}`;

export default defineConfig({
  plugins: [
    react(),
    viteStaticCopy({
      targets: [
        // Note: manifest is copied by copy-manifest.ts, not here (AG-056)
        {
          src: 'public/icons',
          dest: '.'
        },
        {
          src: 'public/_locales',
          dest: '.'
        },
        // AG-056: Static files previously copied via Vite publicDir in content config.
        // Moved here so publicDir can be disabled (prevents wrong manifest leaking).
        {
          src: 'public/popup.html',
          dest: '.'
        },
        {
          src: 'public/warning-modal.css',
          dest: '.'
        },
        {
          src: 'public/warning-modal.html',
          dest: '.'
        }
      ]
    })
  ],
  build: {
    outDir,
    emptyOutDir: false,
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
        background: resolve(__dirname, 'src/background/index.ts')
      },
      output: {
        format: 'iife',
        entryFileNames: 'background.js',
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