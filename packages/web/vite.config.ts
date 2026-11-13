import path from 'node:path';
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';

// SPEC §13: hub serves this build from the same origin at 127.0.0.1:4747.
// CSP there is `script-src 'self'` with no inline scripts, so module preload
// must not inject an inline polyfill script.
export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
  build: {
    outDir: 'dist',
    modulePreload: { polyfill: false },
    rollupOptions: {
      output: {
        manualChunks(id) {
          const marker = 'node_modules/';
          const i = id.lastIndexOf(marker);
          if (i === -1) return undefined;
          // last() so pnpm's nested .pnpm/<pkg>/node_modules/<pkg> path resolves
          // to the real package name, not the outer store folder.
          const rest = id.slice(i + marker.length);
          const pkg = rest.startsWith('@') ? rest.split('/').slice(0, 2).join('/') : rest.split('/')[0];

          if (pkg === 'react' || pkg === 'react-dom' || pkg === 'scheduler') return 'vendor-react';
          if (pkg === 'react-router') return 'vendor-router';
          if (pkg === 'radix-ui' || pkg.startsWith('@radix-ui')) return 'vendor-radix';
          if (pkg === 'cmdk') return 'vendor-cmdk';
          if (
            pkg === 'react-markdown' ||
            pkg.startsWith('remark') ||
            pkg.startsWith('rehype') ||
            pkg.startsWith('mdast') ||
            pkg.startsWith('micromark') ||
            pkg.startsWith('unist') ||
            pkg === 'unified' ||
            pkg === 'vfile' ||
            pkg.startsWith('vfile-') ||
            pkg.startsWith('hast') ||
            ['bail', 'trough', 'property-information', 'space-separated-tokens', 'comma-separated-tokens', 'zwitch', 'decode-named-character-reference', 'ccount', 'escape-string-regexp', 'markdown-table', 'character-entities', 'trim-lines', 'web-namespaces'].includes(pkg)
          ) {
            return 'vendor-markdown';
          }
          return 'vendor';
        },
      },
    },
  },
  server: {
    proxy: {
      '/v1': {
        target: 'http://127.0.0.1:4747',
        changeOrigin: true,
      },
    },
  },
});
