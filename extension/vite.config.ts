import { defineConfig, Plugin } from 'vite';
import react from '@vitejs/plugin-react';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';
import * as esbuild from 'esbuild';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

/**
 * Custom Vite plugin to compile the MV3 background service worker and
 * content script as self-contained bundles without code-splitting chunk
 * issues, and copy the validated manifest.json into /extension/dist.
 */
function phishLensMv3Plugin(): Plugin {
  return {
    name: 'phishlens-mv3-extension-builder',
    configureServer(server) {
      server.middlewares.use((req, _res, next) => {
        if (req.url === '/' || req.url?.startsWith('/?')) {
          const query = req.url.includes('?') ? req.url.slice(req.url.indexOf('?')) : '';
          req.url = `/popup/index.html${query}`;
        }
        next();
      });
    },
    async closeBundle() {
      const distDir = path.resolve(__dirname, 'dist');
      const bgOutDir = path.resolve(distDir, 'background');
      const contentOutDir = path.resolve(distDir, 'content');

      fs.mkdirSync(bgOutDir, { recursive: true });
      fs.mkdirSync(contentOutDir, { recursive: true });

      // 1. Bundle Background Service Worker as a self-contained ES module
      await esbuild.build({
        entryPoints: [path.resolve(__dirname, 'src/background/service-worker.ts')],
        outfile: path.resolve(bgOutDir, 'service-worker.js'),
        bundle: true,
        format: 'esm',
        platform: 'browser',
        target: 'es2022',
        minify: false,
        sourcemap: false,
        define: {
          'process.env.NODE_ENV': '"production"',
        },
      });

      // 2. Bundle Content Script as a self-contained IIFE script
      // Chrome content scripts injected via chrome.scripting.executeScript
      // must not rely on external ES module chunk imports.
      await esbuild.build({
        entryPoints: [path.resolve(__dirname, 'src/content/inspect-page.ts')],
        outfile: path.resolve(contentOutDir, 'inspect-page.js'),
        bundle: true,
        format: 'iife',
        platform: 'browser',
        target: 'es2022',
        minify: false,
        sourcemap: false,
        define: {
          'process.env.NODE_ENV': '"production"',
        },
      });

      // 3. Copy src/manifest.json -> dist/manifest.json
      const manifestSrc = path.resolve(__dirname, 'src/manifest.json');
      const manifestDest = path.resolve(distDir, 'manifest.json');
      fs.copyFileSync(manifestSrc, manifestDest);
    },
  };
}

export default defineConfig({
  root: path.resolve(__dirname, 'src'),
  publicDir: path.resolve(__dirname, 'public'),
  base: './',
  plugins: [react(), phishLensMv3Plugin()],
  build: {
    outDir: path.resolve(__dirname, 'dist'),
    emptyOutDir: true,
    sourcemap: false,
    rollupOptions: {
      input: {
        popup: path.resolve(__dirname, 'src/popup/index.html'),
      },
      output: {
        entryFileNames: 'assets/[name]-[hash].js',
        chunkFileNames: 'assets/[name]-[hash].js',
        assetFileNames: 'assets/[name]-[hash][extname]',
      },
    },
  },
});
