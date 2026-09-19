import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import { resolve } from 'node:path'

// The production bundle has one entry. The test harness is a second entry that exists only when a
// test build asks for it, so the application the person installs never carries the fake host.
const harness = process.env.KR_COMPANION_HARNESS === '1'

export default defineConfig({
  root: import.meta.dirname,
  // Tauri serves the bundle from the application's own origin, so every asset is referenced
  // relatively rather than from an absolute path.
  base: './',
  clearScreen: false,
  server: {
    port: 4187,
    strictPort: true
  },
  preview: {
    port: 4188,
    strictPort: true
  },
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    // The WebView is current on every platform the application ships to, so the output does not
    // carry transforms for engines that are not there.
    target: ['chrome120', 'safari17'],
    sourcemap: true,
    rollupOptions: {
      input: harness
        ? {
            index: resolve(import.meta.dirname, 'index.html'),
            harness: resolve(import.meta.dirname, 'harness.html')
          }
        : { index: resolve(import.meta.dirname, 'index.html') }
    }
  },
  plugins: [react()]
})
