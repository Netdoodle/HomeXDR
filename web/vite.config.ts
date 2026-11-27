/// <reference types="vitest/config" />
import { defineConfig, loadEnv } from 'vite'
import react from '@vitejs/plugin-react'

// Mock mode is decided at build time. When it is off, `__HOMEXDR_MOCK__` is the literal
// `false`, so the dynamic import of src/mock in main.tsx is dead code and Rollup drops
// the fixtures from the bundle entirely.
export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), '')
  const mock = env.VITE_MOCK === '1' || env.VITE_MOCK === 'true'
  const target = env.HOMEXDR_API ?? 'http://localhost:8080'

  return {
    // VITE_BASE serves the console under a subpath (the GitHub Pages demo is /HomeXDR/).
    base: env.VITE_BASE || '/',
    plugins: [react()],
    define: {
      __HOMEXDR_MOCK__: JSON.stringify(mock),
    },
    server: {
      port: 5173,
      proxy: mock
        ? undefined
        : {
            '/api': { target, changeOrigin: false },
            '/healthz': { target, changeOrigin: false },
          },
    },
    build: {
      outDir: 'dist',
      emptyOutDir: true,
      sourcemap: false,
      chunkSizeWarningLimit: 800,
      rollupOptions: {
        output: {
          // Long-lived vendor chunk so app updates do not bust the library cache.
          manualChunks: (id) => (id.includes('node_modules') && !/node_modules[\\/](@xyflow|elkjs|d3-|classcat|zustand)/.test(id) ? 'vendor' : undefined),
        },
      },
    },
    test: {
      environment: 'node',
      include: ['src/**/*.test.ts'],
    },
  }
})
