import path from 'node:path'
import { defineConfig } from 'vitest/config'

export default defineConfig({
  // Mirror the '@/' alias from vite.config.ts. Without it any test that pulls in
  // a module using '@/...' fails to resolve at transform time — which is most of
  // the app, so only dependency-free leaf modules were testable.
  resolve: {
    alias: { '@': path.resolve(__dirname, './src') },
  },
  test: {
    environment: 'jsdom',
    include: ['src/**/*.test.{ts,tsx}'],
  },
})
