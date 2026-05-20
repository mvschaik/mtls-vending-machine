import { defineConfig } from 'vitest/config';

export default defineConfig({
  base: '/static/',
  test: {
    environment: 'node',
    exclude: ['**/node_modules/**', '**/dist/**', '**/e2e/**'],
  },
  server: {
    proxy: {
      '/sign': 'http://localhost:8000',
      '/api': 'http://localhost:8000',
    },
  },
  build: {
    outDir: '../static',
    emptyOutDir: true,
  },
});
