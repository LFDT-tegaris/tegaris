import { defineConfig } from 'vitest/config';
export default defineConfig({
  test: { include: ['apps/admin-cli/src/**/*.test.ts'], environment: 'node', maxWorkers: 2 },
});
