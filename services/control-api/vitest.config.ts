import { defineConfig } from 'vitest/config';

const temporaryRoot = process.env.OPENPC_PNC_TMP_ROOT;
if (!temporaryRoot) throw new Error('OPENPC_PNC_TMP_ROOT is required');

export default defineConfig({
  cacheDir: `${temporaryRoot}/i07-gate2-control-api-vite-cache`,
  test: {
    include: ['src/**/*.test.ts'],
    environment: 'node',
  },
});
