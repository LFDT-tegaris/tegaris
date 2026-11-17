import { fileURLToPath } from 'node:url';

import { defineConfig } from 'vitest/config';

const temporaryRoot = process.env.OPENPC_PNC_TMP_ROOT;
if (!temporaryRoot) throw new Error('OPENPC_PNC_TMP_ROOT is required');

const repositoryRoot = fileURLToPath(new URL('../..', import.meta.url));

export default defineConfig({
  root: repositoryRoot,
  cacheDir: `${temporaryRoot}/i07-gate3-vite-cache`,
  test: {
    include: ['tests/integration/control-api/privacy-explorer-gate3.test.ts'],
    environment: 'node',
    fileParallelism: false,
    maxWorkers: 1,
    testTimeout: 30_000,
  },
});
