import { fileURLToPath } from 'node:url';

import { defineConfig } from 'vitest/config';

const temporaryRoot = process.env.OPENPC_PNC_TMP_ROOT;
if (!temporaryRoot) throw new Error('OPENPC_PNC_TMP_ROOT is required');

const repositoryRoot = fileURLToPath(new URL('../..', import.meta.url));

export default defineConfig({
  root: repositoryRoot,
  cacheDir: `${temporaryRoot}/i07-gate2-b4-vite-cache`,
  test: {
    include: [
      'services/control-api/src/**/*.test.ts',
      'tests/privacy/i07-gate2-b4-conformance.test.ts',
      'tests/privacy/i07-gate2-b5-conformance.test.ts',
      'tests/integration/control-api/i07-gate2-b4-integration.test.ts',
      'tests/integration/control-api/i07-gate2-b5-integration.test.ts',
    ],
    environment: 'node',
  },
});
