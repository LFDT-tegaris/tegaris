import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { defineConfig } from 'vitest/config';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');

export default defineConfig({
  root,
  test: {
    include: ['tests/conformance/modules/**/*.test.ts'],
    environment: 'node',
    fileParallelism: false,
  },
});
