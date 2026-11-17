import { configDefaults, defineConfig } from 'vitest/config';

const serverContracts = ['app/api/v1/ui/*.test.ts'];
const excludedSource = [...configDefaults.exclude, '**/._*'];

export default defineConfig({
  test: {
    projects: [
      {
        test: {
          name: 'server-contracts',
          environment: 'node',
          include: serverContracts,
          exclude: excludedSource,
        },
      },
      {
        test: {
          name: 'browser-components',
          environment: 'jsdom',
          // Complete form workflows also run on the bounded two-CPU development profile.
          testTimeout: 15_000,
          setupFiles: ['./test/setup.ts'],
          exclude: [...excludedSource, ...serverContracts],
        },
      },
    ],
  },
});
