import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: [
      'tests/conformance/assertion-resolution/**/*.test.ts',
      'tests/accessibility/foundation/**/*.test.tsx',
      'tests/conformance/bootstrap/**/*.test.ts',
    ],
    environment: 'jsdom',
    setupFiles: ['tests/conformance/bootstrap/test-setup.ts'],
  },
});
