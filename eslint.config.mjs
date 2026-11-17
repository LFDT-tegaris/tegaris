import eslint from '@eslint/js';
import eslintConfigPrettier from 'eslint-config-prettier';
import globals from 'globals';
import tseslint from 'typescript-eslint';

export default tseslint.config(
  {
    ignores: [
      '**/coverage/**',
      '**/dist/**',
      '**/.next/**',
      '**/generated/**',
      '**/node_modules/**',
      '**/target/**',
      '**/test-results/**',
      'deploy/compose/local/volumes/**',
      ...(process.env.OPENPC_R11_CLI === '1'
        ? []
        : [
            'apps/admin-cli/**',
            'tests/integration/local-runtime/transaction-cli.mjs',
            'tests/integration/local-runtime/administration-cli-readback.mjs',
          ]),
    ],
  },
  eslint.configs.recommended,
  ...tseslint.configs.recommended,
  {
    languageOptions: {
      globals: {
        ...globals.node,
        ...globals.browser,
      },
    },
    rules: {
      '@typescript-eslint/no-unused-vars': ['error', { argsIgnorePattern: '^_' }],
      'eqeqeq': ['error', 'always'],
      'no-console': 'warn',
      'no-var': 'error',
      'prefer-const': 'error',
    },
  },
  eslintConfigPrettier,
);
