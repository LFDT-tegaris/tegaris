import { defineConfig } from 'drizzle-kit';

export default defineConfig({
  dialect: 'postgresql',
  schema: './src/db/schema/index.ts',
  out: '../../migrations/postgres/identity',
  strict: true,
  verbose: false,
});
