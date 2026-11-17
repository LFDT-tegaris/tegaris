import { defineConfig } from 'drizzle-kit';

export default defineConfig({
  dialect: 'postgresql',
  schema: './src/configuration/schema.ts',
  out: '../../migrations/postgres/control-api',
  strict: true,
  verbose: false,
});
