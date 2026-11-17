import { readdir } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import { controlMigrationGenerationArguments } from '../src/db/control-migration-generation.mjs';

const generationArguments = controlMigrationGenerationArguments(process.argv.slice(2));

const directory = new URL('../../../migrations/postgres/identity/', import.meta.url);
const identifiers = spawnSync(
  process.execPath,
  ['--import', 'tsx', 'src/db/validate-control-migration.ts'],
  { stdio: 'inherit' },
);
if (identifiers.error || identifiers.status !== 0)
  throw new Error('Control constraint identifiers rejected before generation');
const before = new Set(await readdir(directory));
const generated = spawnSync(
  'pnpm',
  ['exec', 'drizzle-kit', ...generationArguments, '--config', 'drizzle.config.ts'],
  { stdio: 'inherit' },
);
if (generated.error || generated.status !== 0) throw new Error('Control schema generation failed');
const added = (await readdir(directory)).filter(
  (name) => name.endsWith('.sql') && !before.has(name),
);
// Some Drizzle failures return status zero. Never let a failed/no-change generation rewrite history.
if (added.length !== 1)
  throw new Error('Expected one new Drizzle migration; refusing to rewrite historical SQL');
const secured = spawnSync(
  process.execPath,
  ['--import', 'tsx', 'src/db/generate-security-tail.mjs', '--new-migration', added[0]],
  {
    stdio: 'inherit',
  },
);
if (secured.error || secured.status !== 0)
  throw new Error('Control migration security projection failed');
