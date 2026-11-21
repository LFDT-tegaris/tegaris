import { readFile, readdir } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { dirname, join, basename } from 'node:path';
import { fileURLToPath } from 'node:url';

// Generation may need historical DDL to decide which guards exist. Read it
// from an explicitly supplied, immutable offline package; never restore it
// into the working tree or fetch anything implicitly.
export async function migrationInputs(directory) {
  const lane = basename(directory.replace(/\/$/u, ''));
  const root = fileURLToPath(new URL('../../', import.meta.url));
  const manifest = JSON.parse(
    await readFile(join(root, 'migrations/postgres/baseline-v1/legacy-package.json'), 'utf8'),
  );
  if (
    manifest.format !== 1 ||
    manifest.source_commit !== 'db5e64b566712e5213424db5e166775d9a15a7be'
  )
    throw new Error('Unrecognized legacy generation source');
  const current = (await readdir(directory)).filter((name) => name.endsWith('.sql')).sort();
  const historical = Object.keys(manifest.files)
    .filter((path) => dirname(path) === `migrations/postgres/${lane}` && path.endsWith('.sql'))
    .map((path) => basename(path));
  const source = process.env.OPENPC_LEGACY_SOURCE_ROOT;
  if (historical.some((name) => !current.includes(name)) && !source)
    throw new Error(
      'Migration source checks require OPENPC_LEGACY_SOURCE_ROOT from the verified offline compatibility package',
    );
  const migrations = [...new Set([...historical, ...current])].sort();
  async function readMigration(name) {
    if (!migrations.includes(name) || !/^[0-9]{4}_[a-z0-9_-]+\.sql$/u.test(name))
      throw new Error('Unknown migration generation input');
    const relative = `migrations/postgres/${lane}/${name}`;
    const path = current.includes(name) ? join(directory, name) : join(source, relative);
    const data = await readFile(path);
    const expected = manifest.files[relative];
    if (expected && createHash('sha256').update(data).digest('hex') !== expected.sha256)
      throw new Error('Immutable migration generation input changed');
    return data.toString('utf8');
  }
  return {
    migrations,
    readMigration,
    isHistoricalMigration: (name) => historical.includes(name),
  };
}
