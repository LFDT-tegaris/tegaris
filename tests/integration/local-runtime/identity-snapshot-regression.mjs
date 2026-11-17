import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { resolve } from 'node:path';
import { spawnSync } from 'node:child_process';

const secretRoot = process.argv[2];
if (!secretRoot) throw new Error('Owned local runtime secret directory required');
async function databaseUrl(user, secret) {
  const password = (await readFile(resolve(secretRoot, `${secret}.txt`), 'utf8')).trim();
  const url = new URL('postgresql://127.0.0.1:55432/openpc_control');
  url.username = user;
  url.password = password;
  return url.href;
}
const scratchRoot = process.env.OPENPC_LOCAL_RUNTIME_TMP_ROOT;
if (!scratchRoot) throw new Error('Owned local runtime scratch root required');
const scratch = await mkdtemp(resolve(scratchRoot, 'identity-snapshot-interop-'));
const environment = {
  ...process.env,
  OPENPC_ASTRA05_ADMIN_DATABASE_URL: await databaseUrl('openpc_control', 'control_pg_password'),
  OPENPC_ASTRA05_RUNTIME_DATABASE_URL: await databaseUrl(
    'openpc_identity_runtime',
    'identity_runtime_db_password',
  ),
  OPENPC_ASTRA05_PUBLICATION_FIXTURE: resolve(scratch, 'publication.json'),
};
function run(command, args) {
  const result = spawnSync(command, args, { env: environment, stdio: 'inherit' });
  if (result.error || result.status !== 0) throw new Error('Identity snapshot regression failed');
}
let passed = false;
try {
  run('pnpm', [
    'exec',
    'vitest',
    'run',
    '--config',
    'tests/integration/identity/vitest.config.ts',
    'tests/integration/identity/postgres-runtime-snapshot.test.ts',
  ]);
  run('cargo', [
    'test',
    '-p',
    'openpc-runtime-agent',
    'postgres_tls_publication_is_admitted',
    '--locked',
    '--offline',
  ]);
  passed = true;
} finally {
  if (passed) await rm(scratch, { recursive: true, force: true });
  else process.stderr.write(`Retained public snapshot fixture for diagnosis: ${scratch}\n`);
}
