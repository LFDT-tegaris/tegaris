import { createHash } from 'node:crypto';
import { readdirSync, readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), '../../..');
const container = `openpc-p00-pending-delivery-${process.pid}`;
const image = 'postgres:18.6';
const database = 'openpc_control';
const adminPassword = 'openpc_p00_admin_local_only';
const runtimePassword = 'openpc_p00_runtime_local_only';
const bypassPassword = 'openpc_p00_bypass_local_only';
let running = false;

function run(command, args, options = {}) {
  const result = spawnSync(command, args, {
    cwd: repositoryRoot,
    encoding: 'utf8',
    maxBuffer: 32 * 1024 * 1024,
    ...options,
  });
  if (result.status !== 0) {
    const output = [result.stdout, result.stderr].filter(Boolean).join('\n').trim();
    throw new Error(`${command} ${args[0] ?? ''} failed${output ? `\n${output}` : ''}`);
  }
  return typeof result.stdout === 'string' ? result.stdout.trim() : '';
}

function dockerPsql(sql) {
  return run(
    'docker',
    [
      'exec',
      '-i',
      '-e',
      `PGPASSWORD=${adminPassword}`,
      container,
      'psql',
      '-X',
      '-v',
      'ON_ERROR_STOP=1',
      '-q',
      '-U',
      'postgres',
      '-d',
      database,
    ],
    { input: sql },
  );
}

function cleanup() {
  if (!running) return;
  spawnSync('docker', ['rm', '-f', container], { stdio: 'ignore' });
  running = false;
}

process.once('exit', cleanup);
process.once('SIGINT', () => {
  cleanup();
  process.exit(130);
});
process.once('SIGTERM', () => {
  cleanup();
  process.exit(143);
});

try {
  run('docker', ['rm', '-f', container]);
} catch {
  // An absent purpose-bound container is the expected initial state.
}

try {
  run('docker', [
    'run',
    '--detach',
    '--name',
    container,
    '--publish',
    '127.0.0.1::5432',
    '--env',
    `POSTGRES_PASSWORD=${adminPassword}`,
    '--env',
    `POSTGRES_DB=${database}`,
    image,
  ]);
  running = true;

  let ready = false;
  for (let attempt = 0; attempt < 60; attempt += 1) {
    const probe = spawnSync(
      'docker',
      [
        'exec',
        '-e',
        `PGPASSWORD=${adminPassword}`,
        container,
        'psql',
        '-X',
        '-At',
        '-U',
        'postgres',
        '-d',
        database,
        '-c',
        'select 1',
      ],
      { stdio: 'ignore' },
    );
    if (probe.status === 0) {
      ready = true;
      break;
    }
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 500);
  }
  if (!ready) throw new Error('PostgreSQL 18.6 container did not become ready');

  const migrationDirectory = resolve(repositoryRoot, 'migrations/postgres/identity');
  const migrations = readdirSync(migrationDirectory)
    .filter((name) => /^\d{4}_.+\.sql$/u.test(name))
    .sort();
  if (!migrations.includes('0008_conscious_scalphunter.sql')) {
    throw new Error('generated P00 identity migration is missing');
  }
  for (const migration of migrations) {
    const bytes = readFileSync(resolve(migrationDirectory, migration));
    dockerPsql(bytes);
    process.stdout.write(
      `P00_MIGRATION|${migration}|${createHash('sha256').update(bytes).digest('hex')}\n`,
    );
  }

  dockerPsql(`
    CREATE ROLE openpc_p00_runtime LOGIN PASSWORD '${runtimePassword}'
      NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION INHERIT NOBYPASSRLS;
    GRANT openpc_control_runtime TO openpc_p00_runtime;
    CREATE ROLE openpc_p00_bypass LOGIN PASSWORD '${bypassPassword}'
      NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION INHERIT BYPASSRLS;
    GRANT openpc_control_runtime TO openpc_p00_bypass;
  `);

  const portOutput = run('docker', ['port', container, '5432/tcp']);
  const port = portOutput.match(/:(\d+)$/u)?.[1];
  if (port === undefined) throw new Error(`unable to resolve isolated PostgreSQL port`);
  const adminDatabaseUrl = `postgresql://postgres:${adminPassword}@127.0.0.1:${port}/${database}`;
  const runtimeDatabaseUrl = `postgresql://openpc_p00_runtime:${runtimePassword}@127.0.0.1:${port}/${database}`;
  const bypassDatabaseUrl = `postgresql://openpc_p00_bypass:${bypassPassword}@127.0.0.1:${port}/${database}`;
  const environment = {
    ...process.env,
    OPENPC_P00_ADMIN_DATABASE_URL: adminDatabaseUrl,
    OPENPC_P00_BYPASS_DATABASE_URL: bypassDatabaseUrl,
    OPENPC_P00_RUNTIME_DATABASE_URL: runtimeDatabaseUrl,
  };

  const version = dockerPsql(`select current_setting('server_version');`);
  if (!version.includes('18.6')) throw new Error(`unexpected PostgreSQL version: ${version}`);
  const imageId = run('docker', ['inspect', '--format', '{{.Image}}', container]);
  process.stdout.write(`P00_POSTGRES|${image}|${imageId}|${version}\n`);

  run(
    'pnpm',
    [
      'exec',
      'vitest',
      'run',
      '--config',
      'tests/integration/identity/vitest.config.ts',
      'tests/integration/identity/contracts.test.ts',
      'tests/integration/identity/pending-delivery-contract.test.ts',
      'tests/integration/identity/pending-delivery-kernel.test.ts',
      'tests/integration/identity/pending-delivery-postgres.test.ts',
    ],
    { env: environment, stdio: 'inherit' },
  );
  run(
    'pnpm',
    [
      'exec',
      'vitest',
      'run',
      '--config',
      'tests/security/identity/vitest.config.ts',
      'tests/security/identity/contracts.test.ts',
      'tests/security/identity/pending-delivery-nondisclosure.test.ts',
    ],
    { env: environment, stdio: 'inherit' },
  );
  run('pnpm', ['--filter', '@openpc/identity-service', 'test'], {
    env: environment,
    stdio: 'inherit',
  });

  process.stdout.write('OPENPC_P00_PENDING_DELIVERY_PROOF|PASS\n');
} finally {
  cleanup();
}
