import { spawnSync } from 'node:child_process';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, expect, it } from 'vitest';

const roots: string[] = [];
const health = await readFile(
  new URL('../../../../deploy/compose/local/postgres-final-healthcheck.sh', import.meta.url),
  'utf8',
);

afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

it.each([
  { name: 'legacy final server', pid1: 'postgres', children: [], admitted: true },
  { name: 'legacy bootstrap', pid1: 'docker-entrypoi', children: ['postgres'], admitted: false },
  { name: 'init final server', pid1: 'docker-init', children: ['postgres'], admitted: true },
  { name: 'init bootstrap', pid1: 'docker-init', children: ['docker-entrypoi'], admitted: false },
  { name: 'no final server', pid1: 'docker-init', children: [], admitted: false },
  {
    name: 'multiple final servers',
    pid1: 'docker-init',
    children: ['postgres', 'postgres'],
    admitted: false,
  },
  { name: 'unrelated orphan', pid1: 'docker-init', children: ['postgres', 'sh'], admitted: true },
  {
    name: 'wrong database',
    pid1: 'docker-init',
    children: ['postgres'],
    database: 'foreign',
    admitted: false,
  },
  {
    name: 'failed database query',
    pid1: 'docker-init',
    children: ['postgres'],
    queryExit: '1',
    admitted: false,
  },
])('admits the exact final database with $name', async (scenario) => {
  const root = await mkdtemp(join(process.env.OPENPC_TEST_TMP_ROOT ?? tmpdir(), 'pg-lifecycle-'));
  roots.push(root);
  await mkdir(join(root, 'proc/1/task/1'), { recursive: true });
  await mkdir(join(root, 'bin'));
  await writeFile(join(root, 'proc/1/comm'), scenario.pid1);
  const ids = scenario.children.map((_name, index) => String(index + 10));
  await writeFile(join(root, 'proc/1/task/1/children'), ids.join(' '));
  for (const [index, name] of scenario.children.entries()) {
    await mkdir(join(root, 'proc', ids[index]!));
    await writeFile(join(root, 'proc', ids[index]!, 'comm'), name);
  }
  await writeFile(join(root, 'password'), 'synthetic-unit-password', { mode: 0o600 });
  await writeFile(join(root, 'health.sh'), health.replaceAll('/proc/', root + '/proc/'));
  await writeFile(
    join(root, 'bin/psql'),
    `#!/bin/sh
set -eu
[ "$PGPASSWORD" = synthetic-unit-password ]
printf '%s\\n' "$@" > "$CAPTURE"
printf '%s\\n' "$MOCK_DATABASE"
exit "$MOCK_EXIT"
`,
    { mode: 0o700 },
  );
  const run = spawnSync('sh', [join(root, 'health.sh')], {
    encoding: 'utf8',
    timeout: 3000,
    env: {
      ...process.env,
      PATH: join(root, 'bin') + ':' + process.env.PATH,
      POSTGRES_PASSWORD_FILE: join(root, 'password'),
      POSTGRES_DB: 'openpc_control',
      POSTGRES_USER: 'unit-runtime',
      MOCK_DATABASE: scenario.database ?? 'openpc_control',
      MOCK_EXIT: scenario.queryExit ?? '0',
      CAPTURE: join(root, 'arguments'),
    },
  });
  expect(run.error).toBeUndefined();
  expect(run.status === 0).toBe(scenario.admitted);
  expect(run.stdout + run.stderr).not.toContain('synthetic-unit-password');
  if (scenario.admitted) {
    const args = (await readFile(join(root, 'arguments'), 'utf8')).split('\n');
    expect(args).toEqual([
      '-X',
      '-qAt',
      '-v',
      'ON_ERROR_STOP=1',
      '-h',
      '127.0.0.1',
      '-U',
      'unit-runtime',
      '-d',
      'openpc_control',
      '-c',
      'select current_database()',
      '',
    ]);
  }
});

it('reaps PostgreSQL container orphans outside the database server', async () => {
  const compose = await readFile(
    new URL('../../../../deploy/compose/local/compose.yaml', import.meta.url),
    'utf8',
  );
  const defaults = compose.slice(
    compose.indexOf('x-postgres: &postgres'),
    compose.indexOf('x-postgres-final-healthcheck:'),
  );
  expect(defaults.split('\n')).toContain('  init: true');
  for (const service of ['control-pg', 'fact-pg', 'candidate-index-pg']) {
    expect(compose).toContain(`  ${service}:\n    <<: *postgres\n`);
  }
});
