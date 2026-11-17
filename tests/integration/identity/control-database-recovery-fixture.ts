import { execFile } from 'node:child_process';
import { realpath, writeFile } from 'node:fs/promises';
import { isAbsolute, join, relative, sep } from 'node:path';
import { promisify } from 'node:util';
import { expect } from 'vitest';
import { localOperationId as id } from '../../../services/identity-service/src/domain/local-operation-id.js';

const execute = promisify(execFile);

// Shared only by the two PostgreSQL component recovery fixtures. Errors must
// never print a command's arguments, database credentials or captured output.
export async function recoveryCommand(args: string[]) {
  try {
    return await execute('docker', args, { timeout: 60000, maxBuffer: 65536 });
  } catch {
    throw new Error('PostgreSQL component recovery command failed');
  }
}

export async function recoveryDirectory(root: string, directory: string) {
  const child = relative(root, directory);
  if (
    !isAbsolute(directory) ||
    (await realpath(directory)) !== directory ||
    (child !== '' && (child === '..' || child.startsWith(`..${sep}`) || isAbsolute(child)))
  )
    throw new Error('BLOCKED: recovery path must remain in its owned fixture');
  return directory;
}

export async function retainRecoveryArchive(container: string, insideDump: string, file: string) {
  let bytes: Buffer;
  try {
    bytes = (
      await execute('docker', ['exec', container, 'cat', insideDump], {
        encoding: 'buffer',
        timeout: 30000,
        maxBuffer: 64 * 1024 * 1024,
      })
    ).stdout;
  } catch {
    throw new Error('PostgreSQL component backup read failed');
  }
  try {
    expect(bytes.subarray(0, 5).toString()).toBe('PGDMP');
    await writeFile(file, bytes, { mode: 0o600, flag: 'wx' });
  } finally {
    bytes.fill(0);
  }
}
const adminUrl = process.env.OPENPC_I02_ADMIN_DATABASE_URL;
const workerUrl = process.env.OPENPC_DEPLOYMENT_COMPILATION_DATABASE_URL;
const runtimeUrl = process.env.OPENPC_I02_RUNTIME_DATABASE_URL;

/** Same supported PostgreSQL custom archive/restore tools as the existing local
 * recovery rehearsal. Only the participant runner's labelled, capped disposable
 * container is eligible. No new container or shared retained database is used.
 * The source is fenced permanently for this run; only the recovery DB resumes.
 * Global roles and mounted host trust are preserved in this same-cluster test.
 * This is not cross-host secret/role provisioning or historical schema upgrade. */
export async function controlDatabaseRecoveryFixture(
  dumpName:
    | 'evidence-remote-restore.dump'
    | 'evidence-candidate-restore.dump' = 'evidence-remote-restore.dump',
  dumpDirectory?: string,
) {
  if (!adminUrl || !workerUrl || !runtimeUrl || !process.env.OPENPC_TEST_TMP_ROOT) {
    throw new Error('BLOCKED: isolated participant recovery fixture inputs are required');
  }
  if (!['evidence-remote-restore.dump', 'evidence-candidate-restore.dump'].includes(dumpName)) {
    throw new Error('Invalid component recovery backup name');
  }
  let connections: URL[];
  try {
    connections = [adminUrl, workerUrl, runtimeUrl].map((value) => new URL(value));
  } catch {
    throw new Error('BLOCKED: malformed participant recovery connection');
  }
  const original = connections[0]!;
  for (const connection of connections) {
    if (
      connection.protocol !== 'postgresql:' ||
      connection.hostname !== '127.0.0.1' ||
      connection.pathname !== '/openpc_control' ||
      !connection.port ||
      connection.port !== original.port ||
      connection.search ||
      connection.hash
    )
      throw new Error('BLOCKED: recovery connections must bind the same isolated Control database');
  }
  const root = await realpath(process.env.OPENPC_TEST_TMP_ROOT!);
  const backupDirectory = await recoveryDirectory(root, dumpDirectory ?? root);
  const administrator = decodeURIComponent(original.username);
  if (!['postgres', 'openpc_control'].includes(administrator))
    throw new Error('BLOCKED: unsupported local fixture administrator');
  const ids = (
    await recoveryCommand(['ps', '-q', '--filter', `label=io.openpc.test-owner=${root}`])
  ).stdout
    .trim()
    .split(/\s+/u);
  expect(ids).toHaveLength(1);
  const container = ids[0]!;
  expect(container).toMatch(/^[0-9a-f]{12,64}$/u);
  const format =
    '{"owner":{{json (index .Config.Labels "io.openpc.test-owner")}},"memory":{{.HostConfig.Memory}},"swap":{{.HostConfig.MemorySwap}},"ports":{{json .NetworkSettings.Ports}}}';
  const inspected = JSON.parse(
    (await recoveryCommand(['inspect', '--format', format, container])).stdout,
  ) as {
    owner: string;
    memory: number;
    swap: number;
    ports: Record<string, { HostIp: string; HostPort: string }[]>;
  };
  expect(inspected).toMatchObject({ owner: root, memory: 1073741824, swap: 1073741824 });
  expect(original.hostname).toBe('127.0.0.1');
  expect(original.pathname).toBe('/openpc_control');
  expect(inspected.ports['5432/tcp']).toContainEqual({
    HostIp: '127.0.0.1',
    HostPort: original.port,
  });
  const target = `openpc_restore_${id().replaceAll('-', '')}`;
  const insideDump = `/tmp/${target}.dump`;
  const command = (args: string[]) => recoveryCommand(['exec', container, ...args]);
  const sql = (query: string) =>
    command([
      'psql',
      '-X',
      '-q',
      '-At',
      '-v',
      'ON_ERROR_STOP=1',
      '-U',
      administrator,
      '-d',
      'postgres',
      '-c',
      query,
    ]);
  const url = (source: string) => {
    const next = new URL(source);
    next.pathname = `/${target}`;
    return next.href;
  };
  return {
    adminUrl: url(adminUrl!),
    workerUrl: url(workerUrl!),
    runtimeUrl: url(runtimeUrl!),
    async restore() {
      expect(
        (await sql('select rolsuper from pg_roles where rolname=current_user')).stdout.trim(),
      ).toBe('t');
      // Caller has closed every HTTP owner and DB pool and awaited every --once
      // worker. Refuse a connected source; never terminate another connection.
      expect(
        (
          await sql("select count(*) from pg_stat_activity where datname='openpc_control'")
        ).stdout.trim(),
      ).toBe('0');
      expect(
        (await sql(`select count(*) from pg_database where datname='${target}'`)).stdout.trim(),
      ).toBe('0');
      const sourceOwner = (
        await sql("select pg_get_userbyid(datdba) from pg_database where datname='openpc_control'")
      ).stdout.trim();
      expect(sourceOwner).toBe('openpc_control_owner');
      await sql('alter database openpc_control connection limit 0');
      await command([
        'pg_dump',
        '-Fc',
        '-U',
        administrator,
        '-d',
        'openpc_control',
        '-f',
        insideDump,
      ]);
      // Retain the actual binary backup, privately, for first-failure diagnosis.
      await retainRecoveryArchive(container, insideDump, join(backupDirectory, dumpName));
      await sql('alter database openpc_control allow_connections false');
      expect(
        (
          await sql("select count(*) from pg_stat_activity where datname='openpc_control'")
        ).stdout.trim(),
      ).toBe('0');
      // pg_database_owner follows the database owner. A postgres-owned target
      // would silently remove the definer's access to public cryptographic helpers.
      await command([
        'createdb',
        '-T',
        'template0',
        '-U',
        administrator,
        '--owner',
        sourceOwner,
        target,
      ]);
      await command([
        'pg_restore',
        '--exit-on-error',
        '--single-transaction',
        '-U',
        administrator,
        '-d',
        target,
        insideDump,
      ]);
      expect(
        (
          await sql("select datallowconn from pg_database where datname='openpc_control'")
        ).stdout.trim(),
      ).toBe('f');
    },
  };
}
