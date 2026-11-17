import { createHash } from 'node:crypto';
import { lstat, readFile, readdir, realpath } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { Pool, type PoolClient } from 'pg';
import { z } from 'zod';
import { expect } from 'vitest';
import {
  observeRecovery,
  readRecoverySecurity,
  recoveryAcl,
  finishRecoverySourcePhase,
  type RecoverySourceStep,
  type RecoverySourceAction,
} from './postgres-component-recovery.js';
import {
  recoveryCommand,
  recoveryDirectory,
  retainRecoveryArchive,
} from './control-database-recovery-fixture.js';
import {
  assertCandidateRecoveryComparison,
  candidateDatabaseRecoveryCase,
  candidateRecoveryImage,
  candidateRecoveryTargetPort,
  requireDistinctCandidateClusters,
  type CandidateDatabaseRecoveryCase,
  candidateRecoveryData,
  candidateRecoveryFingerprint,
  candidateRecoverySecurity,
  readCandidateRecoveryBinding,
  requireUnusedCandidateRecoveryBinding,
  retainCandidateRecoveryOriginal,
  sealCandidateRecoveryBinding,
  type CandidateRecoveryComparison,
  type CandidateRecoveryProvenance,
} from './candidate-recovery-binding.js';

const database = 'openpc_candidate_index';
const owner = 'openpc_candidate_index_owner';
type Cluster = CandidateDatabaseRecoveryCase['source'];
type Role = keyof Cluster['passwords'];
export { candidateDatabaseRecoveryCase, candidateRecoveryImage, requireDistinctCandidateClusters };
export type { CandidateDatabaseRecoveryCase };

export async function privateRecoveryInput(root: string, file: string) {
  await recoveryDirectory(root, dirname(file));
  const stat = await lstat(file);
  if (
    (await realpath(file)) !== file ||
    !stat.isFile() ||
    stat.isSymbolicLink() ||
    stat.uid !== process.getuid?.() ||
    (stat.mode & 0o077) !== 0 ||
    stat.nlink !== 1 ||
    stat.size > 64 * 1024 * 1024
  )
    throw new Error('BLOCKED: recovery input must be a private owned regular file');
  return file;
}

/** Compose passwords are read-only mounts for distinct container UIDs. Accept
 * 0444 only in the original owned/private secrets directory, never for signing
 * keys, cases, backups or arbitrary outside files. */
export async function recoveryDatabasePassword(root: string, file: string) {
  const directory = join(root, 'secrets');
  if (dirname(file) !== directory)
    throw new Error('BLOCKED: installed database password path required');
  await recoveryDirectory(root, directory);
  const parent = await lstat(directory);
  if (!parent.isDirectory() || parent.uid !== process.getuid?.() || (parent.mode & 0o777) !== 0o700)
    throw new Error('BLOCKED: installed database password directory must be private and owned');
  const stat = await lstat(file);
  if (
    (await realpath(file)) !== file ||
    !stat.isFile() ||
    stat.isSymbolicLink() ||
    stat.uid !== process.getuid?.() ||
    stat.nlink !== 1 ||
    stat.size > 257 ||
    ![0o400, 0o444, 0o600].includes(stat.mode & 0o777)
  )
    throw new Error('BLOCKED: invalid installed database password file');
  const bytes = await readFile(file);
  try {
    const password = bytes.toString().trim();
    if (!/^[0-9a-f]{64}$/u.test(password))
      throw new Error('BLOCKED: invalid installed database password');
    return password;
  } finally {
    bytes.fill(0);
  }
}

export async function readCandidateRecoveryCase(file: string, root: string) {
  await privateRecoveryInput(root, file);
  // Do not expose Zod input values (which may be credential paths) in failures.
  const parsed = candidateDatabaseRecoveryCase.safeParse(JSON.parse(await readFile(file, 'utf8')));
  if (!parsed.success) throw new Error('BLOCKED: invalid Candidate database recovery case');
  requireDistinctCandidateClusters(parsed.data);
  return parsed.data;
}

export async function recoveryPool(
  root: string,
  port: number,
  user: string,
  passwordFile: string,
  name: string,
) {
  const password = await recoveryDatabasePassword(root, passwordFile);
  return new Pool({
    host: '127.0.0.1',
    port,
    database: name,
    user,
    password,
    max: 1,
    connectionTimeoutMillis: 5000,
    statement_timeout: 15000,
    application_name: 'openpc-candidate-component-recovery',
    options: '-c timezone=UTC -c lock_timeout=5000',
  });
}

export async function currentCandidateMigrations() {
  const directory = new URL('../../../migrations/postgres/candidate-index/', import.meta.url);
  const names = (await readdir(directory))
    .filter((name) => /^[0-9]{4}_[a-z0-9_]+\.sql$/u.test(name))
    .sort();
  expect(names.length).toBeGreaterThan(0);
  const result = [];
  for (const name of names) {
    const bytes = await readFile(new URL(name, directory));
    const sql = bytes.toString();
    const journal = sql.slice(sql.lastIndexOf('INSERT INTO candidate.schema_migration'));
    const phases = [...journal.matchAll(/'(M[0-5]_[A-Z_]+)'/gu)].map((match) => match[1]!);
    expect(phases, 'Candidate migration must declare its journal phase').toHaveLength(1);
    result.push({
      id: `OPENPC-MIG-CANDIDATE-${name.slice(0, 4)}`,
      path: `/migrations/postgres/candidate-index/${name}`,
      sha256: createHash('sha256').update(bytes).digest('hex'),
      phase: phases[0]!,
    });
  }
  expect(new Set(result.map((row) => row.id)).size).toBe(result.length);
  return result;
}

export async function assertCandidateMigrationJournals(pool: Pool | PoolClient) {
  const expected = await currentCandidateMigrations();
  const sqlx = (
    await pool.query(
      `select migration_id id, encode(migration_checksum,'hex') sha256,profile,phase
     from candidate.schema_migration order by migration_id`,
    )
  ).rows;
  expect(sqlx.map(({ id, sha256 }) => ({ id, sha256 }))).toEqual(
    expected.map(({ id, sha256 }) => ({ id, sha256 })),
  );
  expect(sqlx.map(({ id, profile, phase }) => ({ id, profile, phase }))).toEqual(
    expected.map(({ id, phase }) => ({ id, profile: 'MIG-GREENFIELD-V1', phase })),
  );
  expect(
    (await pool.query('select path,sha256 from openpc_local.migration order by path')).rows,
  ).toEqual(expected.map(({ path, sha256 }) => ({ path, sha256 })));
}

const quote = (value: string) => `"${value.replaceAll('"', '""')}"`;
/** Observation cleanup is part of recovery acceptance, not best effort. Borrowed
 * snapshot clients remain owned by the source-fencing phase below. */
const observeCandidateRecovery = <T>(
  pool: Pool,
  borrowed: PoolClient | undefined,
  observe: (client: PoolClient) => Promise<T>,
) =>
  observeRecovery(
    pool,
    borrowed,
    observe,
    'UNKNOWN: Candidate recovery observation or cleanup failed',
  );
/** Only fingerprints leave SQL, including capability secrets, ACKs, private
 * payloads and retained signed wires. Table discovery includes new migrations. */
export async function candidateDatabaseSnapshot(pool: Pool, borrowed?: PoolClient) {
  return observeCandidateRecovery(pool, borrowed, async (client) => {
    if (!borrowed) await client.query('begin isolation level repeatable read read only');
    const tables = (
      await client.query<{ schema: string; name: string }>(
        `select n.nspname schema,c.relname name from pg_class c join pg_namespace n on n.oid=c.relnamespace
       where n.nspname in ('candidate','openpc_local') and c.relkind in ('r','p')
       order by n.nspname,c.relname`,
      )
    ).rows;
    const rows: Record<string, string[]> = {};
    for (const table of tables)
      rows[`${table.schema}.${table.name}`] = (
        await client.query<{ fingerprint: string }>(
          `select encode(sha256(convert_to(to_jsonb(t)::text,'UTF8')),'hex') fingerprint
       from ${quote(table.schema)}.${quote(table.name)} t order by fingerprint`,
        )
      ).rows.map((row) => row.fingerprint);
    const sequences = (
      await client.query<{ schema: string; name: string }>(
        `select n.nspname schema,c.relname name from pg_class c join pg_namespace n on n.oid=c.relnamespace
       where n.nspname='candidate' and c.relkind='S' order by n.nspname,c.relname`,
      )
    ).rows;
    for (const sequence of sequences)
      rows[`sequence.${sequence.name}`] = (
        await client.query<{ fingerprint: string }>(
          `select encode(sha256(convert_to(to_jsonb(s)::text,'UTF8')),'hex') fingerprint
       from (select last_value,is_called from ${quote(sequence.schema)}.${quote(sequence.name)}) s`,
        )
      ).rows.map((row) => row.fingerprint);
    expect(Object.keys(rows)).toContain('candidate.schema_migration');
    expect(Object.keys(rows)).toContain('candidate.store_retirement_attempt');
    return rows;
  });
}

async function roles(pool: Pool | PoolClient) {
  const attributes = (
    await pool.query(
      `select rolname,rolsuper,rolinherit,rolcreaterole,rolcreatedb,rolcanlogin,rolreplication,
      rolbypassrls,rolconnlimit,rolvaliduntil::text,rolconfig from pg_roles
     where rolname !~ '^pg_' order by rolname`,
    )
  ).rows;
  const memberships = (
    await pool.query(
      `select pg_get_userbyid(roleid) role,pg_get_userbyid(member) member,
      pg_get_userbyid(grantor) grantor,admin_option,inherit_option,set_option
     from pg_auth_members order by role,member,grantor`,
    )
  ).rows;
  for (const name of [
    owner,
    'openpc_indexer_manager',
    'openpc_indexer_writer',
    'openpc_fact_bridge_reader',
    'openpc_candidate_index_reader',
    'openpc_candidate_index_maintenance',
    'openpc_backup_operator',
  ]) {
    const row = attributes.find((value) => value.rolname === name);
    expect(row, 'BLOCKED: canonical Candidate role provisioning required').toMatchObject({
      rolsuper: false,
      rolinherit: false,
      rolcreaterole: false,
      rolcreatedb: false,
      rolreplication: false,
      rolbypassrls: false,
    });
  }
  for (const role of [
    'openpc_indexer_manager',
    'openpc_indexer_writer',
    'openpc_candidate_index_reader',
  ]) {
    expect(attributes.find((row) => row.rolname === role)?.rolcanlogin).toBe(true);
    expect(
      (
        await pool.query(
          `select pg_has_role($1,$2,'MEMBER') owner,pg_has_role($1,'openpc_candidate_index_maintenance','MEMBER') maintenance`,
          [role, owner],
        )
      ).rows[0],
    ).toEqual({ owner: false, maintenance: false });
  }
  return { attributes, memberships };
}

// ACL order is role-name based: OIDs differ between the two isolated clusters.
// pg_dump omits an ACL equal to the built-in default. NULL therefore means
// acldefault for the object kind/owner, not a loss of the owner's privileges.
// Resolve only that PostgreSQL-defined default; retain each explicit grantor,
// grantee, privilege and grant option in the comparison.
export const candidateRecoveryAcl = recoveryAcl;

export async function candidateDatabaseSecurity(pool: Pool, borrowed?: PoolClient) {
  return observeCandidateRecovery(pool, borrowed, async (client) => {
    if (!borrowed) await client.query('begin');
    const roleState = await roles(client);
    const result = await readRecoverySecurity(client, 'candidate', roleState);
    const { relations } = result;
    for (const row of relations.filter((row) => row.schema === 'candidate')) {
      expect(row.owner).toBe(owner);
      if (
        ['r', 'p'].includes(row.relkind) &&
        ![
          'schema_migration',
          'migration_checkpoint',
          'retirement_capability_secret',
          'retirement_capability_replay',
        ].includes(row.name)
      )
        expect(row).toMatchObject({ rls: true, forced: true });
    }
    return result;
  });
}

export async function candidateControlSnapshot(pool: Pool, participantId: string) {
  const rows: Record<string, string[]> = {};
  for (const table of [
    'evidence_candidate_archive',
    'evidence_candidate_archive_part',
    'evidence_catalogue',
    'evidence_segment',
    'evidence_segment_payload',
    'evidence_checkpoint',
    'evidence_hold_coverage',
    'retention_hold',
    'retention_policy',
    'deletion_job',
    'evidence_deletion_item',
    'evidence_projection_retirement',
    'store_retirement_host',
    'store_retirement_verifier_key',
    'store_retirement_admission',
    'store_retirement_outcome',
    'store_retirement_delivery',
    'store_retirement_cancellation',
    'mutation_evidence',
    'outbox_event',
    'projection_plan',
    'indexer_profile',
    'configuration_work',
    'idempotency_record',
    'module_installation',
    'runtime_configuration_generation',
  ])
    rows[table] = (
      await pool.query<{ fingerprint: string }>(
        `select encode(sha256(convert_to(to_jsonb(t)::text,'UTF8')),'hex') fingerprint
     from control.${table} t where participant_id=$1 order by fingerprint`,
        [participantId],
      )
    ).rows.map((row) => row.fingerprint);
  return rows;
}

export async function candidateVaultInventory(root: string, directory: string) {
  await recoveryDirectory(root, directory);
  const result = [];
  for (const name of (await readdir(directory)).sort()) {
    if (!/^[a-f0-9]{64}\.(?:segment|hold-[12])$/u.test(name))
      throw new Error('BLOCKED: original Candidate vault contains an unfinished object');
    const file = join(directory, name);
    await privateRecoveryInput(root, file);
    const bytes = await readFile(file);
    try {
      result.push({
        name,
        bytes: bytes.length,
        digest: createHash('sha256').update(bytes).digest('hex'),
      });
    } finally {
      bytes.fill(0);
    }
  }
  expect(result.length).toBeGreaterThan(0);
  return result;
}

type CandidateSourceStep = RecoverySourceStep;
type CandidateSourceAction = RecoverySourceAction;

export class CandidateRecoverySourceFailure extends Error {
  readonly failedSteps: readonly CandidateSourceStep[];

  constructor(primary: unknown, steps: CandidateSourceStep[]) {
    super('UNKNOWN: Candidate source preparation, cleanup or permanent fence failed', {
      cause: primary,
    });
    this.failedSteps = Object.freeze([...steps]);
  }
}

/** One source-ownership boundary for fresh and retained recovery. Cleanup and
 * the permanent fence run independently, even after a synchronous/falsy throw.
 * Returning is the only permission for the caller to enter target recovery.
 * This helper does not retry work, reopen a source or remove any artifact. */
export async function finishCandidateRecoverySourcePhase(actions: {
  prepare: CandidateSourceAction;
  rollbackSnapshot?: CandidateSourceAction;
  releaseSnapshot?: CandidateSourceAction;
  endSourcePool?: CandidateSourceAction;
  fenceSource: CandidateSourceAction;
  verifySourceFence: CandidateSourceAction;
}) {
  return finishRecoverySourcePhase(
    actions,
    (primary, steps) => new CandidateRecoverySourceFailure(primary, steps),
  );
}

export async function candidateDatabaseRecoveryFixture(
  input: CandidateDatabaseRecoveryCase,
  root: string,
  retained = false,
) {
  requireDistinctCandidateClusters(input);
  expect(await realpath(root)).toBe(root);
  const marker = join(root, '.openpc-local-runtime-owner');
  await privateRecoveryInput(root, marker);
  expect((await lstat(marker)).isSymbolicLink()).toBe(false);
  expect(await realpath(marker)).toBe(marker);
  const ownership = /^openpc-local-runtime:(openpc-local-e2e-[0-9a-f]{12}):([0-9a-f]{64})\n$/u.exec(
    await readFile(marker, 'utf8'),
  );
  expect(ownership, 'BLOCKED: original runtime owner required').not.toBeNull();
  expect(ownership?.[1]).toBe(input.project);
  expect(input.project).toBe(`openpc-local-e2e-${ownership?.[2]?.slice(0, 12)}`);
  await recoveryDirectory(root, input.backupDirectory);
  for (const value of [input.source, input.target]) {
    await recoveryDirectory(root, value.dataDirectory);
    for (const password of Object.values(value.passwords))
      await recoveryDatabasePassword(root, password);
  }
  const inspect = async (value: Cluster, source: boolean) => {
    const [info] = JSON.parse((await recoveryCommand(['inspect', value.containerId])).stdout);
    expect(info.Id).toBe(value.containerId);
    expect(info.State.Running).toBe(true);
    expect(info.Config.Image).toBe(candidateRecoveryImage);
    expect(info.HostConfig.Privileged).toBe(false);
    expect(info.HostConfig.NetworkMode).not.toBe('host');
    expect(info.HostConfig.Memory).toBe(1073741824);
    // Existing Compose source defaults to one additional GiB of bounded swap;
    // the fresh target is provisioned without additional swap by its runner.
    expect(source ? [1073741824, 2147483648] : [1073741824]).toContain(info.HostConfig.MemorySwap);
    expect(info.HostConfig.NanoCpus).toBeGreaterThan(0);
    expect(info.HostConfig.NanoCpus).toBeLessThanOrEqual(1_000_000_000);
    expect(info.HostConfig.PidsLimit).toBeGreaterThan(0);
    expect(info.HostConfig.PidsLimit).toBeLessThanOrEqual(256);
    expect(info.HostConfig.SecurityOpt).toContain('no-new-privileges:true');
    if (source)
      expect(info.Config.Labels).toMatchObject({
        'com.docker.compose.project': input.project,
        'com.docker.compose.service': 'candidate-index-pg',
      });
    else
      expect(info.Config.Labels).toMatchObject({
        'io.openpc.test-owner': root,
        'io.openpc.recovery-role': 'candidate-target',
      });
    const port =
      !source && retained ? candidateRecoveryTargetPort(input, root, info.Image, info) : value.port;
    expect(port).toBeDefined();
    expect(info.NetworkSettings.Ports['5432/tcp']).toEqual([
      { HostIp: '127.0.0.1', HostPort: String(port) },
    ]);
    expect(
      info.Mounts.filter(
        (mount: { Destination: string }) => mount.Destination === '/var/lib/postgresql',
      ),
    ).toMatchObject([{ Type: 'bind', Source: value.dataDirectory, RW: true }]);
    return { image: info.Image as string, port: port! };
  };
  const sourceImage = (await inspect(input.source, true)).image;
  const targetInspection = await inspect(input.target, false);
  expect(targetInspection.image).toBe(sourceImage);
  const targetEndpoint = { ...input.target, port: targetInspection.port };
  const connect = (value: Cluster, role: Role, name = database) =>
    recoveryPool(
      root,
      value === input.target ? targetEndpoint.port : value.port,
      role,
      value.passwords[role],
      name,
    );
  const sourceAdmin = await connect(input.source, 'openpc_candidate_index', 'postgres');
  const targetAdmin = await connect(input.target, 'openpc_candidate_index', 'postgres');
  const zeroSessions = async (pool: Pool, name: string) => {
    expect(
      (
        await pool.query('select count(*)::int count from pg_stat_activity where datname=$1', [
          name,
        ])
      ).rows[0].count,
    ).toBe(0);
    expect(
      (
        await pool.query('select count(*)::int count from pg_prepared_xacts where database=$1', [
          name,
        ])
      ).rows[0].count,
    ).toBe(0);
  };
  const command = (value: Cluster, args: string[]) =>
    recoveryCommand(['exec', value.containerId, ...args]);
  const inside = '/tmp/openpc-candidate-component-recovery.dump';
  type Related = { control: Pool; vaultDirectory?: string };
  const related = async ({ control, vaultDirectory }: Related) => {
    if (input.phase === 'RETIRED') {
      await privateRecoveryInput(root, input.custodyCaseFile);
      const custody = JSON.parse(await readFile(input.custodyCaseFile, 'utf8'));
      if (!vaultDirectory || custody.vaultDirectory !== vaultDirectory)
        throw new Error('UNKNOWN: original Candidate vault binding required');
    } else if (vaultDirectory !== undefined) throw new Error('Invalid pristine vault binding');
    return {
      control: candidateRecoveryData(
        await candidateControlSnapshot(control, input.participantId),
        'control.',
      ),
      vault: vaultDirectory ? await candidateVaultInventory(root, vaultDirectory) : null,
    };
  };
  const provenance = async (): Promise<CandidateRecoveryProvenance> => {
    const identity = async (pool: Pool, value: Cluster) => {
      const rows = (
        await pool.query(
          `select s.system_identifier::text "systemIdentifier",d.oid::text "databaseOid",
         pg_get_userbyid(d.datdba) owner from pg_control_system() s cross join pg_database d where d.datname=$1`,
          [database],
        )
      ).rows;
      expect(rows).toHaveLength(1);
      expect(rows[0].owner).toBe(owner);
      return {
        containerId: value.containerId,
        imageId: sourceImage,
        dataDirectory: value.dataDirectory,
        port: value.port,
        systemIdentifier: rows[0].systemIdentifier as string,
        databaseOid: rows[0].databaseOid as string,
      };
    };
    const source = await identity(sourceAdmin, input.source);
    const target = await identity(targetAdmin, input.target);
    expect(source.systemIdentifier).not.toBe(target.systemIdentifier);
    return {
      project: input.project,
      ownerDigest: createHash('sha256')
        .update(await readFile(marker))
        .digest('hex'),
      selectionDigest: createHash('sha256').update(JSON.stringify(input)).digest('hex'),
      phase: input.phase,
      participantId: input.participantId,
      privacyDomainId: input.privacyDomainId,
      database,
      databaseOwner: owner,
      source,
      target,
    };
  };
  const administrators = async () => {
    for (const pool of [sourceAdmin, targetAdmin])
      expect(
        (
          await pool.query(
            "select current_user,session_user,current_setting('server_version_num')::int version,rolsuper from pg_roles where rolname=current_user",
          )
        ).rows[0],
      ).toMatchObject({
        current_user: 'openpc_candidate_index',
        session_user: 'openpc_candidate_index',
        rolsuper: true,
        version: 180006,
      });
  };
  const emptyTarget = async () => {
    const pool = await connect(input.target, 'openpc_candidate_index');
    try {
      return (
        (
          await pool.query(
            `select not exists(select 1 from pg_class c join pg_namespace n on n.oid=c.relnamespace
         where n.nspname not like 'pg_%' and n.nspname<>'information_schema')
         and not exists(select 1 from pg_namespace where nspname not like 'pg_%' and nspname not in ('public','information_schema'))
         and not exists(select 1 from pg_proc p join pg_namespace n on n.oid=p.pronamespace where n.nspname='public')
         and not exists(select 1 from pg_type t join pg_namespace n on n.oid=t.typnamespace where n.nspname='public') empty`,
          )
        ).rows[0].empty === true
      );
    } finally {
      await pool.end();
    }
  };
  const assertSourceFenced = async () => {
    expect(
      (
        await sourceAdmin.query(
          'select datallowconn,datconnlimit from pg_database where datname=$1',
          [database],
        )
      ).rows,
    ).toEqual([{ datallowconn: false, datconnlimit: 0 }]);
    await zeroSessions(sourceAdmin, database);
  };
  // Only the deliberate admission fence is normalized. Its live value must be
  // exactly zero; preserve the original limit separately for successor release.
  const capture = async (
    pool: Pool,
    options: Related,
    connectionLimit: number,
    client?: PoolClient,
  ): Promise<CandidateRecoveryComparison> => {
    const security = await candidateDatabaseSecurity(pool, client);
    expect(security.databases).toHaveLength(1);
    expect(security.databases[0].datconnlimit).toBe(0);
    security.databases[0].datconnlimit = connectionLimit;
    return {
      data: candidateRecoveryData(await candidateDatabaseSnapshot(pool, client)),
      security: candidateRecoverySecurity(security),
      ...(await related(options)),
    };
  };
  const restoreBound = async (options: Related, expected: CandidateRecoveryProvenance) => {
    const bound = await readCandidateRecoveryBinding(input.backupDirectory, expected);
    await assertSourceFenced();
    await zeroSessions(targetAdmin, database);
    await targetAdmin.query(`alter database ${database} connection limit 0`);
    await zeroSessions(targetAdmin, database);
    if (await emptyTarget()) {
      // A retained copy may already exist after interruption. Compare it exactly;
      // never overwrite it, or restore again over a nonempty successor.
      const copied = (
        await command(input.target, [
          'sh',
          '-ceu',
          'if test -e "$1" || test -L "$1"; then printf PRESENT; else printf ABSENT; fi',
          'candidate-recovery',
          inside,
        ])
      ).stdout;
      if (copied === 'ABSENT')
        await recoveryCommand(['cp', bound.archivePath, `${input.target.containerId}:${inside}`]);
      else expect(copied).toBe('PRESENT');
      const archive = (
        await command(input.target, [
          'sh',
          '-ceu',
          'test -f "$1"; test ! -L "$1"; stat -c "%a:%h:%s" "$1"; sha256sum "$1"',
          'candidate-recovery',
          inside,
        ])
      ).stdout
        .trim()
        .split('\n');
      expect(archive[0]).toBe(`600:1:${bound.archive.bytes}`);
      expect(archive[1]?.split(/\s+/u)[0]).toBe(bound.archive.sha256);
      await command(input.target, [
        'pg_restore',
        '--exit-on-error',
        '--single-transaction',
        '-U',
        'openpc_candidate_index',
        '-d',
        database,
        inside,
      ]);
    }
    const target = await connect(input.target, 'openpc_candidate_index');
    try {
      await assertCandidateMigrationJournals(target);
      assertCandidateRecoveryComparison(
        bound.original.comparison,
        await capture(target, options, bound.original.epoch.connectionLimit),
      );
    } finally {
      await target.end();
    }
    // Recheck original artifacts and provenance before admitting target writers.
    await readCandidateRecoveryBinding(input.backupDirectory, await provenance());
    await assertSourceFenced();
    await targetAdmin.query(
      `alter database ${database} connection limit ${bound.original.epoch.connectionLimit}`,
    );
    return bound;
  };
  let used = false;
  return {
    source: (role: Role = 'openpc_candidate_index') => connect(input.source, role),
    target: (role: Role = 'openpc_candidate_index') => connect(input.target, role),
    async close() {
      await Promise.all([sourceAdmin.end(), targetAdmin.end()]);
    },
    assertSourceFenced,
    async restoreRetained(options: Related) {
      if (used) throw new Error('UNKNOWN: Candidate recovery invocation already used');
      used = true;
      await administrators();
      const expected = await provenance();
      // No source DB connection, redump, fresh expected snapshot or metadata
      // regeneration is allowed on this path, including for historical backups.
      await readCandidateRecoveryBinding(input.backupDirectory, expected);
      await finishCandidateRecoverySourcePhase({
        prepare: async () => {
          expect(
            (
              await sourceAdmin.query('select datconnlimit from pg_database where datname=$1', [
                database,
              ])
            ).rows,
          ).toEqual([{ datconnlimit: 0 }]);
          await zeroSessions(sourceAdmin, database);
        },
        fenceSource: () => sourceAdmin.query(`alter database ${database} allow_connections false`),
        verifySourceFence: assertSourceFenced,
      });
      return restoreBound(options, expected);
    },
    async restore(options: Related) {
      if (used) throw new Error('UNKNOWN: recovery fixture cannot replay its original dump');
      used = true;
      await requireUnusedCandidateRecoveryBinding(input.backupDirectory);
      await administrators();
      const expected = await provenance();
      expect(await roles(targetAdmin)).toEqual(await roles(sourceAdmin));
      await zeroSessions(sourceAdmin, database);
      await zeroSessions(targetAdmin, database);
      const sourceDatabase = (
        await sourceAdmin.query(
          'select pg_get_userbyid(datdba) owner,datallowconn,datconnlimit from pg_database where datname=$1',
          [database],
        )
      ).rows;
      expect(sourceDatabase).toHaveLength(1);
      expect(sourceDatabase[0]).toMatchObject({ owner, datallowconn: true });
      const connectionLimit = z
        .number()
        .int()
        .min(-1)
        .max(2147483647)
        .parse(sourceDatabase[0].datconnlimit);
      expect(connectionLimit).not.toBe(0);
      expect(
        (
          await targetAdmin.query(
            "select datname from pg_database where datname not in ('postgres','template0','template1','openpc_candidate_index')",
          )
        ).rows,
      ).toEqual([]);
      expect(
        (
          await targetAdmin.query('select datconnlimit from pg_database where datname=$1', [
            database,
          ])
        ).rows,
      ).toEqual([{ datconnlimit: connectionLimit }]);
      expect(await emptyTarget()).toBe(true);
      await command(input.source, ['test', '!', '-e', inside]);
      await command(input.target, ['test', '!', '-e', inside]);
      let source: Pool | undefined;
      let snapshot: PoolClient | undefined;
      await finishCandidateRecoverySourcePhase({
        prepare: async () => {
          await sourceAdmin.query(`alter database ${database} connection limit 0`);
          await targetAdmin.query(`alter database ${database} connection limit 0`);
          await zeroSessions(sourceAdmin, database);
          source = await connect(input.source, 'openpc_candidate_index');
          snapshot = await source.connect();
          await snapshot.query('begin isolation level repeatable read');
          const tables = (
            await snapshot.query<{ schema: string; name: string }>(
              `select n.nspname schema,c.relname name from pg_class c join pg_namespace n on n.oid=c.relnamespace
           where n.nspname in ('candidate','openpc_local') and c.relkind in ('r','p') order by n.nspname,c.relname`,
            )
          ).rows;
          for (const table of tables)
            await snapshot.query(
              `lock table ${quote(table.schema)}.${quote(table.name)} in share mode`,
            );
          const epoch = (
            await snapshot.query(
              `select pg_export_snapshot() "exportedSnapshot",pg_current_snapshot()::text snapshot,
           pg_backend_pid() "backendPid",clock_timestamp() "observedAt"`,
            )
          ).rows[0];
          const exclusive = async () => {
            expect(
              (
                await sourceAdmin.query(
                  'select pid from pg_stat_activity where datname=$1 order by pid',
                  [database],
                )
              ).rows,
            ).toEqual([{ pid: epoch.backendPid }]);
            expect(
              (
                await sourceAdmin.query('select 1 from pg_prepared_xacts where database=$1', [
                  database,
                ])
              ).rows,
            ).toEqual([]);
          };
          await exclusive();
          await assertCandidateMigrationJournals(snapshot);
          const comparison = await capture(source, options, connectionLimit, snapshot);
          const originalRoles = await roles(sourceAdmin);
          expect(
            candidateRecoveryFingerprint(originalRoles, Object.keys(originalRoles).length),
          ).toEqual(comparison.security.roles);
          await retainCandidateRecoveryOriginal(input.backupDirectory, {
            version: 1,
            kind: 'OPENPC-CANDIDATE-RECOVERY-ORIGINAL-1',
            provenance: expected,
            epoch: {
              ...epoch,
              observedAt: new Date(epoch.observedAt).toISOString(),
              connectionLimit,
            },
            comparison,
          });
          await command(input.source, [
            'sh',
            '-ceu',
            'umask 077; set -C; exec pg_dump -Fc --lock-wait-timeout=5s --snapshot "$2" -U openpc_candidate_index -d openpc_candidate_index > "$1"',
            'candidate-recovery',
            inside,
            epoch.exportedSnapshot,
          ]);
          await exclusive();
          // Sequences are not MVCC. Admission is quiescent, and these live checks
          // reject intervening sequence/global-role/related-owner changes. There
          // is no claimed atomic snapshot across Candidate, Control and the vault.
          expect(candidateRecoveryData(await candidateDatabaseSnapshot(source, snapshot))).toEqual(
            comparison.data,
          );
          expect(await roles(sourceAdmin)).toEqual(originalRoles);
          expect(await related(options)).toEqual({
            control: comparison.control,
            vault: comparison.vault,
          });
          await retainRecoveryArchive(
            input.source.containerId,
            inside,
            join(input.backupDirectory, 'candidate-database-recovery.dump'),
          );
          await sealCandidateRecoveryBinding(input.backupDirectory, expected);
        },
        rollbackSnapshot: async () => {
          if (snapshot) await snapshot.query('rollback');
        },
        releaseSnapshot: () => {
          snapshot?.release(true);
        },
        endSourcePool: async () => {
          await source?.end();
        },
        // Attempt and read back the permanent fence independently of every
        // previous failure. No artifact is removed and target admission requires
        // the entire source phase to return successfully.
        fenceSource: () => sourceAdmin.query(`alter database ${database} allow_connections false`),
        verifySourceFence: assertSourceFenced,
      });
      return restoreBound(options, expected);
    },
  };
}

export async function candidateScope<T>(
  pool: Pool,
  participantId: string,
  privacyDomainId: string,
  action: (client: PoolClient) => Promise<T>,
  readOnly = true,
) {
  const client = await pool.connect();
  let failure: unknown;
  let result: T | undefined;
  try {
    await client.query(readOnly ? 'begin read only' : 'begin');
    await client.query(
      "select openpc.set_request_context('PARTICIPANT',$1,$2,uuidv7(),'ACT-EVIDENCE_EXPORT_RECORDS-V1',true)",
      [participantId, privacyDomainId],
    );
    result = await action(client);
  } catch (error) {
    failure = error;
  } finally {
    try {
      await client.query('rollback');
    } catch (error) {
      failure ??= error;
    } finally {
      client.release();
    }
  }
  if (failure) throw failure;
  return result as T;
}
