import { createHash } from 'node:crypto';
import { execFile } from 'node:child_process';
import { lstat, readFile, readdir, realpath } from 'node:fs/promises';
import { join } from 'node:path';
import { Pool, type PoolClient } from 'pg';
import { z } from 'zod';
import { expect } from 'vitest';
import { recoveryCommand, recoveryDirectory } from './control-database-recovery-fixture.js';
import {
  privateRecoveryInput,
  recoveryDatabasePassword,
  recoveryPool,
  candidateVaultInventory,
} from './candidate-database-recovery-fixture.js';
import {
  observeRecovery,
  readRecoverySecurity,
  recoveryQuote as quote,
  finishRecoverySourcePhase,
  recoveryHash,
} from './postgres-component-recovery.js';
import { candidateRecoveryFingerprint } from './candidate-recovery-binding.js';
import {
  assertFactRecoveryComparison,
  factRecoveryImage,
  factRecoveryTargetPort,
  requireDistinctFactClusters,
  factRecoveryData,
  factRecoverySecurity,
  readFactRecoveryBinding,
  requireUnusedFactRecoveryBinding,
  retainFactRecoveryOriginal,
  captureFactRecoveryArchive,
  sealFactRecoveryBinding,
  withFactRecoveryArchive,
  factRecoveryArchiveLimit,
  type FactDatabaseRecoveryCase,
  type FactRecoveryComparison,
  type FactRecoveryProvenance,
} from './fact-recovery-binding.js';

const database = 'openpc_facts';
const owner = 'openpc_facts';
type Cluster = FactDatabaseRecoveryCase['source'];
type Role = keyof Cluster['passwords'];
export { privateRecoveryInput, recoveryDatabasePassword, recoveryPool };
export async function currentFactMigrations() {
  const directory = new URL('../../../migrations/postgres/facts/', import.meta.url);
  const names = (await readdir(directory))
    .filter((name) => /^[0-9]{4}_[a-z0-9_]+\.sql$/u.test(name))
    .sort();
  expect(names.length).toBeGreaterThanOrEqual(18);
  const files = [
    [
      '/migrations/postgres/common-primitives.sql',
      new URL('../../../migrations/postgres/common-primitives.sql', import.meta.url),
    ] as const,
    ...names.map(
      (name) => ['/migrations/postgres/facts/' + name, new URL(name, directory)] as const,
    ),
  ];
  return Promise.all(
    files.map(async ([path, url]) => ({ path, sha256: recoveryHash(await readFile(url)) })),
  );
}
export async function assertFactMigrationJournals(pool: Pool | PoolClient) {
  expect(
    (await pool.query('select path,sha256 from openpc_local.migration order by path')).rows,
  ).toEqual(await currentFactMigrations());
}
export async function factDatabaseSnapshot(pool: Pool, borrowed?: PoolClient) {
  return observeRecovery(pool, borrowed, async (client) => {
    if (!borrowed) await client.query('begin isolation level repeatable read read only');
    const tables = (
      await client.query<{ schema: string; name: string }>(
        `select n.nspname schema,c.relname name from pg_class c join pg_namespace n on n.oid=c.relnamespace
       where n.nspname in ('facts','openpc_local') and c.relkind in ('r','p')
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
       where n.nspname='facts' and c.relkind='S' order by n.nspname,c.relname`,
      )
    ).rows;
    for (const sequence of sequences)
      rows[`sequence.${sequence.name}`] = (
        await client.query<{ fingerprint: string }>(
          `select encode(sha256(convert_to(to_jsonb(s)::text,'UTF8')),'hex') fingerprint
       from (select last_value,is_called from ${quote(sequence.schema)}.${quote(sequence.name)}) s`,
        )
      ).rows.map((row) => row.fingerprint);
    expect(Object.keys(rows)).toContain('openpc_local.migration');
    expect(Object.keys(rows)).toContain('facts.store_retirement_attempt');
    return rows;
  });
}

export async function factRecoveryRoles(pool: Pool | PoolClient) {
  const attributes = (
    await pool.query(`select rolname,rolsuper,rolinherit,rolcreaterole,rolcreatedb,rolcanlogin,rolreplication,
 rolbypassrls,rolconnlimit,rolvaliduntil::text,rolconfig from pg_roles where rolname !~ '^pg_' order by rolname`)
  ).rows;
  const memberships = (
    await pool.query(`select pg_get_userbyid(roleid) role,pg_get_userbyid(member) member,pg_get_userbyid(grantor) grantor,
 admin_option,inherit_option,set_option from pg_auth_members order by role,member,grantor`)
  ).rows;
  for (const name of [
    'openpc_facts_lifecycle_owner',
    'openpc_facts_capability_owner',
    'openpc_fact_bridge_writer',
    'openpc_candidate_index_reader',
    'openpc_policy_fact_reader',
    'openpc_fact_runtime',
    'openpc_policy_fact_runtime',
  ]) {
    const runtime = ['openpc_fact_runtime', 'openpc_policy_fact_runtime'].includes(name);
    expect(
      attributes.find((row) => row.rolname === name),
      'Fact roles-only provisioning required',
    ).toMatchObject({
      rolsuper: false,
      rolinherit: runtime,
      rolcreaterole: false,
      rolcreatedb: false,
      rolcanlogin: runtime,
      rolreplication: false,
      rolbypassrls: false,
    });
  }
  for (const [runtime, granted] of [
    ['openpc_fact_runtime', 'openpc_fact_bridge_writer'],
    ['openpc_policy_fact_runtime', 'openpc_policy_fact_reader'],
  ]) {
    expect(
      (
        await pool.query(
          `select pg_has_role($1,$2,'MEMBER') allowed,
   pg_has_role($1,'openpc_facts_lifecycle_owner','MEMBER') lifecycle,pg_has_role($1,'openpc_facts_capability_owner','MEMBER') capability`,
          [runtime, granted],
        )
      ).rows,
    ).toEqual([{ allowed: true, lifecycle: false, capability: false }]);
  }
  return { attributes, memberships };
}
export async function factDatabaseSecurity(pool: Pool, borrowed?: PoolClient) {
  return observeRecovery(pool, borrowed, async (client) => {
    if (!borrowed) await client.query('begin');
    const security = await readRecoverySecurity(client, 'facts', await factRecoveryRoles(client));
    const capability = new Set([
      'mutation_capability_secret',
      'mutation_capability_replay',
      'retirement_capability_replay',
      'admission_delivery_capability',
    ]);
    const lifecycle = new Set([
      'retained_fact_identity',
      'signed_fact_custody',
      'store_retirement_attempt',
      'retired_fact_payload',
      'store_retirement_outbox',
      'admission_delivery_head',
      'admission_delivery_event',
      'control_admission_custody_ack',
      'fleet_admission_ack',
    ]);
    for (const row of security.relations.filter(
      (row) => row.schema === 'facts' && ['r', 'p'].includes(row.relkind),
    )) {
      expect(row.owner).toBe(
        capability.has(row.name)
          ? 'openpc_facts_capability_owner'
          : lifecycle.has(row.name)
            ? 'openpc_facts_lifecycle_owner'
            : owner,
      );
      // Retirement nonce custody is intentionally owner-only without RLS in 0011.
      if (row.name !== 'retirement_capability_replay')
        expect(row).toMatchObject({ rls: true, forced: true });
      expect((row.grants ?? []).some((grant: unknown[]) => grant[1] === 'PUBLIC')).toBe(false);
    }
    const indexes = (
      await client.query(`select n.nspname schema,c.relname relation,i.relname name,x.indisunique,x.indisprimary,x.indisvalid,x.indisready,
   pg_get_indexdef(x.indexrelid) definition from pg_index x join pg_class c on c.oid=x.indrelid join pg_class i on i.oid=x.indexrelid
   join pg_namespace n on n.oid=c.relnamespace where n.nspname in ('facts','openpc','openpc_local') order by schema,relation,name`)
    ).rows;
    expect(indexes.every((row) => row.indisvalid && row.indisready)).toBe(true);
    const extensions = (
      await client.query(`select e.extname,e.extversion,n.nspname schema,pg_get_userbyid(e.extowner) owner from pg_extension e
   join pg_namespace n on n.oid=e.extnamespace order by e.extname`)
    ).rows;
    for (const name of ['btree_gist', 'pgcrypto'])
      expect(extensions.some((row) => row.extname === name)).toBe(true);
    return { ...security, indexes, extensions };
  });
}
export async function factControlSnapshot(pool: Pool, participantId: string) {
  const rows: Record<string, string[]> = {};
  for (const table of [
    'evidence_fact_provenance',
    'evidence_fact_admission_inbox',
    'evidence_fact_admission_cursor',
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
    'configuration_work',
    'idempotency_record',
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
/** Child errors never expose command arguments, credentials or database output. */
export async function factRecoveryProcess(
  container: string,
  args: string[],
  input?: Buffer,
): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const child = execFile(
      'docker',
      ['exec', ...(input ? ['-i'] : []), container, ...args],
      { timeout: 60000, maxBuffer: factRecoveryArchiveLimit + 1, encoding: 'buffer' },
      (error, stdout, stderr) => {
        stderr.fill(0);
        if (error) {
          stdout.fill(0);
          reject(new Error('UNKNOWN: Fact recovery database transport failed'));
        } else resolve(stdout);
      },
    );
    child.stdin?.on('error', () =>
      reject(new Error('UNKNOWN: Fact recovery input transport failed')),
    );
    child.stdin?.end(input);
  });
}
const finishFactRecoverySourcePhase = (actions: Parameters<typeof finishRecoverySourcePhase>[0]) =>
  finishRecoverySourcePhase(
    actions,
    (primary, steps) =>
      new Error(
        'UNKNOWN: Fact source preparation, cleanup or permanent fence failed: ' + steps.join(','),
        { cause: primary },
      ),
  );
export async function factDatabaseRecoveryFixture(
  input: FactDatabaseRecoveryCase,
  root: string,
  retained = false,
) {
  requireDistinctFactClusters(input);
  expect(await realpath(root)).toBe(root);
  expect(input.backupDirectory).toBe(join(root, 'data/fact-database-recovery'));
  expect(input.source.dataDirectory).toBe(join(root, 'data/fact-pg'));
  expect(input.target.dataDirectory).toBe(join(input.backupDirectory, 'postgres'));
  expect(input.nativeExecutable).toBe(join(input.backupDirectory, 'fact_retirement_owner'));
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
    expect(info.Config.Image).toBe(factRecoveryImage);
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
        'com.docker.compose.service': 'fact-pg',
      });
    else
      expect(info.Config.Labels).toMatchObject({
        'io.openpc.test-owner': root,
        'io.openpc.recovery-role': 'fact-target',
      });
    const port =
      !source && retained ? factRecoveryTargetPort(input, root, info.Image, info) : value.port;
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
  const sourceAdmin = await connect(input.source, 'openpc_facts', 'postgres');
  const targetAdmin = await connect(input.target, 'openpc_facts', 'postgres');
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
  type Related = {
    control: Pool;
    vaultDirectory: string;
    inputFingerprints: () => Promise<FactRecoveryComparison['inputs']>;
  };
  const related = async ({ control, vaultDirectory, inputFingerprints }: Related) => ({
    control: factRecoveryData(await factControlSnapshot(control, input.participantId), 'control.'),
    vault: await candidateVaultInventory(root, vaultDirectory),
    inputs: await inputFingerprints(),
  });
  const provenance = async (): Promise<FactRecoveryProvenance> => {
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
        current_user: 'openpc_facts',
        session_user: 'openpc_facts',
        rolsuper: true,
        version: 180006,
      });
  };
  const emptyTarget = async () => {
    const pool = await connect(input.target, 'openpc_facts');
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
  ): Promise<FactRecoveryComparison> => {
    const security = await factDatabaseSecurity(pool, client);
    expect(security.databases).toHaveLength(1);
    expect(security.databases[0].datconnlimit).toBe(0);
    security.databases[0].datconnlimit = connectionLimit;
    return {
      data: factRecoveryData(await factDatabaseSnapshot(pool, client)),
      security: factRecoverySecurity(security),
      ...(await related(options)),
    };
  };
  const restoreBound = async (options: Related, expected: FactRecoveryProvenance) => {
    const bound = await readFactRecoveryBinding(input.backupDirectory, expected);
    await assertSourceFenced();
    await zeroSessions(targetAdmin, database);
    await targetAdmin.query(`alter database ${database} connection limit 0`);
    await zeroSessions(targetAdmin, database);
    if (await emptyTarget()) {
      await withFactRecoveryArchive(input.backupDirectory, expected, async (bytes) => {
        const output = await factRecoveryProcess(
          input.target.containerId,
          [
            'pg_restore',
            '--exit-on-error',
            '--single-transaction',
            '-U',
            'openpc_facts',
            '-d',
            database,
          ],
          bytes,
        );
        output.fill(0);
      });
    }

    const target = await connect(input.target, 'openpc_facts');
    try {
      await assertFactMigrationJournals(target);
      assertFactRecoveryComparison(
        bound.original.comparison,
        await capture(target, options, bound.original.epoch.connectionLimit),
      );
    } finally {
      await target.end();
    }
    // Recheck original artifacts and provenance before admitting target writers.
    await readFactRecoveryBinding(input.backupDirectory, await provenance());
    await assertSourceFenced();
    await targetAdmin.query(
      `alter database ${database} connection limit ${bound.original.epoch.connectionLimit}`,
    );
    return bound;
  };
  let used = false;
  return {
    targetPort: targetEndpoint.port,
    source: (role: Role = 'openpc_facts') => connect(input.source, role),
    target: (role: Role = 'openpc_facts') => connect(input.target, role),
    async close() {
      await Promise.all([sourceAdmin.end(), targetAdmin.end()]);
    },
    assertSourceFenced,
    async restoreRetained(options: Related) {
      if (used) throw new Error('UNKNOWN: Fact recovery invocation already used');
      used = true;
      await administrators();
      const expected = await provenance();
      // No source DB connection, redump, fresh expected snapshot or metadata
      // regeneration is allowed on this path, including for historical backups.
      await readFactRecoveryBinding(input.backupDirectory, expected);
      await finishFactRecoverySourcePhase({
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
      await requireUnusedFactRecoveryBinding(input.backupDirectory);
      await administrators();
      const expected = await provenance();
      expect(await factRecoveryRoles(targetAdmin)).toEqual(await factRecoveryRoles(sourceAdmin));
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
            "select datname from pg_database where datname not in ('postgres','template0','template1','openpc_facts')",
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
      let source: Pool | undefined;
      let snapshot: PoolClient | undefined;
      await finishFactRecoverySourcePhase({
        prepare: async () => {
          await sourceAdmin.query(`alter database ${database} connection limit 0`);
          await targetAdmin.query(`alter database ${database} connection limit 0`);
          await zeroSessions(sourceAdmin, database);
          source = await connect(input.source, 'openpc_facts');
          snapshot = await source.connect();
          await snapshot.query('begin isolation level repeatable read');
          const tables = (
            await snapshot.query<{ schema: string; name: string }>(
              `select n.nspname schema,c.relname name from pg_class c join pg_namespace n on n.oid=c.relnamespace
           where n.nspname in ('facts','openpc_local') and c.relkind in ('r','p') order by n.nspname,c.relname`,
            )
          ).rows;
          for (const table of tables)
            await snapshot.query(
              `lock table ${quote(table.schema)}.${quote(table.name)} in share mode`,
            );
          const epoch = (
            await snapshot.query(
              `select pg_export_snapshot() "exportedSnapshot",pg_current_snapshot()::text snapshot,
           pg_backend_pid() "backendPid",clock_timestamp() "observedAt",
           (select timeline_id from pg_control_checkpoint()) "timelineId",pg_current_wal_lsn()::text "walLsn"`,
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
          await assertFactMigrationJournals(snapshot);
          const comparison = await capture(source, options, connectionLimit, snapshot);
          const originalRoles = await factRecoveryRoles(sourceAdmin);
          expect(
            candidateRecoveryFingerprint(originalRoles, Object.keys(originalRoles).length),
          ).toEqual(comparison.security.roles);
          await retainFactRecoveryOriginal(input.backupDirectory, {
            version: 1,
            kind: 'OPENPC-FACT-RECOVERY-ORIGINAL-1',
            provenance: expected,
            epoch: {
              ...epoch,
              observedAt: new Date(epoch.observedAt).toISOString(),
              connectionLimit,
            },
            comparison,
          });
          await captureFactRecoveryArchive(input.backupDirectory, expected, () =>
            factRecoveryProcess(input.source.containerId, [
              'pg_dump',
              '-Fc',
              '--lock-wait-timeout=5s',
              '--snapshot',
              epoch.exportedSnapshot,
              '-U',
              'openpc_facts',
              '-d',
              database,
            ]),
          );
          await exclusive();
          // Sequences are not MVCC. Admission is quiescent, and these live checks
          // reject intervening sequence/global-role/related-owner changes. There
          // is no claimed atomic snapshot across Fact, Control and the vault.
          expect(factRecoveryData(await factDatabaseSnapshot(source, snapshot))).toEqual(
            comparison.data,
          );
          expect(await factRecoveryRoles(sourceAdmin)).toEqual(originalRoles);
          expect(await related(options)).toEqual({
            control: comparison.control,
            vault: comparison.vault,
            inputs: comparison.inputs,
          });
          await sealFactRecoveryBinding(input.backupDirectory, expected);
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
