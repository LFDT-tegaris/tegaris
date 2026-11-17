import { readFile, stat } from 'node:fs/promises';
import { isAbsolute } from 'node:path';
import { Pool, type PoolClient } from 'pg';
import { expect, it } from 'vitest';
import { z } from 'zod';
import { localOperationId } from '../../../services/identity-service/src/domain/local-operation-id.js';
import { parseStrictJsonBytes } from '../../../services/control-api/src/privacy-explorer/strict-json.js';
import {
  parseProviderRetryProbeReference,
  readProviderRetryProbeOriginal,
  withCurrentProviderRetryProbeSource,
  type ProviderRetryProbeReference,
  type ProviderRetryProbeScope,
} from '../../../services/control-api/src/configuration/operations/provider-retry-probe-source.js';

const adminUrl = process.env.OPENPC_I02_ADMIN_DATABASE_URL;
const fixturePath = process.env.OPENPC_PROVIDER_RETRY_PROBE_FIXTURE;
const integration = adminUrl ? it : it.skip;
const scopeSchema = z.strictObject({
  participantId: z.uuidv7(),
  privacyDomainId: z.uuidv7(),
  requestId: z.uuidv7(),
});
const caseSchema = z.strictObject({
  scope: scopeSchema,
  reference: z.unknown().transform(parseProviderRetryProbeReference),
});
const fixtureSchema = z.strictObject({
  current: caseSchema,
  expired: caseSchema,
  failed: caseSchema,
  quarantined: caseSchema,
  replaced: caseSchema,
  expiring: caseSchema,
  providerRequestLog: z.string().refine(isAbsolute),
});
type Case = z.infer<typeof caseSchema>;
async function inputs() {
  if (!fixturePath)
    throw new Error('BLOCKED: actual public provider/probe/qualification originals are required');
  if ((await stat(fixturePath)).size > 65536) throw new Error('PROBE_SOURCE_FIXTURE_INVALID');
  return fixtureSchema.parse(
    parseStrictJsonBytes(await readFile(fixturePath), { maximumDepth: 12 }),
  );
}
async function requestCount(path: string) {
  if ((await stat(path)).size > 64 * 1024 * 1024) throw new Error('PROBE_SOURCE_REQUEST_LOG_BOUND');
  return (await readFile(path, 'utf8')).split('\n').filter((line) => line.trim()).length;
}
// Parser-only negative controls never allocate a database or synthesize source
// success. All integration originals below MUST come from the public workflow.
it('rejects incomplete, mixed-format and caller-eligibility probe source references before PostgreSQL', () => {
  const reference = {
    providerProfileId: localOperationId(),
    observationId: localOperationId(),
    qualificationWorkId: localOperationId(),
    operationId: localOperationId(),
    resultEventId: localOperationId(),
    artifactDigest: `sha256:${'1'.repeat(64)}`,
    configurationDigest: `sha256:${'2'.repeat(64)}`,
    observationDigest: `sha256:${'3'.repeat(64)}`,
    resultReceiptDigest: `sha256:${'4'.repeat(64)}`,
    authorizationEvidenceDigest: `sha256:${'5'.repeat(64)}`,
  };
  for (const bad of [
    null,
    {},
    { ...reference, ready: true },
    { ...reference, observationId: '' },
    { ...reference, resultReceiptDigest: null },
    { ...reference, artifactDigest: 'sha256:abc' },
  ]) {
    expect(() => parseProviderRetryProbeReference(bad)).toThrow();
  }
  expect(() => fixtureSchema.parse({ current: { scope: {}, reference } })).toThrow();
});
async function scoped<T>(
  pool: Pool,
  scope: ProviderRetryProbeScope,
  consume: (client: PoolClient) => Promise<T>,
  role = 'openpc_control_owner',
): Promise<T> {
  if (
    ![
      'openpc_control_owner',
      'openpc_control_runtime',
      'openpc_operations_qualification_owner',
    ].includes(role)
  )
    throw new Error('PROBE_TEST_ROLE');
  const client = await pool.connect();
  let value!: T, primary: unknown;
  let failed = false;
  try {
    await client.query('begin isolation level read committed');
    await client.query(`set local role ${role}`);
    await client.query('set local row_security=on');
    await client.query(
      "select openpc.set_request_context('PARTICIPANT',$1,$2,$3,'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1',true)",
      [scope.participantId, scope.privacyDomainId, scope.requestId],
    );
    value = await consume(client);
  } catch (error) {
    primary = error;
    failed = true;
  }
  const cleanup = (error: unknown) => {
    process.stderr.write('OPS_PROVIDER_PROBE_SOURCE_TEST_CLEANUP|UNKNOWN\n');
    if (!failed) primary = error;
    failed = true;
  };
  await client.query('rollback').catch(cleanup);
  try {
    client.release();
  } catch (error) {
    cleanup(error);
  }
  if (failed) throw primary;
  return value;
}
async function original(pool: Pool, input: Case) {
  return scoped(pool, input.scope, (client) =>
    readProviderRetryProbeOriginal(client, input.scope, input.reference),
  );
}
async function preflight(pool: Pool) {
  const result = await pool.query<{
    present: boolean;
  }>(`select to_regprocedure(name) is not null present from unnest(array[
    'openpc.read_provider_retry_probe_source(jsonb)','openpc.lock_provider_retry_probe_source(jsonb)']) name`);
  expect(result.rows).toEqual([{ present: true }, { present: true }]);
}
integration('denies probe read-action writes under composed installed policies', async () => {
  const pool = new Pool({ connectionString: adminUrl, max: 1 });
  const scope = {
    participantId: localOperationId(),
    privacyDomainId: localOperationId(),
    requestId: localOperationId(),
  };
  try {
    await preflight(pool);
    // Initial scope trust only; no provider, work result or qualification is seeded.
    await pool.query(
      "insert into control.participant(participant_id,display_name,state,authority_epoch) values($1,'Probe read-only scope','ACTIVE',1)",
      [scope.participantId],
    );
    await pool.query(
      "insert into control.privacy_domain(privacy_domain_id,participant_id,domain_name,placement_profile,residency_profile,state) values($1,$2,'Probe read-only scope','PARTICIPANT_LOCAL','LOCAL','ACTIVE')",
      [scope.privacyDomainId, scope.participantId],
    );
    for (const [table, column] of [
      ['participant', 'display_name'],
      ['privacy_domain', 'domain_name'],
    ] as const) {
      const before = await pool.query(
        `select to_jsonb(r) original from control.${table} r where participant_id=$1`,
        [scope.participantId],
      );
      await scoped(pool, scope, async (client) => {
        expect(
          (
            await client.query(`select 1 from control.${table} where participant_id=$1 for share`, [
              scope.participantId,
            ])
          ).rowCount,
        ).toBe(1);
      });
      await expect(
        scoped(pool, scope, (client) =>
          client.query(
            `update control.${table} set ${column}='forbidden read mutation' where participant_id=$1`,
            [scope.participantId],
          ),
        ),
      ).rejects.toMatchObject({ code: '42501' });
      expect(
        (
          await pool.query(
            `select to_jsonb(r) original from control.${table} r where participant_id=$1`,
            [scope.participantId],
          )
        ).rows,
      ).toEqual(before.rows);
    }
  } finally {
    await pool.end();
  }
});

async function assertReadActionCannotUpdateSources(pool: Pool, scope: ProviderRetryProbeScope) {
  for (const [table, column] of [
    ['participant', 'display_name'],
    ['privacy_domain', 'domain_name'],
    ['provider_profile', 'state'],
    ['provider_probe_observation', 'state'],
    ['configuration_work', 'state'],
    ['runtime_configuration_input', 'selected'],
    ['module_installation', 'state'],
    ['module_configuration_generation', 'active'],
  ] as const) {
    const select = `select to_jsonb(r) original from control.${table} r where participant_id=$1 order by to_jsonb(r)::text`;
    const before = (await pool.query(select, [scope.participantId])).rows;
    expect(before.length, table).toBeGreaterThan(0);
    await expect(
      scoped(pool, scope, (client) =>
        client.query(`update control.${table} set ${column}=${column} where participant_id=$1`, [
          scope.participantId,
        ]),
      ),
    ).rejects.toThrow();
    expect((await pool.query(select, [scope.participantId])).rows).toEqual(before);
  }
}
async function assertDenialCause(
  pool: Pool,
  name: 'expired' | 'failed' | 'quarantined' | 'replaced',
  input: Case,
) {
  const result = await scoped(pool, input.scope, (client) =>
    client.query<{
      state: string;
      qualification_observation_id: string | null;
      behavior_fingerprint: string;
      revision: string;
      observed_revision: string;
      expired: boolean;
    }>(
      `select p.state,p.qualification_observation_id,p.behavior_fingerprint,p.revision::text,
    o.observed_revision::text,o.valid_until<=clock_timestamp() expired
    from control.provider_profile p join control.provider_probe_observation o
      on o.provider_profile_id=p.provider_profile_id and o.participant_id=p.participant_id and o.privacy_domain_id=p.privacy_domain_id
    where p.provider_profile_id=$1 and o.observation_id=$2`,
      [input.reference.providerProfileId, input.reference.observationId],
    ),
  );
  expect(result.rowCount).toBe(1);
  const row = result.rows[0]!;
  if (name === 'expired') {
    expect(['QUALIFIED', 'ACTIVE']).toContain(row.state);
    expect(row.qualification_observation_id).toBe(input.reference.observationId);
    expect(BigInt(row.revision)).toBe(BigInt(row.observed_revision) + 2n);
    expect(row.expired).toBe(true);
  } else if (name === 'failed') {
    expect(row.state).toBe('QUARANTINED');
  } else {
    // A stale clock cannot masquerade as the intended quarantine/replacement denial.
    expect(row.expired).toBe(false);
    if (name === 'quarantined') expect(row.state).toBe('QUARANTINED');
    else
      expect(
        row.qualification_observation_id !== input.reference.observationId ||
          row.behavior_fingerprint !== input.reference.artifactDigest ||
          BigInt(row.revision) !== BigInt(row.observed_revision) + 2n,
      ).toBe(true);
  }
}
integration(
  'reads actual immutable provider originals and consumes only the current source without provider I/O',
  async () => {
    const fixture = await inputs(),
      pool = new Pool({ connectionString: adminUrl, max: 2 });
    try {
      await preflight(pool);
      const beforeRequests = await requestCount(fixture.providerRequestLog);
      const saved = await original(pool, fixture.current);
      expect(saved.workState).toBe('COMPLETED');
      expect(saved.authorizationCoseHex.length).toBeGreaterThan(0);
      await assertReadActionCannotUpdateSources(pool, fixture.current.scope);
      const result = await scoped(pool, fixture.current.scope, (client) =>
        withCurrentProviderRetryProbeSource(
          client,
          fixture.current.scope,
          fixture.current.reference,
          async (same, readback) => {
            expect(same).toBe(client);
            expect(readback).toEqual(saved);
            expect(Object.isFrozen(readback.observation)).toBe(true);
            return readback.reference.qualificationWorkId;
          },
        ),
      );
      expect(result).toBe(saved.reference.qualificationWorkId);
      await scoped(
        pool,
        fixture.current.scope,
        (client) =>
          withCurrentProviderRetryProbeSource(
            client,
            fixture.current.scope,
            fixture.current.reference,
            async (same, readback) => {
              expect(same).toBe(client);
              expect(readback).toEqual(saved);
            },
          ),
        'openpc_operations_qualification_owner',
      );
      const reopened = new Pool({ connectionString: adminUrl, max: 1 });
      try {
        expect(await original(reopened, fixture.current)).toEqual(saved);
      } finally {
        await reopened.end();
      }
      for (const name of ['expired', 'failed', 'quarantined', 'replaced'] as const) {
        const input = fixture[name];
        const retained = await original(pool, input);
        expect(retained.workState).toBe(name === 'failed' ? 'FAILED' : 'COMPLETED');
        await assertDenialCause(pool, name, input);
        let consumed = false;
        await expect(
          scoped(pool, input.scope, (client) =>
            withCurrentProviderRetryProbeSource(client, input.scope, input.reference, async () => {
              consumed = true;
            }),
          ),
        ).rejects.toThrow('OPS_PROVIDER_PROBE_SOURCE_UNAVAILABLE');
        expect(consumed).toBe(false);
        expect(await original(pool, input)).toEqual(retained);
      }
      expect(await requestCount(fixture.providerRequestLog)).toBe(beforeRequests);
    } finally {
      await pool.end();
    }
  },
  30000,
);
integration(
  'rejects mixed originals, foreign context, release and transaction loss while preserving real evidence',
  async () => {
    const fixture = await inputs(),
      input = fixture.current,
      pool = new Pool({ connectionString: adminUrl, max: 2 });
    try {
      await preflight(pool);
      const saved = await original(pool, input);
      const beforeRequests = await requestCount(fixture.providerRequestLog);
      for (const key of [
        'providerProfileId',
        'observationId',
        'qualificationWorkId',
        'operationId',
        'resultEventId',
      ] as const) {
        const mixed: ProviderRetryProbeReference = {
          ...input.reference,
          [key]: localOperationId(),
        };
        await expect(
          scoped(pool, input.scope, (client) =>
            readProviderRetryProbeOriginal(client, input.scope, mixed),
          ),
        ).rejects.toThrow();
      }
      for (const key of [
        'artifactDigest',
        'configurationDigest',
        'observationDigest',
        'resultReceiptDigest',
        'authorizationEvidenceDigest',
      ] as const) {
        const changed = input.reference[key].endsWith('0') ? '1' : '0';
        const mixed = { ...input.reference, [key]: input.reference[key].slice(0, -1) + changed };
        await expect(
          scoped(pool, input.scope, (client) =>
            readProviderRetryProbeOriginal(client, input.scope, mixed),
          ),
        ).rejects.toThrow();
      }
      const foreign = { ...input.scope, privacyDomainId: localOperationId() };
      await expect(
        scoped(pool, foreign, (client) =>
          readProviderRetryProbeOriginal(client, foreign, input.reference),
        ),
      ).rejects.toThrow();
      await expect(
        scoped(pool, input.scope, (client) =>
          readProviderRetryProbeOriginal(
            client,
            { ...input.scope, requestId: localOperationId() },
            input.reference,
          ),
        ),
      ).rejects.toThrow('CONTEXT');
      await expect(
        scoped(pool, input.scope, async (client) => {
          await client.query(
            "select openpc.set_request_context('PARTICIPANT',$1,$2,$3,'ACT-PROVIDER_PROFILES_READ_RESOURCE-V1',true)",
            [input.scope.participantId, input.scope.privacyDomainId, input.scope.requestId],
          );
          return readProviderRetryProbeOriginal(client, input.scope, input.reference);
        }),
      ).rejects.toThrow('CONTEXT');
      await expect(
        scoped(pool, input.scope, async (client) => {
          await client.query('rollback');
          await client.query('begin isolation level serializable');
          await client.query('set local role openpc_control_owner');
          await client.query(
            "select openpc.set_request_context('PARTICIPANT',$1,$2,$3,'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1',true)",
            [input.scope.participantId, input.scope.privacyDomainId, input.scope.requestId],
          );
          return readProviderRetryProbeOriginal(client, input.scope, input.reference);
        }),
      ).rejects.toThrow('CONTEXT');
      await expect(
        scoped(
          pool,
          input.scope,
          (client) => readProviderRetryProbeOriginal(client, input.scope, input.reference),
          'openpc_control_runtime',
        ),
      ).rejects.toThrow();
      await expect(
        scoped(pool, input.scope, (client) =>
          withCurrentProviderRetryProbeSource(
            client,
            input.scope,
            input.reference,
            async (same) => {
              same.release();
            },
          ),
        ),
      ).rejects.toThrow('CHANGED');
      await expect(
        scoped(pool, input.scope, (client) =>
          withCurrentProviderRetryProbeSource(
            client,
            input.scope,
            input.reference,
            async (same) => {
              await same.query('rollback');
              await same.query('begin isolation level read committed');
              await same.query('set local role openpc_control_owner');
              await same.query('set local row_security=on');
              await same.query(
                "select openpc.set_request_context('PARTICIPANT',$1,$2,$3,'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1',true)",
                [input.scope.participantId, input.scope.privacyDomainId, input.scope.requestId],
              );
            },
          ),
        ),
      ).rejects.toThrow('CHANGED');
      expect(await original(pool, input)).toEqual(saved);
      expect(await requestCount(fixture.providerRequestLog)).toBe(beforeRequests);
    } finally {
      await pool.end();
    }
  },
  30000,
);
integration(
  'holds the real provider source fence and fails closed on competing source ownership',
  async () => {
    const fixture = await inputs(),
      input = fixture.current,
      pool = new Pool({ connectionString: adminUrl, max: 2 });
    try {
      await preflight(pool);
      const saved = await original(pool, input);
      await scoped(pool, input.scope, (held) =>
        withCurrentProviderRetryProbeSource(held, input.scope, input.reference, async () => {
          const selected = await held.query<{
            runtime_configuration_input_id: string;
            module_installation_id: string;
            module_configuration_generation_id: string;
          }>(
            "select runtime_configuration_input_id,module_installation_id,module_configuration_generation_id from control.runtime_configuration_input_current where 'sha256:'||encode(configuration_digest,'hex')=$1",
            [input.reference.configurationDigest],
          );
          expect(selected.rowCount).toBe(1);
          const source = selected.rows[0]!;
          for (const [table, key, id] of [
            ['participant', 'participant_id', input.scope.participantId],
            ['privacy_domain', 'privacy_domain_id', input.scope.privacyDomainId],
            ['provider_profile', 'provider_profile_id', input.reference.providerProfileId],
            ['provider_probe_observation', 'observation_id', input.reference.observationId],
            ['configuration_work', 'configuration_work_id', input.reference.qualificationWorkId],
            [
              'runtime_configuration_input',
              'runtime_configuration_input_id',
              source.runtime_configuration_input_id,
            ],
            ['module_installation', 'module_installation_id', source.module_installation_id],
            [
              'module_configuration_generation',
              'generation_id',
              source.module_configuration_generation_id,
            ],
          ] as const) {
            await expect(
              scoped(pool, { ...input.scope, requestId: localOperationId() }, (other) =>
                other.query(`select 1 from control.${table} where ${key}=$1 for update nowait`, [
                  id,
                ]),
              ),
            ).rejects.toMatchObject({ code: '55P03' });
          }
          for (const key of [
            `module-admission:${input.scope.participantId}:${input.scope.privacyDomainId}`,
            `openpc-policy-generations:${input.scope.participantId}:${input.scope.privacyDomainId}`,
            `evidence-lifecycle:${input.scope.participantId}`,
          ]) {
            const result = await scoped(
              pool,
              { ...input.scope, requestId: localOperationId() },
              (other) =>
                other.query<{ acquired: boolean }>(
                  'select pg_try_advisory_xact_lock(hashtextextended($1,0)) acquired',
                  [key],
                ),
            );
            expect(result.rows).toEqual([{ acquired: false }]);
          }
        }),
      );
      await scoped(pool, input.scope, async (held) => {
        await held.query(
          'select 1 from control.provider_profile where provider_profile_id=$1 for update',
          [input.reference.providerProfileId],
        );
        const contenderScope = { ...input.scope, requestId: localOperationId() };
        await expect(
          scoped(pool, contenderScope, (other) =>
            withCurrentProviderRetryProbeSource(
              other,
              contenderScope,
              input.reference,
              async () => {
                throw new Error('UNEXPECTED_CONSUMPTION');
              },
            ),
          ),
        ).rejects.toThrow('PC-DATA-6007');
      });
      expect(await original(pool, input)).toEqual(saved);
    } finally {
      await pool.end();
    }
  },
  30000,
);
integration(
  'rejects original authority expiring during consumption without changing its lifetime or evidence',
  async () => {
    const fixture = await inputs(),
      input = fixture.expiring,
      pool = new Pool({ connectionString: adminUrl, max: 1 });
    try {
      await preflight(pool);
      const saved = await original(pool, input),
        beforeRequests = await requestCount(fixture.providerRequestLog);
      let consumed = false;
      await expect(
        scoped(pool, input.scope, (client) =>
          withCurrentProviderRetryProbeSource(
            client,
            input.scope,
            input.reference,
            async (same, readback) => {
              const result = await same.query<{ remaining_ms: string }>(
                'select $1::numeric-extract(epoch from clock_timestamp())*1000 remaining_ms',
                [readback.validUntilMs],
              );
              const remaining = Number(result.rows[0]?.remaining_ms);
              if (!Number.isFinite(remaining) || remaining < 100 || remaining > 10000)
                throw new Error(
                  'BLOCKED: genuine expiring original must have 0.1–10 seconds remaining at this phase',
                );
              consumed = true;
              await same.query('select pg_sleep($1)', [(remaining + 100) / 1000]);
            },
          ),
        ),
      ).rejects.toThrow('OPS_PROVIDER_PROBE_SOURCE_UNAVAILABLE');
      expect(consumed).toBe(true);
      expect(await original(pool, input)).toEqual(saved);
      expect(await requestCount(fixture.providerRequestLog)).toBe(beforeRequests);
    } finally {
      await pool.end();
    }
  },
  15000,
);
