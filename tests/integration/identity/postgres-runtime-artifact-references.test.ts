import { readFile, stat } from 'node:fs/promises';
import { Pool, type PoolClient } from 'pg';
import { expect, it } from 'vitest';
import { z } from 'zod';
import { runScopedTransaction } from '../../../services/identity-service/src/db/scoped-transaction.js';
import { localOperationId } from '../../../services/identity-service/src/domain/local-operation-id.js';
import {
  readRuntimeArtifactReferences,
  runtimeArtifactReferenceSelector,
  type RuntimeArtifactReferenceSelector,
} from '../../../services/control-api/src/evidence/runtime-artifact-references.js';

/** The existing public journey driver supplies original identifiers only after
 * real configuration publication, activation, qualification and rollback. This
 * test neither seeds those business states nor replays their original effects.
 * Database-context tests cover this internal observation adapter, not public
 * authorization, custody disposition or physical retirement acceptance. */
const fixtureSchema = z.strictObject({
  ...runtimeArtifactReferenceSelector.shape,
  completedWorkId: z.uuidv7(),
  activationObservationId: z.uuidv7(),
  probeObservationId: z.uuidv7(),
  routePublicationId: z.uuidv7(),
  rollbackOccurrenceId: z.uuidv7(),
  rollbackTargetId: z.uuidv7(),
});
const fixtureFile = process.env.OPENPC_RUNTIME_ARTIFACT_REFERENCES_FIXTURE;
const enabled = fixtureFile !== undefined;
function blocked(owner: string): never {
  throw new Error(`BLOCKED runtime artifact observation: ${owner}`);
}
async function fixture() {
  if (!fixtureFile) blocked('original public journey identifier fixture');
  const info = await stat(fixtureFile);
  if (!info.isFile() || info.size > 4096) blocked('bounded identifier fixture');
  return fixtureSchema.parse(JSON.parse(await readFile(fixtureFile, 'utf8')));
}
async function runtime() {
  const url = process.env.OPENPC_I02_RUNTIME_DATABASE_URL;
  if (!url) blocked('existing runtime PostgreSQL URL');
  const pool = new Pool({ connectionString: url, max: 2 });
  try {
    const role = await pool.query<{ allowed: boolean }>(
      "select not rolsuper and not rolbypassrls and pg_has_role(current_user,'openpc_control_runtime','USAGE') allowed from pg_roles where rolname=current_user",
    );
    if (role.rows[0]?.allowed !== true) blocked('non-bypass runtime principal');
    return pool;
  } catch (error) {
    await pool.end();
    throw error;
  }
}
function selection(q: z.infer<typeof fixtureSchema>): RuntimeArtifactReferenceSelector {
  return {
    participantId: q.participantId,
    privacyDomainId: q.privacyDomainId,
    inputId: q.inputId,
    configurationDigest: q.configurationDigest,
  };
}
async function scoped<T>(
  pool: Pool,
  q: RuntimeArtifactReferenceSelector,
  run: (client: PoolClient) => Promise<T>,
) {
  return runScopedTransaction(
    pool,
    {
      participantId: q.participantId,
      privacyDomainId: q.privacyDomainId,
      actionIntentId: 'ACT-EVIDENCE_EXPORT_RECORDS-V1',
    },
    localOperationId,
    run,
  );
}
it('accepts only original identifiers, never caller-provided reference clearance or authority', () => {
  const id = localOperationId();
  const q = {
    participantId: id,
    privacyDomainId: id,
    inputId: id,
    configurationDigest: `sha256:${'a'.repeat(64)}`,
    completedWorkId: id,
    activationObservationId: id,
    probeObservationId: id,
    routePublicationId: id,
    rollbackOccurrenceId: id,
    rollbackTargetId: id,
  };
  expect(fixtureSchema.parse(q)).toEqual(q);
  for (const extra of [
    { authorized: true },
    { clear: true },
    { runtimeProducerFencesObserved: true },
    { disposition: 'RETIRED' },
    { receipt: 'caller-data' },
  ])
    expect(() => fixtureSchema.parse({ ...q, ...extra })).toThrow();
});
it.runIf(process.env.OPENPC_I02_RUNTIME_DATABASE_URL !== undefined)(
  'executes the installed scoped observer with real fences without treating an absent input as clearance',
  async () => {
    const pool = await runtime();
    const q = {
      participantId: localOperationId(),
      privacyDomainId: localOperationId(),
      inputId: localOperationId(),
      configurationDigest: `sha256:${'a'.repeat(64)}`,
    };
    try {
      const installed = await pool.query(
        `select p.prosecdef, r.rolname owner,
         has_function_privilege(current_user,p.oid,'EXECUTE') executable,
         exists(select 1 from aclexplode(p.proacl) a where a.grantee=0 and a.privilege_type='EXECUTE') public_execute
         from pg_proc p join pg_roles r on r.oid=p.proowner
         where p.oid='openpc.observe_runtime_artifact_references(uuid,text)'::regprocedure`,
      );
      expect(installed.rows).toEqual([
        {
          prosecdef: false,
          owner: 'openpc_control_owner',
          executable: true,
          public_execute: false,
        },
      ]);
      await expect(
        scoped(pool, q, (client) =>
          client.query('select openpc.observe_runtime_artifact_references($1,$2)', [
            q.inputId,
            q.configurationDigest,
          ]),
        ),
      ).rejects.toMatchObject({ message: 'RUNTIME-ARTIFACT-OBSERVATION-FENCE' });
      const observed = await scoped(pool, q, (client) => readRuntimeArtifactReferences(client, q));
      expect(observed.root).toBeNull();
      expect(observed.references).toEqual([]);
      expect(observed.runtimeProducerFencesObserved).toBe(true);
      expect(observed.dependencyProducerFencesObserved).toBe(true);
      expect(observed.databaseCoverage).toBe('INCOMPLETE');
      expect(observed.authority).toBe('NONE');
      expect(observed.disposition).toBe('UNPROVEN');
      expect(observed.unresolved).toContain('INPUT_NOT_OBSERVED');
      expect(observed.unresolved).toContain('RUNTIME_CUSTODY_DISPOSITION_UNOBSERVED');
      for (const selector of [
        { ...q, participantId: localOperationId() },
        { ...q, privacyDomainId: localOperationId() },
      ])
        await expect(
          scoped(pool, q, (client) => readRuntimeArtifactReferences(client, selector)),
        ).rejects.toThrow();
    } finally {
      await pool.end();
    }
  },
);
it.runIf(process.env.OPENPC_I02_ADMIN_DATABASE_URL !== undefined)(
  'detects each missing dependency writer fence under the real scoped observer without granting clearance',
  async () => {
    const pool = new Pool({ connectionString: process.env.OPENPC_I02_ADMIN_DATABASE_URL, max: 1 });
    const client = await pool.connect();
    const selector = {
      participantId: localOperationId(),
      privacyDomainId: localOperationId(),
      inputId: localOperationId(),
      configurationDigest: `sha256:${'b'.repeat(64)}`,
    };
    try {
      for (const table of [
        'module_configuration_generation',
        'module_installation',
        'policy_activation',
        'policy_activation_prerequisite',
        'policy_generation',
        'provider_profile',
        'indexer_profile',
        'cigl_settings',
        'projection_plan',
      ]) {
        await client.query('begin');
        try {
          // Isolated transactional corruption only. Observation still runs as
          // the real non-bypass role; rollback preserves installed enforcement.
          await client.query(
            `alter table control.${table} disable trigger artifact_lifecycle_fence`,
          );
          await client.query('set local role openpc_control_runtime');
          await client.query(
            "select openpc.set_request_context('PARTICIPANT',$1,$2,$3,'ACT-EVIDENCE_EXPORT_RECORDS-V1',true)",
            [selector.participantId, selector.privacyDomainId, localOperationId()],
          );
          const result = await readRuntimeArtifactReferences(client, selector);
          expect(result.runtimeProducerFencesObserved).toBe(true);
          expect(result.dependencyProducerFencesObserved, table).toBe(false);
          expect(result.unresolved).toContain('DEPENDENCY_PRODUCER_FENCES_UNVERIFIED');
          expect(result.unresolved).toContain('INPUT_NOT_OBSERVED');
          expect(result.databaseCoverage).toBe('INCOMPLETE');
          expect(result.disposition).toBe('UNPROVEN');
          expect(result.authority).toBe('NONE');
        } finally {
          await client.query('rollback');
        }
      }
    } finally {
      client.release();
      await pool.end();
    }
  },
);
let originalPassed = false;
it.runIf(enabled)(
  'observes original completed activation/probe/route and rollback references after reconnect without replay',
  async () => {
    const q = await fixture(),
      select = selection(q);
    const read = async () => {
      const pool = await runtime();
      try {
        return await scoped(pool, select, (client) =>
          readRuntimeArtifactReferences(client, select),
        );
      } finally {
        await pool.end();
      }
    };
    const first = await read();
    expect(first.root?.id).toBe(q.inputId);
    expect(first.root?.state).toBe('RETAINED');
    expect(first.databaseCoverage).toBe('OBSERVED');
    expect(first.runtimeProducerFencesObserved).toBe(true);
    for (const [kind, id, state] of [
      ['WORK', q.completedWorkId, 'COMPLETED'],
      ['ACTIVATION_OBSERVATION', q.activationObservationId, 'RETAINED'],
      ['PROBE', q.probeObservationId, 'OBSERVED'],
      ['ROUTE_PUBLICATION', q.routePublicationId, 'RETAINED'],
    ])
      expect(first.references).toEqual(
        expect.arrayContaining([expect.objectContaining({ kind, id, state })]),
      );
    expect(first.references).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          kind: 'POLICY_TARGET',
          id: `${q.rollbackOccurrenceId}/${q.rollbackTargetId}/ROLLBACK`,
          details: expect.objectContaining({ phase: 'ROLLBACK' }),
        }),
      ]),
    );
    expect(first.authority).toBe('NONE');
    expect(first.disposition).toBe('UNPROVEN');
    expect(first.unresolved).toContain('RUNTIME_CUSTODY_DISPOSITION_UNOBSERVED');
    expect(first.unresolved).toContain('INPUT_REDELIVERY_DISPOSITION_UNPROVEN');
    expect(await read()).toEqual(first);
    originalPassed = true;
  },
);
it.runIf(enabled)(
  'denies cross-context reads and reports unknown exact inputs without metadata disclosure',
  async () => {
    if (!originalPassed) blocked('original observation prerequisite failed');
    const q = selection(await fixture()),
      pool = await runtime();
    try {
      for (const select of [
        { ...q, participantId: localOperationId() },
        { ...q, privacyDomainId: localOperationId() },
      ])
        await expect(
          scoped(pool, q, (client) => readRuntimeArtifactReferences(client, select)),
        ).rejects.toThrow();
      for (const select of [
        { ...q, inputId: localOperationId() },
        { ...q, configurationDigest: `sha256:${'0'.repeat(64)}` },
      ]) {
        const result = await scoped(pool, q, (client) =>
          readRuntimeArtifactReferences(client, select),
        );
        expect(result.root).toBeNull();
        expect(result.references).toEqual([]);
        expect(result.unresolved).toContain('INPUT_NOT_OBSERVED');
      }
    } finally {
      await pool.end();
    }
  },
);
it.runIf(enabled)(
  'requires actual held fences and READ COMMITTED on the installed SQL observation owner',
  async () => {
    const q = selection(await fixture()),
      pool = await runtime();
    try {
      await expect(
        scoped(pool, q, (client) =>
          client.query('select openpc.observe_runtime_artifact_references($1,$2)', [
            q.inputId,
            q.configurationDigest,
          ]),
        ),
      ).rejects.toMatchObject({ message: 'RUNTIME-ARTIFACT-OBSERVATION-FENCE' });
      const client = await pool.connect();
      try {
        await client.query('begin isolation level repeatable read');
        await client.query(
          "select openpc.set_request_context('PARTICIPANT',$1,$2,$3,'ACT-EVIDENCE_EXPORT_RECORDS-V1',true)",
          [q.participantId, q.privacyDomainId, localOperationId()],
        );
        await expect(
          client.query('select openpc.observe_runtime_artifact_references($1,$2)', [
            q.inputId,
            q.configurationDigest,
          ]),
        ).rejects.toMatchObject({ message: 'RUNTIME-ARTIFACT-OBSERVATION-CONTEXT' });
      } finally {
        await client.query('rollback');
        client.release();
      }
    } finally {
      await pool.end();
    }
  },
);
