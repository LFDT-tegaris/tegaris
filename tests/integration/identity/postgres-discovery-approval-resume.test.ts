import { realpath } from 'node:fs/promises';
import { basename } from 'node:path';
import { Pool, type PoolClient } from 'pg';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import type { RootExpiryPlatformRecoveryEnrollment } from '../../../services/identity-service/src/contracts/platform-recovery.js';
import { localOperationId as id } from '../../../services/identity-service/src/domain/local-operation-id.js';
import { rootExpiryPlatformRecoveryFixture } from '../../../services/identity-service/src/domain/platform-recovery.test-fixture.js';

// Installed comparison/ACL/wiring boundaries only. No source is admitted, no
// recovery case or native proof is fabricated, and no business state is seeded.
// The actual current-case resource, pending/used-proof, deferred transaction and
// public original-operation replay positives require their legitimate producers.
// In particular, absent-case denial below does not qualify missing resources on
// a valid current grant, and trigger wiring does not prove successful completion.
type Source = RootExpiryPlatformRecoveryEnrollment['source'];
const resumeAction = 'ACT-APPROVAL_REQUESTS_UPDATE_RESOURCE-V1';
// These ordered arrays are the canonical signed-input contract. Comparison must
// preserve their order; they are neither sets nor grants installed by this test.
const legacyActions = [
  'ACT-APPROVAL_REQUESTS_CREATE_RESOURCE-V1',
  'ACT-APPROVAL_REQUESTS_READ_RESOURCE-V1',
  'ACT-IDENTITY_CREATE_SESSION-V1',
  'ACT-IDENTITY_DELETE_SESSION-V1',
  'ACT-IDENTITY_UPDATE_STEP_UP-V1',
  'ACT-OPERATIONS_READ_OPERATION-V1',
  'ACT-PARTICIPANTS_READ_RESOURCE-V1',
  'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
  'ACT-POLICY_APPROVE_REQUEST-V1',
  'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1',
];
const resumeActions = [
  'ACT-APPROVAL_REQUESTS_CREATE_RESOURCE-V1',
  'ACT-APPROVAL_REQUESTS_READ_RESOURCE-V1',
  'ACT-APPROVAL_REQUESTS_UPDATE_RESOURCE-V1',
  'ACT-IDENTITY_CREATE_SESSION-V1',
  'ACT-IDENTITY_DELETE_SESSION-V1',
  'ACT-IDENTITY_UPDATE_STEP_UP-V1',
  'ACT-OPERATIONS_READ_OPERATION-V1',
  'ACT-PARTICIPANTS_READ_RESOURCE-V1',
  'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
  'ACT-POLICY_APPROVE_REQUEST-V1',
  'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1',
];

function withActions(source: Source, actions: readonly string[]): Source {
  const result = structuredClone(source);
  for (const administrator of result.originalAdministrators)
    for (const scope of ['usable', 'grantable'] as const)
      administrator[scope].administration.actionIntentIds = [...actions];
  return result;
}

function comparisonFixture(): Source {
  // Reuse pure, structurally complete declaration fixtures, never their mocked
  // currentness or timestamps as runtime evidence. This SQL owner is IMMUTABLE.
  const source = withActions(
    rootExpiryPlatformRecoveryFixture().source.enrollment.source,
    legacyActions,
  );
  source.ancestorReceipts = [
    {
      recoveryId: id(),
      enrollmentId: id(),
      activationOperationId: id(),
      receiptDigest: `sha256:${'1'.repeat(64)}`,
    },
  ];
  return source;
}

describe('installed Discovery approval RESUME owner boundaries', () => {
  let admin: Pool | undefined;
  let runtime: Pool | undefined;
  let connection: PoolClient | undefined;
  let initialCounts: Record<string, number> | undefined;
  const participantId = id();
  const privacyDomainId = id();

  function client(): PoolClient {
    if (!connection) throw new Error('Disposable runtime fixture was not established');
    return connection;
  }

  async function effectCounts(): Promise<Record<string, number>> {
    if (!admin) throw new Error('Disposable database owner was not established');
    const result = await admin.query<Record<string, number>>(`SELECT
      (SELECT count(*)::int FROM control.participant) AS participants,
      (SELECT count(*)::int FROM control.principal) AS principals,
      (SELECT count(*)::int FROM control.session) AS sessions,
      (SELECT count(*)::int FROM control.credential) AS credentials,
      (SELECT count(*)::int FROM control.platform_recovery_enrollment) AS sources,
      (SELECT count(*)::int FROM control.platform_recovery_case) AS cases,
      (SELECT count(*)::int FROM control.root_expiry_recovery_case) AS root_receipts,
      (SELECT count(*)::int FROM control.mutation_candidate) AS candidates,
      (SELECT count(*)::int FROM control.approval_request) AS approvals,
      (SELECT count(*)::int FROM control.idempotency_record) AS operations,
      (SELECT count(*)::int FROM control.mfa_challenge) AS challenges,
      (SELECT count(*)::int FROM control.mfa_challenge WHERE used_at IS NOT NULL OR used_operation_id IS NOT NULL) AS used_proofs,
      (SELECT count(*)::int FROM control.discovery_certificate_issuance) AS issuances,
      (SELECT count(*)::int FROM control.discovery_certificate_issuer_attempt) AS issuer_attempts,
      (SELECT count(*)::int FROM control.mutation_evidence) AS evidence,
      (SELECT count(*)::int FROM control.audit_occurrence) AS audit,
      (SELECT count(*)::int FROM control.outbox_event) AS outbox`);
    const row = result.rows[0];
    if (!row) throw new Error('Missing disposable database effect counts');
    return row;
  }

  async function compatible(oldSource: unknown, newSource: unknown): Promise<boolean> {
    const result = await client().query<{ allowed: boolean }>(
      'SELECT openpc.discovery_approval_resume_source_compatible($1::jsonb,$2::jsonb) AS allowed',
      [JSON.stringify(oldSource), JSON.stringify(newSource)],
    );
    expect(result.rowCount).toBe(1);
    expect(typeof result.rows[0]?.allowed).toBe('boolean');
    return result.rows[0]!.allowed;
  }

  beforeAll(async () => {
    const adminUrl = process.env.OPENPC_I02_ADMIN_DATABASE_URL;
    const runtimeUrl = process.env.OPENPC_I02_RUNTIME_DATABASE_URL;
    const scratch = process.env.OPENPC_TEST_TMP_ROOT;
    // Unconditional tests: missing harness/URLs must fail, never skip green.
    if (!adminUrl || !runtimeUrl || !scratch)
      throw new Error(
        'Select this file through the disposable participant-readback database harness',
      );
    expect(basename(await realpath(scratch))).toMatch(/^participant-readback\.[A-Za-z0-9]+$/u);
    const runtimeAddress = new URL(runtimeUrl);
    const adminAddress = new URL(adminUrl);
    expect(runtimeAddress.hostname).toBe('127.0.0.1');
    expect(Number(runtimeAddress.port)).toBeGreaterThan(1024);
    expect(runtimeAddress.username).toBe('openpc_identity_runtime');
    expect(adminAddress.hostname).toBe(runtimeAddress.hostname);
    expect(adminAddress.port).toBe(runtimeAddress.port);
    expect(adminAddress.pathname).toBe(runtimeAddress.pathname);
    expect(adminAddress.username).toBe('postgres');
    admin = new Pool({ connectionString: adminUrl, max: 1, connectionTimeoutMillis: 5000 });
    initialCounts = await effectCounts();
    expect(Object.values(initialCounts).every((count) => count === 0)).toBe(true);
    const migration = await admin.query<{ path: string }>(
      "SELECT path FROM openpc_local.migration WHERE path='/migrations/postgres/identity/0188_discovery_approved_resume_root_lineage.sql'",
    );
    expect(migration.rows).toEqual([
      { path: '/migrations/postgres/identity/0188_discovery_approved_resume_root_lineage.sql' },
    ]);
    runtime = new Pool({ connectionString: runtimeUrl, max: 1, connectionTimeoutMillis: 5000 });
    connection = await runtime.connect();
    const role = await client().query<{ name: string; superuser: boolean; bypass: boolean }>(
      'SELECT rolname AS name,rolsuper AS superuser,rolbypassrls AS bypass FROM pg_roles WHERE rolname=current_user',
    );
    expect(role.rows).toEqual([
      { name: 'openpc_identity_runtime', superuser: false, bypass: false },
    ]);
  });

  beforeEach(async () => {
    await client().query('BEGIN READ ONLY');
    await client().query(
      "SELECT openpc.set_request_context('PARTICIPANT',$1::uuid,$2::uuid,$3::uuid,$4::text,true)",
      [participantId, privacyDomainId, id(), resumeAction],
    );
    await client().query("SELECT set_config('openpc.local_qa_runtime','1',true)");
  });

  afterEach(async () => {
    if (connection) await connection.query('ROLLBACK');
    if (initialCounts) expect(await effectCounts()).toEqual(initialCounts);
  });

  afterAll(async () => {
    connection?.release();
    await Promise.all([runtime?.end(), admin?.end()]);
  });

  it('keeps the installed receipt and candidate tables under forced RLS with the real runtime grant', async () => {
    const tables = await client().query<{ name: string; enabled: boolean; forced: boolean }>(`SELECT
      c.relname AS name,c.relrowsecurity AS enabled,c.relforcerowsecurity AS forced
      FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
      WHERE n.nspname='control' AND c.relname=ANY(ARRAY['mutation_candidate','approval_request',
        'root_expiry_recovery_case','root_expiry_recovery_enrollment','root_expiry_recovery_scope'])
      ORDER BY c.relname`);
    expect(tables.rows).toEqual(
      [
        'approval_request',
        'mutation_candidate',
        'root_expiry_recovery_case',
        'root_expiry_recovery_enrollment',
        'root_expiry_recovery_scope',
      ].map((name) => ({ name, enabled: true, forced: true })),
    );
    const policies = await client().query<{ name: string; command: string }>(`SELECT
      c.relname AS name,p.polcmd::text AS command FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid
      JOIN pg_namespace n ON n.oid=c.relnamespace
      WHERE n.nspname='control' AND p.polname='root_expiry_admin_receipt_prerequisite_read'
      AND c.relname=ANY(ARRAY['root_expiry_recovery_case','root_expiry_recovery_enrollment','root_expiry_recovery_scope'])
      AND 'openpc_control_runtime'::regrole=ANY(p.polroles) ORDER BY c.relname`);
    expect(policies.rows).toEqual(
      [
        'root_expiry_recovery_case',
        'root_expiry_recovery_enrollment',
        'root_expiry_recovery_scope',
      ].map((name) => ({ name, command: 'r' })),
    );
    const grant = await client().query<{ runtime: boolean; worker: boolean }>(`SELECT
      has_function_privilege(current_user,'openpc.discovery_approval_resume_source_compatible(jsonb,jsonb)','EXECUTE') AS runtime,
      has_function_privilege('openpc_control_worker','openpc.discovery_approval_resume_source_compatible(jsonb,jsonb)','EXECUTE') AS worker`);
    expect(grant.rows).toEqual([{ runtime: true, worker: false }]);
  });

  it('accepts only the four-array TEN to ELEVEN relation and preserves an already ELEVEN source', async () => {
    const oldSource = comparisonFixture();
    const newSource = withActions(oldSource, resumeActions);
    expect(await compatible(oldSource, newSource)).toBe(true);
    expect(await compatible(newSource, structuredClone(newSource))).toBe(true);
    expect(await compatible(oldSource, structuredClone(oldSource))).toBe(false);
    expect(await compatible(newSource, oldSource)).toBe(false);
    expect(
      oldSource.originalAdministrators.every((administrator) =>
        (['usable', 'grantable'] as const).every(
          (scope) => !administrator[scope].administration.actionIntentIds.includes(resumeAction),
        ),
      ),
    ).toBe(true);
  });

  it('rejects every independently changed action array, receipt and stored administrator binding', async () => {
    const oldSource = comparisonFixture();
    const newSource = withActions(oldSource, resumeActions);
    const actionMutations = [
      legacyActions,
      resumeActions.filter((action) => action !== 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1'),
      [...resumeActions, '*'],
      [...resumeActions, 'ACT-PARTICIPANTS_DELETE_RESOURCE-V1'],
      [...resumeActions].reverse(),
      [...resumeActions, resumeAction],
    ];
    for (const index of [0, 1] as const)
      for (const scope of ['usable', 'grantable'] as const) {
        const mixedOldSource = structuredClone(oldSource);
        mixedOldSource.originalAdministrators[index][scope].administration.actionIntentIds = [
          ...resumeActions,
        ];
        expect(
          await compatible(mixedOldSource, newSource),
          `administrator ${index}, ${scope}, mixed original action closure`,
        ).toBe(false);
        for (const actions of actionMutations) {
          const changed = structuredClone(newSource);
          changed.originalAdministrators[index][scope].administration.actionIntentIds = [
            ...actions,
          ];
          expect(
            await compatible(oldSource, changed),
            `administrator ${index}, ${scope}, action closure`,
          ).toBe(false);
        }
      }
    const bindingMutations: readonly [string, (source: Source) => void][] = [
      [
        'recovery',
        (source) => {
          source.recoveryId = id();
        },
      ],
      [
        'enrollment',
        (source) => {
          source.enrollmentId = id();
        },
      ],
      [
        'activation operation',
        (source) => {
          source.activationOperationId = id();
        },
      ],
      [
        'receipt digest',
        (source) => {
          source.receiptDigest = `sha256:${'2'.repeat(64)}`;
        },
      ],
      [
        'ancestor',
        (source) => {
          source.ancestorReceipts![0]!.activationOperationId = id();
        },
      ],
      [
        'principal',
        (source) => {
          source.originalAdministrators[0].principalId = id();
        },
      ],
      [
        'envelope',
        (source) => {
          source.originalAdministrators[0].envelopeId = id();
        },
      ],
      [
        'assignment',
        (source) => {
          source.originalAdministrators[0].assignmentId = id();
        },
      ],
      [
        'envelope revision',
        (source) => {
          source.originalAdministrators[0].envelopeRevision = '2';
        },
      ],
      [
        'assignment revision',
        (source) => {
          source.originalAdministrators[0].assignmentRevision = '2';
        },
      ],
      [
        'role digest',
        (source) => {
          source.originalAdministrators[0].roleDigest = `sha256:${'3'.repeat(64)}`;
        },
      ],
      [
        'risk bound',
        (source) => {
          source.originalAdministrators[0].usable.administration.riskClasses = ['LOW'];
        },
      ],
    ];
    for (const [name, change] of bindingMutations) {
      const changed = structuredClone(newSource);
      change(changed);
      expect(await compatible(oldSource, changed), name).toBe(false);
    }
    for (const malformed of [
      null,
      [],
      'source',
      {},
      { ...newSource, originalAdministrators: [newSource.originalAdministrators[0]] },
    ]) {
      expect(await compatible(oldSource, malformed)).toBe(false);
      expect(await compatible(malformed, newSource)).toBe(false);
    }
  });

  it('never turns a compatible source document into current-case visibility or a resource grant', async () => {
    const oldSource = comparisonFixture();
    expect(await compatible(oldSource, withActions(oldSource, resumeActions))).toBe(true);
    const absentPrincipal = id();
    const absentEnvelope = id();
    const absentApproval = id();
    const absentSession = id();
    const absentCredential = id();
    const result = await client().query<Record<string, boolean>>(
      `SELECT
      openpc.discovery_approval_resume_subject_visible($1::uuid,$2::uuid,$3::uuid,$4::uuid,$5::uuid) AS visible,
      openpc.discovery_approval_resume_eligible($1::uuid,$2::uuid,$3::uuid,$4::uuid,$5::uuid) AS eligible,
      openpc.discovery_certificate_resume_administrators_current($6::uuid) AS admitted_source,
      openpc.platform_recovery_envelope_current($4::uuid) AS current_envelope,
      openpc.administration_resource_permits(ARRAY[]::text[],$5::uuid::text,$7::text,$1::uuid,$3::uuid,$8::uuid,$4::uuid) AS empty_resources,
      openpc.administration_resource_permits(ARRAY[$9::uuid::text],$5::uuid::text,$7::text,$1::uuid,$3::uuid,$8::uuid,$4::uuid) AS credential_resources`,
      [
        participantId,
        privacyDomainId,
        absentPrincipal,
        absentEnvelope,
        absentApproval,
        id(),
        resumeAction,
        absentSession,
        absentCredential,
      ],
    );
    expect(result.rows).toEqual([
      {
        visible: false,
        eligible: false,
        admitted_source: false,
        current_envelope: false,
        empty_resources: false,
        credential_resources: false,
      },
    ]);
    for (const table of [
      'root_expiry_recovery_case',
      'root_expiry_recovery_enrollment',
      'root_expiry_recovery_scope',
    ] as const) {
      // Closed test-owned identifiers only. No SELECT success is reported as a
      // scoped-v2 positive: there are intentionally no admitted receipt rows.
      expect((await client().query(`SELECT 1 FROM control.${table}`)).rowCount).toBe(0);
    }
    expect(await effectCounts()).toEqual(initialCounts);
  });

  it('binds completion to its distinct deferred invoker guard and denies direct runtime invocation', async () => {
    const triggers = await client().query<{
      name: string;
      owner: string;
      deferred: boolean;
      initially_deferred: boolean;
      enabled: string;
      row_insert: boolean;
    }>(`SELECT t.tgname AS name,p.proname AS owner,t.tgdeferrable AS deferred,
      t.tginitdeferred AS initially_deferred,t.tgenabled::text AS enabled,t.tgtype=5 AS row_insert
      FROM pg_trigger t JOIN pg_proc p ON p.oid=t.tgfoid
      WHERE t.tgrelid='control.mutation_candidate'::regclass
      AND t.tgname=ANY(ARRAY['zz_discovery_approval_resume_final','zz_discovery_approval_resume_final_completed'])
      ORDER BY t.tgname`);
    expect(triggers.rows).toEqual([
      {
        name: 'zz_discovery_approval_resume_final',
        owner: 'guard_discovery_approval_resume_final',
        deferred: false,
        initially_deferred: false,
        enabled: 'O',
        row_insert: true,
      },
      {
        name: 'zz_discovery_approval_resume_final_completed',
        owner: 'guard_discovery_approval_resume_completed',
        deferred: true,
        initially_deferred: true,
        enabled: 'O',
        row_insert: true,
      },
    ]);
    for (const signature of [
      'openpc.guard_discovery_approval_resume_final()',
      'openpc.guard_discovery_approval_resume_completed()',
    ] as const) {
      const acl = await client().query<{
        definer: boolean;
        runtime: boolean;
        platform: boolean;
        worker: boolean;
        public_execute: boolean;
      }>(
        `SELECT p.prosecdef AS definer,
        has_function_privilege(current_user,p.oid,'EXECUTE') AS runtime,
        has_function_privilege('openpc_control_platform_runtime',p.oid,'EXECUTE') AS platform,
        has_function_privilege('openpc_control_worker',p.oid,'EXECUTE') AS worker,
        EXISTS(SELECT 1 FROM aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
          WHERE a.grantee=0 AND a.privilege_type='EXECUTE') AS public_execute
        FROM pg_proc p WHERE p.oid=$1::regprocedure`,
        [signature],
      );
      expect(acl.rows).toEqual([
        { definer: false, runtime: false, platform: false, worker: false, public_execute: false },
      ]);
      await client().query('SAVEPOINT forbidden_direct_guard');
      try {
        // Closed test-owned signatures, never caller SQL. An ACL regression must
        // not be confused with the generic "trigger functions cannot be called"
        // error: the actual runtime invocation must fail with privilege 42501.
        await expect(client().query(`SELECT ${signature}`)).rejects.toMatchObject({
          code: '42501',
        });
      } finally {
        await client().query('ROLLBACK TO SAVEPOINT forbidden_direct_guard');
        await client().query('RELEASE SAVEPOINT forbidden_direct_guard');
      }
    }
  });
});
