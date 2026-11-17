import { beforeEach, expect, it, vi } from 'vitest';
import { canonicalAuthorizationDigest } from '../contracts/authorization.js';
import {
  platformRecoveryFixture,
  pendingPlatformRecoveryFixture,
} from '../domain/platform-recovery.test-fixture.js';
import {
  readExpiredPlatformAdministration,
  assertPlatformRecoverySigners,
  readRootExpiryPlatformAdministration,
} from './platform-recovery-enrollment.js';
import { readPendingPlatformRecoveryContinuation } from './platform-recovery-continuation.js';
import { readPlatformRecoverySession } from './platform-recovery-proof.js';
import {
  createPlatformRecoveryCase,
  readPlatformRecoveryCeremony,
} from './platform-recovery-case.js';
import { assertPlatformRecoveryRoles } from './platform-recovery-role.js';
import { platformRecoveryLeaseActions } from '../domain/platform-recovery-lease.js';
import { envelopeFixtureId as id } from '../../../../packages/security-kernel/src/identity-envelope/fixture.js';
vi.mock('./platform-recovery-enrollment.js', () => ({
  readExpiredPlatformAdministration: vi.fn(),
  assertPlatformRecoverySigners: vi.fn(),
  readRootExpiryPlatformAdministration: vi.fn(),
}));
vi.mock('./platform-recovery-continuation.js', () => ({
  readPendingPlatformRecoveryContinuation: vi.fn(),
}));
vi.mock('./platform-recovery-proof.js', () => ({ readPlatformRecoverySession: vi.fn() }));
vi.mock('./platform-recovery-role.js', () => ({ assertPlatformRecoveryRoles: vi.fn() }));
beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(assertPlatformRecoveryRoles).mockReset();
});
function fixture(failure?: string) {
  const { source, intent } = platformRecoveryFixture();
  vi.mocked(readExpiredPlatformAdministration).mockResolvedValue({
    root: { ...source.root, platformAuthorityDigest: source.rootDigest },
    rootRevision: source.rootRevision,
    rootState: source.rootState,
    rootDigest: source.rootDigest,
    now: source.now,
    pendingReplacementId: failure === 'pending replacement' ? id(999) : null,
    preparation: intent.preparation,
    originalAdministrators: source.originalAdministrators,
    administratorPrincipalIds: [...source.administratorPrincipalIds],
    administratorEpochs: [...source.administratorEpochs],
    administrationExpired: failure !== 'live prior authority',
  });
  vi.mocked(readPlatformRecoverySession).mockResolvedValue({
    sessionId: id(900),
    sessionEpoch: '1',
    durationProfile: 'C17',
    expiresAt: new Date(source.now.getTime() + 900_000),
  });
  vi.mocked(assertPlatformRecoverySigners).mockImplementation(async () => {
    if (failure === 'revoked signer') throw new Error('unavailable');
  });
  const writes: unknown[][] = [];
  const query = async (sql: string, values: unknown[]) => {
    if (sql.includes('openpc.lock_platform_recovery_enrollment'))
      return {
        rowCount: 1,
        rows: [
          {
            document: source.enrollment,
            document_digest: Buffer.from(
              canonicalAuthorizationDigest(source.enrollment).slice(7),
              'hex',
            ),
            row_version: '1',
            state: 'ACTIVE',
          },
        ],
      };
    if (sql.startsWith('select 1 from control.platform_recovery_case'))
      return { rowCount: failure === 'existing live case' ? 1 : 0, rows: [] };
    if (sql.startsWith('select 1 from control.authority_envelope'))
      return { rowCount: failure === 'record collision' ? 1 : 0, rows: [] };
    if (sql.startsWith('insert into control.platform_recovery_case')) {
      writes.push(values);
      return { rowCount: 1, rows: [] };
    }
    throw new Error('Unexpected case query');
  };
  const actor = {
    participantId: source.enrollment.participantId,
    principalId: source.enrollment.recoveryPrincipal.principalId,
    sessionToken: 'unused-mocked-session',
    platform: true,
  };
  return { source, intent, actor, writes, client: { query } as never };
}
it('generates and persists fresh record names and current epochs without granting authority', async () => {
  const v = fixture();
  expect(assertPlatformRecoveryRoles).not.toHaveBeenCalled();
  const original = structuredClone(v.intent.preparation);
  const result = await createPlatformRecoveryCase(
    v.client,
    v.actor,
    v.source.enrollment.enrollmentId,
    v.intent.preparation,
    true,
  );
  expect(result).toMatchObject({
    state: 'DRAFT',
    authority: 'NONE',
    assurance: 'LOCAL_QA_VIRTUAL_AUTHENTICATOR',
  });
  expect(result.intent.preparation.replacementId).not.toBe(original.replacementId);
  expect(result.intent.preparation.administrators.map((a) => a.principalId)).toEqual(
    original.administrators.map((a) => a.principalId),
  );
  expect(result.intent.administratorEpochs).toEqual(v.source.administratorEpochs);
  expect(Date.parse(result.intent.validUntil) - Date.parse(result.intent.validFrom)).toBe(900000);
  expect(v.writes).toHaveLength(1);
  expect(v.intent.preparation).toEqual(original);
});
it.each([
  'pending replacement',
  'live prior authority',
  'revoked signer',
  'existing live case',
  'record collision',
])('rejects %s without creating a proposal', async (failure) => {
  const v = fixture(failure);
  await expect(
    createPlatformRecoveryCase(
      v.client,
      v.actor,
      v.source.enrollment.enrollmentId,
      v.intent.preparation,
      true,
    ),
  ).rejects.toThrow();
  expect(v.writes).toHaveLength(0);
});
it('does not let a custodian or administration subject create the recovery proposal', async () => {
  const v = fixture();
  for (const principalId of [
    ...v.source.enrollment.administratorPrincipalIds,
    ...v.source.enrollment.custodians.map((v) => v.principalId),
  ])
    await expect(
      createPlatformRecoveryCase(
        v.client,
        { ...v.actor, principalId },
        v.source.enrollment.enrollmentId,
        v.intent.preparation,
        true,
      ),
    ).rejects.toThrow();
  expect(v.writes).toHaveLength(0);
});
it('rejects business scope widening before proposal persistence', async () => {
  const v = fixture();
  v.intent.preparation.successorScope.administration.resourceIds.push(id(999));
  await expect(
    createPlatformRecoveryCase(
      v.client,
      v.actor,
      v.source.enrollment.enrollmentId,
      v.intent.preparation,
      true,
    ),
  ).rejects.toThrow();
  expect(v.writes).toHaveLength(0);
});

it.each(['CREATE', 'CEREMONY'] as const)(
  'rejects a LOW-only submitted intent with valid source roles before %s effects',
  async (phase) => {
    const v = fixture();
    const roles = v.intent.preparation.administrators.map((admin) => ({
      roleId: `urn:openpc:role:${admin.roleId}`,
      version: '1',
      actions: [...platformRecoveryLeaseActions],
    }));
    for (const scope of [
      v.source.root.grantable,
      v.intent.preparation.successorScope,
      ...v.intent.preparation.administrators.flatMap((admin) => [admin.usable, admin.grantable]),
    ]) {
      scope.administration.actionIntentIds = [...platformRecoveryLeaseActions];
      scope.administration.riskClasses = ['HIGH', 'LOW'];
    }
    for (const [index, admin] of v.intent.preparation.administrators.entries()) {
      admin.roleDigest = canonicalAuthorizationDigest({
        domain: 'pc.identity.envelope-role-binding.v1',
        participantId: v.source.enrollment.participantId,
        role: roles[index],
      });
      Object.assign(v.source.originalAdministrators[index]!, structuredClone(admin));
    }
    const narrowed = structuredClone(v.intent);
    narrowed.preparation.administrators[0]!.usable.administration.riskClasses = ['LOW'];
    const realRoles = await vi.importActual<typeof import('./platform-recovery-role.js')>(
      './platform-recovery-role.js',
    );
    vi.mocked(assertPlatformRecoveryRoles).mockImplementation(
      realRoles.assertPlatformRecoveryRoles,
    );
    const baseQuery = (
      v.client as unknown as { query: (sql: string, values: unknown[]) => Promise<unknown> }
    ).query;
    const query = vi.fn(async (sql: string, values: unknown[]) => {
      if (sql.includes('control.action_intent')) {
        const rows = platformRecoveryLeaseActions.map((action_intent_id) => ({
          action_intent_id,
          risk_class: action_intent_id === 'ACT-PARTICIPANT_ACTIVATE_CONTEXT-V1' ? 'HIGH' : 'LOW',
        }));
        return { rowCount: rows.length, rows };
      }
      if (sql.includes('from control.authority_role')) {
        const index = v.intent.preparation.administrators.findIndex(
          (admin) => admin.roleId === values[1],
        );
        return { rowCount: 1, rows: [{ role: roles[index] }] };
      }
      if (sql.startsWith('select intent,intent_digest,planned_record_ids,state'))
        return {
          rowCount: 1,
          rows: [
            {
              intent: narrowed,
              intent_digest: Buffer.from(canonicalAuthorizationDigest(narrowed).slice(7), 'hex'),
              planned_record_ids: v.source.plannedRecordIds,
              state: 'REQUESTED',
            },
          ],
        };
      return baseQuery(sql, values);
    });
    const client = { query } as never;
    await expect(
      phase === 'CREATE'
        ? createPlatformRecoveryCase(
            client,
            v.actor,
            v.source.enrollment.enrollmentId,
            narrowed.preparation,
            true,
          )
        : readPlatformRecoveryCeremony(
            client,
            v.actor,
            v.source.enrollment.enrollmentId,
            narrowed.recoveryId,
            true,
          ),
    ).rejects.toThrow('Platform recovery unavailable');
    expect(assertPlatformRecoveryRoles).toHaveBeenCalledTimes(2);
    expect(v.writes).toHaveLength(0);
    expect(query.mock.calls.every(([sql]) => sql.startsWith('select'))).toBe(true);
  },
);

it('bounds configured QA custody by the persisted enrollment and never extends the input preparation', async () => {
  const v = fixture();
  const preparation = structuredClone(v.intent.preparation);
  const result = await createPlatformRecoveryCase(
    v.client,
    v.actor,
    v.source.enrollment.enrollmentId,
    preparation,
    true,
    { profile: 'LOCAL_QA', leaseMs: 3600000, administratorMs: 28800000 },
  );
  expect(result.intent.validUntil).toBe(v.source.enrollment.validUntil);
  expect(result.intent.lifetimes).toMatchObject({ profile: 'LOCAL_QA', leaseMs: 3600000 });
  expect(preparation).toEqual(v.intent.preparation);
});

it.each([
  [0, 'usable'],
  [0, 'grantable'],
  [1, 'usable'],
  [1, 'grantable'],
] as const)(
  'bounds a fresh case by administrator %s %s expiry after SOURCE and CREATE clocks differ',
  async (index, dimension) => {
    const v = fixture();
    const preparedAt = v.source.now.getTime();
    const rootUntil = (BigInt(preparedAt + 7_200_000) * 1_000_000n).toString();
    v.source.enrollment.validFrom = new Date(preparedAt).toISOString();
    v.source.enrollment.validUntil = new Date(preparedAt + 3_600_000).toISOString();
    v.source.root.grantable.validUntilNs = rootUntil;
    v.intent.preparation.successorScope.validUntilNs = rootUntil;
    for (const administrator of v.intent.preparation.administrators) {
      for (const scope of [administrator.usable, administrator.grantable]) {
        scope.validFromNs = (BigInt(preparedAt + 60_000) * 1_000_000n).toString();
        scope.validUntilNs = (BigInt(preparedAt + 3_600_000) * 1_000_000n).toString();
      }
    }
    const expectedUntil = new Date(preparedAt + 3_599_000).toISOString();
    v.intent.preparation.administrators[index]![dimension].validUntilNs = (
      BigInt(Date.parse(expectedUntil)) * 1_000_000n
    ).toString();
    v.source.now.setTime(preparedAt + 3);
    const preparation = structuredClone(v.intent.preparation);
    const result = await createPlatformRecoveryCase(
      v.client,
      v.actor,
      v.source.enrollment.enrollmentId,
      preparation,
      true,
      { profile: 'LOCAL_QA', leaseMs: 3_600_000, administratorMs: 3_600_000 },
    );
    expect(result).toMatchObject({ state: 'DRAFT', authority: 'NONE' });
    expect(result.intent.validUntil).toBe(expectedUntil);
    expect(Date.parse(result.intent.validUntil) - Date.parse(result.intent.validFrom)).toBeLessThan(
      3_600_000,
    );
    expect(preparation).toEqual(v.intent.preparation);
    expect(v.writes).toHaveLength(1);
  },
);

function continuationFixture() {
  const v = pendingPlatformRecoveryFixture();
  const writes: unknown[][] = [];
  const query = vi.fn(async (sql: string, values: unknown[]) => {
    if (sql.includes('openpc.lock_platform_recovery_enrollment'))
      return {
        rowCount: 1,
        rows: [
          {
            document: v.source.enrollment,
            document_digest: Buffer.from(
              canonicalAuthorizationDigest(v.source.enrollment).slice(7),
              'hex',
            ),
            row_version: '1',
            state: 'ACTIVE',
          },
        ],
      };
    if (sql.startsWith('select 1 from control.platform_recovery_case'))
      return { rowCount: 0, rows: [] };
    if (sql.startsWith('insert into control.platform_recovery_case')) {
      writes.push(values);
      return { rowCount: 1, rows: [] };
    }
    throw new Error('Unexpected continuation query');
  });
  vi.mocked(readRootExpiryPlatformAdministration).mockResolvedValue({
    ...v.source,
    pending: v.source.pendingReplacementId,
    expiredReplacementId: null,
    plannedRecordIds: [],
    enrollment: v.source
      .enrollment as import('../contracts/platform-recovery.js').PendingPlatformRecoveryEnrollment,
    root: { ...v.source.root, platformAuthorityDigest: v.source.rootDigest },
    rootRevision: v.source.rootRevision,
    rootState: v.source.rootState,
    rootDigest: v.source.rootDigest,
    now: v.source.now,
    pendingReplacementId: v.source.pendingReplacementId,
    preparation: v.original.intent.preparation,
    originalAdministrators: v.source.originalAdministrators,
    administratorPrincipalIds: [...v.source.administratorPrincipalIds] as [string, string],
    administratorEpochs: [...v.source.administratorEpochs],
    administrationExpired: false,
    originalAdministrationDisplaced: true,
  });
  vi.mocked(readPendingPlatformRecoveryContinuation).mockResolvedValue({
    recoveryContinuation: v.source.recoveryContinuation!,
    continuationPreparation: v.original.intent.preparation,
    preparation: v.original.intent.preparation,
    plannedRecordIds: [
      v.original.intent.preparation.replacementId,
      ...v.original.intent.preparation.administrators.flatMap((a) => [
        a.envelopeId,
        a.assignmentId,
      ]),
    ],
  });
  vi.mocked(readPlatformRecoverySession).mockResolvedValue({
    sessionId: id(900),
    sessionEpoch: '1',
    durationProfile: 'C17',
    expiresAt: new Date(v.source.now.getTime() + 900000),
  });
  const actor = {
    participantId: v.source.enrollment.participantId,
    principalId: v.source.enrollment.recoveryPrincipal.principalId,
    sessionToken: 'mocked-current-session',
    platform: true,
  };
  return { ...v, query, writes, actor, client: { query } as never };
}
it('persists a new custody case for the exact pending preparation without renaming or replaying existing business records', async () => {
  const v = continuationFixture(),
    before = structuredClone(v.original);
  const result = await createPlatformRecoveryCase(
    v.client,
    v.actor,
    v.source.enrollment.enrollmentId,
    v.original.intent.preparation,
    true,
  );
  expect(result.intent.preparation).toEqual(before.intent.preparation);
  expect(result.intent.continuation).toEqual(v.source.recoveryContinuation);
  expect(result.intent.recoveryId).not.toBe(v.original.intent.recoveryId);
  expect(result.intent.validUntil).toBe(v.intent.validUntil);
  expect(result.authority).toBe('NONE');
  expect(v.writes).toHaveLength(1);
  expect(JSON.parse(v.writes[0]![8] as string)).toEqual([
    before.intent.preparation.replacementId,
    ...before.intent.preparation.administrators.flatMap((a) => [a.envelopeId, a.assignmentId]),
  ]);
  expect(
    v.query.mock.calls.some(([sql]) => sql.startsWith('select 1 from control.authority_envelope')),
  ).toBe(false);
  expect(v.original).toEqual(before);
});
it.each([
  'changed preparation',
  'missing authenticated history',
  'foreign pending',
  'foreign executor',
  'production',
])('denies continuation %s before persisting a case', async (failure) => {
  const v = continuationFixture(),
    original = structuredClone(v.original);
  const input = structuredClone(v.original.intent.preparation);
  if (failure === 'changed preparation') input.administrators[0]!.assignmentId = id(999);
  if (failure === 'missing authenticated history')
    vi.mocked(readPendingPlatformRecoveryContinuation).mockRejectedValueOnce(
      new Error('unavailable'),
    );
  if (failure === 'foreign pending') {
    const current = await vi.mocked(readRootExpiryPlatformAdministration).getMockImplementation()!(
      v.client,
      v.source.enrollment as never,
      undefined,
    );
    vi.mocked(readRootExpiryPlatformAdministration).mockResolvedValueOnce({
      ...current,
      pendingReplacementId: id(999),
    });
  }
  if (failure === 'foreign executor')
    v.actor.principalId = v.source.enrollment.custodians[0].principalId;
  await expect(
    createPlatformRecoveryCase(
      v.client,
      v.actor,
      v.source.enrollment.enrollmentId,
      input,
      failure !== 'production',
    ),
  ).rejects.toThrow();
  expect(v.writes).toHaveLength(0);
  expect(v.original).toEqual(original);
});
