import { beforeEach, expect, it, vi } from 'vitest';
import {
  assertMutationCandidateAuthority,
  stageMutationCandidateInTransaction,
  type MutationCandidateContext,
} from './mutation-candidate-store.js';
import { fenceBoundAuthorities } from './authority-fence.js';
import { platformRecoveryFixture } from '../domain/platform-recovery.test-fixture.js';
import { canonicalAuthorizationDigest } from '../contracts/authorization.js';
import { envelopeFixtureId as id } from '../../../../packages/security-kernel/src/identity-envelope/fixture.js';
vi.mock('./authority-fence.js', async (original) => ({
  ...(await original<typeof import('./authority-fence.js')>()),
  fenceBoundAuthorities: vi.fn(),
}));
vi.mock('./platform-scope-replacement-eligibility.js', () => ({
  platformScopeReplacementContextEligible: vi.fn().mockResolvedValue(true),
}));
beforeEach(() => vi.clearAllMocks());
function fixture(representation = 'RECOVERY_V1') {
  const { source, intent } = platformRecoveryFixture();
  const context: MutationCandidateContext = {
    participantId: source.enrollment.participantId,
    privacyDomainId: source.enrollment.privacyDomainId,
    authorization: {
      participantId: source.enrollment.participantId,
      privacyDomainId: source.enrollment.privacyDomainId,
      principalId: source.enrollment.administratorPrincipalIds[0],
      principalEpoch: '2',
      participantEpoch: '1',
      sessionId: id(900),
      sessionEpoch: '1',
      assignmentId: id(901),
      assignmentRowVersion: '1',
      authorityEnvelopeId: id(902),
      authorityEpoch: '1',
      delegationEpoch: '0',
    },
    actionIntentId: 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
    actionIntentDigest: 'sha256:' + 'a'.repeat(64),
    catalogOperationId: 'ID-OP-PLATFORM-SCOPE-PREPARE',
    resourceType: 'participant',
    operationClass: 'UPDATE',
    resourceId: intent.preparation.replacementId,
    serverGeneratedResourceId: false,
    expectedRevision: '0',
    idempotencyKey: 'unit-recovery-handoff',
    candidateDigest: canonicalAuthorizationDigest(intent.preparation),
    candidate: intent.preparation,
  };
  const query = vi
    .fn()
    .mockResolvedValue({ rowCount: 1, rows: [{ representation, recoveryIntent: intent }] });
  return { client: { query } as never, query, context, intent };
}
it('requires the full live fence before admitting the exact reviewed recovery preparation', async () => {
  const v = fixture();
  await expect(assertMutationCandidateAuthority(v.client, v.context)).resolves.toBeUndefined();
  expect(fenceBoundAuthorities).toHaveBeenCalledWith(
    v.client,
    v.context.participantId,
    [
      expect.objectContaining({
        authorityEnvelopeId: v.context.authorization.authorityEnvelopeId,
        catalogOperationId: 'ID-OP-PLATFORM-SCOPE-PREPARE',
      }),
    ],
    {},
  );
  expect(vi.mocked(fenceBoundAuthorities).mock.invocationCallOrder[0]).toBeLessThan(
    v.query.mock.invocationCallOrder[0]!,
  );
  expect(v.query.mock.calls.every(([sql]) => !/^\s*(insert|update|delete)\b/iu.test(sql))).toBe(
    true,
  );
});
it.each(['changed preparation', 'provider operation', 'foreign target', 'missing intent'])(
  'rejects %s before any candidate or business writes',
  async (failure) => {
    const v = fixture();
    const context = { ...v.context };
    if (failure === 'changed preparation')
      context.candidate = { ...v.intent.preparation, reason: 'different intent' };
    if (failure === 'provider operation') context.catalogOperationId = 'ID-OP-PROVIDER-QUALIFY';
    if (failure === 'foreign target') context.resourceId = id(999);
    if (failure === 'missing intent')
      v.query.mockResolvedValue({
        rowCount: 1,
        rows: [{ representation: 'RECOVERY_V1', recoveryIntent: null }],
      });
    await expect(assertMutationCandidateAuthority(v.client, context)).rejects.toMatchObject({
      code: 'PC-AUTH-0005',
    });
    expect(v.query).toHaveBeenCalledOnce();
  },
);
it('does not apply the fixed recovery purpose to a normal typed issuer', async () => {
  const v = fixture('TYPED_V1');
  await expect(
    assertMutationCandidateAuthority(v.client, {
      ...v.context,
      catalogOperationId: 'ID-OP-PROVIDER-QUALIFY',
      candidate: {},
    }),
  ).resolves.toBeUndefined();
  expect(fenceBoundAuthorities).toHaveBeenCalledOnce();
});
it('preserves rejection of a stale selected grant before the fixed-purpose check', async () => {
  const v = fixture();
  v.query.mockResolvedValue({ rowCount: 0, rows: [] });
  await expect(assertMutationCandidateAuthority(v.client, v.context)).rejects.toMatchObject({
    code: 'PC-AUTH-0005',
  });
});

function commitFixture() {
  const v = fixture(),
    plan = v.intent.preparation;
  const readiness = {
    replacementId: plan.replacementId,
    platformContextId: plan.platformContextId,
    rootRevision: plan.expectedRootRevision,
    replacementRevision: '1',
    predecessorEpoch: plan.predecessorEpoch,
    predecessorDigest: plan.predecessorDigest,
    successorDigest: 'sha256:' + 'b'.repeat(64),
    readinessDigest: 'sha256:' + 'c'.repeat(64),
    state: 'WITHDRAWING',
    sourceExpiresAtNs: plan.successorScope.validUntilNs,
    nowNs: plan.successorScope.validFromNs,
    unacknowledgedTargets: 0,
    unpreparedAdministrators: 0,
    targets: [],
    administrators: plan.administrators.map((a) => ({
      principalId: a.principalId,
      envelopeId: a.envelopeId,
      assignmentId: a.assignmentId,
      ready: true,
    })),
  };
  const body = {
    schema: 'pc.identity.platform-scope-replacement-commit',
    schemaVersion: 1,
    replacementId: plan.replacementId,
    platformContextId: plan.platformContextId,
    expectedRootRevision: plan.expectedRootRevision,
    expectedReplacementRevision: '1',
    predecessorEpoch: plan.predecessorEpoch,
    predecessorDigest: plan.predecessorDigest,
    successorDigest: readiness.successorDigest,
    readinessDigest: readiness.readinessDigest,
    reason: 'Commit the genuine ready handoff.',
  };
  const context = {
    ...v.context,
    catalogOperationId: 'ID-OP-PLATFORM-SCOPE-COMMIT',
    expectedRevision: '1',
    candidate: body,
    candidateDigest: canonicalAuthorizationDigest(body),
  };
  const a = context.authorization;
  const original = {
    resourceId: context.resourceId,
    candidateDigest: Buffer.from(context.candidateDigest.slice(7), 'hex'),
    candidateDocument: body,
    expectedRevision: '1',
    state: 'PROPOSED',
    unexpired: true,
    current: true,
    makerAuthority: {
      participantId: context.participantId,
      principalId: a.principalId,
      sessionId: a.sessionId,
      sessionEpoch: a.sessionEpoch,
      participantEpoch: a.participantEpoch,
      principalEpoch: a.principalEpoch,
      assignmentId: a.assignmentId,
      assignmentRowVersion: a.assignmentRowVersion,
      authorityEnvelopeId: a.authorityEnvelopeId,
      authorityEpoch: a.authorityEpoch,
      delegationEpoch: a.delegationEpoch,
    },
  };
  const state = { stored: false };
  const writes = vi.fn();
  v.query.mockImplementation(async (sql: string) => {
    if (sql.includes('insert into control.mutation_candidate')) {
      writes();
      state.stored = true;
      return { rowCount: 1, rows: [] };
    }
    if (sql.includes('from control.mutation_candidate candidate'))
      return { rowCount: state.stored ? 1 : 0, rows: state.stored ? [original] : [] };
    if (sql.includes('read_platform_scope_replacement_readiness'))
      return { rowCount: 1, rows: [{ readiness }] };
    return { rowCount: 1, rows: [{ representation: 'RECOVERY_V1', recoveryIntent: v.intent }] };
  });
  return { ...v, context, readiness, original, state, writes };
}
it('checks authenticated current full readiness before a new commit candidate and reconciles the exact original read-first', async () => {
  const v = commitFixture();
  await expect(stageMutationCandidateInTransaction(v.client, v.context)).resolves.toBe(
    v.context.resourceId,
  );
  expect(v.writes).toHaveBeenCalledOnce();
  const statements = v.query.mock.calls.map(([sql]) => sql as string);
  expect(
    statements.findIndex((sql) => sql.includes('read_platform_scope_replacement_readiness')),
  ).toBeLessThan(
    statements.findIndex((sql) => sql.includes('insert into control.mutation_candidate')),
  );
  v.query.mockClear();
  await expect(stageMutationCandidateInTransaction(v.client, v.context)).resolves.toBe(
    v.context.resourceId,
  );
  expect(v.writes).toHaveBeenCalledOnce();
  expect(v.query.mock.calls.some(([sql]) => (sql as string).includes('insert into'))).toBe(false);
});
it.each([
  'pending withdrawal',
  'pending administrator',
  'expired source',
  'changed readiness',
  'changed Root',
])('rejects public commit staging with %s before insertion', async (failure) => {
  const v = commitFixture();
  if (failure === 'pending withdrawal') v.readiness.unacknowledgedTargets = 1;
  if (failure === 'pending administrator') v.readiness.unpreparedAdministrators = 1;
  if (failure === 'expired source') v.readiness.sourceExpiresAtNs = v.readiness.nowNs;
  if (failure === 'changed readiness') v.readiness.readinessDigest = 'sha256:' + 'd'.repeat(64);
  if (failure === 'changed Root') v.readiness.rootRevision = '999';
  await expect(stageMutationCandidateInTransaction(v.client, v.context)).rejects.toMatchObject({
    code: 'PC-AUTH-0005',
  });
  expect(v.writes).not.toHaveBeenCalled();
});
it.each([
  'different session',
  'changed epoch',
  'changed selected grant',
  'changed body',
  'expired original',
  'superseded original',
  'cancelled original',
])('rejects %s during original reconciliation without any insertion', async (failure) => {
  const v = commitFixture();
  v.state.stored = true;
  if (failure === 'different session') v.original.makerAuthority.sessionId = id(999);
  if (failure === 'changed epoch') v.original.makerAuthority.sessionEpoch = '999';
  if (failure === 'changed selected grant') v.original.makerAuthority.authorityEnvelopeId = id(999);
  if (failure === 'changed body')
    v.original.candidateDocument = { ...v.original.candidateDocument, reason: 'Changed intent.' };
  if (failure === 'expired original') v.original.unexpired = false;
  if (failure === 'superseded original') v.original.current = false;
  if (failure === 'cancelled original') v.original.state = 'CANCELLED';
  await expect(stageMutationCandidateInTransaction(v.client, v.context)).rejects.toMatchObject({
    code: 'PC-DATA-6007',
  });
  expect(v.writes).not.toHaveBeenCalled();
});
it('retains a consumed original solely for historical idempotent reconciliation', async () => {
  const v = commitFixture();
  v.state.stored = true;
  v.original.state = 'CONSUMED';
  await expect(stageMutationCandidateInTransaction(v.client, v.context)).resolves.toBe(
    v.context.resourceId,
  );
  expect(v.writes).not.toHaveBeenCalled();
});
