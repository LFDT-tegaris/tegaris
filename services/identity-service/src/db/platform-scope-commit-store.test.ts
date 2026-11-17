import { describe, expect, it, vi } from 'vitest';
import type { PoolClient } from 'pg';
import {
  envelopeFixtureId as id,
  envelopeFixtureDigest as digest,
} from '../../../../packages/security-kernel/src/identity-envelope/fixture.js';
import { commitPlatformScopeReplacement } from './platform-scope-commit-store.js';
import { fenceEnvelopePlatformScope } from './platform-envelope-scope.js';
import type { PlatformScopeReplacementCommit } from '../../../participant-service/src/contracts/platform-scope-replacement.js';

vi.mock('./platform-envelope-scope.js', () => ({ fenceEnvelopePlatformScope: vi.fn() }));
function fixture() {
  const candidate: PlatformScopeReplacementCommit = {
    schema: 'pc.identity.platform-scope-replacement-commit',
    schemaVersion: 1,
    replacementId: id(8),
    platformContextId: id(4),
    expectedReplacementRevision: '1',
    expectedRootRevision: '1',
    predecessorEpoch: '1',
    predecessorDigest: digest(1),
    successorDigest: digest(2),
    readinessDigest: digest(3),
    reason: 'Commit the exact signed withdrawal and administration handoff',
  };
  const owner = {
    participantId: id(1),
    privacyDomainId: id(2),
    operationId: id(50),
    approvalRequestId: id(51),
    makerPrincipalId: id(100),
    checkerPrincipalId: id(101),
    makerCredentialId: id(52),
    checkerCredentialId: id(53),
  };
  const readiness = {
    replacementId: id(8),
    platformContextId: id(4),
    replacementRevision: '1',
    rootRevision: '1',
    predecessorEpoch: '1',
    predecessorDigest: digest(1),
    successorDigest: digest(2),
    readinessDigest: digest(3),
    state: 'WITHDRAWING',
    unacknowledgedTargets: 0,
    unpreparedAdministrators: 0,
    sourceExpiresAtNs: '1800003600000000000',
    nowNs: '1800000001000000000',
    targets: [{ targetId: id(60), ready: true }],
    administrators: [100, 101].map((n) => ({
      principalId: id(n),
      envelopeId: id(n + 10),
      assignmentId: id(n + 20),
      ready: true,
    })),
  };
  const root = {
    platformContextId: id(4),
    platformAuthorityEpoch: '1',
    platformAuthorityDigest: digest(1),
    ownerParticipantId: id(1),
    installationPrivacyDomainId: id(2),
  };
  vi.mocked(fenceEnvelopePlatformScope).mockResolvedValue(
    root as Awaited<ReturnType<typeof fenceEnvelopePlatformScope>>,
  );
  const expected = {
    replacementId: id(8),
    successorDigest: digest(2),
    state: 'COMMITTED' as const,
    revision: '2',
    operationId: id(50),
    platformAuthorityEpoch: '2',
  };
  const effect = vi.fn(() => expected);
  const state = { approved: true };
  const query = vi.fn(async (sql: string) => {
    const rows = sql.includes('from control.mutation_candidate')
      ? state.approved
        ? [{ candidateId: id(70), makerEnvelope: id(71), checkerEnvelope: id(72) }]
        : []
      : sql.includes('read_platform_scope_replacement_readiness')
        ? [{ readiness }]
        : sql.includes('commit_platform_scope_replacement')
          ? [{ replacement: effect() }]
          : [];
    return { rows, rowCount: rows.length };
  });
  return {
    candidate,
    owner,
    readiness,
    root,
    expected,
    effect,
    state,
    client: { query } as unknown as PoolClient,
  };
}
describe('governed root commit owner', () => {
  it('commits only exact current readiness and checks atomic effect readback', async () => {
    const f = fixture();
    await expect(commitPlatformScopeReplacement(f.client, f.owner, f.candidate)).resolves.toEqual(
      f.expected,
    );
    expect(f.effect).toHaveBeenCalledTimes(1);
  });
  it.each([
    'self approval',
    'approval missing',
    'withdrawal pending',
    'handoff pending',
    'stale epoch',
    'stale digest',
    'expired source',
    'wrong root',
    'completed replay',
  ])('rejects %s before requesting a root effect', async (change) => {
    const f = fixture();
    if (change === 'self approval') f.owner.checkerPrincipalId = f.owner.makerPrincipalId;
    if (change === 'approval missing') f.state.approved = false;
    if (change === 'withdrawal pending') f.readiness.unacknowledgedTargets = 1;
    if (change === 'handoff pending') f.readiness.unpreparedAdministrators = 1;
    if (change === 'stale epoch') f.readiness.predecessorEpoch = '2';
    if (change === 'stale digest') f.readiness.readinessDigest = digest(99);
    if (change === 'expired source') f.readiness.sourceExpiresAtNs = f.readiness.nowNs;
    if (change === 'wrong root') f.root.platformContextId = id(99);
    if (change === 'completed replay') f.readiness.state = 'COMMITTED';
    await expect(commitPlatformScopeReplacement(f.client, f.owner, f.candidate)).rejects.toThrow();
    expect(f.effect).not.toHaveBeenCalled();
  });
  it('throws on an inconsistent effect so the enclosing mutation transaction must roll back', async () => {
    const f = fixture();
    f.effect.mockReturnValue({ ...f.expected, platformAuthorityEpoch: '3' });
    await expect(commitPlatformScopeReplacement(f.client, f.owner, f.candidate)).rejects.toThrow();
  });
});
