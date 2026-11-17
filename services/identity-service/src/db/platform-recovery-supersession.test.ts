import { beforeEach, expect, it, vi } from 'vitest';
import { platformRecoveryFixture } from '../domain/platform-recovery.test-fixture.js';
import { canonicalAuthorizationDigest } from '../contracts/authorization.js';
import {
  envelopeFixtureId as id,
  envelopeFixtureDigest as digest,
} from '../../../../packages/security-kernel/src/identity-envelope/fixture.js';
import { readPlatformRecoveryReceipt } from './platform-recovery-readback.js';
import { readExpiredRecoverySupersession } from './platform-recovery-supersession.js';
vi.mock('./platform-recovery-readback.js', () => ({ readPlatformRecoveryReceipt: vi.fn() }));
beforeEach(() => vi.clearAllMocks());
function fixture() {
  const { source, intent } = platformRecoveryFixture();
  intent.validFrom = new Date(source.now.getTime() - 30000).toISOString();
  intent.validUntil = new Date(source.now.getTime() - 1000).toISOString();
  for (const admin of intent.preparation.administrators)
    for (const key of ['usable', 'grantable'] as const) {
      admin[key].validFromNs = (BigInt(source.now.getTime() - 30000) * 1000000n).toString();
      admin[key].validUntilNs = (BigInt(source.now.getTime() - 1000) * 1000000n).toString();
    }
  source.pendingReplacementId = intent.preparation.replacementId;
  const link = {
    recoveryId: intent.recoveryId,
    intentDigest: canonicalAuthorizationDigest(intent),
    replacementId: intent.preparation.replacementId,
    preparationDigest: canonicalAuthorizationDigest(intent.preparation),
    preparationOperationId: id(500),
    preparationApprovalId: id(501),
    expectedRevision: '1' as const,
    successorDigest: digest(502),
  };
  const receipt = {
    state: 'EXPIRED',
    authority: 'NONE',
    intent,
    intentDigest: link.intentDigest,
    activation: { operationId: id(503) },
  };
  vi.mocked(readPlatformRecoveryReceipt).mockResolvedValue({ receipt } as never);
  const row = {
    link,
    state: 'WITHDRAWING',
    revision: '1',
    supersededBy: null as string | null,
    candidate: intent.preparation,
    consumed: true,
    hasEffects: false,
  };
  const query = vi.fn().mockResolvedValue({ rowCount: 1, rows: [row] });
  const actor = {
    participantId: source.enrollment.participantId,
    principalId: source.enrollment.recoveryPrincipal.principalId,
    sessionToken: 'mock-only',
    platform: true,
  };
  return {
    source,
    intent,
    link,
    receipt,
    row,
    query,
    client: { query } as never,
    actor,
    verifier: {} as never,
  };
}
it('binds only the closed, expired, consumed and wholly uneffected original without writing or allocating new names', async () => {
  const v = fixture();
  await expect(
    readExpiredRecoverySupersession(v.client, v.actor, v.source, v.verifier),
  ).resolves.toEqual(v.link);
  expect(readPlatformRecoveryReceipt).toHaveBeenCalledWith(
    v.client,
    v.actor,
    v.source.enrollment.enrollmentId,
    v.intent.recoveryId,
    v.verifier,
  );
  expect(v.query).toHaveBeenCalledOnce();
  expect(v.query.mock.calls[0]![1]).toContain(v.source.pendingReplacementId);
  expect(v.query.mock.calls.every(([sql]) => !/^\s*(insert|update|delete)\b/iu.test(sql))).toBe(
    true,
  );
});
it.each([
  'partial envelope',
  'unconsumed preparation',
  'live administration',
  'open case',
  'changed intent',
  'changed candidate',
  'wrong pending state',
  'missing activation',
])('rejects %s before any new recovery or preparation', async (failure) => {
  const v = fixture();
  if (failure === 'partial envelope') v.row.hasEffects = true;
  if (failure === 'unconsumed preparation') v.row.consumed = false;
  if (failure === 'live administration')
    v.intent.preparation.administrators[0]!.usable.validUntilNs = (
      BigInt(v.source.now.getTime() + 1) * 1000000n
    ).toString();
  if (failure === 'live administration') {
    v.link.preparationDigest = canonicalAuthorizationDigest(v.intent.preparation);
    v.link.intentDigest = canonicalAuthorizationDigest(v.intent);
    v.receipt.intentDigest = v.link.intentDigest;
  }
  if (failure === 'open case') v.receipt.state = 'ACTIVE';
  if (failure === 'changed intent') v.receipt.intentDigest = digest(999) as `sha256:${string}`;
  if (failure === 'changed candidate')
    v.row.candidate = { ...v.intent.preparation, reason: 'Different retained intent' };
  if (failure === 'wrong pending state') v.row.state = 'COMMITTED';
  if (failure === 'missing activation') v.receipt.activation = undefined as never;
  await expect(
    readExpiredRecoverySupersession(v.client, v.actor, v.source, v.verifier),
  ).rejects.toThrow();
});
it('requires verified original evidence and rejects concurrent supersession by another owner', async () => {
  const v = fixture();
  await expect(readExpiredRecoverySupersession(v.client, v.actor, v.source)).rejects.toThrow();
  v.row.state = 'SUPERSEDED';
  v.row.revision = '2';
  v.row.supersededBy = id(999);
  await expect(
    readExpiredRecoverySupersession(v.client, v.actor, v.source, v.verifier),
  ).rejects.toThrow();
});

it('keeps the same original linkage after the normal owner consumes the exact superseding preparation', async () => {
  const v = fixture();
  const next = {
    ...v.intent,
    recoveryId: id(600),
    supersession: v.link,
    preparation: {
      ...v.intent.preparation,
      replacementId: id(601),
      supersedes: {
        replacementId: v.link.replacementId,
        expectedRevision: v.link.expectedRevision,
        successorDigest: v.link.successorDigest,
      },
    },
  };
  v.row.state = 'SUPERSEDED';
  v.row.revision = '2';
  v.row.supersededBy = next.preparation.replacementId;
  v.source.pendingReplacementId = next.preparation.replacementId;
  await expect(
    readExpiredRecoverySupersession(v.client, v.actor, v.source, v.verifier, next),
  ).resolves.toEqual(v.link);
  next.supersession = { ...v.link, preparationOperationId: id(999) };
  await expect(
    readExpiredRecoverySupersession(v.client, v.actor, v.source, v.verifier, next),
  ).rejects.toThrow();
});
