import { expect, it, vi } from 'vitest';
import {
  postReviewIdentityEnvelopeRecovery,
  readIdentityEnvelopeRecoveryReview,
  lockIdentityEnvelopeRecoveryReviewVersion,
} from './identity-envelope-recovery-post-review.js';
import { canonicalAuthorizationDigest } from '../contracts/authorization.js';
import { identityEnvelopeRecoveryIntent } from '../contracts/identity-envelope-recovery.js';
import { PostgresIdentityRepository } from '../domain/identity-kernel.js';
import {
  identityEnvelopeRecoveryFixture,
  recoveryFixtureId as id,
} from '../domain/identity-envelope-recovery.test-fixture.js';
function fixture() {
  const f = identityEnvelopeRecoveryFixture();
  const input = {
    participantId: f.enrollment.participantId,
    privacyDomainId: f.enrollment.privacyDomainId,
    recoveryId: id(400),
    principalId: f.enrollment.administratorPrincipalIds[0],
    checkerPrincipalId: f.enrollment.administratorPrincipalIds[1],
    operationId: id(410),
    note: 'Independent review of actual signer repair and retained original effects.',
  };
  const query = vi
    .fn()
    .mockResolvedValueOnce({ rowCount: 1, rows: [{ enrollment: f.enrollment }] })
    .mockResolvedValueOnce({ rowCount: 1, rows: [{ reviewedAt: f.now }] });
  const review = () => postReviewIdentityEnvelopeRecovery({ query } as never, input);
  return { input, query, review };
}
it('uses the existing governed review identity, stores a note digest and fences terminal exact cases', async () => {
  const f = fixture();
  await expect(f.review()).resolves.toMatchObject({ postReviewStatus: 'REVIEWED' });
  expect(f.query.mock.calls[1]![0]).toContain("c.state in ('COMPLETED','REVOKED','EXPIRED')");
  expect(f.query.mock.calls[1]![0]).toContain('c.reviewed_at is null');
  expect(f.query.mock.calls[1]![1][5]).toBeInstanceOf(Buffer);
  expect(f.query.mock.calls[1]![1]).not.toContain(f.input.note);
});
it('retains the older recovery owner when the ID is not a signer-repair case', async () => {
  const f = fixture();
  f.query.mockReset().mockResolvedValue({ rowCount: 0, rows: [] });
  expect(await f.review()).toBeUndefined();
  expect(f.query).toHaveBeenCalledOnce();
});
it('rejects self-review and subject/executor or nonterminal denial without accepting review', async () => {
  const f = fixture();
  f.input.checkerPrincipalId = f.input.principalId;
  await expect(f.review()).rejects.toThrow();
  expect(f.query).toHaveBeenCalledOnce();
  const denied = fixture();
  denied.query
    .mockReset()
    .mockResolvedValueOnce({ rowCount: 1, rows: [{}] })
    .mockResolvedValueOnce({ rowCount: 0, rows: [] });
  await expect(denied.review()).rejects.toThrow();
});
function readFixture() {
  const f = identityEnvelopeRecoveryFixture();
  const intent = identityEnvelopeRecoveryIntent.parse({
    schema: 'pc.identity.identity-envelope-recovery-intent',
    schemaVersion: 1,
    purpose: 'IDENTITY_ENVELOPE_SIGNER_REPAIR_ONLY',
    recoveryId: id(400),
    enrollmentId: f.enrollment.enrollmentId,
    enrollmentRevision: '1',
    enrollmentDigest: canonicalAuthorizationDigest(f.enrollment),
    rotationId: id(401),
    creationOperationId: id(402),
    sourceParticipantEpoch: '7',
    sourceIssuerPrincipalEpoch: '1',
    sourceIssuerCredentialEpoch: '1',
    oldTrustDigest: f.enrollment.oldTrustDigest,
    selectionAdmissionVersion: '1',
    validFrom: f.now.toISOString(),
    validUntil: new Date(f.now.getTime() + 900000).toISOString(),
    postReviewRequired: true,
  });
  const row = {
    document: f.enrollment,
    pin: f.trust,
    signature: Buffer.from(f.signed.signature, 'base64url'),
    documentDigest: Buffer.from(canonicalAuthorizationDigest(f.enrollment).slice(7), 'hex'),
    intent,
    intentDigest: Buffer.from(canonicalAuthorizationDigest(intent).slice(7), 'hex'),
    state: 'REVOKED',
    revision: '4',
    activatedOperationId: id(410),
    reviewedAt: null,
    reviewerId: null,
    reviewOperationId: null,
    noteDigest: null,
    now: new Date(f.now.getTime() + 3600000),
    collision: false,
  };
  const query = vi
    .fn<
      (sql: string, values?: readonly unknown[]) => Promise<{ rowCount: number; rows: unknown[] }>
    >()
    .mockResolvedValue({ rowCount: 1, rows: [row] });
  const read = () =>
    readIdentityEnvelopeRecoveryReview(
      { query } as never,
      f.enrollment.participantId,
      f.enrollment.privacyDomainId,
      intent.recoveryId,
    );
  return { ...f, intent, row, query, read };
}
it('ordinary review read authenticates original custody/intent and preserves signer purpose without lease authority', async () => {
  const f = readFixture();
  const read = await f.read();
  expect(read).toMatchObject({
    effect: {
      purpose: 'IDENTITY_ENVELOPE_SIGNER_REPAIR_ONLY',
      state: 'REVOKED',
      revision: '4',
      authority: 'NONE',
      postReviewStatus: 'REQUIRED',
      intentDigest: canonicalAuthorizationDigest(f.intent),
      activationOperationId: id(410),
    },
    operationId: null,
  });
  expect(read?.effect).not.toHaveProperty('subjectId');
  expect(read?.effect).not.toHaveProperty('purposeDigest');
  expect(read?.effect).not.toHaveProperty('signature');
  expect(f.query.mock.calls.some(([sql]) => /^(insert|update|delete)/iu.test(String(sql)))).toBe(
    false,
  );
});
it.each([
  'foreign-scope',
  'changed-custody',
  'changed-intent',
  'collision',
  'partial-review',
] as const)('denies %s signer review readback', async (failure) => {
  const f = readFixture();
  if (failure === 'foreign-scope') f.enrollment.privacyDomainId = id(999);
  if (failure === 'changed-custody') f.row.signature = Buffer.alloc(64, 0);
  if (failure === 'changed-intent') f.row.intentDigest = Buffer.alloc(32, 9);
  if (failure === 'collision') f.row.collision = true;
  if (failure === 'partial-review') Object.assign(f.row, { reviewerId: id(600) });
  await expect(f.read()).rejects.toThrow();
});
it('returns no signer projection on an absent scoped case without manufacturing an account case', async () => {
  const f = readFixture();
  f.query.mockResolvedValue({ rowCount: 0, rows: [] });
  await expect(f.read()).resolves.toBeUndefined();
});
it('locks original signer review revision and refuses cross-owner identity collision', async () => {
  const query = vi
    .fn<
      (sql: string, values?: readonly unknown[]) => Promise<{ rowCount: number; rows: unknown[] }>
    >()
    .mockResolvedValue({ rowCount: 1, rows: [{ revision: '4', collision: false }] });
  expect(
    await lockIdentityEnvelopeRecoveryReviewVersion({ query } as never, id(2), id(3), id(400)),
  ).toBe('4');
  expect(query.mock.calls[0]?.[0]).toContain('for update of c');
  query.mockResolvedValue({ rowCount: 1, rows: [{ revision: '4', collision: true }] });
  await expect(
    lockIdentityEnvelopeRecoveryReviewVersion({ query } as never, id(2), id(3), id(400)),
  ).rejects.toThrow();
});
it.each(['ID-OP-RECOVERY-POST-REVIEW', 'ID-OP-RECOVERY-COMPLETE'] as const)(
  'selects signer revision only for exact %s aggregate',
  async (operation) => {
    const query = vi.fn<
      (sql: string, values?: readonly unknown[]) => Promise<{ rowCount: number; rows: unknown[] }>
    >(async (sql: string) =>
      sql.includes('from control.platform_recovery_case')
        ? { rowCount: 1, rows: [{ revision: '4', collision: false }] }
        : { rowCount: 1, rows: [{ row_version: '7' }] },
    );
    const version = Reflect.get(
      PostgresIdentityRepository.prototype,
      'currentAggregateVersion',
    ) as (
      client: unknown,
      p: string,
      type: string,
      id: string,
      privacy: string,
      operation: string,
    ) => Promise<string>;
    expect(
      await version.call(
        Object.create(PostgresIdentityRepository.prototype),
        { query },
        id(2),
        'recovery',
        id(400),
        id(3),
        operation,
      ),
    ).toBe(operation === 'ID-OP-RECOVERY-POST-REVIEW' ? '4' : '7');
    expect(query).toHaveBeenCalledOnce();
    if (operation === 'ID-OP-RECOVERY-POST-REVIEW')
      expect(query.mock.calls[0]?.[1]).toEqual([id(2), id(3), id(400)]);
    else expect(query.mock.calls[0]?.[0]).toContain('control.recovery_challenge');
  },
);
