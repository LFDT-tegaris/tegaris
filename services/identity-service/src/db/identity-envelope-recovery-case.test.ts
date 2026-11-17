import type { PoolClient } from 'pg';
import { beforeEach, expect, it, vi } from 'vitest';
import {
  identityEnvelopeRecoveryFixture,
  recoveryFixtureId as id,
} from '../domain/identity-envelope-recovery.test-fixture.js';
import { canonicalAuthorizationDigest } from '../contracts/authorization.js';
import {
  createIdentityEnvelopeRecoveryCase,
  readIdentityEnvelopeRecoveryCeremony,
} from './identity-envelope-recovery-case.js';
import {
  assertPlatformRecoveryCeremony,
  type PlatformRecoveryProof,
} from '../domain/platform-recovery-ceremony.js';

const read = vi.hoisted(() => ({ source: vi.fn(), proofs: vi.fn() }));
vi.mock('./identity-envelope-recovery-source.js', () => ({
  readIdentityEnvelopeRecoverySource: read.source,
}));
vi.mock('./platform-recovery-case.js', () => ({ readRecoveryCeremonyProofs: read.proofs }));
beforeEach(() => vi.resetAllMocks());
function fixture() {
  const f = identityEnvelopeRecoveryFixture();
  const source = {
    enrollment: f.enrollment,
    enrollmentRevision: '1',
    now: f.now,
    root: {
      grantable: {
        validUntilNs: (BigInt(Date.parse(f.enrollment.validUntil)) * 1000000n).toString(),
      },
    },
    issuer: {
      workloadParticipantEpoch: '7',
      workloadPrincipalEpoch: '1',
      workloadCredentialEpoch: '1',
      credentialValidUntilNs: (BigInt(Date.parse(f.enrollment.validUntil)) * 1000000n).toString(),
    },
  };
  read.source.mockResolvedValue(source);
  read.proofs.mockResolvedValue([]);
  const actor = {
    participantId: f.enrollment.participantId,
    principalId: f.enrollment.recoveryPrincipal.principalId,
    sessionToken: 'unit-only',
    platform: true,
  };
  const query = vi.fn().mockResolvedValue({ rowCount: 0, rows: [] });
  const client = { query } as unknown as PoolClient;
  return { ...f, source, actor, client, query };
}
it('reserves only fresh rotation/operation IDs; QA cannot enlarge the signer repair lease', async () => {
  const f = fixture();
  const result = await createIdentityEnvelopeRecoveryCase(
    f.client,
    f.actor,
    f.enrollment.enrollmentId,
    true,
    { profile: 'LOCAL_QA', leaseMs: 3600000, administratorMs: 86400000 },
  );
  expect(result.authority).toBe('NONE');
  expect(result.state).toBe('DRAFT');
  expect(Date.parse(result.intent.validUntil) - Date.parse(result.intent.validFrom)).toBe(900000);
  expect(result.intent.postReviewRequired).toBe(true);
  expect(
    new Set([result.intent.rotationId, result.intent.creationOperationId, result.intent.recoveryId])
      .size,
  ).toBe(3);
  expect(result.intentDigest).toBe(canonicalAuthorizationDigest(result.intent));
  const writes = f.query.mock.calls.filter(([sql]) => /^(insert|update|delete)/iu.test(sql));
  expect(writes).toHaveLength(1);
  expect(writes[0]![0]).toContain('signer_repair_enrollment_id');
  expect(writes[0]![0]).not.toMatch(
    /(assignment|authority_envelope|signing_key_rotation|approval_request)/u,
  );
});
it('keeps the C17 intent within fifteen minutes when installation custody remains valid longer', async () => {
  const f = fixture();
  const custodyEnd = new Date(f.now.getTime() + 3600000).toISOString();
  f.enrollment.validUntil = custodyEnd;
  f.source.root.grantable.validUntilNs = (BigInt(Date.parse(custodyEnd)) * 1000000n).toString();
  f.source.issuer.credentialValidUntilNs = f.source.root.grantable.validUntilNs;
  const result = await createIdentityEnvelopeRecoveryCase(
    f.client,
    f.actor,
    f.enrollment.enrollmentId,
    true,
    { profile: 'C17', leaseMs: 900000, administratorMs: 3600000 },
  );
  expect(result.authority).toBe('NONE');
  expect(Date.parse(result.intent.validUntil) - Date.parse(result.intent.validFrom)).toBe(900000);
  expect(f.enrollment.validUntil).toBe(custodyEnd);
  expect(Date.parse(result.intent.validUntil)).toBeLessThan(Date.parse(custodyEnd));
  expect(result.intent.postReviewRequired).toBe(true);
});
it.each(['enrollment', 'Root', 'issuer'] as const)(
  'retains the earlier %s bound under normal C17 settings',
  async (bound) => {
    const f = fixture();
    const earlier = f.now.getTime() + 45000;
    if (bound === 'enrollment') f.enrollment.validUntil = new Date(earlier).toISOString();
    if (bound === 'Root')
      f.source.root.grantable.validUntilNs = (BigInt(earlier) * 1000000n).toString();
    if (bound === 'issuer')
      f.source.issuer.credentialValidUntilNs = (BigInt(earlier) * 1000000n).toString();
    const result = await createIdentityEnvelopeRecoveryCase(
      f.client,
      f.actor,
      f.enrollment.enrollmentId,
      true,
      { profile: 'C17', leaseMs: 900000, administratorMs: 3600000 },
    );
    expect(Date.parse(result.intent.validUntil)).toBe(earlier);
  },
);
it('uses configured shorter lifetimes and caps by the live issuer expiry', async () => {
  const f = fixture();
  f.source.issuer.credentialValidUntilNs = (BigInt(f.now.getTime() + 45000) * 1000000n).toString();
  const result = await createIdentityEnvelopeRecoveryCase(
    f.client,
    f.actor,
    f.enrollment.enrollmentId,
    true,
    { profile: 'C17', leaseMs: 60000, administratorMs: 3600000 },
  );
  expect(Date.parse(result.intent.validUntil) - Date.parse(result.intent.validFrom)).toBe(45000);
});
it.each([
  'custodian',
  'live-case',
  'unreviewed-case',
  'unavailable-source',
  'expired-source',
  'qa-disabled',
])('rejects %s without inserting a case', async (failure) => {
  const f = fixture();
  if (failure === 'custodian') f.actor.principalId = f.enrollment.custodians[0].principalId;
  if (failure === 'live-case') f.query.mockResolvedValue({ rowCount: 1, rows: [{}] });
  if (failure === 'unreviewed-case') {
    f.query.mockResolvedValue({ rowCount: 1, rows: [{}] });
  }
  if (failure === 'unavailable-source')
    read.source.mockRejectedValue(new Error('source unavailable'));
  if (failure === 'expired-source')
    f.source.issuer.credentialValidUntilNs = (BigInt(f.now.getTime()) * 1000000n).toString();
  await expect(
    createIdentityEnvelopeRecoveryCase(
      f.client,
      f.actor,
      f.enrollment.enrollmentId,
      failure !== 'qa-disabled',
      { profile: 'LOCAL_QA', leaseMs: 3600000, administratorMs: 86400000 },
    ),
  ).rejects.toThrow();
  expect(f.query.mock.calls.some(([sql]) => sql.startsWith('insert'))).toBe(false);
  if (failure === 'unreviewed-case') {
    expect(f.query.mock.calls[0]![0]).toContain(
      'c.activated_at is not null and c.reviewed_at is null',
    );
    expect(f.query.mock.calls[0]![1][2]).toBe(f.enrollment.issuerPrincipalId);
  }
});
it('requires the exact stored immutable intent and current source on ceremony read', async () => {
  const f = fixture();
  const result = await createIdentityEnvelopeRecoveryCase(
    f.client,
    f.actor,
    f.enrollment.enrollmentId,
    true,
  );
  f.query.mockResolvedValue({
    rowCount: 1,
    rows: [
      {
        intent: result.intent,
        digest: Buffer.from(result.intentDigest.slice(7), 'hex'),
        state: 'REQUESTED',
      },
    ],
  });
  await expect(
    readIdentityEnvelopeRecoveryCeremony(
      f.client,
      f.actor,
      f.enrollment.enrollmentId,
      result.intent.recoveryId,
      true,
    ),
  ).resolves.toMatchObject({ state: 'REQUESTED' });
  f.source.issuer.workloadPrincipalEpoch = '2';
  await expect(
    readIdentityEnvelopeRecoveryCeremony(
      f.client,
      f.actor,
      f.enrollment.enrollmentId,
      result.intent.recoveryId,
      true,
    ),
  ).rejects.toThrow();
});
it('requires a fresh request plus both distinct custodians and rejects mismatched recovery purposes', async () => {
  const f = fixture();
  const result = await createIdentityEnvelopeRecoveryCase(
    f.client,
    f.actor,
    f.enrollment.enrollmentId,
    true,
  );
  const proofs: PlatformRecoveryProof[] = [
    f.enrollment.recoveryPrincipal,
    ...f.enrollment.custodians,
  ].map((v, index) => ({
    ...v,
    proofId: id(200 + index),
    sessionId: id(210 + index),
    sessionEpoch: '1',
    phase: index === 0 ? 'REQUEST' : 'APPROVE',
    intentDigest: result.intentDigest,
    verifiedAt: f.now,
  }));
  const assert = (input = proofs) =>
    assertPlatformRecoveryCeremony(
      f.enrollment,
      result.intent,
      'REQUESTED',
      input,
      'ACTIVATE',
      f.actor.principalId,
      f.now,
    );
  expect(() => assert()).not.toThrow();
  expect(() => assert(proofs.slice(0, 2))).toThrow();
  expect(() => assert([proofs[0]!, proofs[1]!, proofs[1]!])).toThrow();
  expect(() =>
    assert(proofs.map((v) => ({ ...v, verifiedAt: new Date(f.now.getTime() - 300000) }))),
  ).toThrow();
  for (const schema of [
    'pc.identity.platform-recovery-intent',
    'pc.identity.discovery-certificate-recovery-intent',
  ] as const)
    expect(() =>
      assertPlatformRecoveryCeremony(
        f.enrollment,
        { ...result.intent, schema } as never,
        'DRAFT',
        [],
        'REQUEST',
        f.actor.principalId,
        f.now,
      ),
    ).toThrow();
});
