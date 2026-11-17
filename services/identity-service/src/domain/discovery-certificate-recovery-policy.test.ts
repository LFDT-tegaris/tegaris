import type { PoolClient } from 'pg';
import { expect, it, vi } from 'vitest';
import { canonicalAuthorizationDigest } from '../contracts/authorization.js';
import { discoveryCertificateRotationCandidate } from '../contracts/discovery-certificate-recovery.js';
import { trustFixture, id } from './discovery-certificate-recovery.test-fixture.js';
import { discoveryCertificateRecoveryPolicyScope } from './discovery-certificate-recovery-policy.js';
import type { PolicyAuthorizationRequest } from './policy-authorization.js';

function fixture() {
  const f = trustFixture();
  const maker = f.intent.administrators[0].principalId;
  const checker = f.intent.administrators[1].principalId;
  const authorityEnvelopeId = id(700);
  const source = { authorityEnvelopeId, recoveryId: f.intent.recoveryId, intent: f.intent };
  const candidate = discoveryCertificateRotationCandidate(f.intent.certificateRecovery);
  const row = {
    candidate,
    candidateDigest: Buffer.from(canonicalAuthorizationDigest(candidate).slice(7), 'hex'),
    expectedRevision: f.intent.certificateRecovery.predecessorRevision,
    resourceId: f.intent.certificateRecovery.predecessorCredentialId,
    makerSessionId: id(701),
    approvalRevision: '1',
    checkerPrincipalId: checker,
  };
  const query = vi.fn().mockResolvedValueOnce({ rowCount: 1, rows: [source] });
  const client = { query } as unknown as PoolClient;
  const input: PolicyAuthorizationRequest = {
    sessionToken: `${f.source.enrollment.participantId}.${id(701)}`,
    privacyDomainId: f.source.enrollment.privacyDomainId,
    actionIntentId: 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
    resourceId: f.intent.certificateRecovery.predecessorCredentialId,
    stepUpRequired: false,
    catalogOperationId: 'ID-OP-WORKLOAD-ROTATE',
    proposedMutation: {
      candidate,
      expectedRevision: f.intent.certificateRecovery.predecessorRevision,
    },
  };
  const run = (request = input, actor = maker) =>
    discoveryCertificateRecoveryPolicyScope(
      client,
      f.source.enrollment.participantId,
      actor,
      id(701),
      request,
    );
  return { f, maker, checker, source, candidate, row, authorityEnvelopeId, query, input, run };
}

it('admits the server-parsed rotation only through the current exact recovery owner', async () => {
  const v = fixture();
  v.query.mockResolvedValueOnce({
    rowCount: 1,
    rows: [{ intent: v.f.intent, recoveryId: v.f.intent.recoveryId }],
  });
  await expect(v.run()).resolves.toEqual({ authorityEnvelopeId: v.authorityEnvelopeId });
  expect(v.query.mock.calls[1]![1]).toEqual([
    v.f.source.enrollment.participantId,
    v.authorityEnvelopeId,
    v.input.privacyDomainId,
    v.maker,
  ]);
});

it.each([
  'changed key',
  'changed successor',
  'foreign predecessor',
  'changed revision',
  'checker proposing',
])('denies %s against the enrolled rotation, without generic Platform fallback', async (reason) => {
  const v = fixture();
  v.query.mockResolvedValueOnce({
    rowCount: 1,
    rows: [{ intent: v.f.intent, recoveryId: v.f.intent.recoveryId }],
  });
  const candidate = { ...v.candidate };
  if (reason === 'changed key') candidate.publicKeySpkiDer += 'AA';
  if (reason === 'changed successor') candidate.credentialId = id(900);
  const input = {
    ...v.input,
    proposedMutation: {
      candidate,
      expectedRevision:
        reason === 'changed revision' ? '99' : v.f.intent.certificateRecovery.predecessorRevision,
    },
    resourceId: reason === 'foreign predecessor' ? id(901) : v.input.resourceId,
  };
  await expect(v.run(input, reason === 'checker proposing' ? v.checker : v.maker)).resolves.toBe(
    false,
  );
});

it('leaves ordinary non-recovery grants with their existing owner', async () => {
  const v = fixture();
  v.query.mockReset().mockResolvedValue({ rowCount: 0, rows: [] });
  await expect(v.run()).resolves.toBeUndefined();
});

it.each(['ambiguous case', 'malformed intent', 'wrong case ID'])(
  'fails closed on %s',
  async (reason) => {
    const v = fixture();
    const source: { authorityEnvelopeId: string; recoveryId: string; intent: unknown } = {
      ...v.source,
    };
    if (reason === 'malformed intent') source.intent = { ...v.source.intent, schemaVersion: 99 };
    if (reason === 'wrong case ID') source.recoveryId = id(999);
    v.query
      .mockReset()
      .mockResolvedValue({ rowCount: reason === 'ambiguous case' ? 2 : 1, rows: [source] });
    await expect(v.run()).resolves.toBe(false);
  },
);

it('admits the exact approved staged mutation, never a different revision or body', async () => {
  const v = fixture();
  v.query.mockResolvedValueOnce({ rowCount: 1, rows: [v.row] });
  await expect(
    v.run({
      ...v.input,
      proposedMutation: undefined,
      stagedMutation: {
        candidateDigest: canonicalAuthorizationDigest(v.candidate),
        expectedRevision: v.row.expectedRevision,
      },
    }),
  ).resolves.toEqual({ authorityEnvelopeId: v.authorityEnvelopeId });
  expect(v.query.mock.calls[1]![0]).toContain('predecessor_candidate_id');
  const w = fixture();
  w.query.mockResolvedValueOnce({ rowCount: 1, rows: [w.row] });
  await expect(
    w.run({
      ...w.input,
      proposedMutation: undefined,
      stagedMutation: {
        candidateDigest: canonicalAuthorizationDigest(w.candidate),
        expectedRevision: '99',
      },
    }),
  ).resolves.toBe(false);
});

it.each([
  'original',
  'ambiguous digest',
  'different enrolled candidate',
  'foreign maker',
  'different maker session',
])('resolves %s approval creation from the authoritative staged subject', async (reason) => {
  const v = fixture();
  const row =
    reason === 'different enrolled candidate'
      ? {
          ...v.row,
          candidate: {
            ...v.candidate,
            credentialId: id(999),
          },
        }
      : { ...v.row, makerSessionId: reason === 'different maker session' ? id(999) : id(701) };
  v.query.mockResolvedValueOnce({ rowCount: 1, rows: [row] });
  v.query.mockResolvedValueOnce({ rows: [{ count: reason === 'ambiguous digest' ? '2' : '1' }] });
  const input = {
    ...v.input,
    catalogOperationId: undefined,
    proposedMutation: undefined,
    actionIntentId: 'ACT-APPROVAL_REQUESTS_CREATE_RESOURCE-V1',
    resourceId: reason === 'foreign maker' ? v.checker : v.maker,
    approvalCandidateDigest: canonicalAuthorizationDigest(v.candidate),
  };
  await expect(v.run(input)).resolves.toEqual(
    reason === 'original'
      ? {
          authorityEnvelopeId: v.authorityEnvelopeId,
        }
      : false,
  );
});

it.each(['checker', 'maker', 'foreign checker', 'changed proof', 'unrelated approval'])(
  'bounds the %s decision to its original maker candidate and exact checker',
  async (reason) => {
    const v = fixture();
    v.query.mockResolvedValueOnce({
      rowCount: reason === 'unrelated approval' ? 0 : 1,
      rows: [{ ...v.row, checkerPrincipalId: reason === 'foreign checker' ? id(998) : v.checker }],
    });

    const approvalId = id(800);
    const proof = canonicalAuthorizationDigest({
      actionIntentId: 'ACT-POLICY_APPROVE_REQUEST-V1',
      approvalRequestId: `urn:openpc:resource:${approvalId}`,
      candidateDigest: canonicalAuthorizationDigest(v.candidate),
      expectedRevision: '1',
      decision: 'APPROVE',
    });
    const input = {
      ...v.input,
      catalogOperationId: undefined,
      proposedMutation: undefined,
      actionIntentId: 'ACT-POLICY_APPROVE_REQUEST-V1',
      resourceId: approvalId,
      stepUpCandidateDigest: reason === 'changed proof' ? `sha256:${'0'.repeat(64)}` : proof,
    };
    await expect(v.run(input, reason === 'maker' ? v.maker : v.checker)).resolves.toEqual(
      reason === 'checker' ? { authorityEnvelopeId: v.authorityEnvelopeId } : false,
    );
  },
);

it('permits consumed original approval readback only through a current exact READ grant', async () => {
  const v = fixture();
  v.query.mockResolvedValueOnce({ rowCount: 1, rows: [v.row] });
  await expect(
    v.run(
      {
        ...v.input,
        proposedMutation: undefined,
        catalogOperationId: undefined,
        actionIntentId: 'ACT-APPROVAL_REQUESTS_READ_RESOURCE-V1',
        resourceId: id(800),
      },
      v.checker,
    ),
  ).resolves.toEqual({ authorityEnvelopeId: v.authorityEnvelopeId });
  expect(v.query.mock.calls[1]![1].slice(8)).toEqual([true, id(701)]);
  expect(v.query.mock.calls[1]![0]).toContain(
    "c.state='CONSUMED' and c.consumed_operation_id is not null",
  );
  const w = fixture();
  w.query.mockReset().mockResolvedValue({ rowCount: 0, rows: [] });
  await expect(
    w.run(
      {
        ...w.input,
        proposedMutation: undefined,
        catalogOperationId: undefined,
        actionIntentId: 'ACT-APPROVAL_REQUESTS_READ_RESOURCE-V1',
        resourceId: id(800),
      },
      w.checker,
    ),
  ).resolves.toBeUndefined();
});
