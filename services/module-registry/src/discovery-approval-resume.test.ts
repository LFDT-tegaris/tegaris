import { generateKeyPairSync } from 'node:crypto';
import { expect, it, vi } from 'vitest';
import type { PoolClient } from 'pg';
import {
  projectApprovalCandidate,
  qualifyApprovalCandidateSuccessor,
} from './approval-candidate-contract.js';
import { resumeApprovalSchema } from './public-approval-http.js';
import { canonicalAuthorizationDigest } from '../../identity-service/src/contracts/authorization.js';
import { readDiscoveryApprovalResumePurpose } from '../../identity-service/src/db/discovery-approval-resume.js';
import { readPlatformRecoveryApprovalResumePurpose } from '../../identity-service/src/db/platform-recovery-approval-resume.js';
import { platformRecoveryApprovalResumeReason } from '../../identity-service/src/contracts/platform-recovery.js';
const id = (n: number) => '01990000-0000-7000-8000-' + String(n).padStart(12, '0');
const candidate = {
  replacedCredentialId: id(1),
  credentialId: id(2),
  publicKeySpkiDer: generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
    .publicKey.export({ format: 'der', type: 'spki' })
    .toString('base64'),
};
const digest = canonicalAuthorizationDigest(candidate);
it('keeps raw successor cardinality and its full stored approval relation closed', () => {
  expect(qualifyApprovalCandidateSuccessor(0, [], true)).toBeNull();
  expect(
    qualifyApprovalCandidateSuccessor(1, [{ approvalId: id(15), compatible: true }], false),
  ).toBe(id(15));
  for (const [count, links] of [
    [1, []],
    [1, [{ approvalId: null, compatible: false }]],
    [1, [{ approvalId: id(15), compatible: false }]],
    [2, [{ approvalId: id(15), compatible: true }]],
    [
      1,
      [
        { approvalId: id(15), compatible: true },
        { approvalId: id(16), compatible: true },
      ],
    ],
    [0, [{ approvalId: id(15), compatible: true }]],
  ] as const)
    expect(() => qualifyApprovalCandidateSuccessor(count, links, count === 0)).toThrow(
      'PC-POLICY-2001',
    );
  expect(() => qualifyApprovalCandidateSuccessor(0, [], false)).toThrow('PC-POLICY-2001');
  expect(() =>
    qualifyApprovalCandidateSuccessor(1, [{ approvalId: id(15), compatible: true }], true),
  ).toThrow('PC-POLICY-2001');
});
it('discloses only the registered workload rotation tuple with the exact closed original body', () => {
  const input = {
    catalogOperationId: 'ID-OP-WORKLOAD-ROTATE',
    actionIntentId: 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
    resourceType: 'participant',
    operationClass: 'UPDATE',
    document: candidate,
    candidateDigest: digest,
  };
  expect(projectApprovalCandidate(input).candidate).toEqual(candidate);
  for (const changed of [
    { operationClass: 'CREATE' },
    { resourceType: 'principal' },
    { actionIntentId: 'ACT-APPROVAL_REQUESTS_UPDATE_RESOURCE-V1' },
    { candidateDigest: 'sha256:' + 'a'.repeat(64) },
    { document: { ...candidate, extra: 'not disclosed' } },
  ])
    expect(() => projectApprovalCandidate({ ...input, ...changed })).toThrow();
});
it('keeps receiving proof transport outside the strict public RESUME contract', () => {
  const body = {
    command: 'RESUME',
    actionIntentId: 'ACT-APPROVAL_REQUESTS_UPDATE_RESOURCE-V1',
    actionIntentDigest: 'sha256:' + 'b'.repeat(64),
    expectedRevision: '2',
    predecessorCandidateId: id(3),
    expectedAttempt: '2',
    candidateDigest: digest,
    reason: 'Preserve the exact original intent.',
  };
  expect(resumeApprovalSchema.parse(body)).toEqual(body);
  for (const extra of [
    { discoveryReceivingProof: { mfaChallengeId: id(4) } },
    { platformReceivingProof: { mfaChallengeId: id(4) } },
    { approvalRequestId: 'urn:openpc:resource:' + id(5) },
    { candidate: { credentialId: id(90) } },
  ])
    expect(resumeApprovalSchema.safeParse({ ...body, ...extra }).success).toBe(false);
});

it('resolves the original Platform activation and binds fresh approval metadata without changing its body', async () => {
  const original = { envelopeId: id(21) };
  const row = {
    approvalRevision: '2',
    candidateId: id(22),
    attempt: '1',
    candidateDigest: canonicalAuthorizationDigest(original),
    actionDigest: 'sha256:' + 'b'.repeat(64),
    candidate: original,
    resourceId: id(21),
    expectedRevision: '3',
  };
  const input = {
    participantId: id(10),
    privacyDomainId: id(11),
    principalId: id(12),
    authorityEnvelopeId: id(13),
    approvalId: id(23),
  };
  const query = vi.fn().mockResolvedValue({ rowCount: 1, rows: [row] });
  const selected = await readPlatformRecoveryApprovalResumePurpose(
    { query } as unknown as PoolClient,
    input,
  );
  expect(selected?.candidate).toEqual(original);
  expect(selected?.request).toEqual({
    command: 'RESUME',
    actionIntentId: 'ACT-APPROVAL_REQUESTS_UPDATE_RESOURCE-V1',
    actionIntentDigest: row.actionDigest,
    expectedRevision: '2',
    predecessorCandidateId: id(22),
    expectedAttempt: '1',
    candidateDigest: row.candidateDigest,
    reason: platformRecoveryApprovalResumeReason,
    approvalRequestId: 'urn:openpc:resource:' + id(23),
  });
  expect(selected?.requestDigest).toBe(canonicalAuthorizationDigest(selected!.request));
  expect(selected?.requestDigest).not.toBe(row.candidateDigest);
  expect(query.mock.calls[0]![0]).toContain('platform_recovery_approval_resume_subject_visible');
  expect(query.mock.calls[0]![0]).toContain('next.predecessor_candidate_id');
  expect(query.mock.calls[0]![1]).toEqual([id(10), id(11), id(12), id(13), id(23)]);
  for (const count of [0, 2]) {
    query.mockResolvedValueOnce({ rowCount: count, rows: [row] });
    expect(
      await readPlatformRecoveryApprovalResumePurpose({ query } as unknown as PoolClient, input),
    ).toBeUndefined();
  }
  query.mockResolvedValueOnce({
    rowCount: 1,
    rows: [{ ...row, candidate: { envelopeId: id(24) } }],
  });
  expect(
    await readPlatformRecoveryApprovalResumePurpose({ query } as unknown as PoolClient, input),
  ).toBeUndefined();
  query.mockClear();
  await readPlatformRecoveryApprovalResumePurpose({ query } as unknown as PoolClient, {
    ...input,
    requireLeaf: false,
  });
  expect(query.mock.calls[0]![0]).not.toContain('next.predecessor_candidate_id');
});
it.each([0, 2])(
  'denies %i historical subjects rather than inventing a native resume purpose',
  async (count) => {
    const client = {
      query: vi.fn().mockResolvedValue({ rowCount: count, rows: [] }),
    } as unknown as PoolClient;
    expect(
      await readDiscoveryApprovalResumePurpose(client, {
        participantId: id(10),
        privacyDomainId: id(11),
        principalId: id(12),
        authorityEnvelopeId: id(13),
        approvalId: id(14),
      }),
    ).toBeUndefined();
  },
);
it('binds every public resume semantic and the actual old approval URI without borrowing the rotation digest', async () => {
  const row = {
    approvalRevision: '2',
    candidateId: id(3),
    attempt: '2',
    candidateDigest: digest,
    actionDigest: 'sha256:' + 'b'.repeat(64),
    candidate,
    resourceId: id(1),
    expectedRevision: '1',
  };
  const query = vi.fn().mockResolvedValue({ rowCount: 1, rows: [row] });
  const result = await readDiscoveryApprovalResumePurpose({ query } as unknown as PoolClient, {
    participantId: id(10),
    privacyDomainId: id(11),
    principalId: id(12),
    authorityEnvelopeId: id(13),
    approvalId: id(14),
  });
  expect(result?.request.approvalRequestId).toBe('urn:openpc:resource:' + id(14));
  expect(result?.request.predecessorCandidateId).toBe(id(3));
  expect(result?.requestDigest).not.toBe(digest);
  for (const changed of [
    { reason: 'Different governance reason' },
    { expectedAttempt: '1' },
    { expectedRevision: '1' },
    { approvalRequestId: 'urn:openpc:resource:' + id(15) },
  ])
    expect(canonicalAuthorizationDigest({ ...result!.request, ...changed })).not.toBe(
      result!.requestDigest,
    );
  expect(query.mock.calls[0]![0]).toContain('openpc.discovery_approval_resume_eligible');
  row.candidateDigest = canonicalAuthorizationDigest({ ...candidate, credentialId: id(90) });
  expect(
    await readDiscoveryApprovalResumePurpose({ query } as unknown as PoolClient, {
      participantId: id(10),
      privacyDomainId: id(11),
      principalId: id(12),
      authorityEnvelopeId: id(13),
      approvalId: id(14),
    }),
  ).toBeUndefined();
});
