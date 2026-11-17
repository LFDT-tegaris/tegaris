import { readDiscoveryReceivingProof } from './discovery-preapproval-proof.js';
import { beforeEach, expect, it, vi } from 'vitest';
import {
  stageMutationCandidateInTransaction,
  type MutationCandidateContext,
} from './mutation-candidate-store.js';
import { fenceBoundAuthorities } from './authority-fence.js';
import { trustFixture, id } from '../domain/discovery-certificate-recovery.test-fixture.js';
import { discoveryCertificateRotationCandidate } from '../contracts/discovery-certificate-recovery.js';
import { canonicalAuthorizationDigest } from '../contracts/authorization.js';
vi.mock('./authority-fence.js', async (original) => ({
  ...(await original<typeof import('./authority-fence.js')>()),
  fenceBoundAuthorities: vi.fn(),
}));
vi.mock('./platform-recovery-commit-purpose.js', async (original) => ({
  ...(await original<typeof import('./platform-recovery-commit-purpose.js')>()),
  discoveryCertificateRecoveryContextEligible: vi.fn().mockResolvedValue(true),
}));
vi.mock('./discovery-preapproval-proof.js', () => ({ readDiscoveryReceivingProof: vi.fn() }));
const receiving = {
  sessionToken: 'authenticated-native-session',
  verifier: { verifyCanonicalAssertion: vi.fn() },
};
beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(readDiscoveryReceivingProof).mockResolvedValue({
    mfaChallengeId: id(980),
    verificationOperationId: id(981),
    evidenceDigest: 'sha256:' + 'e'.repeat(64),
  });
});
function fixture() {
  const { source, intent } = trustFixture(),
    candidate = discoveryCertificateRotationCandidate(intent.certificateRecovery);
  const authorization = {
    participantId: source.enrollment.participantId,
    privacyDomainId: source.enrollment.privacyDomainId,
    principalId: intent.administrators[0].principalId,
    principalEpoch: '4',
    participantEpoch: '1',
    sessionId: id(900),
    sessionEpoch: '1',
    assignmentId: id(901),
    assignmentRowVersion: '1',
    authorityEnvelopeId: id(902),
    authorityEpoch: '1',
    delegationEpoch: '0',
  };
  const context: MutationCandidateContext = {
    participantId: authorization.participantId,
    privacyDomainId: authorization.privacyDomainId,
    authorization,
    actionIntentId: 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
    actionIntentDigest: 'sha256:' + 'a'.repeat(64),
    catalogOperationId: 'ID-OP-WORKLOAD-ROTATE',
    resourceType: 'participant',
    operationClass: 'UPDATE',
    resourceId: candidate.replacedCredentialId,
    serverGeneratedResourceId: false,
    expectedRevision: intent.certificateRecovery.predecessorRevision,
    idempotencyKey: 'unit-retained-original-business-key',
    candidateDigest: canonicalAuthorizationDigest(candidate),
    candidate,
  };
  let row = {
    mutationCandidateId: id(903),
    attempt: '1',
    resourceId: context.resourceId,
    candidateDigest: Buffer.from(context.candidateDigest.slice(7), 'hex'),
    candidateDocument: candidate,
    expectedRevision: context.expectedRevision,
    state: 'PROPOSED',
    unexpired: false,
    current: true,
    makerAuthority: { ...authorization, authorityEnvelopeId: id(904) },
  };
  let count = 1;
  const query = vi.fn(async (sql: string) => {
    if (sql.startsWith('select principal_id'))
      return {
        rowCount: 1,
        rows: [{ principalId: intent.certificateRecovery.workloadPrincipalId }],
      };
    if (sql.includes('select envelope.representation'))
      return { rowCount: 1, rows: [{ representation: 'RECOVERY_V1', recoveryIntent: intent }] };
    if (sql.includes('as "makerAuthority"'))
      return { rowCount: count, rows: count === 2 ? [row, row] : [row] };
    if (sql.includes('insert into control.mutation_candidate')) {
      row = {
        ...row,
        mutationCandidateId: id(905),
        attempt: '2',
        unexpired: true,
        makerAuthority: authorization,
      };
      return { rowCount: 1, rows: [{ resourceId: context.resourceId }] };
    }
    return { rowCount: 0, rows: [] };
  });
  return {
    context,
    query,
    client: { query } as never,
    setAmbiguous: () => {
      count = 2;
    },
  };
}
it('retains the business tuple while declaring source and participant write fences before the successor insert', async () => {
  const v = fixture();
  await expect(
    stageMutationCandidateInTransaction(v.client, v.context, {}, receiving),
  ).resolves.toBe(v.context.resourceId);
  expect(fenceBoundAuthorities).toHaveBeenCalledWith(
    v.client,
    v.context.participantId,
    expect.any(Array),
    expect.objectContaining({
      participant: [{ id: v.context.participantId, write: true }],
      credential: [{ id: v.context.resourceId, write: true }],
    }),
  );
  const writes = v.query.mock.calls.filter(([sql]) =>
    sql.includes('insert into control.mutation_candidate'),
  );
  expect(writes).toHaveLength(1);
  expect(writes[0]![0]).toContain('DISCOVERY_PREAPPROVAL_CONTINUE');
  expect(writes[0]![0]).toContain('old.idempotency_key');
  expect(writes[0]![0]).toContain('old.candidate_document');
});
it.each(['body', 'revision', 'digest', 'ambiguity'])(
  'rejects changed or ambiguous original %s before successor writes',
  async (failure) => {
    const v = fixture();
    let context = v.context;
    if (failure === 'body')
      context = {
        ...context,
        candidate: { ...(context.candidate as object), credentialId: id(950) },
      };
    if (failure === 'revision') context = { ...context, expectedRevision: '99' };
    if (failure === 'digest') context = { ...context, candidateDigest: 'sha256:' + 'f'.repeat(64) };
    if (failure === 'ambiguity') v.setAmbiguous();
    await expect(stageMutationCandidateInTransaction(v.client, context)).rejects.toBeDefined();
    expect(v.query.mock.calls.some(([sql]) => /^\s*insert\b/u.test(sql))).toBe(false);
  },
);

it.each(['missing authenticator', 'unqualified proof'])(
  'does not insert a continuation with %s',
  async (failure) => {
    const v = fixture();
    if (failure === 'unqualified proof')
      vi.mocked(readDiscoveryReceivingProof).mockResolvedValue(undefined);
    await expect(
      stageMutationCandidateInTransaction(
        v.client,
        v.context,
        {},
        failure === 'missing authenticator' ? undefined : receiving,
      ),
    ).rejects.toMatchObject({ code: 'PC-AUTH-0005' });
    expect(v.query.mock.calls.some(([sql]) => /^\s*insert\b/u.test(sql))).toBe(false);
  },
);
