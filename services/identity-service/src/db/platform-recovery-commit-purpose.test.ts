import {
  trustFixture as discoveryTrustFixture,
  id as discoveryId,
} from '../domain/discovery-certificate-recovery.test-fixture.js';
import { discoveryCertificateRotationCandidate } from '../contracts/discovery-certificate-recovery.js';
import { createHash } from 'node:crypto';
import type { PoolClient } from 'pg';
import { createVerifiedWebAuthnAssertion } from '../domain/trust-adapter.js';
import { stepUpAuthorizationCandidate } from '../domain/step-up-authorization.js';
import { canonicalAuthorizationDigest } from '../contracts/authorization.js';
import { expect, it, vi } from 'vitest';
import { assertPlatformRecoveryCommitPurpose } from './platform-recovery-commit-purpose.js';
import {
  pendingPlatformRecoveryFixture,
  pendingExpiryPlatformRecoveryFixture,
  platformRecoveryFixture,
} from '../domain/platform-recovery.test-fixture.js';
import {
  authorityEnvelopeDigest,
  decodeEnvelopeProposal,
  encodeEnvelopeProposal,
} from '@openpc/security-kernel';
import { identityEnvelopeFixture } from '../../../../packages/security-kernel/src/identity-envelope/fixture.js';
import { assignmentCreateCandidate } from '../../../participant-service/src/contracts/assignment.js';
import { typedEnvelopeCreateCandidate } from '../../../participant-service/src/contracts/envelope.js';
import { approvalCreateIntent } from '../../../module-registry/src/public-approval-contract.js';
import { platformRecoveryApprovalResumeReason } from '../contracts/platform-recovery.js';

function fixture(continuation = false) {
  const f = continuation ? pendingPlatformRecoveryFixture() : platformRecoveryFixture();
  const query = vi.fn().mockResolvedValue({
    rowCount: 1,
    rows: [
      {
        representation: 'RECOVERY_V1',
        recoveryIntent: f.intent,
        current: true,
        recoveryId: f.intent.recoveryId,
      },
    ],
  });
  const client = { query } as unknown as PoolClient;
  const input = {
    participantId: f.source.enrollment.participantId,
    privacyDomainId: f.source.enrollment.privacyDomainId,
    authorityEnvelopeId: '018f0000-0000-7000-8000-000000000900',
    catalogOperationId: 'ID-OP-PLATFORM-SCOPE-PREPARE',
    resourceId: f.intent.preparation.replacementId,
    candidate: f.intent.preparation,
  };
  return { f, query, client, input };
}

it('rechecks the exact live selected purpose before its business callback can run', async () => {
  const f = fixture();
  await expect(assertPlatformRecoveryCommitPurpose(f.client, f.input)).resolves.toBeUndefined();
  expect(f.query).toHaveBeenCalledOnce();
  expect(f.query.mock.calls[0]![1]).toEqual([
    f.input.participantId,
    f.input.authorityEnvelopeId,
    f.input.privacyDomainId,
  ]);
});

it.each([
  'expired purpose',
  'missing case',
  'different operation',
  'changed candidate',
  'foreign resource',
  'distinct malformed purpose',
  'missing envelope',
])('denies %s at commit', async (failure) => {
  const f = fixture();
  if (failure === 'expired purpose')
    f.query.mockResolvedValue({
      rowCount: 1,
      rows: [{ representation: 'RECOVERY_V1', recoveryIntent: f.f.intent, current: false }],
    });
  if (failure === 'missing case')
    f.query.mockResolvedValue({
      rowCount: 1,
      rows: [{ representation: 'RECOVERY_V1', recoveryIntent: null, current: true }],
    });
  if (failure === 'different operation') f.input.catalogOperationId = 'ID-OP-WORKLOAD-ROTATE';
  if (failure === 'changed candidate')
    f.input.candidate = { ...f.f.intent.preparation, reason: 'different' };
  if (failure === 'foreign resource') f.input.resourceId = '018f0000-0000-7000-8000-000000000999';
  if (failure === 'distinct malformed purpose')
    f.query.mockResolvedValue({
      rowCount: 1,
      rows: [
        {
          representation: 'RECOVERY_V1',
          recoveryIntent: {
            ...f.f.intent,
            schema: 'pc.identity.discovery-certificate-recovery-intent',
          },
          current: true,
        },
      ],
    });
  if (failure === 'missing envelope') f.query.mockResolvedValue({ rowCount: 0, rows: [] });
  await expect(assertPlatformRecoveryCommitPurpose(f.client, f.input)).rejects.toMatchObject({
    code: 'PC-AUTH-0005',
  });
  expect(f.query).toHaveBeenCalledOnce();
});

it('leaves ordinary selected authority with the existing shared mutation owner', async () => {
  const f = fixture();
  f.query.mockResolvedValue({
    rowCount: 1,
    rows: [{ representation: 'TYPED_V1', recoveryIntent: null, current: true }],
  });
  await expect(assertPlatformRecoveryCommitPurpose(f.client, f.input)).resolves.toBeUndefined();
});

function verificationFixture(
  action = 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
  resource?: string,
  purposeDigest?: string,
  continuation = false,
  checkerActor = false,
) {
  const f = fixture(continuation);
  const sessionId = '018f0000-0000-7000-8000-000000000117';
  const principalId =
    f.f.intent.preparation.administrators[
      action === 'ACT-POLICY_APPROVE_REQUEST-V1' || checkerActor ? 1 : 0
    ]!.principalId;
  const challenge = 'fixed-purpose-assertion-challenge-value-00000000000001';
  const hash = `sha256:${'a'.repeat(64)}`;
  const assertion = createVerifiedWebAuthnAssertion({
    credentialId: '018f0000-0000-7000-8000-000000000916',
    credentialPublicKeyDigest: hash,
    principalId,
    sessionId,
    actionIntentId: action,
    resourceDigest:
      purposeDigest ??
      (action === 'ACT-POLICY_APPROVE_REQUEST-V1'
        ? canonicalAuthorizationDigest({
            actionIntentId: action,
            approvalRequestId: `urn:openpc:resource:${resource}`,
            candidateDigest: canonicalAuthorizationDigest(f.f.intent.preparation),
            expectedRevision: '1',
            decision: 'APPROVE',
          })
        : canonicalAuthorizationDigest(f.f.intent.preparation)),
    challengeDigest: `sha256:${createHash('sha256').update(challenge).digest('hex')}`,
    rpIdHash: hash,
    origin: 'https://control.openpc.example',
    authenticatorDataDigest: hash,
    clientDataJsonDigest: hash,
    signatureDigest: hash,
    signCount: '1',
    verifiedAt: '2026-09-11T00:00:00.000Z',
  });
  const candidate = stepUpAuthorizationCandidate({
    sessionToken: `${f.input.participantId}.${sessionId}`,
    actionIntentId: action,
    resourceId: resource ?? f.f.intent.preparation.replacementId,
    resourceDigest: assertion.resourceDigest,
    challenge,
    rpIdHash: hash,
    verifiedAssertion: assertion,
  });
  const input: Parameters<typeof assertPlatformRecoveryCommitPurpose>[1] = {
    ...f.input,
    catalogOperationId: 'ID-OP-WEBAUTHN-VERIFY',
    resourceId: sessionId,
    candidate,
    principalId,
    verifiedStepUp: assertion,
  };
  return { ...f, input, candidate, assertion };
}

it('allows genuine assertion verification for the exact reviewed handoff before staging', async () => {
  const f = verificationFixture();
  await expect(assertPlatformRecoveryCommitPurpose(f.client, f.input)).resolves.toBeUndefined();
  expect(f.query).toHaveBeenCalledOnce();
});

function handoffReadVerificationFixture(administratorIndex = 0, checkerActor = false) {
  const { intent } = pendingPlatformRecoveryFixture();
  const purpose = {
    purpose: 'platform-administrator-handoff-read',
    preparationApprovalId: intent.continuation!.preparationApprovalId,
    principalId: intent.preparation.administrators[administratorIndex]!.principalId,
    preparation: intent.preparation,
  };
  return {
    ...verificationFixture(
      'ACT-PARTICIPANTS_READ_RESOURCE-V1',
      intent.preparation.replacementId,
      canonicalAuthorizationDigest(purpose),
      true,
      checkerActor,
    ),
    purpose,
  };
}

it.each([
  [0, false],
  [1, false],
  [0, true],
  [1, true],
] as const)(
  'admits only the enrolled continuation handoff read for administrator %s and checker actor %s',
  async (administratorIndex, checkerActor) => {
    const f = handoffReadVerificationFixture(administratorIndex, checkerActor);
    await expect(assertPlatformRecoveryCommitPurpose(f.client, f.input)).resolves.toBeUndefined();
    expect(f.query).toHaveBeenCalledOnce();
  },
);

it.each([
  'wrong preparation approval',
  'undeclared administrator',
  'changed preparation',
  'different purpose',
  'foreign resource',
  'missing continuation',
  'missing assertion',
  'foreign actor',
  'expired source',
])('denies continuation handoff read verification with %s', async (failure) => {
  let f = handoffReadVerificationFixture();
  const purpose = structuredClone(f.purpose);
  if (failure === 'wrong preparation approval')
    purpose.preparationApprovalId = '018f0000-0000-7000-8000-000000000999';
  if (failure === 'undeclared administrator')
    purpose.principalId = '018f0000-0000-7000-8000-000000000999';
  if (failure === 'changed preparation') purpose.preparation.reason = 'A changed handoff.';
  if (failure === 'different purpose') purpose.purpose = 'platform-administrator-activation';
  if (failure === 'foreign resource')
    f.input = {
      ...f.input,
      candidate: { ...f.candidate, resourceId: '018f0000-0000-7000-8000-000000000999' },
    };
  if (failure === 'missing assertion') f.input = { ...f.input, verifiedStepUp: undefined };
  if (failure === 'foreign actor')
    f.input = { ...f.input, principalId: '018f0000-0000-7000-8000-000000000999' };
  if (failure === 'missing continuation' || failure === 'expired source') {
    const recoveryIntent = { ...f.f.intent };
    if (failure === 'missing continuation') delete recoveryIntent.continuation;
    f.query.mockResolvedValue({
      rowCount: 1,
      rows: [
        {
          representation: 'RECOVERY_V1',
          recoveryIntent,
          current: failure !== 'expired source',
          recoveryId: recoveryIntent.recoveryId,
        },
      ],
    });
  }
  if (
    [
      'wrong preparation approval',
      'undeclared administrator',
      'changed preparation',
      'different purpose',
    ].includes(failure)
  )
    f = {
      ...verificationFixture(
        'ACT-PARTICIPANTS_READ_RESOURCE-V1',
        f.f.intent.preparation.replacementId,
        canonicalAuthorizationDigest(purpose),
        true,
      ),
      purpose,
    };
  await expect(assertPlatformRecoveryCommitPurpose(f.client, f.input)).rejects.toMatchObject({
    code: 'PC-AUTH-0005',
  });
  expect(f.query).toHaveBeenCalledOnce();
});

it.each([
  'missing verified proof',
  'unbranded proof',
  'foreign principal',
  'foreign session',
  'foreign target',
  'changed preparation digest',
  'changed assertion digest',
  'changed challenge',
  'changed relying party',
  'extra candidate field',
  'expired lease',
  'absent case',
])('denies verification with %s', async (failure) => {
  const f = verificationFixture();
  const candidate: Record<string, unknown> = { ...f.candidate };
  if (failure === 'missing verified proof')
    delete (f.input as { verifiedStepUp?: unknown }).verifiedStepUp;
  if (failure === 'unbranded proof') f.input = { ...f.input, verifiedStepUp: { ...f.assertion } };
  if (failure === 'foreign principal')
    f.input = { ...f.input, principalId: '018f0000-0000-7000-8000-000000000999' };
  if (failure === 'foreign session')
    f.input = { ...f.input, resourceId: '018f0000-0000-7000-8000-000000000999' };
  if (failure === 'foreign target') candidate.resourceId = '018f0000-0000-7000-8000-000000000999';
  if (failure === 'changed preparation digest')
    candidate.resourceDigest = `sha256:${'b'.repeat(64)}`;
  if (failure === 'changed assertion digest')
    candidate.verifiedAssertionDigest = `sha256:${'b'.repeat(64)}`;
  if (failure === 'changed challenge')
    candidate.challenge = 'changed-challenge-value-00000000000000000000000001';
  if (failure === 'changed relying party') candidate.rpIdHash = `sha256:${'b'.repeat(64)}`;
  if (failure === 'extra candidate field') candidate.permission = 'business-authority';
  if (failure === 'expired lease')
    f.query.mockResolvedValue({
      rowCount: 1,
      rows: [{ representation: 'RECOVERY_V1', recoveryIntent: f.f.intent, current: false }],
    });
  if (failure === 'absent case')
    f.query.mockResolvedValue({
      rowCount: 1,
      rows: [{ representation: 'RECOVERY_V1', recoveryIntent: null, current: true }],
    });
  f.input = { ...f.input, candidate };
  await expect(assertPlatformRecoveryCommitPurpose(f.client, f.input)).rejects.toMatchObject({
    code: 'PC-AUTH-0005',
  });
});
function publicCandidateFixtures() {
  const f = fixture(),
    plan = f.f.intent.preparation,
    admin = plan.administrators[0]!;
  const envelope = typedEnvelopeCreateCandidate.parse({
    schema: 'pc.identity.authority-envelope-proposal',
    schemaVersion: 1,
    envelopeId: admin.envelopeId,
    id: admin.envelopeId,
    participantId: f.input.participantId,
    state: 'DRAFT',
    issuance: 'PLATFORM_ROOT',
    platformScopeReplacementId: plan.replacementId,
    usable: admin.usable,
    grantable: admin.grantable,
  });
  const permission = {
    privacyDomainIds: admin.usable.administration.privacyDomainIds,
    actionIntentIds: [...admin.usable.administration.actionIntentIds].sort(),
    capabilityIds: [],
    resourceIds: [...admin.usable.administration.resourceIds].sort(),
    riskClasses: [...admin.usable.administration.riskClasses].sort(),
    validFrom: new Date(Number(BigInt(admin.usable.validFromNs) / 1000000n)).toISOString(),
    validUntil: new Date(Number(BigInt(admin.usable.validUntilNs) / 1000000n)).toISOString(),
    makerCheckerRequired: true,
    stepUpRequired: true,
    onwardDelegationDepth: 0,
  };
  const assignment = assignmentCreateCandidate.parse({
    ...permission,
    id: admin.assignmentId,
    assignmentId: admin.assignmentId,
    participantId: f.input.participantId,
    state: 'ACTIVE',
    delegationEpoch: '0',
    principalId: admin.principalId,
    authorityEnvelopeId: admin.envelopeId,
    roleId: `urn:openpc:role:${admin.roleId}`,
    scopeDigest: canonicalAuthorizationDigest({
      participantId: f.input.participantId,
      ...permission,
    }),
  });
  return { f, plan, admin, envelope, assignment };
}

it.each(['envelope', 'activation', 'assignment'])(
  'qualifies the complete public %s proof for the exact maker',
  async (kind) => {
    const v = publicCandidateFixtures();
    const body =
      kind === 'envelope'
        ? v.envelope
        : kind === 'assignment'
          ? v.assignment
          : { envelopeId: v.admin.envelopeId };
    const action =
      kind === 'envelope'
        ? 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1'
        : kind === 'assignment'
          ? 'ACT-PARTICIPANT_CREATE_MEMBER-V1'
          : 'ACT-PARTICIPANT_ACTIVATE_CONTEXT-V1';
    const target = kind === 'assignment' ? v.admin.assignmentId : v.admin.envelopeId;
    const f = verificationFixture(action, target, canonicalAuthorizationDigest(body));
    await expect(assertPlatformRecoveryCommitPurpose(f.client, f.input)).resolves.toBeUndefined();
    expect(f.query).toHaveBeenCalledOnce();
  },
);

it.each([
  'role alias',
  'extra runtime capability',
  'changed scope digest',
  'changed validity',
  'changed recipient',
  'extra activation field',
  'wrong maker',
])('rejects a genuinely branded changed business proof: %s', async (failure) => {
  const v = publicCandidateFixtures();
  const body: Record<string, unknown> =
    failure === 'extra activation field'
      ? { envelopeId: v.admin.envelopeId, permission: 'extra' }
      : { ...v.assignment };
  if (failure === 'role alias') body.roleId = `urn:openpc:platform:${v.admin.roleId}`;
  if (failure === 'extra runtime capability') body.capabilityIds = ['CALL_RESULT_DISCLOSURE'];
  if (failure === 'changed scope digest') body.scopeDigest = `sha256:${'a'.repeat(64)}`;
  if (failure === 'changed validity') body.validUntil = '2035-01-01T00:00:00.000Z';
  if (failure === 'changed recipient') body.principalId = '018f0000-0000-7000-8000-000000000999';
  const f = verificationFixture(
    failure === 'extra activation field'
      ? 'ACT-PARTICIPANT_ACTIVATE_CONTEXT-V1'
      : 'ACT-PARTICIPANT_CREATE_MEMBER-V1',
    failure === 'extra activation field' ? v.admin.envelopeId : v.admin.assignmentId,
    canonicalAuthorizationDigest(body),
  );
  if (failure === 'wrong maker') {
    const principalId = v.plan.administrators[1]!.principalId;
    const assertion = createVerifiedWebAuthnAssertion({ ...f.assertion, principalId });
    f.input = {
      ...f.input,
      principalId,
      verifiedStepUp: assertion,
      candidate: stepUpAuthorizationCandidate({ ...f.candidate, verifiedAssertion: assertion }),
    };
  }
  await expect(assertPlatformRecoveryCommitPurpose(f.client, f.input)).rejects.toMatchObject({
    code: 'PC-AUTH-0005',
  });
});

function commitVerificationFixture(reason = 'Commit the actual reviewed ready handoff.') {
  const v = publicCandidateFixtures(),
    plan = v.plan;
  const body = {
    schema: 'pc.identity.platform-scope-replacement-commit',
    schemaVersion: 1,
    replacementId: plan.replacementId,
    platformContextId: plan.platformContextId,
    expectedRootRevision: plan.expectedRootRevision,
    expectedReplacementRevision: '1',
    predecessorEpoch: plan.predecessorEpoch,
    predecessorDigest: plan.predecessorDigest,
    successorDigest: `sha256:${'b'.repeat(64)}`,
    readinessDigest: `sha256:${'c'.repeat(64)}`,
    reason,
  };
  const f = verificationFixture(
    'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
    plan.replacementId,
    canonicalAuthorizationDigest(body),
  );
  const stored = {
    candidate: body,
    digest: Buffer.from(canonicalAuthorizationDigest(body).slice(7), 'hex'),
  };
  const selected = {
    representation: 'RECOVERY_V1',
    recoveryIntent: f.f.intent,
    current: true,
    recoveryId: f.f.intent.recoveryId,
  };
  f.query
    .mockResolvedValueOnce({ rowCount: 1, rows: [selected] })
    .mockResolvedValueOnce({ rowCount: 1, rows: [stored] });
  return { f, body, stored, selected, plan };
}
it('binds the full commit proof to the original authenticated staged candidate and current Root', async () => {
  const v = commitVerificationFixture();
  await expect(assertPlatformRecoveryCommitPurpose(v.f.client, v.f.input)).resolves.toBeUndefined();
  const [sql, params] = v.f.query.mock.calls[1]!;
  expect(sql).not.toContain('read_platform_scope_replacement_readiness');
  expect(sql).toContain('c.maker_session_id=$6');
  expect(sql).toContain("s.state='ACTIVE'");
  expect(sql).toContain('s.idle_expires_at>clock_timestamp()');
  expect(sql).toContain('a.row_version=c.maker_assignment_row_version');
  expect(sql).toContain('openpc.assignment_role_permits');
  expect(sql).toContain('root.authority_epoch=r.predecessor_epoch');
  expect(sql).toContain('r.candidate=$7::jsonb');
  expect(sql).toContain("c.state in ('PROPOSED','APPROVAL_REQUESTED','APPROVED')");
  expect(sql).toContain('successor.predecessor_candidate_id=c.mutation_candidate_id');
  expect(params).toEqual([
    v.f.input.participantId,
    v.f.input.privacyDomainId,
    v.body.replacementId,
    v.f.input.authorityEnvelopeId,
    v.f.f.intent.recoveryId,
    v.f.input.resourceId,
    v.plan,
    v.f.input.principalId,
  ]);
});
it('accepts the actual full staged commit reason rather than inferring the preparation reason', async () => {
  const v = commitVerificationFixture('Commit after reading the genuine signed readiness.');
  expect(v.body.reason).not.toBe(v.plan.reason);
  await expect(assertPlatformRecoveryCommitPurpose(v.f.client, v.f.input)).resolves.toBeUndefined();
});
it.each([
  'missing original',
  'ambiguous original',
  'corrupt stored digest',
  'changed full reason',
  'changed readiness digest',
  'changed root revision',
  'foreign replacement',
  'extra field',
])('rejects genuine commit proof with %s before business effects', async (failure) => {
  const v = commitVerificationFixture();
  if (failure === 'corrupt stored digest') v.stored.digest = Buffer.alloc(31);
  if (failure === 'changed full reason') v.body.reason = 'An unreviewed different full reason.';
  if (failure === 'changed readiness digest') v.body.readinessDigest = `sha256:${'d'.repeat(64)}`;
  if (failure === 'changed root revision') v.body.expectedRootRevision = '999';
  if (failure === 'foreign replacement')
    v.body.replacementId = '018f0000-0000-7000-8000-000000000999';
  if (failure === 'extra field') Object.assign(v.body, { surrogate: true });
  if (failure === 'missing original' || failure === 'ambiguous original')
    v.f.query
      .mockReset()
      .mockResolvedValueOnce({ rowCount: 1, rows: [v.selected] })
      .mockResolvedValueOnce(
        failure === 'missing original'
          ? { rowCount: 0, rows: [] }
          : { rowCount: 2, rows: [v.stored, v.stored] },
      );
  await expect(assertPlatformRecoveryCommitPurpose(v.f.client, v.f.input)).rejects.toMatchObject({
    code: 'PC-AUTH-0005',
  });
});

it.each(['different submission reason', 'unreviewed reservation'])(
  'rejects a genuine full submission proof with %s',
  async (failure) => {
    const v = typedProposalFixture();
    const request =
      failure === 'different submission reason'
        ? { ...v.request, reason: v.f.f.intent.preparation.reason }
        : { ...v.request, resourceReservationId: '018f0000-0000-7000-8000-000000000998' };
    const resourceDigest = approvalCreateIntent(request).intentDigest;
    const assertion = createVerifiedWebAuthnAssertion({ ...v.f.assertion, resourceDigest });
    await expect(
      assertPlatformRecoveryCommitPurpose(v.f.client, {
        ...v.f.input,
        verifiedStepUp: assertion,
        candidate: stepUpAuthorizationCandidate({
          ...v.f.candidate,
          resourceDigest,
          verifiedAssertion: assertion,
        }),
      }),
    ).rejects.toMatchObject({ code: 'PC-AUTH-0005' });
  },
);

function typedProposalFixture(checker = false) {
  const v = publicCandidateFixtures(),
    original = identityEnvelopeFixture('purpose-only-fixture');
  const proposal = decodeEnvelopeProposal(original.proposalBytes);
  proposal.envelopeId = v.admin.envelopeId;
  proposal.participantId = v.f.input.participantId;
  proposal.usable = v.admin.usable;
  proposal.grantable = v.admin.grantable;
  proposal.issuer.authority.principalId = v.plan.administrators[0]!.principalId;
  proposal.issuer.authority.authorityEnvelopeId = v.f.input.authorityEnvelopeId;
  proposal.issuer.platformContextId = v.plan.platformContextId;
  proposal.issuer.platformAuthorityEpoch = (BigInt(v.plan.predecessorEpoch) + 1n).toString();
  proposal.issuer.platformAuthorityDigest = `sha256:${'b'.repeat(64)}`;
  const bytes = encodeEnvelopeProposal(proposal),
    digest = authorityEnvelopeDigest(bytes);
  const approvalId = '018f0000-0000-7000-8000-000000000901',
    registeredDigest = Buffer.from('a'.repeat(64), 'hex');
  const request = {
    actionIntentId: 'ACT-APPROVAL_REQUESTS_CREATE_RESOURCE-V1',
    actionIntentDigest: `sha256:${registeredDigest.toString('hex')}`,
    candidateDigest: digest,
    makerSubjectRef: `urn:openpc:resource:${v.plan.administrators[0]!.principalId}`,
    checkerSubjectRef: `urn:openpc:resource:${v.plan.administrators[1]!.principalId}`,
    reason: 'Submit the typed Platform-root RPC envelope for independent approval.',
  };
  const decision = {
    actionIntentId: 'ACT-POLICY_APPROVE_REQUEST-V1',
    approvalRequestId: `urn:openpc:resource:${approvalId}`,
    candidateDigest: digest,
    expectedRevision: '1',
    decision: 'APPROVE',
  };
  const f = verificationFixture(
    checker ? decision.actionIntentId : request.actionIntentId,
    checker ? approvalId : v.admin.envelopeId,
    checker ? canonicalAuthorizationDigest(decision) : approvalCreateIntent(request).intentDigest,
  );
  const row = {
    envelopeId: v.admin.envelopeId,
    proposalDigest: Buffer.from(digest.slice(7), 'hex'),
    candidate: v.envelope,
    candidateDigest: Buffer.from(canonicalAuthorizationDigest(v.envelope).slice(7), 'hex'),
    makerEnvelopeId: v.f.input.authorityEnvelopeId,
    successorDigest: Buffer.from('b'.repeat(64), 'hex'),
    approvalRevision: checker ? '1' : null,
  };
  const stored = {
    envelopeId: v.admin.envelopeId,
    targetParticipantId: v.f.input.participantId,
    makerPrincipalId: v.plan.administrators[0]!.principalId,
    bytes,
    digest: row.proposalDigest,
    issuerAuthority: {
      binding: proposal.issuer.authority,
      durable: { grant: { privacyDomainId: v.f.input.privacyDomainId } },
    },
    state: checker ? 'SUBMITTED' : 'DRAFT',
    version: checker ? '2' : '1',
    submissionApprovalId: checker ? approvalId : null,
    submissionChecker: null,
    submissionCheckerAuthority: null,
  };
  f.query.mockResolvedValueOnce({
    rowCount: 1,
    rows: [
      {
        representation: 'RECOVERY_V1',
        recoveryIntent: f.f.intent,
        current: true,
        recoveryId: f.f.intent.recoveryId,
      },
    ],
  });
  if (checker) f.query.mockResolvedValueOnce({ rowCount: 0, rows: [] });
  f.query
    .mockResolvedValueOnce({ rowCount: 1, rows: [row] })
    .mockResolvedValueOnce({ rowCount: 1, rows: [stored] });
  if (!checker)
    f.query.mockResolvedValueOnce({ rowCount: 1, rows: [{ digest: registeredDigest }] });
  return { f, row, stored, request, decision, proposal };
}

it.each([false, true])(
  'qualifies the actual typed %s submission/decision through canonical proposal owner',
  async (checker) => {
    const v = typedProposalFixture(checker);
    await expect(
      assertPlatformRecoveryCommitPurpose(v.f.client, v.f.input),
    ).resolves.toBeUndefined();
    const call = v.f.query.mock.calls[checker ? 2 : 1]!;
    expect(call[0]).toContain('maker.recovery_case_id=$6');
    expect(call[0]).toContain("a.subject_type='AUTHORITY_ENVELOPE'");
    expect(call[1]).toEqual([
      v.f.input.participantId,
      v.f.input.privacyDomainId,
      checker ? null : v.row.envelopeId,
      v.f.f.intent.preparation.administrators[0]!.principalId,
      v.f.f.intent.preparation.administrators[1]!.principalId,
      v.f.f.intent.recoveryId,
      checker ? '018f0000-0000-7000-8000-000000000901' : null,
      v.f.f.intent.preparation,
      v.f.input.authorityEnvelopeId,
    ]);
  },
);

it.each([
  'changed creation body',
  'changed canonical proposal',
  'foreign envelope',
  'changed pending root',
  'changed approval revision',
])('rejects typed decision whose owner has %s', async (failure) => {
  const v = typedProposalFixture(true);
  if (failure === 'changed creation body')
    v.row.candidate = { ...v.row.candidate, issuance: 'CHILD' } as typeof v.row.candidate;
  if (failure === 'changed canonical proposal')
    v.stored.bytes = Buffer.from(v.stored.bytes).fill(0);
  if (failure === 'foreign envelope') v.row.envelopeId = '018f0000-0000-7000-8000-000000000999';
  if (failure === 'changed pending root')
    v.row.successorDigest = Buffer.from('c'.repeat(64), 'hex');
  if (failure === 'changed approval revision') v.row.approvalRevision = '2';
  await expect(assertPlatformRecoveryCommitPurpose(v.f.client, v.f.input)).rejects.toMatchObject({
    code: 'PC-AUTH-0005',
  });
});

it.each([
  'ACT-PROVIDERS_CREATE_RESOURCE-V1',
  'ACT-POLICY_CREATE_RESOURCE-V1',
  'ACT-ROLES_CREATE_RESOURCE-V1',
])('denies unrelated authenticated verification action %s', async (action) => {
  const f = verificationFixture(action);
  await expect(assertPlatformRecoveryCommitPurpose(f.client, f.input)).rejects.toMatchObject({
    code: 'PC-AUTH-0005',
  });
});

it('resolves checker verification through the exact current approved business candidate', async () => {
  const f = verificationFixture(
    'ACT-POLICY_APPROVE_REQUEST-V1',
    '018f0000-0000-7000-8000-000000000901',
  );
  f.query
    .mockResolvedValueOnce({
      rowCount: 1,
      rows: [
        {
          representation: 'RECOVERY_V1',
          recoveryIntent: f.f.intent,
          current: true,
          recoveryId: f.f.intent.recoveryId,
        },
      ],
    })
    .mockResolvedValueOnce({
      rowCount: 1,
      rows: [
        {
          catalogOperationId: 'ID-OP-PLATFORM-SCOPE-PREPARE',
          resourceId: f.f.intent.preparation.replacementId,
          candidate: f.f.intent.preparation,
          candidateDigest: Buffer.from(
            canonicalAuthorizationDigest(f.f.intent.preparation).slice(7),
            'hex',
          ),
          approvalRevision: '1',
        },
      ],
    });
  await expect(assertPlatformRecoveryCommitPurpose(f.client, f.input)).resolves.toBeUndefined();
  expect(f.query).toHaveBeenCalledTimes(2);
  expect(f.query.mock.calls[1]![1]).toEqual([
    f.input.participantId,
    f.input.privacyDomainId,
    f.candidate.resourceId,
    f.input.principalId,
    f.f.intent.preparation.administrators[0]!.principalId,
    f.f.intent.recoveryId,
  ]);
  expect(f.query.mock.calls[1]![0]).toContain('a.checker_principal_id=$4');
  expect(f.query.mock.calls[1]![0]).toContain('maker.recovery_case_id=$6');
  expect(f.query.mock.calls[1]![0]).toContain(
    'successor.predecessor_candidate_id=c.mutation_candidate_id',
  );
});

it.each(['absent approval', 'changed body', 'unrelated operation', 'ambiguous approval'])(
  'denies checker verification with %s',
  async (failure) => {
    const f = verificationFixture(
      'ACT-POLICY_APPROVE_REQUEST-V1',
      '018f0000-0000-7000-8000-000000000901',
    );
    const row = {
      catalogOperationId: 'ID-OP-PLATFORM-SCOPE-PREPARE',
      resourceId: f.f.intent.preparation.replacementId,
      candidate: f.f.intent.preparation,
      candidateDigest: Buffer.from(
        canonicalAuthorizationDigest(f.f.intent.preparation).slice(7),
        'hex',
      ),
      approvalRevision: '1',
    };
    const rows =
      failure === 'absent approval'
        ? []
        : [
            failure === 'changed body'
              ? { ...row, candidate: { ...row.candidate, reason: 'different' } }
              : failure === 'unrelated operation'
                ? { ...row, catalogOperationId: 'ID-OP-WORKLOAD-ROTATE' }
                : row,
          ];
    f.query
      .mockResolvedValueOnce({
        rowCount: 1,
        rows: [
          {
            representation: 'RECOVERY_V1',
            recoveryIntent: f.f.intent,
            current: true,
            recoveryId: f.f.intent.recoveryId,
          },
        ],
      })
      .mockResolvedValueOnce({
        rowCount: failure === 'ambiguous approval' ? 2 : rows.length,
        rows,
      });
    await expect(assertPlatformRecoveryCommitPurpose(f.client, f.input)).rejects.toMatchObject({
      code: 'PC-AUTH-0005',
    });
  },
);

it.each([
  'ACT-IDENTITY_CREATE_SESSION-V1',
  'ACT-PARTICIPANT_ACTIVATE_CONTEXT-V1',
  'ACT-PARTICIPANT_CREATE_MEMBER-V1',
])('does not admit unqualified purposes by a named-target membership rule: %s', async (action) => {
  const f = verificationFixture(action);
  await expect(assertPlatformRecoveryCommitPurpose(f.client, f.input)).rejects.toMatchObject({
    code: 'PC-AUTH-0005',
  });
});
it('rejects a signed COMMIT surrogate and a different recovery case', async () => {
  const f = verificationFixture();
  const plan = f.f.intent.preparation;
  const candidate = {
    replacementId: plan.replacementId,
    platformContextId: plan.platformContextId,
    predecessorEpoch: plan.predecessorEpoch,
    predecessorDigest: plan.predecessorDigest,
    expectedRootRevision: plan.expectedRootRevision,
  };
  const assertion = createVerifiedWebAuthnAssertion({
    ...f.assertion,
    resourceDigest: canonicalAuthorizationDigest(candidate),
  });
  const proof = stepUpAuthorizationCandidate({
    ...f.candidate,
    resourceDigest: assertion.resourceDigest,
    verifiedAssertion: assertion,
  });
  await expect(
    assertPlatformRecoveryCommitPurpose(f.client, {
      ...f.input,
      candidate: proof,
      verifiedStepUp: assertion,
    }),
  ).rejects.toMatchObject({ code: 'PC-AUTH-0005' });
  f.query.mockResolvedValue({
    rowCount: 1,
    rows: [
      {
        representation: 'RECOVERY_V1',
        recoveryIntent: f.f.intent,
        current: true,
        recoveryId: '018f0000-0000-7000-8000-000000000999',
      },
    ],
  });
  await expect(assertPlatformRecoveryCommitPurpose(f.client, f.input)).rejects.toMatchObject({
    code: 'PC-AUTH-0005',
  });
});

function discoveryPurposeFixture() {
  const d = discoveryTrustFixture();
  const f = fixture();
  f.query.mockResolvedValue({
    rowCount: 1,
    rows: [
      {
        representation: 'RECOVERY_V1',
        recoveryIntent: d.intent,
        current: true,
        recoveryId: d.intent.recoveryId,
      },
    ],
  });
  const input: Parameters<typeof assertPlatformRecoveryCommitPurpose>[1] = {
    ...f.input,
    participantId: d.source.enrollment.participantId,
    privacyDomainId: d.source.enrollment.privacyDomainId,
    catalogOperationId: 'ID-OP-WORKLOAD-ROTATE',
    resourceId: d.intent.certificateRecovery.predecessorCredentialId,
    expectedRevision: d.intent.certificateRecovery.predecessorRevision,
    principalId: d.intent.administrators[0].principalId,
    candidate: discoveryCertificateRotationCandidate(d.intent.certificateRecovery),
  };
  return { ...f, d, input };
}
it('dispatches the separately governed discovery intent to only its exact native rotation', async () => {
  const f = discoveryPurposeFixture();
  await expect(assertPlatformRecoveryCommitPurpose(f.client, f.input)).resolves.toBeUndefined();
});
it.each(['revision', 'predecessor', 'successor', 'key', 'maker', 'operation', 'case', 'current'])(
  'denies a discovery commit with changed %s',
  async (failure) => {
    const f = discoveryPurposeFixture();
    if (failure === 'revision') f.input = { ...f.input, expectedRevision: '2' };
    if (failure === 'predecessor') f.input = { ...f.input, resourceId: discoveryId(999) };
    if (failure === 'successor')
      f.input = {
        ...f.input,
        candidate: { ...(f.input.candidate as object), credentialId: discoveryId(999) },
      };
    if (failure === 'key')
      f.input = {
        ...f.input,
        candidate: { ...(f.input.candidate as object), publicKeySpkiDer: 'changed' },
      };
    if (failure === 'maker')
      f.input = { ...f.input, principalId: f.d.intent.administrators[1].principalId };
    if (failure === 'operation')
      f.input = { ...f.input, catalogOperationId: 'ID-OP-PLATFORM-SCOPE-PREPARE' };
    if (failure === 'case' || failure === 'current')
      f.query.mockResolvedValue({
        rowCount: 1,
        rows: [
          {
            representation: 'RECOVERY_V1',
            recoveryIntent: f.d.intent,
            current: failure !== 'current',
            recoveryId: failure === 'case' ? discoveryId(999) : f.d.intent.recoveryId,
          },
        ],
      });
    await expect(assertPlatformRecoveryCommitPurpose(f.client, f.input)).rejects.toMatchObject({
      code: 'PC-AUTH-0005',
    });
  },
);
function discoveryVerificationFixture(checker = false) {
  const f = discoveryPurposeFixture(),
    sessionId = discoveryId(800),
    approvalId = discoveryId(801);
  const action = checker ? 'ACT-POLICY_APPROVE_REQUEST-V1' : 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1';
  const purpose = checker
    ? canonicalAuthorizationDigest({
        actionIntentId: action,
        approvalRequestId: `urn:openpc:resource:${approvalId}`,
        candidateDigest: canonicalAuthorizationDigest(f.input.candidate),
        expectedRevision: '1',
        decision: 'APPROVE',
      })
    : canonicalAuthorizationDigest(f.input.candidate);
  const principalId = f.d.intent.administrators[checker ? 1 : 0].principalId;
  const challenge = 'discovery-assertion-challenge-000000000000000000001',
    hash = `sha256:${'a'.repeat(64)}`;
  const assertion = createVerifiedWebAuthnAssertion({
    credentialId: discoveryId(802),
    credentialPublicKeyDigest: hash,
    principalId,
    sessionId,
    actionIntentId: action,
    resourceDigest: purpose,
    challengeDigest: `sha256:${createHash('sha256').update(challenge).digest('hex')}`,
    rpIdHash: hash,
    origin: 'https://control.openpc.example',
    authenticatorDataDigest: hash,
    clientDataJsonDigest: hash,
    signatureDigest: hash,
    signCount: '1',
    verifiedAt: '2026-10-02T08:00:00Z',
  });
  const candidate = stepUpAuthorizationCandidate({
    sessionToken: `${f.input.participantId}.${sessionId}`,
    actionIntentId: action,
    resourceId: checker ? approvalId : f.d.intent.certificateRecovery.predecessorCredentialId,
    resourceDigest: purpose,
    challenge,
    rpIdHash: hash,
    verifiedAssertion: assertion,
  });
  const approval = {
    candidate: f.input.candidate,
    candidateDigest: Buffer.from(canonicalAuthorizationDigest(f.input.candidate).slice(7), 'hex'),
    expectedRevision: f.d.intent.certificateRecovery.predecessorRevision,
    catalogOperationId: 'ID-OP-WORKLOAD-ROTATE',
    resourceId: f.d.intent.certificateRecovery.predecessorCredentialId,
    approvalRevision: '1',
  };
  if (checker)
    f.query
      .mockResolvedValueOnce({
        rowCount: 1,
        rows: [
          {
            representation: 'RECOVERY_V1',
            recoveryIntent: f.d.intent,
            current: true,
            recoveryId: f.d.intent.recoveryId,
          },
        ],
      })
      .mockResolvedValue({ rowCount: 1, rows: [approval] });
  f.input = {
    ...f.input,
    catalogOperationId: 'ID-OP-WEBAUTHN-VERIFY',
    principalId,
    resourceId: sessionId,
    candidate,
    verifiedStepUp: assertion,
  };
  return { ...f, assertion, approval };
}
it.each([false, true])(
  'admits genuine discovery %s verification against the exact maker intent or owning approval',
  async (checker) => {
    const f = discoveryVerificationFixture(checker);
    await expect(assertPlatformRecoveryCommitPurpose(f.client, f.input)).resolves.toBeUndefined();
    expect(f.query).toHaveBeenCalledTimes(checker ? 2 : 1);
  },
);
it.each(['unbranded', 'principal', 'session', 'target', 'challenge', 'digest', 'rp', 'assertion'])(
  'denies discovery verification with changed %s',
  async (failure) => {
    const f = discoveryVerificationFixture();
    const candidate = { ...(f.input.candidate as Record<string, unknown>) };
    if (failure === 'unbranded') f.input = { ...f.input, verifiedStepUp: { ...f.assertion } };
    if (failure === 'principal') f.input = { ...f.input, principalId: discoveryId(999) };
    if (failure === 'session') f.input = { ...f.input, resourceId: discoveryId(999) };
    if (failure === 'target') candidate.resourceId = discoveryId(999);
    if (failure === 'challenge')
      candidate.challenge = 'different-assertion-challenge-000000000000000000001';
    if (failure === 'digest') candidate.resourceDigest = `sha256:${'b'.repeat(64)}`;
    if (failure === 'rp') candidate.rpIdHash = `sha256:${'b'.repeat(64)}`;
    if (failure === 'assertion') candidate.verifiedAssertionDigest = `sha256:${'b'.repeat(64)}`;
    f.input = { ...f.input, candidate };
    await expect(assertPlatformRecoveryCommitPurpose(f.client, f.input)).rejects.toMatchObject({
      code: 'PC-AUTH-0005',
    });
  },
);
it.each(['missing', 'revision', 'candidate', 'digest', 'resource', 'operation'])(
  'denies discovery checker verification against %s approval source',
  async (failure) => {
    const f = discoveryVerificationFixture(true);
    const row = { ...f.approval };
    if (failure === 'revision') row.expectedRevision = '2';
    if (failure === 'candidate')
      row.candidate = { ...(row.candidate as object), credentialId: discoveryId(999) };
    if (failure === 'digest') row.candidateDigest = Buffer.alloc(32, 9);
    if (failure === 'resource') row.resourceId = discoveryId(999);
    if (failure === 'operation') row.catalogOperationId = 'ID-OP-PLATFORM-SCOPE-PREPARE';
    f.query.mockResolvedValue({
      rowCount: failure === 'missing' ? 0 : 1,
      rows: failure === 'missing' ? [] : [row],
    });
    await expect(assertPlatformRecoveryCommitPurpose(f.client, f.input)).rejects.toMatchObject({
      code: 'PC-AUTH-0005',
    });
  },
);

function approvalResumeVerificationFixture(source4 = true, checker = false) {
  const intent = structuredClone(
    (source4 ? pendingExpiryPlatformRecoveryFixture() : pendingPlatformRecoveryFixture()).intent,
  );
  const approvalId = '018f0000-0000-7000-8000-000000000901';
  const candidateId = '018f0000-0000-7000-8000-000000000902';
  const candidateDigest = canonicalAuthorizationDigest(intent.preparation);
  if (source4)
    intent.approvalContinuation = {
      schema: 'pc.identity.platform-prepare-approval-continuation',
      schemaVersion: 1,
      recoveryId: '018f0000-0000-7000-8000-000000000903',
      intentDigest: `sha256:${'b'.repeat(64)}`,
      activationOperationId: '018f0000-0000-7000-8000-000000000904',
      activationReceiptDigest: `sha256:${'c'.repeat(64)}`,
      candidateId,
      approvalId,
      candidateDigest,
      businessKey: 'same-original-business-key',
      attempt: '1',
    };
  const purpose = {
    command: 'RESUME',
    actionIntentId: 'ACT-APPROVAL_REQUESTS_UPDATE_RESOURCE-V1',
    actionIntentDigest: `sha256:${'d'.repeat(64)}`,
    expectedRevision: '2',
    predecessorCandidateId: candidateId,
    expectedAttempt: '1',
    candidateDigest,
    reason: platformRecoveryApprovalResumeReason,
    approvalRequestId: `urn:openpc:resource:${approvalId}`,
  };
  const f = verificationFixture(
    purpose.actionIntentId,
    approvalId,
    canonicalAuthorizationDigest(purpose),
    false,
    checker,
  );
  const selected = {
    representation: 'RECOVERY_V1',
    recoveryIntent: intent,
    current: true,
    recoveryId: intent.recoveryId,
  };
  const original = {
    approvalRevision: '2',
    candidateId,
    attempt: '1',
    candidateDigest,
    actionDigest: purpose.actionIntentDigest,
    candidate: intent.preparation,
    resourceId: intent.preparation.replacementId,
    expectedRevision: '1',
  };
  f.query
    .mockReset()
    .mockResolvedValueOnce({ rowCount: 1, rows: [selected] })
    .mockResolvedValueOnce({ rowCount: 1, rows: [original] });
  return { ...f, intent, purpose, selected, original, approvalId };
}

it.each([false, true])(
  'admits exact maker RESUME assertion through current native purpose for Source4=%s',
  async (source4) => {
    const f = approvalResumeVerificationFixture(source4);
    await expect(assertPlatformRecoveryCommitPurpose(f.client, f.input)).resolves.toBeUndefined();
    expect(f.query.mock.calls[1]![1]).toEqual([
      f.input.participantId,
      f.input.privacyDomainId,
      f.input.principalId,
      f.input.authorityEnvelopeId,
      f.approvalId,
    ]);
  },
);

it.each([
  'checker',
  'expired source',
  'missing continuation',
  'missing original',
  'ambiguous original',
  'changed original body',
  'changed purpose digest',
  'foreign approval',
])('denies Source4 RESUME assertion with %s', async (failure) => {
  const f = approvalResumeVerificationFixture(true, failure === 'checker');
  if (failure === 'expired source') f.selected.current = false;
  if (failure === 'missing continuation') delete f.intent.approvalContinuation;
  if (failure === 'changed original body')
    f.original.candidate = { ...f.original.candidate, reason: 'Changed original intent.' };
  if (failure === 'changed purpose digest') f.original.approvalRevision = '3';
  const absent = ['missing original', 'foreign approval'].includes(failure);
  f.query
    .mockReset()
    .mockResolvedValueOnce({ rowCount: 1, rows: [f.selected] })
    .mockResolvedValueOnce({
      rowCount: absent ? 0 : failure === 'ambiguous original' ? 2 : 1,
      rows: absent ? [] : [f.original],
    });
  if (failure === 'foreign approval')
    f.input = {
      ...f.input,
      candidate: { ...f.candidate, resourceId: '018f0000-0000-7000-8000-000000000999' },
    };
  await expect(assertPlatformRecoveryCommitPurpose(f.client, f.input)).rejects.toMatchObject({
    code: 'PC-AUTH-0005',
  });
});
