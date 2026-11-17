import {
  platformRecoveryFixture,
  pendingPlatformRecoveryFixture,
  pendingExpiryPlatformRecoveryFixture,
} from '../../../../../../services/identity-service/src/domain/platform-recovery.test-fixture';
import { randomBytes } from 'node:crypto';
import { NextRequest } from 'next/server';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  envelopeFixtureId as id,
  envelopeFixtureDigest as hash,
  envelopeFixtureScope,
} from '../../../../../../packages/security-kernel/src/identity-envelope/fixture';
import {
  authenticated,
  identityCsrf,
  localRuntimeConfig,
  openBffPayload,
  sealBffPayload,
  type IdentitySession,
  type LocalConfig,
} from './local-runtime';
import {
  mutatePlatformCeilingWorkbench,
  readPlatformCeilingWorkbench,
} from './local-platform-ceiling-workbench';
import { digest, participantAction, approvalUpdateAction } from './local-governance-api';
import { platformRecoveryApprovalResumeReason } from '../../../../../../services/identity-service/src/contracts/platform-recovery';
import { readPendingAdministrator } from './platform-administrator-selection';

vi.mock('./local-runtime', async (original) => ({
  ...(await original<typeof import('./local-runtime')>()),
  authenticated: vi.fn(),
  identityCsrf: vi.fn(),
  localRuntimeConfig: vi.fn(),
}));
const actor: IdentitySession = {
  sessionId: id(110),
  principalId: id(100),
  participantId: id(1),
  privacyDomainId: id(2),
  contextMode: 'PLATFORM',
  contextEpoch: '1',
  role: 'operator',
  sessionToken: 'private-unit-session',
  platformBootstrapEligible: true,
  stepUpVerifiedAt: null,
};
const runtime: LocalConfig = {
  publicApiUrl: 'http://owner.invalid',
  identityUrl: 'http://identity.invalid',
  policyUrl: 'http://policy.invalid',
  factUrl: 'http://fact.invalid',
  oidcAuthorizationUrl: 'http://oidc.invalid',
  identityToken: 'private-unit-identity',
  policyToken: 'private-unit-policy',
  factToken: 'private-unit-fact',
  cookieKey: randomBytes(64),
};
const selection = {
  platformContextId: id(4),
  replacementId: id(8),
  lifetimeSeconds: 3600,
  reason: 'Exact governed successor in disposable local QA.',
  administrators: [100, 101].map((n) => ({
    principalId: id(n),
    envelopeId: id(n + 20),
    assignmentId: id(n + 40),
    roleId: id(n + 60),
    actionIntentIds: [participantAction.id],
    resourceIds: [id(7)],
  })),
};
const source = {
  root: {
    platformContextId: id(4),
    ownerParticipantId: id(1),
    installationPrivacyDomainId: id(2),
    platformAuthorityEpoch: '1',
    environmentId: 'local-qa',
    installationDigest: hash(1),
    grantable: envelopeFixtureScope(0),
    platformAuthorityDigest: hash(2),
  },
  revision: '1',
  epoch: '1',
  state: 'ACTIVE',
  now: '1800000000123456000',
  pending: null,
  affectedTargets: [],
};
const readiness = () => ({
  replacementId: id(8),
  platformContextId: id(4),
  rootRevision: '1',
  predecessorEpoch: '1',
  predecessorDigest: hash(2),
  successorDigest: hash(3),
  readinessDigest: hash(4),
  replacementRevision: '1',
  state: 'WITHDRAWING',
  unacknowledgedTargets: 0,
  unpreparedAdministrators: 0,
  sourceExpiresAtNs: '1800003600000000000',
  nowNs: source.now,
  targets: [],
  administrators: selection.administrators.map((admin) => ({
    principalId: admin.principalId,
    envelopeId: admin.envelopeId,
    assignmentId: admin.assignmentId,
    ready: true,
  })),
});
const request = (body: unknown) =>
  new NextRequest('http://localhost:8080/api/v1/ui/platform-ceiling-workbench', {
    method: 'POST',
    headers: {
      'origin': 'http://localhost:8080',
      'host': 'localhost:8080',
      'content-type': 'application/json',
    },
    body: JSON.stringify(body),
  });
let observedReadiness = readiness();
let changeActor = false;
beforeEach(() => {
  observedReadiness = readiness();
  changeActor = false;
  vi.mocked(authenticated).mockResolvedValue(actor);
  vi.mocked(localRuntimeConfig).mockResolvedValue(runtime);
  vi.spyOn(globalThis, 'fetch').mockImplementation(async (url) => {
    const path = new URL(String(url)).pathname;
    if (path === '/v1/participants/bootstrap-metadata')
      return Response.json({
        participantId: id(1),
        privacyDomainId: id(2),
        actionIntentDigest: participantAction.digest,
        stepUpActionIntentDigest: hash(99),
      });
    if (path.endsWith('/scope-replacement-source')) return Response.json(source);
    if (path.endsWith('/binding-preview')) {
      const roleId = path.split('/').at(-2)!;
      if (changeActor) vi.mocked(authenticated).mockResolvedValue({ ...actor, contextEpoch: '2' });
      return Response.json({
        participantId: id(1),
        roleId,
        roleRef: `urn:openpc:role:${roleId}`,
        revision: '1',
        roleDigest: hash(5),
        actionIntentIds: [participantAction.id],
      });
    }
    if (path.endsWith('/readiness')) return Response.json(observedReadiness);
    throw new Error('Unexpected mocked owner route');
  });
});
afterEach(() => {
  vi.restoreAllMocks();
});

describe('typed Platform ceiling BFF with mocked owners', () => {
  it('selects declared pending administration only from consumed preparation and the current withdrawal', async () => {
    const preview = await mutatePlatformCeilingWorkbench(
      request({ command: 'PREVIEW_PREPARATION', selection }),
    );
    const value = await preview.json();
    const plan = value.review.body;
    const candidate = {
      approvalRequestId: `urn:openpc:resource:${id(9)}`,
      candidateDigest: digest(plan),
      actionIntentId: participantAction.id,
      resourceRef: `urn:openpc:resource:${id(8)}`,
      expectedRevision: '0',
      state: 'CONSUMED',
      expiresAt: '2027-01-01T00:00:00Z',
      operationRef: `urn:openpc:operation:${id(10)}`,
      runtimePermission: 'NONE',
      deploymentIntent: null,
      candidate: plan,
      redactedFields: [],
    };
    const approval = {
      approvalRequestId: candidate.approvalRequestId,
      actionIntentId: participantAction.id,
      candidateDigest: candidate.candidateDigest,
      state: 'APPROVED',
      makerSubjectRef: `urn:openpc:resource:${id(100)}`,
      checkerSubjectRef: `urn:openpc:resource:${id(101)}`,
      revision: '2',
      createdAt: '2026-10-02T00:00:00.000000Z',
      updatedAt: '2026-10-02T00:00:00.000000Z',
    };
    let observedCandidate = candidate;
    const ownerSignals: AbortSignal[] = [];
    vi.mocked(fetch).mockImplementation(async (url, init) => {
      const path = new URL(String(url)).pathname;
      if (path.endsWith('/candidate') || path.endsWith('/readiness')) {
        expect(init?.signal).toBeInstanceOf(AbortSignal);
        ownerSignals.push(init!.signal!);
      }
      return Response.json(
        path.endsWith('/candidate')
          ? observedCandidate
          : path.endsWith('/readiness')
            ? observedReadiness
            : approval,
      );
    });
    const caller = new AbortController();
    const readRequest = new NextRequest(request({}), { signal: caller.signal });
    const deadlines = vi.spyOn(AbortSignal, 'timeout');
    const selected = await readPendingAdministrator(runtime, actor, readRequest, id(9), id(100));
    expect(selected).toMatchObject({
      administrator: { envelopeId: id(120), assignmentId: id(140) },
      checkerPrincipalId: id(101),
    });
    // Handoff provenance and readiness share the normal owner budget; neither
    // may silently revert to the shorter, unrelated 15-second deadline.
    expect(deadlines.mock.calls.length).toBeGreaterThanOrEqual(2);
    expect(deadlines.mock.calls.every(([milliseconds]) => milliseconds >= 120_000)).toBe(true);
    expect(ownerSignals).toHaveLength(2);
    expect(ownerSignals.every((signal) => !signal.aborted)).toBe(true);
    caller.abort();
    expect(ownerSignals.every((signal) => signal.aborted)).toBe(true);
    for (const changed of [
      { ...candidate, state: 'APPROVED' },
      { ...candidate, candidateDigest: hash(7) },
    ]) {
      observedCandidate = changed;
      expect(
        ((await readPendingAdministrator(runtime, actor, request({}), id(9), id(100))) as Response)
          .status,
      ).toBeGreaterThanOrEqual(400);
    }
    observedCandidate = candidate;
    observedReadiness = { ...readiness(), predecessorEpoch: '2' };
    expect(
      ((await readPendingAdministrator(runtime, actor, request({}), id(9), id(100))) as Response)
        .status,
    ).toBeGreaterThanOrEqual(400);
    observedReadiness = readiness();
    expect(
      (
        (await readPendingAdministrator(
          runtime,
          { ...actor, privacyDomainId: id(99) },
          request({}),
          id(9),
          id(100),
        )) as Response
      ).status,
    ).toBeGreaterThanOrEqual(400);
    expect(vi.mocked(fetch).mock.calls.every(([, init]) => init?.method !== 'POST')).toBe(true);
  });
  it('uses authoritative source and role digests, sealing exact actor and intended administration', async () => {
    const response = await mutatePlatformCeilingWorkbench(
      request({ command: 'PREVIEW_PREPARATION', selection }),
    );
    expect(response.status).toBe(200);
    const result = await response.json();
    const sealed = openBffPayload(result.reviewToken, runtime.cookieKey, 'platform-ceiling-review');
    expect(sealed).toMatchObject({
      actor: { principalId: actor.principalId, contextEpoch: '1' },
      checkerPrincipalId: id(101),
      body: {
        predecessorEpoch: '1',
        predecessorDigest: hash(2),
        administrators: [
          { roleDigest: hash(5), usable: { makerCheckerRequired: true, stepUpRequired: true } },
          { roleDigest: hash(5), usable: { makerCheckerRequired: true, stepUpRequired: true } },
        ],
      },
    });
    expect(result.review.candidateDigest).toBe(digest(result.review.body));
    expect(vi.mocked(fetch).mock.calls.every((call) => !call[1]?.method)).toBe(true);
    expect(
      (
        await mutatePlatformCeilingWorkbench(
          request({
            command: 'PREVIEW_PREPARATION',
            selection: { ...selection, predecessorEpoch: '9' },
          }),
        )
      ).status,
    ).toBe(400);
    changeActor = true;
    expect(
      (await mutatePlatformCeilingWorkbench(request({ command: 'PREVIEW_PREPARATION', selection })))
        .status,
    ).toBe(404);
  });
  it('blocks commit preview until signed withdrawal and both administration handoffs are complete and live', async () => {
    const command = {
      command: 'PREVIEW_COMMIT',
      platformContextId: id(4),
      replacementId: id(8),
      checkerPrincipalId: id(101),
      reason: selection.reason,
    };
    observedReadiness = {
      ...readiness(),
      unpreparedAdministrators: 1,
      administrators: readiness().administrators.map((admin, i) => ({ ...admin, ready: i !== 0 })),
    };
    expect((await mutatePlatformCeilingWorkbench(request(command))).status).toBeGreaterThanOrEqual(
      400,
    );
    observedReadiness = { ...readiness(), sourceExpiresAtNs: source.now };
    expect((await mutatePlatformCeilingWorkbench(request(command))).status).toBeGreaterThanOrEqual(
      400,
    );
    observedReadiness = readiness();
    const response = await mutatePlatformCeilingWorkbench(request(command));
    expect(response.status).toBe(200);
    expect((await response.json()).review.body).toMatchObject({
      expectedReplacementRevision: '1',
      expectedRootRevision: '1',
      predecessorEpoch: '1',
      readinessDigest: hash(4),
    });
    expect(vi.mocked(fetch).mock.calls.every((call) => !call[1]?.method)).toBe(true);
  });
  it('rejects a review from an old actor epoch before any proposal, approval or effect request', async () => {
    const preview = await mutatePlatformCeilingWorkbench(
      request({ command: 'PREVIEW_PREPARATION', selection }),
    );
    const result = await preview.json();
    vi.mocked(fetch).mockClear();
    vi.mocked(authenticated).mockResolvedValue({ ...actor, contextEpoch: '2' });
    expect(
      (
        await mutatePlatformCeilingWorkbench(
          request({ command: 'SUBMIT', reviewToken: result.reviewToken }),
        )
      ).status,
    ).toBe(404);
    expect(vi.mocked(fetch).mock.calls.every((call) => !call[1]?.method)).toBe(true);
  });
});

it.each([
  'eligible',
  'live-proof',
  'superseded',
  'wrong-business-key',
  'changed-revision',
  'changed-attempt',
  'missing-purpose',
] as const)('resumes the same Platform intent only after proof expiry: %s', async (mode) => {
  const preview = await mutatePlatformCeilingWorkbench(
    request({ command: 'PREVIEW_PREPARATION', selection }),
  );
  const reviewed = await preview.json();
  const original = openBffPayload(
    reviewed.reviewToken,
    runtime.cookieKey,
    'platform-ceiling-review',
  ) as { issuedAt: number; key: string };
  reviewed.reviewToken = sealBffPayload(
    { ...original, issuedAt: Date.now() - 31 * 60 * 1000 },
    runtime.cookieKey,
    'platform-ceiling-review',
  );
  const sealed = openBffPayload(
    reviewed.reviewToken,
    runtime.cookieKey,
    'platform-ceiling-review',
  ) as { key: string };
  const candidate = {
    attemptId: id(91),
    attempt: '1',
    predecessorApprovalRef: null,
    successorApprovalRef: mode === 'superseded' ? `urn:openpc:resource:${id(92)}` : null,
    businessIdempotencyKey: mode === 'wrong-business-key' ? 'different-business-key' : sealed.key,
    canRequestResume: mode !== 'live-proof',
    approvalUsable: mode === 'live-proof',
    makerSessionMatches: true,
    approvalRequestId: `urn:openpc:resource:${id(9)}`,
    candidateDigest: digest(reviewed.review.body),
    actionIntentId: participantAction.id,
    resourceRef: `urn:openpc:resource:${id(8)}`,
    expectedRevision: '0',
    state: 'APPROVED',
    expiresAt: '2027-01-01T00:00:00Z',
    operationRef: null,
    runtimePermission: 'NONE',
    deploymentIntent: null,
    candidate: reviewed.review.body,
    redactedFields: [],
  };
  const old = {
    approvalRequestId: candidate.approvalRequestId,
    actionIntentId: participantAction.id,
    candidateDigest: candidate.candidateDigest,
    state: 'APPROVED',
    makerSubjectRef: `urn:openpc:resource:${actor.principalId}`,
    checkerSubjectRef: `urn:openpc:resource:${id(101)}`,
    revision: '2',
    createdAt: '2026-10-02T00:00:00.000000Z',
    updatedAt: '2026-10-02T00:00:00.000000Z',
  };
  const patches: { headers: Headers; body: Record<string, unknown> }[] = [];
  let resuming = false;
  vi.mocked(fetch).mockImplementation(async (url, init) => {
    const path = new URL(String(url)).pathname;
    if (path === '/v1/participants/bootstrap-metadata')
      return Response.json({
        participantId: id(1),
        privacyDomainId: id(2),
        actionIntentDigest: participantAction.digest,
        stepUpActionIntentDigest: hash(99),
      });
    if (path.endsWith('/candidate'))
      return Response.json(
        resuming && mode === 'changed-attempt' ? { ...candidate, attempt: '2' } : candidate,
      );
    if (path.endsWith('/csrf')) return Response.json({ csrfToken: 'c'.repeat(64) });
    if (init?.method === 'PATCH') {
      patches.push({ headers: new Headers(init.headers), body: JSON.parse(String(init.body)) });
      return Response.json({
        operationId: id(93),
        actionIntentId: 'ACT-APPROVAL_REQUESTS_UPDATE_RESOURCE-V1',
        intentDigest: hash(3),
        idempotencyKey: 'same-resume-request',
        resourceRef: `urn:openpc:resource:${id(94)}`,
        revision: '1',
        state: 'SUCCEEDED',
        truthState: 'SUCCESS',
        createdAt: old.createdAt,
        updatedAt: old.updatedAt,
      });
    }
    return Response.json(resuming && mode === 'changed-revision' ? { ...old, revision: '3' } : old);
  });
  const readRequest = new NextRequest(
    `http://localhost:8080/api/v1/ui/platform-ceiling-workbench?approvalRequestId=${id(9)}`,
  );
  const loaded = await readPlatformCeilingWorkbench(readRequest);
  expect(loaded.status).toBe(200);
  const readback = await loaded.json();
  const eligible = !['live-proof', 'superseded'].includes(mode);
  expect(Boolean(readback.resumableReview)).toBe(eligible);
  const receivingPurpose = {
    command: 'RESUME',
    actionIntentId: approvalUpdateAction.id,
    actionIntentDigest: approvalUpdateAction.digest,
    expectedRevision: old.revision,
    predecessorCandidateId: candidate.attemptId,
    expectedAttempt: candidate.attempt,
    candidateDigest: candidate.candidateDigest,
    reason: platformRecoveryApprovalResumeReason,
    approvalRequestId: old.approvalRequestId,
  };
  expect(readback.resumeStepUp).toEqual(
    eligible
      ? {
          actionIntentId: approvalUpdateAction.id,
          actionIntentDigest: approvalUpdateAction.digest,
          resourceId: id(9),
          resourceDigest: digest(receivingPurpose),
        }
      : null,
  );
  if (eligible) {
    expect(readback.resumeStepUp.resourceDigest).not.toBe(candidate.candidateDigest);
    expect(readback.resumeStepUp.resourceDigest).not.toBe(
      digest({ ...receivingPurpose, approvalRequestId: `urn:openpc:resource:${id(10)}` }),
    );
    expect(readback.resumeStepUp.resourceDigest).not.toBe(
      digest({ ...receivingPurpose, expectedRevision: '3' }),
    );
    expect(readback.resumeStepUp.resourceDigest).not.toBe(
      digest({ ...receivingPurpose, predecessorCandidateId: id(92) }),
    );
  }

  if (eligible) {
    const rebound = openBffPayload(
      readback.resumableReview.reviewToken,
      runtime.cookieKey,
      'platform-ceiling-review',
    );
    expect(rebound).toMatchObject({
      body: candidate.candidate,
      key: candidate.businessIdempotencyKey,
      checkerPrincipalId: id(101),
    });
    expect(readback.resumableReview.review.businessIdempotencyKey).toBe(
      candidate.businessIdempotencyKey,
    );
    expect(readback.resumableReview.reviewToken).not.toBe(reviewed.reviewToken);
    expect((rebound as { issuedAt: number }).issuedAt).toBeGreaterThan(
      original.issuedAt - 30 * 60 * 1000,
    );
  }
  vi.mocked(authenticated).mockResolvedValue({ ...actor, principalId: id(101) });
  const checkerRead = await readPlatformCeilingWorkbench(readRequest);
  const checkerResult = await checkerRead.json();
  expect(checkerResult.resumableReview).toBeUndefined();
  expect(checkerResult.resumeStepUp).toBeNull();
  expect(patches).toHaveLength(0);
  vi.mocked(authenticated).mockResolvedValue(actor);
  resuming = true;
  let selectedReviewToken = eligible ? readback.resumableReview.reviewToken : reviewed.reviewToken;
  if (mode === 'missing-purpose') {
    const bound = openBffPayload(
      selectedReviewToken,
      runtime.cookieKey,
      'platform-ceiling-review',
    ) as Record<string, unknown>;
    const withoutPurpose = { ...bound };
    delete withoutPurpose.resumePurpose;
    selectedReviewToken = sealBffPayload(
      withoutPurpose,
      runtime.cookieKey,
      'platform-ceiling-review',
    );
  }
  const response = await mutatePlatformCeilingWorkbench(
    request({
      command: 'RESUME',
      reviewToken: mode === 'wrong-business-key' ? reviewed.reviewToken : selectedReviewToken,
      approvalRequestId: id(9),
    }),
  );
  if (mode === 'eligible') {
    expect(response.status).toBe(202);
    const result = await response.json();
    expect(result.approvalRequestId).toBe(id(94));
    expect(result.review.body).toEqual(reviewed.review.body);
    expect(patches).toHaveLength(1);
    expect(patches[0]?.body).toMatchObject({
      command: 'RESUME',
      candidateDigest: candidate.candidateDigest,
      predecessorCandidateId: id(91),
      expectedAttempt: '1',
      expectedRevision: '2',
      reason: platformRecoveryApprovalResumeReason,
    });
    expect(patches[0]?.body).not.toHaveProperty('approvalRequestId');
    expect(digest({ ...patches[0]?.body, approvalRequestId: old.approvalRequestId })).toBe(
      readback.resumeStepUp.resourceDigest,
    );
    expect(patches[0]?.headers.get('If-Match')).toBe(
      `"${digest({ resourceId: id(9), revision: '2' })}"`,
    );
  } else {
    expect(response.status).toBe(404);
    expect(patches).toHaveLength(0);
  }
});

function recoveryReceipt() {
  const { source: enrolled, intent } = platformRecoveryFixture();
  const intentDigest = digest(intent);
  return {
    actors: {
      executorPrincipalId: enrolled.enrollment.recoveryPrincipal.principalId,
      custodianPrincipalIds: enrolled.enrollment.custodians.map((v) => v.principalId),
      administratorPrincipalIds: enrolled.enrollment.administratorPrincipalIds,
    },
    recoveryId: intent.recoveryId,
    enrollmentId: intent.enrollmentId,
    intent,
    intentDigest,
    state: 'ACTIVE',
    revision: '4',
    assurance: enrolled.enrollment.assurance,
    authority: 'FIXED_PLATFORM_HANDOFF_ONLY',
    proofs: [],
    activation: {
      recoveryId: intent.recoveryId,
      enrollmentId: intent.enrollmentId,
      operationId: id(900),
      state: 'ACTIVE',
      authority: 'FIXED_PLATFORM_HANDOFF_ONLY',
      assurance: enrolled.enrollment.assurance,
      activatedAt: intent.validFrom,
      expiresAt: intent.validUntil,
      intentDigest,
      bindings: [100, 101].map((n) => ({
        principalId: id(n),
        principalEpoch: '2',
        envelopeId: id(n + 500),
        assignmentId: id(n + 600),
      })),
    },
  };
}
it('loads the exact owner recovery intent into normal approval without selecting new names or changing its lifetime', async () => {
  const receipt = recoveryReceipt();
  vi.mocked(identityCsrf).mockResolvedValue('unit-recovery-csrf');
  vi.mocked(fetch).mockImplementation(async (url, init) => {
    if (String(url).endsWith('/commands')) {
      expect(init?.headers).toMatchObject({
        'X-CSRF-Token': 'unit-recovery-csrf',
        'X-OpenPC-Browser-Origin': 'http://localhost:8080',
      });
      expect(JSON.parse(String(init?.body))).toEqual({
        privacyDomainId: actor.privacyDomainId,
        command: { kind: 'READ', recoveryId: receipt.recoveryId },
      });
      return Response.json(receipt);
    }
    return Response.json({
      participantId: id(1),
      privacyDomainId: id(2),
      actionIntentDigest: participantAction.digest,
      stepUpActionIntentDigest: hash(99),
    });
  });
  const response = await mutatePlatformCeilingWorkbench(
    request({
      command: 'PREVIEW_RECOVERY_HANDOFF',
      enrollmentId: receipt.enrollmentId,
      recoveryId: receipt.recoveryId,
    }),
  );
  expect(response.status).toBe(200);
  const reviewed = await response.json();
  expect(reviewed.review.phase).toBe('PREPARE');
  expect(reviewed.review.body).toEqual(receipt.intent.preparation);
  expect(reviewed.review.checkerPrincipalId).toBe(id(101));
  expect(reviewed.approvalRequestId).toBeUndefined();
});

function retainedRecoveryReview() {
  const receipt = recoveryReceipt();
  return {
    phase: 'PREPARE',
    issuedAt: Date.now() - 31 * 60 * 1000,
    actor: {
      sessionId: actor.sessionId,
      principalId: actor.principalId,
      participantId: actor.participantId,
      privacyDomainId: actor.privacyDomainId,
      contextEpoch: actor.contextEpoch,
    },
    body: receipt.intent.preparation,
    checkerPrincipalId: id(101),
    candidateDigest: digest(receipt.intent.preparation),
    key: 'original-recovery-business-key',
    resourceReservationId: id(888),
  };
}

it.each(['EXPIRED', 'REVOKED'] as const)(
  'reconciles the exact %s recovery review from a fresh session without minting or staging authority',
  async (state) => {
    const receipt = recoveryReceipt(),
      original = retainedRecoveryReview();
    receipt.state = state;
    receipt.authority = 'NONE';
    receipt.intent.validUntil = new Date(Date.now() - 1).toISOString();
    receipt.intentDigest = digest(receipt.intent);
    receipt.activation.intentDigest = receipt.intentDigest;
    receipt.activation.expiresAt = receipt.intent.validUntil;
    Object.assign(receipt, {
      closedPreparationCorrespondence: {
        schema: 'pc.identity.closed-platform-preparation-correspondence',
        schemaVersion: 1,
        preparationDigest: original.candidateDigest,
        enrollmentId: receipt.enrollmentId,
        recoveryId: receipt.recoveryId,
        intentDigest: receipt.intentDigest,
        activationOperationId: receipt.activation.operationId,
      },
    });
    vi.mocked(authenticated).mockResolvedValue({ ...actor, sessionId: id(999), contextEpoch: '2' });
    vi.mocked(identityCsrf).mockResolvedValue('unit-recovery-csrf');
    const commands: unknown[] = [];
    vi.mocked(fetch).mockImplementation(async (url, init) => {
      if (String(url).endsWith('/commands')) {
        commands.push(JSON.parse(String(init?.body)));
        return Response.json(receipt);
      }
      return Response.json({
        participantId: id(1),
        privacyDomainId: id(2),
        actionIntentDigest: participantAction.digest,
        stepUpActionIntentDigest: hash(99),
      });
    });
    const retainedReviewToken = sealBffPayload(
      original,
      runtime.cookieKey,
      'platform-ceiling-review',
    );
    const response = await mutatePlatformCeilingWorkbench(
      request({
        command: 'RECONCILE_CLOSED_RECOVERY_HANDOFF',
        enrollmentId: receipt.enrollmentId,
        recoveryId: receipt.recoveryId,
        retainedReviewToken,
      }),
    );
    expect(response.status).toBe(200);
    const value = await response.json();
    expect(value.closedRecovery).toMatchObject({
      state,
      authority: 'NONE',
      candidateDigest: original.candidateDigest,
      businessIdempotencyKey: original.key,
    });
    expect(value.reviewToken).toBeUndefined();
    expect(value.review).toBeUndefined();
    expect(value.approvalRequestId).toBeUndefined();
    expect(commands).toEqual([
      {
        privacyDomainId: actor.privacyDomainId,
        command: {
          kind: 'READ',
          recoveryId: receipt.recoveryId,
          preparationDigest: original.candidateDigest,
        },
      },
    ]);
    const mutation = await mutatePlatformCeilingWorkbench(
      request({ command: 'SUBMIT', reviewToken: retainedReviewToken }),
    );
    expect(mutation.status).toBeGreaterThanOrEqual(400);
    expect(commands).toHaveLength(1);
  },
);

it.each(['unbound-continuation', 'wrong-bound-case', 'expired-state-before-expiry'] as const)(
  'does not release closed review custody for %s',
  async (failure) => {
    const receipt = recoveryReceipt(),
      original = retainedRecoveryReview();
    receipt.state = 'REVOKED';
    receipt.authority = 'NONE';
    let binding:
      | {
          enrollmentId: string;
          recoveryId: string;
          intentDigest: string;
          activationOperationId: string;
        }
      | undefined;
    if (failure === 'unbound-continuation') {
      receipt.intent = pendingPlatformRecoveryFixture().intent;
      receipt.intentDigest = digest(receipt.intent);
      receipt.activation.intentDigest = receipt.intentDigest;
      original.body = receipt.intent.preparation;
      original.candidateDigest = digest(original.body);
    }
    if (failure === 'wrong-bound-case')
      binding = {
        enrollmentId: receipt.enrollmentId,
        recoveryId: id(999),
        intentDigest: receipt.intentDigest,
        activationOperationId: receipt.activation.operationId,
      };
    if (failure === 'expired-state-before-expiry') receipt.state = 'EXPIRED';
    vi.mocked(identityCsrf).mockResolvedValue('unit-recovery-csrf');
    const commands: unknown[] = [];
    vi.mocked(fetch).mockImplementation(async (url, init) => {
      if (String(url).endsWith('/commands')) {
        commands.push(JSON.parse(String(init?.body)));
        return Response.json(receipt);
      }
      return Response.json({
        participantId: id(1),
        privacyDomainId: id(2),
        actionIntentDigest: participantAction.digest,
        stepUpActionIntentDigest: hash(99),
      });
    });
    const response = await mutatePlatformCeilingWorkbench(
      request({
        command: 'RECONCILE_CLOSED_RECOVERY_HANDOFF',
        enrollmentId: receipt.enrollmentId,
        recoveryId: receipt.recoveryId,
        retainedReviewToken: sealBffPayload(
          { ...original, ...(binding ? { recoveryBinding: binding } : {}) },
          runtime.cookieKey,
          'platform-ceiling-review',
        ),
      }),
    );
    expect(response.status).toBeGreaterThanOrEqual(400);
    expect((await response.json()).closedRecovery).toBeUndefined();
    expect(commands).toEqual([
      {
        privacyDomainId: actor.privacyDomainId,
        command: {
          kind: 'READ',
          recoveryId: receipt.recoveryId,
          ...(binding ? {} : { preparationDigest: original.candidateDigest }),
        },
      },
    ]);
  },
);

it.each([
  'principalId',
  'participantId',
  'privacyDomainId',
  'future',
  'phase',
  'digest',
  'body',
  'checker',
  'token',
  'active-case',
  'completed-case',
  'authority',
  'wrong-enrollment',
  'wrong-case',
  'activation',
  'activation-digest',
  'changed-current-actor',
] as const)(
  'denies closed recovery reconciliation with %s while performing no business staging',
  async (failure) => {
    const receipt = recoveryReceipt(),
      original = retainedRecoveryReview();
    receipt.state = 'REVOKED';
    receipt.authority = 'NONE';
    if (['principalId', 'participantId', 'privacyDomainId'].includes(failure))
      original.actor[failure as 'principalId'] = id(999);
    if (failure === 'future') original.issuedAt = Date.now() + 60000;
    if (failure === 'phase') original.phase = 'COMMIT';
    if (failure === 'digest') original.candidateDigest = hash(999);
    if (failure === 'body') {
      original.body.reason = 'Different original intent.';
      original.candidateDigest = digest(original.body);
    }
    if (failure === 'checker') original.checkerPrincipalId = id(999);
    if (failure === 'active-case') receipt.state = 'ACTIVE';
    if (failure === 'completed-case') receipt.state = 'COMPLETED';
    if (failure === 'authority') receipt.authority = 'FIXED_PLATFORM_HANDOFF_ONLY';
    if (failure === 'wrong-enrollment') receipt.enrollmentId = id(999);
    if (failure === 'wrong-case') receipt.recoveryId = id(999);
    if (failure === 'activation') delete (receipt as Partial<typeof receipt>).activation;
    if (failure === 'activation-digest') receipt.activation.intentDigest = hash(999);
    vi.mocked(identityCsrf).mockResolvedValue('unit-recovery-csrf');
    const posts: unknown[] = [];
    vi.mocked(fetch).mockImplementation(async (url, init) => {
      if (init?.method === 'POST') posts.push(JSON.parse(String(init.body)));
      if (String(url).endsWith('/commands')) {
        if (failure === 'changed-current-actor')
          vi.mocked(authenticated).mockResolvedValue({ ...actor, contextEpoch: '2' });
        return Response.json(receipt);
      }
      return Response.json({
        participantId: id(1),
        privacyDomainId: id(2),
        actionIntentDigest: participantAction.digest,
        stepUpActionIntentDigest: hash(99),
      });
    });
    const response = await mutatePlatformCeilingWorkbench(
      request({
        command: 'RECONCILE_CLOSED_RECOVERY_HANDOFF',
        enrollmentId: id(5),
        recoveryId: id(7),
        retainedReviewToken:
          failure === 'token'
            ? 'invalid-old-token'
            : sealBffPayload(original, runtime.cookieKey, 'platform-ceiling-review'),
      }),
    );
    expect(response.status).toBeGreaterThanOrEqual(400);
    const result = await response.json();
    expect(result.closedRecovery).toBeUndefined();
    expect(result.reviewToken).toBeUndefined();
    expect(
      posts.every((post) => (post as { command: { kind: string } }).command.kind === 'READ'),
    ).toBe(true);
  },
);

it('refreshes an expired browser seal only through current recovery readback while preserving its original business intent', async () => {
  const receipt = recoveryReceipt(),
    original = retainedRecoveryReview();
  vi.mocked(identityCsrf).mockResolvedValue('unit-recovery-csrf');
  const commands: unknown[] = [];
  vi.mocked(fetch).mockImplementation(async (url, init) => {
    if (String(url).endsWith('/commands')) {
      commands.push(JSON.parse(String(init?.body)));
      return Response.json(receipt);
    }
    return Response.json({
      participantId: id(1),
      privacyDomainId: id(2),
      actionIntentDigest: participantAction.digest,
      stepUpActionIntentDigest: hash(99),
    });
  });
  const response = await mutatePlatformCeilingWorkbench(
    request({
      command: 'PREVIEW_RECOVERY_HANDOFF',
      enrollmentId: receipt.enrollmentId,
      recoveryId: receipt.recoveryId,
      retainedReviewToken: sealBffPayload(original, runtime.cookieKey, 'platform-ceiling-review'),
    }),
  );
  expect(response.status).toBe(200);
  const value = await response.json();
  const refreshed = openBffPayload(
    value.reviewToken,
    runtime.cookieKey,
    'platform-ceiling-review',
  ) as typeof original;
  expect(refreshed).toEqual({
    ...original,
    issuedAt: refreshed.issuedAt,
    recoveryBinding: {
      enrollmentId: receipt.enrollmentId,
      recoveryId: receipt.recoveryId,
      intentDigest: receipt.intentDigest,
      activationOperationId: receipt.activation.operationId,
    },
  });
  expect(refreshed.issuedAt).toBeGreaterThan(original.issuedAt);
  expect(value.review.businessIdempotencyKey).toBe(original.key);
  expect(value.review.body).toEqual(original.body);
  expect(value.approvalRequestId).toBeUndefined();
  expect(commands).toEqual([
    {
      privacyDomainId: actor.privacyDomainId,
      command: { kind: 'READ', recoveryId: receipt.recoveryId },
    },
  ]);
});

it.each([0, 1])(
  'denies recovery review minting when its case expires during final actor readback by %s ms',
  async (afterExpiryMs) => {
    const receipt = recoveryReceipt(),
      original = retainedRecoveryReview(),
      expiresAt = Date.parse(receipt.intent.validUntil);
    let now = expiresAt - 1;
    vi.spyOn(Date, 'now').mockImplementation(() => now);
    vi.mocked(identityCsrf).mockResolvedValue('unit-recovery-csrf');
    let actorReads = 0;
    const commands: unknown[] = [];
    vi.mocked(fetch).mockImplementation(async (url, init) => {
      if (String(url).endsWith('/commands')) {
        commands.push(JSON.parse(String(init?.body)));
        return Response.json(receipt);
      }
      actorReads += 1;
      if (actorReads === 2) now = expiresAt + afterExpiryMs;
      return Response.json({
        participantId: id(1),
        privacyDomainId: id(2),
        actionIntentDigest: participantAction.digest,
        stepUpActionIntentDigest: hash(99),
      });
    });
    const response = await mutatePlatformCeilingWorkbench(
      request({
        command: 'PREVIEW_RECOVERY_HANDOFF',
        enrollmentId: receipt.enrollmentId,
        recoveryId: receipt.recoveryId,
        retainedReviewToken: sealBffPayload(original, runtime.cookieKey, 'platform-ceiling-review'),
      }),
    );
    expect(actorReads).toBe(2);
    expect(response.status).toBeGreaterThanOrEqual(400);
    expect((await response.json()).reviewToken).toBeUndefined();
    expect(commands).toEqual([
      {
        privacyDomainId: actor.privacyDomainId,
        command: { kind: 'READ', recoveryId: receipt.recoveryId },
      },
    ]);
  },
);

it.each([
  'sessionId',
  'principalId',
  'participantId',
  'privacyDomainId',
  'contextEpoch',
  'future',
  'phase',
  'digest',
  'checker',
  'body',
  'token',
  'expired-case',
  'no-authority',
  'changed-current-actor',
] as const)(
  'denies retained recovery refresh with %s and performs no business staging',
  async (failure) => {
    const original = retainedRecoveryReview(),
      receipt = recoveryReceipt();
    if (['sessionId', 'principalId', 'participantId', 'privacyDomainId'].includes(failure))
      original.actor[failure as 'sessionId'] = id(999);
    if (failure === 'contextEpoch') original.actor.contextEpoch = '2';
    if (failure === 'future') original.issuedAt = Date.now() + 60000;
    if (failure === 'phase') original.phase = 'COMMIT';
    if (failure === 'digest') original.candidateDigest = hash(999);
    if (failure === 'checker') original.checkerPrincipalId = id(999);
    if (failure === 'body') {
      original.body.reason = 'A different retained business intent.';
      original.candidateDigest = digest(original.body);
    }
    if (failure === 'expired-case')
      receipt.intent.validUntil = new Date(Date.now() - 1).toISOString();
    if (failure === 'no-authority') receipt.authority = 'NONE';
    const mutations: string[] = [];
    vi.mocked(identityCsrf).mockResolvedValue('unit-recovery-csrf');
    vi.mocked(fetch).mockImplementation(async (url, init) => {
      if (init?.method === 'POST') mutations.push(String(url));
      if (String(url).endsWith('/commands')) {
        expect(JSON.parse(String(init?.body)).command.kind).toBe('READ');
        if (failure === 'changed-current-actor')
          vi.mocked(authenticated).mockResolvedValue({ ...actor, contextEpoch: '2' });
        return Response.json(receipt);
      }
      return Response.json({
        participantId: id(1),
        privacyDomainId: id(2),
        actionIntentDigest: participantAction.digest,
        stepUpActionIntentDigest: hash(99),
      });
    });
    const response = await mutatePlatformCeilingWorkbench(
      request({
        command: 'PREVIEW_RECOVERY_HANDOFF',
        enrollmentId: receipt.enrollmentId,
        recoveryId: receipt.recoveryId,
        retainedReviewToken:
          failure === 'token'
            ? 'invalid-original-seal'
            : sealBffPayload(original, runtime.cookieKey, 'platform-ceiling-review'),
      }),
    );
    expect(response.status).toBeGreaterThanOrEqual(400);
    expect((await response.json()).reviewToken).toBeUndefined();
    expect(mutations.every((url) => url.endsWith('/commands'))).toBe(true);
  },
);
it.each([
  'expired',
  'no authority',
  'wrong case',
  'wrong enrollment',
  'wrong maker',
  'missing activation',
  'changed activation digest',
])('rejects recovery handoff %s without a normal approval or execution', async (failure) => {
  const receipt = recoveryReceipt();
  if (failure === 'expired') receipt.intent.validUntil = new Date(Date.now() - 1).toISOString();
  if (failure === 'no authority') receipt.authority = 'NONE';
  if (failure === 'wrong case') receipt.recoveryId = id(999);
  if (failure === 'wrong enrollment') receipt.enrollmentId = id(999);
  if (failure === 'wrong maker')
    receipt.intent.preparation.administrators[0]!.principalId = id(999);
  if (failure === 'missing activation') delete (receipt as Partial<typeof receipt>).activation;
  if (failure === 'changed activation digest') receipt.activation.intentDigest = hash(777);
  vi.mocked(identityCsrf).mockResolvedValue('unit-csrf');
  vi.mocked(fetch).mockImplementation(async (url) =>
    String(url).endsWith('/commands')
      ? Response.json(receipt)
      : Response.json({
          participantId: id(1),
          privacyDomainId: id(2),
          actionIntentDigest: participantAction.digest,
          stepUpActionIntentDigest: hash(99),
        }),
  );
  const response = await mutatePlatformCeilingWorkbench(
    request({ command: 'PREVIEW_RECOVERY_HANDOFF', enrollmentId: id(5), recoveryId: id(7) }),
  );
  expect(response.status).toBeGreaterThanOrEqual(400);
  expect((await response.json()).reviewToken).toBeUndefined();
});

it.each([
  'absent',
  'original',
  'foreign-key',
  'different-session',
  'ambiguous-page',
  'unavailable',
] as const)('reconciles the original commit approval before durable requests: %s', async (mode) => {
  const preview = await mutatePlatformCeilingWorkbench(
    request({
      command: 'PREVIEW_COMMIT',
      platformContextId: id(4),
      replacementId: id(8),
      checkerPrincipalId: id(101),
      reason: selection.reason,
    }),
  );
  const reviewed = await preview.json();
  const sealed = openBffPayload(
    reviewed.reviewToken,
    runtime.cookieKey,
    'platform-ceiling-review',
  ) as { key: string };
  const approval = {
    approvalRequestId: `urn:openpc:resource:${id(9)}`,
    actionIntentId: participantAction.id,
    candidateDigest: reviewed.review.candidateDigest,
    state: 'REQUESTED',
    makerSubjectRef: `urn:openpc:resource:${actor.principalId}`,
    checkerSubjectRef: `urn:openpc:resource:${id(101)}`,
    revision: '1',
    createdAt: '2026-10-02T00:00:00Z',
    updatedAt: '2026-10-02T00:00:00Z',
  };
  const candidate = {
    approvalRequestId: approval.approvalRequestId,
    candidateDigest: approval.candidateDigest,
    actionIntentId: participantAction.id,
    resourceRef: `urn:openpc:resource:${id(8)}`,
    expectedRevision: '1',
    state: 'APPROVAL_REQUESTED',
    expiresAt: '2027-01-01T00:00:00Z',
    operationRef: null,
    runtimePermission: 'NONE',
    deploymentIntent: null,
    candidate: reviewed.review.body,
    redactedFields: [],
    businessIdempotencyKey: mode === 'foreign-key' ? 'foreign-original' : sealed.key,
    makerSessionMatches: mode !== 'different-session',
    successorApprovalRef: null,
  };
  const events: string[] = [];
  vi.mocked(fetch).mockImplementation(async (url, init) => {
    const u = new URL(String(url)),
      path = u.pathname;
    if (path === '/v1/participants/bootstrap-metadata')
      return Response.json({
        participantId: id(1),
        privacyDomainId: id(2),
        actionIntentDigest: participantAction.digest,
        stepUpActionIntentDigest: hash(99),
      });
    if (path === '/api/v1/approval-requests' && !init?.method) {
      events.push('read-original');
      expect(u.searchParams.get('filter')).toBe(`candidateDigest:eq:${approval.candidateDigest}`);
      if (mode === 'unavailable') throw new Error('Unavailable owner readback.');
      const items =
        mode === 'absent' ? [] : mode === 'ambiguous-page' ? [approval, approval] : [approval];
      return Response.json({
        items,
        nextCursor: null,
        total: String(items.length),
        completeness: 'COMPLETE',
        authorizedEmpty: items.length === 0,
        snapshotRevision: '1',
      });
    }
    if (path.endsWith('/candidate')) return Response.json(candidate);
    if (decodeURIComponent(path).endsWith(id(9))) return Response.json(approval);
    if (path.endsWith('/csrf')) return Response.json({ csrfToken: 'c'.repeat(64) });
    if (path.endsWith('/commit/prepare')) {
      events.push('stage');
      expect(JSON.parse(String(init?.body))).toEqual(reviewed.review.body);
      expect(new Headers(init?.headers).get('Idempotency-Key')).toBe(sealed.key);
      return Response.json({
        candidate: reviewed.review.body,
        candidateDigest: approval.candidateDigest,
        expectedRevision: '1',
        actionIntentDigest: participantAction.digest,
      });
    }
    if (path === '/api/v1/approval-requests' && init?.method === 'POST') {
      events.push('request-approval');
      return Response.json({
        operationId: id(93),
        actionIntentId: 'ACT-APPROVAL_REQUESTS_CREATE_RESOURCE-V1',
        intentDigest: hash(3),
        idempotencyKey: sealed.key + '-approval',
        resourceRef: `urn:openpc:resource:${id(9)}`,
        revision: '1',
        state: 'SUCCEEDED',
        truthState: 'SUCCESS',
        createdAt: approval.createdAt,
        updatedAt: approval.updatedAt,
      });
    }
    throw new Error('Unexpected mocked route');
  });
  const response = await mutatePlatformCeilingWorkbench(
    request({ command: 'SUBMIT', reviewToken: reviewed.reviewToken }),
  );
  if (mode === 'absent') {
    expect(response.status).toBe(202);
    expect(events).toEqual(['read-original', 'stage', 'request-approval']);
  } else if (mode === 'original') {
    expect(response.status).toBe(200);
    expect((await response.json()).approvalRequestId).toBe(id(9));
    expect(events).toEqual(['read-original']);
  } else {
    expect(response.status).toBeGreaterThanOrEqual(400);
    expect(events).toEqual(['read-original']);
  }
});

it.each([
  'missing',
  'wrong-digest',
  'wrong-enrollment',
  'wrong-case',
  'wrong-intent',
  'wrong-activation',
] as const)('cannot retire an unbound legacy seal on %s owner correspondence', async (failure) => {
  const receipt = recoveryReceipt(),
    original = retainedRecoveryReview();
  receipt.state = 'REVOKED';
  receipt.authority = 'NONE';
  const correspondence = {
    schema: 'pc.identity.closed-platform-preparation-correspondence',
    schemaVersion: 1,
    preparationDigest: original.candidateDigest,
    enrollmentId: receipt.enrollmentId,
    recoveryId: receipt.recoveryId,
    intentDigest: receipt.intentDigest,
    activationOperationId: receipt.activation.operationId,
  };
  if (failure === 'wrong-digest') correspondence.preparationDigest = hash(99);
  if (failure === 'wrong-enrollment') correspondence.enrollmentId = id(999);
  if (failure === 'wrong-case') correspondence.recoveryId = id(999);
  if (failure === 'wrong-intent') correspondence.intentDigest = hash(99);
  if (failure === 'wrong-activation') correspondence.activationOperationId = id(999);
  if (failure !== 'missing')
    Object.assign(receipt, { closedPreparationCorrespondence: correspondence });
  vi.mocked(identityCsrf).mockResolvedValue('unit-recovery-csrf');
  vi.mocked(fetch).mockResolvedValue(Response.json(receipt));
  const response = await mutatePlatformCeilingWorkbench(
    request({
      command: 'RECONCILE_CLOSED_RECOVERY_HANDOFF',
      enrollmentId: receipt.enrollmentId,
      recoveryId: receipt.recoveryId,
      retainedReviewToken: sealBffPayload(original, runtime.cookieKey, 'platform-ceiling-review'),
    }),
  );
  expect(response.status).toBeGreaterThanOrEqual(400);
  expect((await response.json()).closedRecovery).toBeUndefined();
  expect(fetch).toHaveBeenCalledTimes(1);
});

it.each(['original-response', 'owner-denial', 'caller-abort'] as const)(
  'retains exact one approval request across a delayed owner: %s',
  async (mode) => {
    const preview = await mutatePlatformCeilingWorkbench(
      request({ command: 'PREVIEW_PREPARATION', selection }),
    );
    const reviewed = await preview.json();
    expect(preview.status).toBe(200);
    const controller = new AbortController();
    const input = request({ command: 'SUBMIT', reviewToken: reviewed.reviewToken });
    const submittedRequest = new NextRequest(input.url, {
      method: 'POST',
      headers: input.headers,
      body: JSON.stringify({ command: 'SUBMIT', reviewToken: reviewed.reviewToken }),
      signal: controller.signal,
    });
    let announceApproval!: () => void;
    const approvalStarted = new Promise<void>((resolve) => {
      announceApproval = resolve;
    });
    const submittedBodies: unknown[] = [];
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
    vi.spyOn(AbortSignal, 'timeout').mockImplementation((ms) => {
      const deadline = new AbortController();
      setTimeout(() => deadline.abort(new DOMException('Owner deadline', 'TimeoutError')), ms);
      return deadline.signal;
    });
    vi.mocked(fetch).mockImplementation(async (url, init) => {
      const path = new URL(String(url)).pathname;
      if (path === '/v1/participants/bootstrap-metadata')
        return Response.json({
          participantId: id(1),
          privacyDomainId: id(2),
          actionIntentDigest: participantAction.digest,
          stepUpActionIntentDigest: hash(99),
        });
      if (path.endsWith('/csrf')) return Response.json({ csrfToken: 'c'.repeat(64) });
      if (path.endsWith('/scope-replacements/prepare'))
        return Response.json({
          candidate: reviewed.review.body,
          candidateDigest: reviewed.review.candidateDigest,
          expectedRevision: '0',
          actionIntentDigest: participantAction.digest,
        });
      if (path === '/api/v1/approval-requests' && init?.method === 'POST') {
        submittedBodies.push(JSON.parse(String(init.body)));
        expect(new Headers(init.headers).get('Idempotency-Key')).toBe(
          reviewed.review.businessIdempotencyKey + '-approval',
        );
        announceApproval();
        return new Promise<Response>((resolve, reject) => {
          const timer = setTimeout(
            () =>
              resolve(
                mode === 'owner-denial'
                  ? Response.json({ code: 'PC-POLICY-2005' }, { status: 403 })
                  : Response.json(
                      {
                        operationId: id(93),
                        actionIntentId: 'ACT-APPROVAL_REQUESTS_CREATE_RESOURCE-V1',
                        intentDigest: hash(3),
                        idempotencyKey: reviewed.review.businessIdempotencyKey + '-approval',
                        resourceRef: `urn:openpc:resource:${id(9)}`,
                        revision: '1',
                        state: 'SUCCEEDED',
                        truthState: 'SUCCESS',
                        createdAt: '2026-10-02T00:00:00.000000Z',
                        updatedAt: '2026-10-02T00:00:00.000000Z',
                      },
                      { status: 202 },
                    ),
              ),
            21_000,
          );
          init.signal?.addEventListener(
            'abort',
            () => {
              clearTimeout(timer);
              reject(init.signal?.reason);
            },
            { once: true },
          );
        });
      }
      throw new Error('Unexpected delayed-owner request');
    });
    try {
      const pending = mutatePlatformCeilingWorkbench(submittedRequest);
      await approvalStarted;
      if (mode === 'caller-abort') controller.abort();
      await vi.advanceTimersByTimeAsync(21_001);
      const response = await pending;
      expect(response.status).toBe(
        mode === 'original-response' ? 202 : mode === 'owner-denial' ? 404 : 503,
      );
      expect(submittedBodies).toHaveLength(1);
      expect(submittedBodies[0]).toMatchObject({
        candidateDigest: reviewed.review.candidateDigest,
        makerSubjectRef: `urn:openpc:resource:${actor.principalId}`,
        checkerSubjectRef: `urn:openpc:resource:${reviewed.review.checkerPrincipalId}`,
      });
      if (mode === 'original-response')
        expect((await response.json()).approvalRequestId).toBe(id(9));
      expect(
        vi
          .mocked(fetch)
          .mock.calls.some(
            ([url]) =>
              new URL(String(url)).pathname === `/v1/platform-contexts/${id(4)}/scope-replacements`,
          ),
      ).toBe(false);
    } finally {
      vi.clearAllTimers();
      vi.useRealTimers();
    }
  },
);

it.each(['before-stage', 'after-stage', 'approval-csrf', 'changed-actor'] as const)(
  'does not carry stale review authority across an awaited owner: %s',
  async (boundary) => {
    const preview = await mutatePlatformCeilingWorkbench(
      request({ command: 'PREVIEW_PREPARATION', selection }),
    );
    const reviewed = await preview.json();
    const seal = openBffPayload(
      reviewed.reviewToken,
      runtime.cookieKey,
      'platform-ceiling-review',
    ) as { issuedAt: number };
    let staged = 0,
      approvals = 0;
    const expire = () => vi.spyOn(Date, 'now').mockReturnValue(seal.issuedAt + 30 * 60 * 1000 + 1);
    vi.mocked(fetch).mockImplementation(async (url, init) => {
      const path = new URL(String(url)).pathname;
      if (path === '/v1/participants/bootstrap-metadata')
        return Response.json({
          participantId: id(1),
          privacyDomainId: id(2),
          actionIntentDigest: participantAction.digest,
          stepUpActionIntentDigest: hash(99),
        });
      if (path.endsWith('/csrf')) {
        const action = JSON.parse(String(init?.body)).actionIntentId;
        if (
          boundary === 'before-stage' ||
          (boundary === 'approval-csrf' && action === 'ACT-APPROVAL_REQUESTS_CREATE_RESOURCE-V1')
        )
          expire();
        return Response.json({ csrfToken: 'c'.repeat(64) });
      }
      if (path.endsWith('/scope-replacements/prepare')) {
        staged += 1;
        if (boundary === 'after-stage') expire();
        if (boundary === 'changed-actor')
          vi.mocked(authenticated).mockResolvedValue({ ...actor, contextEpoch: '2' });
        return Response.json({
          candidate: reviewed.review.body,
          candidateDigest: reviewed.review.candidateDigest,
          expectedRevision: '0',
          actionIntentDigest: participantAction.digest,
        });
      }
      if (path === '/api/v1/approval-requests' && init?.method === 'POST') approvals += 1;
      throw new Error('Forbidden owner mutation');
    });
    const response = await mutatePlatformCeilingWorkbench(
      request({ command: 'SUBMIT', reviewToken: reviewed.reviewToken }),
    );
    expect(response.status).toBe(404);
    expect(staged).toBe(boundary === 'before-stage' ? 0 : 1);
    expect(approvals).toBe(0);
    expect(reviewed.review.businessIdempotencyKey).toBeTruthy();
  },
);

it.each(['shared-second-read', 'shared-csrf'] as const)(
  'cancelled checker does not dispatch the next approval write after %s resolves',
  async (boundary) => {
    const preview = await mutatePlatformCeilingWorkbench(
      request({ command: 'PREVIEW_PREPARATION', selection }),
    );
    const reviewed = await preview.json();
    vi.mocked(authenticated).mockResolvedValue({ ...actor, principalId: id(101) });
    const current = {
      approvalRequestId: `urn:openpc:resource:${id(9)}`,
      actionIntentId: participantAction.id,
      candidateDigest: reviewed.review.candidateDigest,
      state: 'REQUESTED',
      makerSubjectRef: `urn:openpc:resource:${actor.principalId}`,
      checkerSubjectRef: `urn:openpc:resource:${id(101)}`,
      revision: '1',
      createdAt: '2026-10-02T00:00:00.000000Z',
      updatedAt: '2026-10-02T00:00:00.000000Z',
    };
    const candidate = {
      approvalRequestId: current.approvalRequestId,
      candidateDigest: current.candidateDigest,
      actionIntentId: participantAction.id,
      resourceRef: `urn:openpc:resource:${id(8)}`,
      expectedRevision: '0',
      state: 'APPROVAL_REQUESTED',
      expiresAt: '2027-01-01T00:00:00Z',
      operationRef: null,
      runtimePermission: 'NONE',
      deploymentIntent: null,
      candidate: reviewed.review.body,
      redactedFields: [],
    };
    const controller = new AbortController();
    let release!: () => void, arrived!: () => void;
    const blocked = new Promise<void>((resolve) => {
      release = resolve;
    });
    const started = new Promise<void>((resolve) => {
      arrived = resolve;
    });
    let reads = 0,
      decisions = 0;
    const observed: AbortSignal[] = [];
    vi.mocked(fetch).mockImplementation(async (url, init) => {
      const path = new URL(String(url)).pathname;
      if (path === '/v1/participants/bootstrap-metadata')
        return Response.json({
          participantId: id(1),
          privacyDomainId: id(2),
          actionIntentDigest: participantAction.digest,
          stepUpActionIntentDigest: hash(99),
        });
      if (path.endsWith('/candidate')) return Response.json(candidate);
      if (path.endsWith('/approve')) {
        decisions += 1;
        throw new Error('Forbidden decision');
      }
      if (path.endsWith('/csrf')) {
        expect(init?.signal).toBeTruthy();
        observed.push(init!.signal!);
        if (boundary === 'shared-csrf') {
          arrived();
          await blocked;
        }
        return Response.json({ csrfToken: 'c'.repeat(64) });
      }
      reads += 1;
      if (reads === 2) {
        expect(init?.signal).toBeTruthy();
        observed.push(init!.signal!);
        if (boundary === 'shared-second-read') {
          arrived();
          await blocked;
        }
      }
      return Response.json(current);
    });
    const input = request({ command: 'APPROVE', approvalRequestId: id(9) });
    const pending = mutatePlatformCeilingWorkbench(
      new NextRequest(input.url, {
        method: 'POST',
        headers: input.headers,
        body: JSON.stringify({ command: 'APPROVE', approvalRequestId: id(9) }),
        signal: controller.signal,
      }),
    );
    await started;
    controller.abort();
    release();
    expect((await pending).status).toBe(503);
    expect(decisions).toBe(0);
    expect(observed.length).toBeGreaterThan(0);
    expect(observed.every((signal) => signal.aborted)).toBe(true);
  },
);

it.each(['EXECUTE', 'RESUME'] as const)(
  'does not use an expired review after %s prerequisites complete',
  async (command) => {
    const preview = await mutatePlatformCeilingWorkbench(
      request({ command: 'PREVIEW_PREPARATION', selection }),
    );
    const reviewed = await preview.json();
    const seal = openBffPayload(
      reviewed.reviewToken,
      runtime.cookieKey,
      'platform-ceiling-review',
    ) as { issuedAt: number };
    const current = {
      approvalRequestId: `urn:openpc:resource:${id(9)}`,
      actionIntentId: participantAction.id,
      candidateDigest: reviewed.review.candidateDigest,
      state: 'APPROVED',
      makerSubjectRef: `urn:openpc:resource:${actor.principalId}`,
      checkerSubjectRef: `urn:openpc:resource:${id(101)}`,
      revision: '2',
      createdAt: '2026-10-02T00:00:00.000000Z',
      updatedAt: '2026-10-02T00:00:00.000000Z',
    };
    let mutations = 0;
    vi.mocked(fetch).mockImplementation(async (url, init) => {
      const path = new URL(String(url)).pathname;
      if (path === '/v1/participants/bootstrap-metadata')
        return Response.json({
          participantId: id(1),
          privacyDomainId: id(2),
          actionIntentDigest: participantAction.digest,
          stepUpActionIntentDigest: hash(99),
        });
      if (path.endsWith('/candidate')) {
        if (command === 'EXECUTE')
          vi.spyOn(Date, 'now').mockReturnValue(seal.issuedAt + 30 * 60 * 1000 + 1);
        return Response.json({
          attemptId: id(91),
          attempt: '1',
          predecessorApprovalRef: null,
          successorApprovalRef: null,
          businessIdempotencyKey: reviewed.review.businessIdempotencyKey,
          canRequestResume: command === 'RESUME',
          approvalUsable: command === 'EXECUTE',
          makerSessionMatches: true,
          approvalRequestId: current.approvalRequestId,
          candidateDigest: current.candidateDigest,
          actionIntentId: participantAction.id,
          resourceRef: `urn:openpc:resource:${id(8)}`,
          expectedRevision: '0',
          state: 'APPROVED',
          expiresAt: '2027-01-01T00:00:00Z',
          operationRef: null,
          runtimePermission: 'NONE',
          deploymentIntent: null,
          candidate: reviewed.review.body,
          redactedFields: [],
        });
      }
      if (path.endsWith('/csrf')) {
        if (command === 'RESUME')
          vi.spyOn(Date, 'now').mockReturnValue(seal.issuedAt + 30 * 60 * 1000 + 1);
        return Response.json({ csrfToken: 'c'.repeat(64) });
      }
      if (init?.method === 'POST' || init?.method === 'PATCH') {
        mutations += 1;
        throw new Error('Forbidden phase effect');
      }
      return Response.json(current);
    });
    const response = await mutatePlatformCeilingWorkbench(
      request({ command, reviewToken: reviewed.reviewToken, approvalRequestId: id(9) }),
    );
    expect(response.status).toBe(404);
    expect(mutations).toBe(0);
  },
);

it.each([
  'valid',
  'foreign-principal',
  'foreign-privacy',
  'wrong-key',
  'wrong-checker',
  'wrong-body',
  'tampered-seal',
  'different-approval',
  'not-resumable',
  'actor-after-read',
  'future-original',
  'cross-origin',
] as const)(
  'reconciles old-session sealed custody through authoritative owner read only: %s',
  async (mode) => {
    const preview = await mutatePlatformCeilingWorkbench(
      request({ command: 'PREVIEW_PREPARATION', selection }),
    );
    const reviewed = await preview.json();
    const original = openBffPayload(
      reviewed.reviewToken,
      runtime.cookieKey,
      'platform-ceiling-review',
    ) as Record<string, unknown>;
    const historical = { ...original, issuedAt: Date.now() - 2 * 60 * 60 * 1000 };
    if (mode === 'future-original') historical.issuedAt = Date.now() + 60000;
    let retainedReviewToken = sealBffPayload(
      historical,
      runtime.cookieKey,
      'platform-ceiling-review',
    );
    if (mode === 'tampered-seal') retainedReviewToken = 'invalid-signature-original-custody';
    const current = {
      ...actor,
      sessionId: id(999),
      contextEpoch: '2',
      ...(mode === 'foreign-principal' ? { principalId: id(998) } : {}),
      ...(mode === 'foreign-privacy' ? { privacyDomainId: id(997) } : {}),
    };
    vi.mocked(authenticated).mockResolvedValue(current);
    const body =
      mode === 'wrong-body'
        ? { ...reviewed.review.body, reason: 'Different authoritative replacement intent.' }
        : reviewed.review.body;
    const candidate = {
      attemptId: id(91),
      attempt: '1',
      predecessorApprovalRef: null,
      successorApprovalRef: null,
      businessIdempotencyKey:
        mode === 'wrong-key' ? 'different-original-business-key' : original.key,
      canRequestResume: mode !== 'not-resumable',
      approvalUsable: false,
      makerSessionMatches: false,
      approvalRequestId: `urn:openpc:resource:${mode === 'different-approval' ? id(10) : id(9)}`,
      candidateDigest: digest(body),
      actionIntentId: participantAction.id,
      resourceRef: `urn:openpc:resource:${id(8)}`,
      expectedRevision: '0',
      state: 'APPROVED',
      expiresAt: '2027-01-01T00:00:00Z',
      operationRef: null,
      runtimePermission: 'NONE',
      deploymentIntent: null,
      candidate: body,
      redactedFields: [],
    };
    const approval = {
      approvalRequestId: candidate.approvalRequestId,
      actionIntentId: participantAction.id,
      candidateDigest: candidate.candidateDigest,
      state: 'APPROVED',
      makerSubjectRef: `urn:openpc:resource:${actor.principalId}`,
      checkerSubjectRef: `urn:openpc:resource:${mode === 'wrong-checker' ? id(996) : id(101)}`,
      revision: '2',
      createdAt: '2026-10-02T00:00:00.000000Z',
      updatedAt: '2026-10-02T00:00:00.000000Z',
    };
    let externalMutations = 0;
    vi.mocked(fetch).mockImplementation(async (url, init) => {
      if (init?.method === 'POST' || init?.method === 'PATCH') {
        externalMutations++;
        throw Error('Forbidden owner mutation');
      }
      const path = new URL(String(url)).pathname;
      if (path === '/v1/participants/bootstrap-metadata')
        return Response.json({
          participantId: id(1),
          privacyDomainId: mode === 'foreign-privacy' ? id(997) : id(2),
          actionIntentDigest: participantAction.digest,
          stepUpActionIntentDigest: hash(99),
        });
      if (path.endsWith('/candidate')) {
        if (mode === 'actor-after-read')
          vi.mocked(authenticated).mockResolvedValue({ ...current, contextEpoch: '3' });
        return Response.json(candidate);
      }
      return Response.json(approval);
    });
    const input = {
      command: 'RECONCILE_APPROVAL_REVIEW',
      approvalRequestId: id(9),
      retainedReviewToken,
    };
    const req =
      mode === 'cross-origin'
        ? new NextRequest('http://localhost:8080/api/v1/ui/platform-ceiling-workbench', {
            method: 'POST',
            headers: {
              'origin': 'https://foreign.invalid',
              'host': 'localhost:8080',
              'content-type': 'application/json',
            },
            body: JSON.stringify(input),
          })
        : request(input);
    const response = await mutatePlatformCeilingWorkbench(req);
    const result = await response.json();
    expect(externalMutations).toBe(0);
    if (mode === 'valid') {
      expect(response.status).toBe(200);
      expect(result.custodyCorrespondence).toEqual({
        retainedReviewTokenDigest: digest(retainedReviewToken),
        approvalRequestId: id(9),
        candidateDigest: reviewed.review.candidateDigest,
        businessIdempotencyKey: original.key,
        checkerPrincipalId: id(101),
      });
      const rebound = openBffPayload(
        result.resumableReview.reviewToken,
        runtime.cookieKey,
        'platform-ceiling-review',
      );
      expect(rebound).toMatchObject({
        actor: {
          sessionId: current.sessionId,
          principalId: actor.principalId,
          participantId: actor.participantId,
          privacyDomainId: actor.privacyDomainId,
          contextEpoch: '2',
        },
        body: reviewed.review.body,
        key: original.key,
        retainedCustody: {
          reviewTokenDigest: digest(retainedReviewToken),
          approvalRequestId: id(9),
        },
      });
      expect(result.resumableReview.review.businessIdempotencyKey).toBe(original.key);
      expect(result.resumableReview.reviewToken).not.toBe(retainedReviewToken);
      // Historical custody is never a current execution seal.
      const oldExecution = await mutatePlatformCeilingWorkbench(
        request({ command: 'EXECUTE', reviewToken: retainedReviewToken, approvalRequestId: id(9) }),
      );
      expect(oldExecution.status).not.toBe(200);
      expect(externalMutations).toBe(0);
    } else {
      expect(response.status).not.toBe(200);
      expect(result.resumableReview).toBeUndefined();
    }
  },
);

it.each([
  'valid',
  'wrong-key',
  'wrong-old-case',
  'wrong-envelope',
  'wrong-assignment',
  'wrong-epoch',
  'missing-retained',
  'missing-binding-and-session',
])(
  'checks the exact closed-source receiving lease before refreshing custody: %s',
  async (failure) => {
    const f = pendingExpiryPlatformRecoveryFixture();
    const original = {
      ...retainedRecoveryReview(),
      body: f.intent.preparation,
      candidateDigest: digest(f.intent.preparation),
      recoveryBinding: {
        enrollmentId: f.intent.enrollmentId,
        recoveryId: f.intent.recoveryId,
        intentDigest: digest(f.intent),
        activationOperationId: id(1800),
      },
    };
    const intent = {
      ...f.intent,
      recoveryId: id(1801),
      enrollmentId: id(1802),
      validUntil: new Date(Date.now() + 600000).toISOString(),
      closedApprovalSourceDigest: hash(1803),
      approvalContinuation: {
        schema: 'pc.identity.platform-prepare-approval-continuation' as const,
        schemaVersion: 1 as const,
        recoveryId: original.recoveryBinding.recoveryId,
        intentDigest: original.recoveryBinding.intentDigest,
        activationOperationId: original.recoveryBinding.activationOperationId,
        activationReceiptDigest: hash(1804),
        candidateId: id(1805),
        approvalId: id(1806),
        candidateDigest: original.candidateDigest,
        businessKey: original.key,
        attempt: '1',
      },
    };
    const receipt = {
      ...recoveryReceipt(),
      intent,
      intentDigest: digest(intent),
      enrollmentId: intent.enrollmentId,
      recoveryId: intent.recoveryId,
    };
    receipt.activation = {
      ...receipt.activation,
      enrollmentId: intent.enrollmentId,
      recoveryId: intent.recoveryId,
      intentDigest: receipt.intentDigest,
      expiresAt: intent.validUntil,
    };
    const current = {
      ...actor,
      authorityEnvelopeId: id(600),
      assignmentId: id(700),
      principalEpoch: '2',
    };
    if (failure === 'wrong-key') intent.approvalContinuation.businessKey += '-foreign';
    if (failure === 'wrong-old-case') original.recoveryBinding.recoveryId = id(1890);
    if (failure === 'wrong-envelope') current.authorityEnvelopeId = id(1891);
    if (failure === 'wrong-assignment') current.assignmentId = id(1892);
    if (failure === 'wrong-epoch') current.principalEpoch = '3';
    if (failure === 'missing-binding-and-session') {
      receipt.activation.bindings = [];
      Object.assign(current, {
        authorityEnvelopeId: undefined,
        assignmentId: undefined,
        principalEpoch: undefined,
      });
    }
    vi.mocked(authenticated).mockResolvedValue(current);
    vi.mocked(identityCsrf).mockResolvedValue('unit-csrf');
    const calls: string[] = [];
    vi.mocked(fetch).mockImplementation(async (url) => {
      const path = new URL(String(url)).pathname;
      calls.push(path);
      if (path.endsWith('/commands')) return Response.json(receipt);
      if (path === '/v1/participants/bootstrap-metadata')
        return Response.json({
          participantId: id(1),
          privacyDomainId: id(2),
          actionIntentDigest: participantAction.digest,
          stepUpActionIntentDigest: hash(99),
        });
      throw new Error('Unexpected mutation');
    });
    const response = await mutatePlatformCeilingWorkbench(
      request({
        command: 'PREVIEW_RECOVERY_HANDOFF',
        enrollmentId: intent.enrollmentId,
        recoveryId: intent.recoveryId,
        ...(failure === 'missing-retained'
          ? {}
          : {
              retainedReviewToken: sealBffPayload(
                original,
                runtime.cookieKey,
                'platform-ceiling-review',
              ),
            }),
      }),
    );
    const result = await response.json();
    if (failure === 'valid') {
      expect(response.status).toBe(200);
      const review = openBffPayload(
        result.reviewToken,
        runtime.cookieKey,
        'platform-ceiling-review',
      );
      expect(review).toMatchObject({
        key: original.key,
        body: original.body,
        recoveryBinding: { recoveryId: intent.recoveryId, enrollmentId: intent.enrollmentId },
      });
    } else {
      expect(response.status).toBeGreaterThanOrEqual(400);
      expect(result.reviewToken).toBeUndefined();
    }
    expect(
      calls.every((path) => path.endsWith('/commands') || path.endsWith('/bootstrap-metadata')),
    ).toBe(true);
  },
);
