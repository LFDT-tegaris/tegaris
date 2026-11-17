import { isEnvelopeCreateResumeCandidate } from '../../../../../../services/module-registry/src/envelope-create-resume-contract';
import { randomUUID } from 'node:crypto';
import {
  readPendingAdministrator,
  readPendingAdministratorPreparation,
} from './platform-administrator-selection';
import { NextResponse, type NextRequest } from 'next/server';
import { z } from 'zod';

import { typedEnvelopeCreate } from '../../../../../../services/participant-service/src/contracts/envelope';
import {
  platformRecoveryApprovalResumePurpose,
  platformRecoveryApprovalResumeReason,
  platformRecoveryReceiptView,
} from '../../../../../../services/identity-service/src/contracts/platform-recovery';
import { approvalCandidateResponseSchema } from '../../../../../../services/module-registry/src/approval-candidate-contract';
import { approvalCreateIntent } from '../../../../../../services/module-registry/src/public-approval-contract';
import { policySetCollection } from './local-policy-set-workbench';
import {
  approval,
  approvalCreateAction,
  approvalDecisionAction,
  approvalPageSchema,
  approvalUpdateAction,
  approveGovernanceRequest,
  checkerPrincipalId,
  csrf,
  digest,
  digestSchema,
  isResponse,
  logOwnerFailure,
  ownerJson,
  ownerFailure,
  participantAction,
  publicHeaders,
  publicOperationSchema,
  timestampSchema,
  uuidSchema,
} from './local-governance-api';
import {
  authenticated,
  hasJsonContentType,
  localRuntimeConfig,
  identityCsrf,
  identityOwnerHeaders,
  localOwnerFetch,
  openBffPayload,
  parsePublicCommand,
  responseIds,
  safeProblem,
  sameOrigin,
  sealBffPayload,
  type IdentitySession,
  type LocalConfig,
} from './local-runtime';

const capability = z.enum(['CALL_RESULT_DISCLOSURE', 'SIGNED_TRANSACTION_SUBMISSION']);
const activateAction = {
  id: 'ACT-PARTICIPANT_ACTIVATE_CONTEXT-V1',
  digest: 'sha256:a3de751c7a68380154458c737a54b0d7de5328e33f83b8e37bd5ef610b2304c4',
} as const;
const noStore = { 'Cache-Control': 'no-store' };
const revision = z.string().regex(/^(0|[1-9][0-9]*)$/u);

const metadataSchema = z.strictObject({
  participantId: uuidSchema,
  privacyDomainId: uuidSchema,
  actionIntentDigest: digestSchema,
  stepUpActionIntentDigest: digestSchema,
});
const participantRecord = z.strictObject({
  participantId: uuidSchema,
  displayName: z.string().min(1).max(160),
  state: z.enum([
    'PROVISIONING',
    'ACTIVE',
    'SUSPENDED',
    'TRANSFER_PENDING',
    'REVOKED',
    'OFFBOARDED',
  ]),
  authorityEpoch: revision,
  rowVersion: revision,
});
const envelopeEffect = z
  .object({
    id: uuidSchema,
    participantId: uuidSchema,
    state: z.enum(['DRAFT', 'SUBMITTED', 'APPROVED', 'ACTIVE', 'SUPERSEDED', 'REVOKED']),
    authorityEpoch: revision,
    revision: revision.optional(),
    capabilityIds: z.array(capability).optional(),
    resourceIds: z.array(z.string()),
    privacyDomainIds: z.array(uuidSchema),
    validFrom: z.coerce.date(),
    validUntil: z.coerce.date().nullable(),
    makerCheckerRequired: z.boolean(),
    stepUpRequired: z.boolean(),
    semanticDigest: digestSchema,
  })
  .passthrough();
const envelopeReadback = z.strictObject({
  effect: envelopeEffect,
  operationId: uuidSchema.nullable(),
});
const page = <T extends z.ZodType>(item: T) =>
  z.strictObject({
    items: z.array(item).max(50),
    nextCursor: uuidSchema.nullable(),
    completeness: z.literal('COMPLETE'),
    authorizedEmpty: z.boolean(),
    observedAt: timestampSchema,
  });
const actorBinding = z.strictObject({
  sessionId: uuidSchema,
  principalId: uuidSchema,
  participantId: uuidSchema,
  contextMode: z.enum(['PLATFORM', 'PARTICIPANT']),
  contextEpoch: revision,
  privacyDomainId: uuidSchema,
  role: z.enum(['operator', 'viewer']),
});
const createReview = z.strictObject({
  version: z.literal(1),
  kind: z.literal('CREATE_ENVELOPE'),
  resourceReservationId: z.uuidv7().optional(),
  checkerPrincipalId: uuidSchema.optional(),
  resumedApprovalRequestId: uuidSchema.optional(),
  issuedAt: z.number().int().nonnegative(),
  actor: actorBinding,
  targetParticipantId: uuidSchema,
  targetPrivacyDomainId: uuidSchema,
  reason: z.string().min(10).max(1024),
  candidateDigest: digestSchema,
  expectedRevision: z.literal('0'),
  idempotencyKey: z.string().min(16).max(128),
  body: typedEnvelopeCreate,
});
const submitEnvelopeReview = z.strictObject({
  version: z.literal(1),
  kind: z.literal('SUBMIT_ENVELOPE'),
  resourceReservationId: z.uuidv7().optional(),
  issuedAt: z.number().int().nonnegative(),
  actor: actorBinding,
  targetParticipantId: uuidSchema,
  targetPrivacyDomainId: uuidSchema,
  reason: z.string().min(10).max(1024),
  candidateDigest: digestSchema,
  stepUpDigest: digestSchema,
  expectedRevision: z.literal('1'),
  idempotencyKey: z.string().min(16).max(128),
  envelopeId: uuidSchema,
});
const activateReview = z.strictObject({
  version: z.literal(1),
  kind: z.literal('ACTIVATE_ENVELOPE'),
  resourceReservationId: z.uuidv7().optional(),
  issuedAt: z.number().int().nonnegative(),
  actor: actorBinding,
  targetParticipantId: uuidSchema,
  targetPrivacyDomainId: uuidSchema,
  reason: z.string().min(10).max(1024),
  candidateDigest: digestSchema,
  expectedRevision: z.literal('3'),
  idempotencyKey: z.string().min(16).max(128),
  envelopeId: uuidSchema,
  resumedApprovalRequestId: uuidSchema.optional(),
  continuationPreparationApprovalId: uuidSchema.optional(),
  continuationResume: z
    .strictObject({
      enrollmentId: uuidSchema,
      recoveryId: uuidSchema,
      intentDigest: digestSchema,
      expiresAt: timestampSchema,
      request: platformRecoveryApprovalResumePurpose,
      idempotencyKey: z.string().min(16).max(128),
    })
    .optional(),
});
const revokeReview = z.strictObject({
  version: z.literal(1),
  kind: z.literal('REVOKE_ENVELOPE'),
  resourceReservationId: z.uuidv7().optional(),
  issuedAt: z.number().int().nonnegative(),
  actor: actorBinding,
  targetParticipantId: uuidSchema,
  targetPrivacyDomainId: uuidSchema,
  reason: z.string().min(10).max(1024),
  candidateDigest: digestSchema,
  expectedRevision: revision,
  idempotencyKey: z.string().min(16).max(128),
  envelopeId: uuidSchema,
});
const reviewSchema = z.discriminatedUnion('kind', [
  createReview,
  submitEnvelopeReview,
  activateReview,
  revokeReview,
]);
type Review = z.infer<typeof reviewSchema>;
type PlatformSession = IdentitySession & {
  readonly privacyDomainId: string;
  readonly platformStepUpActionIntentDigest: string;
};
const commands = z.discriminatedUnion('command', [
  z.strictObject({
    command: z.literal('PREVIEW_CONTINUE_CREATION'),
    approvalRequestId: uuidSchema,
    reason: z.string().trim().min(10).max(1024),
  }),
  z.strictObject({
    command: z.literal('RESUME_CREATE'),
    approvalRequestId: uuidSchema,
    reason: z.string().trim().min(10).max(1024),
  }),
  z.strictObject({
    command: z.literal('PREVIEW_CONTINUE_ACTIVATION'),
    approvalRequestId: uuidSchema,
    enrollmentId: uuidSchema,
    recoveryId: uuidSchema,
  }),
  z.strictObject({
    command: z.literal('PREVIEW_PENDING_ADMINISTRATOR'),
    resourceReservationId: z.uuidv7().optional(),
    approvalRequestId: uuidSchema,
    principalId: uuidSchema,
    reason: z.string().trim().min(10).max(1024),
  }),
  z.strictObject({
    command: z.literal('PREVIEW_ENVELOPE'),
    envelopeId: z.uuidv7().optional(),
    resourceReservationId: z.uuidv7().optional(),
    targetParticipantId: uuidSchema,
    targetPrivacyDomainId: uuidSchema,
    capabilityIds: z.array(capability).min(1).max(2),
    resourceIds: z.array(uuidSchema).min(1).max(16),
    targetProfileIds: z
      .array(z.string().regex(/^[A-Za-z0-9][A-Za-z0-9:._/-]{0,159}$/u))
      .min(1)
      .max(16),
    validUntil: timestampSchema,
    makerCheckerRequired: z.boolean().default(true),
    stepUpRequired: z.boolean().default(true),
    reason: z.string().trim().min(10).max(1024),
  }),
  z.strictObject({
    command: z.literal('PREVIEW_SUBMIT'),
    resourceReservationId: z.uuidv7().optional(),
    envelopeId: uuidSchema,
    reason: z.string().trim().min(10).max(1024),
  }),
  z.strictObject({
    command: z.literal('PREVIEW_ACTIVATE'),
    resourceReservationId: z.uuidv7().optional(),
    envelopeId: uuidSchema,
    reason: z.string().trim().min(10).max(1024),
  }),
  z.strictObject({
    command: z.literal('PREVIEW_REVOKE'),
    resourceReservationId: z.uuidv7().optional(),
    envelopeId: uuidSchema,
    reason: z.string().trim().min(10).max(1024),
  }),
  z.strictObject({
    command: z.literal('RESUME'),
    reviewToken: z.string().min(80).max(65536),
  }),
  z.strictObject({
    command: z.literal('SUBMIT'),
    reviewToken: z.string().min(80).max(65536),
  }),
  z.strictObject({
    command: z.literal('COMMIT'),
    reviewToken: z.string().min(80).max(65536),
    approvalRequestId: uuidSchema,
  }),
  z.strictObject({
    command: z.literal('APPROVE'),
    approvalRequestId: uuidSchema,
    candidateDigest: digestSchema,
  }),
]);

function boundSession(current: IdentitySession, privacyDomainId: string) {
  return { ...current, privacyDomainId };
}

export async function platformSession(
  runtime: LocalConfig,
  current: IdentitySession,
  request: NextRequest,
): Promise<PlatformSession | NextResponse | undefined> {
  if (current.contextMode !== 'PLATFORM' || current.platformBootstrapEligible !== true)
    return undefined;
  const metadata = await ownerJson(
    await fetch(`${runtime.publicApiUrl}/v1/participants/bootstrap-metadata`, {
      cache: 'no-store',
      headers: { Authorization: `Bearer ${current.sessionToken}` },
    }).catch(() => undefined),
    metadataSchema,
    request,
  );
  if (isResponse(metadata)) return metadata;
  if (metadata.participantId !== current.participantId)
    return safeProblem('PC-INTEGRATION-5001', request);
  return {
    ...boundSession(current, metadata.privacyDomainId),
    privacyDomainId: metadata.privacyDomainId,
    platformStepUpActionIntentDigest: metadata.stepUpActionIntentDigest,
  };
}

function freshStepUp(session: IdentitySession): boolean {
  if (!session.stepUpVerifiedAt) return false;
  const verifiedAt = Date.parse(session.stepUpVerifiedAt);
  return (
    Number.isFinite(verifiedAt) &&
    verifiedAt <= Date.now() &&
    Date.now() - verifiedAt < 5 * 60 * 1000
  );
}

const policyAuthoringContextSchema = z
  .object({
    moduleBindings: z.array(
      z.strictObject({
        moduleId: z.string(),
        semanticVersion: z.string(),
        manifestDigest: digestSchema,
        configurationDigest: digestSchema,
        installationId: uuidSchema,
        revision,
      }),
    ),
    simulationAuthorities: z.array(
      z.strictObject({
        assignmentId: uuidSchema,
        envelopeId: uuidSchema,
        principalId: uuidSchema,
        roleId: z.string().min(1).max(256),
        workloadDisplayLabel: z.string().min(1).max(160).optional(),
        roleDisplayName: z.string().min(1).max(160).optional(),
        workloadId: z
          .string()
          .regex(
            /^urn:openpc:workload:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u,
          ),
      }),
    ),
    simulationWorkloads: z.array(
      z.strictObject({
        principalId: uuidSchema,
        workloadId: z
          .string()
          .regex(
            /^urn:openpc:workload:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u,
          ),
      }),
    ),
    observedAt: timestampSchema,
    completeness: z.literal('COMPLETE'),
    authorizedEmpty: z.boolean(),
  })
  .strict();

function actorFor(session: IdentitySession) {
  if (!session.privacyDomainId) return undefined;
  return actorBinding.parse({
    sessionId: session.sessionId,
    principalId: session.principalId,
    participantId: session.participantId,
    contextMode: session.contextMode,
    contextEpoch: session.contextEpoch,
    privacyDomainId: session.privacyDomainId,
    role: session.role,
  });
}

async function approvals(runtime: LocalConfig, session: IdentitySession, request: NextRequest) {
  const filter = `${session.role === 'viewer' ? 'checkerSubjectRef' : 'makerSubjectRef'}:eq:urn:openpc:resource:${session.principalId}`;
  return ownerJson(
    await fetch(
      `${runtime.publicApiUrl}/api/v1/approval-requests?limit=50&sort=-updatedAt&filter=${encodeURIComponent(filter)}`,
      {
        cache: 'no-store',
        headers: publicHeaders(runtime, session, responseIds(request)),
      },
    ).catch(() => undefined),
    approvalPageSchema,
    request,
  );
}

const approvalCandidate = z
  .object({
    attemptId: uuidSchema,
    attempt: z.string().regex(/^[1-9][0-9]*$/u),
    successorApprovalRef: z.string().nullable(),
    businessIdempotencyKey: z.string().min(16).max(128).nullable(),
    canRequestResume: z.boolean(),
    candidateDigest: digestSchema,
    actionIntentId: z.literal(activateAction.id),
    resourceRef: z.string(),
    expectedRevision: revision,
  })
  .passthrough();

async function continuationReceipt(
  runtime: LocalConfig,
  session: IdentitySession,
  enrollmentId: string,
  recoveryId: string,
  request: NextRequest,
) {
  const token = await identityCsrf(runtime, session, participantAction.id);
  if (!token) return safeProblem('PC-AUTH-0005', request);
  const receipt = await ownerJson(
    await localOwnerFetch(
      `${runtime.identityUrl}/v1/identity/platform-recovery/enrollments/${enrollmentId}/commands`,
      {
        method: 'POST',
        cache: 'no-store',
        headers: {
          ...identityOwnerHeaders(runtime, session, request.headers.get('origin')!),
          'X-CSRF-Token': token,
        },
        body: JSON.stringify({
          privacyDomainId: session.privacyDomainId,
          command: { kind: 'READ', recoveryId },
        }),
      },
    ).catch(() => undefined),
    platformRecoveryReceiptView,
    request,
  );
  if (isResponse(receipt)) return receipt;
  if (
    receipt.enrollmentId !== enrollmentId ||
    receipt.recoveryId !== recoveryId ||
    receipt.intent.enrollmentId !== enrollmentId ||
    receipt.intent.recoveryId !== recoveryId ||
    receipt.intent.preparation.administrators.length !== 2 ||
    receipt.intent.preparation.administrators.some((administrator) =>
      [administrator.usable, administrator.grantable].some(
        (scope) =>
          scope.administration.participantIds.length !== 1 ||
          scope.administration.participantIds[0] !== session.participantId ||
          scope.administration.privacyDomainIds.length !== 1 ||
          scope.administration.privacyDomainIds[0] !== session.privacyDomainId ||
          scope.runtime.capabilityIds.length !== 0,
      ),
    ) ||
    !receipt.intent.continuation ||
    receipt.state !== 'ACTIVE' ||
    receipt.authority !== 'FIXED_PLATFORM_HANDOFF_ONLY' ||
    !receipt.activation ||
    receipt.activation.recoveryId !== recoveryId ||
    receipt.activation.enrollmentId !== enrollmentId ||
    receipt.activation.intentDigest !== receipt.intentDigest ||
    digest(receipt.intent) !== receipt.intentDigest ||
    Date.parse(receipt.intent.validFrom) > Date.now() ||
    Date.parse(receipt.intent.validUntil) <= Date.now() ||
    Date.parse(receipt.activation.expiresAt) <= Date.now() ||
    Date.parse(receipt.activation.expiresAt) > Date.parse(receipt.intent.validUntil) ||
    receipt.proofs.length !== 4 ||
    new Set(receipt.proofs.map((proof) => proof.proofId)).size !== 4 ||
    receipt.actors.administratorPrincipalIds[0] !== session.principalId ||
    receipt.actors.administratorPrincipalIds[1] !== checkerPrincipalId ||
    receipt.intent.preparation.administrators[0]?.principalId !== session.principalId ||
    receipt.intent.preparation.administrators[1]?.principalId !== checkerPrincipalId ||
    receipt.activation.bindings[0].principalId !== session.principalId ||
    receipt.activation.bindings[1].principalId !== checkerPrincipalId
  )
    return safeProblem('PC-AUTH-0005', request);
  return receipt;
}

async function activationCandidate(
  runtime: LocalConfig,
  session: IdentitySession,
  approvalRequestId: string,
  request: NextRequest,
) {
  return ownerJson(
    await localOwnerFetch(
      `${runtime.publicApiUrl}/api/v1/approval-requests/${encodeURIComponent(`urn:openpc:resource:${approvalRequestId}`)}/candidate`,
      { cache: 'no-store', headers: publicHeaders(runtime, session) },
    ).catch(() => undefined),
    approvalCandidateResponseSchema,
    request,
  );
}

function originalActivationMatches(
  candidate: z.infer<typeof approvalCandidateResponseSchema>,
  checked: z.infer<typeof approvalPageSchema>['items'][number],
  receipt: z.infer<typeof platformRecoveryReceiptView>,
  session: IdentitySession,
) {
  const envelopeId = receipt.intent.preparation.administrators[0]!.envelopeId;
  return (
    candidate.approvalRequestId === checked.approvalRequestId &&
    candidate.actionIntentId === activateAction.id &&
    checked.actionIntentId === activateAction.id &&
    checked.makerSubjectRef === `urn:openpc:resource:${session.principalId}` &&
    checked.checkerSubjectRef === `urn:openpc:resource:${checkerPrincipalId}` &&
    candidate.resourceRef === `urn:openpc:resource:${envelopeId}` &&
    candidate.expectedRevision === '3' &&
    candidate.candidateDigest === digest({ envelopeId }) &&
    candidate.candidateDigest === checked.candidateDigest &&
    digest(candidate.candidate) === candidate.candidateDigest &&
    candidate.operationRef === null &&
    !['CONSUMED', 'CANCELLED'].includes(candidate.state) &&
    candidate.attemptId !== undefined &&
    candidate.attempt !== undefined &&
    candidate.businessIdempotencyKey !== null &&
    candidate.businessIdempotencyKey !== undefined &&
    candidate.businessIdempotencyKey.length >= 16 &&
    candidate.successorApprovalRef !== undefined
  );
}

async function restoredActivation(
  runtime: LocalConfig,
  session: IdentitySession,
  review: z.infer<typeof activateReview>,
  original: z.infer<typeof approvalCandidateResponseSchema>,
  receipt: z.infer<typeof platformRecoveryReceiptView>,
  request: NextRequest,
) {
  if (!original.successorApprovalRef) return safeProblem('PC-INTEGRATION-5001', request);
  const successorId = original.successorApprovalRef.slice(-36);
  const child = await activationCandidate(runtime, session, successorId, request);
  if (isResponse(child)) return child;
  const checked = await approval(runtime, session, successorId, request);
  if (isResponse(checked)) return checked;
  if (
    !originalActivationMatches(child, checked, receipt, session) ||
    child.predecessorApprovalRef !== original.approvalRequestId ||
    child.successorApprovalRef !== null ||
    child.attempt !== String(BigInt(original.attempt!) + 1n) ||
    child.businessIdempotencyKey !== original.businessIdempotencyKey ||
    child.candidateDigest !== review.candidateDigest ||
    Date.parse(child.expiresAt) <= Date.now() ||
    !['REQUESTED', 'APPROVED'].includes(checked.state)
  )
    return safeProblem('PC-INTEGRATION-5001', request);
  const base = { ...review, continuationResume: undefined };
  return {
    review: activateReview.parse({ ...base, resumedApprovalRequestId: successorId }),
    approvalRequestId: successorId,
  };
}

async function resumeEnvelopeActivation(
  runtime: LocalConfig,
  session: IdentitySession,
  review: z.infer<typeof activateReview>,
  request: NextRequest,
) {
  const filter = `candidateDigest:eq:${review.candidateDigest}`;
  const page = await ownerJson(
    await fetch(
      `${runtime.publicApiUrl}/api/v1/approval-requests?limit=50&sort=-updatedAt&filter=${encodeURIComponent(filter)}`,
      { cache: 'no-store', headers: publicHeaders(runtime, session, responseIds(request)) },
    ).catch(() => undefined),
    approvalPageSchema,
    request,
  );
  if (isResponse(page)) {
    await logOwnerFailure('rpc-envelope-activation-resume-list', page);
    return page;
  }
  for (const item of page.items) {
    if (
      item.actionIntentId !== activateAction.id ||
      item.makerSubjectRef !== `urn:openpc:resource:${session.principalId}`
    )
      continue;
    const candidateResponse = await fetch(
      `${runtime.publicApiUrl}/api/v1/approval-requests/${encodeURIComponent(item.approvalRequestId)}/candidate`,
      { cache: 'no-store', headers: publicHeaders(runtime, session) },
    ).catch(() => undefined);
    const candidate = await ownerJson(candidateResponse, approvalCandidate, request);
    if (isResponse(candidate)) {
      await logOwnerFailure('rpc-envelope-activation-resume-candidate', candidateResponse);
      return candidate;
    }
    if (
      candidate.candidateDigest !== review.candidateDigest ||
      candidate.resourceRef !== `urn:openpc:resource:${review.envelopeId}` ||
      candidate.successorApprovalRef !== null ||
      !candidate.canRequestResume ||
      candidate.businessIdempotencyKey === null
    )
      continue;
    const token = await csrf(runtime, session, approvalUpdateAction.id);
    if (!token) {
      process.stderr.write('OPENPC_RPC_ENVELOPE_RESUME|stage=csrf|status=denied\n');
      return safeProblem('PC-AUTH-0005', request);
    }
    const predecessorId = item.approvalRequestId.slice(-36);
    const response = await fetch(
      `${runtime.publicApiUrl}/api/v1/approval-requests/${encodeURIComponent(item.approvalRequestId)}`,
      {
        method: 'PATCH',
        cache: 'no-store',
        headers: {
          ...publicHeaders(runtime, session),
          'Content-Type': 'application/json',
          'X-CSRF-Token': token,
          'Idempotency-Key': `rpc-envelope-resume-${candidate.attemptId}`,
          'X-OpenPC-Action-Intent-Digest': approvalUpdateAction.digest,
          'If-Match': `"${digest({ resourceId: predecessorId, revision: item.revision })}"`,
        },
        body: JSON.stringify({
          command: 'RESUME',
          actionIntentId: approvalUpdateAction.id,
          actionIntentDigest: approvalUpdateAction.digest,
          expectedRevision: item.revision,
          predecessorCandidateId: candidate.attemptId,
          expectedAttempt: candidate.attempt,
          candidateDigest: candidate.candidateDigest,
          reason: 'Resume the unchanged envelope activation after approval expiry.',
        }),
      },
    ).catch(() => undefined);
    const operation = await ownerJson(response, publicOperationSchema, request);
    if (isResponse(operation)) {
      await logOwnerFailure('rpc-envelope-activation-resume-update', response);
      return operation;
    }
    return {
      approvalRequestId: operation.resourceRef.slice(-36),
      idempotencyKey: candidate.businessIdempotencyKey,
    };
  }
  return undefined;
}

function approvalViews(
  session: IdentitySession,
  items: z.infer<typeof approvalPageSchema>['items'],
) {
  return items.map((item) => ({
    ...item,
    ...(session.role === 'viewer' && item.state === 'REQUESTED'
      ? {
          stepUp: {
            actionIntentId: approvalDecisionAction.id,
            actionIntentDigest: approvalDecisionAction.digest,
            resourceId: item.approvalRequestId.slice(-36),
            resourceDigest: digest({
              actionIntentId: approvalDecisionAction.id,
              approvalRequestId: item.approvalRequestId,
              candidateDigest: item.candidateDigest,
              expectedRevision: item.revision,
              decision: 'APPROVE',
            }),
          },
        }
      : {}),
  }));
}

async function participantEnvelopes(
  runtime: LocalConfig,
  session: IdentitySession,
  participantId: string,
  state: string,
  request: NextRequest,
) {
  return ownerJson(
    await fetch(
      `${runtime.publicApiUrl}/v1/participants/${participantId}/envelopes?${new URLSearchParams({ state, limit: '50' })}`,
      {
        cache: 'no-store',
        headers: {
          'Authorization': `Bearer ${session.sessionToken}`,
          'OpenPC-Privacy-Domain-ID': `urn:openpc:privacy-domain:${session.privacyDomainId}`,
        },
      },
    ).catch(() => undefined),
    page(envelopeReadback),
    request,
  );
}

export async function readRpcAccessWorkbench(request: NextRequest): Promise<NextResponse> {
  const runtime = await localRuntimeConfig().catch(() => undefined);
  const current = runtime && (await authenticated(request, runtime));
  if (!runtime || !current) return safeProblem('PC-AUTH-0005', request);
  const mode = request.nextUrl.searchParams.get('mode');
  if (mode === 'platform-handoff') {
    const selected = await platformSession(runtime, current, request);
    if (!selected || isResponse(selected)) return selected ?? safeProblem('PC-AUTH-0005', request);
    const approvalId = request.nextUrl.searchParams.get('preparationApprovalId');
    const principalId = request.nextUrl.searchParams.get('principalId');
    if (
      (approvalId || principalId) &&
      (!uuidSchema.safeParse(approvalId).success || !uuidSchema.safeParse(principalId).success)
    )
      return safeProblem('PC-DATA-6004', request);
    const approvalIdSelector = request.nextUrl.searchParams.get('approvalRequestId');
    if (approvalIdSelector && !uuidSchema.safeParse(approvalIdSelector).success)
      return safeProblem('PC-DATA-6004', request);
    if (approvalId && principalId && !freshStepUp(selected)) {
      const preparation = await readPendingAdministratorPreparation(
        runtime,
        selected,
        request,
        approvalId,
        principalId,
      );
      if (isResponse(preparation)) return preparation;
      return NextResponse.json(
        {
          actor: actorFor(selected),
          requiresStepUp: {
            actionIntentId: 'ACT-PARTICIPANTS_READ_RESOURCE-V1',
            actionIntentDigest:
              'sha256:73a4a8e0cc469d63163715b94ce3882d4a66e86e3d7799cb7089dd3c5aff8ad0',
            resourceId: preparation.plan.replacementId,
            resourceDigest: digest({
              purpose: 'platform-administrator-handoff-read',
              preparationApprovalId: approvalId,
              principalId,
              preparation: preparation.plan,
            }),
          },
        },
        { headers: noStore },
      );
    }
    const handoff =
      approvalId && principalId
        ? await readPendingAdministrator(runtime, selected, request, approvalId, principalId)
        : undefined;
    if (isResponse(handoff)) return handoff;
    const selectedApproval = approvalIdSelector
      ? await approval(runtime, selected, approvalIdSelector, request)
      : undefined;
    if (isResponse(selectedApproval)) return selectedApproval;
    let envelope;
    if (handoff) {
      const response = await fetch(
        `${runtime.publicApiUrl}/v1/participants/${selected.participantId}/envelopes/${handoff.administrator.envelopeId}`,
        {
          cache: 'no-store',
          headers: {
            'Authorization': `Bearer ${selected.sessionToken}`,
            'OpenPC-Privacy-Domain-ID': `urn:openpc:privacy-domain:${selected.privacyDomainId}`,
          },
        },
      ).catch(() => undefined);
      // A scoped 404 conveys only unavailability; it never proves absence or readiness.
      if (response?.status !== 404) {
        envelope = await ownerJson(
          response,
          envelopeReadback,
          request,
          'platform-handoff-envelope',
        );
        if (isResponse(envelope)) return envelope;
        if (
          envelope.effect.id !== handoff.administrator.envelopeId ||
          envelope.effect.participantId !== selected.participantId
        )
          return safeProblem('PC-INTEGRATION-5001', request);
      }
    }
    return NextResponse.json(
      {
        actor: actorFor(selected),
        items: [],
        nextCursor: null,
        authorizedEmpty: false,
        approvals: approvalViews(selected, selectedApproval ? [selectedApproval] : []),
        approvalsLoaded: !!selectedApproval,
        ...(handoff
          ? {
              handoff: {
                administrator: handoff.administrator,
                replacementId: handoff.plan.replacementId,
                envelope: envelope ?? null,
              },
            }
          : {}),
      },
      { headers: noStore },
    );
  }
  if (mode === 'platform') {
    const selected = await platformSession(runtime, current, request);
    if (!selected || isResponse(selected)) return selected ?? safeProblem('PC-AUTH-0005', request);
    const session = selected;
    if (!freshStepUp(session))
      return NextResponse.json(
        {
          actor: actorFor(session),
          requiresStepUp: {
            actionIntentId: 'ACT-IDENTITY_UPDATE_STEP_UP-V1',
            actionIntentDigest: session.platformStepUpActionIntentDigest,
            resourceId: session.sessionId,
            resourceDigest: digest({
              purpose: 'rpc-platform-catalogue',
              sessionId: session.sessionId,
            }),
          },
        },
        { headers: noStore },
      );
    const parameters = new URLSearchParams({
      search: request.nextUrl.searchParams.get('search') ?? '',
      state: request.nextUrl.searchParams.get('state') ?? 'ACTIVE',
      limit: request.nextUrl.searchParams.get('limit') ?? '25',
      ...(request.nextUrl.searchParams.get('after')
        ? { after: request.nextUrl.searchParams.get('after')! }
        : {}),
    });
    const participants = await ownerJson(
      await fetch(`${runtime.publicApiUrl}/v1/participants?${parameters}`, {
        cache: 'no-store',
        headers: {
          'Authorization': `Bearer ${session.sessionToken}`,
          'OpenPC-Privacy-Domain-ID': `urn:openpc:privacy-domain:${session.privacyDomainId}`,
        },
      }).catch(() => undefined),
      page(participantRecord),
      request,
    );
    if (isResponse(participants)) return participants;
    const listed = [];
    for (const participant of participants.items) {
      const envelopes = await participantEnvelopes(
        runtime,
        session,
        participant.participantId,
        'ALL',
        request,
      );
      if (isResponse(envelopes)) return envelopes;
      listed.push({ participant, envelopes: envelopes.items });
    }
    const inbox = await approvals(runtime, session, request);
    if (isResponse(inbox)) return inbox;
    return NextResponse.json(
      {
        actor: actorFor(session),
        ...participants,
        items: listed,
        approvals: approvalViews(session, inbox.items),
      },
      { headers: noStore },
    );
  }
  if (
    (mode !== 'participant' && mode !== 'simulation') ||
    current.contextMode !== 'PARTICIPANT' ||
    !current.privacyDomainId
  )
    return safeProblem('PC-AUTH-0005', request);
  const session = current;
  if (!freshStepUp(session))
    return NextResponse.json(
      {
        actor: actorFor(session),
        workloads: [],
        roles: [],
        envelopes: [],
        modules: {
          moduleBindings: [],
          simulationAuthorities: [],
          simulationWorkloads: [],
          authorizedEmpty: true,
        },
        policySets: [],
        approvals: [],
        requiresStepUp: {
          actionIntentId: participantAction.id,
          actionIntentDigest: participantAction.digest,
          resourceId: session.participantId,
          resourceDigest: digest({
            purpose: 'rpc-participant-catalogue',
            sessionId: session.sessionId,
            participantId: session.participantId,
          }),
        },
      },
      { headers: noStore },
    );
  const owner = (path: string) =>
    fetch(`${runtime.publicApiUrl}${path}`, {
      cache: 'no-store',
      headers: {
        ...publicHeaders(runtime, session, responseIds(request)),
        Authorization: `Bearer ${session.sessionToken}`,
      },
    }).catch(() => undefined);
  if (mode === 'simulation') {
    // Simulation consumes the policy owner's current workload assignments. It
    // does not need authority to browse unrelated administrative envelopes.
    const response = await owner('/api/v1/policy-authoring-context');
    if (!response?.ok) await logOwnerFailure('simulation-authorities', response);
    const modules = await ownerJson(response, policyAuthoringContextSchema, request);
    if (isResponse(modules)) return modules;
    return NextResponse.json({ actor: actorFor(session), modules }, { headers: noStore });
  }
  // Each owner performs its own live authority fence. Keep the catalogue reads
  // ordered so the same session is not fenced concurrently across services.
  const workloadsResponse = await owner(
    '/v1/identity/principals?search=&state=ACTIVE&kind=WORKLOAD&limit=50',
  );
  const rolesResponse = await owner(
    `/v1/participants/${session.participantId}/roles?search=&state=ACTIVE&limit=50`,
  );
  const envelopesResponse = await owner(
    `/v1/participants/${session.participantId}/envelopes?state=ALL&limit=50`,
  );
  const modulesResponse = await owner('/api/v1/policy-authoring-context');
  const policySets = await policySetCollection(runtime, session, request);
  for (const [stage, response] of [
    ['rpc-participant-workloads', workloadsResponse],
    ['rpc-participant-roles', rolesResponse],
    ['rpc-participant-envelopes', envelopesResponse],
    ['rpc-participant-modules', modulesResponse],
  ] as const)
    if (!response?.ok) await logOwnerFailure(stage, response);
  if (isResponse(policySets)) return policySets;
  const loosePage = z
    .object({ items: z.array(z.unknown()).max(50), authorizedEmpty: z.boolean() })
    .passthrough();
  const workloads = await ownerJson(workloadsResponse, loosePage, request);
  const roles = await ownerJson(rolesResponse, loosePage, request);
  const envelopes = await ownerJson(envelopesResponse, page(envelopeReadback), request);
  const modules = await ownerJson(modulesResponse, policyAuthoringContextSchema, request);
  for (const result of [workloads, roles, envelopes, modules])
    if (isResponse(result)) return result;
  let preview: unknown;
  const workloadId = request.nextUrl.searchParams.get('workloadId');
  const policySetId = request.nextUrl.searchParams.get('policySetId');
  if (workloadId && policySetId) {
    const response = await owner(
      `/api/v1/rpc-access-preview?${new URLSearchParams({
        workloadId,
        policySetId,
        methods: 'eth_call,eth_sendRawTransaction',
      })}`,
    );
    preview = await ownerJson(
      response,
      z.object({ authoritative: z.literal(false) }).passthrough(),
      request,
    );
    if (isResponse(preview)) return preview;
  }
  const inbox = await approvals(runtime, session, request);
  if (isResponse(inbox)) return inbox;
  return NextResponse.json(
    {
      actor: actorFor(session),
      workloads: (workloads as z.infer<typeof loosePage>).items,
      roles: (roles as z.infer<typeof loosePage>).items,
      envelopes: (envelopes as z.infer<ReturnType<typeof page>>).items,
      modules,
      policySets: policySets.items,
      approvals: approvalViews(session, inbox.items),
      ...(preview ? { preview } : {}),
    },
    { headers: noStore },
  );
}

function reviewResponse(review: Review, runtime: LocalConfig) {
  const resourceId = review.kind === 'CREATE_ENVELOPE' ? review.body.envelopeId : review.envelopeId;
  const resume = review.kind === 'ACTIVATE_ENVELOPE' ? review.continuationResume : undefined;
  const action = resume
    ? approvalUpdateAction
    : review.kind === 'CREATE_ENVELOPE'
      ? participantAction
      : review.kind === 'SUBMIT_ENVELOPE'
        ? approvalCreateAction
        : review.kind === 'ACTIVATE_ENVELOPE'
          ? activateAction
          : participantAction;
  return {
    reviewToken: sealBffPayload(review, runtime.cookieKey, 'rpc-access-review'),
    review: {
      kind: review.kind,
      targetParticipantId: review.targetParticipantId,
      targetPrivacyDomainId: review.targetPrivacyDomainId,
      resourceId,
      candidateDigest: review.candidateDigest,
      expectedRevision: review.expectedRevision,
      reason: review.reason,
      ...(review.kind === 'ACTIVATE_ENVELOPE' && review.continuationPreparationApprovalId
        ? {
            continuationHandoff: {
              preparationApprovalId: review.continuationPreparationApprovalId,
              principalId: review.actor.principalId,
            },
          }
        : {}),
      ...(resume
        ? {
            resumeDraft: {
              approvalRequestId: resume.request.approvalRequestId.slice(-36),
              enrollmentId: resume.enrollmentId,
              recoveryId: resume.recoveryId,
              intentDigest: resume.intentDigest,
              expiresAt: resume.expiresAt,
              expectedAttempt: resume.request.expectedAttempt,
              requestDigest: digest(resume.request),
            },
          }
        : {}),
      ...(review.kind === 'CREATE_ENVELOPE'
        ? {
            capabilityIds: review.body.usable.runtime.capabilityIds,
            makerCheckerRequired: review.body.usable.makerCheckerRequired,
            stepUpRequired: review.body.usable.stepUpRequired,
            platformScopeReplacementId: review.body.platformScopeReplacementId,
            administrationActionIntentIds: review.body.usable.administration.actionIntentIds,
            administrationResourceIds: review.body.usable.administration.resourceIds,
          }
        : {}),
      stepUp: {
        actionIntentId: action.id,
        actionIntentDigest: action.digest,
        resourceId: resume ? resume.request.approvalRequestId.slice(-36) : resourceId,
        resourceDigest: resume
          ? digest(resume.request)
          : review.kind === 'SUBMIT_ENVELOPE'
            ? review.stepUpDigest
            : review.candidateDigest,
      },
    },
  };
}

function openReview(token: string, runtime: LocalConfig, session: IdentitySession) {
  const value = reviewSchema.safeParse(
    openBffPayload(token, runtime.cookieKey, 'rpc-access-review'),
  );
  const actor = actorFor(session);
  if (
    !value.success ||
    !actor ||
    value.data.issuedAt > Date.now() ||
    Date.now() - value.data.issuedAt >= 30 * 60 * 1000 ||
    digest(value.data.actor) !== digest(actor)
  )
    return undefined;
  return value.data;
}

export async function mutateRpcAccessWorkbench(request: NextRequest) {
  const runtime = await localRuntimeConfig().catch(() => undefined);
  if (!runtime || !sameOrigin(request) || !hasJsonContentType(request.headers.get('content-type')))
    return safeProblem('PC-AUTH-0002', request);
  const current = await authenticated(request, runtime);
  if (!current) return safeProblem('PC-AUTH-0005', request);
  const input = commands.safeParse(parsePublicCommand(await request.text(), 69632));
  if (!input.success) return safeProblem('PC-DATA-6004', request);
  let selected: IdentitySession | NextResponse | undefined;
  if (current.contextMode === 'PLATFORM')
    selected = await platformSession(runtime, current, request);
  else if (current.contextMode === 'PARTICIPANT' && current.privacyDomainId) selected = current;
  if (!selected || isResponse(selected)) return selected ?? safeProblem('PC-AUTH-0005', request);
  const session = selected;
  const actor = actorFor(session);
  if (!actor) return safeProblem('PC-AUTH-0005', request);
  if (
    input.data.command === 'RESUME_CREATE' ||
    input.data.command === 'PREVIEW_CONTINUE_CREATION'
  ) {
    const observing = input.data.command === 'PREVIEW_CONTINUE_CREATION';
    const originalApprovalId = input.data.approvalRequestId;
    if (session.contextMode !== 'PLATFORM' || session.role !== 'operator')
      return safeProblem('PC-AUTH-0005', request);
    const original = await approval(runtime, session, input.data.approvalRequestId, request);
    if (isResponse(original)) return original;
    if (
      original.approvalRequestId !== `urn:openpc:resource:${input.data.approvalRequestId}` ||
      original.makerSubjectRef !== `urn:openpc:resource:${session.principalId}` ||
      original.actionIntentId !== participantAction.id ||
      !original.checkerSubjectRef ||
      original.checkerSubjectRef === original.makerSubjectRef
    )
      return safeProblem('PC-AUTH-0005', request);
    const candidateSchema = approvalCandidate.extend({
      actionIntentId: z.literal(participantAction.id),
      candidate: z.record(z.string(), z.unknown()),
      state: z.string(),
      operationRef: z.null(),
      expectedRevision: z.literal('0'),
      predecessorApprovalRef: z.string().nullable(),
      makerSessionMatches: z.boolean(),
    });
    const readCandidate = async (id: string) =>
      ownerJson(
        await fetch(
          `${runtime.publicApiUrl}/api/v1/approval-requests/${encodeURIComponent('urn:openpc:resource:' + id)}/candidate`,
          { cache: 'no-store', headers: publicHeaders(runtime, session) },
        ).catch(() => undefined),
        candidateSchema,
        request,
      );
    const candidate = await readCandidate(input.data.approvalRequestId);
    if (isResponse(candidate)) return candidate;
    const eligible = (value: z.infer<typeof candidateSchema>) =>
      isEnvelopeCreateResumeCandidate({
        catalogOperationId: 'ID-OP-ENVELOPE-CREATE',
        actionIntentId: value.actionIntentId,
        resourceType: 'participant',
        operationClass: 'UPDATE',
        expectedRevision: value.expectedRevision,
        resourceId: value.resourceRef.slice(-36),
        participantId: session.participantId,
        document: value.candidate,
      });
    if (
      !eligible(candidate) ||
      candidate.businessIdempotencyKey === null ||
      candidate.candidateDigest !== digest(candidate.candidate) ||
      candidate.candidateDigest !== original.candidateDigest
    )
      return safeProblem('PC-AUTH-0005', request);
    let nextId = candidate.successorApprovalRef?.slice(-36);
    if (!nextId) {
      if (observing) return safeProblem('PC-RUNTIME-3007', request);
      if (!candidate.canRequestResume) return safeProblem('PC-RUNTIME-3007', request);
      const token = await csrf(runtime, session, approvalUpdateAction.id);
      if (!token) return safeProblem('PC-AUTH-0005', request);
      const response = await fetch(
        `${runtime.publicApiUrl}/api/v1/approval-requests/${encodeURIComponent(original.approvalRequestId)}`,
        {
          method: 'PATCH',
          cache: 'no-store',
          headers: {
            ...publicHeaders(runtime, session),
            'Content-Type': 'application/json',
            'X-CSRF-Token': token,
            'Idempotency-Key': `rpc-envelope-create-resume-${candidate.attemptId}`,
            'X-OpenPC-Action-Intent-Digest': approvalUpdateAction.digest,
            'If-Match': `"${digest({ resourceId: input.data.approvalRequestId, revision: original.revision })}"`,
          },
          body: JSON.stringify({
            command: 'RESUME',
            actionIntentId: approvalUpdateAction.id,
            actionIntentDigest: approvalUpdateAction.digest,
            expectedRevision: original.revision,
            predecessorCandidateId: candidate.attemptId,
            expectedAttempt: candidate.attempt,
            candidateDigest: candidate.candidateDigest,
            reason: input.data.reason,
          }),
        },
      ).catch(() => undefined);
      const operation = await ownerJson(response, publicOperationSchema, request);
      if (isResponse(operation)) {
        await logOwnerFailure('rpc-envelope-create-resume', response);
        return operation;
      }
      nextId = operation.resourceRef.slice(-36);
    }
    const unresolvedRead = (phase: 'approval' | 'candidate') => {
      process.stderr.write(
        JSON.stringify({
          event: 'rpc_envelope_create_resume_read_unresolved',
          predecessorApprovalId: originalApprovalId,
          successorApprovalId: nextId,
          phase,
          disposition: 'RETAIN_ORIGINAL_CUSTODY',
        }) + '\n',
      );
      // A denied read cannot undo the already-created or linked successor.
      return safeProblem('PC-INTEGRATION-5001', request);
    };
    const nextApproval = await approval(runtime, session, nextId, request);
    if (isResponse(nextApproval)) return unresolvedRead('approval');
    const next = await readCandidate(nextId);
    if (isResponse(next)) return unresolvedRead('candidate');
    if (
      !eligible(next) ||
      !next.makerSessionMatches ||
      nextApproval.approvalRequestId !== `urn:openpc:resource:${nextId}` ||
      nextApproval.actionIntentId !== participantAction.id ||
      nextApproval.candidateDigest !== candidate.candidateDigest ||
      nextApproval.state !== 'REQUESTED' ||
      next.state !== 'APPROVAL_REQUESTED' ||
      nextApproval.makerSubjectRef !== original.makerSubjectRef ||
      nextApproval.checkerSubjectRef !== original.checkerSubjectRef ||
      next.candidateDigest !== candidate.candidateDigest ||
      digest(next.candidate) !== candidate.candidateDigest ||
      next.resourceRef !== candidate.resourceRef ||
      next.businessIdempotencyKey !== candidate.businessIdempotencyKey ||
      BigInt(next.attempt) !== BigInt(candidate.attempt) + 1n ||
      next.predecessorApprovalRef !== original.approvalRequestId
    )
      return safeProblem('PC-INTEGRATION-5001', request);
    const body = {
      schema: next.candidate.schema,
      schemaVersion: next.candidate.schemaVersion,
      envelopeId: next.candidate.envelopeId,
      issuance: next.candidate.issuance,
      usable: next.candidate.usable,
      grantable: next.candidate.grantable,
    };
    const review = createReview.parse({
      version: 1,
      kind: 'CREATE_ENVELOPE',
      issuedAt: Date.now(),
      actor,
      targetParticipantId: session.participantId,
      targetPrivacyDomainId: session.privacyDomainId,
      reason: input.data.reason,
      candidateDigest: next.candidateDigest,
      expectedRevision: '0',
      idempotencyKey: next.businessIdempotencyKey,
      checkerPrincipalId: nextApproval.checkerSubjectRef.slice(-36),
      resumedApprovalRequestId: nextId,
      body: typedEnvelopeCreate.parse(body),
    });
    process.stderr.write(
      JSON.stringify({
        event: 'rpc_envelope_create_resume_review',
        predecessorApprovalId: input.data.approvalRequestId,
        successorApprovalId: nextId,
        envelopeId: review.body.envelopeId,
        observationOnly: observing,
        disposition: 'AWAIT_INDEPENDENT_APPROVAL',
      }) + '\n',
    );
    return NextResponse.json(
      {
        ...reviewResponse(review, runtime),
        originalApprovalRequestId: input.data.approvalRequestId,
        approvalRequestId: nextId,
      },
      { status: observing ? 200 : 202, headers: noStore },
    );
  }
  if (input.data.command === 'PREVIEW_CONTINUE_ACTIVATION') {
    if (session.contextMode !== 'PLATFORM' || session.role !== 'operator')
      return safeProblem('PC-AUTH-0005', request);
    const receipt = await continuationReceipt(
      runtime,
      session,
      input.data.enrollmentId,
      input.data.recoveryId,
      request,
    );
    if (isResponse(receipt)) return receipt;
    const checked = await approval(runtime, session, input.data.approvalRequestId, request);
    if (isResponse(checked)) return checked;
    const candidate = await activationCandidate(
      runtime,
      session,
      input.data.approvalRequestId,
      request,
    );
    if (isResponse(candidate)) return candidate;
    if (!originalActivationMatches(candidate, checked, receipt, session))
      return safeProblem('PC-AUTH-0005', request);
    const purpose = platformRecoveryApprovalResumePurpose.parse({
      command: 'RESUME',
      actionIntentId: approvalUpdateAction.id,
      actionIntentDigest: approvalUpdateAction.digest,
      expectedRevision: checked.revision,
      predecessorCandidateId: candidate.attemptId,
      expectedAttempt: candidate.attempt,
      candidateDigest: candidate.candidateDigest,
      reason: platformRecoveryApprovalResumeReason,
      approvalRequestId: checked.approvalRequestId,
    });
    const review = activateReview.parse({
      version: 1,
      kind: 'ACTIVATE_ENVELOPE',
      issuedAt: Date.now(),
      actor,
      targetParticipantId: session.participantId,
      targetPrivacyDomainId: session.privacyDomainId,
      reason: platformRecoveryApprovalResumeReason,
      candidateDigest: candidate.candidateDigest,
      expectedRevision: '3',
      idempotencyKey: candidate.businessIdempotencyKey,
      envelopeId: receipt.intent.preparation.administrators[0]!.envelopeId,
      continuationPreparationApprovalId: receipt.intent.continuation!.preparationApprovalId,
      continuationResume: {
        enrollmentId: input.data.enrollmentId,
        recoveryId: input.data.recoveryId,
        intentDigest: receipt.intentDigest,
        expiresAt: receipt.activation!.expiresAt,
        request: purpose,
        idempotencyKey: `rpc-handoff-resume-${receipt.recoveryId}-${candidate.attemptId}`,
      },
    });
    if (candidate.successorApprovalRef) {
      const restored = await restoredActivation(
        runtime,
        session,
        review,
        candidate,
        receipt,
        request,
      );
      return isResponse(restored)
        ? restored
        : NextResponse.json(
            {
              ...reviewResponse(restored.review, runtime),
              approvalRequestId: restored.approvalRequestId,
            },
            { status: 200, headers: noStore },
          );
    }
    if (candidate.canRequestResume !== true) return safeProblem('PC-AUTH-0005', request);
    return NextResponse.json(reviewResponse(review, runtime), { status: 201, headers: noStore });
  }
  if (input.data.command === 'PREVIEW_PENDING_ADMINISTRATOR') {
    if (session.contextMode !== 'PLATFORM') return safeProblem('PC-AUTH-0005', request);
    const selected = await readPendingAdministrator(
      runtime,
      session,
      request,
      input.data.approvalRequestId,
      input.data.principalId,
    );
    if (isResponse(selected)) return selected;
    const body = typedEnvelopeCreate.parse({
      schema: 'pc.identity.authority-envelope-proposal',
      schemaVersion: 1,
      envelopeId: selected.administrator.envelopeId,
      issuance: 'PLATFORM_ROOT',
      platformScopeReplacementId: selected.plan.replacementId,
      usable: selected.administrator.usable,
      grantable: selected.administrator.grantable,
    });
    const review = createReview.parse({
      version: 1,
      kind: 'CREATE_ENVELOPE',
      resourceReservationId: input.data.resourceReservationId,
      issuedAt: Date.now(),
      actor,
      targetParticipantId: session.participantId,
      targetPrivacyDomainId: session.privacyDomainId,
      reason: input.data.reason,
      expectedRevision: '0',
      idempotencyKey: `platform-admin-envelope-${body.envelopeId}`,
      checkerPrincipalId: selected.checkerPrincipalId,
      candidateDigest: digest({
        ...body,
        id: body.envelopeId,
        participantId: session.participantId,
        state: 'DRAFT',
      }),
      body,
    });
    return NextResponse.json(reviewResponse(review, runtime), { headers: noStore });
  }
  if (input.data.command === 'PREVIEW_ENVELOPE') {
    if (session.contextMode !== 'PLATFORM' || session.role !== 'operator')
      return safeProblem('PC-AUTH-0005', request);
    const envelopeId = input.data.envelopeId ?? responseIds().requestId;
    const validUntil = Date.parse(input.data.validUntil);
    if (validUntil <= Date.now() + 5 * 60_000 || validUntil > Date.now() + 366 * 24 * 60 * 60_000)
      return safeProblem('PC-DATA-6004', request);
    // A child scope starts at its actual review issuance, after the parent exists.
    const nowNs = (BigInt(Date.now()) * 1_000_000n).toString();
    const untilNs = (BigInt(validUntil) * 1_000_000n).toString();
    const emptyDimensions = {
      participantIds: [],
      privacyDomainIds: [],
      resourceIds: [],
      dataClasses: [],
      targetProfileIds: [],
      riskClasses: [] as const,
    };
    const runtimeDimensions = {
      participantIds: [input.data.targetParticipantId],
      privacyDomainIds: [input.data.targetPrivacyDomainId],
      resourceIds: [...new Set(input.data.resourceIds)].sort(),
      dataClasses: [],
      targetProfileIds: [...new Set(input.data.targetProfileIds)].sort(),
      riskClasses: ['LOW'] as const,
    };
    const body = typedEnvelopeCreate.parse({
      schema: 'pc.identity.authority-envelope-proposal',
      schemaVersion: 1,
      envelopeId,
      issuance: 'PLATFORM_ROOT',
      usable: {
        administration: { ...emptyDimensions, actionIntentIds: [] },
        runtime: { ...runtimeDimensions, capabilityIds: [...input.data.capabilityIds].sort() },
        validFromNs: nowNs,
        validUntilNs: untilNs,
        makerCheckerRequired: input.data.makerCheckerRequired,
        stepUpRequired: input.data.stepUpRequired,
        onwardDelegationDepth: 0,
      },
      grantable: {
        administration: { ...emptyDimensions, actionIntentIds: [] },
        runtime: { ...runtimeDimensions, capabilityIds: [...input.data.capabilityIds].sort() },
        validFromNs: nowNs,
        validUntilNs: untilNs,
        makerCheckerRequired: input.data.makerCheckerRequired,
        stepUpRequired: input.data.stepUpRequired,
        onwardDelegationDepth: 0,
      },
    });
    const candidateDigest = digest({
      ...body,
      id: envelopeId,
      participantId: input.data.targetParticipantId,
      state: 'DRAFT',
    });
    const review = createReview.parse({
      version: 1,
      kind: 'CREATE_ENVELOPE',
      resourceReservationId: input.data.resourceReservationId,
      issuedAt: Date.now(),
      actor,
      targetParticipantId: input.data.targetParticipantId,
      targetPrivacyDomainId: input.data.targetPrivacyDomainId,
      reason: input.data.reason,
      candidateDigest,
      expectedRevision: '0',
      idempotencyKey: `rpc-envelope-${randomUUID()}`,
      body,
    });
    process.stderr.write(
      JSON.stringify({
        level: 'info',
        event: 'rpc_envelope_preview',
        stage: 'seal_workload_conditions',
        envelopeId,
        participantId: input.data.targetParticipantId,
        privacyDomainId: input.data.targetPrivacyDomainId,
        makerCheckerRequired: body.usable.makerCheckerRequired,
        stepUpRequired: body.usable.stepUpRequired,
        resourceCount: body.usable.runtime.resourceIds.length,
        capabilityCount: body.usable.runtime.capabilityIds.length,
        validUntilNs: body.usable.validUntilNs,
        candidateDigest,
        disposition: 'AWAIT_GOVERNED_ISSUANCE',
      }) + '\n',
    );
    return NextResponse.json(reviewResponse(review, runtime), { status: 201, headers: noStore });
  }
  if (input.data.command === 'PREVIEW_ACTIVATE') {
    if (session.contextMode !== 'PLATFORM' || session.role !== 'operator')
      return safeProblem('PC-AUTH-0005', request);
    let review = activateReview.parse({
      version: 1,
      kind: 'ACTIVATE_ENVELOPE',
      resourceReservationId: input.data.resourceReservationId,
      issuedAt: Date.now(),
      actor,
      targetParticipantId: session.participantId,
      targetPrivacyDomainId: session.privacyDomainId,
      reason: input.data.reason,
      candidateDigest: digest({ envelopeId: input.data.envelopeId }),
      expectedRevision: '3',
      idempotencyKey: `rpc-envelope-activate-${randomUUID()}`,
      envelopeId: input.data.envelopeId,
    });
    // The activation policy admits action-bound WebAuthn only for an exact,
    // current activation candidate. Stage that approval-required candidate
    // before returning the sealed review; this creates no envelope effect.
    const mutationCsrf = await csrf(runtime, session, activateAction.id);
    const approvalCsrf = await csrf(runtime, session, approvalCreateAction.id);
    if (!mutationCsrf || !approvalCsrf) return safeProblem('PC-AUTH-0005', request);
    const staged = await fetch(
      `${runtime.publicApiUrl}/v1/participants/${review.targetParticipantId}/envelopes/${review.envelopeId}/activate`,
      {
        method: 'POST',
        cache: 'no-store',
        headers: {
          ...publicHeaders(runtime, session),
          'Authorization': `Bearer ${session.sessionToken}`,
          'Content-Type': 'application/json',
          'X-CSRF-Token': mutationCsrf,
          'Idempotency-Key': review.idempotencyKey,
          'X-OpenPC-Aggregate-Version': review.expectedRevision,
          'X-OpenPC-Approval-Request-ID': '00000000-0000-7000-8000-000000000000',
          'OpenPC-Action-Intent-Digest': activateAction.digest,
        },
        body: '{}',
      },
    ).catch(() => undefined);
    const stagedProblem = z
      .object({ error: z.object({ code: z.literal('PC-IDENTITY-1004') }).passthrough() })
      .passthrough()
      .safeParse(
        await staged
          ?.clone()
          .json()
          .catch(() => undefined),
      );
    const stageCode = z
      .object({ error: z.object({ code: z.string() }).passthrough() })
      .passthrough()
      .safeParse(
        await staged
          ?.clone()
          .json()
          .catch(() => undefined),
      );
    if (
      staged?.status === 403 &&
      stageCode.success &&
      stageCode.data.error.code === 'PC-IDENTITY-1009'
    ) {
      const resumed = await resumeEnvelopeActivation(runtime, session, review, request);
      if (!resumed || isResponse(resumed)) {
        if (!resumed) await logOwnerFailure('rpc-envelope-activation-resume-missing', staged);
        return resumed ?? ownerFailure(staged, request);
      }
      review = activateReview.parse({
        ...review,
        idempotencyKey: resumed.idempotencyKey,
        resumedApprovalRequestId: resumed.approvalRequestId,
      });
    } else if (!staged || staged.status !== 403 || !stagedProblem.success) {
      await logOwnerFailure('rpc-envelope-activation-stage', staged);
      return ownerFailure(staged, request);
    }
    return NextResponse.json(reviewResponse(review, runtime), { status: 201, headers: noStore });
  }
  if (input.data.command === 'PREVIEW_REVOKE') {
    if (session.contextMode !== 'PLATFORM' || session.role !== 'operator')
      return safeProblem('PC-AUTH-0005', request);
    const currentEnvelope = await ownerJson(
      await fetch(
        `${runtime.publicApiUrl}/v1/participants/${session.participantId}/envelopes/${input.data.envelopeId}`,
        {
          cache: 'no-store',
          headers: {
            'Authorization': `Bearer ${session.sessionToken}`,
            'OpenPC-Privacy-Domain-ID': `urn:openpc:privacy-domain:${session.privacyDomainId}`,
          },
        },
      ).catch(() => undefined),
      envelopeReadback,
      request,
    );
    if (isResponse(currentEnvelope)) return currentEnvelope;
    if (
      currentEnvelope.effect.participantId !== session.participantId ||
      currentEnvelope.effect.id !== input.data.envelopeId ||
      currentEnvelope.effect.state !== 'ACTIVE' ||
      currentEnvelope.effect.revision === undefined
    )
      return safeProblem('PC-AUTH-0005', request);
    const body = { envelopeId: input.data.envelopeId, reason: input.data.reason };
    const review = revokeReview.parse({
      version: 1,
      kind: 'REVOKE_ENVELOPE',
      resourceReservationId: input.data.resourceReservationId,
      issuedAt: Date.now(),
      actor,
      targetParticipantId: session.participantId,
      targetPrivacyDomainId: session.privacyDomainId,
      reason: input.data.reason,
      candidateDigest: digest(body),
      expectedRevision: currentEnvelope.effect.revision,
      idempotencyKey: `rpc-envelope-revoke-${randomUUID()}`,
      envelopeId: input.data.envelopeId,
    });
    return NextResponse.json(reviewResponse(review, runtime), { status: 201, headers: noStore });
  }
  if (input.data.command === 'PREVIEW_SUBMIT') {
    if (session.contextMode !== 'PLATFORM' || session.role !== 'operator')
      return safeProblem('PC-AUTH-0005', request);
    const currentEnvelope = await ownerJson(
      await fetch(
        `${runtime.publicApiUrl}/v1/participants/${session.participantId}/envelopes/${input.data.envelopeId}`,
        {
          cache: 'no-store',
          headers: {
            'Authorization': `Bearer ${session.sessionToken}`,
            'OpenPC-Privacy-Domain-ID': `urn:openpc:privacy-domain:${session.privacyDomainId}`,
          },
        },
      ).catch(() => undefined),
      envelopeReadback,
      request,
    );
    if (isResponse(currentEnvelope)) return currentEnvelope;
    if (
      currentEnvelope.effect.participantId !== session.participantId ||
      currentEnvelope.effect.id !== input.data.envelopeId ||
      currentEnvelope.effect.state !== 'DRAFT'
    )
      return safeProblem('PC-AUTH-0005', request);
    const reason = input.data.reason;
    const approvalRequest = {
      actionIntentId: approvalCreateAction.id,
      actionIntentDigest: approvalCreateAction.digest,
      candidateDigest: currentEnvelope.effect.semanticDigest,
      ...(input.data.resourceReservationId
        ? { resourceReservationId: input.data.resourceReservationId }
        : {}),
      makerSubjectRef: `urn:openpc:resource:${session.principalId}`,
      checkerSubjectRef: `urn:openpc:resource:${checkerPrincipalId}`,
      reason,
    };
    const review = submitEnvelopeReview.parse({
      version: 1,
      kind: 'SUBMIT_ENVELOPE',
      resourceReservationId: input.data.resourceReservationId,
      issuedAt: Date.now(),
      actor,
      targetParticipantId: session.participantId,
      targetPrivacyDomainId: session.privacyDomainId,
      reason,
      candidateDigest: currentEnvelope.effect.semanticDigest,
      stepUpDigest: approvalCreateIntent(approvalRequest).intentDigest,
      expectedRevision: '1',
      idempotencyKey: `rpc-envelope-submit-${randomUUID()}`,
      envelopeId: input.data.envelopeId,
    });
    return NextResponse.json(reviewResponse(review, runtime), { status: 201, headers: noStore });
  }
  if (input.data.command === 'APPROVE') {
    if (session.role !== 'viewer') return safeProblem('PC-AUTH-0005', request);
    const checked = await approval(runtime, session, input.data.approvalRequestId, request);
    if (
      isResponse(checked) ||
      checked.candidateDigest !== input.data.candidateDigest ||
      checked.checkerSubjectRef !== `urn:openpc:resource:${session.principalId}`
    )
      return isResponse(checked) ? checked : safeProblem('PC-AUTH-0002', request);
    return approveGovernanceRequest(runtime, session, input.data.approvalRequestId, request);
  }
  const review = openReview(input.data.reviewToken, runtime, session);
  if (!review || session.role !== 'operator') {
    process.stderr.write('OPENPC_RPC_ACCESS_FAILURE|stage=review-open\n');
    return safeProblem('PC-AUTH-0005', request);
  }
  if (input.data.command === 'RESUME') {
    if (
      session.contextMode !== 'PLATFORM' ||
      review.kind !== 'ACTIVATE_ENVELOPE' ||
      !review.continuationResume
    )
      return safeProblem('PC-AUTH-0005', request);
    const resume = review.continuationResume;
    const receipt = await continuationReceipt(
      runtime,
      session,
      resume.enrollmentId,
      resume.recoveryId,
      request,
    );
    if (isResponse(receipt)) {
      await logOwnerFailure('rpc-envelope-continuation-resume-receipt', receipt);
      return receipt;
    }
    if (
      receipt.intentDigest !== resume.intentDigest ||
      receipt.activation!.expiresAt !== resume.expiresAt
    )
      return safeProblem('PC-AUTH-0005', request);
    const predecessorId = resume.request.approvalRequestId.slice(-36);
    const checked = await approval(runtime, session, predecessorId, request);
    if (isResponse(checked)) {
      await logOwnerFailure('rpc-envelope-continuation-resume-predecessor-approval', checked);
      return checked;
    }
    let original = await activationCandidate(runtime, session, predecessorId, request);
    if (isResponse(original)) {
      await logOwnerFailure('rpc-envelope-continuation-resume-predecessor-candidate', original);
      return original;
    }
    if (
      !originalActivationMatches(original, checked, receipt, session) ||
      original.candidateDigest !== review.candidateDigest ||
      original.businessIdempotencyKey !== review.idempotencyKey ||
      original.attemptId !== resume.request.predecessorCandidateId ||
      original.attempt !== resume.request.expectedAttempt
    )
      return safeProblem('PC-DATA-6007', request);
    // A response can be lost after durable RESUME. Read the original child link
    // before retrying the same metadata intent, never a fresh business key.
    if (!original.successorApprovalRef) {
      if (
        original.canRequestResume !== true ||
        checked.revision !== resume.request.expectedRevision
      )
        return safeProblem('PC-DATA-6007', request);
      const token = await csrf(runtime, session, approvalUpdateAction.id);
      if (!token) return safeProblem('PC-AUTH-0005', request);
      const { approvalRequestId, ...body } = platformRecoveryApprovalResumePurpose.parse(
        resume.request,
      );
      const response = await localOwnerFetch(
        `${runtime.publicApiUrl}/api/v1/approval-requests/${encodeURIComponent(approvalRequestId)}`,
        {
          method: 'PATCH',
          cache: 'no-store',
          headers: {
            ...publicHeaders(runtime, session),
            'Content-Type': 'application/json',
            'X-CSRF-Token': token,
            'Idempotency-Key': resume.idempotencyKey,
            'X-OpenPC-Action-Intent-Digest': approvalUpdateAction.digest,
            'If-Match': `"${digest({ resourceId: predecessorId, revision: resume.request.expectedRevision })}"`,
          },
          body: JSON.stringify(body),
        },
      ).catch(() => undefined);
      const operation = await ownerJson(response, publicOperationSchema, request);
      if (isResponse(operation)) {
        await logOwnerFailure('rpc-envelope-continuation-resume-public-patch', response);
        return operation;
      }
      if (
        response?.status !== 202 ||
        operation.actionIntentId !== approvalUpdateAction.id ||
        operation.idempotencyKey !== resume.idempotencyKey
      )
        return safeProblem('PC-INTEGRATION-5001', request);
      original = await activationCandidate(runtime, session, predecessorId, request);
      if (isResponse(original)) {
        await logOwnerFailure('rpc-envelope-continuation-resume-child-link', original);
        // PATCH already returned a durable successor. Preserve reconciliation
        // when its readback fails instead of reporting a pre-write denial.
        return safeProblem('PC-INTEGRATION-5001', request);
      }
      if (original.successorApprovalRef !== operation.resourceRef)
        return safeProblem('PC-INTEGRATION-5001', request);
    }
    const restored = await restoredActivation(runtime, session, review, original, receipt, request);
    if (isResponse(restored))
      await logOwnerFailure('rpc-envelope-continuation-resume-restored-child', restored);
    return isResponse(restored)
      ? safeProblem('PC-INTEGRATION-5001', request)
      : NextResponse.json(
          {
            ...reviewResponse(restored.review, runtime),
            approvalRequestId: restored.approvalRequestId,
          },
          { status: 202, headers: noStore },
        );
  }
  if (review.kind === 'ACTIVATE_ENVELOPE' && review.continuationResume)
    return safeProblem('PC-AUTH-0005', request);
  if (review.kind === 'SUBMIT_ENVELOPE') {
    if (input.data.command !== 'SUBMIT') return safeProblem('PC-AUTH-0005', request);
    const approvalCsrf = await csrf(runtime, session, approvalCreateAction.id);
    if (!approvalCsrf) {
      process.stderr.write('OPENPC_RPC_ACCESS_FAILURE|stage=submission-csrf\n');
      return safeProblem('PC-AUTH-0005', request);
    }
    const approvalResponse = await fetch(`${runtime.publicApiUrl}/api/v1/approval-requests`, {
      method: 'POST',
      cache: 'no-store',
      headers: {
        ...publicHeaders(runtime, session),
        'Content-Type': 'application/json',
        'X-CSRF-Token': approvalCsrf,
        'Idempotency-Key': `${review.idempotencyKey}-approval`,
        'X-OpenPC-Action-Intent-Digest': approvalCreateAction.digest,
      },
      body: JSON.stringify({
        actionIntentId: approvalCreateAction.id,
        actionIntentDigest: approvalCreateAction.digest,
        candidateDigest: review.candidateDigest,
        resourceReservationId: review.resourceReservationId,
        makerSubjectRef: `urn:openpc:resource:${session.principalId}`,
        checkerSubjectRef: `urn:openpc:resource:${checkerPrincipalId}`,
        reason: review.reason,
      }),
    }).catch(() => undefined);
    if (!approvalResponse?.ok)
      await logOwnerFailure('rpc-envelope-submission-approval-create', approvalResponse);
    const operation = await ownerJson(approvalResponse, publicOperationSchema, request);
    if (isResponse(operation)) return operation;
    return NextResponse.json(
      { ...reviewResponse(review, runtime), approvalRequestId: operation.resourceRef.slice(-36) },
      { status: 202, headers: noStore },
    );
  }
  const action =
    review.kind === 'CREATE_ENVELOPE' || review.kind === 'REVOKE_ENVELOPE'
      ? participantAction
      : activateAction;
  const path =
    review.kind === 'CREATE_ENVELOPE'
      ? `/v1/participants/${review.targetParticipantId}/envelopes`
      : review.kind === 'ACTIVATE_ENVELOPE'
        ? `/v1/participants/${review.targetParticipantId}/envelopes/${review.envelopeId}/activate`
        : `/v1/participants/${review.targetParticipantId}/envelopes/${review.envelopeId}/revoke`;
  const mutationBody =
    review.kind === 'CREATE_ENVELOPE'
      ? review.body
      : review.kind === 'REVOKE_ENVELOPE'
        ? { envelopeId: review.envelopeId, reason: review.reason }
        : {};
  if (input.data.command === 'SUBMIT') {
    const mutationCsrf = await csrf(runtime, session, action.id);
    const approvalCsrf = await csrf(runtime, session, approvalCreateAction.id);
    if (!mutationCsrf || !approvalCsrf) return safeProblem('PC-AUTH-0005', request);
    const staged = await fetch(`${runtime.publicApiUrl}${path}`, {
      method: 'POST',
      cache: 'no-store',
      headers: {
        ...publicHeaders(runtime, session),
        'Authorization': `Bearer ${session.sessionToken}`,
        'Content-Type': 'application/json',
        'X-CSRF-Token': mutationCsrf,
        'Idempotency-Key': review.idempotencyKey,
        'X-OpenPC-Aggregate-Version': review.expectedRevision,
        'X-OpenPC-Approval-Request-ID': '00000000-0000-7000-8000-000000000000',
        'OpenPC-Action-Intent-Digest': action.digest,
      },
      body: JSON.stringify(mutationBody),
    }).catch(() => undefined);
    const stagedProblem = z
      .object({ error: z.object({ code: z.literal('PC-IDENTITY-1004') }).passthrough() })
      .passthrough()
      .safeParse(
        await staged
          ?.clone()
          .json()
          .catch(() => undefined),
      );
    if (!staged || staged.status !== 403 || !stagedProblem.success)
      return safeProblem('PC-INTEGRATION-5001', request);
    if (review.kind === 'ACTIVATE_ENVELOPE' && review.resumedApprovalRequestId) {
      const existing = await approval(runtime, session, review.resumedApprovalRequestId, request);
      if (
        isResponse(existing) ||
        existing.state !== 'REQUESTED' ||
        existing.candidateDigest !== review.candidateDigest ||
        existing.makerSubjectRef !== `urn:openpc:resource:${session.principalId}` ||
        existing.checkerSubjectRef !== `urn:openpc:resource:${checkerPrincipalId}`
      )
        return isResponse(existing) ? existing : safeProblem('PC-AUTH-0005', request);
      return NextResponse.json(
        { ...reviewResponse(review, runtime), approvalRequestId: review.resumedApprovalRequestId },
        { status: 202, headers: noStore },
      );
    }
    const operation = await ownerJson(
      await fetch(`${runtime.publicApiUrl}/api/v1/approval-requests`, {
        method: 'POST',
        cache: 'no-store',
        headers: {
          ...publicHeaders(runtime, session),
          'Content-Type': 'application/json',
          'X-CSRF-Token': approvalCsrf,
          'Idempotency-Key': `${review.idempotencyKey}-approval`,
          'X-OpenPC-Action-Intent-Digest': approvalCreateAction.digest,
        },
        body: JSON.stringify({
          actionIntentId: approvalCreateAction.id,
          actionIntentDigest: approvalCreateAction.digest,
          candidateDigest: review.candidateDigest,
          resourceReservationId: review.resourceReservationId,
          makerSubjectRef: `urn:openpc:resource:${session.principalId}`,
          checkerSubjectRef: `urn:openpc:resource:${review.kind === 'CREATE_ENVELOPE' ? (review.checkerPrincipalId ?? checkerPrincipalId) : checkerPrincipalId}`,
          reason: review.reason,
        }),
      }).catch(() => undefined),
      publicOperationSchema,
      request,
    );
    if (isResponse(operation)) return operation;
    return NextResponse.json(
      { ...reviewResponse(review, runtime), approvalRequestId: operation.resourceRef.slice(-36) },
      { status: 202, headers: noStore },
    );
  }
  const checked = await approval(runtime, session, input.data.approvalRequestId, request);
  if (
    isResponse(checked) ||
    checked.state !== 'APPROVED' ||
    checked.candidateDigest !== review.candidateDigest ||
    checked.makerSubjectRef !== `urn:openpc:resource:${session.principalId}`
  )
    return isResponse(checked) ? checked : safeProblem('PC-AUTH-0002', request);
  const token = await csrf(runtime, session, action.id);
  if (!token) return safeProblem('PC-AUTH-0005', request);
  const committed = await fetch(`${runtime.publicApiUrl}${path}`, {
    method: 'POST',
    cache: 'no-store',
    headers: {
      ...publicHeaders(runtime, session),
      'Authorization': `Bearer ${session.sessionToken}`,
      'Content-Type': 'application/json',
      'X-CSRF-Token': token,
      'Idempotency-Key': review.idempotencyKey,
      'X-OpenPC-Aggregate-Version': review.expectedRevision,
      'X-OpenPC-Approval-Request-ID': input.data.approvalRequestId,
      'OpenPC-Action-Intent-Digest': action.digest,
    },
    body: JSON.stringify(mutationBody),
  }).catch(() => undefined);
  if (!committed?.ok) {
    await logOwnerFailure('rpc-envelope-commit', committed);
    return ownerFailure(committed, request);
  }
  const committedEffect = envelopeEffect.safeParse(await committed.json().catch(() => undefined));
  if (!committedEffect.success) return safeProblem('PC-INTEGRATION-5001', request);
  // The mutation response is the authoritative committed row. A Platform actor
  // may list the resulting bound but cannot use the Participant resource-read
  // route, so a second resource GET would turn success into a false 404. The
  // component immediately refreshes the Platform catalogue for its operation.
  return NextResponse.json(
    { effect: { effect: committedEffect.data, operationId: null } },
    { status: 202, headers: noStore },
  );
}
