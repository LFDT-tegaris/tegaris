import { NextResponse, type NextRequest } from 'next/server';
import { z } from 'zod';
import {
  platformRecoveryReceiptView,
  platformRecoveryApprovalResumeReason,
  platformRecoveryApprovalResumePurpose,
} from '../../../../../../services/identity-service/src/contracts/platform-recovery';
import {
  platformScopeSourceSchema,
  platformScopeReadinessSchema,
} from '../../../../../../services/participant-service/src/contracts/platform-scope-readback';
import {
  platformScopeReplacementPreparation,
  platformScopeReplacementCommit,
} from '../../../../../../services/participant-service/src/contracts/platform-scope-replacement';
import { approvalCandidateResponseSchema } from '../../../../../../services/module-registry/src/approval-candidate-contract';
import {
  authenticated,
  hasJsonContentType,
  localRuntimeConfig,
  localOwnerFetch,
  openBffPayload,
  readPublicCommand,
  identityCsrf,
  identityOwnerHeaders,
  responseIds,
  safeProblem,
  sameOrigin,
  sealBffPayload,
  type IdentitySession,
  type LocalConfig,
} from './local-runtime';
import {
  approval,
  approvalPageSchema,
  approvalCreateAction,
  approvalUpdateAction,
  approvalDecisionAction,
  approveGovernanceRequest,
  csrf,
  digest,
  digestSchema,
  isResponse,
  logOwnerFailure,
  ownerJson,
  participantAction,
  publicHeaders,
  publicOperationSchema,
} from './local-governance-api';
import { platformSession } from './local-rpc-access-workbench';
import {
  buildCeilingPreparation,
  ceilingPreparationSelection,
  roleBindingPreviewSchema,
  platformAdministratorLifetimeSettings,
} from './platform-ceiling-plan';

const noStore = { 'Cache-Control': 'no-store' };
const id = z.uuidv7();
const bindingSchema = z.strictObject({
  sessionId: id,
  principalId: id,
  participantId: id,
  privacyDomainId: id,
  contextEpoch: z.string(),
});
const bodySchema = z.union([platformScopeReplacementPreparation, platformScopeReplacementCommit]);
const recoveryBindingSchema = z.strictObject({
  enrollmentId: id,
  recoveryId: id,
  intentDigest: digestSchema,
  activationOperationId: id,
});
const reviewSchema = z.strictObject({
  phase: z.enum(['PREPARE', 'COMMIT']),
  issuedAt: z.number().int().nonnegative(),
  actor: bindingSchema,
  body: bodySchema,
  checkerPrincipalId: id,
  candidateDigest: digestSchema,
  key: z.string().min(16).max(128),
  resourceReservationId: id.optional(),
  recoveryBinding: recoveryBindingSchema.optional(),
  resumePurpose: platformRecoveryApprovalResumePurpose.optional(),
  retainedCustody: z
    .strictObject({ reviewTokenDigest: digestSchema, approvalRequestId: id })
    .optional(),
});
type Review = z.infer<typeof reviewSchema>;
const commands = z.discriminatedUnion('command', [
  z.strictObject({
    command: z.literal('RECONCILE_APPROVAL_REVIEW'),
    approvalRequestId: id,
    retainedReviewToken: z.string().min(16).max(262144),
  }),
  z.strictObject({
    command: z.literal('RECONCILE_CLOSED_RECOVERY_HANDOFF'),
    enrollmentId: id,
    recoveryId: id,
    retainedReviewToken: z.string().min(1).max(262144),
  }),
  z.strictObject({
    command: z.literal('PREVIEW_RECOVERY_HANDOFF'),
    enrollmentId: id,
    recoveryId: id,
    retainedReviewToken: z.string().min(1).max(262144).optional(),
  }),
  z.strictObject({
    command: z.literal('PREVIEW_PREPARATION'),
    selection: ceilingPreparationSelection,
    resourceReservationId: id.optional(),
  }),
  z.strictObject({
    command: z.literal('PREVIEW_COMMIT'),
    platformContextId: id,
    replacementId: id,
    checkerPrincipalId: id,
    reason: z.string().trim().min(10).max(1024),
    resourceReservationId: id.optional(),
  }),
  z.strictObject({ command: z.literal('SUBMIT'), reviewToken: z.string().max(262144) }),
  z.strictObject({
    command: z.literal('EXECUTE'),
    reviewToken: z.string().max(262144),
    approvalRequestId: id,
  }),
  z.strictObject({ command: z.literal('APPROVE'), approvalRequestId: id }),
  z.strictObject({
    command: z.literal('RESUME'),
    reviewToken: z.string().max(262144),
    approvalRequestId: id,
  }),
]);
const actorBinding = (session: IdentitySession) =>
  bindingSchema.parse({
    sessionId: session.sessionId,
    principalId: session.principalId,
    participantId: session.participantId,
    privacyDomainId: session.privacyDomainId,
    contextEpoch: session.contextEpoch,
  });

async function context(request: NextRequest, mutation = false) {
  const runtime = await localRuntimeConfig().catch(() => undefined);
  if (!runtime) return safeProblem('PC-INTEGRATION-5001', request);
  if (mutation && !sameOrigin(request)) return safeProblem('PC-AUTH-0005', request);
  const current = await authenticated(request, runtime);
  if (!current) return safeProblem('PC-AUTH-0005', request);
  const session = await platformSession(runtime, current, request);
  if (isResponse(session)) {
    await logOwnerFailure('platform-ceiling-platform-context', session);
    return session;
  }
  if (!session) return safeProblem('PC-AUTH-0005', request);
  return { runtime, session };
}

async function currentActorStillMatches(
  runtime: LocalConfig,
  session: IdentitySession,
  request: NextRequest,
) {
  const current = await authenticated(request, runtime);
  if (!current) return false;
  const bound = await platformSession(runtime, current, request);
  return (
    bound && !isResponse(bound) && digest(actorBinding(bound)) === digest(actorBinding(session))
  );
}

async function sourceRead(
  runtime: LocalConfig,
  session: IdentitySession,
  rootId: string,
  request: NextRequest,
) {
  const response = await localOwnerFetch(
    `${runtime.publicApiUrl}/v1/platform-contexts/${rootId}/scope-replacement-source`,
    {
      cache: 'no-store',
      headers: {
        ...publicHeaders(runtime, session),
        Authorization: `Bearer ${session.sessionToken}`,
      },
      signal: request.signal,
    },
  ).catch(() => undefined);
  const source = await ownerJson(response, platformScopeSourceSchema, request);
  if (isResponse(source)) {
    await logOwnerFailure('platform-ceiling-source', response);
    return source;
  }
  if (
    source.root.platformContextId !== rootId ||
    source.root.ownerParticipantId !== session.participantId ||
    source.root.installationPrivacyDomainId !== session.privacyDomainId
  )
    return safeProblem('PC-INTEGRATION-5001', request);
  return source;
}

async function readinessRead(
  runtime: LocalConfig,
  session: IdentitySession,
  rootId: string,
  replacementId: string,
  request: NextRequest,
) {
  const response = await localOwnerFetch(
    `${runtime.publicApiUrl}/v1/platform-contexts/${rootId}/scope-replacements/${replacementId}/readiness`,
    {
      cache: 'no-store',
      headers: {
        ...publicHeaders(runtime, session),
        Authorization: `Bearer ${session.sessionToken}`,
      },
      signal: request.signal,
    },
  ).catch(() => undefined);
  const readiness = await ownerJson(response, platformScopeReadinessSchema, request);
  if (isResponse(readiness)) {
    await logOwnerFailure('platform-ceiling-readiness', response);
    return readiness;
  }
  if (readiness.platformContextId !== rootId || readiness.replacementId !== replacementId)
    return safeProblem('PC-INTEGRATION-5001', request);
  return readiness;
}

async function approvalRead(
  runtime: LocalConfig,
  session: IdentitySession,
  approvalId: string,
  request: NextRequest,
) {
  const selected = await approval(runtime, session, approvalId, request);
  if (isResponse(selected)) {
    await logOwnerFailure('platform-ceiling-approval-read', selected);
    return selected;
  }
  const candidateResponse = await localOwnerFetch(
    `${runtime.publicApiUrl}/api/v1/approval-requests/${encodeURIComponent(selected.approvalRequestId)}/candidate`,
    {
      cache: 'no-store',
      headers: publicHeaders(runtime, session),
      signal: request.signal,
    },
  ).catch((error: unknown) => {
    const classified = z
      .object({ cause: z.object({ code: z.string().regex(/^[A-Z0-9_]{1,64}$/u) }).optional() })
      .safeParse(error);
    process.stderr.write(
      `OPENPC_PLATFORM_CEILING_READ_TRANSPORT|code=${classified.success ? (classified.data.cause?.code ?? 'UNKNOWN') : 'UNKNOWN'}\n`,
    );
    return undefined;
  });
  const candidate = await ownerJson(candidateResponse, approvalCandidateResponseSchema, request);
  if (isResponse(candidate)) {
    await logOwnerFailure('platform-ceiling-candidate-read', candidateResponse);
    return candidate;
  }
  const parsed = bodySchema.safeParse(candidate.candidate);
  if (
    !parsed.success ||
    selected.approvalRequestId !== `urn:openpc:resource:${approvalId}` ||
    candidate.candidateDigest !== digest(parsed.data) ||
    selected.candidateDigest !== candidate.candidateDigest ||
    selected.approvalRequestId !== candidate.approvalRequestId ||
    selected.actionIntentId !== participantAction.id ||
    candidate.actionIntentId !== participantAction.id ||
    candidate.resourceRef !== `urn:openpc:resource:${parsed.data.replacementId}` ||
    candidate.redactedFields.length !== 0
  )
    return safeProblem('PC-INTEGRATION-5001', request);
  return { approval: selected, candidate, body: parsed.data };
}

function reviewResponse(review: Review, runtime: LocalConfig) {
  return {
    reviewToken: sealBffPayload(review, runtime.cookieKey, 'platform-ceiling-review'),
    review: {
      phase: review.phase,
      businessIdempotencyKey: review.key,
      body: review.body,
      candidateDigest: review.candidateDigest,
      checkerPrincipalId: review.checkerPrincipalId,
      stepUp: {
        actionIntentId: participantAction.id,
        actionIntentDigest: participantAction.digest,
        resourceId: review.body.replacementId,
        resourceDigest: review.candidateDigest,
      },
    },
  };
}

function approvalResumePurpose(
  selected: Exclude<Awaited<ReturnType<typeof approvalRead>>, NextResponse>,
  approvalRequestId: string,
) {
  const parsed = platformRecoveryApprovalResumePurpose.safeParse({
    command: 'RESUME',
    actionIntentId: approvalUpdateAction.id,
    actionIntentDigest: approvalUpdateAction.digest,
    expectedRevision: selected.approval.revision,
    predecessorCandidateId: selected.candidate.attemptId,
    expectedAttempt: selected.candidate.attempt,
    candidateDigest: selected.candidate.candidateDigest,
    reason: platformRecoveryApprovalResumeReason,
    approvalRequestId: `urn:openpc:resource:${approvalRequestId}`,
  });
  return parsed.success ? parsed.data : undefined;
}

async function replacementApprovalRead(
  runtime: LocalConfig,
  session: IdentitySession,
  approvalRequestId: string,
  request: NextRequest,
  retained?: { review: Review; token: string },
) {
  const selected = await approvalRead(runtime, session, approvalRequestId, request);
  if (isResponse(selected)) return selected;
  if (
    retained &&
    (retained.review.phase !==
      (selected.body.schema === 'pc.identity.platform-scope-replacement' ? 'PREPARE' : 'COMMIT') ||
      retained.review.candidateDigest !== selected.candidate.candidateDigest ||
      digest(retained.review.body) !== digest(selected.body) ||
      retained.review.key !== selected.candidate.businessIdempotencyKey ||
      selected.approval.makerSubjectRef !==
        `urn:openpc:resource:${retained.review.actor.principalId}` ||
      selected.approval.checkerSubjectRef !==
        `urn:openpc:resource:${retained.review.checkerPrincipalId}`)
  )
    return safeProblem('PC-AUTH-0005', request);
  const checker =
    selected.approval.checkerSubjectRef === `urn:openpc:resource:${session.principalId}` &&
    selected.approval.makerSubjectRef !== selected.approval.checkerSubjectRef;
  const stepUp =
    checker &&
    selected.approval.state === 'REQUESTED' &&
    selected.candidate.state === 'APPROVAL_REQUESTED'
      ? {
          actionIntentId: approvalDecisionAction.id,
          actionIntentDigest: approvalDecisionAction.digest,
          resourceId: approvalRequestId,
          resourceDigest: digest({
            actionIntentId: approvalDecisionAction.id,
            approvalRequestId: selected.approval.approvalRequestId,
            candidateDigest: selected.approval.candidateDigest,
            expectedRevision: selected.approval.revision,
            decision: 'APPROVE',
          }),
        }
      : null;
  const resumable =
    selected.candidate.canRequestResume === true &&
    selected.candidate.successorApprovalRef === null &&
    selected.candidate.approvalUsable !== true &&
    selected.approval.makerSubjectRef === `urn:openpc:resource:${session.principalId}` &&
    selected.approval.checkerSubjectRef !== null &&
    selected.candidate.businessIdempotencyKey;
  const resumePurpose = resumable ? approvalResumePurpose(selected, approvalRequestId) : undefined;
  if (resumable && !resumePurpose) return safeProblem('PC-INTEGRATION-5001', request);
  if (retained && (!resumable || !(await currentActorStillMatches(runtime, session, request))))
    return safeProblem('PC-AUTH-0005', request);
  const resumeReview = resumable
    ? reviewSchema.safeParse({
        phase:
          selected.body.schema === 'pc.identity.platform-scope-replacement' ? 'PREPARE' : 'COMMIT',
        issuedAt: Date.now(),
        actor: actorBinding(session),
        body: selected.body,
        checkerPrincipalId: selected.approval.checkerSubjectRef!.slice(-36),
        candidateDigest: selected.candidate.candidateDigest,
        key: selected.candidate.businessIdempotencyKey,
        resumePurpose,
        ...(retained
          ? { retainedCustody: { reviewTokenDigest: digest(retained.token), approvalRequestId } }
          : {}),
      })
    : undefined;
  return NextResponse.json(
    {
      actor: actorBinding(session),
      ...selected,
      stepUp,
      resumeStepUp: resumePurpose
        ? {
            actionIntentId: approvalUpdateAction.id,
            actionIntentDigest: approvalUpdateAction.digest,
            resourceId: approvalRequestId,
            resourceDigest: digest(resumePurpose),
          }
        : null,
      ...(retained
        ? {
            custodyCorrespondence: {
              retainedReviewTokenDigest: digest(retained.token),
              approvalRequestId,
              candidateDigest: retained.review.candidateDigest,
              businessIdempotencyKey: retained.review.key,
              checkerPrincipalId: retained.review.checkerPrincipalId,
            },
          }
        : {}),
      ...(resumeReview?.success
        ? {
            resumableReview: {
              ...reviewResponse(resumeReview.data, runtime),
              approvalRequestId: approvalRequestId,
            },
          }
        : {}),
    },
    { headers: noStore },
  );
}

export async function readPlatformCeilingWorkbench(request: NextRequest) {
  const current = await context(request);
  if (isResponse(current)) return current;
  const { runtime, session } = current;
  const query = z
    .strictObject({
      platformContextId: id.optional(),
      replacementId: id.optional(),
      approvalRequestId: id.optional(),
    })
    .safeParse(Object.fromEntries(request.nextUrl.searchParams));
  if (!query.success || request.nextUrl.searchParams.size !== Object.keys(query.data).length)
    return safeProblem('PC-DATA-6004', request);
  const input = query.data;
  if (input.approvalRequestId) {
    if (input.platformContextId || input.replacementId) return safeProblem('PC-DATA-6004', request);
    return replacementApprovalRead(runtime, session, input.approvalRequestId, request);
  }
  if (!input.platformContextId) {
    if (input.replacementId) return safeProblem('PC-DATA-6004', request);
    return NextResponse.json(
      {
        actor: actorBinding(session),
        administratorLifetime: platformAdministratorLifetimeSettings(),
        suggestedIds: {
          replacementId: responseIds().requestId,
          makerEnvelopeId: responseIds().requestId,
          makerAssignmentId: responseIds().requestId,
          checkerEnvelopeId: responseIds().requestId,
          checkerAssignmentId: responseIds().requestId,
        },
      },
      { headers: noStore },
    );
  }
  const result = input.replacementId
    ? await readinessRead(runtime, session, input.platformContextId, input.replacementId, request)
    : await sourceRead(runtime, session, input.platformContextId, request);
  if (isResponse(result)) return result;
  return NextResponse.json(
    { actor: actorBinding(session), [input.replacementId ? 'readiness' : 'source']: result },
    { headers: noStore },
  );
}

export async function mutatePlatformCeilingWorkbench(request: NextRequest) {
  if (!hasJsonContentType(request.headers.get('content-type')))
    return safeProblem('PC-DATA-6004', request);
  const current = await context(request, true);
  if (isResponse(current)) return current;
  const { runtime, session } = current;
  const parsed = commands.safeParse(await readPublicCommand(request, 262144));
  if (!parsed.success) return safeProblem('PC-DATA-6004', request);
  const input = parsed.data;
  if (input.command === 'RECONCILE_APPROVAL_REVIEW') {
    const original = reviewSchema.safeParse(
      openBffPayload(input.retainedReviewToken, runtime.cookieKey, 'platform-ceiling-review'),
    );
    // Historical custody can be read by the same human in a fresh session.
    // Only the current authoritative approval can supply a usable new seal.
    if (
      !original.success ||
      original.data.issuedAt > Date.now() ||
      original.data.actor.principalId !== session.principalId ||
      original.data.actor.participantId !== session.participantId ||
      original.data.actor.privacyDomainId !== session.privacyDomainId ||
      original.data.candidateDigest !== digest(original.data.body)
    )
      return safeProblem('PC-AUTH-0005', request);
    return replacementApprovalRead(runtime, session, input.approvalRequestId, request, {
      review: original.data,
      token: input.retainedReviewToken,
    });
  }
  if (input.command === 'RECONCILE_CLOSED_RECOVERY_HANDOFF') {
    const original = reviewSchema.safeParse(
      openBffPayload(input.retainedReviewToken, runtime.cookieKey, 'platform-ceiling-review'),
    );
    // A fresh session may read the same human's closed custody. It cannot
    // mint a review, stage business intent or submit the old session's seal.
    if (
      !original.success ||
      original.data.phase !== 'PREPARE' ||
      original.data.issuedAt > Date.now() ||
      original.data.actor.principalId !== session.principalId ||
      original.data.actor.participantId !== session.participantId ||
      original.data.actor.privacyDomainId !== session.privacyDomainId ||
      original.data.candidateDigest !== digest(original.data.body)
    )
      return safeProblem('PC-AUTH-0005', request);
    const token = await identityCsrf(runtime, session, participantAction.id);
    if (!token) return safeProblem('PC-AUTH-0001', request);
    const response = await localOwnerFetch(
      `${runtime.identityUrl}/v1/identity/platform-recovery/enrollments/${input.enrollmentId}/commands`,
      {
        method: 'POST',
        cache: 'no-store',
        headers: {
          ...identityOwnerHeaders(runtime, session, request.headers.get('origin')!),
          'X-CSRF-Token': token,
        },
        body: JSON.stringify({
          privacyDomainId: session.privacyDomainId,
          command: {
            kind: 'READ',
            recoveryId: input.recoveryId,
            ...(original.data.recoveryBinding
              ? {}
              : { preparationDigest: original.data.candidateDigest }),
          },
        }),
        signal: request.signal,
      },
    ).catch(() => undefined);
    const receipt = await ownerJson(response, platformRecoveryReceiptView, request);
    if (isResponse(receipt)) return receipt;
    if (
      receipt.enrollmentId !== input.enrollmentId ||
      receipt.recoveryId !== input.recoveryId ||
      !['EXPIRED', 'REVOKED'].includes(receipt.state) ||
      receipt.authority !== 'NONE' ||
      !receipt.activation ||
      receipt.activation.intentDigest !== receipt.intentDigest ||
      (original.data.recoveryBinding
        ? digest(original.data.recoveryBinding) !==
          digest({
            enrollmentId: receipt.enrollmentId,
            recoveryId: receipt.recoveryId,
            intentDigest: receipt.intentDigest,
            activationOperationId: receipt.activation.operationId,
          })
        : !receipt.closedPreparationCorrespondence ||
          receipt.closedPreparationCorrespondence.preparationDigest !==
            original.data.candidateDigest ||
          receipt.closedPreparationCorrespondence.enrollmentId !== receipt.enrollmentId ||
          receipt.closedPreparationCorrespondence.recoveryId !== receipt.recoveryId ||
          receipt.closedPreparationCorrespondence.intentDigest !== receipt.intentDigest ||
          receipt.closedPreparationCorrespondence.activationOperationId !==
            receipt.activation.operationId) ||
      (receipt.state === 'EXPIRED' && Date.parse(receipt.intent.validUntil) > Date.now()) ||
      receipt.intent.preparation.administrators[0]?.principalId !== session.principalId ||
      original.data.candidateDigest !== digest(receipt.intent.preparation) ||
      digest(original.data.body) !== digest(receipt.intent.preparation) ||
      original.data.checkerPrincipalId !==
        receipt.intent.preparation.administrators[1]?.principalId ||
      !(await currentActorStillMatches(runtime, session, request))
    )
      return safeProblem('PC-AUTH-0005', request);
    return NextResponse.json(
      {
        closedRecovery: {
          enrollmentId: receipt.enrollmentId,
          recoveryId: receipt.recoveryId,
          state: receipt.state,
          authority: 'NONE',
          intentDigest: receipt.intentDigest,
          activationOperationId: receipt.activation.operationId,
          candidateDigest: original.data.candidateDigest,
          businessIdempotencyKey: original.data.key,
          principalId: session.principalId,
          participantId: session.participantId,
          privacyDomainId: session.privacyDomainId,
        },
      },
      { headers: noStore },
    );
  }
  if (
    input.command === 'PREVIEW_PREPARATION' ||
    input.command === 'PREVIEW_COMMIT' ||
    input.command === 'PREVIEW_RECOVERY_HANDOFF'
  ) {
    let body: z.infer<typeof bodySchema>;
    let checkerPrincipalId: string;
    let retained: Review | undefined;
    let recoveryValidUntil: number | undefined;
    let recoveryBinding: z.infer<typeof recoveryBindingSchema> | undefined;
    if (input.command === 'PREVIEW_RECOVERY_HANDOFF') {
      if (input.retainedReviewToken !== undefined) {
        const original = reviewSchema.safeParse(
          openBffPayload(input.retainedReviewToken, runtime.cookieKey, 'platform-ceiling-review'),
        );
        if (
          !original.success ||
          original.data.phase !== 'PREPARE' ||
          original.data.issuedAt > Date.now() ||
          digest(original.data.actor) !== digest(actorBinding(session)) ||
          original.data.candidateDigest !== digest(original.data.body)
        )
          return safeProblem('PC-AUTH-0005', request);
        retained = original.data;
      }
      const token = await identityCsrf(runtime, session, participantAction.id);
      if (!token) return safeProblem('PC-AUTH-0001', request);
      const receiptResponse = await localOwnerFetch(
        `${runtime.identityUrl}/v1/identity/platform-recovery/enrollments/${input.enrollmentId}/commands`,
        {
          method: 'POST',
          cache: 'no-store',
          headers: {
            ...identityOwnerHeaders(runtime, session, request.headers.get('origin')!),
            'X-CSRF-Token': token,
          },
          body: JSON.stringify({
            privacyDomainId: session.privacyDomainId,
            command: { kind: 'READ', recoveryId: input.recoveryId },
          }),
          signal: request.signal,
        },
      ).catch(() => undefined);
      const receipt = await ownerJson(receiptResponse, platformRecoveryReceiptView, request);
      if (isResponse(receipt)) return receipt;
      if (
        receipt.enrollmentId !== input.enrollmentId ||
        receipt.recoveryId !== input.recoveryId ||
        receipt.state !== 'ACTIVE' ||
        receipt.authority !== 'FIXED_PLATFORM_HANDOFF_ONLY' ||
        !receipt.activation ||
        receipt.activation.intentDigest !== receipt.intentDigest ||
        Date.parse(receipt.intent.validUntil) <= Date.now() ||
        receipt.intent.preparation.administrators[0]?.principalId !== session.principalId
      )
        return safeProblem('PC-AUTH-0005', request);
      body = receipt.intent.preparation;
      recoveryValidUntil = Date.parse(receipt.intent.validUntil);
      recoveryBinding = {
        enrollmentId: receipt.enrollmentId,
        recoveryId: receipt.recoveryId,
        intentDigest: receipt.intentDigest,
        activationOperationId: receipt.activation.operationId,
      };
      checkerPrincipalId = body.administrators[1]!.principalId;
      const closedApproval = receipt.intent.closedApprovalSourceDigest
        ? receipt.intent.approvalContinuation
        : undefined;
      const receivingBinding = receipt.activation.bindings.find(
        (binding) => binding.principalId === session.principalId,
      );
      const closedCorrespondence =
        !!closedApproval &&
        !!retained?.recoveryBinding &&
        !!receivingBinding &&
        session.authorityEnvelopeId !== undefined &&
        session.assignmentId !== undefined &&
        session.principalEpoch !== undefined &&
        closedApproval.recoveryId === retained.recoveryBinding.recoveryId &&
        closedApproval.intentDigest === retained.recoveryBinding.intentDigest &&
        closedApproval.activationOperationId === retained.recoveryBinding.activationOperationId &&
        closedApproval.candidateDigest === retained.candidateDigest &&
        closedApproval.businessKey === retained.key &&
        closedApproval.attempt === '1' &&
        receivingBinding?.envelopeId === session.authorityEnvelopeId &&
        receivingBinding?.assignmentId === session.assignmentId &&
        receivingBinding?.principalEpoch === session.principalEpoch;
      if (receipt.intent.closedApprovalSourceDigest && !closedCorrespondence)
        return safeProblem('PC-AUTH-0005', request);
      if (
        retained &&
        (retained.candidateDigest !== digest(body) ||
          digest(retained.body) !== digest(body) ||
          retained.checkerPrincipalId !== checkerPrincipalId ||
          (retained.recoveryBinding &&
            digest(retained.recoveryBinding) !== digest(recoveryBinding) &&
            !closedCorrespondence))
      )
        return safeProblem('PC-RUNTIME-3007', request);
    } else if (input.command === 'PREVIEW_PREPARATION') {
      const source = await sourceRead(runtime, session, input.selection.platformContextId, request);
      if (isResponse(source)) return source;
      const roles = [];
      for (const roleId of new Set(input.selection.administrators.map((admin) => admin.roleId))) {
        const roleResponse = await localOwnerFetch(
          `${runtime.publicApiUrl}/v1/participants/${session.participantId}/roles/${roleId}/binding-preview`,
          {
            cache: 'no-store',
            headers: {
              ...publicHeaders(runtime, session),
              Authorization: `Bearer ${session.sessionToken}`,
            },
            signal: request.signal,
          },
        ).catch(() => undefined);
        const role = await ownerJson(roleResponse, roleBindingPreviewSchema, request);
        if (isResponse(role)) {
          await logOwnerFailure('platform-ceiling-role-binding', roleResponse);
          return role;
        }
        roles.push(role);
      }
      try {
        body = buildCeilingPreparation(input.selection, source, roles, session.principalId);
      } catch {
        return safeProblem('PC-DATA-6007', request);
      }
      checkerPrincipalId = input.selection.administrators[1]!.principalId;
    } else {
      if (input.checkerPrincipalId === session.principalId)
        return safeProblem('PC-AUTH-0005', request);
      const readiness = await readinessRead(
        runtime,
        session,
        input.platformContextId,
        input.replacementId,
        request,
      );
      if (isResponse(readiness)) return readiness;
      if (
        readiness.state !== 'WITHDRAWING' ||
        readiness.unacknowledgedTargets !== 0 ||
        readiness.unpreparedAdministrators !== 0 ||
        BigInt(readiness.sourceExpiresAtNs) <= BigInt(readiness.nowNs)
      )
        return safeProblem('PC-RUNTIME-3007', request);
      body = platformScopeReplacementCommit.parse({
        schema: 'pc.identity.platform-scope-replacement-commit',
        schemaVersion: 1,
        replacementId: readiness.replacementId,
        platformContextId: readiness.platformContextId,
        expectedRootRevision: readiness.rootRevision,
        expectedReplacementRevision: readiness.replacementRevision,
        predecessorEpoch: readiness.predecessorEpoch,
        predecessorDigest: readiness.predecessorDigest,
        successorDigest: readiness.successorDigest,
        readinessDigest: readiness.readinessDigest,
        reason: input.reason,
      });
      checkerPrincipalId = input.checkerPrincipalId;
    }
    if (!(await currentActorStillMatches(runtime, session, request)))
      return safeProblem('PC-AUTH-0005', request);
    if (recoveryValidUntil !== undefined && recoveryValidUntil <= Date.now())
      return safeProblem('PC-AUTH-0005', request);
    const review = reviewSchema.parse({
      phase: input.command === 'PREVIEW_COMMIT' ? 'COMMIT' : 'PREPARE',
      issuedAt: Date.now(),
      actor: actorBinding(session),
      body,
      checkerPrincipalId,
      candidateDigest: digest(body),
      recoveryBinding,
      key: retained?.key ?? `platform-ceiling-${responseIds().requestId}`,
      resourceReservationId:
        retained?.resourceReservationId ??
        ('resourceReservationId' in input ? input.resourceReservationId : undefined),
    });
    return NextResponse.json(reviewResponse(review, runtime), { headers: noStore });
  }
  if (input.command === 'APPROVE') {
    const selected = await approvalRead(runtime, session, input.approvalRequestId, request);
    if (isResponse(selected)) return selected;
    return approveGovernanceRequest(runtime, session, input.approvalRequestId, request);
  }
  const decoded = reviewSchema.safeParse(
    openBffPayload(input.reviewToken, runtime.cookieKey, 'platform-ceiling-review'),
  );
  if (!decoded.success) return safeProblem('PC-AUTH-0005', request);
  const review = decoded.data;
  if (
    review.issuedAt > Date.now() ||
    Date.now() - review.issuedAt > 30 * 60 * 1000 ||
    digest(review.actor) !== digest(actorBinding(session)) ||
    review.candidateDigest !== digest(review.body) ||
    (review.phase === 'PREPARE') !==
      (review.body.schema === 'pc.identity.platform-scope-replacement')
  )
    return safeProblem('PC-AUTH-0005', request);
  // Awaited reads/tokens cannot carry an expired seal or changed actor into the next write.
  const admitNextMutation = async () => {
    const liveSeal = () =>
      review.issuedAt <= Date.now() && Date.now() - review.issuedAt <= 30 * 60 * 1000;
    if (request.signal.aborted) return safeProblem('PC-INTEGRATION-5001', request);
    if (!liveSeal()) return safeProblem('PC-AUTH-0005', request);
    const sameActor = await currentActorStillMatches(runtime, session, request);
    if (request.signal.aborted) return safeProblem('PC-INTEGRATION-5001', request);
    return sameActor && liveSeal() ? undefined : safeProblem('PC-AUTH-0005', request);
  };
  if (input.command === 'RESUME') {
    process.stderr.write('OPENPC_PLATFORM_CEILING_RESUME|stage=original_read_started\n');
    const selected = await approvalRead(runtime, session, input.approvalRequestId, request);
    if (isResponse(selected)) return selected;
    if (
      selected.approval.makerSubjectRef !== `urn:openpc:resource:${session.principalId}` ||
      selected.approval.checkerSubjectRef !== `urn:openpc:resource:${review.checkerPrincipalId}` ||
      selected.candidate.candidateDigest !== review.candidateDigest ||
      selected.candidate.businessIdempotencyKey !== review.key ||
      selected.candidate.canRequestResume !== true ||
      selected.candidate.successorApprovalRef !== null ||
      !selected.candidate.attemptId ||
      !selected.candidate.attempt
    )
      return safeProblem('PC-AUTH-0005', request);
    process.stderr.write('OPENPC_PLATFORM_CEILING_RESUME|stage=original_read_completed\n');
    const purpose = approvalResumePurpose(selected, input.approvalRequestId);
    if (!purpose) return safeProblem('PC-INTEGRATION-5001', request);
    if (!review.resumePurpose || digest(review.resumePurpose) !== digest(purpose))
      return safeProblem('PC-AUTH-0005', request);
    process.stderr.write('OPENPC_PLATFORM_CEILING_RESUME|stage=csrf_started\n');
    const token = await csrf(runtime, session, approvalUpdateAction.id, request.signal);
    if (!token) return safeProblem('PC-AUTH-0005', request);
    process.stderr.write('OPENPC_PLATFORM_CEILING_RESUME|stage=actor_revalidation_started\n');
    const admission = await admitNextMutation();
    if (admission) return admission;
    process.stderr.write('OPENPC_PLATFORM_CEILING_RESUME|stage=public_patch_started\n');
    const response = await localOwnerFetch(
      `${runtime.publicApiUrl}/api/v1/approval-requests/${encodeURIComponent(selected.approval.approvalRequestId)}`,
      {
        method: 'PATCH',
        cache: 'no-store',
        signal: request.signal,
        headers: {
          ...publicHeaders(runtime, session),
          'Content-Type': 'application/json',
          'X-CSRF-Token': token,
          'Idempotency-Key': `platform-ceiling-resume-${selected.candidate.attemptId}`,
          'X-OpenPC-Action-Intent-Digest': approvalUpdateAction.digest,
          'If-Match': `"${digest({ resourceId: input.approvalRequestId, revision: selected.approval.revision })}"`,
        },
        // The receiving proof includes the approval URN; the public route supplies it.
        body: JSON.stringify({
          command: purpose.command,
          actionIntentId: purpose.actionIntentId,
          actionIntentDigest: purpose.actionIntentDigest,
          expectedRevision: purpose.expectedRevision,
          predecessorCandidateId: purpose.predecessorCandidateId,
          expectedAttempt: purpose.expectedAttempt,
          candidateDigest: purpose.candidateDigest,
          reason: purpose.reason,
        }),
      },
    ).catch(() => undefined);
    const operation = await ownerJson(response, publicOperationSchema, request);
    if (isResponse(operation)) {
      await logOwnerFailure('platform-ceiling-resume', response);
      return operation;
    }
    process.stderr.write(
      `OPENPC_PLATFORM_CEILING_RESUME|stage=successor_requested|replacement=${review.body.replacementId}|predecessor=${input.approvalRequestId}|attempt=${selected.candidate.attempt}\n`,
    );
    return NextResponse.json(
      {
        ...reviewResponse(review, runtime),
        approvalRequestId: operation.resourceRef.slice(-36),
        operation,
      },
      { status: 202, headers: noStore },
    );
  }
  const path = `/v1/platform-contexts/${review.body.platformContextId}/scope-replacements${review.phase === 'COMMIT' ? '/commit' : ''}`;
  if (input.command === 'SUBMIT' && review.phase === 'COMMIT') {
    // The caller retains the original sealed key/body before any stage request.
    // Resolve an ambiguous approval through supported public readback first.
    const query = new URLSearchParams({
      filter: `candidateDigest:eq:${review.candidateDigest}`,
      limit: '50',
    });
    const page = await ownerJson(
      await localOwnerFetch(`${runtime.publicApiUrl}/api/v1/approval-requests?${query}`, {
        cache: 'no-store',
        headers: publicHeaders(runtime, session),
        signal: request.signal,
      }).catch(() => undefined),
      approvalPageSchema,
      request,
    );
    if (isResponse(page)) return page;
    if (
      page.completeness !== 'COMPLETE' ||
      page.nextCursor !== null ||
      page.total !== String(page.items.length) ||
      page.items.length > 1 ||
      page.authorizedEmpty !== (page.items.length === 0)
    )
      return safeProblem('PC-INTEGRATION-5001', request);
    if (page.items[0]) {
      const original = await approvalRead(
        runtime,
        session,
        page.items[0].approvalRequestId.slice(-36),
        request,
      );
      if (isResponse(original)) return original;
      if (
        original.approval.makerSubjectRef !== `urn:openpc:resource:${session.principalId}` ||
        original.approval.checkerSubjectRef !==
          `urn:openpc:resource:${review.checkerPrincipalId}` ||
        original.candidate.candidateDigest !== review.candidateDigest ||
        digest(original.body) !== review.candidateDigest ||
        original.candidate.businessIdempotencyKey !== review.key ||
        original.candidate.makerSessionMatches !== true ||
        original.candidate.successorApprovalRef !== null
      )
        return safeProblem('PC-AUTH-0005', request);
      return NextResponse.json(
        {
          ...reviewResponse(review, runtime),
          approvalRequestId: original.approval.approvalRequestId.slice(-36),
        },
        { headers: noStore },
      );
    }
    // No discoverable approval proves neither absence of a proposal nor of CREATE.
    // Existing /prepare reconciles this exact original under its intent lock,
    // read-first; only a genuinely absent original is inserted after readiness.
    // Intended CREATE also reconciles its original key/full request at its owner.
  }
  const headers = {
    ...publicHeaders(runtime, session),
    'Authorization': `Bearer ${session.sessionToken}`,
    'Content-Type': 'application/json',
    'Idempotency-Key': review.key,
    'X-OpenPC-Aggregate-Version': review.phase === 'PREPARE' ? '0' : '1',
    'OpenPC-Action-Intent-Digest': participantAction.digest,
  };
  if (input.command === 'SUBMIT') {
    const mutationToken = await csrf(runtime, session, participantAction.id, request.signal);
    if (!mutationToken) return safeProblem('PC-AUTH-0005', request);
    const admission = await admitNextMutation();
    if (admission) return admission;
    const stagedResponse = await localOwnerFetch(`${runtime.publicApiUrl}${path}/prepare`, {
      method: 'POST',
      cache: 'no-store',
      headers: { ...headers, 'X-CSRF-Token': mutationToken },
      body: JSON.stringify(review.body),
      signal: request.signal,
    }).catch(() => undefined);
    const staged = await ownerJson(
      stagedResponse,
      z.strictObject({
        candidate: bodySchema,
        candidateDigest: digestSchema,
        expectedRevision: z.string(),
        actionIntentDigest: digestSchema,
      }),
      request,
    );
    if (isResponse(staged)) {
      await logOwnerFailure('platform-ceiling-prepare-governance', stagedResponse);
      return staged;
    }
    if (
      digest(staged.candidate) !== review.candidateDigest ||
      staged.candidateDigest !== review.candidateDigest ||
      staged.expectedRevision !== headers['X-OpenPC-Aggregate-Version'] ||
      staged.actionIntentDigest !== participantAction.digest
    )
      return safeProblem('PC-INTEGRATION-5001', request);
    const approvalToken = await csrf(runtime, session, approvalCreateAction.id, request.signal);
    if (!approvalToken) return safeProblem('PC-AUTH-0005', request);
    const approvalAdmission = await admitNextMutation();
    if (approvalAdmission) return approvalAdmission;
    const response = await localOwnerFetch(`${runtime.publicApiUrl}/api/v1/approval-requests`, {
      method: 'POST',
      cache: 'no-store',
      headers: {
        ...publicHeaders(runtime, session),
        'Content-Type': 'application/json',
        'X-CSRF-Token': approvalToken,
        'Idempotency-Key': `${review.key}-approval`,
        'X-OpenPC-Action-Intent-Digest': approvalCreateAction.digest,
      },
      body: JSON.stringify({
        actionIntentId: approvalCreateAction.id,
        actionIntentDigest: approvalCreateAction.digest,
        candidateDigest: review.candidateDigest,
        makerSubjectRef: `urn:openpc:resource:${session.principalId}`,
        checkerSubjectRef: `urn:openpc:resource:${review.checkerPrincipalId}`,
        reason: review.body.reason,
        ...(review.resourceReservationId
          ? { resourceReservationId: review.resourceReservationId }
          : {}),
      }),
      signal: request.signal,
    }).catch(() => undefined);
    const operation = await ownerJson(response, publicOperationSchema, request);
    if (isResponse(operation)) {
      await logOwnerFailure('platform-ceiling-request-approval', response);
      return operation;
    }
    return NextResponse.json(
      {
        ...reviewResponse(review, runtime),
        approvalRequestId: operation.resourceRef.slice(-36),
        operation,
      },
      { status: 202, headers: noStore },
    );
  }
  const selected = await approvalRead(runtime, session, input.approvalRequestId, request);
  if (isResponse(selected)) return selected;
  if (
    selected.approval.state !== 'APPROVED' ||
    selected.candidate.state !== 'APPROVED' ||
    selected.candidate.approvalUsable === false ||
    selected.candidate.makerSessionMatches === false ||
    selected.approval.candidateDigest !== review.candidateDigest ||
    selected.approval.makerSubjectRef !== `urn:openpc:resource:${session.principalId}` ||
    selected.approval.checkerSubjectRef !== `urn:openpc:resource:${review.checkerPrincipalId}`
  )
    return safeProblem('PC-AUTH-0005', request);
  const executionToken = await csrf(runtime, session, participantAction.id, request.signal);
  if (!executionToken) return safeProblem('PC-AUTH-0005', request);
  const executionAdmission = await admitNextMutation();
  if (executionAdmission) return executionAdmission;
  const response = await localOwnerFetch(`${runtime.publicApiUrl}${path}`, {
    method: 'POST',
    cache: 'no-store',
    headers: {
      ...headers,
      'X-CSRF-Token': executionToken,
      'X-OpenPC-Approval-Request-ID': input.approvalRequestId,
    },
    body: JSON.stringify(review.body),
    signal: request.signal,
  }).catch(() => undefined);
  const result = await ownerJson(
    response,
    z.strictObject({
      replacementId: id,
      successorDigest: digestSchema,
      state: z.enum(['WITHDRAWING', 'COMMITTED']),
      revision: z.string(),
      operationId: id,
      platformAuthorityEpoch: z.string().optional(),
    }),
    request,
  );
  if (isResponse(result)) {
    await logOwnerFailure('platform-ceiling-execute', response);
    return result;
  }
  if (
    result.replacementId !== review.body.replacementId ||
    result.state !== (review.phase === 'PREPARE' ? 'WITHDRAWING' : 'COMMITTED') ||
    result.revision !== (review.phase === 'PREPARE' ? '1' : '2') ||
    (review.body.schema === 'pc.identity.platform-scope-replacement-commit' &&
      (result.successorDigest !== review.body.successorDigest ||
        result.platformAuthorityEpoch !==
          (BigInt(review.body.predecessorEpoch) + 1n).toString())) ||
    (review.phase === 'PREPARE' && result.platformAuthorityEpoch !== undefined)
  )
    return safeProblem('PC-INTEGRATION-5001', request);
  return NextResponse.json({ result, actor: actorBinding(session) }, { headers: noStore });
}
