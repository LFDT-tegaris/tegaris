import {
  approveGovernanceRequest,
  participantId,
  privacyDomainId,
  checkerPrincipalId,
  participantAction,
  approvalCreateAction,
  approvalDecisionAction,
  digestSchema,
  uuidSchema,
  timestampSchema,
  publicOperationSchema,
  approvalPageSchema,
  digest,
  contextAdmitted,
  publicHeaders,
  csrf,
  ownerFailure,
  logOwnerFailure,
  ownerJson,
  isResponse,
  approval,
} from './local-governance-api';
import { NextResponse, type NextRequest } from 'next/server';
import { z } from 'zod';
import { readParticipantEnvelopeRecovery } from './local-participant-envelope-recovery';

import {
  authenticated,
  hasJsonContentType,
  localRuntimeConfig,
  openBffPayload,
  parsePublicCommand,
  responseIds,
  rfc3339Micros,
  safeProblem,
  sameOrigin,
  sealBffPayload,
  type IdentitySession,
  type LocalConfig,
} from './local-runtime';

const reviewMaximumAgeMs = 30 * 60 * 1000;
const noStoreHeaders = { 'Cache-Control': 'no-store' } as const;
const previewInputSchema = z
  .object({
    command: z.literal('PREVIEW'),
    label: z.string().trim().min(3).max(80),
    reason: z.string().trim().min(10).max(1024),
    validUntil: timestampSchema,
  })
  .strict()
  .superRefine((value, context) => {
    const validUntil = Date.parse(value.validUntil);
    if (
      !Number.isFinite(validUntil) ||
      validUntil <= Date.now() + 60_000 ||
      validUntil > Date.now() + 366 * 24 * 60 * 60 * 1000
    ) {
      context.addIssue({
        code: 'custom',
        path: ['validUntil'],
        message: 'validity is out of range',
      });
    }
  });
const tokenInputSchema = z.discriminatedUnion('command', [
  z.object({ command: z.literal('SUBMIT'), reviewToken: z.string().min(80).max(8192) }).strict(),
  z
    .object({
      command: z.literal('COMMIT'),
      reviewToken: z.string().min(80).max(8192),
      approvalRequestId: uuidSchema,
      simulateResponseLoss: z.boolean().optional(),
    })
    .strict(),
]);
const approveInputSchema = z
  .object({ command: z.literal('APPROVE'), approvalRequestId: uuidSchema })
  .strict();

const envelopeBodySchema = z
  .object({
    envelopeId: uuidSchema,
    semanticDigest: digestSchema,
    privacyDomainIds: z.tuple([z.literal(privacyDomainId)]),
    actionIntentIds: z.tuple([z.literal(participantAction.id)]),
    resourceIds: z.tuple([z.literal('*')]),
    riskClasses: z.tuple([z.literal('HIGH')]),
    validFrom: timestampSchema,
    validUntil: timestampSchema,
    makerCheckerRequired: z.literal(true),
    stepUpRequired: z.literal(true),
    onwardDelegationDepth: z.literal(0),
  })
  .strict();
const reviewSchema = z
  .object({
    version: z.literal(1),
    issuedAt: z.number().int().nonnegative(),
    sessionId: uuidSchema,
    principalId: uuidSchema,
    contextEpoch: z.string().regex(/^[1-9][0-9]*$/u),
    label: z.string().min(3).max(80),
    reason: z.string().min(10).max(1024),
    idempotencyKey: z.string().min(16).max(128),
    candidateDigest: digestSchema,
    body: envelopeBodySchema,
  })
  .strict();
const envelopeReadbackSchema = z
  .object({
    operationId: uuidSchema,
    effect: envelopeBodySchema
      .omit({ envelopeId: true })
      .extend({
        id: uuidSchema,
        participantId: z.literal(participantId),
        authorityEpoch: z.string().regex(/^(?:0|[1-9][0-9]*)$/u),
        state: z.enum(['DRAFT', 'SUBMITTED', 'APPROVED', 'ACTIVE', 'SUPERSEDED', 'REVOKED']),
      })
      .strict(),
  })
  .strict();

type Review = z.infer<typeof reviewSchema>;
type EnvelopeBody = z.infer<typeof envelopeBodySchema>;

function stagedEnvelopeValue(body: EnvelopeBody) {
  return {
    id: body.envelopeId,
    participantId,
    authorityEpoch: '0',
    state: 'DRAFT',
    ...body,
    validFrom: new Date(body.validFrom).toISOString(),
    validUntil: new Date(body.validUntil).toISOString(),
  } as const;
}

async function readEffect(
  runtime: LocalConfig,
  session: IdentitySession,
  envelopeId: string,
  request: NextRequest,
) {
  const response = await fetch(
    `${runtime.publicApiUrl}/v1/participants/${participantId}/envelopes/${envelopeId}`,
    {
      cache: 'no-store',
      headers: {
        'Authorization': `Bearer ${session.sessionToken}`,
        'OpenPC-Privacy-Domain-ID': `urn:openpc:privacy-domain:${privacyDomainId}`,
      },
    },
  ).catch(() => undefined);
  return ownerJson(response, envelopeReadbackSchema, request);
}

function reviewFor(session: IdentitySession, input: z.infer<typeof previewInputSchema>): Review {
  const envelopeId = responseIds().requestId;
  const validFrom = rfc3339Micros();
  const semanticDigest = digest({
    label: input.label,
    privacyDomainId,
    actionIntentId: participantAction.id,
    riskClass: 'HIGH',
    validFrom,
    validUntil: input.validUntil,
    makerCheckerRequired: true,
    stepUpRequired: true,
  });
  const body = envelopeBodySchema.parse({
    envelopeId,
    semanticDigest,
    privacyDomainIds: [privacyDomainId],
    actionIntentIds: [participantAction.id],
    resourceIds: ['*'],
    riskClasses: ['HIGH'],
    validFrom,
    validUntil: input.validUntil,
    makerCheckerRequired: true,
    stepUpRequired: true,
    onwardDelegationDepth: 0,
  });
  return reviewSchema.parse({
    version: 1,
    issuedAt: Date.now(),
    sessionId: session.sessionId,
    principalId: session.principalId,
    contextEpoch: session.contextEpoch,
    label: input.label,
    reason: input.reason,
    idempotencyKey: `workbench-envelope-${envelopeId}`,
    // The approval binds the authoritative candidate staged by Participant, not
    // merely its request body. Keep this shape aligned with the owner boundary.
    candidateDigest: digest(stagedEnvelopeValue(body)),
    body,
  });
}

function openReview(
  token: string,
  runtime: LocalConfig,
  session: IdentitySession,
): Review | undefined {
  const review = reviewSchema.safeParse(
    openBffPayload(token, runtime.cookieKey, 'participant-review'),
  );
  if (
    !review.success ||
    review.data.issuedAt > Date.now() ||
    Date.now() - review.data.issuedAt >= reviewMaximumAgeMs ||
    review.data.sessionId !== session.sessionId ||
    review.data.principalId !== session.principalId ||
    review.data.contextEpoch !== session.contextEpoch
  )
    return undefined;
  return review.data;
}

function reviewResponse(review: Review, runtime: LocalConfig) {
  return {
    reviewToken: sealBffPayload(review, runtime.cookieKey, 'participant-review'),
    review: {
      envelopeId: review.body.envelopeId,
      label: review.label,
      reason: review.reason,
      candidateDigest: review.candidateDigest,
      validFrom: review.body.validFrom,
      validUntil: review.body.validUntil,
      actionIntentId: participantAction.id,
      riskClass: 'HIGH',
      makerCheckerRequired: true,
      stepUpRequired: true,
    },
  };
}

export async function readParticipantWorkbench(request: NextRequest) {
  const runtime = await localRuntimeConfig().catch(() => undefined);
  if (!runtime) return undefined;
  const session = await authenticated(request, runtime);
  if (!session) return safeProblem('PC-AUTH-0005', request);
  if (request.nextUrl.searchParams.has('creationApprovalRequestId'))
    return readParticipantEnvelopeRecovery(runtime, session, request);
  if (!contextAdmitted(session)) return safeProblem('PC-AUTH-0005', request);
  const filter = `${session.role === 'viewer' ? 'checkerSubjectRef' : 'makerSubjectRef'}:eq:urn:openpc:resource:${session.principalId}`;
  const response = await fetch(
    `${runtime.publicApiUrl}/api/v1/approval-requests?limit=50&sort=-updatedAt&filter=${encodeURIComponent(filter)}`,
    {
      cache: 'no-store',
      headers: publicHeaders(runtime, session, responseIds(request)),
    },
  ).catch(() => undefined);
  const page = await ownerJson(response, approvalPageSchema, request);
  if (isResponse(page)) return page;
  const envelopeId = request.nextUrl.searchParams.get('envelopeId');
  const effect =
    envelopeId && uuidSchema.safeParse(envelopeId).success
      ? await readEffect(runtime, session, envelopeId, request)
      : undefined;
  if (isResponse(effect)) {
    if (effect.status !== 404) return effect;
  }
  const approvals = page.items.map((item) => ({
    ...item,
    ...(session.role === 'viewer' && item.state === 'REQUESTED'
      ? {
          stepUp: {
            actionIntentId: approvalDecisionAction.id,
            actionIntentDigest: approvalDecisionAction.digest,
            resourceId: item.approvalRequestId.split(':').at(-1)!,
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
  return NextResponse.json(
    {
      actor: {
        role: session.role,
        principalId: session.principalId,
        participantId: session.participantId,
        privacyDomainId: session.privacyDomainId,
        contextEpoch: session.contextEpoch,
      },
      approvals,
      ...(effect && !isResponse(effect) ? { effect } : {}),
      snapshotRevision: page.snapshotRevision,
    },
    { headers: noStoreHeaders },
  );
}

export async function mutateParticipantWorkbench(request: NextRequest) {
  const runtime = await localRuntimeConfig().catch(() => undefined);
  if (!runtime) return safeProblem('PC-AUTH-0005', request);
  if (!sameOrigin(request) || !hasJsonContentType(request.headers.get('content-type')))
    return safeProblem('PC-AUTH-0002', request);
  const session = await authenticated(request, runtime);
  if (!session || !contextAdmitted(session)) return safeProblem('PC-AUTH-0005', request);
  const raw = parsePublicCommand(await request.text());
  const preview = previewInputSchema.safeParse(raw);
  if (preview.success) {
    if (session.role !== 'operator') return safeProblem('PC-AUTH-0005', request);
    const review = reviewFor(session, preview.data);
    return NextResponse.json(reviewResponse(review, runtime), {
      status: 201,
      headers: noStoreHeaders,
    });
  }
  const tokenInput = tokenInputSchema.safeParse(raw);
  const approveInput = approveInputSchema.safeParse(raw);
  if (!tokenInput.success && !approveInput.success) return safeProblem('PC-DATA-6004', request);

  if (approveInput.success) {
    if (session.role !== 'viewer') return safeProblem('PC-AUTH-0005', request);
    return approveGovernanceRequest(runtime, session, approveInput.data.approvalRequestId, request);
  }

  if (!tokenInput.success) return safeProblem('PC-DATA-6004', request);
  const token = tokenInput.data;
  if (session.role !== 'operator') return safeProblem('PC-AUTH-0005', request);
  const review = openReview(token.reviewToken, runtime, session);
  if (!review) return safeProblem('PC-DATA-6007', request);
  if (token.command === 'SUBMIT') {
    const participantCsrf = await csrf(runtime, session, participantAction.id);
    if (!participantCsrf) return safeProblem('PC-AUTH-0005', request);
    const ownerOrigin = new URL(runtime.publicApiUrl).origin;
    const stage = await fetch(
      `${runtime.publicApiUrl}/v1/participants/${participantId}/envelopes`,
      {
        method: 'POST',
        cache: 'no-store',
        headers: {
          'Authorization': `Bearer ${session.sessionToken}`,
          'Content-Type': 'application/json',
          'Origin': ownerOrigin,
          'X-CSRF-Token': participantCsrf,
          'Idempotency-Key': review.idempotencyKey,
          'X-OpenPC-Aggregate-Version': '0',
          'X-OpenPC-Approval-Request-ID': '00000000-0000-7000-8000-000000000000',
          'OpenPC-Action-Intent-Digest': participantAction.digest,
        },
        body: JSON.stringify(review.body),
      },
    ).catch(() => undefined);
    if (!stage || stage.status !== 403) {
      await logOwnerFailure('candidate-stage', stage);
      return safeProblem('PC-INTEGRATION-5001', request);
    }
    const approvalCsrf = await csrf(runtime, session, approvalCreateAction.id);
    if (!approvalCsrf) return safeProblem('PC-AUTH-0005', request);
    const ids = responseIds(request);
    const ownerResponse = await fetch(`${runtime.publicApiUrl}/api/v1/approval-requests`, {
      method: 'POST',
      cache: 'no-store',
      headers: {
        ...publicHeaders(runtime, session, ids),
        'Content-Type': 'application/json',
        'X-CSRF-Token': approvalCsrf,
        'Idempotency-Key': `workbench-request-${review.body.envelopeId}`,
        'X-OpenPC-Action-Intent-Digest': approvalCreateAction.digest,
        'OpenPC-Action-Intent-Digest': approvalCreateAction.digest,
      },
      body: JSON.stringify({
        actionIntentId: approvalCreateAction.id,
        candidateDigest: review.candidateDigest,
        makerSubjectRef: `urn:openpc:resource:${session.principalId}`,
        checkerSubjectRef: `urn:openpc:resource:${checkerPrincipalId}`,
        actionIntentDigest: approvalCreateAction.digest,
        reason: review.reason,
      }),
    }).catch(() => undefined);
    if (!ownerResponse?.ok) await logOwnerFailure('approval-create', ownerResponse);
    const operation = await ownerJson(ownerResponse, publicOperationSchema, request);
    if (isResponse(operation)) return operation;
    const approvalRequestId = operation.resourceRef.split(':').at(-1)!;
    const current = await approval(runtime, session, approvalRequestId, request);
    if (
      isResponse(current) ||
      current.candidateDigest !== review.candidateDigest ||
      current.state !== 'REQUESTED'
    )
      return safeProblem('PC-INTEGRATION-5001', request);
    return NextResponse.json(
      { ...reviewResponse(review, runtime), operation, approval: current },
      { status: 202, headers: noStoreHeaders },
    );
  }

  const current = await approval(runtime, session, token.approvalRequestId, request);
  if (isResponse(current)) return current;
  if (
    current.state !== 'APPROVED' ||
    current.candidateDigest !== review.candidateDigest ||
    current.makerSubjectRef !== `urn:openpc:resource:${session.principalId}`
  )
    return safeProblem('PC-DATA-6007', request);
  const participantCsrf = await csrf(runtime, session, participantAction.id);
  if (!participantCsrf) return safeProblem('PC-AUTH-0005', request);
  const ownerResponse = await fetch(
    `${runtime.publicApiUrl}/v1/participants/${participantId}/envelopes`,
    {
      method: 'POST',
      cache: 'no-store',
      headers: {
        'Authorization': `Bearer ${session.sessionToken}`,
        'Content-Type': 'application/json',
        'Origin': new URL(runtime.publicApiUrl).origin,
        'X-CSRF-Token': participantCsrf,
        'Idempotency-Key': review.idempotencyKey,
        'X-OpenPC-Aggregate-Version': '0',
        'X-OpenPC-Approval-Request-ID': token.approvalRequestId,
        'OpenPC-Action-Intent-Digest': participantAction.digest,
      },
      body: JSON.stringify(review.body),
    },
  ).catch(() => undefined);
  if (!ownerResponse?.ok || !hasJsonContentType(ownerResponse.headers.get('content-type')))
    return ownerFailure(ownerResponse, request);
  const effect = envelopeBodySchema
    .omit({ envelopeId: true })
    .extend({
      id: uuidSchema,
      participantId: z.literal(participantId),
      authorityEpoch: z.string(),
      state: z.literal('DRAFT'),
    })
    .strict()
    .safeParse(await ownerResponse.json());
  if (!effect.success || effect.data.id !== review.body.envelopeId)
    return safeProblem('PC-INTEGRATION-5001', request);
  if (token.simulateResponseLoss === true) {
    return NextResponse.json(
      {
        truthState: 'WRITE_AMBIGUITY',
        envelopeId: review.body.envelopeId,
        reconciliation: 'READ_AUTHORITATIVE_EFFECT',
      },
      { status: 202, headers: noStoreHeaders },
    );
  }
  const readback = await readEffect(runtime, session, review.body.envelopeId, request);
  if (isResponse(readback)) return readback;
  return NextResponse.json(
    {
      operation: { operationId: readback.operationId, state: 'SUCCEEDED', truthState: 'SUCCESS' },
      effect: readback.effect,
    },
    { status: 202, headers: noStoreHeaders },
  );
}

export async function participantWorkbenchEvent(request: NextRequest) {
  const runtime = await localRuntimeConfig().catch(() => undefined);
  if (!runtime) return safeProblem('PC-AUTH-0005', request);
  const session = await authenticated(request, runtime);
  if (!session || !contextAdmitted(session)) return safeProblem('PC-AUTH-0005', request);
  const approvalRequestId = request.nextUrl.searchParams.get('approvalRequestId');
  if (approvalRequestId && !uuidSchema.safeParse(approvalRequestId).success)
    return safeProblem('PC-DATA-6004', request);
  let eventId: string;
  let data: Record<string, string>;
  if (approvalRequestId) {
    const current = await approval(runtime, session, approvalRequestId, request);
    if (isResponse(current)) return current;
    eventId = digest({ approvalRequestId, revision: current.revision, state: current.state });
    data = { approvalRequestId, state: current.state, revision: current.revision };
  } else {
    const filter = `${session.role === 'viewer' ? 'checkerSubjectRef' : 'makerSubjectRef'}:eq:urn:openpc:resource:${session.principalId}`;
    const ownerResponse = await fetch(
      `${runtime.publicApiUrl}/api/v1/approval-requests?limit=1&sort=-updatedAt&filter=${encodeURIComponent(filter)}`,
      {
        cache: 'no-store',
        headers: publicHeaders(runtime, session, responseIds(request)),
      },
    ).catch(() => undefined);
    const page = await ownerJson(ownerResponse, approvalPageSchema, request);
    if (isResponse(page)) return page;
    eventId = digest({
      principalId: session.principalId,
      role: session.role,
      approvals: page.items.map(({ approvalRequestId: id, revision, state }) => ({
        id,
        revision,
        state,
      })),
    });
    data = { snapshotRevision: page.snapshotRevision };
  }
  const last = request.headers.get('last-event-id');
  const payload =
    last === eventId
      ? 'retry: 1500\n: owner state unchanged\n\n'
      : `retry: 1500\nid: ${eventId}\nevent: snapshot-invalidated\ndata: ${JSON.stringify(data)}\n\n`;
  return new Response(payload, {
    headers: {
      ...noStoreHeaders,
      'Connection': 'keep-alive',
      'Content-Type': 'text/event-stream; charset=utf-8',
      'X-Accel-Buffering': 'no',
    },
  });
}

export const participantWorkbenchActions = { participantAction, approvalDecisionAction } as const;
