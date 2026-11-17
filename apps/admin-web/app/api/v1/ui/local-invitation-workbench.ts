import { randomUUID } from 'node:crypto';
import { NextResponse, type NextRequest } from 'next/server';
import { z } from 'zod';
import {
  invitationActor,
  invitationCandidate,
  invitationChange,
  invitationOperation,
  invitationPrepared,
  invitationProposal,
  invitationReadback,
  invitationReview,
} from '../../../../lib/invitation-workflow';
import { actorBinding } from './local-recovery-model';
import {
  approval,
  approvalCreateAction,
  approvalDecisionAction,
  approvalPageSchema,
  approveGovernanceRequest,
  csrf,
  digest,
  isResponse,
  ownerFailure,
  ownerJson,
  participantAction,
  principalCreateAction,
  publicHeaders,
  publicOperationSchema,
} from './local-governance-api';
import {
  authenticated,
  hasJsonContentType,
  localRuntimeConfig,
  openBffPayload,
  parsePublicCommand,
  responseIds,
  safeProblem,
  sameOrigin,
  sealBffPayload,
  type IdentitySession,
  type LocalConfig,
} from './local-runtime';
const noStore = { 'Cache-Control': 'no-store' };
const fullReview = invitationReview
  .extend({ actor: invitationActor, origin: z.url(), idempotencyKey: z.string().min(16).max(128) })
  .strict();
type Review = z.infer<typeof fullReview>;
const commands = z.discriminatedUnion('command', [
  z.strictObject({
    command: z.literal('PREPARE'),
    input: z.union(
      invitationChange.options.map((option) =>
        option.shape.mutation.value === 'CREATE'
          ? option.extend({ invitationId: z.uuidv7().optional() })
          : option,
      ),
    ),
    reason: z.string().trim().min(10).max(1024),
    checkerPrincipalId: z.uuid(),
    expectedSessionId: z.uuid(),
  }),
  z.strictObject({ command: z.literal('SUBMIT'), reviewToken: z.string().min(80).max(65536) }),
  z.strictObject({
    command: z.literal('COMMIT'),
    reviewToken: z.string().min(80).max(65536),
    approvalRequestId: z.uuid(),
  }),
  z.strictObject({
    command: z.literal('APPROVE'),
    approvalRequestId: z.uuid(),
    candidateDigest: invitationReview.shape.candidateDigest,
    expectedRevision: invitationReview.shape.expectedRevision,
  }),
]);
const actionFor = (candidate: z.infer<typeof invitationCandidate>) =>
  candidate.change.mutation === 'CREATE' ? principalCreateAction : participantAction;
function responseReview(value: Review, runtime: LocalConfig) {
  return {
    reviewToken: sealBffPayload(value, runtime.cookieKey, 'invitation-review'),
    review: invitationReview.strip().parse(value),
  };
}
async function readOwner<T>(
  runtime: LocalConfig,
  session: IdentitySession,
  path: string,
  schema: z.ZodType<T>,
  request: NextRequest,
) {
  return ownerJson(
    await fetch(`${runtime.publicApiUrl}/v1/identity/${path}`, {
      cache: 'no-store',
      headers: publicHeaders(runtime, session),
    }).catch(() => undefined),
    schema,
    request,
  );
}
async function readback(
  runtime: LocalConfig,
  session: IdentitySession,
  invitationId: string,
  request: NextRequest,
) {
  const record = await readOwner(
    runtime,
    session,
    `invitations/${invitationId}`,
    invitationReadback,
    request,
  );
  if (isResponse(record)) return record;
  return record.effect.invitationId === invitationId &&
    record.effect.participantId === session.participantId &&
    record.effect.privacyDomainId === session.privacyDomainId
    ? record
    : safeProblem('PC-INTEGRATION-5001', request);
}
async function proposal(
  runtime: LocalConfig,
  session: IdentitySession,
  candidateDigest: string,
  binding: { approvalRequestId: string } | { expectedRevision: string; makerPrincipalId: string },
  request: NextRequest,
) {
  const result = await readOwner(
    runtime,
    session,
    `invitation-proposals/${encodeURIComponent(candidateDigest)}?${new URLSearchParams(binding)}`,
    invitationProposal,
    request,
  );
  if (isResponse(result)) return result;
  return result.candidateDigest === candidateDigest &&
    digest(result.candidate) === candidateDigest &&
    result.catalogOperationId === invitationOperation(result.candidate) &&
    result.resourceId === result.candidate.change.invitationId &&
    result.expectedRevision === result.candidate.expectedRevision &&
    (!('approvalRequestId' in binding) ||
      result.approval?.approvalRequestId === binding.approvalRequestId)
    ? result
    : safeProblem('PC-INTEGRATION-5001', request);
}
export async function mutateInvitationWorkbench(request: NextRequest) {
  const runtime = await localRuntimeConfig().catch(() => undefined);
  if (!runtime) return safeProblem('PC-AUTH-0005', request);
  if (!sameOrigin(request) || !hasJsonContentType(request.headers.get('content-type')))
    return safeProblem('PC-AUTH-0002', request);
  const session = await authenticated(request, runtime),
    actor = session && actorBinding(session);
  if (!session || !actor) return safeProblem('PC-AUTH-0005', request);
  const parsed = commands.safeParse(parsePublicCommand(await request.text()));
  if (!parsed.success) return safeProblem('PC-DATA-6004', request);
  const input = parsed.data,
    origin = request.headers.get('origin')!;
  if (input.command === 'PREPARE') {
    if (
      input.expectedSessionId !== actor.sessionId ||
      input.checkerPrincipalId === actor.principalId
    )
      return safeProblem('PC-AUTH-0005', request);
    const change = invitationChange.parse({
      ...input.input,
      invitationId: input.input.invitationId ?? responseIds().requestId,
    });
    let expectedRevision = '0';
    if (change.mutation !== 'CREATE') {
      const record = await readback(runtime, session, change.invitationId, request);
      if (isResponse(record)) return record;
      expectedRevision = record.effect.revision;
    }
    const action = change.mutation === 'CREATE' ? principalCreateAction : participantAction;
    const token = await csrf(runtime, session, action.id);
    if (!token) return safeProblem('PC-AUTH-0005', request);
    const idempotencyKey = `invitation-${randomUUID()}`;
    const staged = await ownerJson(
      await fetch(`${runtime.publicApiUrl}/v1/identity/invitations/prepare`, {
        method: 'POST',
        cache: 'no-store',
        headers: {
          ...publicHeaders(runtime, session),
          'Content-Type': 'application/json',
          'X-CSRF-Token': token,
          'Idempotency-Key': idempotencyKey,
          'X-OpenPC-Aggregate-Version': expectedRevision,
          'OpenPC-Action-Intent-Digest': action.digest,
        },
        body: JSON.stringify(change),
      }).catch(() => undefined),
      invitationPrepared,
      request,
    );
    if (isResponse(staged)) return staged;
    if (
      staged.resourceId !== change.invitationId ||
      digest(staged.candidate.change) !== digest(change) ||
      staged.candidate.expectedRevision !== expectedRevision ||
      staged.expectedRevision !== expectedRevision ||
      staged.candidateDigest !== digest(staged.candidate) ||
      staged.catalogOperationId !== invitationOperation(staged.candidate) ||
      staged.actionIntentId !== action.id
    )
      return safeProblem('PC-INTEGRATION-5001', request);
    const value: Review = {
      candidate: staged.candidate,
      candidateDigest: staged.candidateDigest,
      resourceId: change.invitationId,
      expectedRevision,
      actor,
      origin,
      checkerPrincipalId: input.checkerPrincipalId,
      reason: input.reason,
      expiresAt: new Date(Date.now() + 900_000).toISOString(),
      idempotencyKey,
      stepUp: {
        actionIntentId: action.id,
        actionIntentDigest: action.digest,
        resourceId: change.invitationId,
        resourceDigest: staged.candidateDigest,
      },
    };
    return NextResponse.json(responseReview(value, runtime), { headers: noStore });
  }
  if (input.command === 'APPROVE') {
    const current = await approval(runtime, session, input.approvalRequestId, request);
    if (isResponse(current)) return current;
    const detail = await proposal(
      runtime,
      session,
      input.candidateDigest,
      { approvalRequestId: input.approvalRequestId },
      request,
    );
    if (isResponse(detail)) return detail;
    if (
      current.candidateDigest !== input.candidateDigest ||
      current.revision !== input.expectedRevision ||
      current.makerSubjectRef !== `urn:openpc:resource:${detail.makerPrincipalId}` ||
      current.checkerSubjectRef !== `urn:openpc:resource:${actor.principalId}` ||
      Date.parse(detail.expiresAt) <= Date.now()
    )
      return safeProblem('PC-DATA-6007', request);
    return approveGovernanceRequest(runtime, session, input.approvalRequestId, request);
  }
  const opened = fullReview.safeParse(
    openBffPayload(input.reviewToken, runtime.cookieKey, 'invitation-review'),
  );
  if (
    !opened.success ||
    digest(opened.data.actor) !== digest(actor) ||
    opened.data.origin !== origin
  )
    return safeProblem('PC-AUTH-0005', request);
  const value = opened.data;
  const detail = await proposal(
    runtime,
    session,
    value.candidateDigest,
    input.command === 'COMMIT'
      ? { approvalRequestId: input.approvalRequestId }
      : { expectedRevision: value.expectedRevision, makerPrincipalId: actor.principalId },
    request,
  );
  if (isResponse(detail)) return detail;
  if (
    detail.resourceId !== value.resourceId ||
    detail.catalogOperationId !== invitationOperation(value.candidate) ||
    detail.expectedRevision !== value.expectedRevision ||
    digest(detail.candidate) !== digest(value.candidate)
  )
    return safeProblem('PC-DATA-6007', request);
  if (input.command === 'SUBMIT') {
    if (Date.parse(value.expiresAt) <= Date.now()) return safeProblem('PC-DATA-6007', request);
    const token = await csrf(runtime, session, approvalCreateAction.id);
    if (!token) return safeProblem('PC-AUTH-0005', request);
    const operation = await ownerJson(
      await fetch(`${runtime.publicApiUrl}/api/v1/approval-requests`, {
        method: 'POST',
        cache: 'no-store',
        headers: {
          ...publicHeaders(runtime, session),
          'Content-Type': 'application/json',
          'X-CSRF-Token': token,
          'Idempotency-Key': `${value.idempotencyKey}-request`,
          'X-OpenPC-Action-Intent-Digest': approvalCreateAction.digest,
          'OpenPC-Action-Intent-Digest': approvalCreateAction.digest,
        },
        body: JSON.stringify({
          actionIntentId: approvalCreateAction.id,
          actionIntentDigest: approvalCreateAction.digest,
          candidateDigest: value.candidateDigest,
          makerSubjectRef: `urn:openpc:resource:${actor.principalId}`,
          checkerSubjectRef: `urn:openpc:resource:${value.checkerPrincipalId}`,
          reason: value.reason,
        }),
      }).catch(() => undefined),
      publicOperationSchema,
      request,
    );
    if (isResponse(operation)) return operation;
    const current = await approval(runtime, session, operation.resourceRef.slice(-36), request);
    if (isResponse(current)) return current;
    if (
      current.candidateDigest !== value.candidateDigest ||
      current.makerSubjectRef !== `urn:openpc:resource:${actor.principalId}` ||
      current.checkerSubjectRef !== `urn:openpc:resource:${value.checkerPrincipalId}`
    )
      return safeProblem('PC-INTEGRATION-5001', request);
    return NextResponse.json(
      { ...responseReview(value, runtime), approval: current },
      { status: 202, headers: noStore },
    );
  }
  const current = await approval(runtime, session, input.approvalRequestId, request);
  if (isResponse(current)) return current;
  if (
    current.state !== 'APPROVED' ||
    current.candidateDigest !== value.candidateDigest ||
    current.makerSubjectRef !== `urn:openpc:resource:${actor.principalId}` ||
    current.checkerSubjectRef !== `urn:openpc:resource:${value.checkerPrincipalId}` ||
    detail.approval?.reason !== value.reason
  )
    return safeProblem('PC-DATA-6007', request);
  async function reconcile(after: z.infer<typeof invitationProposal>) {
    if (after.state !== 'CONSUMED' || !after.operationId) return undefined;
    const record = await readback(runtime!, session!, value.resourceId, request);
    return isResponse(record)
      ? record
      : NextResponse.json(
          { truthState: 'SUCCESS', operationId: after.operationId, readback: record },
          { headers: noStore },
        );
  }
  const prior = await reconcile(detail);
  if (prior) return prior;
  if (Date.parse(value.expiresAt) <= Date.now()) return safeProblem('PC-DATA-6007', request);
  const action = actionFor(value.candidate),
    token = await csrf(runtime, session, action.id);
  if (!token) return safeProblem('PC-AUTH-0005', request);
  const response = await fetch(`${runtime.publicApiUrl}/v1/identity/invitations/mutate`, {
    method: 'POST',
    cache: 'no-store',
    headers: {
      ...publicHeaders(runtime, session),
      'Content-Type': 'application/json',
      'X-CSRF-Token': token,
      'Idempotency-Key': value.idempotencyKey,
      'X-OpenPC-Aggregate-Version': value.expectedRevision,
      'OpenPC-Action-Intent-Digest': action.digest,
      'X-OpenPC-Approval-Request-ID': input.approvalRequestId,
    },
    body: JSON.stringify(value.candidate),
  }).catch(() => undefined);
  const after = await proposal(
    runtime,
    session,
    value.candidateDigest,
    { approvalRequestId: input.approvalRequestId },
    request,
  );
  if (!isResponse(after)) {
    const committed = await reconcile(after);
    if (committed) return committed;
  }
  return ownerFailure(response, request);
}
export async function readInvitationWorkbench(request: NextRequest) {
  const runtime = await localRuntimeConfig().catch(() => undefined);
  if (!runtime) return safeProblem('PC-AUTH-0005', request);
  const session = await authenticated(request, runtime),
    actor = session && actorBinding(session);
  if (!session || !actor) return safeProblem('PC-AUTH-0005', request);
  const query = z
    .strictObject({
      invitationId: z.uuidv7().optional(),
      lane: z.enum(['maker', 'checker']).default('checker'),
      cursor: z.string().max(8192).optional(),
    })
    .safeParse(Object.fromEntries(request.nextUrl.searchParams));
  if (
    !query.success ||
    [...request.nextUrl.searchParams].length !== new Set(request.nextUrl.searchParams.keys()).size
  )
    return safeProblem('PC-DATA-6004', request);
  if (query.data.invitationId) {
    const record = await readback(runtime, session, query.data.invitationId, request);
    return isResponse(record)
      ? record
      : NextResponse.json({ actor, ...record }, { headers: noStore });
  }
  const params = new URLSearchParams({
    limit: '50',
    sort: '-updatedAt',
    filter: `${query.data.lane === 'maker' ? 'makerSubjectRef' : 'checkerSubjectRef'}:eq:urn:openpc:resource:${actor.principalId}`,
    ...(query.data.cursor ? { cursor: query.data.cursor } : {}),
  });
  const page = await ownerJson(
    await fetch(`${runtime.publicApiUrl}/api/v1/approval-requests?${params}`, {
      cache: 'no-store',
      headers: publicHeaders(runtime, session),
    }).catch(() => undefined),
    approvalPageSchema,
    request,
  );
  if (isResponse(page)) return page;
  const approvals = [];
  for (const item of page.items) {
    if (
      (query.data.lane === 'maker' ? item.makerSubjectRef : item.checkerSubjectRef) !==
      `urn:openpc:resource:${actor.principalId}`
    )
      return safeProblem('PC-INTEGRATION-5001', request);
    const detail = await proposal(
      runtime,
      session,
      item.candidateDigest,
      { approvalRequestId: item.approvalRequestId.slice(-36) },
      request,
    );
    if (isResponse(detail)) {
      if ([403, 404].includes(detail.status)) continue;
      return detail;
    }
    if (item.makerSubjectRef !== `urn:openpc:resource:${detail.makerPrincipalId}`)
      return safeProblem('PC-INTEGRATION-5001', request);
    approvals.push({
      ...item,
      proposal: detail,
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
    });
  }
  return NextResponse.json({ actor, approvals, nextCursor: page.nextCursor }, { headers: noStore });
}
