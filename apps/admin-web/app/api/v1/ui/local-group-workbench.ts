import { randomUUID } from 'node:crypto';
import { NextResponse, type NextRequest } from 'next/server';
import { z } from 'zod';
import {
  groupChange,
  groupReadback,
  groupProposal,
  groupReview,
  groupOperationIds,
  groupCataloguePage,
} from '../../../../lib/group-workflow';
import { recoveryActor } from '../../../../lib/recovery-workflow';
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
  publicHeaders,
  publicOperationSchema,
} from './local-governance-api';
import {
  authenticated,
  hasJsonContentType,
  localRuntimeConfig,
  openBffPayload,
  parsePublicCommand,
  safeProblem,
  responseIds,
  sameOrigin,
  sealBffPayload,
  type IdentitySession,
  type LocalConfig,
} from './local-runtime';
const noStore = { 'Cache-Control': 'no-store' };
const uuid = z.uuid();
const sealed = groupReview
  .extend({ actor: recoveryActor, origin: z.url(), idempotencyKey: z.string().min(16).max(128) })
  .strict();
type Review = z.infer<typeof sealed>;
const preview = z.union(
  groupChange.options.map((option) =>
    option.shape.mutation.value === 'CREATE'
      ? option.extend({ groupId: z.uuid().optional() })
      : option,
  ),
);
const commands = z.discriminatedUnion('command', [
  z.strictObject({
    command: z.literal('PREPARE'),
    input: preview,
    reason: z.string().trim().min(10).max(1024),
    checkerPrincipalId: uuid,
    expectedSessionId: uuid,
  }),
  z.strictObject({ command: z.literal('SUBMIT'), reviewToken: z.string().min(80).max(65536) }),
  z.strictObject({
    command: z.literal('COMMIT'),
    reviewToken: z.string().min(80).max(65536),
    approvalRequestId: uuid,
  }),
  z.strictObject({
    command: z.literal('APPROVE'),
    approvalRequestId: uuid,
    candidateDigest: groupReview.shape.candidateDigest,
    expectedRevision: groupReview.shape.expectedRevision,
  }),
]);
function responseReview(value: Review, runtime: LocalConfig) {
  return {
    reviewToken: sealBffPayload(value, runtime.cookieKey, 'group-review'),
    review: groupReview.strip().parse(value),
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
    await fetch(`${runtime.publicApiUrl}/v1/participants/${session.participantId}/${path}`, {
      cache: 'no-store',
      headers: {
        ...publicHeaders(runtime, session),
        Authorization: `Bearer ${session.sessionToken}`,
      },
    }).catch(() => undefined),
    schema,
    request,
  );
}
async function readGroup(
  runtime: LocalConfig,
  session: IdentitySession,
  groupId: string,
  request: NextRequest,
  cursor?: string,
) {
  const value = await readOwner(
    runtime,
    session,
    `groups/${groupId}${cursor ? `?cursor=${encodeURIComponent(cursor)}` : ''}`,
    groupReadback,
    request,
  );
  if (isResponse(value)) return value;
  return value.effect.groupId === groupId && value.effect.participantId === session.participantId
    ? value
    : safeProblem('PC-INTEGRATION-5001', request);
}
async function proposal(
  runtime: LocalConfig,
  session: IdentitySession,
  candidateDigest: string,
  binding: { approvalRequestId: string } | { expectedRevision: string; makerPrincipalId: string },
  request: NextRequest,
) {
  const value = await readOwner(
    runtime,
    session,
    `group-proposals/${encodeURIComponent(candidateDigest)}?${new URLSearchParams(binding)}`,
    groupProposal,
    request,
  );
  if (isResponse(value)) return value;
  return value.candidateDigest === candidateDigest &&
    digest(value.candidate) === candidateDigest &&
    value.catalogOperationId === groupOperationIds[value.candidate.mutation] &&
    value.resourceId === value.candidate.groupId &&
    (!('approvalRequestId' in binding) ||
      value.approval?.approvalRequestId === binding.approvalRequestId)
    ? value
    : safeProblem('PC-INTEGRATION-5001', request);
}

async function write(
  runtime: LocalConfig,
  session: IdentitySession,
  value: Review,
  approvalId?: string,
  preparedCsrfToken?: string,
) {
  const token = preparedCsrfToken ?? (await csrf(runtime, session, participantAction.id));
  if (!token) return undefined;
  const path = approvalId ? 'groups/mutate' : 'groups/prepare';
  return fetch(`${runtime.publicApiUrl}/v1/participants/${session.participantId}/${path}`, {
    method: 'POST',
    cache: 'no-store',
    headers: {
      ...publicHeaders(runtime, session),
      'Authorization': `Bearer ${session.sessionToken}`,
      'Content-Type': 'application/json',
      'X-CSRF-Token': token,
      'Idempotency-Key': value.idempotencyKey,
      'X-OpenPC-Aggregate-Version': value.expectedRevision,
      'OpenPC-Action-Intent-Digest': participantAction.digest,
      ...(approvalId ? { 'X-OpenPC-Approval-Request-ID': approvalId } : {}),
    },
    body: JSON.stringify(
      groupChange.parse(
        Object.fromEntries(
          Object.entries(value.candidate).filter(([key]) => key !== 'expectedRevision'),
        ),
      ),
    ),
  }).catch(() => undefined);
}
async function completed(
  runtime: LocalConfig,
  session: IdentitySession,
  value: Review,
  detail: z.infer<typeof groupProposal>,
  request: NextRequest,
) {
  if (detail.state !== 'CONSUMED' || !detail.operationId) return undefined;
  const readback = await readGroup(runtime, session, value.resourceId, request);
  if (isResponse(readback)) return readback;
  return NextResponse.json(
    { truthState: 'SUCCESS', operationId: detail.operationId, readback },
    { headers: noStore },
  );
}
export async function mutateGroupWorkbench(request: NextRequest) {
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
    const change = groupChange.parse({
      ...input.input,
      groupId: input.input.groupId ?? responseIds().requestId,
    });
    let expectedRevision = '0';
    const resourceId = change.groupId;
    if (change.mutation !== 'CREATE') {
      const current = await readGroup(runtime, session, resourceId, request);
      if (isResponse(current)) return current;
      if (current.effect.state !== 'ACTIVE') return safeProblem('PC-DATA-6007', request);
      expectedRevision = current.effect.revision;
    }
    const candidate = { ...change, expectedRevision };
    const value: Review = {
      mutation: change.mutation,
      candidate,
      resourceId,
      expectedRevision,
      candidateDigest: digest(candidate),
      actor,
      origin,
      checkerPrincipalId: input.checkerPrincipalId,
      reason: input.reason,
      expiresAt: new Date(Date.now() + 15 * 60 * 1000).toISOString(),
      idempotencyKey: `group-${randomUUID()}`,
      stepUp: {
        actionIntentId: participantAction.id,
        actionIntentDigest: participantAction.digest,
        resourceId,
        resourceDigest: digest(candidate),
      },
    };
    return NextResponse.json(responseReview(value, runtime), { headers: noStore });
  }
  if (input.command === 'APPROVE') {
    const current = await approval(runtime, session, input.approvalRequestId, request);
    if (isResponse(current)) return current;
    if (
      current.candidateDigest !== input.candidateDigest ||
      current.revision !== input.expectedRevision
    )
      return safeProblem('PC-DATA-6007', request);
    const detail = await proposal(
      runtime,
      session,
      input.candidateDigest,
      { approvalRequestId: input.approvalRequestId },
      request,
    );
    if (isResponse(detail)) return detail;
    if (
      current.makerSubjectRef !== `urn:openpc:resource:${detail.makerPrincipalId}` ||
      Date.parse(detail.expiresAt) <= Date.now()
    )
      return safeProblem('PC-DATA-6007', request);
    return approveGovernanceRequest(runtime, session, input.approvalRequestId, request);
  }
  const opened = sealed.safeParse(
    openBffPayload(input.reviewToken, runtime.cookieKey, 'group-review'),
  );
  if (
    !opened.success ||
    digest(opened.data.actor) !== digest(actor) ||
    opened.data.origin !== origin
  )
    return safeProblem('PC-AUTH-0005', request);
  const value = opened.data;
  if (input.command === 'SUBMIT') {
    if (Date.parse(value.expiresAt) <= Date.now()) return safeProblem('PC-DATA-6007', request);
    const verifiedAt = session.stepUpVerifiedAt ? Date.parse(session.stepUpVerifiedAt) : Number.NaN;
    if (
      !Number.isFinite(verifiedAt) ||
      verifiedAt > Date.now() ||
      Date.now() - verifiedAt >= 5 * 60 * 1000
    )
      return safeProblem('PC-AUTH-0005', request);
    const [participantToken, approvalToken] = await Promise.all([
      csrf(runtime, session, participantAction.id),
      csrf(runtime, session, approvalCreateAction.id),
    ]);
    if (!participantToken || !approvalToken) return safeProblem('PC-AUTH-0005', request);
    const staged = await write(runtime, session, value, undefined, participantToken);
    if (staged?.status !== 202) return ownerFailure(staged, request);
    const detail = await proposal(
      runtime,
      session,
      value.candidateDigest,
      { expectedRevision: value.expectedRevision, makerPrincipalId: actor.principalId },
      request,
    );
    if (isResponse(detail)) return detail;
    if (
      detail.resourceId !== value.resourceId ||
      detail.catalogOperationId !== groupOperationIds[value.mutation]
    )
      return safeProblem('PC-DATA-6007', request);
    const response = await fetch(`${runtime.publicApiUrl}/api/v1/approval-requests`, {
      method: 'POST',
      cache: 'no-store',
      headers: {
        ...publicHeaders(runtime, session),
        'Content-Type': 'application/json',
        'X-CSRF-Token': approvalToken,
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
    }).catch(() => undefined);
    const operation = await ownerJson(response, publicOperationSchema, request);
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
  const detail = await proposal(
    runtime,
    session,
    value.candidateDigest,
    { approvalRequestId: input.approvalRequestId },
    request,
  );
  if (isResponse(detail)) return detail;
  if (
    current.state !== 'APPROVED' ||
    current.candidateDigest !== value.candidateDigest ||
    current.makerSubjectRef !== `urn:openpc:resource:${actor.principalId}` ||
    current.checkerSubjectRef !== `urn:openpc:resource:${value.checkerPrincipalId}` ||
    detail.expectedRevision !== value.expectedRevision ||
    detail.approval?.reason !== value.reason ||
    detail.resourceId !== value.resourceId ||
    detail.catalogOperationId !== groupOperationIds[value.mutation]
  )
    return safeProblem('PC-DATA-6007', request);
  const prior = await completed(runtime, session, value, detail, request);
  if (prior) return prior;
  if (Date.parse(value.expiresAt) <= Date.now()) return safeProblem('PC-DATA-6007', request);
  const result = await write(runtime, session, value, input.approvalRequestId);
  const after = await proposal(
    runtime,
    session,
    value.candidateDigest,
    { approvalRequestId: input.approvalRequestId },
    request,
  );
  if (!isResponse(after)) {
    const saved = await completed(runtime, session, value, after, request);
    if (saved) return saved;
  }
  if (!result || result.ok)
    return NextResponse.json({ truthState: 'WRITE_AMBIGUITY' }, { status: 202, headers: noStore });
  return ownerFailure(result, request);
}

export async function readGroupWorkbench(request: NextRequest) {
  const runtime = await localRuntimeConfig().catch(() => undefined);
  if (!runtime) return safeProblem('PC-AUTH-0005', request);
  const session = await authenticated(request, runtime),
    actor = session && actorBinding(session);
  if (!session || !actor) return safeProblem('PC-AUTH-0005', request);
  const query = z
    .strictObject({
      lane: z.enum(['maker', 'checker']).default('checker'),
      cursor: z.string().max(8192).optional(),
      groupId: uuid.optional(),
      memberCursor: uuid.optional(),
      resumeApprovalRequestId: uuid.optional(),
      candidateDigest: groupReview.shape.candidateDigest.optional(),
    })
    .safeParse(Object.fromEntries(request.nextUrl.searchParams));
  if (
    !query.success ||
    [...request.nextUrl.searchParams.keys()].length !==
      new Set(request.nextUrl.searchParams.keys()).size ||
    !!query.data.resumeApprovalRequestId !== !!query.data.candidateDigest ||
    (query.data.resumeApprovalRequestId !== undefined &&
      (query.data.groupId !== undefined ||
        query.data.memberCursor !== undefined ||
        query.data.cursor !== undefined))
  )
    return safeProblem('PC-DATA-6004', request);
  if (query.data.resumeApprovalRequestId && query.data.candidateDigest) {
    const current = await approval(runtime, session, query.data.resumeApprovalRequestId, request);
    if (isResponse(current)) return current;
    const detail = await proposal(
      runtime,
      session,
      query.data.candidateDigest,
      { approvalRequestId: query.data.resumeApprovalRequestId },
      request,
    );
    if (isResponse(detail)) return detail;
    if (
      current.candidateDigest !== query.data.candidateDigest ||
      current.makerSubjectRef !== `urn:openpc:resource:${actor.principalId}` ||
      detail.makerPrincipalId !== actor.principalId
    )
      return safeProblem('PC-AUTH-0005', request);
    const readback =
      detail.state === 'CONSUMED' && detail.operationId
        ? await readGroup(runtime, session, detail.resourceId, request)
        : undefined;
    if (isResponse(readback)) return readback;
    return NextResponse.json(
      {
        candidateDigest: detail.candidateDigest,
        state: detail.state,
        operationId: detail.operationId,
        ...(readback ? { readback } : {}),
      },
      { headers: noStore },
    );
  }
  if (query.data.groupId) {
    const result = await readGroup(
      runtime,
      session,
      query.data.groupId,
      request,
      query.data.memberCursor,
    );
    return isResponse(result) ? result : NextResponse.json(result, { headers: noStore });
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

export async function readGroupCatalogue(request: NextRequest) {
  const runtime = await localRuntimeConfig().catch(() => undefined);
  if (!runtime) return safeProblem('PC-AUTH-0005', request);
  const session = await authenticated(request, runtime),
    actor = session && actorBinding(session);
  if (!session || !actor) return safeProblem('PC-AUTH-0005', request);
  if (
    [...request.nextUrl.searchParams.keys()].length !==
    new Set(request.nextUrl.searchParams.keys()).size
  )
    return safeProblem('PC-DATA-6004', request);
  const query = z
    .strictObject({
      search: z.string().trim().max(160).default(''),
      state: z.enum(['ALL', 'ACTIVE', 'RETIRED']).default('ALL'),
      after: uuid.optional(),
      limit: z.coerce.number().int().min(1).max(50).default(25),
    })
    .safeParse(Object.fromEntries(request.nextUrl.searchParams));
  if (!query.success) return safeProblem('PC-DATA-6004', request);
  const parameters = new URLSearchParams({
    search: query.data.search,
    state: query.data.state,
    limit: String(query.data.limit),
    ...(query.data.after ? { after: query.data.after } : {}),
  });
  const page = await readOwner(
    runtime,
    session,
    `groups?${parameters}`,
    groupCataloguePage.extend({ items: groupCataloguePage.shape.items.max(query.data.limit) }),
    request,
  );
  if (isResponse(page)) return page;
  if (
    page.authorizedEmpty !== (page.items.length === 0) ||
    (page.nextCursor !== null &&
      (page.items.length !== query.data.limit ||
        page.nextCursor !== page.items.at(-1)?.effect.groupId)) ||
    page.items.some(
      ({ effect }, index) =>
        effect.participantId !== session.participantId ||
        (query.data.state !== 'ALL' && effect.state !== query.data.state) ||
        !effect.groupName.toLowerCase().includes(query.data.search.toLowerCase()) ||
        effect.groupId <= (page.items[index - 1]?.effect.groupId ?? query.data.after ?? ''),
    )
  )
    return safeProblem('PC-INTEGRATION-5001', request);
  const current = await authenticated(request, runtime);
  const binding = (value: IdentitySession) => {
    const { sessionToken: _, stepUpVerifiedAt: __, ...identity } = value;
    void _;
    void __;
    return digest(identity);
  };
  if (!current || !actorBinding(current) || binding(current) !== binding(session))
    return safeProblem('PC-AUTH-0005', request);
  return NextResponse.json({ ...page, actor }, { headers: noStore });
}
