import { NextResponse, type NextRequest } from 'next/server';
import { z } from 'zod';
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
  publicHeaders,
  publicOperationSchema,
  uuidSchema,
} from './local-governance-api';
import {
  authenticated,
  hasJsonContentType,
  localRuntimeConfig,
  parsePublicCommand,
  localOwnerFetch,
  safeProblem,
  sameOrigin,
} from './local-runtime';
import {
  actorBinding,
  commandSchema,
  noStore,
  openReview,
  operations,
  responseReview,
} from './local-recovery-model';
import {
  caseReadback,
  qualificationReadback,
  readProposal,
  writeOwner,
} from './local-recovery-owner';
import { preview } from './local-recovery-preview';
export async function mutateRecoveryWorkbench(request: NextRequest) {
  const runtime = await localRuntimeConfig().catch(() => undefined);
  if (!runtime) return safeProblem('PC-AUTH-0005', request);
  if (!sameOrigin(request) || !hasJsonContentType(request.headers.get('content-type')))
    return safeProblem('PC-AUTH-0002', request);
  const session = await authenticated(request, runtime);
  if (!session || !actorBinding(session)) return safeProblem('PC-AUTH-0005', request);
  const command = commandSchema.safeParse(parsePublicCommand(await request.text()));
  if (!command.success) return safeProblem('PC-DATA-6004', request);
  const input = command.data;
  if (input.command === 'PREVIEW') return preview(runtime, session, input.input, request);
  if (input.command === 'APPROVE') {
    const current = await approval(runtime, session, input.approvalRequestId, request);
    if (isResponse(current)) return current;
    if (
      current.candidateDigest !== input.candidateDigest ||
      current.revision !== input.expectedRevision
    )
      return safeProblem('PC-DATA-6007', request);
    const detail = await readProposal(
      runtime,
      session,
      current.candidateDigest,
      { approvalRequestId: input.approvalRequestId },
      request,
    );
    if (isResponse(detail)) return detail;
    if (
      Date.parse(detail.expiresAt) <= Date.now() ||
      current.makerSubjectRef !== `urn:openpc:resource:${detail.makerPrincipalId}`
    )
      return safeProblem('PC-DATA-6007', request);
    return approveGovernanceRequest(runtime, session, input.approvalRequestId, request);
  }
  const value = openReview(input.reviewToken, runtime, session);
  if (!value) return safeProblem('PC-DATA-6007', request);
  if (input.command === 'SUBMIT') {
    const staged = await writeOwner(
      runtime,
      session,
      value,
      '00000000-0000-7000-8000-000000000000',
    );
    const failure =
      staged &&
      (await staged
        .clone()
        .json()
        .catch(() => undefined));
    if (staged?.status !== 409 || failure?.error?.code !== 'PC-IDENTITY-1005')
      return ownerFailure(staged, request);
    const detail = await readProposal(
      runtime,
      session,
      value.candidateDigest,
      { expectedRevision: value.expectedRevision, makerPrincipalId: session.principalId! },
      request,
    );
    if (isResponse(detail)) return detail;
    if (
      detail.catalogOperationId !== operations[value.mutation] ||
      detail.resourceId !== value.resourceId ||
      detail.makerPrincipalId !== session.principalId ||
      detail.expectedRevision !== value.expectedRevision
    )
      return safeProblem('PC-DATA-6007', request);
    const token = await csrf(runtime, session, approvalCreateAction.id);
    if (!token) return safeProblem('PC-AUTH-0005', request);
    const response = await localOwnerFetch(`${runtime.publicApiUrl}/api/v1/approval-requests`, {
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
        makerSubjectRef: `urn:openpc:resource:${session.principalId}`,
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
      current.makerSubjectRef !== `urn:openpc:resource:${session.principalId}` ||
      current.checkerSubjectRef !== `urn:openpc:resource:${value.checkerPrincipalId}`
    )
      return safeProblem('PC-INTEGRATION-5001', request);
    return NextResponse.json(
      { ...responseReview(value, runtime), operation, approval: current },
      { status: 202, headers: noStore },
    );
  }
  const current = await approval(runtime, session, input.approvalRequestId, request);
  if (isResponse(current)) return current;
  const detail = await readProposal(
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
    current.makerSubjectRef !== `urn:openpc:resource:${session.principalId}` ||
    current.checkerSubjectRef !== `urn:openpc:resource:${value.checkerPrincipalId}` ||
    detail.expectedRevision !== value.expectedRevision ||
    detail.makerPrincipalId !== session.principalId ||
    detail.catalogOperationId !== operations[value.mutation] ||
    detail.resourceId !== value.resourceId ||
    detail.approval?.reason !== value.reason
  )
    return safeProblem('PC-DATA-6007', request);
  const response = await writeOwner(runtime, session, value, input.approvalRequestId);
  if (!response)
    return NextResponse.json(
      {
        truthState: 'WRITE_AMBIGUITY',
        resourceId: value.resourceId,
        reconciliation: 'READ_AUTHORITATIVE_EFFECT',
      },
      { status: 202, headers: noStore },
    );
  if (!response.ok) return ownerFailure(response, request);
  const readback =
    value.mutation === 'QUALIFY' || value.mutation === 'REVOKE'
      ? await qualificationReadback(runtime, session, value.resourceId, request)
      : await caseReadback(runtime, session, value.resourceId, request);
  if (isResponse(readback)) return readback;
  return NextResponse.json(
    { truthState: 'SUCCESS', resourceId: value.resourceId, readback },
    { status: 202, headers: noStore },
  );
}
export async function readRecoveryWorkbench(request: NextRequest) {
  const runtime = await localRuntimeConfig().catch(() => undefined);
  if (!runtime) return safeProblem('PC-AUTH-0005', request);
  const session = await authenticated(request, runtime);
  const actor = session && actorBinding(session);
  if (!session || !actor) return safeProblem('PC-AUTH-0005', request);
  const query = z
    .strictObject({
      lane: z.enum(['maker', 'checker']).default('checker'),
      cursor: z.string().min(1).max(8192).optional(),
      recoveryId: uuidSchema.optional(),
      principalId: uuidSchema.optional(),
      approvalRequestId: uuidSchema.optional(),
    })
    .safeParse(Object.fromEntries(request.nextUrl.searchParams));
  if (
    !query.success ||
    [...request.nextUrl.searchParams.keys()].length !==
      new Set(request.nextUrl.searchParams.keys()).size
  )
    return safeProblem('PC-DATA-6004', request);
  const filter = `${query.data.lane === 'maker' ? 'makerSubjectRef' : 'checkerSubjectRef'}:eq:urn:openpc:resource:${session.principalId}`;
  const params = new URLSearchParams({
    limit: '50',
    sort: '-updatedAt',
    filter,
    ...(query.data.cursor ? { cursor: query.data.cursor } : {}),
  });
  // Qualified executors cannot enumerate general approvals. Individual saved
  // requests still pass through the public owner's exact resource authorization.
  let approvalListAccess: 'AVAILABLE' | 'DENIED' | 'NOT_REQUESTED' = 'AVAILABLE';
  let page;
  if (query.data.approvalRequestId) {
    const item = await approval(runtime, session, query.data.approvalRequestId, request);
    if (isResponse(item)) return item;
    approvalListAccess = 'NOT_REQUESTED';
    page = { items: [item], nextCursor: null, completeness: 'UNKNOWN' as const };
  } else {
    const response = await localOwnerFetch(
      `${runtime.publicApiUrl}/api/v1/approval-requests?${params}`,
      {
        cache: 'no-store',
        headers: publicHeaders(runtime, session),
      },
    ).catch(() => undefined);
    if (response?.status === 403) {
      approvalListAccess = 'DENIED';
      page = { items: [], nextCursor: null, completeness: 'UNKNOWN' as const };
    } else page = await ownerJson(response, approvalPageSchema, request);
  }
  if (isResponse(page)) return page;
  const approvals = [];
  for (const item of page.items) {
    if (
      (query.data.lane === 'maker' ? item.makerSubjectRef : item.checkerSubjectRef) !==
      `urn:openpc:resource:${session.principalId}`
    )
      return safeProblem('PC-INTEGRATION-5001', request);
    const detail = await readProposal(
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
    const recoveryContext = ['CUSTODY', 'COMPLETE', 'POST_REVIEW'].includes(detail.mutation)
      ? await caseReadback(runtime, session, detail.resourceId, request)
      : undefined;
    if (isResponse(recoveryContext)) return recoveryContext;
    approvals.push({
      ...item,
      ...(recoveryContext ? { recoveryContext } : {}),
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
  const recovery = query.data.recoveryId
    ? await caseReadback(runtime, session, query.data.recoveryId, request)
    : undefined;
  if (isResponse(recovery)) return recovery;
  const qualification = query.data.principalId
    ? await qualificationReadback(runtime, session, query.data.principalId, request)
    : undefined;
  if (isResponse(qualification)) return qualification;
  return NextResponse.json(
    {
      actor,
      approvals,
      approvalListAccess,
      recovery,
      qualification,
      nextCursor: page.nextCursor,
      completeness: page.completeness,
    },
    { headers: noStore },
  );
}
