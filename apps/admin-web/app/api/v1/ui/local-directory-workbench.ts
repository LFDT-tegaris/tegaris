import { randomUUID } from 'node:crypto';
import { NextResponse, type NextRequest } from 'next/server';
import { z } from 'zod';
import {
  directoryChange,
  directoryReadback,
  directoryProposal,
  directoryReview,
  directoryOperation,
  directoryResource,
  directoryCandidate,
  directoryReconcile,
  directoryProfiles,
  directoryMemberReadback,
  directoryPrepared,
} from '../../../../lib/directory-workflow';
import { recoveryActor } from '../../../../lib/recovery-workflow';
import {
  directoryGroupChange,
  directoryGroupReadback,
} from '../../../../lib/directory-group-workflow';
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
  safeProblem,
  responseIds,
  sameOrigin,
  sealBffPayload,
  type IdentitySession,
  type LocalConfig,
} from './local-runtime';
const noStore = { 'Cache-Control': 'no-store' };
const uuid = z.uuid();
const fullReview = directoryReview
  .extend({ actor: recoveryActor, origin: z.url(), idempotencyKey: z.string().min(16).max(128) })
  .strict();
type Review = z.infer<typeof fullReview>;
const sealed = fullReview
  .omit({ candidate: true })
  .extend({
    candidate: directoryCandidate.optional(),
    group: z.literal(true).optional(),
  })
  .strict();
const preview = z.union([
  ...directoryChange.options.map((option) =>
    option.shape.mutation.value === 'CREATE'
      ? option.extend({ connectorId: z.uuid().optional() })
      : option,
  ),
  directoryReconcile,
  directoryGroupChange,
]);
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
    candidateDigest: directoryReview.shape.candidateDigest,
    expectedRevision: directoryReview.shape.expectedRevision,
    group: z.boolean().optional(),
  }),
]);
function responseReview(value: Review, runtime: LocalConfig) {
  // Large member lists stay at their authoritative proposal owner. The sealed
  // browser token binds a reference and cannot substitute a different candidate.
  const { candidate, ...reference } = value;
  return {
    reviewToken: sealBffPayload(
      'observation' in candidate ? { ...reference, group: true } : value,
      runtime.cookieKey,
      'directory-review',
    ),
    review: directoryReview.strip().parse(value),
  };
}
async function readOwner<T>(
  runtime: LocalConfig,
  session: IdentitySession,
  path: string,
  schema: z.ZodType<T>,
  request: NextRequest,
  group = false,
) {
  return ownerJson(
    await fetch(
      `${runtime.publicApiUrl}/v1/${group ? `participants/${session.participantId}` : 'identity'}/${path}`,
      {
        cache: 'no-store',
        headers: {
          ...publicHeaders(runtime, session),
          ...(group ? { Authorization: `Bearer ${session.sessionToken}` } : {}),
        },
      },
    ).catch(() => undefined),
    schema,
    request,
  );
}
async function readProjectedGroup(
  runtime: LocalConfig,
  session: IdentitySession,
  groupId: string,
  request: NextRequest,
  cursor?: string,
) {
  const value = await readOwner(
    runtime,
    session,
    `directory-groups/${groupId}${cursor ? `?cursor=${encodeURIComponent(cursor)}` : ''}`,
    directoryGroupReadback,
    request,
    true,
  );
  if (isResponse(value)) return value;
  return value.group.effect.groupId === groupId &&
    value.group.effect.participantId === session.participantId
    ? value
    : safeProblem('PC-INTEGRATION-5001', request);
}
function readResult(
  runtime: LocalConfig,
  session: IdentitySession,
  value: Review,
  request: NextRequest,
) {
  return 'observation' in value.candidate
    ? readProjectedGroup(runtime, session, value.resourceId, request)
    : readDirectory(runtime, session, value.resourceId, request);
}
async function readDirectory(
  runtime: LocalConfig,
  session: IdentitySession,
  connectorId: string,
  request: NextRequest,
) {
  const value = await readOwner(
    runtime,
    session,
    `directory-connectors/${connectorId}`,
    directoryReadback,
    request,
  );
  if (isResponse(value)) return value;
  return value.effect.connectorId === connectorId &&
    value.effect.participantId === session.participantId
    ? value
    : safeProblem('PC-INTEGRATION-5001', request);
}
async function proposal(
  runtime: LocalConfig,
  session: IdentitySession,
  candidateDigest: string,
  binding: { approvalRequestId: string } | { expectedRevision: string; makerPrincipalId: string },
  request: NextRequest,
  group?: boolean,
): Promise<z.infer<typeof directoryProposal> | NextResponse> {
  let value = await readOwner(
    runtime,
    session,
    `${group ? 'group' : 'directory'}-proposals/${encodeURIComponent(candidateDigest)}?${new URLSearchParams(binding)}`,
    directoryProposal,
    request,
    group,
  );
  if (group === undefined && isResponse(value) && [403, 404].includes(value.status)) {
    const projected = await proposal(runtime, session, candidateDigest, binding, request, true);
    if (!isResponse(projected)) value = projected;
  }
  if (isResponse(value)) return value;
  return value.candidateDigest === candidateDigest &&
    digest(value.candidate) === candidateDigest &&
    value.catalogOperationId === directoryOperation(value.candidate) &&
    value.resourceId === directoryResource(value.candidate) &&
    (!('approvalRequestId' in binding) ||
      value.approval?.approvalRequestId === binding.approvalRequestId)
    ? value
    : safeProblem('PC-INTEGRATION-5001', request);
}

function actionFor(candidate: z.infer<typeof directoryCandidate>) {
  return !('change' in candidate) && !('observation' in candidate) && candidate.mode === 'PROVISION'
    ? principalCreateAction
    : participantAction;
}
async function write(
  runtime: LocalConfig,
  session: IdentitySession,
  value: Review,
  approvalId: string,
) {
  const action = actionFor(value.candidate),
    token = await csrf(runtime, session, action.id);
  if (!token) return undefined;
  return fetch(
    `${runtime.publicApiUrl}/v1/${'observation' in value.candidate ? `participants/${session.participantId}/directory-groups` : `identity/${'change' in value.candidate ? 'directory-connectors' : 'directory-reconciliation'}`}/mutate`,
    {
      method: 'POST',
      cache: 'no-store',
      headers: {
        ...publicHeaders(runtime, session),
        ...('observation' in value.candidate
          ? { Authorization: `Bearer ${session.sessionToken}` }
          : {}),
        'Content-Type': 'application/json',
        'X-CSRF-Token': token,
        'Idempotency-Key': value.idempotencyKey,
        'X-OpenPC-Aggregate-Version': value.expectedRevision,
        'OpenPC-Action-Intent-Digest': action.digest,
        'X-OpenPC-Approval-Request-ID': approvalId,
      },
      body: JSON.stringify(value.candidate),
    },
  ).catch(() => undefined);
}
async function completed(
  runtime: LocalConfig,
  session: IdentitySession,
  value: Review,
  detail: z.infer<typeof directoryProposal>,
  request: NextRequest,
) {
  if (detail.state !== 'CONSUMED' || !detail.operationId) return undefined;
  const readback = await readResult(runtime, session, value, request);
  return NextResponse.json(
    {
      truthState: 'SUCCESS',
      operationId: detail.operationId,
      ...(isResponse(readback)
        ? { requiresReauthentication: await authenticationUnavailable(readback) }
        : { readback }),
    },
    { headers: noStore },
  );
}
async function authenticationUnavailable(response: Response) {
  const problem = z.object({ code: z.string() }).safeParse(
    await response
      .clone()
      .json()
      .catch(() => undefined),
  );
  return problem.success && problem.data.code === 'PC-AUTH-0005';
}
export async function mutateDirectoryWorkbench(request: NextRequest) {
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
    const change =
      'groupId' in input.input
        ? directoryGroupChange.parse(input.input)
        : 'mode' in input.input
          ? directoryReconcile.parse(input.input)
          : directoryChange.parse({
              ...input.input,
              connectorId: input.input.connectorId ?? responseIds().requestId,
            });
    const resourceId = 'groupId' in change ? change.groupId : change.connectorId;
    let expectedRevision = '0',
      freshnessSeconds = 300;
    if ('groupId' in change) {
      const current = await readProjectedGroup(runtime, session, resourceId, request);
      if (isResponse(current)) return current;
      expectedRevision = current.group.effect.revision;
    } else if (!('mutation' in change) || change.mutation !== 'CREATE') {
      const current = await readDirectory(runtime, session, resourceId, request);
      if (isResponse(current)) return current;
      expectedRevision = current.effect.revision;
      freshnessSeconds = Math.min(300, current.effect.externalGroupFreshnessSeconds);
    }
    const action =
      'mode' in change && change.mode === 'PROVISION' ? principalCreateAction : participantAction;
    const token = await csrf(runtime, session, action.id);
    if (!token) return safeProblem('PC-AUTH-0005', request);
    const idempotencyKey = `directory-${randomUUID()}`;
    const staged = await ownerJson(
      await fetch(
        `${runtime.publicApiUrl}/v1/${'groupId' in change ? `participants/${session.participantId}/directory-groups` : `identity/${'mode' in change ? 'directory-reconciliation' : 'directory-connectors'}`}/prepare`,
        {
          method: 'POST',
          cache: 'no-store',
          headers: {
            ...publicHeaders(runtime, session),
            ...('groupId' in change ? { Authorization: `Bearer ${session.sessionToken}` } : {}),
            'Content-Type': 'application/json',
            'X-CSRF-Token': token,
            'Idempotency-Key': idempotencyKey,
            'X-OpenPC-Aggregate-Version': expectedRevision,
            'OpenPC-Action-Intent-Digest': action.digest,
          },
          body: JSON.stringify(change),
        },
      ).catch(() => undefined),
      directoryPrepared,
      request,
    );
    if (isResponse(staged)) return staged;
    if (
      staged.resourceId !== resourceId ||
      directoryResource(staged.candidate) !== resourceId ||
      staged.expectedRevision !== expectedRevision ||
      staged.candidate.expectedRevision !== expectedRevision ||
      digest(staged.candidate) !== staged.candidateDigest ||
      staged.catalogOperationId !== directoryOperation(staged.candidate) ||
      actionFor(staged.candidate).id !== action.id
    )
      return safeProblem('PC-INTEGRATION-5001', request);
    const expiresAt =
      'observation' in staged.candidate
        ? Math.min(
            Date.parse(staged.candidate.observation.freshUntil),
            Date.parse(staged.candidate.observation.observedAt) + 300_000,
          )
        : 'change' in staged.candidate
          ? Date.now() + 15 * 60 * 1000
          : Date.parse(staged.candidate.observedAt) + freshnessSeconds * 1000;
    const value: Review = {
      candidate: staged.candidate,
      resourceId,
      expectedRevision,
      candidateDigest: staged.candidateDigest,
      actor,
      origin,
      checkerPrincipalId: input.checkerPrincipalId,
      reason: input.reason,
      expiresAt: new Date(expiresAt).toISOString(),
      idempotencyKey,
      stepUp: {
        actionIntentId: action.id,
        actionIntentDigest: action.digest,
        resourceId,
        resourceDigest: staged.candidateDigest,
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
      input.group,
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
    openBffPayload(input.reviewToken, runtime.cookieKey, 'directory-review'),
  );
  if (
    !opened.success ||
    digest(opened.data.actor) !== digest(actor) ||
    opened.data.origin !== origin
  )
    return safeProblem('PC-AUTH-0005', request);
  const loadedProposal =
    opened.data.candidate === undefined && opened.data.group === true
      ? await proposal(
          runtime,
          session,
          opened.data.candidateDigest,
          input.command === 'COMMIT'
            ? { approvalRequestId: input.approvalRequestId }
            : {
                expectedRevision: opened.data.expectedRevision,
                makerPrincipalId: actor.principalId,
              },
          request,
          true,
        )
      : undefined;
  if (loadedProposal && isResponse(loadedProposal)) return loadedProposal;
  const hydrated = fullReview.safeParse({
    ...Object.fromEntries(Object.entries(opened.data).filter(([key]) => key !== 'group')),
    candidate: opened.data.candidate ?? loadedProposal?.candidate,
  });
  if (!hydrated.success) return safeProblem('PC-AUTH-0005', request);
  const value = hydrated.data;
  if (input.command === 'SUBMIT') {
    if (Date.parse(value.expiresAt) <= Date.now()) return safeProblem('PC-DATA-6007', request);
    const detail =
      loadedProposal ??
      (await proposal(
        runtime,
        session,
        value.candidateDigest,
        { expectedRevision: value.expectedRevision, makerPrincipalId: actor.principalId },
        request,
        'observation' in value.candidate,
      ));
    if (isResponse(detail)) return detail;
    if (
      detail.resourceId !== value.resourceId ||
      detail.catalogOperationId !== directoryOperation(value.candidate)
    )
      return safeProblem('PC-DATA-6007', request);
    const token = await csrf(runtime, session, approvalCreateAction.id);
    if (!token) return safeProblem('PC-AUTH-0005', request);
    const response = await fetch(`${runtime.publicApiUrl}/api/v1/approval-requests`, {
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
  const detail =
    loadedProposal ??
    (await proposal(
      runtime,
      session,
      value.candidateDigest,
      { approvalRequestId: input.approvalRequestId },
      request,
      'observation' in value.candidate,
    ));
  if (isResponse(detail)) return detail;
  if (
    current.state !== 'APPROVED' ||
    current.candidateDigest !== value.candidateDigest ||
    current.makerSubjectRef !== `urn:openpc:resource:${actor.principalId}` ||
    current.checkerSubjectRef !== `urn:openpc:resource:${value.checkerPrincipalId}` ||
    detail.expectedRevision !== value.expectedRevision ||
    detail.approval?.reason !== value.reason ||
    detail.resourceId !== value.resourceId ||
    detail.catalogOperationId !== directoryOperation(value.candidate)
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
    'observation' in value.candidate,
  );
  if (!isResponse(after)) {
    const saved = await completed(runtime, session, value, after, request);
    if (saved) return saved;
  }
  if (result?.ok) {
    const response = await result.json().catch(() => undefined);
    if ('observation' in value.candidate) {
      const record = directoryGroupReadback.safeParse(
        response && { group: response.group, mapping: response.mapping },
      );
      if (
        record.success &&
        record.data.group.effect.groupId === value.resourceId &&
        record.data.group.effect.participantId === session.participantId &&
        record.data.group.effect.operationId &&
        record.data.group.effect.revision === String(BigInt(value.expectedRevision) + 1n)
      )
        return NextResponse.json(
          {
            truthState: 'SUCCESS',
            operationId: record.data.group.effect.operationId,
            readback: record.data,
            requiresReauthentication: isResponse(after) && (await authenticationUnavailable(after)),
          },
          { headers: noStore },
        );
    }
    const record = directoryReadback.safeParse(
      response?.effect?.connector ? { effect: response.effect.connector } : response,
    );
    if (
      record.success &&
      record.data.effect.connectorId === value.resourceId &&
      record.data.effect.participantId === session.participantId &&
      record.data.effect.operationId &&
      record.data.effect.revision === String(BigInt(value.expectedRevision) + 1n)
    )
      return NextResponse.json(
        {
          truthState: 'SUCCESS',
          operationId: record.data.effect.operationId,
          readback: record.data,
          requiresReauthentication: isResponse(after) && (await authenticationUnavailable(after)),
        },
        { headers: noStore },
      );
  }
  if (!result || result.ok)
    return NextResponse.json({ truthState: 'WRITE_AMBIGUITY' }, { status: 202, headers: noStore });
  return ownerFailure(result, request);
}

export async function readDirectoryWorkbench(request: NextRequest) {
  const runtime = await localRuntimeConfig().catch(() => undefined);
  if (!runtime) return safeProblem('PC-AUTH-0005', request);
  const session = await authenticated(request, runtime),
    actor = session && actorBinding(session);
  if (!session || !actor) return safeProblem('PC-AUTH-0005', request);
  const query = z
    .strictObject({
      lane: z.enum(['maker', 'checker']).default('checker'),
      cursor: z.string().max(8192).optional(),
      connectorId: uuid.optional(),
      groupId: uuid.optional(),
      externalId: z.string().min(1).max(512).optional(),
    })
    .safeParse(Object.fromEntries(request.nextUrl.searchParams));
  if (
    !query.success ||
    [...request.nextUrl.searchParams.keys()].length !==
      new Set(request.nextUrl.searchParams.keys()).size
  )
    return safeProblem('PC-DATA-6004', request);
  if (query.data.groupId) {
    if (query.data.connectorId || query.data.externalId)
      return safeProblem('PC-DATA-6004', request);
    const result = await readProjectedGroup(
      runtime,
      session,
      query.data.groupId,
      request,
      query.data.cursor,
    );
    return isResponse(result) ? result : NextResponse.json(result, { headers: noStore });
  }
  if (query.data.externalId) {
    if (!query.data.connectorId) return safeProblem('PC-DATA-6004', request);
    const member = await readOwner(
      runtime,
      session,
      `directory-connectors/${query.data.connectorId}/members/${encodeURIComponent(query.data.externalId)}`,
      directoryMemberReadback,
      request,
    );
    if (isResponse(member)) return member;
    if (
      member.binding.participantId !== session.participantId ||
      member.binding.connectorId !== query.data.connectorId ||
      member.binding.externalId !== query.data.externalId ||
      member.binding.principalId !== member.membership.principalId
    )
      return safeProblem('PC-INTEGRATION-5001', request);
    return NextResponse.json(member, { headers: noStore });
  }
  if (query.data.connectorId) {
    const result = await readDirectory(runtime, session, query.data.connectorId, request);
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
  const registered = await readOwner(
    runtime,
    session,
    'directory-profiles',
    directoryProfiles,
    request,
  );
  if (isResponse(registered)) return registered;
  return NextResponse.json(
    { actor, profiles: registered.profiles, approvals, nextCursor: page.nextCursor },
    { headers: noStore },
  );
}
