import { randomUUID } from 'node:crypto';
import { NextResponse, type NextRequest } from 'next/server';
import { z } from 'zod';
import {
  credentialInventory,
  credentialProposal,
  credentialReview,
} from '../../../../lib/credential-workflow';
import { enrollmentReadbackSchema } from '../../../../lib/authenticator-enrollment';
import { recoveryActor } from '../../../../lib/recovery-workflow';
import { registrationOptionsSchema, registrationResponseSchema } from './local-bootstrap-runtime';
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
  identityCsrf,
  identityOwnerHeaders,
  localRuntimeConfig,
  openBffPayload,
  parsePublicCommand,
  safeProblem,
  sameOrigin,
  sealBffPayload,
  type IdentitySession,
  type LocalConfig,
} from './local-runtime';

const noStore = { 'Cache-Control': 'no-store' };
const uuid = z.uuid();
const sealed = credentialReview
  .extend({
    actor: recoveryActor,
    origin: z.url(),
    response: registrationResponseSchema,
    idempotencyKey: z.string().min(16).max(128),
  })
  .strict();
type Review = z.infer<typeof sealed>;
const commands = z.discriminatedUnion('command', [
  z.strictObject({
    command: z.literal('OPTIONS'),
    replacedCredentialId: uuid,
    hardwareAttestation: z.boolean(),
    expectedSessionId: uuid,
  }),
  z.strictObject({
    command: z.literal('PREPARE'),
    enrollmentId: uuid,
    response: registrationResponseSchema,
    reason: z.string().trim().min(10).max(1024),
    checkerPrincipalId: uuid,
    expectedSessionId: uuid,
  }),
  z.strictObject({ command: z.literal('SUBMIT'), reviewToken: z.string().min(80).max(131072) }),
  z.strictObject({
    command: z.literal('COMMIT'),
    reviewToken: z.string().min(80).max(131072),
    approvalRequestId: uuid,
  }),
  z.strictObject({
    command: z.literal('APPROVE'),
    approvalRequestId: uuid,
    candidateDigest: credentialReview.shape.candidateDigest,
    expectedRevision: credentialReview.shape.expectedRevision,
  }),
]);
function responseReview(value: Review, runtime: LocalConfig) {
  return {
    reviewToken: sealBffPayload(value, runtime.cookieKey, 'credential-review'),
    review: credentialReview.strip().parse(value),
  };
}
async function identityWrite(
  runtime: LocalConfig,
  session: IdentitySession,
  origin: string,
  path: string,
  body: unknown,
  action: string,
  headers: Record<string, string> = {},
) {
  const token = await identityCsrf(runtime, session, action);
  if (!token) return undefined;
  return fetch(`${runtime.identityUrl}/v1/identity/webauthn/replacement/${path}`, {
    method: 'POST',
    cache: 'no-store',
    headers: {
      ...identityOwnerHeaders(runtime, session, origin),
      'X-CSRF-Token': token,
      ...headers,
    },
    body: JSON.stringify(body),
  }).catch(() => undefined);
}
async function enrollment(
  runtime: LocalConfig,
  session: IdentitySession,
  id: string,
  request: NextRequest,
) {
  const value = await ownerJson(
    await fetch(`${runtime.identityUrl}/v1/identity/webauthn/enrollments/${id}`, {
      cache: 'no-store',
      headers: identityOwnerHeaders(runtime, session),
    }).catch(() => undefined),
    enrollmentReadbackSchema,
    request,
  );
  if (isResponse(value)) return value;
  return value.enrollmentId === id &&
    value.principalId === session.principalId &&
    value.participantId === session.participantId
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
  const value = await ownerJson(
    await fetch(
      `${runtime.publicApiUrl}/v1/identity/webauthn-proposals/${encodeURIComponent(candidateDigest)}?${new URLSearchParams(binding)}`,
      {
        cache: 'no-store',
        headers: publicHeaders(runtime, session),
      },
    ).catch(() => undefined),
    credentialProposal,
    request,
  );
  if (isResponse(value)) return value;
  return value.candidateDigest === candidateDigest &&
    digest(value.candidate) === candidateDigest &&
    value.resourceId === value.candidate.replacedCredentialId &&
    (!('approvalRequestId' in binding) ||
      value.approval?.approvalRequestId === binding.approvalRequestId)
    ? value
    : safeProblem('PC-INTEGRATION-5001', request);
}
function write(runtime: LocalConfig, session: IdentitySession, value: Review, approvalId?: string) {
  return identityWrite(
    runtime,
    session,
    value.origin,
    'complete',
    {
      enrollmentId: value.enrollmentId,
      response: value.response,
    },
    participantAction.id,
    {
      'Idempotency-Key': value.idempotencyKey,
      'X-OpenPC-Aggregate-Version': value.expectedRevision,
      'OpenPC-Action-Intent-Digest': participantAction.digest,
      ...(approvalId ? { 'X-OpenPC-Approval-Request-ID': approvalId } : {}),
    },
  );
}

export async function mutateCredentialWorkbench(request: NextRequest) {
  const runtime = await localRuntimeConfig().catch(() => undefined);
  if (!runtime) return safeProblem('PC-AUTH-0005', request);
  if (!sameOrigin(request) || !hasJsonContentType(request.headers.get('content-type')))
    return safeProblem('PC-AUTH-0002', request);
  const session = await authenticated(request, runtime);
  const actor = session && actorBinding(session);
  if (!session || !actor) return safeProblem('PC-AUTH-0005', request);
  const parsed = commands.safeParse(parsePublicCommand(await request.text()));
  if (!parsed.success) return safeProblem('PC-DATA-6004', request);
  const input = parsed.data,
    origin = request.headers.get('origin')!;
  if ('expectedSessionId' in input && input.expectedSessionId !== session.sessionId)
    return safeProblem('PC-AUTH-0005', request);
  if (input.command === 'OPTIONS') {
    const result = await ownerJson(
      await identityWrite(
        runtime,
        session,
        origin,
        'options',
        {
          replacedCredentialId: input.replacedCredentialId,
          hardwareAttestation: input.hardwareAttestation,
        },
        'ACT-IDENTITY_UPDATE_STEP_UP-V1',
      ),
      registrationOptionsSchema.extend({ replacedCredentialId: uuid }),
      request,
    );
    if (isResponse(result)) return result;
    if (
      result.replacedCredentialId !== input.replacedCredentialId ||
      result.publicKey.rp.id !== new URL(origin).hostname
    )
      return safeProblem('PC-INTEGRATION-5001', request);
    return NextResponse.json(result, { status: 201, headers: noStore });
  }
  if (input.command === 'PREPARE') {
    if (input.checkerPrincipalId === session.principalId)
      return safeProblem('PC-AUTH-0005', request);
    const stored = await enrollment(runtime, session, input.enrollmentId, request);
    if (isResponse(stored)) return stored;
    if (stored.state !== 'PENDING') return safeProblem('PC-DATA-6007', request);
    const prepared = await ownerJson(
      await identityWrite(
        runtime,
        session,
        origin,
        'complete',
        {
          enrollmentId: input.enrollmentId,
          response: input.response,
        },
        participantAction.id,
      ),
      credentialReview
        .pick({
          enrollmentId: true,
          replacedCredentialId: true,
          candidateDigest: true,
          expectedRevision: true,
        })
        .extend({ state: z.literal('PREPARED') }),
      request,
    );
    if (isResponse(prepared)) return prepared;
    if (prepared.enrollmentId !== input.enrollmentId)
      return safeProblem('PC-INTEGRATION-5001', request);
    const value: Review = {
      enrollmentId: prepared.enrollmentId,
      replacedCredentialId: prepared.replacedCredentialId,
      candidateDigest: prepared.candidateDigest,
      expectedRevision: prepared.expectedRevision,
      actor,
      origin,
      response: input.response,
      reason: input.reason,
      checkerPrincipalId: input.checkerPrincipalId,
      expiresAt: stored.expiresAt,
      idempotencyKey: `webauthn-${randomUUID()}`,
      stepUp: {
        actionIntentId: participantAction.id,
        actionIntentDigest: participantAction.digest,
        resourceId: prepared.replacedCredentialId,
        resourceDigest: prepared.candidateDigest,
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
    openBffPayload(input.reviewToken, runtime.cookieKey, 'credential-review'),
  );
  if (
    !opened.success ||
    digest(opened.data.actor) !== digest(actor) ||
    opened.data.origin !== origin
  )
    return safeProblem('PC-AUTH-0005', request);
  const value = opened.data;
  const stored = await enrollment(runtime, session, value.enrollmentId, request);
  if (isResponse(stored)) return stored;
  if (stored.state === 'COMPLETED')
    return NextResponse.json({ truthState: 'SUCCESS', readback: stored }, { headers: noStore });
  if (stored.state !== 'PENDING' || Date.parse(value.expiresAt) <= Date.now())
    return safeProblem('PC-DATA-6007', request);
  if (input.command === 'SUBMIT') {
    const staged = await write(runtime, session, value);
    if (staged?.status !== 202) return ownerFailure(staged, request);
    const detail = await proposal(
      runtime,
      session,
      value.candidateDigest,
      {
        expectedRevision: value.expectedRevision,
        makerPrincipalId: session.principalId!,
      },
      request,
    );
    if (isResponse(detail)) return detail;
    if (
      detail.resourceId !== value.replacedCredentialId ||
      detail.candidate.enrollmentId !== value.enrollmentId
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
    detail.candidate.enrollmentId !== value.enrollmentId
  )
    return safeProblem('PC-DATA-6007', request);
  const result = await write(runtime, session, value, input.approvalRequestId);
  const readback = await enrollment(runtime, session, value.enrollmentId, request);
  if (!isResponse(readback) && readback.state === 'COMPLETED')
    return NextResponse.json({ truthState: 'SUCCESS', readback }, { headers: noStore });
  if (!result || result.ok)
    return NextResponse.json({ truthState: 'WRITE_AMBIGUITY' }, { status: 202, headers: noStore });
  return ownerFailure(result, request);
}

export async function readCredentialWorkbench(request: NextRequest) {
  const runtime = await localRuntimeConfig().catch(() => undefined);
  if (!runtime) return safeProblem('PC-AUTH-0005', request);
  const session = await authenticated(request, runtime),
    actor = session && actorBinding(session);
  if (!session || !actor) return safeProblem('PC-AUTH-0005', request);
  const query = z
    .strictObject({
      lane: z.enum(['maker', 'checker']).default('checker'),
      cursor: z.string().max(8192).optional(),
      credentialCursor: uuid.optional(),
    })
    .safeParse(Object.fromEntries(request.nextUrl.searchParams));
  if (
    !query.success ||
    [...request.nextUrl.searchParams.keys()].length !==
      new Set(request.nextUrl.searchParams.keys()).size
  )
    return safeProblem('PC-DATA-6004', request);
  const inventory = await ownerJson(
    await fetch(
      `${runtime.publicApiUrl}/v1/identity/webauthn/credentials${query.data.credentialCursor ? `?cursor=${query.data.credentialCursor}` : ''}`,
      {
        cache: 'no-store',
        headers: publicHeaders(runtime, session),
      },
    ).catch(() => undefined),
    credentialInventory,
    request,
  );
  if (isResponse(inventory)) return inventory;
  if (
    inventory.principalId !== actor.principalId ||
    inventory.participantId !== actor.participantId
  )
    return safeProblem('PC-INTEGRATION-5001', request);
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
  return NextResponse.json(
    { actor, inventory, approvals, nextCursor: page.nextCursor },
    { headers: noStore },
  );
}
