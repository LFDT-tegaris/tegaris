import { NextResponse, type NextRequest } from 'next/server';
import { z } from 'zod';
import {
  approval,
  approvalCreateAction,
  approvalDecisionAction,
  approvalPageSchema,
  approveGovernanceRequest,
  checkerPrincipalId,
  contextAdmitted,
  csrf,
  digest,
  digestSchema,
  isResponse,
  ownerFailure,
  ownerJson,
  participantAction,
  principalCreateAction,
  participantId,
  privacyDomainId,
  publicHeaders,
  publicOperationSchema,
  timestampSchema,
  uuidSchema,
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
const revision = z.string().regex(/^(?:0|[1-9][0-9]*)$/u);
const principal = z
  .object({
    principalId: uuidSchema,
    participantId: z.literal(participantId),
    displayLabel: z.string().min(1).max(160),
    kind: z.enum(['USER', 'WALLET', 'WORKLOAD', 'PLATFORM_OPERATOR']),
    state: z.enum(['PROVISIONED', 'ACTIVE', 'SUSPENDED', 'REVOKED', 'OFFBOARDED']),
  })
  .strict();
const record = principal
  .extend({
    identityEpoch: revision,
    revision,
    identitySubjectId: uuidSchema.optional(),
    membershipId: uuidSchema.optional(),
  })
  .strict();
const readback = z.object({ effect: record, operationId: uuidSchema.nullable() }).strict();
const subjectReadback = z
  .object({
    effect: z.object({ identitySubjectId: uuidSchema, createdAt: timestampSchema }).strict(),
    membership: record,
    membershipOperationId: uuidSchema.nullable(),
  })
  .strict();
const membershipReadback = z
  .object({
    effect: z
      .object({
        membershipId: uuidSchema,
        identitySubjectId: uuidSchema,
        participantId: z.literal(participantId),
        state: principal.shape.state,
        revision,
        membershipEpoch: revision,
      })
      .strict(),
    operationId: uuidSchema.nullable(),
  })
  .strict();
const mutation = z.enum(['PROVISION', 'ACTIVATE', 'SUSPEND', 'REMOVE']);
const proposal = z
  .object({
    candidateDigest: digestSchema,
    resourceId: uuidSchema,
    mutation,
    expectedRevision: revision,
    state: z.string(),
    expiresAt: timestampSchema,
    proposedPrincipal: principal,
  })
  .strict();
const reviewSchema = z
  .object({
    version: z.literal(1),
    issuedAt: z.number().int().nonnegative(),
    sessionId: uuidSchema,
    principalId: uuidSchema,
    contextEpoch: revision,
    mutation,
    expectedRevision: revision,
    reason: z.string().min(10).max(1024),
    proposedPrincipal: principal,
    candidateDigest: digestSchema,
    idempotencyKey: z.string().min(16).max(128),
  })
  .strict();
const previewSchema = z.discriminatedUnion('command', [
  z
    .object({
      command: z.literal('PREVIEW_PROVISION'),
      displayLabel: z.string().trim().min(1).max(160),
      kind: z.enum(['USER', 'WALLET', 'WORKLOAD']),
      reason: z.string().trim().min(10).max(1024),
    })
    .strict(),
  z
    .object({
      command: z.enum(['PREVIEW_ACTIVATE', 'PREVIEW_SUSPEND', 'PREVIEW_REMOVE']),
      principalId: uuidSchema,
      reason: z.string().trim().min(10).max(1024),
    })
    .strict(),
]);
const tokenSchema = z.discriminatedUnion('command', [
  z.object({ command: z.literal('SUBMIT'), reviewToken: z.string().min(80).max(65536) }).strict(),
  z
    .object({
      command: z.literal('COMMIT'),
      reviewToken: z.string().min(80).max(65536),
      approvalRequestId: uuidSchema,
    })
    .strict(),
]);
const approveSchema = z
  .object({
    command: z.literal('APPROVE'),
    approvalRequestId: uuidSchema,
    candidateDigest: digestSchema,
  })
  .strict();
type Review = z.infer<typeof reviewSchema>;
const actionFor = (value: Review) =>
  value.mutation === 'PROVISION' ? principalCreateAction : participantAction;
async function readOwner<T>(
  runtime: LocalConfig,
  session: IdentitySession,
  path: string,
  schema: z.ZodType<T>,
  request: NextRequest,
) {
  const response = await fetch(`${runtime.publicApiUrl}/v1/identity/${path}`, {
    cache: 'no-store',
    headers: publicHeaders(runtime, session),
  }).catch(() => undefined);
  return ownerJson(response, schema, request);
}
export async function readPrincipalCatalogue(request: NextRequest) {
  const runtime = await localRuntimeConfig().catch(() => undefined);
  if (!runtime) return safeProblem('PC-AUTH-0005', request);
  const session = await authenticated(request, runtime);
  if (!session || !contextAdmitted(session)) return safeProblem('PC-AUTH-0005', request);
  const keys = [...request.nextUrl.searchParams.keys()];
  if (keys.length !== new Set(keys).size) return safeProblem('PC-DATA-6004', request);
  const query = z
    .strictObject({
      search: z.string().trim().max(160).default(''),
      state: z.enum(['ALL', ...principal.shape.state.options]).default('ALL'),
      kind: z.enum(['ALL', ...principal.shape.kind.options]).default('ALL'),
      after: uuidSchema.optional(),
      limit: z.coerce.number().int().min(1).max(50).default(25),
    })
    .safeParse(Object.fromEntries(request.nextUrl.searchParams));
  if (!query.success) return safeProblem('PC-DATA-6004', request);
  const parameters = new URLSearchParams({
    search: query.data.search,
    state: query.data.state,
    kind: query.data.kind,
    limit: String(query.data.limit),
    ...(query.data.after ? { after: query.data.after } : {}),
  });
  const schema = z.strictObject({
    items: z
      .array(readback.extend({ effect: record.extend({ participantId: uuidSchema }) }))
      .max(query.data.limit),
    nextCursor: uuidSchema.nullable(),
    completeness: z.literal('COMPLETE'),
    authorizedEmpty: z.boolean(),
    observedAt: timestampSchema,
  });
  const page = await readOwner(runtime, session, `principals?${parameters}`, schema, request);
  if (isResponse(page)) return page;
  if (
    page.authorizedEmpty !== (page.items.length === 0) ||
    (page.nextCursor !== null &&
      (page.items.length !== query.data.limit ||
        page.nextCursor !== page.items.at(-1)?.effect.principalId)) ||
    page.items.some(
      ({ effect }, index) =>
        effect.participantId !== session.participantId ||
        (query.data.state !== 'ALL' && effect.state !== query.data.state) ||
        (query.data.kind !== 'ALL' && effect.kind !== query.data.kind) ||
        effect.principalId <= (page.items[index - 1]?.effect.principalId ?? query.data.after ?? ''),
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
  if (!current || !contextAdmitted(current) || binding(current) !== binding(session))
    return safeProblem('PC-AUTH-0005', request);
  return NextResponse.json(
    {
      ...page,
      actor: {
        sessionId: session.sessionId,
        principalId: session.principalId,
        participantId: session.participantId,
        privacyDomainId: session.privacyDomainId,
        contextEpoch: session.contextEpoch,
      },
    },
    { headers: noStore },
  );
}

function responseReview(value: Review, runtime: LocalConfig) {
  const action = actionFor(value);
  return {
    reviewToken: sealBffPayload(value, runtime.cookieKey, 'principal-review'),
    review: {
      mutation: value.mutation,
      proposedPrincipal: value.proposedPrincipal,
      reason: value.reason,
      expectedRevision: value.expectedRevision,
      candidateDigest: value.candidateDigest,
      stepUp: {
        actionIntentId: action.id,
        actionIntentDigest: action.digest,
        resourceId: value.proposedPrincipal.principalId,
        resourceDigest: value.candidateDigest,
      },
    },
  };
}
function openReview(token: string, runtime: LocalConfig, session: IdentitySession) {
  const parsed = reviewSchema.safeParse(
    openBffPayload(token, runtime.cookieKey, 'principal-review'),
  );
  if (
    !parsed.success ||
    parsed.data.issuedAt > Date.now() ||
    Date.now() - parsed.data.issuedAt >= 1800000 ||
    parsed.data.sessionId !== session.sessionId ||
    parsed.data.principalId !== session.principalId ||
    parsed.data.contextEpoch !== session.contextEpoch
  )
    return undefined;
  return parsed.data;
}
async function writeOwner(
  runtime: LocalConfig,
  session: IdentitySession,
  value: Review,
  approvalId: string,
) {
  const action = actionFor(value);
  const csrfToken = await csrf(runtime, session, action.id);
  if (!csrfToken) return undefined;
  const path =
    value.mutation === 'PROVISION'
      ? 'principals'
      : value.mutation === 'REMOVE'
        ? `memberships/${value.proposedPrincipal.principalId}/remove`
        : `principals/${value.proposedPrincipal.principalId}/${value.mutation.toLowerCase()}`;
  const body =
    value.mutation === 'PROVISION'
      ? {
          principalId: value.proposedPrincipal.principalId,
          displayLabel: value.proposedPrincipal.displayLabel,
          kind: value.proposedPrincipal.kind,
        }
      : {};
  return fetch(`${runtime.publicApiUrl}/v1/identity/${path}`, {
    method: 'POST',
    cache: 'no-store',
    headers: {
      ...publicHeaders(runtime, session),
      'Content-Type': 'application/json',
      'X-CSRF-Token': csrfToken,
      'Idempotency-Key': value.idempotencyKey,
      'X-OpenPC-Aggregate-Version': value.expectedRevision,
      'X-OpenPC-Approval-Request-ID': approvalId,
      'OpenPC-Action-Intent-Digest': action.digest,
    },
    body: JSON.stringify(body),
  }).catch(() => undefined);
}

async function readPrincipalWithIdentity(
  runtime: LocalConfig,
  session: IdentitySession,
  principalId: string,
  request: NextRequest,
) {
  const value = await readOwner(runtime, session, `principals/${principalId}`, readback, request);
  if (isResponse(value)) return value;
  const { identitySubjectId, membershipId } = value.effect;
  if (!identitySubjectId && !membershipId) return { ...value, humanIdentity: undefined };
  if (!identitySubjectId || membershipId !== principalId)
    return safeProblem('PC-INTEGRATION-5001', request);
  const subject = await readOwner(
    runtime,
    session,
    `identity-subjects/${identitySubjectId}`,
    subjectReadback,
    request,
  );
  if (isResponse(subject)) return subject;
  const membership = await readOwner(
    runtime,
    session,
    `memberships/${membershipId}`,
    membershipReadback,
    request,
  );
  if (isResponse(membership)) return membership;
  if (
    subject.effect.identitySubjectId !== identitySubjectId ||
    subject.membership.principalId !== principalId ||
    subject.membership.identitySubjectId !== identitySubjectId ||
    subject.membership.membershipId !== membershipId ||
    membership.effect.membershipId !== membershipId ||
    membership.effect.identitySubjectId !== identitySubjectId ||
    subject.membership.state !== value.effect.state ||
    membership.effect.state !== value.effect.state ||
    subject.membership.revision !== value.effect.revision ||
    membership.effect.revision !== value.effect.revision ||
    subject.membership.identityEpoch !== value.effect.identityEpoch ||
    membership.effect.membershipEpoch !== value.effect.identityEpoch ||
    subject.membershipOperationId !== value.operationId ||
    membership.operationId !== value.operationId
  )
    return safeProblem('PC-DATA-6007', request);
  return { ...value, humanIdentity: { ...subject.effect, ...membership.effect } };
}

export async function readPrincipalWorkbench(request: NextRequest) {
  const runtime = await localRuntimeConfig().catch(() => undefined);
  if (!runtime) return undefined;
  const session = await authenticated(request, runtime);
  if (!session || !contextAdmitted(session)) return safeProblem('PC-AUTH-0005', request);
  const cursor = request.nextUrl.searchParams.get('cursor');
  const principalId = request.nextUrl.searchParams.get('principalId');
  if (
    (cursor && !z.string().min(1).max(8192).safeParse(cursor).success) ||
    (principalId && !uuidSchema.safeParse(principalId).success)
  )
    return safeProblem('PC-DATA-6004', request);
  const filter = `${session.role === 'viewer' ? 'checkerSubjectRef' : 'makerSubjectRef'}:eq:urn:openpc:resource:${session.principalId}`;
  const response = await fetch(
    `${runtime.publicApiUrl}/api/v1/approval-requests?limit=50&sort=-updatedAt&filter=${encodeURIComponent(filter)}${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ''}`,
    { cache: 'no-store', headers: publicHeaders(runtime, session) },
  ).catch(() => undefined);
  const page = await ownerJson(response, approvalPageSchema, request);
  if (isResponse(page)) return page;
  const approvals = [];
  for (const item of page.items) {
    const detail = await readOwner(
      runtime,
      session,
      `principal-proposals/${encodeURIComponent(item.candidateDigest)}`,
      proposal,
      request,
    );
    if (isResponse(detail)) {
      if ([403, 404].includes(detail.status)) continue;
      return detail;
    }
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
  const effect = principalId
    ? await readPrincipalWithIdentity(runtime, session, principalId, request)
    : undefined;
  if (isResponse(effect)) return effect;
  return NextResponse.json(
    {
      actor: {
        role: session.role,
        sessionId: session.sessionId,
        principalId: session.principalId,
        participantId,
        privacyDomainId,
        contextEpoch: session.contextEpoch,
      },
      approvals,
      ...(effect ? { effect } : {}),
      nextCursor: page.nextCursor,
      completeness: page.completeness,
    },
    { headers: noStore },
  );
}

export async function mutatePrincipalWorkbench(request: NextRequest) {
  const runtime = await localRuntimeConfig().catch(() => undefined);
  if (!runtime) return safeProblem('PC-AUTH-0005', request);
  if (!sameOrigin(request) || !hasJsonContentType(request.headers.get('content-type')))
    return safeProblem('PC-AUTH-0002', request);
  const session = await authenticated(request, runtime);
  if (!session || !contextAdmitted(session)) return safeProblem('PC-AUTH-0005', request);
  const raw = parsePublicCommand(await request.text());
  const input = previewSchema.safeParse(raw);
  if (input.success) {
    if (session.role !== 'operator') return safeProblem('PC-AUTH-0005', request);
    const command = input.data;
    const old =
      command.command === 'PREVIEW_PROVISION'
        ? undefined
        : await readOwner(runtime, session, `principals/${command.principalId}`, readback, request);
    if (isResponse(old)) return old;
    if (
      old &&
      (old.effect.principalId === session.principalId ||
        (command.command === 'PREVIEW_REMOVE'
          ? !old.effect.membershipId ||
            !['PROVISIONED', 'ACTIVE', 'SUSPENDED'].includes(old.effect.state)
          : old.effect.state !==
            (command.command === 'PREVIEW_ACTIVATE' ? 'PROVISIONED' : 'ACTIVE')))
    )
      return safeProblem('PC-DATA-6007', request);
    const id = old?.effect.principalId ?? responseIds().requestId;
    const proposedPrincipal = principal.parse({
      principalId: id,
      participantId,
      displayLabel:
        command.command === 'PREVIEW_PROVISION' ? command.displayLabel : old!.effect.displayLabel,
      kind: command.command === 'PREVIEW_PROVISION' ? command.kind : old!.effect.kind,
      state:
        command.command === 'PREVIEW_PROVISION'
          ? 'PROVISIONED'
          : command.command === 'PREVIEW_ACTIVATE'
            ? 'ACTIVE'
            : command.command === 'PREVIEW_REMOVE'
              ? 'OFFBOARDED'
              : 'SUSPENDED',
    });
    const value = reviewSchema.parse({
      version: 1,
      issuedAt: Date.now(),
      sessionId: session.sessionId,
      principalId: session.principalId,
      contextEpoch: session.contextEpoch,
      reason: command.reason,
      mutation: command.command.slice(8),
      expectedRevision: old?.effect.revision ?? '0',
      proposedPrincipal,
      candidateDigest: digest(
        old
          ? { principalId: id, state: proposedPrincipal.state }
          : { ...proposedPrincipal, identityEpoch: '0' },
      ),
      idempotencyKey: `principal-workbench-${responseIds().requestId}`,
    });
    return NextResponse.json(responseReview(value, runtime), { status: 201, headers: noStore });
  }
  const approve = approveSchema.safeParse(raw);
  if (approve.success) {
    if (session.role !== 'viewer') return safeProblem('PC-AUTH-0005', request);
    const current = await approval(runtime, session, approve.data.approvalRequestId, request);
    if (isResponse(current)) return current;
    if (current.candidateDigest !== approve.data.candidateDigest)
      return safeProblem('PC-DATA-6007', request);
    const detail = await readOwner(
      runtime,
      session,
      `principal-proposals/${encodeURIComponent(current.candidateDigest)}`,
      proposal,
      request,
    );
    if (isResponse(detail)) return detail;
    if (Date.parse(detail.expiresAt) <= Date.now()) return safeProblem('PC-DATA-6007', request);
    return approveGovernanceRequest(runtime, session, approve.data.approvalRequestId, request);
  }
  const token = tokenSchema.safeParse(raw);
  if (!token.success) return safeProblem('PC-DATA-6004', request);
  if (session.role !== 'operator') return safeProblem('PC-AUTH-0005', request);
  const value = openReview(token.data.reviewToken, runtime, session);
  if (!value) return safeProblem('PC-DATA-6007', request);
  if (token.data.command === 'SUBMIT') {
    const staged = await writeOwner(
      runtime,
      session,
      value,
      '00000000-0000-7000-8000-000000000000',
    );
    if (staged?.status !== 409) return ownerFailure(staged, request);
    const detail = await readOwner(
      runtime,
      session,
      `principal-proposals/${encodeURIComponent(value.candidateDigest)}`,
      proposal,
      request,
    );
    if (isResponse(detail)) return detail;
    if (
      detail.expectedRevision !== value.expectedRevision ||
      digest(detail.proposedPrincipal) !== digest(value.proposedPrincipal)
    )
      return safeProblem('PC-DATA-6007', request);
    const csrfToken = await csrf(runtime, session, approvalCreateAction.id);
    if (!csrfToken) return safeProblem('PC-AUTH-0005', request);
    const response = await fetch(`${runtime.publicApiUrl}/api/v1/approval-requests`, {
      method: 'POST',
      cache: 'no-store',
      headers: {
        ...publicHeaders(runtime, session),
        'Content-Type': 'application/json',
        'X-CSRF-Token': csrfToken,
        'Idempotency-Key': `${value.idempotencyKey}-request`,
        'X-OpenPC-Action-Intent-Digest': approvalCreateAction.digest,
        'OpenPC-Action-Intent-Digest': approvalCreateAction.digest,
      },
      body: JSON.stringify({
        actionIntentId: approvalCreateAction.id,
        actionIntentDigest: approvalCreateAction.digest,
        candidateDigest: value.candidateDigest,
        makerSubjectRef: `urn:openpc:resource:${session.principalId}`,
        checkerSubjectRef: `urn:openpc:resource:${checkerPrincipalId}`,
        reason: value.reason,
      }),
    }).catch(() => undefined);
    const operation = await ownerJson(response, publicOperationSchema, request);
    if (isResponse(operation)) return operation;
    const current = await approval(runtime, session, operation.resourceRef.slice(-36), request);
    if (isResponse(current)) return current;
    if (current.candidateDigest !== value.candidateDigest)
      return safeProblem('PC-INTEGRATION-5001', request);
    return NextResponse.json(
      { ...responseReview(value, runtime), operation, approval: current },
      { status: 202, headers: noStore },
    );
  }
  const current = await approval(runtime, session, token.data.approvalRequestId, request);
  if (isResponse(current)) return current;
  if (
    current.state !== 'APPROVED' ||
    current.candidateDigest !== value.candidateDigest ||
    current.makerSubjectRef !== `urn:openpc:resource:${session.principalId}`
  )
    return safeProblem('PC-DATA-6007', request);
  const response = await writeOwner(runtime, session, value, token.data.approvalRequestId);
  if (!response)
    return NextResponse.json(
      {
        truthState: 'WRITE_AMBIGUITY',
        principalId: value.proposedPrincipal.principalId,
        reconciliation: 'READ_AUTHORITATIVE_EFFECT',
      },
      { status: 202, headers: noStore },
    );
  if (!response.ok) return ownerFailure(response, request);
  if (value.mutation === 'REMOVE') {
    const committed = await ownerJson(response, record, request);
    if (isResponse(committed)) return committed;
    if (
      committed.principalId !== value.proposedPrincipal.principalId ||
      committed.state !== 'OFFBOARDED'
    )
      return safeProblem('PC-INTEGRATION-5001', request);
    // The Participant epoch has advanced. Readback must use a fresh authenticated context.
    return NextResponse.json(
      {
        truthState: 'REAUTH_REQUIRED',
        principalId: committed.principalId,
        reconciliation: 'SIGN_IN_THEN_READ_AUTHORITATIVE_EFFECT',
      },
      { status: 202, headers: noStore },
    );
  }
  const effect = await readPrincipalWithIdentity(
    runtime,
    session,
    value.proposedPrincipal.principalId,
    request,
  );
  if (isResponse(effect)) return effect;
  return NextResponse.json({ ...effect, truthState: 'SUCCESS' }, { status: 202, headers: noStore });
}
