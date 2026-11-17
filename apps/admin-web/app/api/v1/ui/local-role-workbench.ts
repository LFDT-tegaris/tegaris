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
  readPublicCommand,
  responseIds,
  safeProblem,
  sameOrigin,
  sealBffPayload,
  type IdentitySession,
  type LocalConfig,
} from './local-runtime';

const noStore = { 'Cache-Control': 'no-store' };
const revision = z.string().regex(/^(?:0|[1-9][0-9]*)$/u);
const actions = z
  .array(z.string().regex(/^ACT-[A-Z0-9_]+-V[1-9][0-9]*$/u))
  .max(256)
  .refine((values) => new Set(values).size === values.length);
const role = z
  .object({
    id: uuidSchema,
    participantId: z.literal(participantId),
    roleId: z.string().regex(/^urn:openpc:role:[0-9a-f-]{36}$/u),
    displayName: z.string().min(1).max(160),
    actionIntentIds: actions,
    state: z.enum(['ACTIVE', 'ARCHIVED']),
  })
  .strict();
const record = role
  .extend({ revision, origin: z.enum(['GOVERNED', 'MIGRATED_ASSIGNMENT', 'BOOTSTRAP']) })
  .strict();
const readback = z.object({ effect: record, operationId: uuidSchema.nullable() }).strict();
const cataloguePage = z
  .object({
    items: z.array(readback).max(50),
    nextCursor: uuidSchema.nullable(),
    completeness: z.literal('COMPLETE'),
    authorizedEmpty: z.boolean(),
    observedAt: timestampSchema,
  })
  .strict();
const proposal = z
  .object({
    candidateDigest: digestSchema,
    resourceId: uuidSchema,
    mutation: z.enum(['CREATE', 'ARCHIVE']),
    expectedRevision: revision,
    state: z.string(),
    expiresAt: timestampSchema,
    proposedRole: role,
    consumption: z.object({ operationId: uuidSchema, effect: record }).strict().nullable(),
  })
  .strict()
  .superRefine((value, context) => {
    const consumed = value.consumption;
    const expectedDigest = digest(
      value.mutation === 'CREATE'
        ? value.proposedRole
        : { roleId: value.resourceId, state: 'ARCHIVED' },
    );
    if (
      value.resourceId !== value.proposedRole.id ||
      value.proposedRole.roleId !== `urn:openpc:role:${value.resourceId}` ||
      value.proposedRole.state !== (value.mutation === 'CREATE' ? 'ACTIVE' : 'ARCHIVED') ||
      value.candidateDigest !== expectedDigest ||
      (value.state === 'CONSUMED') !== (consumed !== null) ||
      (consumed &&
        (consumed.effect.id !== value.resourceId ||
          consumed.effect.roleId !== value.proposedRole.roleId ||
          consumed.effect.displayName !== value.proposedRole.displayName ||
          JSON.stringify(consumed.effect.actionIntentIds) !==
            JSON.stringify(value.proposedRole.actionIntentIds) ||
          consumed.effect.state !== (value.mutation === 'CREATE' ? 'ACTIVE' : 'ARCHIVED') ||
          BigInt(consumed.effect.revision) !== BigInt(value.expectedRevision) + 1n ||
          (value.mutation === 'CREATE' &&
            (value.expectedRevision !== '0' || consumed.effect.origin !== 'GOVERNED'))))
    )
      context.addIssue({
        code: 'custom',
        message: 'Role proposal receipt does not match its intent.',
      });
  });
const reviewSchema = z
  .object({
    version: z.literal(1),
    issuedAt: z.number().int().nonnegative(),
    sessionId: uuidSchema,
    principalId: uuidSchema,
    contextEpoch: revision,
    mutation: z.enum(['CREATE', 'ARCHIVE']),
    expectedRevision: revision,
    reason: z.string().min(10).max(1024),
    proposedRole: role,
    candidateDigest: digestSchema,
    idempotencyKey: z.string().min(16).max(128),
  })
  .strict();
const preview = z.discriminatedUnion('command', [
  z
    .object({
      command: z.literal('PREVIEW_CREATE'),
      displayName: z.string().trim().min(1).max(160),
      actionIntentIds: actions,
      reason: z.string().trim().min(10).max(1024),
    })
    .strict(),
  z
    .object({
      command: z.literal('PREVIEW_ARCHIVE'),
      roleId: uuidSchema,
      reason: z.string().trim().min(10).max(1024),
    })
    .strict(),
]);
const tokenInput = z.discriminatedUnion('command', [
  z.object({ command: z.literal('SUBMIT'), reviewToken: z.string().min(80).max(65536) }).strict(),
  z
    .object({
      command: z.literal('COMMIT'),
      reviewToken: z.string().min(80).max(65536),
      approvalRequestId: uuidSchema,
      simulateResponseLoss: z.boolean().optional(),
    })
    .strict(),
]);
const approveInput = z
  .object({
    command: z.literal('APPROVE'),
    approvalRequestId: uuidSchema,
    candidateDigest: digestSchema,
  })
  .strict();
type Review = z.infer<typeof reviewSchema>;

async function ownerRead<T>(
  runtime: LocalConfig,
  session: IdentitySession,
  path: string,
  schema: z.ZodType<T>,
  request: NextRequest,
) {
  const response = await fetch(`${runtime.publicApiUrl}/v1/participants/${participantId}/${path}`, {
    cache: 'no-store',
    headers: {
      'Authorization': `Bearer ${session.sessionToken}`,
      'OpenPC-Privacy-Domain-ID': `urn:openpc:privacy-domain:${privacyDomainId}`,
    },
  }).catch(() => undefined);
  return ownerJson(response, schema, request);
}
function responseReview(value: Review, runtime: LocalConfig) {
  return {
    reviewToken: sealBffPayload(value, runtime.cookieKey, 'role-review'),
    review: {
      mutation: value.mutation,
      proposedRole: value.proposedRole,
      reason: value.reason,
      expectedRevision: value.expectedRevision,
      candidateDigest: value.candidateDigest,
      stepUp: {
        actionIntentId: participantAction.id,
        actionIntentDigest: participantAction.digest,
        resourceId: value.proposedRole.id,
        resourceDigest: value.candidateDigest,
      },
    },
  };
}
function openReview(token: string, runtime: LocalConfig, session: IdentitySession) {
  const value = reviewSchema.safeParse(openBffPayload(token, runtime.cookieKey, 'role-review'));
  if (
    !value.success ||
    value.data.issuedAt > Date.now() ||
    Date.now() - value.data.issuedAt >= 1800000 ||
    value.data.sessionId !== session.sessionId ||
    value.data.principalId !== session.principalId ||
    value.data.contextEpoch !== session.contextEpoch
  )
    return undefined;
  return value.data;
}
async function writeRole(
  runtime: LocalConfig,
  session: IdentitySession,
  value: Review,
  approvalId: string,
) {
  const csrfToken = await csrf(runtime, session, participantAction.id);
  if (!csrfToken) return undefined;
  const target = value.mutation === 'CREATE' ? 'roles' : `roles/${value.proposedRole.id}/archive`;
  const body =
    value.mutation === 'CREATE'
      ? {
          roleId: value.proposedRole.id,
          displayName: value.proposedRole.displayName,
          actionIntentIds: value.proposedRole.actionIntentIds,
        }
      : {};
  return fetch(`${runtime.publicApiUrl}/v1/participants/${participantId}/${target}`, {
    method: 'POST',
    cache: 'no-store',
    headers: {
      'Authorization': `Bearer ${session.sessionToken}`,
      'Content-Type': 'application/json',
      'Origin': new URL(runtime.publicApiUrl).origin,
      'X-CSRF-Token': csrfToken,
      'Idempotency-Key': value.idempotencyKey,
      'X-OpenPC-Aggregate-Version': value.expectedRevision,
      'X-OpenPC-Approval-Request-ID': approvalId,
      'OpenPC-Action-Intent-Digest': participantAction.digest,
    },
    body: JSON.stringify(body),
  }).catch(() => undefined);
}

export async function readRoleWorkbench(request: NextRequest) {
  const runtime = await localRuntimeConfig().catch(() => undefined);
  if (!runtime) return undefined;
  const session = await authenticated(request, runtime);
  if (!session || !contextAdmitted(session)) return safeProblem('PC-AUTH-0005', request);
  const cursor = request.nextUrl.searchParams.get('cursor');
  if (cursor && !z.string().min(1).max(8192).safeParse(cursor).success)
    return safeProblem('PC-DATA-6004', request);
  const roleId = request.nextUrl.searchParams.get('roleId');
  if (roleId && !uuidSchema.safeParse(roleId).success) return safeProblem('PC-DATA-6004', request);
  const filter = `${session.role === 'viewer' ? 'checkerSubjectRef' : 'makerSubjectRef'}:eq:urn:openpc:resource:${session.principalId}`;
  const response = await fetch(
    `${runtime.publicApiUrl}/api/v1/approval-requests?limit=50&sort=-updatedAt&filter=${encodeURIComponent(filter)}${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ''}`,
    {
      cache: 'no-store',
      headers: publicHeaders(runtime, session),
    },
  ).catch(() => undefined);
  const page = await ownerJson(response, approvalPageSchema, request);
  if (isResponse(page)) return page;
  const approvals = [];
  for (const item of page.items) {
    const detail = await ownerRead(
      runtime,
      session,
      `role-proposals/${encodeURIComponent(item.candidateDigest)}`,
      proposal,
      request,
    );
    if (isResponse(detail)) {
      // Other approval families and invisible candidates are omitted, never approved without a proposal.
      if (detail.status === 404 || detail.status === 403) continue;
      return detail;
    }
    if (detail.candidateDigest !== item.candidateDigest)
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
  const effect = roleId
    ? await ownerRead(runtime, session, `roles/${roleId}`, readback, request)
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

export async function readRoleCatalogue(request: NextRequest) {
  const runtime = await localRuntimeConfig().catch(() => undefined);
  if (!runtime) return safeProblem('PC-AUTH-0005', request);
  const session = await authenticated(request, runtime);
  if (!session || !contextAdmitted(session)) return safeProblem('PC-AUTH-0005', request);
  if (
    [...request.nextUrl.searchParams.keys()].length !==
    new Set(request.nextUrl.searchParams.keys()).size
  )
    return safeProblem('PC-DATA-6004', request);
  const query = z
    .strictObject({
      search: z.string().trim().max(160).default(''),
      state: z.enum(['ALL', 'ACTIVE', 'ARCHIVED']).default('ALL'),
      after: uuidSchema.optional(),
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
  const schema = cataloguePage.extend({
    items: z
      .array(readback.extend({ effect: record.extend({ participantId: uuidSchema }) }))
      .max(query.data.limit),
  });
  const page = await ownerJson(
    await fetch(
      `${runtime.publicApiUrl}/v1/participants/${session.participantId}/roles?${parameters}`,
      {
        cache: 'no-store',
        headers: {
          'Authorization': `Bearer ${session.sessionToken}`,
          'OpenPC-Privacy-Domain-ID': `urn:openpc:privacy-domain:${session.privacyDomainId}`,
        },
      },
    ).catch(() => undefined),
    schema,
    request,
  );
  if (isResponse(page)) return page;
  if (
    page.authorizedEmpty !== (page.items.length === 0) ||
    (page.nextCursor !== null &&
      (page.items.length !== query.data.limit ||
        page.nextCursor !== page.items.at(-1)?.effect.id)) ||
    page.items.some(
      ({ effect }, index) =>
        effect.participantId !== session.participantId ||
        (query.data.state !== 'ALL' && effect.state !== query.data.state) ||
        !effect.displayName.toLowerCase().includes(query.data.search.toLowerCase()) ||
        effect.id <= (page.items[index - 1]?.effect.id ?? query.data.after ?? ''),
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

export async function mutateRoleWorkbench(request: NextRequest) {
  const runtime = await localRuntimeConfig().catch(() => undefined);
  if (!runtime) return safeProblem('PC-AUTH-0005', request);
  if (!sameOrigin(request) || !hasJsonContentType(request.headers.get('content-type')))
    return safeProblem('PC-AUTH-0002', request);
  const session = await authenticated(request, runtime);
  if (!session || !contextAdmitted(session)) return safeProblem('PC-AUTH-0005', request);
  const raw = await readPublicCommand(request, 73_728);
  const previewInput = preview.safeParse(raw);
  if (previewInput.success) {
    if (session.role !== 'operator') return safeProblem('PC-AUTH-0005', request);
    const input = previewInput.data;
    const old =
      input.command === 'PREVIEW_ARCHIVE'
        ? await ownerRead(runtime, session, `roles/${input.roleId}`, readback, request)
        : undefined;
    if (isResponse(old)) return old;
    if (old && old.effect.state !== 'ACTIVE') return safeProblem('PC-DATA-6007', request);
    const id = old?.effect.id ?? responseIds().requestId;
    const proposedRole = role.parse(
      old
        ? {
            id,
            participantId,
            roleId: old.effect.roleId,
            displayName: old.effect.displayName,
            actionIntentIds: old.effect.actionIntentIds,
            state: 'ARCHIVED',
          }
        : {
            id,
            participantId,
            roleId: `urn:openpc:role:${id}`,
            displayName: input.command === 'PREVIEW_CREATE' ? input.displayName : '',
            actionIntentIds:
              input.command === 'PREVIEW_CREATE' ? [...input.actionIntentIds].sort() : [],
            state: 'ACTIVE',
          },
    );
    const value = reviewSchema.parse({
      version: 1,
      issuedAt: Date.now(),
      sessionId: session.sessionId,
      principalId: session.principalId,
      contextEpoch: session.contextEpoch,
      reason: input.reason,
      mutation: old ? 'ARCHIVE' : 'CREATE',
      expectedRevision: old?.effect.revision ?? '0',
      proposedRole,
      candidateDigest: digest(old ? { roleId: id, state: 'ARCHIVED' } : proposedRole),
      idempotencyKey: `role-workbench-${responseIds().requestId}`,
    });
    return NextResponse.json(responseReview(value, runtime), { status: 201, headers: noStore });
  }
  const approved = approveInput.safeParse(raw);
  if (approved.success) {
    if (session.role !== 'viewer') return safeProblem('PC-AUTH-0005', request);
    const current = await approval(runtime, session, approved.data.approvalRequestId, request);
    if (isResponse(current)) return current;
    if (current.candidateDigest !== approved.data.candidateDigest)
      return safeProblem('PC-DATA-6007', request);
    const detail = await ownerRead(
      runtime,
      session,
      `role-proposals/${encodeURIComponent(current.candidateDigest)}`,
      proposal,
      request,
    );
    if (isResponse(detail)) return detail;
    if (Date.parse(detail.expiresAt) <= Date.now()) return safeProblem('PC-DATA-6007', request);
    return approveGovernanceRequest(runtime, session, approved.data.approvalRequestId, request);
  }
  const token = tokenInput.safeParse(raw);
  if (!token.success) return safeProblem('PC-DATA-6004', request);
  if (session.role !== 'operator') return safeProblem('PC-AUTH-0005', request);
  const value = openReview(token.data.reviewToken, runtime, session);
  if (!value) return safeProblem('PC-DATA-6007', request);
  if (token.data.command === 'SUBMIT') {
    const staged = await writeRole(runtime, session, value, '00000000-0000-7000-8000-000000000000');
    if (staged?.status !== 403) return ownerFailure(staged, request);
    // A denial alone does not prove staging; confirm the exact immutable proposal through its owner.
    const detail = await ownerRead(
      runtime,
      session,
      `role-proposals/${encodeURIComponent(value.candidateDigest)}`,
      proposal,
      request,
    );
    if (isResponse(detail)) return detail;
    if (
      detail.expectedRevision !== value.expectedRevision ||
      digest(detail.proposedRole) !== digest(value.proposedRole)
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
  const response = await writeRole(runtime, session, value, token.data.approvalRequestId);
  // A lost transport response cannot establish whether the durable mutation committed.
  if (!response || (token.data.simulateResponseLoss === true && response.ok))
    return NextResponse.json(
      {
        truthState: 'WRITE_AMBIGUITY',
        roleId: value.proposedRole.id,
        reconciliation: 'READ_AUTHORITATIVE_EFFECT',
      },
      { status: 202, headers: noStore },
    );
  if (!response.ok) return ownerFailure(response, request);
  if (value.mutation === 'ARCHIVE') {
    const result = await ownerJson(
      response,
      z
        .object({
          effect: record,
          newEpoch: revision,
          revokedAssignments: z.number().int().nonnegative(),
        })
        .strict(),
      request,
    );
    if (isResponse(result)) return result;
    return NextResponse.json(
      {
        ...result,
        reauthenticationRequired: true,
        truthState: 'SUCCESS',
        reconciliation: 'READ_AFTER_REAUTHENTICATION',
      },
      { status: 202, headers: noStore },
    );
  }
  const result = await ownerRead(
    runtime,
    session,
    `roles/${value.proposedRole.id}`,
    readback,
    request,
  );
  if (isResponse(result)) return result;
  return NextResponse.json({ ...result, truthState: 'SUCCESS' }, { status: 202, headers: noStore });
}
