import { NextResponse, type NextRequest } from 'next/server';
import { readPendingAdministrator } from './platform-administrator-selection';
import { roleBindingPreviewSchema } from './platform-ceiling-plan';
import { platformSession } from './local-rpc-access-workbench';
import {
  grantKinds,
  grantRevision,
  grantPermission,
  grantRecord,
  grantReadback,
  grantProposal,
} from '../../../../components/grant-workflow-contract';
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
  logOwnerFailure,
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
  readPublicCommand,
  responseIds,
  safeProblem,
  sameOrigin,
  sealBffPayload,
  type IdentitySession,
  type LocalConfig,
} from './local-runtime';

const noStore = { 'Cache-Control': 'no-store' };
const revision = grantRevision;
const proposal = grantProposal;
const readback = grantReadback;
const reason = z.string().trim().min(10).max(1024);
const reviewSchema = z
  .object({
    version: z.literal(1),
    issuedAt: z.number().int().nonnegative(),
    sessionId: uuidSchema,
    principalId: uuidSchema,
    contextEpoch: revision,
    kind: grantKinds,
    mutation: z.enum(['CREATE', 'REVOKE']),
    expectedRevision: revision,
    reason,
    proposedGrant: grantRecord,
    candidateDigest: digestSchema,
    resourceReservationId: z.uuidv7().optional(),
    platformScopeReplacementId: uuidSchema.optional(),
    checkerPrincipalId: uuidSchema.optional(),
    idempotencyKey: z.string().min(16).max(128),
  })
  .strict()
  .refine((value) => (value.kind === 'assignment') === 'principalId' in value.proposedGrant);
const requestedScope = grantPermission
  .omit({ privacyDomainIds: true })
  .extend({ validUntil: timestampSchema });
const preview = z.discriminatedUnion('command', [
  requestedScope
    .extend({
      command: z.literal('PREVIEW_ASSIGN'),
      assignmentId: uuidSchema.optional(),
      principalId: uuidSchema,
      groupId: uuidSchema.optional(),
      authorityEnvelopeId: uuidSchema,
      roleId: z
        .string()
        .regex(/^urn:openpc:role:[0-9a-f-]{36}$/u)
        .optional(),
      reason,
      resourceReservationId: z.uuidv7().optional(),
    })
    .strict(),
  requestedScope
    .extend({
      command: z.literal('PREVIEW_DELEGATE'),
      granteeId: uuidSchema,
      parentId: uuidSchema,
      parentKind: grantKinds,
      reason,
      resourceReservationId: z.uuidv7().optional(),
    })
    .strict(),
  z
    .object({
      command: z.literal('PREVIEW_REVOKE'),
      kind: grantKinds,
      grantId: uuidSchema,
      reason,
      resourceReservationId: z.uuidv7().optional(),
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
type PendingAdministrator = Exclude<
  Awaited<ReturnType<typeof readPendingAdministrator>>,
  NextResponse
>;

async function ownerRead<T>(
  runtime: LocalConfig,
  session: IdentitySession,
  path: string,
  schema: z.ZodType<T>,
  request: NextRequest,
) {
  const response = await fetch(
    `${runtime.publicApiUrl}${path.startsWith('/v1/') ? path : `/v1/participants/${participantId}/${path}`}`,
    {
      cache: 'no-store',
      headers: {
        'Authorization': `Bearer ${session.sessionToken}`,
        'Cookie': `__Host-openpc_session=${session.sessionToken}`,
        'OpenPC-Privacy-Domain-ID': `urn:openpc:privacy-domain:${privacyDomainId}`,
      },
    },
  ).catch(() => undefined);
  return ownerJson(response, schema, request);
}
function responseReview(value: Review, runtime: LocalConfig) {
  return {
    reviewToken: sealBffPayload(value, runtime.cookieKey, 'grant-review'),
    review: {
      mutation: value.mutation,
      kind: value.kind,
      resourceId: value.proposedGrant.id,
      proposedGrant: value.proposedGrant,
      reason: value.reason,
      expectedRevision: value.expectedRevision,
      candidateDigest: value.candidateDigest,
      stepUp: {
        actionIntentId: grantAction(value).id,
        actionIntentDigest: grantAction(value).digest,
        resourceId: value.proposedGrant.id,
        resourceDigest: value.candidateDigest,
      },
    },
  };
}
function openReview(token: string, runtime: LocalConfig, session: IdentitySession) {
  const value = reviewSchema.safeParse(openBffPayload(token, runtime.cookieKey, 'grant-review'));
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
function grantAction(value: { mutation: string }) {
  return value.mutation === 'CREATE' ? principalCreateAction : participantAction;
}
function grantBody(value: Pick<Review, 'kind' | 'mutation' | 'proposedGrant'>) {
  if (value.mutation === 'REVOKE') return {};
  const grant = value.proposedGrant;
  const permission = grantPermission.strip().parse(grant);
  return 'principalId' in grant
    ? {
        ...permission,
        assignmentId: grant.id,
        principalId: grant.principalId,
        authorityEnvelopeId: grant.authorityEnvelopeId,
        scopeDigest: grant.scopeDigest,
        ...(grant.roleId ? { roleId: grant.roleId } : {}),
        ...(grant.groupId ? { groupId: grant.groupId } : {}),
      }
    : {
        ...permission,
        delegationId: grant.id,
        parentId: grant.parentId,
        granteeId: grant.granteeId,
        scopeDigest: grant.scopeDigest,
      };
}
function candidate(value: Pick<Review, 'kind' | 'mutation' | 'proposedGrant'>) {
  if (value.mutation === 'REVOKE') return { kind: value.kind, targetId: value.proposedGrant.id };
  return {
    id: value.proposedGrant.id,
    participantId,
    state: 'ACTIVE',
    delegationEpoch: '0',
    ...('grantorId' in value.proposedGrant ? { grantorId: value.proposedGrant.grantorId } : {}),
    ...grantBody(value),
  };
}
async function writeGrant(
  runtime: LocalConfig,
  session: IdentitySession,
  value: Review,
  approvalId: string,
) {
  const action = grantAction(value);
  const csrfToken = await csrf(runtime, session, action.id);
  if (!csrfToken) return undefined;
  const target = `${value.kind}s${value.mutation === 'REVOKE' ? `/${value.proposedGrant.id}` : ''}`;
  return fetch(`${runtime.publicApiUrl}/v1/participants/${participantId}/${target}`, {
    method: value.mutation === 'REVOKE' ? 'DELETE' : 'POST',
    cache: 'no-store',
    headers: {
      'Authorization': `Bearer ${session.sessionToken}`,
      'Content-Type': 'application/json',
      'Origin': new URL(runtime.publicApiUrl).origin,
      'X-CSRF-Token': csrfToken,
      'Idempotency-Key': value.idempotencyKey,
      'X-OpenPC-Aggregate-Version': value.expectedRevision,
      'X-OpenPC-Approval-Request-ID': approvalId,
      'OpenPC-Action-Intent-Digest': action.digest,
    },
    body: JSON.stringify(grantBody(value)),
  }).catch(() => undefined);
}
function withinSource(
  child: z.infer<typeof grantPermission>,
  source: z.infer<typeof grantPermission>,
  delegation: boolean,
) {
  const subset = (values: string[], allowed: string[]) =>
    values.every((value) => allowed.includes(value));
  return (
    subset(child.privacyDomainIds, source.privacyDomainIds) &&
    subset(child.actionIntentIds, source.actionIntentIds) &&
    subset(child.capabilityIds, source.capabilityIds) &&
    (source.resourceIds.includes('*') || subset(child.resourceIds, source.resourceIds)) &&
    subset(child.riskClasses, source.riskClasses) &&
    Date.parse(child.validFrom) >= Date.parse(source.validFrom) &&
    (source.validUntil === null ||
      (child.validUntil !== null &&
        Date.parse(child.validUntil) <= Date.parse(source.validUntil))) &&
    (!source.makerCheckerRequired || child.makerCheckerRequired) &&
    (!source.stepUpRequired || child.stepUpRequired) &&
    (delegation
      ? child.onwardDelegationDepth < source.onwardDelegationDepth
      : child.onwardDelegationDepth <= source.onwardDelegationDepth)
  );
}
async function previewReview(
  input: z.infer<typeof preview>,
  runtime: LocalConfig,
  session: IdentitySession,
  request: NextRequest,
  pendingSelection?: PendingAdministrator,
) {
  let kind: Review['kind'];
  let proposedGrant: Review['proposedGrant'];
  let expectedRevision = '0';
  if (input.command === 'PREVIEW_REVOKE') {
    const current = await ownerRead(
      runtime,
      session,
      `${input.kind}s/${input.grantId}`,
      readback,
      request,
    );
    if (isResponse(current)) return current;
    if (!['ACTIVE', 'SUSPENDED'].includes(current.effect.state))
      return safeProblem('PC-DATA-6007', request);
    kind = input.kind;
    expectedRevision = current.revision;
    proposedGrant = { ...current.effect, state: 'REVOKED' };
  } else {
    const subjectId = input.command === 'PREVIEW_ASSIGN' ? input.principalId : input.granteeId;
    const pendingPlatformAssignment =
      pendingSelection && session.contextMode === 'PLATFORM' && input.command === 'PREVIEW_ASSIGN';
    if (pendingPlatformAssignment) {
      const admin = pendingSelection.administrator;
      if (
        subjectId !== admin.principalId ||
        input.assignmentId !== admin.assignmentId ||
        input.authorityEnvelopeId !== admin.envelopeId ||
        input.roleId !== `urn:openpc:role:${admin.roleId}`
      )
        return safeProblem('PC-DATA-6007', request);
      // The consumed preparation and current readiness select this exact target.
      // Native assignment execution checks its current ACTIVE state; preview does
      // not require general visibility of the other administrator's identity.
    } else {
      const subject = await ownerRead(
        runtime,
        session,
        `/v1/identity/principals/${subjectId}`,
        z.object({
          effect: z.object({
            principalId: uuidSchema,
            participantId: z.literal(participantId),
            state: z.string(),
          }),
          operationId: uuidSchema.nullable(),
        }),
        request,
      );
      if (isResponse(subject)) return subject;
      if (subject.effect.state !== 'ACTIVE') return safeProblem('PC-DATA-6007', request);
    }
    const permission = grantPermission.parse({
      privacyDomainIds: [privacyDomainId],
      actionIntentIds: [...input.actionIntentIds].sort(),
      capabilityIds: [...input.capabilityIds].sort(),
      resourceIds: [...input.resourceIds].sort(),
      riskClasses: [...input.riskClasses].sort(),
      validFrom: new Date(input.validFrom).toISOString(),
      validUntil: new Date(input.validUntil).toISOString(),
      makerCheckerRequired: input.makerCheckerRequired,
      stepUpRequired: input.stepUpRequired,
      onwardDelegationDepth: input.onwardDelegationDepth,
    });
    if (
      Date.parse(permission.validUntil!) <= Date.now() ||
      Date.parse(permission.validUntil!) <= Date.parse(permission.validFrom)
    )
      return safeProblem('PC-DATA-6004', request);
    const common = {
      ...permission,
      id:
        input.command === 'PREVIEW_ASSIGN'
          ? (input.assignmentId ?? responseIds().requestId)
          : responseIds().requestId,
      participantId,
      state: 'ACTIVE' as const,
      delegationEpoch: '0',
      scopeDigest: digest({ participantId, ...permission }),
    };
    if (input.command === 'PREVIEW_ASSIGN') {
      const envelope = await ownerRead(
        runtime,
        session,
        `envelopes/${input.authorityEnvelopeId}`,
        z.object({
          effect: grantPermission.extend({
            id: uuidSchema,
            participantId: z.literal(participantId),
            state: z.string(),
            authorityEpoch: revision,
            revision,
            semanticDigest: digestSchema,
            platformScopeReplacementId: uuidSchema.optional(),
          }),
          operationId: uuidSchema.nullable(),
        }),
        request,
      );
      if (isResponse(envelope)) return envelope;
      if (envelope.effect.state !== 'ACTIVE') return safeProblem('PC-DATA-6007', request);
      if (!withinSource(permission, envelope.effect, false))
        return safeProblem('PC-DATA-6004', request);
      if (
        pendingSelection &&
        (envelope.effect.id !== pendingSelection.administrator.envelopeId ||
          envelope.effect.platformScopeReplacementId !== pendingSelection.plan.replacementId)
      )
        return safeProblem('PC-DATA-6007', request);
      if (input.roleId) {
        let roleActions: string[];
        if (pendingSelection && session.contextMode === 'PLATFORM') {
          const admin = pendingSelection.administrator;
          const role = await ownerRead(
            runtime,
            session,
            `roles/${admin.roleId}/binding-preview`,
            roleBindingPreviewSchema,
            request,
          );
          if (isResponse(role)) return role;
          if (
            role.participantId !== participantId ||
            role.roleId !== admin.roleId ||
            role.roleRef !== input.roleId ||
            input.roleId !== `urn:openpc:role:${admin.roleId}` ||
            role.revision !== admin.expectedRoleRevision ||
            role.roleDigest !== admin.roleDigest
          )
            return safeProblem('PC-DATA-6007', request);
          roleActions = role.actionIntentIds;
        } else {
          const role = await ownerRead(
            runtime,
            session,
            `roles/${input.roleId.slice(-36)}`,
            z.object({
              effect: z.object({
                roleId: z.literal(input.roleId),
                state: z.string(),
                actionIntentIds: z.array(z.string()),
              }),
            }),
            request,
          );
          if (isResponse(role)) return role;
          if (role.effect.state !== 'ACTIVE') return safeProblem('PC-DATA-6007', request);
          roleActions = role.effect.actionIntentIds;
        }
        if (!permission.actionIntentIds.every((action) => roleActions.includes(action)))
          return safeProblem('PC-DATA-6004', request);
      }
      kind = 'assignment';
      proposedGrant = {
        ...common,
        principalId: subjectId,
        authorityEnvelopeId: input.authorityEnvelopeId,
        ...(input.roleId ? { roleId: input.roleId } : {}),
        ...(input.groupId ? { groupId: input.groupId } : {}),
      };
    } else {
      if (subjectId === session.principalId) return safeProblem('PC-DATA-6004', request);
      const parent = await ownerRead(
        runtime,
        session,
        `${input.parentKind}s/${input.parentId}`,
        readback,
        request,
      );
      if (isResponse(parent)) return parent;
      const grantor =
        'principalId' in parent.effect ? parent.effect.principalId : parent.effect.granteeId;
      if (
        parent.effect.state !== 'ACTIVE' ||
        grantor !== session.principalId ||
        !withinSource(permission, parent.effect, true)
      )
        return safeProblem('PC-DATA-6004', request);
      kind = 'delegation';
      proposedGrant = {
        ...common,
        parentId: input.parentId,
        granteeId: subjectId,
        grantorId: session.principalId,
      };
    }
  }
  const mutation = input.command === 'PREVIEW_REVOKE' ? ('REVOKE' as const) : ('CREATE' as const);
  return reviewSchema.parse({
    version: 1,
    issuedAt: Date.now(),
    sessionId: session.sessionId,
    principalId: session.principalId,
    contextEpoch: session.contextEpoch,
    kind,
    mutation,
    expectedRevision,
    reason: input.reason,
    resourceReservationId: input.resourceReservationId,
    proposedGrant,
    candidateDigest: digest(candidate({ kind, mutation, proposedGrant })),
    idempotencyKey: `grant-workbench-${responseIds().requestId}`,
  });
}

async function admittedGrantSession(runtime: LocalConfig, request: NextRequest) {
  const current = await authenticated(request, runtime);
  if (!current) return undefined;
  if (contextAdmitted(current)) return current;
  if (request.nextUrl.searchParams.get('mode') !== 'platform-handoff') return undefined;
  const selected = await platformSession(runtime, current, request);
  if (!selected || isResponse(selected)) return selected;
  // This existing local workbench owns one Participant/privacy pair. Metadata,
  // never caller input, must bind a Platform handoff to that same owner.
  return selected.participantId === participantId && selected.privacyDomainId === privacyDomainId
    ? selected
    : undefined;
}

export async function readGrantWorkbench(request: NextRequest) {
  const runtime = await localRuntimeConfig().catch(() => undefined);
  if (!runtime) return undefined;
  const session = await admittedGrantSession(runtime, request);
  if (!session || isResponse(session)) return session ?? safeProblem('PC-AUTH-0005', request);
  const cursor = request.nextUrl.searchParams.get('cursor');
  if (cursor && !z.string().min(1).max(8192).safeParse(cursor).success)
    return safeProblem('PC-DATA-6004', request);
  const grantId = request.nextUrl.searchParams.get('grantId');
  const kind = grantKinds.safeParse(request.nextUrl.searchParams.get('kind') ?? 'assignment');
  if (!kind.success || (grantId && !uuidSchema.safeParse(grantId).success))
    return safeProblem('PC-DATA-6004', request);
  if (session.contextMode === 'PLATFORM' && kind.data !== 'assignment')
    return safeProblem('PC-AUTH-0005', request);
  const filter = `${session.role === 'viewer' ? 'checkerSubjectRef' : 'makerSubjectRef'}:eq:urn:openpc:resource:${session.principalId}`;
  const approvalSelector = request.nextUrl.searchParams.get('approvalRequestId');
  if (approvalSelector && !uuidSchema.safeParse(approvalSelector).success)
    return safeProblem('PC-DATA-6004', request);
  const selectedApproval =
    session.contextMode === 'PLATFORM' && approvalSelector
      ? await approval(runtime, session, approvalSelector, request)
      : undefined;
  if (isResponse(selectedApproval)) return selectedApproval;
  const response =
    session.contextMode === 'PLATFORM'
      ? undefined
      : await fetch(
          `${runtime.publicApiUrl}/api/v1/approval-requests?limit=50&sort=-updatedAt&filter=${encodeURIComponent(filter)}${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ''}`,
          {
            cache: 'no-store',
            headers: publicHeaders(runtime, session),
          },
        ).catch(() => undefined);
  const page =
    session.contextMode === 'PLATFORM'
      ? {
          items: selectedApproval ? [selectedApproval] : [],
          nextCursor: null,
          completeness: selectedApproval ? 'COMPLETE' : 'UNKNOWN',
        }
      : await ownerJson(response, approvalPageSchema, request);
  if (isResponse(page)) return page;
  const approvals = [];
  for (const item of page.items) {
    const detail = await ownerRead(
      runtime,
      session,
      `grant-proposals/${encodeURIComponent(item.candidateDigest)}`,
      proposal,
      request,
    );
    if (isResponse(detail)) {
      // Other approval families and invisible candidates are omitted, never approved without a proposal.
      if (detail.status === 404 || detail.status === 403) continue;
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
  const effect = grantId
    ? await ownerRead(runtime, session, `${kind.data}s/${grantId}`, readback, request)
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
      approvalsLoaded: session.contextMode !== 'PLATFORM' || !!selectedApproval,
      ...(effect ? { effect } : {}),
      nextCursor: page.nextCursor,
      completeness: page.completeness,
    },
    { headers: noStore },
  );
}

export async function mutateGrantWorkbench(request: NextRequest) {
  const runtime = await localRuntimeConfig().catch(() => undefined);
  if (!runtime) return safeProblem('PC-AUTH-0005', request);
  if (!sameOrigin(request) || !hasJsonContentType(request.headers.get('content-type')))
    return safeProblem('PC-AUTH-0002', request);
  const session = await admittedGrantSession(runtime, request);
  if (!session || isResponse(session)) return session ?? safeProblem('PC-AUTH-0005', request);
  let raw = await readPublicCommand(request, 73728);
  let pendingSelection: Awaited<ReturnType<typeof readPendingAdministrator>> | undefined;
  const pending = z
    .strictObject({
      command: z.literal('PREVIEW_PENDING_ASSIGNMENT'),
      approvalRequestId: uuidSchema,
      principalId: uuidSchema,
      reason,
      resourceReservationId: z.uuidv7().optional(),
    })
    .safeParse(raw);
  if (pending.success) {
    const selected = await readPendingAdministrator(
      runtime,
      session,
      request,
      pending.data.approvalRequestId,
      pending.data.principalId,
    );
    if (isResponse(selected)) return selected;
    pendingSelection = selected;
    const admin = selected.administrator,
      scope = admin.usable;
    if (BigInt(scope.validFromNs) % 1000000n !== 0n || BigInt(scope.validUntilNs) % 1000000n !== 0n)
      return safeProblem('PC-DATA-6007', request);
    raw = {
      command: 'PREVIEW_ASSIGN',
      assignmentId: admin.assignmentId,
      principalId: admin.principalId,
      authorityEnvelopeId: admin.envelopeId,
      roleId: `urn:openpc:role:${admin.roleId}`,
      actionIntentIds: scope.administration.actionIntentIds,
      resourceIds: scope.administration.resourceIds,
      riskClasses: scope.administration.riskClasses,
      capabilityIds: [],
      validFrom: new Date(Number(BigInt(scope.validFromNs) / 1000000n)).toISOString(),
      validUntil: new Date(Number(BigInt(scope.validUntilNs) / 1000000n)).toISOString(),
      makerCheckerRequired: true,
      stepUpRequired: true,
      onwardDelegationDepth: 0,
      reason: pending.data.reason,
      resourceReservationId: pending.data.resourceReservationId,
    };
  }
  const previewInput = preview.safeParse(raw);
  if (previewInput.success) {
    if (session.role !== 'operator') return safeProblem('PC-AUTH-0005', request);
    if (session.contextMode === 'PLATFORM' && !pendingSelection)
      return safeProblem('PC-AUTH-0005', request);
    const value = await previewReview(
      previewInput.data,
      runtime,
      session,
      request,
      pendingSelection && !isResponse(pendingSelection) ? pendingSelection : undefined,
    );
    if (isResponse(value)) return value;
    if (pendingSelection && !isResponse(pendingSelection)) {
      value.platformScopeReplacementId = pendingSelection.plan.replacementId;
      value.checkerPrincipalId = pendingSelection.checkerPrincipalId;
    }
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
      `grant-proposals/${encodeURIComponent(current.candidateDigest)}`,
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
  if (
    session.contextMode === 'PLATFORM' &&
    (!value.platformScopeReplacementId ||
      !value.checkerPrincipalId ||
      value.kind !== 'assignment' ||
      value.mutation !== 'CREATE')
  )
    return safeProblem('PC-AUTH-0005', request);
  if (token.data.command === 'SUBMIT') {
    const staged = await writeGrant(
      runtime,
      session,
      value,
      '00000000-0000-7000-8000-000000000000',
    );
    if (staged?.status !== 403) {
      await logOwnerFailure(`grant-proposal-stage-${value.kind}-${value.proposedGrant.id}`, staged);
      return ownerFailure(staged, request);
    }
    // A denial alone does not prove staging; confirm the exact immutable proposal through its owner.
    const detail = await ownerRead(
      runtime,
      session,
      `grant-proposals/${encodeURIComponent(value.candidateDigest)}`,
      proposal,
      request,
    );
    if (isResponse(detail)) return detail;
    if (
      detail.expectedRevision !== value.expectedRevision ||
      digest(detail.proposedGrant) !== digest(value.proposedGrant)
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
        resourceReservationId: value.resourceReservationId,
        makerSubjectRef: `urn:openpc:resource:${session.principalId}`,
        checkerSubjectRef: `urn:openpc:resource:${value.checkerPrincipalId ?? checkerPrincipalId}`,
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
  const response = await writeGrant(runtime, session, value, token.data.approvalRequestId);
  // A lost transport response cannot establish whether the durable mutation committed.
  if (!response || (token.data.simulateResponseLoss === true && response.ok))
    return NextResponse.json(
      {
        truthState: 'WRITE_AMBIGUITY',
        grantId: value.proposedGrant.id,
        kind: value.kind,
        reconciliation: 'READ_AUTHORITATIVE_EFFECT',
      },
      { status: 202, headers: noStore },
    );
  if (!response.ok) return ownerFailure(response, request);
  if (value.mutation === 'REVOKE') {
    const result = await ownerJson(response, z.object({ newEpoch: revision }).strict(), request);
    if (isResponse(result)) return result;
    return NextResponse.json(
      {
        ...result,
        kind: value.kind,
        grantId: value.proposedGrant.id,
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
    `${value.kind}s/${value.proposedGrant.id}`,
    readback,
    request,
  );
  if (isResponse(result)) return result;
  return NextResponse.json({ ...result, truthState: 'SUCCESS' }, { status: 202, headers: noStore });
}
