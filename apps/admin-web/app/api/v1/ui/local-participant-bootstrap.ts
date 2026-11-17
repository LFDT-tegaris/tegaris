import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { NextResponse, type NextRequest } from 'next/server';
import { z } from 'zod';
import {
  firstAdministratorMetadata,
  firstAdministratorCreate,
  firstAdministratorGovernanceProposal as firstAdministratorCreationProposal,
  firstAdministratorCandidate,
  firstAdministratorChange,
  firstAdministratorCustody,
} from '../../../../lib/first-administrator-contract';
import {
  participantAction,
  approval,
  approvalCreateAction,
  approvalDecisionAction,
  approveGovernanceRequest,
  csrf,
  digest,
  isResponse,
  ownerJson,
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
const createAction = 'ACT-PARTICIPANTS_CREATE_RESOURCE-V1';
const digestSchema = z.string().regex(/^sha256:[0-9a-f]{64}$/u);
const metadataSchema = firstAdministratorMetadata;
const actorSchema = z.strictObject({
  participantId: z.uuid(),
  principalId: z.uuid(),
  sessionId: z.uuid(),
});
const reviewSchema = z.strictObject({
  candidate: firstAdministratorCandidate,
  custody: firstAdministratorCustody.optional(),
  candidateDigest: digestSchema,
  actor: actorSchema,
  sourcePrivacyDomainId: z.uuid().optional(),
  origin: z.url(),
  checkerPrincipalId: z.uuid(),
  reason: z.string().min(10).max(1024),
  secret: z.string().length(43),
  actionIntentDigest: digestSchema,
});
const commands = z.discriminatedUnion('command', [
  z.strictObject({ command: z.literal('SESSION') }),
  z.strictObject({ command: z.literal('READ_CUSTODY'), participantId: z.uuid() }),
  z.strictObject({
    command: z.literal('PREPARE_CHANGE'),
    participantId: z.uuid(),
    mutation: z.enum(['ROTATE', 'REVOKE']),
    reason: z.string().trim().min(10).max(1024),
  }),
  z.strictObject({
    command: z.literal('PREPARE'),
    displayName: z.string().trim().min(1).max(160),
    administratorName: z.string().trim().min(1).max(160),
    recipientIssuer: z.url(),
    recipientSubject: z.string().min(1).max(255),
    recipientAudience: z.string().min(1).max(255),
    ttlMinutes: z.number().int().min(15).max(10080),
    checkerPrincipalId: z.uuid(),
    reason: z.string().trim().min(10).max(1024),
    actionIntentIds: firstAdministratorCreate.shape.firstAdministrator.shape.actionIntentIds,
  }),
  z.strictObject({ command: z.literal('SUBMIT'), reviewToken: z.string().min(80).max(65536) }),
  z.strictObject({
    command: z.literal('READ_ORIGINAL'),
    reviewToken: z.string().min(80).max(65536),
  }),
  z.strictObject({
    command: z.literal('COMMIT'),
    reviewToken: z.string().min(80).max(65536),
    approvalRequestId: z.uuid(),
  }),
  z.strictObject({
    command: z.literal('REVIEW'),
    resourceId: z.uuid(),
    candidateDigest: digestSchema,
    approvalRequestId: z.uuid(),
  }),
  z.strictObject({
    command: z.literal('APPROVE'),
    resourceId: z.uuid(),
    candidateDigest: digestSchema,
    approvalRequestId: z.uuid(),
  }),
]);
const noStore = { 'Cache-Control': 'no-store' };
async function metadata(runtime: LocalConfig, session: IdentitySession, request: NextRequest) {
  return ownerJson(
    await fetch(`${runtime.publicApiUrl}/v1/participants/bootstrap-metadata`, {
      cache: 'no-store',
      headers: { Authorization: `Bearer ${session.sessionToken}` },
    }).catch(() => undefined),
    metadataSchema,
    request,
  );
}
async function proposal(
  runtime: LocalConfig,
  session: IdentitySession,
  resourceId: string,
  candidateDigest: string,
  request: NextRequest,
) {
  const value = await ownerJson(
    await fetch(
      `${runtime.publicApiUrl}/v1/participants/bootstrap-proposals/${resourceId}/${encodeURIComponent(candidateDigest)}`,
      {
        cache: 'no-store',
        headers: {
          ...publicHeaders(runtime, session),
          Authorization: `Bearer ${session.sessionToken}`,
        },
      },
    ).catch(() => undefined),
    firstAdministratorCreationProposal,
    request,
  );
  if (isResponse(value)) return value;
  return value.candidate.participantId === resourceId &&
    value.candidateDigest === candidateDigest &&
    digest(value.candidate) === candidateDigest
    ? value
    : safeProblem('PC-INTEGRATION-5001', request);
}
export async function participantBootstrapWorkbench(request: NextRequest) {
  if (!sameOrigin(request) || !hasJsonContentType(request.headers.get('content-type')))
    return safeProblem('PC-AUTH-0002', request);
  const runtime = await localRuntimeConfig().catch(() => undefined);
  if (!runtime) return safeProblem('PC-AUTH-0005', request);
  const current = await authenticated(request, runtime);
  if (!current || current.contextMode !== 'PLATFORM') return safeProblem('PC-AUTH-0005', request);
  // This command carries a sealed review with the complete governed capability set.
  const parsed = commands.safeParse(parsePublicCommand(await request.text(), 69632));
  if (!parsed.success) return safeProblem('PC-DATA-6004', request);
  const input = parsed.data;
  const actor = {
    participantId: current.participantId,
    principalId: current.principalId,
    sessionId: current.sessionId,
  };
  let reviewed: z.infer<typeof reviewSchema> | undefined;
  if ('reviewToken' in input) {
    const opened = reviewSchema.safeParse(
      openBffPayload(input.reviewToken, runtime.cookieKey, 'participant-bootstrap-review'),
    );
    if (
      !opened.success ||
      digest(opened.data.actor) !== digest(actor) ||
      opened.data.origin !== request.headers.get('origin') ||
      opened.data.candidateDigest !== digest(opened.data.candidate)
    )
      return safeProblem('PC-AUTH-0005', request);
    reviewed = opened.data;
  }
  let original: z.infer<typeof firstAdministratorCreationProposal> | undefined;
  if (input.command === 'READ_ORIGINAL' || input.command === 'COMMIT') {
    if (!reviewed) return safeProblem('PC-AUTH-0005', request);
    let sourcePrivacyDomainId = reviewed.sourcePrivacyDomainId;
    if (!sourcePrivacyDomainId) {
      // Old seals have no source privacy. Only the public owner may resolve it.
      const source = await metadata(runtime, current, request);
      if (isResponse(source)) return source;
      if (source.participantId !== current.participantId)
        return safeProblem('PC-AUTH-0005', request);
      sourcePrivacyDomainId = source.privacyDomainId;
    }
    // The seal identifies the original scope; the native owner still authorizes READ.
    const detail = await proposal(
      runtime,
      { ...current, privacyDomainId: sourcePrivacyDomainId },
      reviewed.candidate.participantId,
      reviewed.candidateDigest,
      request,
    );
    if (isResponse(detail)) return detail;
    if (detail.state === 'CONSUMED')
      return (await receipt(detail, reviewed)) ?? safeProblem('PC-INTEGRATION-5001', request);
    if (input.command === 'READ_ORIGINAL')
      return NextResponse.json(
        {
          state: 'NOT_CONSUMED',
          proposalState: detail.state,
          participantId: detail.candidate.participantId,
          candidateDigest: detail.candidateDigest,
        },
        { headers: noStore },
      );
    original = detail;
  }
  if (current.platformBootstrapEligible !== true) return safeProblem('PC-AUTH-0005', request);
  const info = await metadata(runtime, current, request);
  if (isResponse(info)) return info;
  if (
    info.participantId !== current.participantId ||
    (reviewed?.sourcePrivacyDomainId !== undefined &&
      reviewed.sourcePrivacyDomainId !== info.privacyDomainId)
  )
    return safeProblem('PC-AUTH-0005', request);
  const session = { ...current, privacyDomainId: info.privacyDomainId };
  if (input.command === 'SESSION')
    return NextResponse.json(
      {
        actor,
        stepUp: {
          actionIntentId: 'ACT-IDENTITY_UPDATE_STEP_UP-V1',
          actionIntentDigest: info.stepUpActionIntentDigest,
          resourceId: session.sessionId,
          resourceDigest: digest({
            purpose: 'participant-bootstrap-session',
            sessionId: session.sessionId,
          }),
        },
      },
      { headers: noStore },
    );
  if (input.command === 'READ_CUSTODY' || input.command === 'PREPARE_CHANGE') {
    const custody = await ownerJson(
      await fetch(
        `${runtime.publicApiUrl}/v1/participants/${input.participantId}/first-administrator`,
        {
          cache: 'no-store',
          headers: {
            ...publicHeaders(runtime, session),
            Authorization: `Bearer ${session.sessionToken}`,
          },
        },
      ).catch(() => undefined),
      firstAdministratorCustody,
      request,
    );
    if (isResponse(custody)) return custody;
    if (custody.participantId !== input.participantId)
      return safeProblem('PC-INTEGRATION-5001', request);
    if (input.command === 'READ_CUSTODY') return NextResponse.json(custody, { headers: noStore });
    if (
      custody.makerPrincipalId !== actor.principalId ||
      !['ACTIVE', 'CLAIM_PENDING'].includes(custody.state)
    )
      return safeProblem('PC-AUTH-0005', request);
    const secret = randomBytes(32).toString('base64url');
    const candidate = firstAdministratorChange.parse({
      participantId: custody.participantId,
      mandateId: custody.mandateId,
      invitationId: custody.invitationId,
      custodyGeneration: custody.custodyGeneration,
      tokenVersion: custody.tokenVersion,
      expectedRevision: custody.revision,
      idempotencyKey: `first-admin-custody-${randomUUID()}`,
      change:
        input.mutation === 'ROTATE'
          ? {
              mutation: 'ROTATE',
              tokenDigest: `sha256:${createHash('sha256').update(secret).digest('hex')}`,
            }
          : { mutation: 'REVOKE' },
    });
    const token = await csrf(runtime, session, participantAction.id);
    if (!token) return safeProblem('PC-AUTH-0005', request);
    const prepared = await ownerJson(
      await fetch(
        `${runtime.publicApiUrl}/v1/participants/${candidate.participantId}/first-administrator/prepare`,
        {
          method: 'POST',
          cache: 'no-store',
          headers: {
            ...publicHeaders(runtime, session),
            'Authorization': `Bearer ${session.sessionToken}`,
            'Content-Type': 'application/json',
            'X-CSRF-Token': token,
            'Idempotency-Key': candidate.idempotencyKey,
            'X-OpenPC-Aggregate-Version': candidate.expectedRevision,
            'OpenPC-Action-Intent-Digest': participantAction.digest,
          },
          body: JSON.stringify(candidate),
        },
      ).catch(() => undefined),
      z.strictObject({
        candidate: firstAdministratorChange,
        candidateDigest: digestSchema,
        expectedRevision: z.string(),
        actionIntentDigest: digestSchema,
      }),
      request,
    );
    if (isResponse(prepared)) return prepared;
    if (
      digest(prepared.candidate) !== digest(candidate) ||
      prepared.candidateDigest !== digest(candidate) ||
      prepared.expectedRevision !== candidate.expectedRevision ||
      prepared.actionIntentDigest !== participantAction.digest
    )
      return safeProblem('PC-INTEGRATION-5001', request);
    return NextResponse.json(
      {
        candidate,
        candidateDigest: prepared.candidateDigest,
        reviewToken: sealBffPayload(
          {
            candidate,
            custody,
            candidateDigest: prepared.candidateDigest,
            actor,
            sourcePrivacyDomainId: info.privacyDomainId,
            origin: request.headers.get('origin'),
            checkerPrincipalId: custody.checkerPrincipalId,
            reason: input.reason,
            secret,
            actionIntentDigest: participantAction.digest,
          },
          runtime.cookieKey,
          'participant-bootstrap-review',
        ),
        stepUp: {
          actionIntentId: participantAction.id,
          actionIntentDigest: participantAction.digest,
          resourceId: candidate.participantId,
          resourceDigest: prepared.candidateDigest,
        },
      },
      { status: 202, headers: noStore },
    );
  }
  if (input.command === 'PREPARE') {
    if (input.checkerPrincipalId === actor.principalId) return safeProblem('PC-AUTH-0002', request);
    const secret = randomBytes(32).toString('base64url'),
      id = () => responseIds().requestId;
    const candidate = firstAdministratorCreate.parse({
      participantId: id(),
      displayName: input.displayName,
      idempotencyKey: `participant-bootstrap-${randomUUID()}`,
      firstAdministrator: {
        invitationId: id(),
        mandateId: id(),
        privacyDomainId: id(),
        roleId: id(),
        authorityEnvelopeId: id(),
        assignmentId: id(),
        displayName: input.administratorName,
        recipientIssuer: input.recipientIssuer,
        recipientSubject: input.recipientSubject,
        recipientAudience: input.recipientAudience,
        tokenDigest: `sha256:${createHash('sha256').update(secret).digest('hex')}`,
        actionIntentIds: input.actionIntentIds,
        configuration: { 'participant.first_admin_invite_ttl': input.ttlMinutes * 60000 },
      },
    });
    const token = await csrf(runtime, session, createAction);
    if (!token) return safeProblem('PC-AUTH-0005', request);
    const prepared = await ownerJson(
      await fetch(`${runtime.publicApiUrl}/v1/participants/prepare`, {
        method: 'POST',
        cache: 'no-store',
        headers: {
          ...publicHeaders(runtime, session),
          'Authorization': `Bearer ${session.sessionToken}`,
          'Content-Type': 'application/json',
          'X-CSRF-Token': token,
          'Idempotency-Key': candidate.idempotencyKey,
          'X-OpenPC-Aggregate-Version': '0',
          'OpenPC-Action-Intent-Digest': info.actionIntentDigest,
        },
        body: JSON.stringify(candidate),
      }).catch(() => undefined),
      z.strictObject({
        candidate: firstAdministratorCreate,
        candidateDigest: digestSchema,
        expectedRevision: z.literal('0'),
        actionIntentDigest: digestSchema,
      }),
      request,
    );
    if (isResponse(prepared)) return prepared;
    if (
      digest(prepared.candidate) !== digest(candidate) ||
      prepared.candidateDigest !== digest(candidate) ||
      prepared.actionIntentDigest !== info.actionIntentDigest
    )
      return safeProblem('PC-INTEGRATION-5001', request);
    return NextResponse.json(
      {
        candidate,
        candidateDigest: prepared.candidateDigest,
        reviewToken: sealBffPayload(
          {
            candidate,
            candidateDigest: prepared.candidateDigest,
            actor,
            sourcePrivacyDomainId: info.privacyDomainId,
            origin: request.headers.get('origin'),
            checkerPrincipalId: input.checkerPrincipalId,
            reason: input.reason,
            secret,
            actionIntentDigest: info.actionIntentDigest,
          },
          runtime.cookieKey,
          'participant-bootstrap-review',
        ),
        stepUp: {
          actionIntentId: createAction,
          actionIntentDigest: info.actionIntentDigest,
          resourceId: candidate.participantId,
          resourceDigest: prepared.candidateDigest,
        },
      },
      { status: 202, headers: noStore },
    );
  }
  if (input.command === 'REVIEW' || input.command === 'APPROVE') {
    const detail = await proposal(
      runtime,
      session,
      input.resourceId,
      input.candidateDigest,
      request,
    );
    if (isResponse(detail)) return detail;
    const checked = await approval(runtime, session, input.approvalRequestId, request);
    if (isResponse(checked)) return checked;
    if (
      checked.candidateDigest !== detail.candidateDigest ||
      checked.checkerSubjectRef !== `urn:openpc:resource:${session.principalId}` ||
      checked.makerSubjectRef === checked.checkerSubjectRef
    )
      return safeProblem('PC-AUTH-0002', request);
    if (input.command === 'APPROVE')
      return approveGovernanceRequest(runtime, session, input.approvalRequestId, request);
    return NextResponse.json(
      {
        proposal: detail,
        approval: checked,
        stepUp: {
          actionIntentId: approvalDecisionAction.id,
          actionIntentDigest: approvalDecisionAction.digest,
          resourceId: input.approvalRequestId,
          resourceDigest: digest({
            actionIntentId: approvalDecisionAction.id,
            approvalRequestId: checked.approvalRequestId,
            candidateDigest: checked.candidateDigest,
            expectedRevision: checked.revision,
            decision: 'APPROVE',
          }),
        },
      },
      { headers: noStore },
    );
  }
  if (!reviewed) return safeProblem('PC-AUTH-0005', request);
  const value = reviewed;
  if (input.command === 'SUBMIT') {
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
          'Idempotency-Key': `${value.candidate.idempotencyKey}-request`,
          'X-OpenPC-Action-Intent-Digest': approvalCreateAction.digest,
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
    return NextResponse.json(
      { approvalRequestId: operation.resourceRef.slice(-36) },
      { status: 202, headers: noStore },
    );
  }
  if (input.command !== 'COMMIT') return safeProblem('PC-DATA-6004', request);
  const detail =
    original ??
    (await proposal(
      runtime,
      session,
      value.candidate.participantId,
      value.candidateDigest,
      request,
    ));
  if (isResponse(detail)) return detail;
  async function receipt(
    after: z.infer<typeof firstAdministratorCreationProposal>,
    value: z.infer<typeof reviewSchema>,
  ) {
    if (after.state !== 'CONSUMED' || !after.operationId) return undefined;
    if ('change' in value.candidate) {
      const candidate = value.candidate,
        before = value.custody;
      const saved = z
        .strictObject({ operationId: z.uuid(), result: firstAdministratorCustody })
        .safeParse(after.result);
      const rotating = candidate.change.mutation === 'ROTATE';
      if (
        !before ||
        !saved.success ||
        saved.data.operationId !== after.operationId ||
        saved.data.result.operationId !== after.operationId
      )
        return safeProblem('PC-INTEGRATION-5001', request);
      const result = saved.data.result;
      if (
        result.participantId !== candidate.participantId ||
        result.mandateId !== candidate.mandateId ||
        result.invitationId !== candidate.invitationId ||
        result.privacyDomainId !== before.privacyDomainId ||
        result.makerPrincipalId !== before.makerPrincipalId ||
        result.checkerPrincipalId !== before.checkerPrincipalId ||
        result.expiresAt !== before.expiresAt ||
        result.revision !== String(BigInt(candidate.expectedRevision) + 1n) ||
        result.custodyGeneration !==
          String(BigInt(candidate.custodyGeneration) + (rotating ? 1n : 0n)) ||
        result.tokenVersion !== String(BigInt(candidate.tokenVersion) + (rotating ? 1n : 0n)) ||
        result.state !== (rotating ? 'ACTIVE' : 'CANCELLED')
      )
        return safeProblem('PC-INTEGRATION-5001', request);
      const link = new URL('/govern/memberships?view=invitation-acceptance', value.origin);
      link.hash = new URLSearchParams({
        participantId: result.participantId,
        privacyDomainId: result.privacyDomainId,
        invitationId: result.invitationId,
        tokenVersion: result.tokenVersion,
        token: value.secret,
      }).toString();
      return NextResponse.json(
        {
          operationId: after.operationId,
          participantId: result.participantId,
          state: result.state,
          ...(rotating ? { invitationLink: link.href } : {}),
        },
        { headers: noStore },
      );
    }
    const candidate = value.candidate,
      first = candidate.firstAdministrator;
    const saved = z
      .strictObject({
        operationId: z.uuid(),
        result: z.strictObject({
          participantId: z.uuid(),
          displayName: z.string(),
          state: z.literal('PROVISIONING'),
          authorityEpoch: z.literal('0'),
          rowVersion: z.literal('1'),
          bootstrap: z.strictObject({
            mandateId: z.uuid(),
            invitationId: z.uuid(),
            privacyDomainId: z.uuid(),
            state: z.literal('ACTIVE'),
            expiresAt: z.string().datetime(),
            configuration: firstAdministratorCreate.shape.firstAdministrator.shape.configuration,
            issuanceAuthorityDigest: digestSchema,
          }),
        }),
      })
      .safeParse(after.result);
    if (
      !saved.success ||
      saved.data.operationId !== after.operationId ||
      saved.data.result.participantId !== candidate.participantId ||
      saved.data.result.displayName !== candidate.displayName ||
      saved.data.result.bootstrap.mandateId !== first.mandateId ||
      saved.data.result.bootstrap.invitationId !== first.invitationId ||
      saved.data.result.bootstrap.privacyDomainId !== first.privacyDomainId ||
      digest(saved.data.result.bootstrap.configuration) !== digest(first.configuration)
    )
      return safeProblem('PC-INTEGRATION-5001', request);
    const link = new URL('/govern/memberships?view=invitation-acceptance', value.origin);
    link.hash = new URLSearchParams({
      participantId: candidate.participantId,
      privacyDomainId: first.privacyDomainId,
      invitationId: first.invitationId,
      tokenVersion: '1',
      token: value.secret,
    }).toString();
    return NextResponse.json(
      {
        operationId: after.operationId,
        participantId: candidate.participantId,
        state: 'PROVISIONING',
        invitationLink: link.href,
      },
      { headers: noStore },
    );
  }
  if (detail.state === 'CONSUMED')
    return (await receipt(detail, value)) ?? safeProblem('PC-INTEGRATION-5001', request);
  const checked = await approval(runtime, session, input.approvalRequestId, request);
  if (isResponse(checked)) return checked;
  if (
    checked.state !== 'APPROVED' ||
    checked.candidateDigest !== value.candidateDigest ||
    checked.makerSubjectRef !== `urn:openpc:resource:${actor.principalId}` ||
    checked.checkerSubjectRef !== `urn:openpc:resource:${value.checkerPrincipalId}`
  )
    return safeProblem('PC-AUTH-0002', request);
  const mutationAction = 'change' in value.candidate ? participantAction.id : createAction;
  const token = await csrf(runtime, session, mutationAction);
  if (!token) return safeProblem('PC-AUTH-0005', request);
  await fetch(
    `${runtime.publicApiUrl}/v1/participants${'change' in value.candidate ? `/${value.candidate.participantId}/first-administrator/mutate` : ''}`,
    {
      method: 'POST',
      cache: 'no-store',
      headers: {
        ...publicHeaders(runtime, session),
        'Authorization': `Bearer ${session.sessionToken}`,
        'Content-Type': 'application/json',
        'X-CSRF-Token': token,
        'Idempotency-Key': value.candidate.idempotencyKey,
        'X-OpenPC-Aggregate-Version':
          'change' in value.candidate ? value.candidate.expectedRevision : '0',
        'OpenPC-Action-Intent-Digest': value.actionIntentDigest,
        'X-OpenPC-Approval-Request-ID': input.approvalRequestId,
      },
      body: JSON.stringify(value.candidate),
    },
  ).catch(() => undefined);
  const after = await proposal(
    runtime,
    session,
    value.candidate.participantId,
    value.candidateDigest,
    request,
  );
  if (isResponse(after)) return after;
  return (await receipt(after, value)) ?? safeProblem('PC-INTEGRATION-5001', request);
}
