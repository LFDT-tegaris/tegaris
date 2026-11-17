import { approvalCandidateResponseSchema } from '../../../../../../services/module-registry/src/approval-candidate-contract';
import { createHash, createPublicKey, randomUUID, X509Certificate } from 'node:crypto';
import { NextResponse, type NextRequest } from 'next/server';
import { z } from 'zod';
import {
  workloadCandidate,
  workloadCandidates,
  workloadCertificate,
  workloadId,
  workloadProposal,
  workloadReview,
} from '../../../../lib/workload-workflow';
import { recoveryActor } from '../../../../lib/recovery-workflow';
import {
  discoveryApprovalResume,
  discoveryApprovalResumeReason,
  discoveryCertificateRecoveryReceiptView,
  discoveryCertificateRotationCandidate,
} from '../../../../../../services/identity-service/src/contracts/discovery-certificate-recovery';
import { actorBinding } from './local-recovery-model';
import {
  approval,
  approvalCreateAction,
  approvalDecisionAction,
  approvalUpdateAction,
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
  identityCsrf,
  identityOwnerHeaders,
  openBffPayload,
  parsePublicCommand,
  localOwnerFetch,
  safeProblem,
  sameOrigin,
  sealBffPayload,
  type IdentitySession,
  type LocalConfig,
} from './local-runtime';
const noStore = { 'Cache-Control': 'no-store' };
const uuid = z.uuid();
const discoveryRecovery = z.strictObject({
  enrollmentId: z.uuidv7(),
  recoveryId: z.uuidv7(),
  privacyDomainId: z.uuidv7(),
});
const sealed = workloadReview
  .extend({
    actor: recoveryActor,
    origin: z.url(),
    idempotencyKey: z.string().min(16).max(128),
    discoveryRecovery: discoveryRecovery.optional(),
    resumeRequest: discoveryApprovalResume.optional(),
    resumeIdempotencyKey: z.string().min(16).max(128).optional(),
  })
  .strict();
type Review = z.infer<typeof sealed>;
const preview = z.discriminatedUnion('mutation', [
  z.strictObject({
    mutation: z.literal('ISSUE'),
    credentialId: uuid,
    principalId: uuid,
    workloadId,
    publicKeySpkiDer: z.string().min(1).max(4096),
  }),
  z.strictObject({
    mutation: z.literal('ROTATE'),
    replacedCredentialId: uuid,
    credentialId: uuid,
    publicKeySpkiDer: z.string().min(1).max(4096),
  }),
  z.strictObject({ mutation: z.literal('REVOKE'), credentialId: uuid }),
]);
const ordinaryCommands = z.discriminatedUnion('command', [
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
    candidateDigest: workloadReview.shape.candidateDigest,
    expectedRevision: workloadReview.shape.expectedRevision,
  }),
]);
const commands = z.discriminatedUnion('command', [
  ordinaryCommands.options[0].extend({
    discoveryRecovery: discoveryRecovery.optional(),
    originalReviewToken: z.string().min(80).max(65536).optional(),
    originalApprovalRequestId: uuid.optional(),
  }),
  z.strictObject({
    command: z.literal('RESUME'),
    reviewToken: z.string().min(80).max(65536),
    discoveryRecovery,
  }),
  ordinaryCommands.options[1].extend({ discoveryRecovery: discoveryRecovery.optional() }),
  ordinaryCommands.options[2].extend({ discoveryRecovery: discoveryRecovery.optional() }),
  ordinaryCommands.options[3].extend({ discoveryRecovery: discoveryRecovery.optional() }),
]);
function responseReview(value: Review, runtime: LocalConfig) {
  return {
    reviewToken: sealBffPayload(value, runtime.cookieKey, 'workload-review'),
    review: workloadReview.strip().parse(value),
  };
}
async function approvalCandidate(
  runtime: LocalConfig,
  session: IdentitySession,
  id: string,
  request: NextRequest,
) {
  return ownerJson(
    await localOwnerFetch(
      `${runtime.publicApiUrl}/api/v1/approval-requests/${encodeURIComponent('urn:openpc:resource:' + id)}/candidate`,
      {
        cache: 'no-store',
        headers: publicHeaders(runtime, session),
      },
    ).catch(() => undefined),
    approvalCandidateResponseSchema,
    request,
  );
}
function nativeCandidateMatches(
  value: z.infer<typeof approvalCandidateResponseSchema>,
  receipt: z.infer<typeof discoveryCertificateRecoveryReceiptView>,
  actor: z.infer<typeof recoveryActor>,
) {
  const body = discoveryCertificateRotationCandidate(receipt.intent.certificateRecovery);
  return (
    value.actionIntentId === participantAction.id &&
    value.resourceRef ===
      `urn:openpc:resource:${receipt.intent.certificateRecovery.predecessorCredentialId}` &&
    value.candidateDigest === digest(body) &&
    digest(value.candidate) === digest(body) &&
    value.expectedRevision === receipt.intent.certificateRecovery.predecessorRevision &&
    value.runtimePermission === 'NONE' &&
    value.operationRef === null &&
    !!value.attemptId &&
    !!value.attempt &&
    typeof value.businessIdempotencyKey === 'string' &&
    actor.principalId === receipt.intent.administrators[0].principalId
  );
}
async function resumedReview(
  runtime: LocalConfig,
  session: IdentitySession,
  original: z.infer<typeof approvalCandidateResponseSchema>,
  actor: z.infer<typeof recoveryActor>,
  recovery: z.infer<typeof discoveryRecovery>,
  receipt: z.infer<typeof discoveryCertificateRecoveryReceiptView>,
  origin: string,
  request: NextRequest,
) {
  if (!original.successorApprovalRef || !nativeCandidateMatches(original, receipt, actor))
    return safeProblem('PC-DATA-6007', request);
  const id = original.successorApprovalRef.slice(-36);
  const current = await approval(runtime, session, id, request);
  if (isResponse(current)) return current;
  const next = await approvalCandidate(runtime, session, id, request);
  if (isResponse(next)) return next;
  if (
    !nativeCandidateMatches(next, receipt, actor) ||
    !next.makerSessionMatches ||
    next.predecessorApprovalRef !== original.approvalRequestId ||
    BigInt(next.attempt!) !== BigInt(original.attempt!) + 1n ||
    next.businessIdempotencyKey !== original.businessIdempotencyKey ||
    next.successorApprovalRef !== null ||
    !['REQUESTED', 'APPROVED'].includes(current.state) ||
    current.makerSubjectRef !== `urn:openpc:resource:${actor.principalId}` ||
    current.checkerSubjectRef !==
      `urn:openpc:resource:${receipt.intent.administrators[1].principalId}` ||
    current.candidateDigest !== next.candidateDigest
  )
    return safeProblem('PC-DATA-6007', request);
  const value: Review = {
    mutation: 'ROTATE',
    candidate: workloadCandidates.ROTATE.parse(next.candidate),
    resourceId: receipt.intent.certificateRecovery.predecessorCredentialId,
    expectedRevision: next.expectedRevision,
    candidateDigest: next.candidateDigest,
    checkerPrincipalId: receipt.intent.administrators[1].principalId,
    reason: discoveryApprovalResumeReason,
    expiresAt: next.expiresAt,
    actor,
    origin,
    discoveryRecovery: recovery,
    idempotencyKey: next.businessIdempotencyKey!,
    stepUp: {
      actionIntentId: participantAction.id,
      actionIntentDigest: participantAction.digest,
      resourceId: receipt.intent.certificateRecovery.predecessorCredentialId,
      resourceDigest: next.candidateDigest,
    },
  };
  return { value, current, next };
}
async function readOwner<T>(
  runtime: LocalConfig,
  session: IdentitySession,
  path: string,
  schema: z.ZodType<T>,
  request: NextRequest,
) {
  return ownerJson(
    await localOwnerFetch(`${runtime.publicApiUrl}/v1/identity/${path}`, {
      cache: 'no-store',
      headers: publicHeaders(runtime, session),
    }).catch(() => undefined),
    schema,
    request,
  );
}
async function certificate(
  runtime: LocalConfig,
  session: IdentitySession,
  credentialId: string,
  request: NextRequest,
  recovery?: z.infer<typeof discoveryRecovery>,
) {
  const value = await readOwner(
    runtime,
    session,
    `workloads/${credentialId}/certificate${recovery ? `?${new URLSearchParams({ recoveryEnrollmentId: recovery.enrollmentId, recoveryId: recovery.recoveryId })}` : ''}`,
    workloadCertificate,
    request,
  );
  if (isResponse(value)) return value;
  if (
    value.credentialId !== credentialId ||
    value.participantId !== session.participantId ||
    value.uriSan !==
      `urn:openpc:participant:${value.participantId}:workload:${value.workloadId.slice(-36)}`
  )
    return safeProblem('PC-INTEGRATION-5001', request);
  if (value.certificateDer !== null) {
    try {
      const der = Buffer.from(value.certificateDer, 'base64'),
        cert = new X509Certificate(der);
      const key = cert.publicKey.export({ format: 'der', type: 'spki' });
      if (
        der.toString('base64') !== value.certificateDer ||
        !cert.raw.equals(der) ||
        `sha256:${createHash('sha256').update(der).digest('hex')}` !==
          value.certificateFingerprint ||
        `sha256:${createHash('sha256').update(key).digest('hex')}` !== value.keyId ||
        cert.subjectAltName !== `URI:${value.uriSan}` ||
        new Date(cert.validFrom).toISOString() !== value.notBefore ||
        new Date(cert.validTo).toISOString() !== value.notAfter
      )
        return safeProblem('PC-INTEGRATION-5001', request);
    } catch {
      return safeProblem('PC-INTEGRATION-5001', request);
    }
  }
  return value;
}
async function discoveryPreapproval(
  runtime: LocalConfig,
  session: IdentitySession,
  receipt: z.infer<typeof discoveryCertificateRecoveryReceiptView>,
  request: NextRequest,
) {
  const candidate = discoveryCertificateRotationCandidate(receipt.intent.certificateRecovery);
  const binding = {
    expectedRevision: receipt.intent.certificateRecovery.predecessorRevision,
    makerPrincipalId: receipt.intent.administrators[0].principalId,
    preapprovalResourceId: receipt.intent.certificateRecovery.predecessorCredentialId,
    preapprovalRecoveryId: receipt.recoveryId,
    preapprovalEnrollmentId: receipt.enrollmentId,
  };
  const result = await readOwner(
    runtime,
    session,
    `workload-proposals/${encodeURIComponent(digest(candidate))}?${new URLSearchParams(binding)}`,
    z.discriminatedUnion('preapprovalState', [
      z.strictObject({ preapprovalState: z.literal('ABSENT') }),
      z.strictObject({ preapprovalState: z.literal('PRESENT'), proposal: workloadProposal }),
    ]),
    request,
  );
  if (isResponse(result)) return result;
  if (
    result.preapprovalState === 'PRESENT' &&
    (result.proposal.candidateDigest !== digest(candidate) ||
      digest(result.proposal.candidate) !== digest(candidate) ||
      result.proposal.resourceId !== binding.preapprovalResourceId ||
      result.proposal.expectedRevision !== binding.expectedRevision ||
      result.proposal.makerPrincipalId !== binding.makerPrincipalId ||
      result.proposal.catalogOperationId !== 'ID-OP-WORKLOAD-ROTATE')
  )
    return safeProblem('PC-INTEGRATION-5001', request);
  return result;
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
    `workload-proposals/${encodeURIComponent(candidateDigest)}?${new URLSearchParams(binding)}`,
    workloadProposal,
    request,
  );
  if (isResponse(value)) return value;
  const mutation = value.catalogOperationId.slice('ID-OP-WORKLOAD-'.length) as Review['mutation'];
  return value.candidateDigest === candidateDigest &&
    digest(value.candidate) === candidateDigest &&
    workloadCandidates[mutation].safeParse(value.candidate).success &&
    value.resourceId ===
      ('replacedCredentialId' in value.candidate
        ? value.candidate.replacedCredentialId
        : value.candidate.credentialId) &&
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
) {
  const token = await csrf(runtime, session, participantAction.id);
  if (!token) return undefined;
  const candidate = value.candidate;
  const body =
    value.mutation === 'ISSUE' && 'principalId' in candidate
      ? {
          credentialId: candidate.credentialId,
          principalId: candidate.principalId,
          workloadId: candidate.workloadId,
          publicKeySpkiDer: candidate.publicKeySpkiDer,
        }
      : value.mutation === 'ROTATE' && 'publicKeySpkiDer' in candidate
        ? { credentialId: candidate.credentialId, publicKeySpkiDer: candidate.publicKeySpkiDer }
        : {};
  const path = !approvalId
    ? 'workloads/prepare'
    : value.mutation === 'ISSUE'
      ? 'workloads'
      : `workloads/${value.resourceId}/${value.mutation.toLowerCase()}`;
  return localOwnerFetch(`${runtime.publicApiUrl}/v1/identity/${path}`, {
    method: 'POST',
    cache: 'no-store',
    headers: {
      ...publicHeaders(runtime, session),
      'Content-Type': 'application/json',
      'X-CSRF-Token': token,
      'Idempotency-Key': value.idempotencyKey,
      'X-OpenPC-Aggregate-Version': value.expectedRevision,
      'OpenPC-Action-Intent-Digest': participantAction.digest,
      ...(approvalId ? { 'X-OpenPC-Approval-Request-ID': approvalId } : {}),
    },
    body: JSON.stringify(
      approvalId
        ? body
        : {
            ...body,
            mutation: value.mutation,
            ...(value.mutation === 'ROTATE' ? { replacedCredentialId: value.resourceId } : {}),
            ...(value.mutation === 'REVOKE' ? { credentialId: value.resourceId } : {}),
          },
    ),
  }).catch(() => undefined);
}
async function readDiscoveryCase(
  runtime: LocalConfig,
  session: IdentitySession,
  recovery: z.infer<typeof discoveryRecovery>,
  request: NextRequest,
) {
  if (session.contextMode !== 'PLATFORM') return safeProblem('PC-AUTH-0005', request);
  let browserOrigin: string;
  try {
    const host = request.headers.get('host');
    if (!host) throw new Error('Missing request host');
    const supplied = request.headers.get('origin');
    const external = new URL(supplied ?? `${new URL(request.url).protocol}//${host}`);
    if (
      !['http:', 'https:'].includes(external.protocol) ||
      external.host !== host ||
      external.username ||
      external.password ||
      (supplied !== null && external.origin !== supplied)
    )
      throw new Error('Invalid browser origin');
    browserOrigin = external.origin;
  } catch {
    return safeProblem('PC-AUTH-0002', request);
  }
  const token = await identityCsrf(runtime, session, participantAction.id);
  if (!token) return safeProblem('PC-AUTH-0005', request);
  const receipt = await ownerJson(
    await localOwnerFetch(
      `${runtime.identityUrl}/v1/identity/discovery-certificate-recovery/enrollments/${recovery.enrollmentId}/commands`,
      {
        method: 'POST',
        cache: 'no-store',
        headers: {
          ...identityOwnerHeaders(runtime, session, browserOrigin),
          'X-CSRF-Token': token,
        },
        body: JSON.stringify({
          privacyDomainId: recovery.privacyDomainId,
          command: { kind: 'READ', recoveryId: recovery.recoveryId },
        }),
      },
    ).catch(() => undefined),
    discoveryCertificateRecoveryReceiptView,
    request,
  );
  if (isResponse(receipt)) return receipt;
  if (
    receipt.enrollmentId !== recovery.enrollmentId ||
    receipt.recoveryId !== recovery.recoveryId ||
    receipt.intent.enrollmentId !== recovery.enrollmentId ||
    receipt.intent.recoveryId !== recovery.recoveryId
  )
    return safeProblem('PC-INTEGRATION-5001', request);
  return receipt;
}
async function completedDiscovery(
  runtime: LocalConfig,
  session: IdentitySession,
  recovery: z.infer<typeof discoveryRecovery>,
  receipt: z.infer<typeof discoveryCertificateRecoveryReceiptView>,
  request: NextRequest,
) {
  if (receipt.state !== 'COMPLETED' || !receipt.completion || receipt.authority !== 'NONE')
    return undefined;
  const readback = await certificate(
    runtime,
    session,
    receipt.completion.successorCredentialId,
    request,
    recovery,
  );
  if (isResponse(readback)) return readback;
  if (readback.certificateFingerprint !== receipt.completion.certificateFingerprint)
    return safeProblem('PC-INTEGRATION-5001', request);
  return NextResponse.json(
    { truthState: 'SUCCESS', operationId: receipt.completion.operationId, readback },
    { headers: noStore },
  );
}
async function completed(
  runtime: LocalConfig,
  session: IdentitySession,
  value: Review,
  detail: z.infer<typeof workloadProposal>,
  request: NextRequest,
) {
  if (detail.state !== 'CONSUMED' || !detail.operationId) return undefined;
  const readback = await certificate(runtime, session, value.candidate.credentialId, request);
  if (isResponse(readback)) return readback;
  if (
    'publicKeySpkiDer' in value.candidate &&
    readback.keyId !==
      `sha256:${createHash('sha256').update(Buffer.from(value.candidate.publicKeySpkiDer, 'base64')).digest('hex')}`
  )
    return safeProblem('PC-INTEGRATION-5001', request);
  return NextResponse.json(
    { truthState: 'SUCCESS', operationId: detail.operationId, readback },
    { headers: noStore },
  );
}
export async function mutateWorkloadWorkbench(request: NextRequest) {
  const runtime = await localRuntimeConfig().catch(() => undefined);
  if (!runtime) return safeProblem('PC-AUTH-0005', request);
  if (!sameOrigin(request) || !hasJsonContentType(request.headers.get('content-type')))
    return safeProblem('PC-AUTH-0002', request);
  let session = await authenticated(request, runtime);
  if (!session) return safeProblem('PC-AUTH-0005', request);
  const parsed = commands.safeParse(parsePublicCommand(await request.text()));
  if (!parsed.success) return safeProblem('PC-DATA-6004', request);
  const input = parsed.data,
    origin = request.headers.get('origin')!;
  let actor = actorBinding(session);
  let recoveryReceipt: z.infer<typeof discoveryCertificateRecoveryReceiptView> | undefined;
  if (input.discoveryRecovery) {
    const receipt = await readDiscoveryCase(runtime, session, input.discoveryRecovery, request);
    if (isResponse(receipt)) return receipt;
    if (
      receipt.enrollmentId !== input.discoveryRecovery.enrollmentId ||
      receipt.recoveryId !== input.discoveryRecovery.recoveryId ||
      !receipt.intent.administrators.some((admin) => admin.principalId === session!.principalId)
    )
      return safeProblem('PC-AUTH-0005', request);
    // Privacy is a request scope verified by the actual enrolled READ owner;
    // the opaque session remains PLATFORM and conveys no Participant grant.
    session = { ...session, privacyDomainId: input.discoveryRecovery.privacyDomainId };
    actor = recoveryActor.parse({
      sessionId: session.sessionId,
      principalId: session.principalId,
      participantId: session.participantId,
      privacyDomainId: input.discoveryRecovery.privacyDomainId,
      contextEpoch: session.contextEpoch,
    });
    recoveryReceipt = receipt;
    if (
      receipt.state !== 'COMPLETED' &&
      (receipt.state !== 'ACTIVE' ||
        receipt.authority !== 'DISCOVERY_CERTIFICATE_REPLACEMENT_ONLY' ||
        Date.parse(receipt.intent.validUntil) <= Date.now())
    )
      return safeProblem('PC-AUTH-0005', request);
    if (
      input.command === 'APPROVE'
        ? session.principalId !== receipt.intent.administrators[1].principalId
        : session.principalId !== receipt.intent.administrators[0].principalId
    )
      return safeProblem('PC-AUTH-0005', request);
  }
  if (!actor) return safeProblem('PC-AUTH-0005', request);
  if (input.command === 'PREPARE') {
    if (recoveryReceipt && input.input.mutation !== 'ROTATE')
      return safeProblem('PC-AUTH-0005', request);
    if (
      input.expectedSessionId !== actor.sessionId ||
      input.checkerPrincipalId === actor.principalId
    )
      return safeProblem('PC-AUTH-0005', request);
    const change = input.input;
    if ('publicKeySpkiDer' in change) {
      try {
        const bytes = Buffer.from(change.publicKeySpkiDer, 'base64');
        if (
          bytes.toString('base64') !== change.publicKeySpkiDer ||
          !Buffer.from(
            createPublicKey({ key: bytes, format: 'der', type: 'spki' }).export({
              format: 'der',
              type: 'spki',
            }),
          ).equals(bytes)
        )
          return safeProblem('PC-DATA-6004', request);
      } catch {
        return safeProblem('PC-DATA-6004', request);
      }
    }
    let expectedRevision = '0';
    let candidate: z.infer<typeof workloadCandidate>;
    const resourceId =
      change.mutation === 'ROTATE' ? change.replacedCredentialId : change.credentialId;
    if (change.mutation === 'ISSUE') {
      const principal = await readOwner(
        runtime,
        session,
        `principals/${change.principalId}`,
        z.object({
          effect: z.object({
            principalId: uuid,
            participantId: uuid,
            state: z.string(),
            kind: z.string(),
          }),
        }),
        request,
      );
      if (isResponse(principal)) return principal;
      if (
        principal.effect.principalId !== change.principalId ||
        principal.effect.participantId !== actor.participantId ||
        principal.effect.kind !== 'WORKLOAD' ||
        principal.effect.state !== 'ACTIVE'
      )
        return safeProblem('PC-DATA-6007', request);
      candidate = workloadCandidates.ISSUE.parse({
        credentialId: change.credentialId,
        principalId: change.principalId,
        workloadId: change.workloadId,
        publicKeySpkiDer: change.publicKeySpkiDer,
        participantId: actor.participantId,
      });
    } else if (recoveryReceipt) {
      if (
        change.mutation !== 'ROTATE' ||
        digest({
          replacedCredentialId: change.replacedCredentialId,
          credentialId: change.credentialId,
          publicKeySpkiDer: change.publicKeySpkiDer,
        }) !==
          digest(
            discoveryCertificateRotationCandidate(recoveryReceipt.intent.certificateRecovery),
          ) ||
        input.checkerPrincipalId !== recoveryReceipt.intent.administrators[1].principalId ||
        recoveryReceipt.state !== 'ACTIVE'
      )
        return safeProblem('PC-AUTH-0005', request);
      expectedRevision = recoveryReceipt.intent.certificateRecovery.predecessorRevision;
      candidate = discoveryCertificateRotationCandidate(recoveryReceipt.intent.certificateRecovery);
    } else {
      const current = await certificate(runtime, session, resourceId, request);
      if (isResponse(current)) return current;
      if (
        !['ACTIVE', 'ROTATING', 'ISSUED'].includes(current.state) ||
        (change.mutation === 'ROTATE' &&
          (current.state !== 'ACTIVE' || change.credentialId === resourceId))
      )
        return safeProblem('PC-DATA-6007', request);
      expectedRevision = current.revision;
      candidate =
        change.mutation === 'ROTATE'
          ? workloadCandidates.ROTATE.parse({
              replacedCredentialId: resourceId,
              credentialId: change.credentialId,
              publicKeySpkiDer: change.publicKeySpkiDer,
            })
          : { credentialId: resourceId, state: 'REVOKED' };
    }
    if (recoveryReceipt && !input.originalReviewToken) {
      const original = await discoveryPreapproval(runtime, session, recoveryReceipt, request);
      if (isResponse(original)) return original;
      if (original.preapprovalState !== 'ABSENT') return safeProblem('PC-DATA-6007', request);
    }
    let idempotencyKey = `workload-${randomUUID()}`;
    let resumeRequest: z.infer<typeof discoveryApprovalResume> | undefined;
    let resumeAttempt: string | undefined;
    if (input.originalReviewToken) {
      const original = sealed.safeParse(
        openBffPayload(input.originalReviewToken, runtime.cookieKey, 'workload-review'),
      );
      if (
        !recoveryReceipt ||
        !input.discoveryRecovery ||
        !original.success ||
        !original.data.discoveryRecovery ||
        original.data.discoveryRecovery.recoveryId === input.discoveryRecovery.recoveryId ||
        original.data.origin !== origin ||
        original.data.actor.principalId !== actor.principalId ||
        original.data.actor.participantId !== actor.participantId ||
        original.data.actor.privacyDomainId !== actor.privacyDomainId ||
        original.data.mutation !== 'ROTATE' ||
        original.data.resourceId !== resourceId ||
        original.data.expectedRevision !== expectedRevision ||
        original.data.candidateDigest !== digest(candidate) ||
        digest(original.data.candidate) !== digest(candidate) ||
        original.data.checkerPrincipalId !== input.checkerPrincipalId ||
        original.data.reason !== input.reason
      )
        return safeProblem('PC-AUTH-0005', request);
      const previous = await readDiscoveryCase(
        runtime,
        session,
        original.data.discoveryRecovery,
        request,
      );
      if (isResponse(previous)) return previous;
      if (
        previous.state !== 'EXPIRED' ||
        previous.authority !== 'NONE' ||
        previous.completion ||
        digest(previous.intent.certificateRecovery) !==
          digest(recoveryReceipt.intent.certificateRecovery)
      )
        return safeProblem('PC-DATA-6007', request);
      if (input.originalApprovalRequestId) {
        if (recoveryReceipt.intent.schemaVersion !== 2) return safeProblem('PC-AUTH-0005', request);
        const current = await approval(runtime, session, input.originalApprovalRequestId, request);
        if (isResponse(current)) return current;
        const retained = await approvalCandidate(
          runtime,
          session,
          input.originalApprovalRequestId,
          request,
        );
        if (isResponse(retained)) return retained;
        if (
          !nativeCandidateMatches(retained, recoveryReceipt, actor) ||
          !retained.canRequestResume ||
          retained.successorApprovalRef !== null ||
          retained.businessIdempotencyKey !== original.data.idempotencyKey ||
          current.candidateDigest !== original.data.candidateDigest ||
          current.makerSubjectRef !== `urn:openpc:resource:${actor.principalId}` ||
          current.checkerSubjectRef !== `urn:openpc:resource:${input.checkerPrincipalId}` ||
          !['REQUESTED', 'APPROVED', 'EXPIRED'].includes(current.state)
        )
          return safeProblem('PC-DATA-6007', request);
        resumeAttempt = retained.attempt!;
        resumeRequest = discoveryApprovalResume.parse({
          command: 'RESUME',
          actionIntentId: approvalUpdateAction.id,
          actionIntentDigest: approvalUpdateAction.digest,
          expectedRevision: current.revision,
          predecessorCandidateId: retained.attemptId,
          expectedAttempt: retained.attempt,
          candidateDigest: retained.candidateDigest,
          reason: discoveryApprovalResumeReason,
        });
      } else {
        const retained = await proposal(
          runtime,
          session,
          original.data.candidateDigest,
          { expectedRevision, makerPrincipalId: actor.principalId },
          request,
        );
        if (isResponse(retained)) return retained;
        if (
          retained.state !== 'PROPOSED' ||
          retained.approval ||
          retained.operationId !== null ||
          retained.resourceId !== resourceId ||
          retained.catalogOperationId !== 'ID-OP-WORKLOAD-ROTATE' ||
          retained.makerPrincipalId !== actor.principalId ||
          digest(retained.candidate) !== digest(candidate)
        )
          return safeProblem('PC-DATA-6007', request);
      }
      // A new receiving review retains the original business key. It does not
      // revive the old review, session, case, approval or authenticator proof.
      idempotencyKey = original.data.idempotencyKey;
    }
    if (input.originalApprovalRequestId && !resumeRequest)
      return safeProblem('PC-DATA-6004', request);
    const value: Review = {
      ...(resumeRequest
        ? {
            resumeRequest,
            resumeIdempotencyKey: `discovery-resume-${randomUUID()}`,
            resumeDraft: {
              approvalRequestId: input.originalApprovalRequestId!,
              expectedAttempt: resumeAttempt!,
            },
          }
        : {}),
      mutation: change.mutation,
      ...(input.discoveryRecovery ? { discoveryRecovery: input.discoveryRecovery } : {}),
      candidate,
      resourceId,
      expectedRevision,
      candidateDigest: digest(candidate),
      actor,
      origin,
      checkerPrincipalId: input.checkerPrincipalId,
      reason: input.reason,
      expiresAt:
        recoveryReceipt?.intent.validUntil ?? new Date(Date.now() + 15 * 60 * 1000).toISOString(),
      idempotencyKey,
      stepUp: resumeRequest
        ? {
            actionIntentId: approvalUpdateAction.id,
            actionIntentDigest: approvalUpdateAction.digest,
            resourceId: input.originalApprovalRequestId!,
            resourceDigest: digest({
              ...resumeRequest,
              approvalRequestId: `urn:openpc:resource:${input.originalApprovalRequestId}`,
            }),
          }
        : {
            actionIntentId: participantAction.id,
            actionIntentDigest: participantAction.digest,
            resourceId,
            resourceDigest: digest(candidate),
          },
    };
    return NextResponse.json(responseReview(value, runtime), { headers: noStore });
  }
  if (input.command === 'APPROVE') {
    if (
      recoveryReceipt &&
      (recoveryReceipt.state !== 'ACTIVE' ||
        input.candidateDigest !==
          digest(discoveryCertificateRotationCandidate(recoveryReceipt.intent.certificateRecovery)))
    )
      return safeProblem('PC-AUTH-0005', request);
    const current = await approval(runtime, session, input.approvalRequestId, request);
    if (isResponse(current)) return current;
    if (
      current.checkerSubjectRef !== `urn:openpc:resource:${actor.principalId}` ||
      current.makerSubjectRef === current.checkerSubjectRef
    )
      return safeProblem('PC-AUTH-0005', request);
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
    openBffPayload(input.reviewToken, runtime.cookieKey, 'workload-review'),
  );
  if (
    !opened.success ||
    digest(opened.data.actor) !== digest(actor) ||
    opened.data.origin !== origin ||
    digest(opened.data.discoveryRecovery ?? null) !== digest(input.discoveryRecovery ?? null)
  )
    return safeProblem('PC-AUTH-0005', request);
  const value = opened.data;
  if (
    recoveryReceipt &&
    (value.mutation !== 'ROTATE' ||
      value.candidateDigest !==
        digest(discoveryCertificateRotationCandidate(recoveryReceipt.intent.certificateRecovery)) ||
      value.expectedRevision !== recoveryReceipt.intent.certificateRecovery.predecessorRevision ||
      value.checkerPrincipalId !== recoveryReceipt.intent.administrators[1].principalId)
  )
    return safeProblem('PC-AUTH-0005', request);
  if (recoveryReceipt && input.discoveryRecovery) {
    const prior = await completedDiscovery(
      runtime,
      session,
      input.discoveryRecovery,
      recoveryReceipt,
      request,
    );
    if (prior) return prior;
  }
  if (input.command === 'RESUME') {
    if (
      !recoveryReceipt ||
      !input.discoveryRecovery ||
      recoveryReceipt.intent.schemaVersion !== 2 ||
      !value.resumeDraft ||
      !value.resumeRequest ||
      !value.resumeIdempotencyKey ||
      Date.parse(value.expiresAt) <= Date.now()
    )
      return safeProblem('PC-AUTH-0005', request);
    const original = await approvalCandidate(
      runtime,
      session,
      value.resumeDraft.approvalRequestId,
      request,
    );
    if (isResponse(original)) return original;
    if (
      !nativeCandidateMatches(original, recoveryReceipt, actor) ||
      original.businessIdempotencyKey !== value.idempotencyKey ||
      original.attempt !== value.resumeDraft.expectedAttempt
    )
      return safeProblem('PC-DATA-6007', request);
    // Reconcile an already committed exact child before any transport retry.
    if (!original.successorApprovalRef) {
      const token = await csrf(runtime, session, approvalUpdateAction.id);
      if (!token) return safeProblem('PC-AUTH-0005', request);
      const response = await localOwnerFetch(
        `${runtime.publicApiUrl}/api/v1/approval-requests/${encodeURIComponent(original.approvalRequestId)}`,
        {
          method: 'PATCH',
          cache: 'no-store',
          headers: {
            ...publicHeaders(runtime, session),
            'Content-Type': 'application/json',
            'X-CSRF-Token': token,
            'Idempotency-Key': value.resumeIdempotencyKey,
            'X-OpenPC-Action-Intent-Digest': approvalUpdateAction.digest,
            'OpenPC-Action-Intent-Digest': approvalUpdateAction.digest,
            'If-Match': `"${digest({ resourceId: value.resumeDraft.approvalRequestId, revision: value.resumeRequest.expectedRevision })}"`,
          },
          body: JSON.stringify(value.resumeRequest),
        },
      ).catch(() => undefined);
      const operation = await ownerJson(response, publicOperationSchema, request);
      if (isResponse(operation)) return operation;
      if (
        response?.status !== 202 ||
        operation.actionIntentId !== approvalUpdateAction.id ||
        operation.idempotencyKey !== value.resumeIdempotencyKey
      )
        return safeProblem('PC-INTEGRATION-5001', request);
      const after = await approvalCandidate(
        runtime,
        session,
        value.resumeDraft.approvalRequestId,
        request,
      );
      if (isResponse(after)) return after;
      if (after.successorApprovalRef !== operation.resourceRef)
        return safeProblem('PC-INTEGRATION-5001', request);
      const restored = await resumedReview(
        runtime,
        session,
        after,
        actor,
        input.discoveryRecovery,
        recoveryReceipt,
        origin,
        request,
      );
      if (isResponse(restored)) return restored;
      return NextResponse.json(
        { ...responseReview(restored.value, runtime), approval: restored.current },
        { status: 202, headers: noStore },
      );
    }
    const restored = await resumedReview(
      runtime,
      session,
      original,
      actor,
      input.discoveryRecovery,
      recoveryReceipt,
      origin,
      request,
    );
    return isResponse(restored)
      ? restored
      : NextResponse.json(
          { ...responseReview(restored.value, runtime), approval: restored.current },
          { status: 202, headers: noStore },
        );
  }
  if (value.resumeDraft || value.resumeRequest || value.resumeIdempotencyKey)
    return safeProblem('PC-DATA-6007', request);
  if (input.command === 'SUBMIT') {
    if (Date.parse(value.expiresAt) <= Date.now()) return safeProblem('PC-DATA-6007', request);
    const staged = await write(runtime, session, value);
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
      detail.catalogOperationId !== `ID-OP-WORKLOAD-${value.mutation}`
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
    detail.catalogOperationId !== `ID-OP-WORKLOAD-${value.mutation}`
  )
    return safeProblem('PC-DATA-6007', request);
  const prior = await completed(runtime, session, value, detail, request);
  if (prior) return prior;
  if (Date.parse(value.expiresAt) <= Date.now()) return safeProblem('PC-DATA-6007', request);
  const result = await write(runtime, session, value, input.approvalRequestId);
  if (input.discoveryRecovery) {
    const after = await readDiscoveryCase(runtime, session, input.discoveryRecovery, request);
    if (!isResponse(after)) {
      const saved = await completedDiscovery(
        runtime,
        session,
        input.discoveryRecovery,
        after,
        request,
      );
      if (saved) return saved;
    }
    if (!result || result.ok)
      return NextResponse.json(
        { truthState: 'WRITE_AMBIGUITY' },
        { status: 202, headers: noStore },
      );
    return ownerFailure(result, request);
  }
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

export async function readWorkloadWorkbench(request: NextRequest) {
  const runtime = await localRuntimeConfig().catch(() => undefined);
  if (!runtime) return safeProblem('PC-AUTH-0005', request);
  const session = await authenticated(request, runtime);
  if (!session) return safeProblem('PC-AUTH-0005', request);
  // Discovery privacy is an explicit owner-verified request scope, not a
  // Participant session grant. Compare the actual session before that overlay.
  const binding = (value: IdentitySession) => ({
    sessionId: value.sessionId,
    principalId: value.principalId,
    participantId: value.participantId,
    contextMode: value.contextMode,
    privacyDomainId: value.privacyDomainId ?? null,
    contextEpoch: value.contextEpoch,
  });
  const originalBinding = digest(binding(session));
  const response = await readWorkloadForSession(request, runtime, session);
  if (!response.ok || !request.nextUrl.searchParams.has('recoveryEnrollmentId')) return response;
  const current = await authenticated(request, runtime);
  if (!current || digest(binding(current)) !== originalBinding)
    return safeProblem('PC-AUTH-0005', request);
  return response;
}

async function readWorkloadForSession(
  request: NextRequest,
  runtime: LocalConfig,
  session: IdentitySession,
) {
  const query = z
    .strictObject({
      lane: z.enum(['maker', 'checker']).default('checker'),
      cursor: z.string().max(8192).optional(),
      credentialId: uuid.optional(),
      originalApprovalRequestId: uuid.optional(),
      candidateDigest: workloadReview.shape.candidateDigest.optional(),
      expectedRevision: workloadReview.shape.expectedRevision.optional(),
      recoveryEnrollmentId: z.uuidv7().optional(),
      recoveryId: z.uuidv7().optional(),
      privacyDomainId: z.uuidv7().optional(),
    })
    .superRefine((value, ctx) => {
      const present = [value.recoveryEnrollmentId, value.recoveryId, value.privacyDomainId].filter(
        Boolean,
      ).length;
      if (present !== 0 && present !== 3)
        ctx.addIssue({ code: 'custom', message: 'Incomplete discovery read binding' });
      if (
        (value.candidateDigest === undefined) !== (value.expectedRevision === undefined) ||
        (value.candidateDigest && (present !== 0 || value.originalApprovalRequestId)) ||
        ((value.originalApprovalRequestId || value.candidateDigest) &&
          (value.credentialId || value.cursor))
      )
        ctx.addIssue({ code: 'custom', message: 'Conflicting original operation selectors' });
    })
    .safeParse(Object.fromEntries(request.nextUrl.searchParams));
  if (
    !query.success ||
    [...request.nextUrl.searchParams.keys()].length !==
      new Set(request.nextUrl.searchParams.keys()).size
  )
    return safeProblem('PC-DATA-6004', request);
  let actor = actorBinding(session);
  let recovery: z.infer<typeof discoveryRecovery> | undefined;
  let recoveryReceipt: z.infer<typeof discoveryCertificateRecoveryReceiptView> | undefined;
  if (query.data.recoveryEnrollmentId && query.data.recoveryId && query.data.privacyDomainId) {
    recovery = {
      enrollmentId: query.data.recoveryEnrollmentId,
      recoveryId: query.data.recoveryId,
      privacyDomainId: query.data.privacyDomainId,
    };
    const receipt = await readDiscoveryCase(runtime, session, recovery, request);
    if (isResponse(receipt)) return receipt;
    recoveryReceipt = receipt;
    if (!receipt.intent.administrators.some((admin) => admin.principalId === session!.principalId))
      return safeProblem('PC-AUTH-0005', request);
    session = { ...session, privacyDomainId: recovery.privacyDomainId };
    actor = recoveryActor.parse({
      sessionId: session.sessionId,
      principalId: session.principalId,
      participantId: session.participantId,
      privacyDomainId: recovery.privacyDomainId,
      contextEpoch: session.contextEpoch,
    });
    const completed = await completedDiscovery(runtime, session, recovery, receipt, request);
    if (completed) return completed;
    if (
      receipt.state !== 'ACTIVE' ||
      receipt.authority !== 'DISCOVERY_CERTIFICATE_REPLACEMENT_ONLY' ||
      Date.parse(receipt.intent.validUntil) <= Date.now()
    )
      return safeProblem('PC-AUTH-0005', request);
  }
  if (!actor) return safeProblem('PC-AUTH-0005', request);
  if (!recovery && (query.data.originalApprovalRequestId || query.data.candidateDigest)) {
    // An exact owner read works independently of catalogue pagination and of
    // browser storage. It confers no replacement-session mutation authority.
    let originalId = query.data.originalApprovalRequestId;
    if (query.data.candidateDigest) {
      const original = await proposal(
        runtime,
        session,
        query.data.candidateDigest,
        { expectedRevision: query.data.expectedRevision!, makerPrincipalId: actor.principalId },
        request,
      );
      if (isResponse(original)) return original;
      if (
        original.makerPrincipalId !== actor.principalId ||
        original.expectedRevision !== query.data.expectedRevision
      )
        return safeProblem('PC-INTEGRATION-5001', request);
      originalId = original.approval?.approvalRequestId;
      if (!originalId) {
        const currentSession = await authenticated(request, runtime);
        if (!currentSession || digest(actorBinding(currentSession)) !== digest(actor))
          return safeProblem('PC-AUTH-0005', request);
        return NextResponse.json(
          { actor, approvals: [], nextCursor: null, preapprovalState: 'PRESENT' },
          { headers: noStore },
        );
      }
    }
    const current = await approval(runtime, session, originalId!, request);
    if (isResponse(current)) return current;
    if (
      current.approvalRequestId !== `urn:openpc:resource:${originalId}` ||
      ![current.makerSubjectRef, current.checkerSubjectRef].includes(
        `urn:openpc:resource:${actor.principalId}`,
      )
    )
      return safeProblem('PC-AUTH-0005', request);
    const original = await proposal(
      runtime,
      session,
      current.candidateDigest,
      { approvalRequestId: originalId! },
      request,
    );
    if (isResponse(original)) return original;
    const detail = original;
    if (
      current.makerSubjectRef !== `urn:openpc:resource:${detail.makerPrincipalId}` ||
      (query.data.candidateDigest &&
        (detail.candidateDigest !== query.data.candidateDigest ||
          detail.expectedRevision !== query.data.expectedRevision))
    )
      return safeProblem('PC-INTEGRATION-5001', request);
    const currentSession = await authenticated(request, runtime);
    if (!currentSession || digest(actorBinding(currentSession)) !== digest(actor))
      return safeProblem('PC-AUTH-0005', request);
    return NextResponse.json(
      {
        actor,
        approvals: [
          {
            ...current,
            proposal: detail,
            stepUp: {
              actionIntentId: approvalDecisionAction.id,
              actionIntentDigest: approvalDecisionAction.digest,
              resourceId: originalId!,
              resourceDigest: digest({
                actionIntentId: approvalDecisionAction.id,
                approvalRequestId: current.approvalRequestId,
                candidateDigest: current.candidateDigest,
                expectedRevision: current.revision,
                decision: 'APPROVE',
              }),
            },
          },
        ],
        nextCursor: null,
      },
      { headers: noStore },
    );
  }
  if (query.data.credentialId) {
    const result = await certificate(runtime, session, query.data.credentialId, request, recovery);
    if (!recovery && !isResponse(result)) {
      const currentSession = await authenticated(request, runtime);
      if (!currentSession || digest(actorBinding(currentSession)) !== digest(actor))
        return safeProblem('PC-AUTH-0005', request);
    }
    return isResponse(result) ? result : NextResponse.json(result, { headers: noStore });
  }
  if (query.data.originalApprovalRequestId) {
    if (
      !recoveryReceipt ||
      !recovery ||
      recoveryReceipt.intent.schemaVersion !== 2 ||
      actor.principalId !== recoveryReceipt.intent.administrators[0].principalId
    )
      return safeProblem('PC-AUTH-0005', request);
    const original = await approvalCandidate(
      runtime,
      session,
      query.data.originalApprovalRequestId,
      request,
    );
    if (isResponse(original)) return original;
    if (!nativeCandidateMatches(original, recoveryReceipt, actor))
      return safeProblem('PC-DATA-6007', request);
    if (original.successorApprovalRef) {
      const restored = await resumedReview(
        runtime,
        session,
        original,
        actor,
        recovery,
        recoveryReceipt,
        request.nextUrl.origin,
        request,
      );
      if (isResponse(restored)) return restored;
      const detail = await proposal(
        runtime,
        session,
        restored.next.candidateDigest,
        { approvalRequestId: restored.current.approvalRequestId.slice(-36) },
        request,
      );
      if (isResponse(detail)) return detail;
      return NextResponse.json(
        {
          actor,
          restoredReview: {
            ...responseReview(restored.value, runtime),
            approvalRequestId: restored.current.approvalRequestId.slice(-36),
          },
          approvals: [
            {
              ...restored.current,
              proposal: detail,
              stepUp: {
                actionIntentId: approvalDecisionAction.id,
                actionIntentDigest: approvalDecisionAction.digest,
                resourceId: restored.current.approvalRequestId.slice(-36),
                resourceDigest: digest({
                  actionIntentId: approvalDecisionAction.id,
                  approvalRequestId: restored.current.approvalRequestId,
                  candidateDigest: restored.current.candidateDigest,
                  expectedRevision: restored.current.revision,
                  decision: 'APPROVE',
                }),
              },
            },
          ],
          nextCursor: null,
          preapprovalState: 'PRESENT',
        },
        { headers: noStore },
      );
    }
    return NextResponse.json(
      { actor, approvals: [], nextCursor: null, preapprovalState: 'PRESENT' },
      { headers: noStore },
    );
  }
  if (recoveryReceipt) {
    if (query.data.cursor) return safeProblem('PC-DATA-6004', request);
    const intent = recoveryReceipt.intent;
    const expected = discoveryCertificateRotationCandidate(intent.certificateRecovery);
    const candidateDigest = digest(expected);
    const original = await discoveryPreapproval(runtime, session, recoveryReceipt, request);
    if (isResponse(original)) return original;
    if (original.preapprovalState === 'ABSENT')
      return NextResponse.json(
        { actor, approvals: [], nextCursor: null, preapprovalState: 'ABSENT' },
        { headers: noStore },
      );
    const detail = original.proposal;
    if (!detail.approval)
      return NextResponse.json(
        { actor, approvals: [], nextCursor: null, preapprovalState: 'PRESENT' },
        { headers: noStore },
      );
    const current = await approval(runtime, session, detail.approval.approvalRequestId, request);
    if (isResponse(current)) return current;
    if (
      current.candidateDigest !== candidateDigest ||
      current.makerSubjectRef !== `urn:openpc:resource:${intent.administrators[0].principalId}` ||
      current.checkerSubjectRef !== `urn:openpc:resource:${intent.administrators[1].principalId}`
    )
      return safeProblem('PC-INTEGRATION-5001', request);
    const stepUp = {
      actionIntentId: approvalDecisionAction.id,
      actionIntentDigest: approvalDecisionAction.digest,
      resourceId: detail.approval.approvalRequestId,
      resourceDigest: digest({
        actionIntentId: approvalDecisionAction.id,
        approvalRequestId: current.approvalRequestId,
        candidateDigest,
        expectedRevision: current.revision,
        decision: 'APPROVE',
      }),
    };
    return NextResponse.json(
      {
        actor,
        approvals: [{ ...current, proposal: detail, stepUp }],
        nextCursor: null,
        preapprovalState: 'PRESENT',
      },
      { headers: noStore },
    );
  }
  const params = new URLSearchParams({
    limit: '50',
    sort: '-updatedAt',
    filter: `${query.data.lane === 'maker' ? 'makerSubjectRef' : 'checkerSubjectRef'}:eq:urn:openpc:resource:${actor.principalId}`,
    ...(query.data.cursor ? { cursor: query.data.cursor } : {}),
  });
  const page = await ownerJson(
    await localOwnerFetch(`${runtime.publicApiUrl}/api/v1/approval-requests?${params}`, {
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
  if (!recovery) {
    const currentSession = await authenticated(request, runtime);
    if (!currentSession || digest(actorBinding(currentSession)) !== digest(actor))
      return safeProblem('PC-AUTH-0005', request);
  }
  return NextResponse.json({ actor, approvals, nextCursor: page.nextCursor }, { headers: noStore });
}
