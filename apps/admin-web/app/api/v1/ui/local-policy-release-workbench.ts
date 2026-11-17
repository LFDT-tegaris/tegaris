import { createHash } from 'node:crypto';

import { NextResponse, type NextRequest } from 'next/server';
import { z } from 'zod';
import { policyActivationPreviewSchema } from '../../../../../../services/module-registry/src/policy-activation-preview';

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

const digestSchema = z.string().regex(/^sha256:[0-9a-f]{64}$/u);
const uuidSchema = z.uuid();
const reviewMaximumAgeMs = 30 * 60 * 1000;
const stagePreviewCommand = z.strictObject({
  command: z.literal('PREVIEW_OCCURRENCE'),
  releaseId: z.uuidv7(),
  expectedRevision: z.string().regex(/^[1-9][0-9]*$/u),
  reason: z.string().trim().min(10).max(1024),
  resourceReservationId: z.uuidv7().optional(),
});
const stageReviewSchema = z.strictObject({
  version: z.literal(1),
  issuedAt: z.number().int().nonnegative(),
  sessionId: uuidSchema,
  principalId: uuidSchema,
  contextEpoch: z.string().regex(/^[1-9][0-9]*$/u),
  participantId: uuidSchema,
  privacyDomainId: uuidSchema,
  preview: policyActivationPreviewSchema,
  reason: z.string().min(10).max(1024),
  resourceReservationId: z.uuidv7().optional(),
  idempotencyKey: z.string().min(16).max(128),
});
const noStoreHeaders = { 'Cache-Control': 'no-store' } as const;

const actions = {
  approvalCreate: {
    id: 'ACT-APPROVAL_REQUESTS_CREATE_RESOURCE-V1',
    digest: 'sha256:c86183ee9e432405de0d145e007846fc9511a43bec274a055ad43b1ccbc207f9',
  },
  approvalDecide: {
    id: 'ACT-POLICY_APPROVE_REQUEST-V1',
    digest: 'sha256:460403d23ce1c8fb48362b045fb558200fb3ea7ab73469546730b067c1d63cd8',
  },
  releaseCreate: {
    id: 'ACT-RELEASE_BUNDLES_CREATE_RESOURCE-V1',
    digest: 'sha256:c5269bf64e0bad8b0dda285a0a1040592038bcd6ab6541c58998a3e40bb512c0',
  },
  publish: {
    id: 'ACT-POLICY_ACTIVATE_PUBLISH-V1',
    digest: 'sha256:69027f899349c765077f9a9dfdc7868bb92c653a071347251d22c8bcf87c4edb',
  },
  occurrenceCreate: {
    id: 'ACT-ACTIVATION_OCCURRENCES_CREATE_RESOURCE-V1',
    digest: 'sha256:ab25e0e1acc4faa65753906943f99e359ef60e4f90cd70f8cfb72bfd4e9c0dfd',
  },
  activate: {
    id: 'ACT-POLICY_ACTIVATE_RELEASE-V1',
    digest: 'sha256:6dd0e7edc1933d43beb79a0156559f9fc56f729fbc761cfb7770dd50bce8734c',
  },
  rollback: {
    id: 'ACT-POLICY_ROLLBACK_RELEASE-V1',
    digest: 'sha256:d5bc5ec3e43562a072ee107859df6803c0394add98d9e1837bf5b8074689914d',
  },
  recover: {
    id: 'ACT-FLEET_RECOVER_OCCURRENCE-V1',
    digest: 'sha256:4dac3f1679a92c185899c5142e16f23d465b043112781f1686853a8e7679ab1d',
  },
  retire: {
    id: 'ACT-RELEASE_BUNDLES_UPDATE_RESOURCE-V1',
    digest: 'sha256:eb4b0823bc1d02a92a62e3f6dd7faa3d74f92f6297141d05cc5b1c9ca1939512',
  },
} as const;

const previewSchema = z
  .object({
    command: z.literal('PREVIEW'),
    checkerPrincipalId: uuidSchema.optional(),
    policyVersionId: uuidSchema,
    manifestDigest: digestSchema,
    dependencyClosureDigest: digestSchema,
    reason: z.string().trim().min(10).max(1024),
  })
  .strict();
const commandSchema = z.discriminatedUnion('command', [
  z.object({ command: z.literal('SUBMIT_APPROVAL'), reviewToken: z.string().min(80) }).strict(),
  z.object({ command: z.literal('CREATE_RELEASE'), reviewToken: z.string().min(80) }).strict(),
  z
    .object({
      command: z.literal('CREATE_OCCURRENCE'),
      reviewToken: z.string().min(80),
      releaseId: uuidSchema,
    })
    .strict(),
  z.object({ command: z.literal('APPROVE'), approvalId: uuidSchema }).strict(),
  z.object({ command: z.literal('PUBLISH'), releaseId: uuidSchema }).strict(),
  z.object({ command: z.literal('ACTIVATE'), occurrenceId: uuidSchema }).strict(),
  z.object({ command: z.literal('ROLLBACK'), occurrenceId: uuidSchema }).strict(),
  z.object({ command: z.literal('RECOVER'), occurrenceId: uuidSchema }).strict(),
  z.object({ command: z.literal('RETIRE'), releaseId: uuidSchema }).strict(),
]);
const reviewSchema = z
  .object({
    version: z.literal(1),
    issuedAt: z.number().int().nonnegative(),
    sessionId: uuidSchema,
    principalId: uuidSchema,
    checkerPrincipalId: uuidSchema,
    contextEpoch: z.string().regex(/^[1-9][0-9]*$/u),
    policyVersionId: uuidSchema,
    manifestDigest: digestSchema,
    dependencyClosureDigest: digestSchema,
    reason: z.string().min(10).max(1024),
    idempotencyRoot: z.string().min(16).max(128),
  })
  .strict();
const policyVersionSchema = z
  .object({
    policyVersionId: z.string(),
    normalizedPolicyDigest: digestSchema,
    dependencyClosureDigest: digestSchema,
  })
  .passthrough();
const approvalSchema = z
  .object({
    approvalRequestId: z.string(),
    candidateDigest: digestSchema,
    makerSubjectRef: z.string(),
    checkerSubjectRef: z.string().nullable(),
    state: z.string(),
    revision: z.string(),
  })
  .passthrough();
const releaseSchema = z
  .object({
    releaseBundleId: z.string(),
    manifestDigest: digestSchema,
    dependencyClosureDigest: digestSchema,
    state: z.string(),
    revision: z.string(),
  })
  .passthrough();
const occurrenceSchema = z
  .object({
    activationOccurrenceId: z.string(),
    releaseBundleId: z.string(),
    targetGenerationDigest: digestSchema,
    exactCohortDigest: digestSchema,
    state: z.string(),
    revision: z.string(),
  })
  .passthrough();

type Review = z.infer<typeof reviewSchema>;

function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`)
    .join(',')}}`;
}

function digest(value: unknown): string {
  return `sha256:${createHash('sha256').update(canonicalJson(value)).digest('hex')}`;
}

function contextAdmitted(session: IdentitySession): session is IdentitySession & {
  readonly privacyDomainId: string;
} {
  return session.contextMode === 'PARTICIPANT' && session.privacyDomainId !== undefined;
}

function publicHeaders(runtime: LocalConfig, session: IdentitySession, ids = responseIds()) {
  return {
    'Cookie': `__Host-openpc_session=${session.sessionToken}`,
    'OpenPC-API-Version': '1',
    'OpenPC-Participant-ID': `urn:openpc:participant:${session.participantId}`,
    'OpenPC-Privacy-Domain-ID': `urn:openpc:privacy-domain:${session.privacyDomainId}`,
    'X-Request-ID': ids.requestId,
    'X-Correlation-ID': ids.correlationId,
    'Origin': new URL(runtime.publicApiUrl).origin,
  };
}

async function csrf(runtime: LocalConfig, session: IdentitySession, actionIntentId: string) {
  const response = await fetch(`${runtime.publicApiUrl}/api/v1/session/csrf`, {
    method: 'POST',
    cache: 'no-store',
    headers: {
      'Cookie': `__Host-openpc_session=${session.sessionToken}`,
      'Content-Type': 'application/json',
      'Origin': new URL(runtime.publicApiUrl).origin,
    },
    body: JSON.stringify({ actionIntentId }),
  }).catch(() => undefined);
  if (!response?.ok || !hasJsonContentType(response.headers.get('content-type'))) return undefined;
  const parsed = z.object({ csrfToken: z.string().min(32) }).safeParse(await response.json());
  return parsed.success ? parsed.data.csrfToken : undefined;
}

function ownerFailure(response: Response | undefined, request: NextRequest) {
  if (!response) return safeProblem('PC-INTEGRATION-5001', request);
  if (response.status === 409) return safeProblem('PC-RUNTIME-3007', request);
  if (response.status === 412 || response.status === 428)
    return safeProblem('PC-DATA-6007', request);
  if (response.status === 400 || response.status === 422)
    return safeProblem('PC-DATA-6004', request);
  if ([401, 403, 404].includes(response.status)) return safeProblem('PC-AUTH-0005', request);
  return safeProblem('PC-INTEGRATION-5001', request);
}

async function ownerJson<T>(
  response: Response | undefined,
  schema: z.ZodType<T>,
  request: NextRequest,
): Promise<T | NextResponse> {
  if (!response?.ok || !hasJsonContentType(response.headers.get('content-type')))
    return ownerFailure(response, request);
  const parsed = schema.safeParse(await response.json());
  return parsed.success ? parsed.data : safeProblem('PC-INTEGRATION-5001', request);
}

function isResponse(value: unknown): value is NextResponse {
  return value instanceof Response;
}

async function readOwner<T>(
  runtime: LocalConfig,
  session: IdentitySession,
  path: string,
  schema: z.ZodType<T>,
  request: NextRequest,
) {
  const response = await fetch(`${runtime.publicApiUrl}${path}`, {
    cache: 'no-store',
    headers: publicHeaders(runtime, session, responseIds(request)),
  }).catch(() => undefined);
  return ownerJson(response, schema, request);
}

async function mutateOwner(
  runtime: LocalConfig,
  session: IdentitySession,
  request: NextRequest,
  input: {
    readonly action: (typeof actions)[keyof typeof actions];
    readonly path: string;
    readonly body: Record<string, unknown>;
    readonly idempotencyKey: string;
    readonly method?: 'POST' | 'PATCH';
    readonly etag?: string;
  },
) {
  const token = await csrf(runtime, session, input.action.id);
  if (!token) return safeProblem('PC-AUTH-0005', request);
  const ids = responseIds(request);
  const response = await fetch(`${runtime.publicApiUrl}${input.path}`, {
    method: input.method ?? 'POST',
    cache: 'no-store',
    headers: {
      ...publicHeaders(runtime, session, ids),
      'Content-Type': 'application/json',
      'X-CSRF-Token': token,
      'Idempotency-Key': input.idempotencyKey,
      'X-OpenPC-Action-Intent-Digest': input.action.digest,
      'OpenPC-Action-Intent-Digest': input.action.digest,
      ...(input.etag ? { 'If-Match': input.etag } : {}),
    },
    body: JSON.stringify({
      ...input.body,
      actionIntentId: input.action.id,
      actionIntentDigest: input.action.digest,
    }),
  }).catch(() => undefined);
  if (!response?.ok || !hasJsonContentType(response.headers.get('content-type')))
    return ownerFailure(response, request);
  return NextResponse.json(await response.json(), { status: 202, headers: noStoreHeaders });
}

function openReview(token: string, runtime: LocalConfig, session: IdentitySession) {
  const parsed = reviewSchema.safeParse(
    openBffPayload(token, runtime.cookieKey, 'policy-release-review'),
  );
  if (
    !parsed.success ||
    parsed.data.issuedAt > Date.now() ||
    Date.now() - parsed.data.issuedAt >= reviewMaximumAgeMs ||
    parsed.data.sessionId !== session.sessionId ||
    parsed.data.principalId !== session.principalId ||
    parsed.data.contextEpoch !== session.contextEpoch
  )
    return undefined;
  return parsed.data;
}

function reviewResponse(review: Review, runtime: LocalConfig) {
  return {
    reviewToken: sealBffPayload(review, runtime.cookieKey, 'policy-release-review'),
    review: {
      policyVersionId: review.policyVersionId,
      checkerPrincipalId: review.checkerPrincipalId,
      manifestDigest: review.manifestDigest,
      dependencyClosureDigest: review.dependencyClosureDigest,
      reason: review.reason,
    },
  };
}

function stepUp(
  action: (typeof actions)[keyof typeof actions],
  resourceId: string,
  resourceDigest: string,
) {
  return {
    actionIntentId: action.id,
    actionIntentDigest: action.digest,
    resourceId,
    resourceDigest,
  };
}

export async function readPolicyReleaseWorkbench(request: NextRequest) {
  const runtime = await localRuntimeConfig().catch(() => undefined);
  if (!runtime) return undefined;
  const session = await authenticated(request, runtime);
  if (!session || !contextAdmitted(session)) return safeProblem('PC-AUTH-0005', request);
  const approvalId = request.nextUrl.searchParams.get('approvalId');
  const releaseId = request.nextUrl.searchParams.get('releaseId');
  const occurrenceId = request.nextUrl.searchParams.get('occurrenceId');
  if (
    [approvalId, releaseId, occurrenceId].some(
      (id) => id !== null && !uuidSchema.safeParse(id).success,
    )
  )
    return safeProblem('PC-DATA-6004', request);
  const approval = approvalId
    ? await readOwner(
        runtime,
        session,
        `/api/v1/approval-requests/urn:openpc:resource:${approvalId}`,
        approvalSchema,
        request,
      )
    : undefined;
  if (isResponse(approval)) return approval;
  const release = releaseId
    ? await readOwner(
        runtime,
        session,
        `/api/v1/release-bundles/urn:openpc:resource:${releaseId}`,
        releaseSchema,
        request,
      )
    : undefined;
  if (isResponse(release)) return release;
  const occurrence = occurrenceId
    ? await readOwner(
        runtime,
        session,
        `/api/v1/activation-occurrences/urn:openpc:resource:${occurrenceId}`,
        occurrenceSchema,
        request,
      )
    : undefined;
  if (isResponse(occurrence)) return occurrence;
  return NextResponse.json(
    {
      actor: {
        role: session.role,
        sessionId: session.sessionId,
        principalId: session.principalId,
        participantId: session.participantId,
        privacyDomainId: session.privacyDomainId,
        contextEpoch: session.contextEpoch,
      },
      ...(approval ? { approval } : {}),
      ...(release ? { release } : {}),
      ...(occurrence ? { occurrence } : {}),
      ...(approval?.state === 'REQUESTED' &&
      approval.checkerSubjectRef === `urn:openpc:resource:${session.principalId}` &&
      approval.makerSubjectRef !== `urn:openpc:resource:${session.principalId}`
        ? {
            approvalStepUp: stepUp(
              actions.approvalDecide,
              approvalId!,
              digest({
                actionIntentId: actions.approvalDecide.id,
                approvalRequestId: approval.approvalRequestId,
                candidateDigest: approval.candidateDigest,
                expectedRevision: approval.revision,
                decision: 'APPROVE',
              }),
            ),
          }
        : {}),
      ...(release?.state === 'DRAFT'
        ? {
            publishStepUp: stepUp(
              actions.publish,
              releaseId!,
              digest({
                actionIntentId: actions.publish.id,
                targetRef: release.releaseBundleId,
                manifestDigest: release.manifestDigest,
                dependencyClosureDigest: release.dependencyClosureDigest,
                expectedRevision: release.revision,
              }),
            ),
          }
        : {}),
      ...(occurrence &&
      ['REQUESTED', 'ACTIVE_MATCHED', 'FAILED', 'PARTIAL'].includes(occurrence.state)
        ? {
            occurrenceStepUp: stepUp(
              occurrence.state === 'REQUESTED'
                ? actions.activate
                : occurrence.state === 'ACTIVE_MATCHED'
                  ? actions.rollback
                  : actions.recover,
              occurrenceId!,
              digest({
                actionIntentId:
                  occurrence.state === 'REQUESTED'
                    ? actions.activate.id
                    : occurrence.state === 'ACTIVE_MATCHED'
                      ? actions.rollback.id
                      : actions.recover.id,
                targetRef: occurrence.activationOccurrenceId,
                targetGenerationDigest: occurrence.targetGenerationDigest,
                exactCohortDigest: occurrence.exactCohortDigest,
                expectedRevision: occurrence.revision,
              }),
            ),
          }
        : {}),
    },
    { headers: noStoreHeaders },
  );
}

export async function mutatePolicyReleaseWorkbench(request: NextRequest) {
  const runtime = await localRuntimeConfig().catch(() => undefined);
  if (!runtime || !sameOrigin(request) || !hasJsonContentType(request.headers.get('content-type')))
    return safeProblem('PC-AUTH-0002', request);
  const session = await authenticated(request, runtime);
  if (!session || !contextAdmitted(session)) return safeProblem('PC-AUTH-0005', request);
  const raw = parsePublicCommand(await request.text());
  const stagePreview = stagePreviewCommand.safeParse(raw);
  if (stagePreview.success) {
    const source = await readOwner(
      runtime,
      session,
      `/api/v1/release-bundles/urn:openpc:resource:${stagePreview.data.releaseId}/activation-preview`,
      policyActivationPreviewSchema,
      request,
    );
    if (isResponse(source)) return source;
    const current = await authenticated(request, runtime);
    if (
      !current ||
      current.sessionId !== session.sessionId ||
      current.principalId !== session.principalId ||
      current.contextEpoch !== session.contextEpoch ||
      current.participantId !== session.participantId ||
      current.privacyDomainId !== session.privacyDomainId ||
      source.releaseBundleId !== `urn:openpc:resource:${stagePreview.data.releaseId}` ||
      source.releaseRevision !== stagePreview.data.expectedRevision
    )
      return safeProblem('PC-DATA-6007', request);
    const sealed = stageReviewSchema.parse({
      version: 1,
      issuedAt: Date.now(),
      sessionId: session.sessionId,
      principalId: session.principalId,
      contextEpoch: session.contextEpoch,
      participantId: session.participantId,
      privacyDomainId: session.privacyDomainId,
      preview: source,
      reason: stagePreview.data.reason,
      resourceReservationId: stagePreview.data.resourceReservationId,
      idempotencyKey: `policy-stage-${responseIds().requestId}`,
    });
    return NextResponse.json(
      {
        stageReviewToken: sealBffPayload(
          sealed,
          runtime.cookieKey,
          'policy-activation-stage-review',
        ),
        preview: source,
      },
      { status: 201, headers: noStoreHeaders },
    );
  }
  const stage = z
    .strictObject({
      command: z.literal('STAGE_OCCURRENCE'),
      stageReviewToken: z.string().min(80).max(65536),
    })
    .safeParse(raw);
  if (stage.success) {
    const parsedStage = stageReviewSchema.safeParse(
      openBffPayload(
        stage.data.stageReviewToken,
        runtime.cookieKey,
        'policy-activation-stage-review',
      ),
    );
    if (
      !parsedStage.success ||
      parsedStage.data.issuedAt > Date.now() ||
      Date.now() - parsedStage.data.issuedAt >= reviewMaximumAgeMs ||
      parsedStage.data.sessionId !== session.sessionId ||
      parsedStage.data.principalId !== session.principalId ||
      parsedStage.data.contextEpoch !== session.contextEpoch ||
      parsedStage.data.participantId !== session.participantId ||
      parsedStage.data.privacyDomainId !== session.privacyDomainId
    )
      return safeProblem('PC-DATA-6007', request);
    const value = parsedStage.data;
    return mutateOwner(runtime, session, request, {
      action: actions.occurrenceCreate,
      path: '/api/v1/activation-occurrences',
      idempotencyKey: value.idempotencyKey,
      body: {
        releaseBundleId: value.preview.releaseBundleId,
        targetGenerationDigest: value.preview.targetGenerationDigest,
        matchedTargetCount: value.preview.matchedTargetCount,
        totalTargetCount: value.preview.totalTargetCount,
        activationPreviewDigest: value.preview.activationPreviewDigest,
        resourceReservationId: value.resourceReservationId,
        reason: value.reason,
      },
    });
  }
  const preview = previewSchema.safeParse(raw);
  if (preview.success) {
    // Preserve the original local fixture default only in its original context.
    // All other makers select an explicit checker; the public owner verifies eligibility.
    const checkerPrincipalId =
      preview.data.checkerPrincipalId ??
      (session.principalId === '018f0000-0000-7000-8000-000000000111' &&
      session.participantId === '018f0000-0000-7000-8000-000000000101' &&
      session.privacyDomainId === '018f0000-0000-7000-8000-000000000201'
        ? '018f0000-0000-7000-8000-000000000112'
        : undefined);
    if (!checkerPrincipalId || checkerPrincipalId === session.principalId)
      return safeProblem('PC-DATA-6004', request);
    const versionRef = `urn:openpc:policy-version:${preview.data.policyVersionId}`;
    const version = await readOwner(
      runtime,
      session,
      `/api/v1/policy-versions/${versionRef}`,
      policyVersionSchema,
      request,
    );
    if (isResponse(version)) return version;
    if (
      version.policyVersionId !== versionRef ||
      version.normalizedPolicyDigest !== preview.data.manifestDigest ||
      version.dependencyClosureDigest !== preview.data.dependencyClosureDigest
    )
      return safeProblem('PC-DATA-6007', request);
    const review = reviewSchema.parse({
      version: 1,
      issuedAt: Date.now(),
      sessionId: session.sessionId,
      principalId: session.principalId,
      checkerPrincipalId,
      contextEpoch: session.contextEpoch,
      policyVersionId: preview.data.policyVersionId,
      manifestDigest: preview.data.manifestDigest,
      dependencyClosureDigest: preview.data.dependencyClosureDigest,
      reason: preview.data.reason,
      idempotencyRoot: `policy-release-${responseIds().requestId}`,
    });
    return NextResponse.json(reviewResponse(review, runtime), {
      status: 201,
      headers: noStoreHeaders,
    });
  }
  const parsed = commandSchema.safeParse(raw);
  if (!parsed.success) return safeProblem('PC-DATA-6004', request);
  const command = parsed.data;
  if ('reviewToken' in command) {
    const review = openReview(command.reviewToken, runtime, session);
    if (!review) return safeProblem('PC-DATA-6007', request);
    if (command.command === 'SUBMIT_APPROVAL') {
      return mutateOwner(runtime, session, request, {
        action: actions.approvalCreate,
        path: '/api/v1/approval-requests',
        idempotencyKey: `${review.idempotencyRoot}-approval`,
        body: {
          candidateDigest: review.manifestDigest,
          makerSubjectRef: `urn:openpc:resource:${session.principalId}`,
          checkerSubjectRef: `urn:openpc:resource:${review.checkerPrincipalId}`,
          reason: review.reason,
        },
      });
    }
    if (command.command === 'CREATE_RELEASE') {
      return mutateOwner(runtime, session, request, {
        action: actions.releaseCreate,
        path: '/api/v1/release-bundles',
        idempotencyKey: `${review.idempotencyRoot}-release`,
        body: {
          participantId: `urn:openpc:participant:${session.participantId}`,
          manifestDigest: review.manifestDigest,
          dependencyClosureDigest: review.dependencyClosureDigest,
          reason: review.reason,
        },
      });
    }
    const source = await readOwner(
      runtime,
      session,
      `/api/v1/release-bundles/urn:openpc:resource:${command.releaseId}/activation-preview`,
      policyActivationPreviewSchema,
      request,
    );
    if (isResponse(source)) return source;
    if (
      source.targetGenerationDigest !== review.manifestDigest ||
      source.dependencyClosureDigest !== review.dependencyClosureDigest
    )
      return safeProblem('PC-DATA-6007', request);
    return mutateOwner(runtime, session, request, {
      action: actions.occurrenceCreate,
      path: '/api/v1/activation-occurrences',
      idempotencyKey: `${review.idempotencyRoot}-occurrence`,
      body: {
        releaseBundleId: `urn:openpc:resource:${command.releaseId}`,
        targetGenerationDigest: review.manifestDigest,
        matchedTargetCount: source.matchedTargetCount,
        totalTargetCount: source.totalTargetCount,
        activationPreviewDigest: source.activationPreviewDigest,
        reason: review.reason,
      },
    });
  }
  if (command.command === 'APPROVE') {
    const approval = await readOwner(
      runtime,
      session,
      `/api/v1/approval-requests/urn:openpc:resource:${command.approvalId}`,
      approvalSchema,
      request,
    );
    if (isResponse(approval)) return approval;
    const inputDigest = digest({
      actionIntentId: actions.approvalDecide.id,
      approvalRequestId: approval.approvalRequestId,
      candidateDigest: approval.candidateDigest,
      expectedRevision: approval.revision,
      decision: 'APPROVE',
    });
    return mutateOwner(runtime, session, request, {
      action: actions.approvalDecide,
      path: `/api/v1/approval-requests/${approval.approvalRequestId}/approve`,
      idempotencyKey: `policy-workbench-approve-${command.approvalId}`,
      etag: `"${digest({ resourceId: command.approvalId, revision: approval.revision })}"`,
      body: {
        targetRef: approval.approvalRequestId,
        inputDigest,
        expectedRevision: approval.revision,
        reason: 'Distinct checker approved the immutable policy review.',
      },
    });
  }
  if (command.command === 'PUBLISH') {
    const release = await readOwner(
      runtime,
      session,
      `/api/v1/release-bundles/urn:openpc:resource:${command.releaseId}`,
      releaseSchema,
      request,
    );
    if (isResponse(release)) return release;
    const inputDigest = digest({
      actionIntentId: actions.publish.id,
      targetRef: release.releaseBundleId,
      manifestDigest: release.manifestDigest,
      dependencyClosureDigest: release.dependencyClosureDigest,
      expectedRevision: release.revision,
    });
    return mutateOwner(runtime, session, request, {
      action: actions.publish,
      path: `/api/v1/release-bundles/${release.releaseBundleId}/publish`,
      idempotencyKey: `policy-workbench-publish-${command.releaseId}`,
      etag: `"${digest({ resourceId: command.releaseId, revision: release.revision })}"`,
      body: {
        targetRef: release.releaseBundleId,
        inputDigest,
        expectedRevision: release.revision,
        reason: 'Publish the exact checker-approved policy release.',
      },
    });
  }
  if (command.command === 'RETIRE') {
    const release = await readOwner(
      runtime,
      session,
      `/api/v1/release-bundles/urn:openpc:resource:${command.releaseId}`,
      releaseSchema,
      request,
    );
    if (isResponse(release)) return release;
    return mutateOwner(runtime, session, request, {
      action: actions.retire,
      method: 'PATCH',
      path: `/api/v1/release-bundles/${release.releaseBundleId}`,
      idempotencyKey: `policy-workbench-retire-${command.releaseId}`,
      etag: `"${digest({ resourceId: command.releaseId, revision: release.revision })}"`,
      body: {
        expectedRevision: release.revision,
        replacementDigest: release.manifestDigest,
        reason: 'Retire the rolled-back release while preserving immutable evidence.',
      },
    });
  }
  const occurrence = await readOwner(
    runtime,
    session,
    `/api/v1/activation-occurrences/urn:openpc:resource:${command.occurrenceId}`,
    occurrenceSchema,
    request,
  );
  if (isResponse(occurrence)) return occurrence;
  const action =
    command.command === 'ACTIVATE'
      ? actions.activate
      : command.command === 'ROLLBACK'
        ? actions.rollback
        : actions.recover;
  const inputDigest = digest({
    actionIntentId: action.id,
    targetRef: occurrence.activationOccurrenceId,
    targetGenerationDigest: occurrence.targetGenerationDigest,
    exactCohortDigest: occurrence.exactCohortDigest,
    expectedRevision: occurrence.revision,
  });
  return mutateOwner(runtime, session, request, {
    action,
    path: `/api/v1/activation-occurrences/${occurrence.activationOccurrenceId}/${command.command.toLowerCase()}`,
    idempotencyKey: `policy-workbench-${command.command.toLowerCase()}-${command.occurrenceId}`,
    etag: `"${digest({ resourceId: command.occurrenceId, revision: occurrence.revision })}"`,
    body: {
      targetRef: occurrence.activationOccurrenceId,
      inputDigest,
      expectedRevision: occurrence.revision,
      reason:
        command.command === 'ACTIVATE'
          ? 'Activate the exact reviewed release.'
          : command.command === 'ROLLBACK'
            ? 'Roll back to the admitted predecessor.'
            : 'Recover the original failed activation work.',
    },
  });
}

export const policyReleaseActions = actions;
