import {
  moduleLifecycleInputDigest,
  moduleReleaseResponseSchema,
  moduleResourceRefSchema,
} from '../../../../../../services/module-registry/src/module-command-contract';
import { protectedProofPreview } from './protected-proof-preview';
import { policyActivationRenewalSourceSchema } from '../../../../../../services/module-registry/src/policy-activation-renewal-contract';
import {
  runtimeArtifactRetirementPlan,
  runtimeArtifactRetirementPlanInput,
} from '../../../../../../services/control-api/src/evidence/runtime-artifact-deletion-contracts';
import { factRetirementPreview, factRetirementSummary } from './fact-retirement-preview';
import {
  projectionDeletionPlan,
  projectionDeletionSelection,
} from '../../../../../../services/control-api/src/evidence/projection-deletion-contracts';
import {
  rawProofDeletionPlan,
  rawProofDeletionSelection,
} from '../../../../../../services/control-api/src/evidence/raw-deletion-contracts';
import {
  evidenceDeletionBatchPlan,
  evidenceDeletionBatchSelection,
} from '../../../../../../services/control-api/src/evidence/deletion-continuation-contracts';
import { localEvidenceDeletionPlan } from '../../../../../../services/control-api/src/evidence/deletion-contracts';
import { randomUUID } from 'node:crypto';
import { approvalCatalogueSchema } from '../../../../lib/approval-catalogue';
import { NextResponse, type NextRequest } from 'next/server';
import { z } from 'zod';
import { evidenceExportSelectionView } from '../../../../../../services/control-api/src/evidence/export-contracts';
import {
  operationResponseSchema,
  runtimeActivationCandidateResponseSchema,
  providerProfileResponseSchema,
} from '../../../../../../services/control-api/src/configuration/resource-contracts';
import {
  approvalCandidateResponseSchema,
  projectApprovalCandidate,
} from '../../../../../../services/module-registry/src/approval-candidate-contract';
import {
  authenticated,
  hasJsonContentType,
  localRuntimeConfig,
  localOwnerFetch,
  openBffPayload,
  readPublicCommand,
  safeProblem,
  sameOrigin,
  sealBffPayload,
  type IdentitySession,
  type LocalConfig,
} from './local-runtime';
import {
  approval,
  approvalCreateAction,
  approvalPageSchema,
  approvalDecisionAction,
  approvalUpdateAction,
  approveGovernanceRequest,
  csrf,
  digest,
  isResponse,
  ownerJson,
  publicHeaders,
  publicOperationSchema,
} from './local-governance-api';
import {
  transactionCandidate,
  transactionKindForAction,
  transactionKindSchema,
  transactionMutationPath,
  transactionOperation,
  walletBindingView,
  type TransactionKind,
} from './transaction-workbench-contract';

const uuid = z.uuidv7();
const noStore = { 'Cache-Control': 'no-store' };
const maximumBody = 6 * 1024 * 1024;
const lifetime = 30 * 60 * 1000;
const contractRegistrationKinds = new Set<TransactionKind>([
  'contract-abi',
  'contract-asset',
  'contract-binding',
  'contract-method',
]);
const resumableKinds = new Set<TransactionKind>([
  ...contractRegistrationKinds,
  'provider-profile',
  'provider-qualification',
  'provider-observation-renewal',
  'runtime-profile-binding',
  'module-registration',
  'module-install',
  'retention-policy',
  'evidence-hold',
  'evidence-participant-hold',
  'evidence-deletion-normalized',
  'evidence-deletion-search',
  'evidence-deletion-projection-continuation',
  'evidence-deletion-fact',
  'evidence-deletion-candidate',
  'evidence-deletion-runtime',
]);
const reviewSchema = z.strictObject({
  version: z.literal(1),
  resourceReservationId: z.uuidv7().optional(),
  issuedAt: z.number().int().nonnegative(),
  sessionId: uuid,
  principalId: uuid,
  participantId: uuid,
  privacyDomainId: uuid,
  contextEpoch: z.string(),
  kind: transactionKindSchema,
  key: z.uuid(),
  businessKey: z.string().min(16).max(128).optional(),
  body: z.record(z.string(), z.unknown()),
  reason: z.string().min(1).max(1024).optional(),
  targetRef: moduleResourceRefSchema.optional(),
});
type Review = z.infer<typeof reviewSchema>;
const commandSchema = z.discriminatedUnion('command', [
  z.strictObject({
    command: z.literal('PREVIEW'),
    resourceReservationId: z.uuidv7().optional(),
    requestKey: z.uuid().optional(),
    kind: transactionKindSchema,
    fields: z.record(z.string(), z.unknown()),
    reason: z.string().min(1).max(1024),
  }),
  z.strictObject({
    command: z.literal('REQUEST_APPROVAL'),
    resourceReservationId: z.uuidv7().optional(),
    reviewToken: z.string().max(maximumBody),
    checkerId: uuid,
  }),
  z.strictObject({ command: z.literal('APPROVE'), approvalId: uuid }),
  z.strictObject({
    command: z.literal('RESUME'),
    approvalId: uuid,
    predecessorCandidateId: uuid,
    expectedAttempt: z.string(),
    expectedRevision: z.string(),
    reason: z.string().min(1).max(1024),
  }),
  z.strictObject({
    command: z.literal('EXECUTE'),
    reviewToken: z.string().max(maximumBody),
    approvalId: uuid,
  }),
]);
const commandResultSchema = publicOperationSchema.extend({
  state: z.enum(['ACCEPTED', 'SUCCEEDED', 'FAILED', 'RECONCILING']),
  truthState: z.enum(['SUCCESS', 'UNKNOWN', 'FAILED', 'WRITE_AMBIGUITY']),
});

function actor(session: IdentitySession) {
  return {
    sessionId: session.sessionId,
    principalId: session.principalId,
    participantId: session.participantId,
    privacyDomainId: session.privacyDomainId!,
    contextEpoch: session.contextEpoch,
  };
}

async function context(request: NextRequest, mutation: boolean) {
  const runtime = await localRuntimeConfig().catch(() => undefined);
  if (!runtime) return safeProblem('PC-INTEGRATION-5001', request);
  if (mutation && !sameOrigin(request)) return safeProblem('PC-AUTH-0005', request);
  const session = await authenticated(request, runtime);
  if (!session || session.contextMode !== 'PARTICIPANT' || !session.privacyDomainId)
    return safeProblem('PC-AUTH-0005', request);
  return { runtime, session };
}

function openReview(
  token: string,
  runtime: LocalConfig,
  session: IdentitySession,
): Review | undefined {
  const parsed = reviewSchema.safeParse(
    openBffPayload(token, runtime.cookieKey, 'transaction-review'),
  );
  if (!parsed.success) return undefined;
  const review = parsed.data;
  if (
    review.issuedAt > Date.now() ||
    Date.now() - review.issuedAt > lifetime ||
    Object.entries(actor(session)).some(([key, value]) => review[key as keyof Review] !== value)
  )
    return undefined;
  const operation = transactionOperation(review.kind);
  const body = operation.input.safeParse(review.body);
  if (
    !body.success ||
    (review.kind !== 'wallet-binding' &&
      (body.data.actionIntentDigest !== operation.actionIntentDigest ||
        body.data.actionIntentId !== operation.actionIntentId)) ||
    (review.kind === 'wallet-binding' && body.data.participantId !== session.participantId) ||
    (review.kind === 'provider-observation-renewal' && !review.targetRef) ||
    digest(body.data) !== digest(review.body)
  )
    return undefined;
  return review;
}

export function functionalReviewMatches(
  runtime: LocalConfig,
  session: IdentitySession,
  token: string,
  value: {
    kind: string;
    candidate: { candidateDigest: string };
    approval: { makerSubjectRef: string };
  },
) {
  const review = openReview(token, runtime, session);
  return (
    !!review &&
    review.kind === value.kind &&
    value.candidate.candidateDigest === digest(review.body) &&
    value.approval.makerSubjectRef === `urn:openpc:resource:${session.principalId}`
  );
}

async function readCandidate(
  runtime: LocalConfig,
  session: IdentitySession,
  id: string,
  request: NextRequest,
) {
  const current = await approval(runtime, session, id, request, 'transaction-approval');
  if (isResponse(current)) return current;
  const response = await localOwnerFetch(
    `${runtime.publicApiUrl}/api/v1/approval-requests/${encodeURIComponent(current.approvalRequestId)}/candidate`,
    {
      cache: 'no-store',
      headers: publicHeaders(runtime, session),
      signal: AbortSignal.timeout(15_000),
    },
  ).catch(() => undefined);
  const candidate = await ownerJson(
    response,
    approvalCandidateResponseSchema,
    request,
    'transaction-candidate',
  );
  if (isResponse(candidate)) return candidate;
  let kind = transactionKindForAction(candidate.actionIntentId);
  if (candidate.actionIntentId === 'ACT-EVIDENCE_DELETIONS_CREATE_PROJECTION_BATCH-V1') {
    const selection = projectionDeletionSelection.safeParse(candidate.candidate.selection);
    if (!selection.success) return safeProblem('PC-INTEGRATION-5001', request);
    kind = selection.data.priorCursor
      ? 'evidence-deletion-projection-continuation'
      : selection.data.dataClass === 'SEARCH_PROJECTION'
        ? 'evidence-deletion-search'
        : 'evidence-deletion-normalized';
  }
  if (kind === 'evidence-deletion-batch') {
    const selection = evidenceDeletionBatchSelection.safeParse(candidate.candidate.selection);
    if (!selection.success) return safeProblem('PC-INTEGRATION-5001', request);
    if (selection.data.priorCursor) kind = 'evidence-deletion-continuation';
  }
  if (kind === 'evidence-deletion-raw') {
    const selection = rawProofDeletionSelection.safeParse(candidate.candidate.selection);
    if (!selection.success) return safeProblem('PC-INTEGRATION-5001', request);
    if (selection.data.priorCursor) kind = 'evidence-deletion-raw-continuation';
  }
  if (
    !kind ||
    candidate.approvalRequestId !== current.approvalRequestId ||
    candidate.candidateDigest !== current.candidateDigest ||
    candidate.actionIntentId !== current.actionIntentId
  )
    return safeProblem('PC-INTEGRATION-5001', request);
  if (kind === 'wallet-binding') {
    const parsed = transactionOperation(kind).input.safeParse(candidate.candidate);
    if (
      !parsed.success ||
      parsed.data.participantId !== session.participantId ||
      parsed.data.walletBindingId !== candidate.resourceRef.slice(-36) ||
      candidate.expectedRevision !== '0' ||
      candidate.redactedFields.length ||
      digest(parsed.data) !== candidate.candidateDigest
    )
      return safeProblem('PC-INTEGRATION-5001', request);
  }
  let evidenceSelection;
  if (kind === 'evidence-export') {
    const response = await fetch(
      `${runtime.publicApiUrl}/api/v1/evidence-exports/${encodeURIComponent(candidate.resourceRef)}/selection`,
      {
        cache: 'no-store',
        headers: publicHeaders(runtime, session),
        signal: AbortSignal.timeout(15000),
      },
    ).catch(() => undefined);
    const selection = await ownerJson(response, evidenceExportSelectionView, request);
    if (isResponse(selection)) return selection;
    if (selection.requestDigest !== candidate.candidate.inputDigest)
      return safeProblem('PC-DATA-6007', request);
    evidenceSelection = selection;
  }
  let factRetirement;
  if (kind === 'evidence-deletion-fact' || kind === 'evidence-deletion-candidate') {
    try {
      if (
        candidate.redactedFields.length ||
        digest(candidate.candidate) !== candidate.candidateDigest ||
        candidate.candidate.participantId !== `urn:openpc:participant:${session.participantId}`
      )
        return safeProblem('PC-INTEGRATION-5001', request);
      factRetirement = factRetirementSummary(candidate.candidate);
      kind =
        factRetirement.class === 'CANDIDATE_PROJECTION'
          ? 'evidence-deletion-candidate'
          : 'evidence-deletion-fact';
    } catch {
      return safeProblem('PC-INTEGRATION-5001', request);
    }
  }
  return {
    approval: current,
    candidate,
    kind,
    ...(evidenceSelection ? { evidenceSelection } : {}),
    ...(factRetirement ? { factRetirement } : {}),
  };
}

async function resourceRead(
  runtime: LocalConfig,
  session: IdentitySession,
  kind: TransactionKind,
  resourceId: string,
  request: NextRequest,
) {
  const operation = transactionOperation(kind);
  const path =
    kind === 'wallet-binding'
      ? `/v1/identity/wallet-bindings/${resourceId}?${new URLSearchParams({ privacyDomainId: session.privacyDomainId! })}`
      : `/api/v1/${operation.readCollection ?? operation.collection}/${encodeURIComponent(`urn:openpc:resource:${resourceId}`)}`;
  const response = await localOwnerFetch(`${runtime.publicApiUrl}${path}`, {
    cache: 'no-store',
    headers: publicHeaders(runtime, session),
    signal: AbortSignal.timeout(15_000),
  }).catch(() => undefined);
  const result = await ownerJson(response, operation.output, request, 'transaction-resource');
  if (kind === 'wallet-binding' && !isResponse(result)) {
    const parsed = walletBindingView.safeParse(result);
    if (
      !parsed.success ||
      parsed.data.walletBindingId !== resourceId ||
      parsed.data.participantId !== session.participantId ||
      parsed.data.privacyDomainId !== session.privacyDomainId
    )
      return safeProblem('PC-INTEGRATION-5001', request);
  }
  return result;
}

async function committedOperationRead(
  runtime: LocalConfig,
  session: IdentitySession,
  operationRef: string,
  actionIntentId: string,
  request: NextRequest,
) {
  const operationId = operationRef.slice(-36);
  const response = await localOwnerFetch(
    `${runtime.publicApiUrl}/api/v1/operations/${operationId}`,
    {
      cache: 'no-store',
      headers: publicHeaders(runtime, session),
      signal: AbortSignal.timeout(15_000),
    },
  ).catch(() => undefined);
  const value = await ownerJson(
    response,
    operationResponseSchema,
    request,
    'transaction-operation',
  );
  if (isResponse(value)) return value;
  if (value.operationId !== operationId || value.actionIntentId !== actionIntentId)
    return safeProblem('PC-DATA-6004', request);
  return {
    operationId: value.operationId,
    state: value.state,
    truthState: value.truthState,
    revision: value.revision,
    updatedAt: value.updatedAt,
  };
}

export async function readTransactionWorkbench(request: NextRequest) {
  const authorized = await context(request, false);
  if (isResponse(authorized)) return authorized;
  const { runtime, session } = authorized;
  const query = z
    .strictObject({
      approvalId: uuid.optional(),
      kind: transactionKindSchema.optional(),
      resourceId: uuid.optional(),
      approvals: z.literal('1').optional(),
      approvalsCursor: z.string().min(1).max(4096).optional(),
    })
    .safeParse(Object.fromEntries(request.nextUrl.searchParams));
  if (!query.success) return safeProblem('PC-DATA-6004', request);
  if (query.data.approvals) {
    if (query.data.approvalId || query.data.kind || query.data.resourceId)
      return safeProblem('PC-DATA-6004', request);
    const response = await localOwnerFetch(
      `${runtime.publicApiUrl}/api/v1/approval-requests?${new URLSearchParams({
        limit: '20',
        sort: '-updatedAt',
        ...(query.data.approvalsCursor ? { cursor: query.data.approvalsCursor } : {}),
      })}`,
      {
        cache: 'no-store',
        headers: publicHeaders(runtime, session),
        signal: AbortSignal.timeout(15_000),
      },
    ).catch(() => undefined);
    const page = await ownerJson(response, approvalPageSchema, request, 'transaction-approvals');
    if (isResponse(page)) return page;
    const catalogue = approvalCatalogueSchema.safeParse({
      ...page,
      actor: actor(session),
      items: page.items.map((item) => ({
        approvalRequestId: item.approvalRequestId,
        actionIntentId: item.actionIntentId,
        kinds: transactionKindSchema.options.filter(
          (kind) => transactionOperation(kind).actionIntentId === item.actionIntentId,
        ),
        state: item.state,
        revision: item.revision,
        createdAt: item.createdAt,
        updatedAt: item.updatedAt,
        relationship:
          item.makerSubjectRef === `urn:openpc:resource:${session.principalId}`
            ? 'MAKER'
            : item.checkerSubjectRef === `urn:openpc:resource:${session.principalId}`
              ? 'CHECKER'
              : 'REVIEWER',
      })),
    });
    if (!catalogue.success) return safeProblem('PC-INTEGRATION-5001', request);
    return NextResponse.json(catalogue.data, { headers: noStore });
  }
  if (query.data.approvalsCursor) return safeProblem('PC-DATA-6004', request);
  if (query.data.approvalId) {
    if (query.data.kind || query.data.resourceId) return safeProblem('PC-DATA-6004', request);
    const state = await readCandidate(runtime, session, query.data.approvalId, request);
    if (isResponse(state)) return state;
    const maker = state.approval.makerSubjectRef === `urn:openpc:resource:${session.principalId}`;
    const checker =
      !maker && state.approval.checkerSubjectRef === `urn:openpc:resource:${session.principalId}`;
    const operation = transactionOperation(state.kind);
    const makerSessionMatches = contractRegistrationKinds.has(state.kind)
      ? state.candidate.makerSessionMatches === true
      : state.candidate.makerSessionMatches !== false;
    const recoveredBody = operation.input.safeParse(state.candidate.candidate);
    // Restore only the maker's complete, digest-bound durable intent. This
    // grants no successor approval and preserves the original business key.
    const recoverable =
      maker &&
      makerSessionMatches &&
      state.candidate.attemptId &&
      state.candidate.businessIdempotencyKey &&
      state.candidate.redactedFields.length === 0 &&
      recoveredBody.success &&
      digest(recoveredBody.data) === state.candidate.candidateDigest;
    const stepUp =
      state.candidate.state === 'APPROVED' &&
      state.approval.state === 'APPROVED' &&
      state.candidate.approvalUsable !== false &&
      makerSessionMatches &&
      maker
        ? {
            actionIntentId: operation.actionIntentId,
            actionIntentDigest: operation.actionIntentDigest,
            resourceId: state.candidate.resourceRef.slice(-36),
            resourceDigest: state.candidate.candidateDigest,
          }
        : state.approval.state === 'REQUESTED' &&
            state.candidate.state === 'APPROVAL_REQUESTED' &&
            checker
          ? {
              actionIntentId: approvalDecisionAction.id,
              actionIntentDigest: approvalDecisionAction.digest,
              resourceId: query.data.approvalId,
              resourceDigest: digest({
                actionIntentId: approvalDecisionAction.id,
                approvalRequestId: state.approval.approvalRequestId,
                candidateDigest: state.approval.candidateDigest,
                expectedRevision: state.approval.revision,
                decision: 'APPROVE',
              }),
            }
          : null;
    // Review permission is distinct from the original maker's result permission.
    const result =
      maker && state.candidate.state === 'CONSUMED'
        ? await resourceRead(
            runtime,
            session,
            state.kind,
            state.candidate.resourceRef.slice(-36),
            request,
          )
        : null;
    const committedOperation =
      maker &&
      state.kind !== 'wallet-binding' &&
      state.candidate.state === 'CONSUMED' &&
      state.candidate.operationRef
        ? await committedOperationRead(
            runtime,
            session,
            state.candidate.operationRef,
            state.approval.actionIntentId,
            request,
          )
        : null;
    return NextResponse.json(
      {
        actor: actor(session),
        ...(runtime.functionalTest ? { functionalTest: true } : {}),
        ...state,
        ...(recoverable
          ? {
              reviewToken: sealBffPayload(
                {
                  version: 1,
                  issuedAt: Date.now(),
                  ...actor(session),
                  kind: state.kind,
                  key: state.candidate.attemptId,
                  businessKey: state.candidate.businessIdempotencyKey,
                  body: state.candidate.candidate,
                  ...(state.kind === 'runtime-activation' ||
                  state.kind === 'provider-observation-renewal' ||
                  state.kind === 'policy-activation-renewal'
                    ? { targetRef: state.candidate.resourceRef }
                    : {}),
                },
                runtime.cookieKey,
                'transaction-review',
              ),
            }
          : {}),
        stepUp,
        result: isResponse(result) ? null : result,
        resultUnavailable: isResponse(result),
        operation: isResponse(committedOperation) ? null : committedOperation,
        operationUnavailable: isResponse(committedOperation),
      },
      { headers: noStore },
    );
  }
  if (query.data.kind && query.data.resourceId) {
    const result = await resourceRead(
      runtime,
      session,
      query.data.kind,
      query.data.resourceId,
      request,
    );
    if (isResponse(result)) return result;
    return NextResponse.json(
      { actor: actor(session), kind: query.data.kind, result },
      { headers: noStore },
    );
  }
  if (query.data.kind || query.data.resourceId) return safeProblem('PC-DATA-6004', request);
  return NextResponse.json(
    { actor: actor(session), ...(runtime.functionalTest ? { functionalTest: true } : {}) },
    { headers: noStore },
  );
}

async function sendCandidate(
  runtime: LocalConfig,
  session: IdentitySession,
  review: Review,
  request: NextRequest,
  proposalOnly = false,
  approvalId?: string,
) {
  const operation = transactionOperation(review.kind);
  const csrfToken = await csrf(runtime, session, operation.actionIntentId);
  if (!csrfToken) return safeProblem('PC-AUTH-0005', request);
  if (review.kind === 'wallet-binding') {
    const { participantId: boundParticipant, ...body } = review.body;
    if (boundParticipant !== session.participantId) return safeProblem('PC-AUTH-0005', request);
    const response = await fetch(
      `${runtime.publicApiUrl}/v1/identity/wallet-bindings${proposalOnly ? '/prepare' : ''}`,
      {
        method: 'POST',
        cache: 'no-store',
        signal: AbortSignal.timeout(20000),
        headers: {
          ...publicHeaders(runtime, session),
          'Content-Type': 'application/json',
          'X-CSRF-Token': csrfToken,
          'Idempotency-Key': review.businessKey ?? `workbench-transaction-${review.key}`,
          'OpenPC-Action-Intent-Digest': operation.actionIntentDigest,
          'X-OpenPC-Aggregate-Version': '0',
          ...(approvalId ? { 'X-OpenPC-Approval-Request-ID': approvalId } : {}),
        },
        body: JSON.stringify(proposalOnly ? { ...body, mutation: 'CREATE' } : body),
      },
    ).catch(() => undefined);
    if (!proposalOnly) return response;
    const prepared = await ownerJson(
      response,
      z.strictObject({
        state: z.literal('PREPARED'),
        resourceId: z.literal(String(body.walletBindingId)),
        candidateDigest: z.literal(digest(review.body)),
        expectedRevision: z.literal('0'),
      }),
      request,
    );
    if (isResponse(prepared)) return prepared;
    return Response.json({
      resourceRef: `urn:openpc:resource:${prepared.resourceId}`,
      actionIntentId: operation.actionIntentId,
      candidateDigest: prepared.candidateDigest,
      expectedRevision: prepared.expectedRevision,
      runtimePermission: 'NONE',
    });
  }
  const revision = review.body.expectedRevision;
  return fetch(
    `${runtime.publicApiUrl}${transactionMutationPath(review.kind, review.body, review.targetRef)}${proposalOnly ? '/proposals' : ''}`,
    {
      method: proposalOnly ? 'POST' : (operation.method ?? 'POST'),
      cache: 'no-store',
      signal: AbortSignal.timeout(20_000),
      headers: {
        ...publicHeaders(runtime, session),
        'Content-Type': 'application/json',
        'X-CSRF-Token': csrfToken,
        'Idempotency-Key': review.businessKey ?? `workbench-transaction-${review.key}`,
        'X-OpenPC-Action-Intent-Digest': operation.actionIntentDigest,
        ...(revision === undefined
          ? {}
          : {
              'If-Match': `"${digest({ resourceId: String(review.targetRef ?? review.body.targetRef).slice(-36), revision })}"`,
            }),
      },
      body: JSON.stringify(review.body),
    },
  ).catch(() => undefined);
}

export async function mutateTransactionWorkbench(request: NextRequest) {
  if (!hasJsonContentType(request.headers.get('content-type')))
    return safeProblem('PC-DATA-6004', request);
  const authorized = await context(request, true);
  if (isResponse(authorized)) return authorized;
  const { runtime, session } = authorized;
  const parsed = commandSchema.safeParse(await readPublicCommand(request, maximumBody));
  if (!parsed.success) return safeProblem('PC-DATA-6004', request);
  const input = parsed.data;
  if (input.command === 'PREVIEW') {
    try {
      let fields = input.fields;
      let targetRef: string | undefined;
      if (input.kind === 'policy-activation-renewal') {
        const selection = z
          .strictObject({
            targetRef: moduleResourceRefSchema,
            expectedRevision: z.string().regex(/^[1-9][0-9]{0,18}$/u),
          })
          .parse(fields);
        const response = await fetch(
          `${runtime.publicApiUrl}/api/v1/activation-occurrences/${encodeURIComponent(selection.targetRef)}/renewal-preview`,
          {
            cache: 'no-store',
            headers: publicHeaders(runtime, session),
            signal: AbortSignal.any([request.signal, AbortSignal.timeout(15000)]),
          },
        ).catch(() => undefined);
        const source = await ownerJson(response, policyActivationRenewalSourceSchema, request);
        if (isResponse(source)) return source;
        const current = await authenticated(request, runtime);
        if (
          !current ||
          current.contextMode !== 'PARTICIPANT' ||
          !current.privacyDomainId ||
          digest(actor(current)) !== digest(actor(session))
        )
          return safeProblem('PC-AUTH-0005', request);
        if (
          source.targetRef !== selection.targetRef ||
          source.expectedRevision !== selection.expectedRevision
        )
          return safeProblem('PC-RUNTIME-3007', request);
        targetRef = source.targetRef;
        fields = source;
      }
      if (input.kind === 'provider-observation-renewal') {
        const selection = z
          .strictObject({
            targetRef: moduleResourceRefSchema,
            expectedRevision: z.string().regex(/^[1-9][0-9]{0,19}$/u),
          })
          .parse(fields);
        const response = await fetch(
          `${runtime.publicApiUrl}/api/v1/provider-profiles/${encodeURIComponent(selection.targetRef)}`,
          {
            cache: 'no-store',
            headers: publicHeaders(runtime, session),
            signal: AbortSignal.any([request.signal, AbortSignal.timeout(15000)]),
          },
        ).catch(() => undefined);
        const provider = await ownerJson(response, providerProfileResponseSchema, request);
        if (isResponse(provider)) return provider;
        const current = await authenticated(request, runtime);
        if (
          !current ||
          current.contextMode !== 'PARTICIPANT' ||
          !current.privacyDomainId ||
          digest(actor(current)) !== digest(actor(session))
        )
          return safeProblem('PC-AUTH-0005', request);
        if (
          provider.providerProfileId !== selection.targetRef ||
          provider.participantId !== `urn:openpc:participant:${session.participantId}` ||
          provider.revision !== selection.expectedRevision ||
          provider.state === 'RETIRED'
        )
          return safeProblem('PC-RUNTIME-3007', request);
        targetRef = selection.targetRef;
        fields = { ...selection, replacementDigest: provider.behaviorFingerprint };
      }
      if (input.kind === 'runtime-activation') {
        const selection = z
          .strictObject({
            targetRef: moduleResourceRefSchema,
            expectedRevision: z.string().regex(/^[1-9][0-9]{0,19}$/u),
          })
          .parse(fields);
        const response = await fetch(
          `${runtime.publicApiUrl}/api/v1/runtime-targets/${encodeURIComponent(selection.targetRef)}/activation-candidate`,
          {
            cache: 'no-store',
            headers: publicHeaders(runtime, session),
            signal: AbortSignal.any([request.signal, AbortSignal.timeout(15000)]),
          },
        ).catch(() => undefined);
        const target = await ownerJson(response, runtimeActivationCandidateResponseSchema, request);
        if (isResponse(target)) return target;
        if (
          target.targetRef !== selection.targetRef ||
          target.expectedRevision !== selection.expectedRevision ||
          !target.replacementDigest
        )
          return safeProblem('PC-RUNTIME-3007', request);
        targetRef = selection.targetRef;
        fields = { ...selection, replacementDigest: target.replacementDigest };
      }

      if (input.kind === 'module-install' || input.kind === 'module-enable') {
        const selection = z
          .strictObject({
            targetRef: moduleResourceRefSchema,
            expectedRevision: z.string().regex(/^[1-9][0-9]{0,19}$/u),
          })
          .parse(fields);
        const response = await fetch(
          `${runtime.publicApiUrl}/api/v1/modules/${encodeURIComponent(selection.targetRef)}`,
          {
            cache: 'no-store',
            headers: publicHeaders(runtime, session),
            signal: AbortSignal.any([request.signal, AbortSignal.timeout(15000)]),
          },
        ).catch(() => undefined);
        const release = await ownerJson(response, moduleReleaseResponseSchema, request);
        if (isResponse(release)) return release;
        if (
          release.moduleId !== selection.targetRef ||
          release.revision !== selection.expectedRevision
        )
          return safeProblem('PC-RUNTIME-3007', request);
        fields = {
          ...selection,
          inputDigest: moduleLifecycleInputDigest(
            selection.targetRef,
            selection.expectedRevision,
            release.manifestDigest,
          ),
        };
      }

      if (input.kind === 'evidence-deletion-runtime') {
        const selection = runtimeArtifactRetirementPlanInput.parse({
          previousDeletionJobId: null,
          ...fields,
        });
        const response = await fetch(
          `${runtime.publicApiUrl}/api/v1/evidence-deletions/runtime-batches/plan`,
          {
            method: 'POST',
            cache: 'no-store',
            headers: { ...publicHeaders(runtime, session), 'Content-Type': 'application/json' },
            body: JSON.stringify(selection),
            signal: AbortSignal.any([request.signal, AbortSignal.timeout(15000)]),
          },
        ).catch(() => undefined);
        const plan = await ownerJson(response, runtimeArtifactRetirementPlan, request);
        if (isResponse(plan)) return plan;
        if (
          plan.selection &&
          (plan.selection.participantId !== `urn:openpc:participant:${session.participantId}` ||
            plan.selection.privacyDomainId !== session.privacyDomainId ||
            plan.selection.retentionPolicyId !== selection.retentionPolicyId ||
            (plan.selection.priorCursor?.deletionJobId ?? null) !== selection.previousDeletionJobId)
        )
          return safeProblem('PC-INTEGRATION-5001', request);
        const current = await authenticated(request, runtime);
        if (
          !current ||
          current.contextMode !== 'PARTICIPANT' ||
          !current.privacyDomainId ||
          digest(actor(current)) !== digest(actor(session))
        )
          return safeProblem('PC-AUTH-0005', request);
        if (
          !plan.eligible ||
          plan.blockers.length ||
          plan.continuationState !== 'READY' ||
          !plan.selection ||
          !plan.beforeDigest
        )
          return safeProblem('PC-DATA-6007', request);
        fields = { selection: plan.selection, beforeDigest: plan.beforeDigest };
      }
      if (input.kind === 'evidence-deletion-fact' || input.kind === 'evidence-deletion-candidate') {
        const resolved = await factRetirementPreview(
          request,
          runtime,
          session,
          fields,
          input.kind === 'evidence-deletion-candidate' ? 'candidate' : 'fact',
        );
        if (isResponse(resolved)) return resolved;
        fields = resolved;
      }
      if (input.kind === 'protected-proof-retention' || input.kind === 'protected-proof-access') {
        const resolved = await protectedProofPreview(request, runtime, session, input.kind, fields);
        if (isResponse(resolved)) return resolved;
        fields = resolved;
      }
      if (input.kind === 'evidence-deletion') {
        const selection = z
          .strictObject({
            evidenceId: z
              .string()
              .regex(
                /^urn:openpc:resource:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u,
              ),
          })
          .parse(fields);
        const response = await fetch(
          `${runtime.publicApiUrl}/api/v1/evidence-records/${encodeURIComponent(selection.evidenceId)}/deletion-plan`,
          {
            cache: 'no-store',
            headers: publicHeaders(runtime, session),
            signal: AbortSignal.any([request.signal, AbortSignal.timeout(15000)]),
          },
        ).catch(() => undefined);
        const plan = await ownerJson(response, localEvidenceDeletionPlan, request);
        if (isResponse(plan)) return plan;
        if (
          plan.evidenceId !== selection.evidenceId ||
          (plan.selection &&
            (plan.selection.evidenceId !== selection.evidenceId ||
              plan.selection.participantId !== `urn:openpc:participant:${session.participantId}` ||
              plan.selection.privacyDomainId !== session.privacyDomainId))
        )
          return safeProblem('PC-INTEGRATION-5001', request);
        const current = await authenticated(request, runtime);
        if (
          !current ||
          current.contextMode !== 'PARTICIPANT' ||
          !current.privacyDomainId ||
          digest(actor(current)) !== digest(actor(session))
        )
          return safeProblem('PC-AUTH-0005', request);
        if (!plan.eligible || plan.blockers.length || !plan.selection || !plan.beforeDigest)
          return safeProblem('PC-DATA-6007', request);
        fields = { selection: plan.selection, beforeDigest: plan.beforeDigest };
      }
      if (
        input.kind === 'evidence-deletion-batch' ||
        input.kind === 'evidence-deletion-continuation' ||
        input.kind === 'evidence-deletion-raw' ||
        input.kind === 'evidence-deletion-raw-continuation' ||
        input.kind === 'evidence-deletion-search' ||
        input.kind === 'evidence-deletion-normalized' ||
        input.kind === 'evidence-deletion-projection-continuation'
      ) {
        const continuation = input.kind.endsWith('-continuation');
        const raw = input.kind.startsWith('evidence-deletion-raw');
        const projection =
          input.kind === 'evidence-deletion-search' ||
          input.kind === 'evidence-deletion-normalized' ||
          input.kind === 'evidence-deletion-projection-continuation';
        const reference = z
          .string()
          .regex(
            /^urn:openpc:resource:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u,
          );
        const parsedReference = (
          continuation
            ? z.strictObject({ deletionJobId: reference })
            : raw
              ? z.strictObject({ objectRef: reference })
              : z.strictObject({ evidenceId: reference })
        ).parse(fields);
        const ref =
          'deletionJobId' in parsedReference
            ? parsedReference.deletionJobId
            : 'objectRef' in parsedReference
              ? parsedReference.objectRef
              : parsedReference.evidenceId;
        const path = continuation
          ? `evidence-deletions/${encodeURIComponent(ref)}/${projection ? 'projection-continuation-plan' : raw ? 'raw-continuation-plan' : 'continuation-plan'}`
          : projection
            ? `evidence-records/${encodeURIComponent(ref)}/${input.kind === 'evidence-deletion-search' ? 'search' : 'normalized'}-projection-deletion-plan`
            : raw
              ? `protected-proofs/${encodeURIComponent(ref)}/deletion-plan`
              : `evidence-records/${encodeURIComponent(ref)}/deletion-batch-plan`;
        const response = await fetch(`${runtime.publicApiUrl}/api/v1/${path}`, {
          cache: 'no-store',
          headers: publicHeaders(runtime, session),
          signal: AbortSignal.any([request.signal, AbortSignal.timeout(15000)]),
        }).catch(() => undefined);
        const plan = projection
          ? await ownerJson(response, projectionDeletionPlan, request)
          : raw
            ? await ownerJson(response, rawProofDeletionPlan, request)
            : await ownerJson(response, evidenceDeletionBatchPlan, request);
        if (isResponse(plan)) return plan;
        if (
          (projection &&
            !continuation &&
            (!('dataClass' in plan) ||
              plan.dataClass !==
                (input.kind === 'evidence-deletion-search'
                  ? 'SEARCH_PROJECTION'
                  : 'NORMALIZED_JSON_PROJECTION') ||
              !('evidenceId' in plan) ||
              plan.evidenceId !== ref)) ||
          (raw && !continuation && (!('objectRef' in plan) || plan.objectRef !== ref)) ||
          ('objectRef' in plan &&
            plan.selection &&
            'objectRef' in plan.selection &&
            plan.selection.objectRef !== plan.objectRef) ||
          (plan.selection &&
            (plan.selection.participantId !== `urn:openpc:participant:${session.participantId}` ||
              plan.selection.privacyDomainId !== session.privacyDomainId ||
              (continuation
                ? plan.selection.priorCursor?.deletionJobId !== ref
                : plan.selection.priorCursor !== null)))
        )
          return safeProblem('PC-INTEGRATION-5001', request);
        const current = await authenticated(request, runtime);
        if (
          !current ||
          current.contextMode !== 'PARTICIPANT' ||
          !current.privacyDomainId ||
          digest(actor(current)) !== digest(actor(session))
        )
          return safeProblem('PC-AUTH-0005', request);
        if (
          !plan.eligible ||
          plan.continuationState !== 'READY' ||
          plan.blockers.length ||
          !plan.selection ||
          !plan.beforeDigest
        )
          return safeProblem('PC-DATA-6007', request);
        fields = { selection: plan.selection, beforeDigest: plan.beforeDigest };
      }
      const { operation, body } = transactionCandidate(
        input.kind,
        fields,
        input.reason,
        session.participantId,
      );
      const candidateDigest = digest(body);
      const projection = projectApprovalCandidate({
        document: body,
        candidateDigest,
        ...operation.binding,
      });
      const review: Review = {
        version: 1,
        issuedAt: Date.now(),
        ...actor(session),
        kind: input.kind,
        ...(targetRef ? { targetRef } : {}),
        ...(input.kind === 'wallet-binding' ? { reason: input.reason } : {}),
        key: input.requestKey ?? randomUUID(),
        resourceReservationId: input.resourceReservationId,
        body,
      };
      return NextResponse.json(
        {
          reviewToken: sealBffPayload(review, runtime.cookieKey, 'transaction-review'),
          preview: {
            kind: input.kind,
            candidateDigest,
            ...projection,
            authority: 'NONE',
            ...(input.kind === 'evidence-deletion-fact' ||
            input.kind === 'evidence-deletion-candidate'
              ? { factRetirement: factRetirementSummary(body) }
              : {}),
          },
        },
        { headers: noStore },
      );
    } catch {
      return safeProblem('PC-DATA-6004', request);
    }
  }
  if (input.command === 'RESUME') {
    const state = await readCandidate(runtime, session, input.approvalId, request);
    if (isResponse(state)) return state;
    if (
      state.approval.makerSubjectRef !== `urn:openpc:resource:${session.principalId}` ||
      state.candidate.attemptId !== input.predecessorCandidateId ||
      state.candidate.attempt !== input.expectedAttempt ||
      state.approval.revision !== input.expectedRevision ||
      !resumableKinds.has(state.kind)
    )
      return safeProblem('PC-AUTH-0005', request);
    const csrfToken = await csrf(runtime, session, approvalUpdateAction.id);
    if (!csrfToken) return safeProblem('PC-AUTH-0005', request);
    const response = await fetch(
      `${runtime.publicApiUrl}/api/v1/approval-requests/${encodeURIComponent(state.approval.approvalRequestId)}`,
      {
        method: 'PATCH',
        cache: 'no-store',
        signal: AbortSignal.timeout(20000),
        headers: {
          ...publicHeaders(runtime, session),
          'Content-Type': 'application/json',
          'X-CSRF-Token': csrfToken,
          'Idempotency-Key': `workbench-resume-${input.predecessorCandidateId}`,
          'X-OpenPC-Action-Intent-Digest': approvalUpdateAction.digest,
          'If-Match': `"${digest({ resourceId: input.approvalId, revision: input.expectedRevision })}"`,
        },
        body: JSON.stringify({
          command: 'RESUME',
          actionIntentId: approvalUpdateAction.id,
          actionIntentDigest: approvalUpdateAction.digest,
          expectedRevision: input.expectedRevision,
          predecessorCandidateId: input.predecessorCandidateId,
          expectedAttempt: input.expectedAttempt,
          candidateDigest: state.candidate.candidateDigest,
          reason: input.reason,
        }),
      },
    ).catch(() => undefined);
    if (!response)
      return NextResponse.json(
        { truthState: 'UNKNOWN', reconciliation: 'READ_APPROVAL', approvalId: input.approvalId },
        { status: 202, headers: noStore },
      );
    const operation = await ownerJson(response, publicOperationSchema, request);
    if (isResponse(operation)) return operation;
    return NextResponse.json(
      { approvalId: operation.resourceRef.slice(-36), operation },
      { status: 202, headers: noStore },
    );
  }
  if (input.command === 'APPROVE') {
    const state = await readCandidate(runtime, session, input.approvalId, request);
    if (isResponse(state)) return state;
    if (!['APPROVAL_REQUESTED', 'APPROVED', 'CONSUMED'].includes(state.candidate.state))
      return safeProblem('PC-RUNTIME-3007', request);
    return approveGovernanceRequest(runtime, session, input.approvalId, request);
  }
  const review = openReview(input.reviewToken, runtime, session);
  if (!review) return safeProblem('PC-AUTH-0005', request);
  if (input.command === 'REQUEST_APPROVAL') {
    if (input.checkerId === session.principalId) return safeProblem('PC-AUTH-0005', request);
    const staged = await sendCandidate(runtime, session, review, request, true);
    if (staged instanceof NextResponse) return staged;
    const proposal = await ownerJson(
      staged,
      z.strictObject({
        resourceRef: z.string().regex(/^urn:openpc:resource:[0-9a-f-]{36}$/u),
        actionIntentId: z.literal(transactionOperation(review.kind).actionIntentId),
        candidateDigest: z.literal(digest(review.body)),
        expectedRevision: z.string(),
        runtimePermission: z.literal('NONE'),
      }),
      request,
    );
    if (isResponse(proposal)) return proposal;
    if (
      (review.kind === 'provider-observation-renewal' ||
        review.kind === 'policy-activation-renewal') &&
      (proposal.resourceRef !== review.targetRef ||
        proposal.expectedRevision !== review.body.expectedRevision)
    )
      return safeProblem('PC-INTEGRATION-5001', request);
    const existingResponse = await fetch(
      `${runtime.publicApiUrl}/api/v1/approval-requests?${new URLSearchParams({
        filter: `candidateDigest:eq:${digest(review.body)}`,
        limit: '50',
        sort: '-updatedAt',
      })}`,
      {
        cache: 'no-store',
        headers: publicHeaders(runtime, session),
        signal: AbortSignal.timeout(15_000),
      },
    ).catch(() => undefined);
    const existing = await ownerJson(existingResponse, approvalPageSchema, request);
    if (isResponse(existing)) return existing;
    if (existing.nextCursor !== null || existing.completeness !== 'COMPLETE')
      return safeProblem('PC-RUNTIME-3007', request);
    const prior = existing.items.find(
      (item) =>
        item.makerSubjectRef === `urn:openpc:resource:${session.principalId}` &&
        item.actionIntentId === transactionOperation(review.kind).actionIntentId,
    );
    if (prior) {
      if (prior.checkerSubjectRef !== `urn:openpc:resource:${input.checkerId}`)
        return safeProblem('PC-RUNTIME-3007', request);
      return NextResponse.json(
        { approvalId: prior.approvalRequestId.slice(-36), reconciled: true },
        { headers: noStore },
      );
    }
    const csrfToken = await csrf(runtime, session, approvalCreateAction.id);
    if (!csrfToken) return safeProblem('PC-AUTH-0005', request);
    const response = await fetch(`${runtime.publicApiUrl}/api/v1/approval-requests`, {
      method: 'POST',
      cache: 'no-store',
      signal: AbortSignal.timeout(15_000),
      headers: {
        ...publicHeaders(runtime, session),
        'Content-Type': 'application/json',
        'X-CSRF-Token': csrfToken,
        'Idempotency-Key': `workbench-transaction-approval-${review.key}`,
        'X-OpenPC-Action-Intent-Digest': approvalCreateAction.digest,
      },
      body: JSON.stringify({
        actionIntentId: approvalCreateAction.id,
        actionIntentDigest: approvalCreateAction.digest,
        candidateDigest: digest(review.body),
        resourceReservationId: input.resourceReservationId ?? review.resourceReservationId,
        makerSubjectRef: `urn:openpc:resource:${session.principalId}`,
        checkerSubjectRef: `urn:openpc:resource:${input.checkerId}`,
        reason: review.reason ?? review.body.reason,
      }),
    }).catch(() => undefined);
    const operation = await ownerJson(response, publicOperationSchema, request);
    if (isResponse(operation)) return operation;
    return NextResponse.json(
      { approvalId: operation.resourceRef.slice(-36), operation },
      { status: 202, headers: noStore },
    );
  }
  const state = await readCandidate(runtime, session, input.approvalId, request);
  if (isResponse(state)) return state;
  if (
    state.approval.makerSubjectRef !== `urn:openpc:resource:${session.principalId}` ||
    state.candidate.candidateDigest !== digest(review.body) ||
    ((review.kind === 'provider-observation-renewal' ||
      review.kind === 'policy-activation-renewal') &&
      state.candidate.resourceRef !== review.targetRef) ||
    state.kind !== review.kind
  )
    return safeProblem('PC-AUTH-0005', request);
  if (state.candidate.state === 'CONSUMED')
    return NextResponse.json(
      {
        reconciled: true,
        operationRef: state.candidate.operationRef,
        resourceRef: state.candidate.resourceRef,
      },
      { headers: noStore },
    );
  if (
    state.approval.state !== 'APPROVED' ||
    state.candidate.state !== 'APPROVED' ||
    state.candidate.approvalUsable === false
  )
    return safeProblem('PC-RUNTIME-3007', request);
  if (
    contractRegistrationKinds.has(state.kind)
      ? state.candidate.makerSessionMatches !== true
      : state.candidate.makerSessionMatches === false
  )
    return safeProblem('PC-AUTH-0005', request);
  const response = await sendCandidate(runtime, session, review, request, false, input.approvalId);
  if (response instanceof NextResponse) return response;
  if (!response)
    return NextResponse.json(
      { truthState: 'UNKNOWN', reconciliation: 'READ_APPROVAL', approvalId: input.approvalId },
      { status: 202, headers: noStore },
    );
  if (review.kind === 'wallet-binding') {
    const result = await ownerJson(response, walletBindingView, request);
    if (isResponse(result)) return result;
    if (
      result.walletBindingId !== review.body.walletBindingId ||
      result.participantId !== session.participantId ||
      result.privacyDomainId !== session.privacyDomainId ||
      result.subjectId !== review.body.subjectId ||
      result.chainId !== review.body.chainId ||
      result.walletAddress !== review.body.walletAddress
    )
      return safeProblem('PC-INTEGRATION-5001', request);
    return NextResponse.json(
      { result, approvalId: input.approvalId },
      { status: 202, headers: noStore },
    );
  }
  const operation = await ownerJson(response, commandResultSchema, request);
  if (isResponse(operation)) return operation;
  return NextResponse.json(
    { operation, approvalId: input.approvalId },
    { status: 202, headers: noStore },
  );
}
