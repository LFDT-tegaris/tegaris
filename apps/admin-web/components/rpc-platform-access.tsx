'use client';

import { performWebAuthnStepUp } from '@openpc/ui-shell';
import { useCallback, useLayoutEffect, useRef, useState } from 'react';
import { z } from 'zod';
import { SecondaryPanel } from './secondary-panel';

const panel = 'rounded border border-[color:var(--border)] bg-[color:var(--surface)] p-4';
const field = 'min-w-0 rounded border border-[color:var(--border)] bg-[color:var(--canvas)] p-2';
const button =
  'w-fit rounded bg-[color:var(--accent)] px-3 py-2 font-medium text-white disabled:opacity-60';
const storageKey = 'openpc:rpc-platform-envelope:v1';

interface Actor {
  sessionId: string;
  principalId: string;
  participantId: string;
  privacyDomainId: string;
  contextMode: 'PLATFORM' | 'PARTICIPANT';
  contextEpoch: string;
  role: 'operator' | 'viewer';
}
interface Approval {
  approvalRequestId: string;
  candidateDigest: string;
  state: string;
  stepUp?: {
    actionIntentId: string;
    actionIntentDigest: string;
    resourceId: string;
    resourceDigest: string;
  };
}
interface Review {
  reviewToken: string;
  approvalRequestId?: string;
  review: {
    kind: 'CREATE_ENVELOPE' | 'SUBMIT_ENVELOPE' | 'ACTIVATE_ENVELOPE' | 'REVOKE_ENVELOPE';
    resourceId: string;
    candidateDigest: string;
    expectedRevision: string;
    reason: string;
    targetParticipantId: string;
    targetPrivacyDomainId: string;
    capabilityIds?: string[];
    makerCheckerRequired?: boolean;
    stepUpRequired?: boolean;
    platformScopeReplacementId?: string;
    administrationActionIntentIds?: string[];
    administrationResourceIds?: string[];
    continuationHandoff?: { preparationApprovalId: string; principalId: string };
    resumeDraft?: {
      approvalRequestId: string;
      enrollmentId: string;
      recoveryId: string;
      intentDigest: string;
      expiresAt: string;
      expectedAttempt: string;
      requestDigest: string;
    };
    stepUp: {
      actionIntentId: string;
      actionIntentDigest: string;
      resourceId: string;
      resourceDigest: string;
    };
  };
}
interface StepUp {
  actionIntentId: string;
  actionIntentDigest: string;
  resourceId: string;
  resourceDigest: string;
}
interface StepUpState {
  actor: Actor;
  requiresStepUp: StepUp;
}
interface Envelope {
  effect: { id: string; state: string; revision?: string; capabilityIds?: string[] };
  operationId: string | null;
}
interface LoadedState {
  approvalsLoaded?: boolean;
  handoff?: {
    replacementId: string;
    administrator: { principalId: string; envelopeId: string; assignmentId: string };
    envelope: Envelope | null;
  };
  actor: Actor;
  items: {
    participant: {
      participantId: string;
      displayName: string;
      state: string;
      rowVersion: string;
    };
    envelopes: {
      effect: {
        id: string;
        state: string;
        revision?: string;
        capabilityIds?: string[];
      };
      operationId: string | null;
    }[];
  }[];
  approvals: Approval[];
  nextCursor: string | null;
  authorizedEmpty: boolean;
}
type State = StepUpState | LoadedState;

const requestFailure = 'The request was not completed. Refresh RPC access before continuing.';
const readFailure = 'Platform RPC access is unavailable. Refresh to try again.';
const identifier = z.uuid();
const revision = z.string().regex(/^(0|[1-9][0-9]*)$/u);
const digest = z.string().regex(/^sha256:[0-9a-f]{64}$/u);
const actorSchema = z.object({
  sessionId: identifier,
  principalId: identifier,
  participantId: identifier,
  privacyDomainId: identifier,
  contextMode: z.literal('PLATFORM'),
  contextEpoch: revision,
  role: z.enum(['operator', 'viewer']),
});
const stepUpSchema = z.object({
  actionIntentId: z.string().min(1),
  actionIntentDigest: digest,
  resourceId: identifier,
  resourceDigest: digest,
});
const resumeDraftSchema = z
  .object({
    approvalRequestId: identifier,
    enrollmentId: identifier,
    recoveryId: identifier,
    intentDigest: digest,
    expiresAt: z.string().datetime(),
    expectedAttempt: z.string().regex(/^[1-9][0-9]*$/u),
    requestDigest: digest,
  })
  .strict();
const envelopeSchema = z.object({
  effect: z.object({
    id: identifier,
    state: z.enum(['DRAFT', 'SUBMITTED', 'APPROVED', 'ACTIVE', 'SUPERSEDED', 'REVOKED']),
    revision: revision.optional(),
    capabilityIds: z
      .array(z.enum(['CALL_RESULT_DISCLOSURE', 'SIGNED_TRANSACTION_SUBMISSION']))
      .optional(),
  }),
  operationId: identifier.nullable(),
});
const loadedSchema = z.object({
  actor: actorSchema,
  items: z.array(
    z.object({
      participant: z.object({
        participantId: identifier,
        displayName: z.string().min(1).max(160),
        state: z.enum([
          'PROVISIONING',
          'ACTIVE',
          'SUSPENDED',
          'TRANSFER_PENDING',
          'REVOKED',
          'OFFBOARDED',
        ]),
        rowVersion: revision,
      }),
      envelopes: z.array(envelopeSchema),
    }),
  ),
  approvals: z.array(
    z.object({
      approvalRequestId: z.string().regex(/^urn:openpc:resource:[0-9a-f-]{36}$/u),
      candidateDigest: digest,
      state: z.enum(['REQUESTED', 'APPROVED', 'REJECTED', 'EXPIRED', 'CANCELLED']),
      stepUp: stepUpSchema.optional(),
    }),
  ),
  nextCursor: identifier.nullable(),
  authorizedEmpty: z.boolean(),
  approvalsLoaded: z.boolean().optional(),
  handoff: z
    .object({
      replacementId: identifier,
      administrator: z.object({
        principalId: identifier,
        envelopeId: identifier,
        assignmentId: identifier,
      }),
      envelope: envelopeSchema.nullable(),
    })
    .optional(),
});
const reviewFieldsSchema = z
  .object({
    kind: z.enum(['CREATE_ENVELOPE', 'SUBMIT_ENVELOPE', 'ACTIVATE_ENVELOPE', 'REVOKE_ENVELOPE']),
    resourceId: identifier,
    candidateDigest: digest,
    expectedRevision: revision,
    reason: z.string().min(10).max(1024),
    targetParticipantId: identifier,
    targetPrivacyDomainId: identifier,
    capabilityIds: z
      .array(z.enum(['CALL_RESULT_DISCLOSURE', 'SIGNED_TRANSACTION_SUBMISSION']))
      .optional(),
    makerCheckerRequired: z.boolean().optional(),
    stepUpRequired: z.boolean().optional(),
    platformScopeReplacementId: identifier.optional(),
    administrationActionIntentIds: z.array(z.string().min(1)).optional(),
    administrationResourceIds: z.array(z.string().min(1)).optional(),
    continuationHandoff: z
      .object({ preparationApprovalId: identifier, principalId: identifier })
      .strict()
      .optional(),
    resumeDraft: resumeDraftSchema.optional(),
    stepUp: stepUpSchema,
  })
  .passthrough()
  .superRefine((value, context) => {
    if (
      value.stepUp.resourceId !== (value.resumeDraft?.approvalRequestId ?? value.resourceId) ||
      value.stepUp.actionIntentId !==
        (value.resumeDraft
          ? 'ACT-APPROVAL_REQUESTS_UPDATE_RESOURCE-V1'
          : value.kind === 'SUBMIT_ENVELOPE'
            ? 'ACT-APPROVAL_REQUESTS_CREATE_RESOURCE-V1'
            : value.kind === 'ACTIVATE_ENVELOPE'
              ? 'ACT-PARTICIPANT_ACTIVATE_CONTEXT-V1'
              : 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1') ||
      (value.resumeDraft
        ? value.kind !== 'ACTIVATE_ENVELOPE' ||
          value.stepUp.resourceDigest !== value.resumeDraft.requestDigest ||
          Date.parse(value.resumeDraft.expiresAt) <= Date.now()
        : value.kind !== 'SUBMIT_ENVELOPE' &&
          value.stepUp.resourceDigest !== value.candidateDigest) ||
      (value.kind === 'CREATE_ENVELOPE' &&
        (value.expectedRevision !== '0' ||
          value.capabilityIds === undefined ||
          value.makerCheckerRequired === undefined ||
          value.stepUpRequired === undefined ||
          value.administrationActionIntentIds === undefined ||
          value.administrationResourceIds === undefined)) ||
      (value.kind === 'SUBMIT_ENVELOPE' && value.expectedRevision !== '1') ||
      (value.kind === 'ACTIVATE_ENVELOPE' && value.expectedRevision !== '3') ||
      (value.continuationHandoff && value.kind !== 'ACTIVATE_ENVELOPE')
    )
      context.addIssue({ code: 'custom', message: requestFailure });
  });
const reviewResponseSchema = z
  .object({
    reviewToken: z.string().min(80).max(65536),
    approvalRequestId: identifier.optional(),
    review: reviewFieldsSchema,
  })
  .passthrough();
const savedReviewSchema = reviewResponseSchema.extend({ actor: actorSchema });
const resourceUrn = z
  .string()
  .refine(
    (value) =>
      value.startsWith('urn:openpc:resource:') && identifier.safeParse(value.slice(20)).success,
  );
const publicOperationSchema = z.object({
  operationId: identifier,
  actionIntentId: z.string().min(1),
  intentDigest: digest,
  idempotencyKey: z.string().min(1),
  resourceRef: resourceUrn,
  revision,
  state: z.enum(['ACCEPTED', 'SUCCEEDED']),
  truthState: z.literal('SUCCESS'),
  createdAt: z.string().datetime(),
  updatedAt: z.string().datetime(),
});
const fullApprovalSchema = z.object({
  approvalRequestId: resourceUrn,
  actionIntentId: z.string().min(1),
  candidateDigest: digest,
  state: z.enum(['REQUESTED', 'APPROVED', 'REJECTED', 'EXPIRED', 'CANCELLED']),
  makerSubjectRef: resourceUrn,
  checkerSubjectRef: resourceUrn.nullable(),
  revision,
  createdAt: z.string().datetime(),
  updatedAt: z.string().datetime(),
});
const decisionSchema = z.union([
  z.object({ reconciled: z.literal(true), approval: fullApprovalSchema }).strict(),
  z.object({ operation: publicOperationSchema, approval: fullApprovalSchema }).strict(),
]);
const committedEnvelopeSchema = z.object({
  effect: z.object({
    effect: z
      .object({
        id: identifier,
        participantId: identifier,
        state: z.enum(['DRAFT', 'SUBMITTED', 'APPROVED', 'ACTIVE', 'SUPERSEDED', 'REVOKED']),
        authorityEpoch: revision,
        revision: revision.optional(),
        capabilityIds: z
          .array(z.enum(['CALL_RESULT_DISCLOSURE', 'SIGNED_TRANSACTION_SUBMISSION']))
          .optional(),
        resourceIds: z.array(z.string()),
        privacyDomainIds: z.array(identifier),
        validFrom: z.string().datetime(),
        validUntil: z.string().datetime().nullable(),
        makerCheckerRequired: z.boolean(),
        stepUpRequired: z.boolean(),
        semanticDigest: digest,
      })
      .passthrough(),
    operationId: z.null(),
  }),
});
function decodePreview(
  value: unknown,
  kind: Review['review']['kind'],
  participant: string,
  privacy: string,
  resource?: string,
): Review {
  const next = reviewResponseSchema.parse(value);
  if (
    next.approvalRequestId !== undefined ||
    next.review.kind !== kind ||
    next.review.targetParticipantId !== participant ||
    next.review.targetPrivacyDomainId !== privacy ||
    (resource !== undefined && next.review.resourceId !== resource)
  )
    throw new Error(requestFailure);
  return next;
}
function decodeSubmission(value: unknown, original: Review): Review {
  const next = reviewResponseSchema.extend({ approvalRequestId: identifier }).parse(value);
  if (
    JSON.stringify(reviewFieldsSchema.strip().parse(next.review)) !==
      JSON.stringify(reviewFieldsSchema.strip().parse(original.review)) ||
    (original.approvalRequestId !== undefined &&
      next.approvalRequestId !== original.approvalRequestId)
  )
    throw new Error(requestFailure);
  // SUBMIT reseals the same intent with a fresh IV; keep the first token.
  return { ...next, reviewToken: original.reviewToken, review: original.review };
}
function decodeResumption(value: unknown, original: Review): Review {
  const next = reviewResponseSchema.extend({ approvalRequestId: identifier }).parse(value);
  const { resumeDraft, ...before } = reviewFieldsSchema.strip().parse(original.review);
  const after = reviewFieldsSchema.strip().parse(next.review);
  if (
    !resumeDraft ||
    next.approvalRequestId === resumeDraft.approvalRequestId ||
    next.review.resumeDraft !== undefined ||
    next.review.stepUp.actionIntentId !== 'ACT-PARTICIPANT_ACTIVATE_CONTEXT-V1' ||
    JSON.stringify({ ...before, stepUp: undefined }) !==
      JSON.stringify({ ...after, stepUp: undefined })
  )
    throw new Error(requestFailure);
  // RESUME is a new approval attempt with a distinct step-up purpose. Retain
  // the business digest, but adopt the newly sealed activation review.
  return next;
}
function decodeDecision(value: unknown, original: Approval, principal: string) {
  const next = decisionSchema.parse(value);
  if (
    next.approval.approvalRequestId !== original.approvalRequestId ||
    next.approval.candidateDigest !== original.candidateDigest ||
    next.approval.state !== 'APPROVED' ||
    next.approval.checkerSubjectRef !== `urn:openpc:resource:${principal}` ||
    next.approval.makerSubjectRef === next.approval.checkerSubjectRef ||
    ('operation' in next &&
      (next.operation.resourceRef !== original.approvalRequestId ||
        next.operation.actionIntentId !== 'ACT-POLICY_APPROVE_REQUEST-V1'))
  )
    throw new Error(requestFailure);
  return next;
}
function decodeCommit(value: unknown, original: Review) {
  const next = committedEnvelopeSchema.parse(value).effect.effect;
  const expected =
    original.review.kind === 'CREATE_ENVELOPE'
      ? 'DRAFT'
      : original.review.kind === 'ACTIVATE_ENVELOPE'
        ? 'ACTIVE'
        : 'REVOKED';
  if (
    original.review.kind === 'SUBMIT_ENVELOPE' ||
    next.id !== original.review.resourceId ||
    next.participantId !== original.review.targetParticipantId ||
    next.state !== expected ||
    !next.privacyDomainIds.includes(original.review.targetPrivacyDomainId) ||
    next.privacyDomainIds.some((id) => id !== original.review.targetPrivacyDomainId) ||
    (original.review.platformScopeReplacementId !== undefined &&
      next.platformScopeReplacementId !== original.review.platformScopeReplacementId) ||
    (next.validUntil !== null && Date.parse(next.validUntil) <= Date.parse(next.validFrom))
  )
    throw new Error(requestFailure);
  if (original.review.kind === 'CREATE_ENVELOPE') {
    const expectedCapabilities = new Set(original.review.capabilityIds ?? []);
    const actualCapabilities = new Set(next.capabilityIds ?? []);
    if (
      actualCapabilities.size !== expectedCapabilities.size ||
      [...actualCapabilities].some((capability) => !expectedCapabilities.has(capability))
    )
      throw new Error(requestFailure);
  }
  return next;
}
function actorKey(actor?: Actor) {
  return actor ? JSON.stringify(actor) : '';
}
function removeSavedReview(original: Review, actor: Actor) {
  try {
    const saved = localStorage.getItem(storageKey);
    if (!saved) return;
    const parsed = savedReviewSchema.parse(JSON.parse(saved));
    if (
      actorKey(parsed.actor) === actorKey(actor) &&
      parsed.reviewToken === original.reviewToken &&
      parsed.approvalRequestId === original.approvalRequestId &&
      JSON.stringify(reviewFieldsSchema.strip().parse(parsed.review)) ===
        JSON.stringify(reviewFieldsSchema.strip().parse(original.review))
    )
      localStorage.removeItem(storageKey);
  } catch {
    // Optional storage cannot undo readback or justify deleting unqualified custody.
  }
}
const localSessionSchema = actorSchema.omit({ privacyDomainId: true }).extend({
  enabled: z.literal(true),
  authenticated: z.literal(true),
  privacyDomainId: identifier.optional(),
});
type LocalSession = z.infer<typeof localSessionSchema>;
async function readLocalSession(signal: AbortSignal): Promise<LocalSession> {
  return localSessionSchema.parse(
    await fetch('/api/v1/ui/local-session', {
      cache: 'no-store',
      credentials: 'same-origin',
      signal,
    }).then(json<unknown>),
  );
}
function sessionKey(session: LocalSession) {
  return JSON.stringify({
    sessionId: session.sessionId,
    principalId: session.principalId,
    participantId: session.participantId,
    contextMode: session.contextMode,
    contextEpoch: session.contextEpoch,
    role: session.role,
    privacyDomainId: session.privacyDomainId,
  });
}
function matchesSession(actor: Actor, session: LocalSession) {
  return (
    actor.sessionId === session.sessionId &&
    actor.principalId === session.principalId &&
    actor.participantId === session.participantId &&
    actor.contextMode === session.contextMode &&
    actor.contextEpoch === session.contextEpoch &&
    actor.role === session.role &&
    // Platform's RPC producer obtains privacy from bootstrap metadata when the
    // authenticated local session has no Participant privacy context.
    (session.privacyDomainId === undefined || actor.privacyDomainId === session.privacyDomainId)
  );
}
interface MutationContext {
  generation: number;
  actor: string;
  mode: boolean;
  approval: string;
  administrator: string;
  reservation: string;
}
interface Mutation {
  context: MutationContext;
  actor: Actor;
  state: State;
  review?: Review;
  inputRevision: number;
  controller: AbortController;
  sent: boolean;
  reconciling?: boolean;
  originalCommand?: unknown;
  readApproval?: string;
}
const creationResumeSchema = z.strictObject({
  command: z.literal('RESUME_CREATE'),
  approvalRequestId: identifier,
  reason: z.string().min(10).max(1024),
});
function pendingCreation(operation?: Mutation) {
  const parsed = creationResumeSchema.safeParse(operation?.originalCommand);
  return operation && parsed.success ? { original: operation, input: parsed.data } : undefined;
}
function decodeCreationResume(value: unknown, actor: Actor, originalApprovalId: string): Review {
  const next = reviewResponseSchema
    .extend({ approvalRequestId: identifier, originalApprovalRequestId: identifier })
    .parse(value);
  if (
    next.originalApprovalRequestId !== originalApprovalId ||
    next.approvalRequestId === originalApprovalId ||
    next.review.kind !== 'CREATE_ENVELOPE' ||
    next.review.targetParticipantId !== actor.participantId ||
    next.review.targetPrivacyDomainId !== actor.privacyDomainId
  )
    throw new Error(requestFailure);
  return next;
}
class UnresolvedRequest extends Error {}
class DeniedRequest extends Error {}
function administratorKey(value?: { preparationApprovalId: string; principalId: string }) {
  return JSON.stringify(value ?? null);
}
function readState(value: unknown, handoffOnly: boolean): State {
  // A step-up response is a separate producer variant, never a loaded catalogue.
  if (value && typeof value === 'object' && 'requiresStepUp' in value) {
    return z.object({ actor: actorSchema, requiresStepUp: stepUpSchema }).parse(value);
  }
  const next = loadedSchema.parse(value);
  if (next.authorizedEmpty && next.items.length !== 0) throw new Error(readFailure);
  if (handoffOnly ? next.items.length !== 0 || next.authorizedEmpty : next.handoff !== undefined)
    throw new Error(readFailure);
  if (
    next.handoff?.envelope &&
    next.handoff.envelope.effect.id !== next.handoff.administrator.envelopeId
  )
    throw new Error(readFailure);
  return next;
}
async function json<T>(response: Response): Promise<T> {
  if (!response.ok) throw new Error(requestFailure);
  return response.json().catch(() => {
    throw new Error(requestFailure);
  }) as Promise<T>;
}
async function requestCommand<T>(value: unknown, signal?: AbortSignal) {
  let response: Response;
  try {
    response = await fetch('/api/v1/ui/rpc-access-workbench', {
      method: 'POST',
      signal,
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(value),
    });
  } catch {
    throw new UnresolvedRequest(requestFailure);
  }
  if (response.status >= 500) throw new UnresolvedRequest(requestFailure);
  if (!response.ok) throw new DeniedRequest(requestFailure);
  return json<T>(response).catch(() => {
    throw new UnresolvedRequest(requestFailure);
  });
}
function localTime(delta: number) {
  const date = new Date(Date.now() + delta);
  return new Date(date.getTime() - date.getTimezoneOffset() * 60_000).toISOString().slice(0, 16);
}

export function RpcPlatformAccess({
  handoffOnly = false,
}: { readonly handoffOnly?: boolean } = {}) {
  const mounted = useRef(false);
  const read = useRef<{ generation: number; controller?: AbortController }>({ generation: 0 });
  const readMode = useRef(handoffOnly);
  const currentActor = useRef('');
  const approvalSelection = useRef('');
  const [approvalSelector, setApprovalSelector] = useState('');
  const selection = useRef<{ preparationApprovalId: string; principalId: string } | undefined>(
    undefined,
  );
  const [storedState, setState] = useState<State>();
  const state = readMode.current === handoffOnly ? storedState : undefined;
  const [review, setReview] = useState<Review>();
  const [reservedApprovalId, setReservedApprovalId] = useState('');
  const reservationSelection = useRef('');
  const [status, setStatus] = useState('Loading Platform RPC assignments.');
  const [busy, setBusy] = useState(false);
  const mutation = useRef<Mutation | undefined>(undefined);
  const unresolved = useRef<Mutation | undefined>(undefined);
  const restoredResumption = useRef<Review | undefined>(undefined);
  const inputRevision = useRef(0);
  const frame = useRef({ state, review, mode: handoffOnly });
  const memoryReview = useRef<{ actor: Actor; value?: Review } | undefined>(undefined);
  useLayoutEffect(() => {
    frame.current = { state, review, mode: handoffOnly };
    const operation = mutation.current;
    if (
      operation &&
      !operation.sent &&
      !operation.reconciling &&
      (operation.state !== state ||
        operation.review !== review ||
        operation.context.mode !== handoffOnly)
    )
      operation.controller.abort();
  }, [state, review, handoffOnly]);
  const load = useCallback(
    async (original?: Mutation) => {
      original ??= unresolved.current;
      if (!mounted.current || readMode.current !== handoffOnly) return false;
      read.current.controller?.abort();
      const controller = new AbortController();
      const generation = read.current.generation + 1;
      read.current = { generation, controller };
      readMode.current = handoffOnly;
      const previousActor = currentActor.current;
      let requestedApproval = original
        ? (original.readApproval ?? original.review?.approvalRequestId ?? original.context.approval)
        : approvalSelection.current;
      let requestedAdministrator = original
        ? (JSON.parse(original.context.administrator) as typeof selection.current)
        : selection.current && { ...selection.current };
      const relevant = () => mounted.current && read.current.generation === generation;
      setState(undefined);
      setReview(undefined);
      setStatus('Loading Platform RPC assignments.');
      const creationReconciliation =
        original?.originalCommand !== null &&
        typeof original?.originalCommand === 'object' &&
        'command' in original.originalCommand &&
        original.originalCommand.command === 'RESUME_CREATE';
      try {
        const before = await readLocalSession(controller.signal);
        if (!relevant()) return false;
        if (
          original &&
          (before.principalId !== original.actor.principalId ||
            before.participantId !== original.actor.participantId ||
            before.contextMode !== original.actor.contextMode ||
            (before.privacyDomainId !== undefined &&
              before.privacyDomainId !== original.actor.privacyDomainId))
        )
          throw new Error(readFailure);
        if (handoffOnly && !original && !requestedAdministrator) {
          try {
            const retained = memoryReview.current;
            const raw = localStorage.getItem(storageKey);
            const saved = savedReviewSchema.safeParse(
              retained?.value
                ? { ...retained.value, actor: retained.actor }
                : raw
                  ? JSON.parse(raw)
                  : undefined,
            );
            if (
              saved.success &&
              matchesSession(saved.data.actor, before) &&
              saved.data.review.continuationHandoff?.principalId === before.principalId
            ) {
              requestedAdministrator = { ...saved.data.review.continuationHandoff };
              if (!requestedApproval)
                requestedApproval =
                  saved.data.approvalRequestId ??
                  saved.data.review.resumeDraft?.approvalRequestId ??
                  '';
            }
          } catch {
            /* Stored selectors only request authoritative readback. */
          }
        }
        const parameters = new URLSearchParams({
          mode: handoffOnly || creationReconciliation ? 'platform-handoff' : 'platform',
          ...((handoffOnly || creationReconciliation) && requestedApproval
            ? { approvalRequestId: requestedApproval }
            : {}),
          ...(handoffOnly ? requestedAdministrator : {}),
        });
        const payload = await fetch(`/api/v1/ui/rpc-access-workbench?${parameters}`, {
          cache: 'no-store',
          credentials: 'same-origin',
          signal: controller.signal,
        })
          .then(json<unknown>)
          .catch(() => undefined);
        if (!relevant()) return false;
        const after = await readLocalSession(controller.signal);
        if (!relevant()) return false;
        const next = readState(payload, handoffOnly);
        if (sessionKey(before) !== sessionKey(after) || !matchesSession(next.actor, after))
          throw new Error(readFailure);
        if (
          'handoff' in next &&
          next.handoff &&
          requestedAdministrator &&
          next.handoff.administrator.principalId !== requestedAdministrator.principalId
        )
          throw new Error(readFailure);
        if (
          'approvals' in next &&
          (handoffOnly || creationReconciliation) &&
          requestedApproval &&
          next.approvals.some((item) => item.approvalRequestId.slice(-36) !== requestedApproval)
        )
          throw new Error(readFailure);
        const changedActor = previousActor !== '' && previousActor !== actorKey(next.actor);
        if (
          original &&
          (next.actor.principalId !== original.actor.principalId ||
            next.actor.participantId !== original.actor.participantId ||
            next.actor.privacyDomainId !== original.actor.privacyDomainId ||
            next.actor.contextMode !== original.actor.contextMode)
        )
          throw new Error(readFailure);
        currentActor.current = actorKey(next.actor);
        if (changedActor) {
          approvalSelection.current = '';
          selection.current = undefined;
          setApprovalSelector('');
          setReservedApprovalId('');
          reservationSelection.current = '';
          if ('items' in next && handoffOnly && !original) {
            next.handoff = undefined;
            next.approvals = [];
            next.approvalsLoaded = false;
          }
        }
        // Pin selectors authenticated by the preparation reader before the proof.
        // Optional custody storage must not choose a different retry resource.
        if (
          !selection.current &&
          requestedAdministrator &&
          (('handoff' in next && next.handoff) || 'requiresStepUp' in next)
        )
          selection.current = { ...requestedAdministrator };
        if (!changedActor && !approvalSelection.current && requestedApproval) {
          approvalSelection.current = requestedApproval;
          setApprovalSelector(requestedApproval);
        }
        // Catalogue state cannot prove the outcome of an ambiguous original command.
        setState(next);
        setStatus(
          'requiresStepUp' in next
            ? 'Verify the registered Platform authenticator to load RPC assignments.'
            : handoffOnly
              ? 'Platform administrator handoff loaded.'
              : next.authorizedEmpty
                ? 'No authorized Participants are available.'
                : 'Platform RPC assignments loaded.',
        );
        try {
          // Optional persistence failure must not replace newer accepted in-memory custody.
          let saved: string | null = null;
          try {
            saved = localStorage.getItem(storageKey);
          } catch {
            /* storage is optional */
          }
          const retained = memoryReview.current;
          const value =
            retained && actorKey(retained.actor) === actorKey(next.actor)
              ? retained.value && { ...retained.value, actor: retained.actor }
              : saved
                ? JSON.parse(saved)
                : undefined;
          if (value) {
            const parsed = savedReviewSchema.parse(value);
            if (
              !('requiresStepUp' in next) &&
              actorKey(parsed.actor) === actorKey(next.actor) &&
              (!handoffOnly ||
                (next.handoff
                  ? parsed.review.resourceId === next.handoff.administrator.envelopeId
                  : parsed.review.kind === 'CREATE_ENVELOPE' &&
                    !!parsed.review.platformScopeReplacementId &&
                    (parsed.review.capabilityIds?.length ?? 0) === 0)) &&
              (!handoffOnly ||
                ((!requestedApproval ||
                  (parsed.approvalRequestId ?? parsed.review.resumeDraft?.approvalRequestId) ===
                    requestedApproval) &&
                  (!requestedAdministrator ||
                    parsed.review.resourceId === next.handoff?.administrator.envelopeId)))
            ) {
              const envelope =
                'items' in next
                  ? [
                      ...next.items.flatMap((item) => item.envelopes),
                      ...(next.handoff?.envelope ? [next.handoff.envelope] : []),
                    ].find((item) => item.effect.id === parsed.review.resourceId)?.effect
                  : undefined;
              const completedSubmission =
                parsed.review.kind === 'SUBMIT_ENVELOPE' &&
                (envelope?.state === 'APPROVED' || envelope?.state === 'ACTIVE');
              const completedActivation =
                parsed.review.kind === 'ACTIVATE_ENVELOPE' && envelope?.state === 'ACTIVE';
              const completedRevocation =
                parsed.review.kind === 'REVOKE_ENVELOPE' && envelope?.state === 'REVOKED';
              if (
                !unresolved.current &&
                (completedSubmission || completedActivation || completedRevocation)
              ) {
                memoryReview.current = { actor: next.actor };
                setReview(undefined);
                // A catalogue can retire visible controls, but cannot prove this
                // original command's outcome or delete its persisted custody.
              } else {
                memoryReview.current = { actor: next.actor, value: parsed };
                // Saved custody does not say whether the original RESUME reached
                // its durable owner. Restore a draft into observation only.
                if (parsed.review.resumeDraft) restoredResumption.current = parsed;
                setReview(parsed);
                if (!requestedApproval && !changedActor)
                  approvalSelection.current =
                    parsed.approvalRequestId ?? parsed.review.resumeDraft?.approvalRequestId ?? '';
              }
            }
          }
        } catch {
          // Invalid or foreign custody is unavailable here; preserve its original bytes.
        }
        // A read-specific proof request cannot establish the linked child's
        // authoritative handoff or release the original ambiguity latch.
        return (
          !original?.reconciling ||
          (!('requiresStepUp' in next) &&
            !!next.handoff &&
            next.approvalsLoaded === true &&
            next.approvals.some(
              (item) =>
                item.approvalRequestId.slice(-36) === requestedApproval &&
                item.candidateDigest === original.review?.review.candidateDigest,
            ))
        );
      } catch {
        if (relevant()) setStatus(readFailure);
        return false;
      }
    },
    [handoffOnly],
  );
  useLayoutEffect(() => {
    mounted.current = true;
    setBusy(false);
    readMode.current = handoffOnly;
    void load();
    return () => {
      mounted.current = false;
      mutation.current?.controller.abort();
      mutation.current = undefined;
      read.current.generation += 1;
      read.current.controller?.abort();
    };
  }, [load]);
  const captureContext = (): MutationContext => ({
    generation: read.current.generation,
    actor: actorKey(state?.actor),
    mode: handoffOnly,
    approval: approvalSelection.current,
    administrator: administratorKey(selection.current),
    reservation: reservationSelection.current,
  });
  const sameContext = (context: MutationContext) =>
    mounted.current &&
    context.actor !== '' &&
    readMode.current === context.mode &&
    read.current.generation === context.generation &&
    currentActor.current === context.actor &&
    approvalSelection.current === context.approval &&
    administratorKey(selection.current) === context.administrator &&
    reservationSelection.current === context.reservation;
  const showMutationStatus = (message: string, context: MutationContext) => {
    if (sameContext(context)) setStatus(message);
  };
  const save = (value: Review, context: MutationContext, operation: Mutation) => {
    let displayed: MutationContext | undefined;
    if (
      mutation.current === operation &&
      sameContext(context) &&
      (operation.sent || operation.reconciling || currentMutation(operation))
    ) {
      if (value.review.continuationHandoff) {
        if (value.review.continuationHandoff.principalId !== operation.actor.principalId)
          throw new Error(requestFailure);
        selection.current = { ...value.review.continuationHandoff };
        operation.context = {
          ...operation.context,
          administrator: administratorKey(selection.current),
        };
      }
      approvalSelection.current = value.approvalRequestId ?? '';
      setReview(value);
      displayed = captureContext();
    }
    if (
      mutation.current === operation &&
      mounted.current &&
      readMode.current === context.mode &&
      currentActor.current === context.actor
    ) {
      memoryReview.current = { actor: operation.actor, value };
    }
    try {
      const raw = localStorage.getItem(storageKey);
      const prior = raw ? savedReviewSchema.safeParse(JSON.parse(raw)) : undefined;
      const accepted = savedReviewSchema.parse({ ...value, actor: operation.actor });
      const matches = (original: Review) =>
        prior?.success &&
        actorKey(prior.data.actor) === actorKey(accepted.actor) &&
        prior.data.reviewToken === original.reviewToken &&
        prior.data.approvalRequestId === original.approvalRequestId &&
        JSON.stringify(reviewFieldsSchema.strip().parse(prior.data.review)) ===
          JSON.stringify(reviewFieldsSchema.strip().parse(original.review));
      if (
        !raw ||
        matches(value) ||
        ((operation.sent || operation.reconciling) && operation.review && matches(operation.review))
      )
        localStorage.setItem(storageKey, JSON.stringify(accepted));
    } catch {
      /* Current accepted custody remains in memory; unrelated saved originals stay intact. */
    }
    return displayed;
  };
  const refreshMutation = async (context: MutationContext) => {
    if (!sameContext(context) || !(await load()) || currentActor.current !== context.actor)
      return undefined;
    return captureContext();
  };
  const currentMutation = (operation: Mutation) =>
    mutation.current === operation &&
    !operation.controller.signal.aborted &&
    frame.current.state === operation.state &&
    frame.current.review === operation.review &&
    frame.current.mode === operation.context.mode &&
    inputRevision.current === operation.inputRevision &&
    sameContext(operation.context);
  const assertMutation = (operation = mutation.current) => {
    if (!operation || !currentMutation(operation)) throw new Error(requestFailure);
    return operation;
  };
  const invalidateInput = () => {
    inputRevision.current += 1;
    if (mutation.current && !mutation.current.sent) mutation.current.controller.abort();
  };
  const stepUp = async (
    action: Parameters<typeof performWebAuthnStepUp>[0],
    binding: Parameters<typeof performWebAuthnStepUp>[1],
  ) => {
    const operation = assertMutation();
    await performWebAuthnStepUp(action, binding, {
      signal: operation.controller.signal,
      isCurrent: () => currentMutation(operation),
    });
    assertMutation(operation);
    try {
      const actual = await readLocalSession(operation.controller.signal);
      assertMutation(operation);
      if (!matchesSession(operation.actor, actual)) throw new Error(requestFailure);
    } catch {
      if (
        !operation.controller.signal.aborted &&
        mutation.current === operation &&
        mounted.current &&
        frame.current.state === operation.state
      ) {
        currentActor.current = '';
        setState(undefined);
        setReview(undefined);
        setStatus(readFailure);
      }
      throw new Error(requestFailure);
    }
    assertMutation(operation);
  };
  const readOriginal = async (operation: Mutation) => {
    if (
      mutation.current !== operation ||
      !mounted.current ||
      readMode.current !== operation.context.mode ||
      currentActor.current !== operation.context.actor
    )
      return undefined;
    if (!(await load(operation))) return undefined;
    return captureContext();
  };
  const observeResumption = async (operation: Mutation, original: Review, actor: Actor) => {
    const draft = original.review.resumeDraft;
    if (!draft || actorKey(operation.actor) !== actorKey(actor)) throw new Error(requestFailure);
    assertMutation(operation);
    const before = await readLocalSession(operation.controller.signal);
    assertMutation(operation);
    if (!matchesSession(actor, before)) throw new Error(requestFailure);
    const response = await requestCommand<unknown>(
      {
        command: 'PREVIEW_CONTINUE_ACTIVATION',
        approvalRequestId: draft.approvalRequestId,
        enrollmentId: draft.enrollmentId,
        recoveryId: draft.recoveryId,
      },
      operation.controller.signal,
    );
    assertMutation(operation);
    const after = await readLocalSession(operation.controller.signal);
    assertMutation(operation);
    if (sessionKey(before) !== sessionKey(after) || !matchesSession(actor, after))
      throw new Error(requestFailure);
    return decodeResumption(response, original);
  };
  const reconcileResumption = async (operation: Mutation) => {
    const original = operation.review;
    if (
      !original ||
      !original.review.resumeDraft ||
      unresolved.current !== operation ||
      !operation.sent ||
      !operation.originalCommand ||
      typeof operation.originalCommand !== 'object' ||
      !('command' in operation.originalCommand) ||
      operation.originalCommand.command !== 'RESUME' ||
      !('reviewToken' in operation.originalCommand) ||
      operation.originalCommand.reviewToken !== original.reviewToken
    )
      throw new Error(requestFailure);
    // This public reader observes the original metadata attempt. It cannot
    // issue another RESUME or activate the business envelope.
    // A still-unresolved draft is not a successor. The same strict decoder
    // binds the original business intent and requires a distinct linked child.
    return observeResumption(operation, original, operation.actor);
  };
  const readResumptionOutcome = async () => {
    const operation = assertMutation();
    const pending = unresolved.current;
    const original = pending?.review ?? operation.review;
    const actor = pending?.actor ?? operation.actor;
    const handoff = original?.review.continuationHandoff;
    if (
      !original?.review.resumeDraft ||
      !handoff ||
      !('handoff' in operation.state) ||
      operation.state.handoff?.administrator.envelopeId !== original.review.resourceId ||
      actorKey(actor) !== actorKey(operation.actor) ||
      handoff.principalId !== actor.principalId ||
      administratorKey(handoff) !== operation.context.administrator
    )
      throw new Error(requestFailure);
    const next = await observeResumption(operation, original, actor);
    assertMutation(operation);
    // A real linked child is known; keep that observation stable while its
    // supported handoff read replaces the rendered read state.
    operation.reconciling = true;
    operation.review = original;
    operation.readApproval = next.approvalRequestId;
    const retained = pending ?? operation;
    if (!pending) unresolved.current = retained;
    const refreshed = await readOriginal(operation);
    if (
      !refreshed ||
      mutation.current !== operation ||
      inputRevision.current !== operation.inputRevision ||
      currentActor.current !== actorKey(actor) ||
      !sameContext(refreshed) ||
      administratorKey(selection.current) !== administratorKey(handoff)
    ) {
      // Keep subsequent proof/readback bound to the original draft until the
      // child handoff is actually available. A preview alone is insufficient.
      retained.readApproval = original.review.resumeDraft.approvalRequestId;
      return;
    }
    const displayed = save(next, refreshed, operation);
    if (!displayed) return;
    if (unresolved.current === retained) unresolved.current = undefined;
    if (restoredResumption.current?.reviewToken === original.reviewToken)
      restoredResumption.current = undefined;
    showMutationStatus(
      'The original activation approval was resumed. Independent checker approval is required.',
      displayed,
    );
  };
  const command = async <T,>(value: unknown) => {
    const operation = assertMutation();
    const creationResume =
      typeof value === 'object' &&
      value !== null &&
      'command' in value &&
      value.command === 'RESUME_CREATE';
    const business =
      typeof value === 'object' &&
      value !== null &&
      'command' in value &&
      ['SUBMIT', 'RESUME', 'RESUME_CREATE', 'APPROVE', 'COMMIT'].includes(String(value.command));
    if (business) {
      operation.originalCommand = value;
      if ('approvalRequestId' in value && typeof value.approvalRequestId === 'string')
        operation.readApproval = value.approvalRequestId;
      operation.sent = true;
      unresolved.current = operation;
    }
    try {
      return await requestCommand<T>(value, business ? undefined : operation.controller.signal);
    } catch (error) {
      if (business && error instanceof DeniedRequest && unresolved.current === operation)
        unresolved.current = undefined;
      if (
        business &&
        (error instanceof UnresolvedRequest ||
          (creationResume && !(error instanceof DeniedRequest)))
      ) {
        if (mutation.current === operation) unresolved.current = operation;
        if (operation.review?.review.resumeDraft) {
          try {
            return (await reconcileResumption(operation)) as T;
          } catch {
            // Keep the exact original custody and unresolved latch when the
            // reader denies, remains ambiguous, or the local context changes.
          }
        }
        // Preserve the exact original token/body/selector. No business replay is issued here.
        const refreshed = await readOriginal(operation);
        if (refreshed)
          showMutationStatus(
            'The original RPC envelope request requires authoritative reconciliation before continuing.',
            refreshed,
          );
      }
      throw error;
    }
  };
  const run = async (work: () => Promise<void>, proofOnly = false) => {
    if (mutation.current || !state || !mounted.current) return;
    if ((unresolved.current || restoredResumption.current) && !proofOnly) {
      setStatus(
        'The original RPC envelope request requires authoritative reconciliation before continuing.',
      );
      return;
    }
    const operation: Mutation = {
      context: captureContext(),
      actor: state.actor,
      state,
      review,
      inputRevision: inputRevision.current,
      controller: new AbortController(),
      sent: false,
    };
    mutation.current = operation;
    setBusy(true);
    try {
      await work();
    } catch {
      if (operation.sent ? mutation.current === operation : currentMutation(operation))
        showMutationStatus(
          unresolved.current === operation
            ? 'The request was not completed. The original RPC envelope request requires authoritative reconciliation before continuing.'
            : requestFailure,
          operation.context,
        );
    } finally {
      if (mutation.current === operation) {
        mutation.current = undefined;
        if (mounted.current) setBusy(false);
      }
    }
  };
  const currentApproval =
    state && 'approvals' in state
      ? state.approvals.find(
          (item) =>
            item.approvalRequestId.slice(-36) === review?.approvalRequestId &&
            item.candidateDigest === review?.review.candidateDigest,
        )
      : undefined;
  async function prepare(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const operation = assertMutation();
    const context = captureContext();
    const input = new FormData(event.currentTarget);
    const response = await command<unknown>({
      command: 'PREVIEW_ENVELOPE',
      envelopeId: String(input.get('envelopeId') ?? '') || undefined,
      resourceReservationId: reservedApprovalId || undefined,
      targetParticipantId: input.get('targetParticipantId'),
      targetPrivacyDomainId: input.get('targetPrivacyDomainId'),
      capabilityIds: input.getAll('capabilityIds').map(String),
      resourceIds: String(input.get('resourceIds'))
        .split(',')
        .map((value) => value.trim())
        .filter(Boolean),
      targetProfileIds: String(input.get('targetProfileIds'))
        .split(',')
        .map((value) => value.trim())
        .filter(Boolean),
      validUntil: new Date(String(input.get('validUntil'))).toISOString(),
      makerCheckerRequired: input.has('makerCheckerRequired'),
      stepUpRequired: input.has('stepUpRequired'),
      reason: input.get('reason'),
    });
    const next = decodePreview(
      response,
      'CREATE_ENVELOPE',
      String(input.get('targetParticipantId')),
      String(input.get('targetPrivacyDomainId')),
      String(input.get('envelopeId') ?? '') || undefined,
    );
    if (
      next.review.reason !== String(input.get('reason')).trim() ||
      JSON.stringify(next.review.capabilityIds) !==
        JSON.stringify(input.getAll('capabilityIds').map(String)) ||
      next.review.makerCheckerRequired !== input.has('makerCheckerRequired') ||
      next.review.stepUpRequired !== input.has('stepUpRequired')
    )
      throw new Error(requestFailure);
    const displayed = save(next, context, operation);
    if (displayed)
      showMutationStatus('The Platform-root RPC envelope review is locked.', displayed);
  }
  async function resumeCreation(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const operation = assertMutation();
    const context = captureContext();
    const input = new FormData(event.currentTarget);
    const originalApprovalId = identifier.parse(String(input.get('approvalRequestId')));
    const response = await command<unknown>({
      command: 'RESUME_CREATE',
      approvalRequestId: originalApprovalId,
      reason:
        'Continue the unchanged RPC envelope creation using fresh administrator authorization.',
    });
    let next: Review;
    try {
      next = decodeCreationResume(response, operation.actor, originalApprovalId);
    } catch {
      const refreshed = await readOriginal(operation);
      if (refreshed)
        showMutationStatus(
          'The original RPC envelope request requires authoritative reconciliation before continuing.',
          refreshed,
        );
      throw new Error(requestFailure);
    }
    if (unresolved.current === operation) unresolved.current = undefined;
    const displayed = save(next, context, operation);
    if (displayed)
      showMutationStatus(
        'The original RPC envelope creation was resumed. Fresh independent approval is required.',
        displayed,
      );
  }
  async function reconcileCreation() {
    const operation = assertMutation();
    const retained = pendingCreation(unresolved.current);
    const context = captureContext();
    if (
      !retained ||
      operation.actor.role !== 'operator' ||
      context.mode ||
      operation.actor.principalId !== retained.original.actor.principalId ||
      operation.actor.participantId !== retained.original.actor.participantId ||
      operation.actor.privacyDomainId !== retained.original.actor.privacyDomainId
    )
      throw new Error(requestFailure);
    try {
      const before = await readLocalSession(operation.controller.signal);
      assertMutation(operation);
      if (!matchesSession(operation.actor, before)) throw new Error(requestFailure);
      const response = await command<unknown>({
        ...retained.input,
        command: 'PREVIEW_CONTINUE_CREATION',
      });
      assertMutation(operation);
      const after = await readLocalSession(operation.controller.signal);
      assertMutation(operation);
      if (sessionKey(before) !== sessionKey(after) || !matchesSession(operation.actor, after))
        throw new Error(requestFailure);
      const next = decodeCreationResume(
        response,
        operation.actor,
        retained.input.approvalRequestId,
      );
      if (unresolved.current !== retained.original) throw new Error(requestFailure);
      const displayed = save(next, context, operation);
      if (!displayed) throw new Error(requestFailure);
      unresolved.current = undefined;
      showMutationStatus(
        'The original RPC envelope creation was confirmed. Fresh independent approval is required.',
        displayed,
      );
    } catch {
      if (currentMutation(operation))
        showMutationStatus(
          'The original RPC envelope request requires authoritative reconciliation before continuing.',
          context,
        );
    }
  }
  async function prepareSubmission(envelopeId: string) {
    const operation = assertMutation();
    const context = captureContext();
    const response = await command<unknown>({
      command: 'PREVIEW_SUBMIT',
      resourceReservationId: reservedApprovalId || undefined,
      envelopeId,
      reason: 'Submit the typed Platform-root RPC envelope for independent approval.',
    });
    const next = decodePreview(
      response,
      'SUBMIT_ENVELOPE',
      state!.actor.participantId,
      state!.actor.privacyDomainId,
      envelopeId,
    );
    const displayed = save(next, context, operation);
    if (displayed) showMutationStatus('The envelope submission review is locked.', displayed);
  }
  async function prepareActivation(envelopeId: string) {
    const operation = assertMutation();
    const context = captureContext();
    const response = await command<unknown>({
      command: 'PREVIEW_ACTIVATE',
      resourceReservationId: reservedApprovalId || undefined,
      envelopeId,
      reason: 'Activate the approved Platform-root RPC capability envelope.',
    });
    const next = decodePreview(
      response,
      'ACTIVATE_ENVELOPE',
      state!.actor.participantId,
      state!.actor.privacyDomainId,
      envelopeId,
    );
    const displayed = save(next, context, operation);
    if (displayed) showMutationStatus('The envelope activation review is locked.', displayed);
  }
  async function prepareContinuation(event: React.FormEvent<HTMLFormElement>) {
    const form = new FormData(event.currentTarget);
    const approvalRequestId = identifier.parse(form.get('originalApprovalRequestId'));
    const enrollmentId = identifier.parse(form.get('receivingEnrollmentId'));
    const recoveryId = identifier.parse(form.get('receivingRecoveryId'));
    const operation = assertMutation();
    const context = captureContext();
    const response = await command<unknown>({
      command: 'PREVIEW_CONTINUE_ACTIVATION',
      approvalRequestId,
      enrollmentId,
      recoveryId,
    });
    const next = reviewResponseSchema.parse(response);
    const draft = next.review.resumeDraft;
    if (
      next.review.kind !== 'ACTIVATE_ENVELOPE' ||
      next.review.targetParticipantId !== state!.actor.participantId ||
      next.review.targetPrivacyDomainId !== state!.actor.privacyDomainId ||
      next.review.continuationHandoff?.principalId !== state!.actor.principalId ||
      (draft
        ? next.approvalRequestId !== undefined ||
          draft.approvalRequestId !== approvalRequestId ||
          draft.enrollmentId !== enrollmentId ||
          draft.recoveryId !== recoveryId
        : next.approvalRequestId === undefined || next.approvalRequestId === approvalRequestId)
    )
      throw new Error(requestFailure);
    if (next.approvalRequestId) operation.readApproval = next.approvalRequestId;
    const displayed = save(next, context, operation);
    if (displayed)
      showMutationStatus(
        draft
          ? 'The original activation approval is ready for a fresh receiving passkey proof.'
          : 'The original activation approval was already resumed.',
        displayed,
      );
    // The preview authorizes no effect and precedes the receiving assertion.
    // Keep its proof controls visible; current handoff readback follows RESUME.
    if (displayed && !draft) await readOriginal(operation);
  }
  async function prepareRevocation(envelopeId: string) {
    const operation = assertMutation();
    const context = captureContext();
    const response = await command<unknown>({
      command: 'PREVIEW_REVOKE',
      resourceReservationId: reservedApprovalId || undefined,
      envelopeId,
      reason: 'Remove these RPC capability bounds from the Participant.',
    });
    const next = decodePreview(
      response,
      'REVOKE_ENVELOPE',
      state!.actor.participantId,
      state!.actor.privacyDomainId,
      envelopeId,
    );
    const displayed = save(next, context, operation);
    if (displayed) showMutationStatus('The RPC envelope revocation review is locked.', displayed);
  }
  async function submit() {
    if (!review) return;
    const operation = assertMutation();
    const context = captureContext();
    if (review.review.resumeDraft)
      operation.readApproval = review.review.resumeDraft.approvalRequestId;
    await stepUp(
      { ...review.review.stepUp, stepUp: 'FRESH_WEBAUTHN_MAX_5M' },
      {
        resourceId: review.review.stepUp.resourceId,
        resourceDigest: review.review.stepUp.resourceDigest,
      },
    );
    const response = await command<unknown>({
      command: review.review.resumeDraft ? 'RESUME' : 'SUBMIT',
      reviewToken: review.reviewToken,
    });
    let next: Review;
    if (review.review.resumeDraft) {
      try {
        next = decodeResumption(response, review);
      } catch {
        next = await reconcileResumption(operation);
      }
    } else next = decodeSubmission(response, review);
    if (unresolved.current === operation) unresolved.current = undefined;
    operation.readApproval = next.approvalRequestId;
    save(next, context, operation);
    const refreshed = await readOriginal(operation);
    if (refreshed)
      showMutationStatus(
        review.review.resumeDraft
          ? 'The original activation approval was resumed. Independent checker approval is required.'
          : review.review.kind === 'SUBMIT_ENVELOPE'
            ? 'Envelope submission approval requested.'
            : review.review.kind === 'ACTIVATE_ENVELOPE'
              ? 'Envelope activation approval requested.'
              : review.review.kind === 'REVOKE_ENVELOPE'
                ? 'Envelope revocation approval requested.'
                : 'The RPC envelope is staged and one checker approval was requested.',
        refreshed,
      );
  }
  async function approve(item: Approval) {
    if (!item.stepUp) return;
    const operation = assertMutation();
    await stepUp(
      { ...item.stepUp, stepUp: 'FRESH_WEBAUTHN_MAX_5M' },
      { resourceId: item.stepUp.resourceId, resourceDigest: item.stepUp.resourceDigest },
    );
    const response = await command<unknown>({
      command: 'APPROVE',
      approvalRequestId: item.approvalRequestId.slice(-36),
      candidateDigest: item.candidateDigest,
    });
    decodeDecision(response, item, state!.actor.principalId);
    if (unresolved.current === operation) unresolved.current = undefined;
    const refreshed = operation && (await readOriginal(operation));
    if (refreshed) showMutationStatus('The exact RPC envelope candidate was approved.', refreshed);
  }
  async function commit() {
    if (!review?.approvalRequestId) return;
    const operation = assertMutation();
    const context = captureContext();
    const kind = review.review.kind;
    await stepUp(
      { ...review.review.stepUp, stepUp: 'FRESH_WEBAUTHN_MAX_5M' },
      {
        resourceId: review.review.stepUp.resourceId,
        resourceDigest: review.review.stepUp.resourceDigest,
      },
    );
    const response = await command<unknown>({
      command: 'COMMIT',
      reviewToken: review.reviewToken,
      approvalRequestId: review.approvalRequestId,
    });
    decodeCommit(response, review);
    if (unresolved.current === operation) unresolved.current = undefined;
    if (
      mutation.current === operation &&
      mounted.current &&
      readMode.current === context.mode &&
      currentActor.current === context.actor
    ) {
      memoryReview.current = { actor: operation.actor };
      setReview(undefined);
      removeSavedReview(review, operation.actor);
    }
    const refreshed = operation && (await readOriginal(operation));
    if (refreshed)
      showMutationStatus(
        kind === 'ACTIVATE_ENVELOPE'
          ? 'The Platform-root RPC envelope is ACTIVE.'
          : kind === 'REVOKE_ENVELOPE'
            ? 'The Platform-root RPC envelope is REVOKED.'
            : 'The Platform-root RPC envelope is durable. Submit it for independent approval.',
        refreshed,
      );
  }
  const creationCustody = pendingCreation(unresolved.current);
  if (!state)
    return (
      <section className={panel}>
        <h2 className="text-xl font-semibold">Platform RPC access</h2>
        <p className="mt-3" role="status">
          {status}
        </p>
        <button className={button + ' mt-3'} disabled={busy} onClick={() => void load()}>
          {handoffOnly ? 'Refresh administrator handoff' : 'Refresh Platform RPC access'}
        </button>
      </section>
    );
  if ('requiresStepUp' in state)
    return (
      <section className={panel}>
        <h2 className="text-xl font-semibold">Platform RPC access</h2>
        <p className="mt-3" role="status">
          {status}
        </p>
        <button
          className={`${button} mt-4`}
          disabled={busy}
          onClick={() =>
            void run(async () => {
              const context = captureContext();
              await stepUp(
                { ...state.requiresStepUp, stepUp: 'FRESH_WEBAUTHN_MAX_5M' },
                {
                  resourceId: state.requiresStepUp.resourceId,
                  resourceDigest: state.requiresStepUp.resourceDigest,
                },
              );
              await refreshMutation(context);
            }, true)
          }
        >
          {handoffOnly
            ? 'Verify Platform authenticator and read administrator handoff'
            : 'Verify Platform authenticator and load RPC assignments'}
        </button>
      </section>
    );
  return (
    <div className="mt-6 space-y-6">
      {handoffOnly && (
        <section className={panel} aria-label="Exact envelope approval">
          <label className="grid gap-1">
            Envelope approval ID
            <input
              className={field}
              value={approvalSelector}
              onChange={(event) => {
                invalidateInput();
                read.current.generation += 1;
                read.current.controller?.abort();
                approvalSelection.current = '';
                setApprovalSelector(event.target.value);
                setReview(undefined);
                setState((current) =>
                  current && 'items' in current
                    ? { ...current, approvals: [], approvalsLoaded: false }
                    : current,
                );
              }}
            />
          </label>
          <button
            className={button + ' mt-3'}
            disabled={busy || !approvalSelector}
            onClick={() => {
              approvalSelection.current = approvalSelector;
              void load();
            }}
          >
            Load envelope approval
          </button>
        </section>
      )}
      <SecondaryPanel
        title="Approval references"
        inline={handoffOnly}
        closeOnChange={currentActor.current}
      >
        <label className="grid gap-1 mt-4">
          Reserved approval operation ID
          <input
            className={field}
            value={reservedApprovalId}
            onChange={(event) => {
              invalidateInput();
              read.current.generation += 1;
              read.current.controller?.abort();
              reservationSelection.current = event.target.value;
              setReservedApprovalId(event.target.value);
              setReview(undefined);
            }}
          />
        </label>
      </SecondaryPanel>
      {handoffOnly && (
        <>
          <section
            className={panel}
            aria-label="Prepare approved successor administration envelope"
          >
            <h2 className="text-lg font-semibold">Prepare a declared successor administrator</h2>
            <p className="mt-2">
              Use the consumed replacement preparation approval. This loads the exact declared
              administration envelope for the normal approval, submission and activation steps. It
              grants no runtime capabilities.
            </p>
            <form
              className="mt-3 grid gap-3 md:grid-cols-2"
              onChangeCapture={invalidateInput}
              onSubmit={(event) => {
                event.preventDefault();
                if (mutation.current) return;
                const data = new FormData(event.currentTarget);
                selection.current = {
                  preparationApprovalId: String(data.get('replacementPreparationApprovalId')),
                  principalId: String(data.get('administratorPrincipalId')),
                };
                void run(async () => {
                  const operation = assertMutation();
                  const context = captureContext();
                  const response = await command<unknown>({
                    command: 'PREVIEW_PENDING_ADMINISTRATOR',
                    resourceReservationId: reservedApprovalId || undefined,
                    approvalRequestId: data.get('replacementPreparationApprovalId'),
                    principalId: data.get('administratorPrincipalId'),
                    reason:
                      'Prepare the exact administration envelope declared by the approved Platform replacement.',
                  });
                  const next = decodePreview(
                    response,
                    'CREATE_ENVELOPE',
                    state.actor.participantId,
                    state.actor.privacyDomainId,
                    state.handoff?.administrator.principalId ===
                      data.get('administratorPrincipalId')
                      ? state.handoff.administrator.envelopeId
                      : undefined,
                  );
                  if (
                    next.review.capabilityIds?.length !== 0 ||
                    !next.review.platformScopeReplacementId
                  )
                    throw new Error(requestFailure);
                  const displayed = save(next, context, operation);
                  if (displayed)
                    showMutationStatus(
                      'The declared successor administration envelope is ready for independent approval.',
                      displayed,
                    );
                });
              }}
            >
              <label>
                Consumed replacement preparation approval ID
                <input
                  className={field}
                  name="replacementPreparationApprovalId"
                  required
                  defaultValue={selection.current?.preparationApprovalId}
                  onChange={() => {
                    read.current.generation += 1;
                    read.current.controller?.abort();
                    selection.current = undefined;
                    setReview(undefined);
                    setState((current) =>
                      current && 'items' in current ? { ...current, handoff: undefined } : current,
                    );
                  }}
                />
              </label>
              <label>
                Declared administrator principal ID
                <input
                  className={field}
                  name="administratorPrincipalId"
                  required
                  defaultValue={selection.current?.principalId}
                  onChange={() => {
                    read.current.generation += 1;
                    read.current.controller?.abort();
                    selection.current = undefined;
                    setReview(undefined);
                    setState((current) =>
                      current && 'items' in current ? { ...current, handoff: undefined } : current,
                    );
                  }}
                />
              </label>
              {state.actor.role === 'operator' && (
                <button className={button} disabled={busy} type="submit">
                  Review declared administration envelope
                </button>
              )}
              {handoffOnly && (
                <button
                  className={button}
                  disabled={busy}
                  type="button"
                  onClick={(event) => {
                    const form = event.currentTarget.form;
                    if (!form || !form.reportValidity()) return;
                    const data = new FormData(form);
                    selection.current = {
                      preparationApprovalId: String(data.get('replacementPreparationApprovalId')),
                      principalId: String(data.get('administratorPrincipalId')),
                    };
                    void load();
                  }}
                >
                  Read declared administrator records
                </button>
              )}
            </form>
          </section>
        </>
      )}
      {handoffOnly && (
        <section className={panel} aria-label="Declared administrator records">
          <h2 className="text-xl font-semibold">Declared administrator records</h2>
          <p role="status">{status}</p>
          <button className={button + ' mt-3'} disabled={busy} onClick={() => void load()}>
            Refresh administrator handoff
          </button>
          {state.handoff ? (
            <>
              <p className="break-all">Replacement: {state.handoff.replacementId}</p>
              <p className="break-all">Principal: {state.handoff.administrator.principalId}</p>
              <p className="break-all">Envelope: {state.handoff.administrator.envelopeId}</p>
              <p className="break-all">Assignment: {state.handoff.administrator.assignmentId}</p>
              {state.handoff.envelope ? (
                <>
                  <p>
                    {state.handoff.envelope.effect.state} · revision{' '}
                    {state.handoff.envelope.effect.revision ?? 'unavailable'}
                  </p>
                  <p className="break-all">
                    Operation: {state.handoff.envelope.operationId ?? 'pending activation'}
                  </p>
                  {state.actor.role === 'operator' &&
                    state.handoff.envelope.effect.state === 'DRAFT' && (
                      <button
                        className={button}
                        disabled={busy}
                        onClick={() =>
                          void run(() => prepareSubmission(state.handoff!.administrator.envelopeId))
                        }
                      >
                        Review envelope submission
                      </button>
                    )}
                  {state.actor.role === 'operator' &&
                    state.handoff.envelope.effect.state === 'APPROVED' && (
                      <button
                        className={button}
                        disabled={busy}
                        onClick={() =>
                          void run(() => prepareActivation(state.handoff!.administrator.envelopeId))
                        }
                      >
                        Review envelope activation
                      </button>
                    )}
                </>
              ) : (
                <p>The exact envelope is unavailable. This does not prove handoff readiness.</p>
              )}
            </>
          ) : (
            <p>
              Select the consumed preparation approval and declared administrator to read their
              exact records.
            </p>
          )}
        </section>
      )}
      {!handoffOnly && (
        <section className={panel}>
          <h2 className="text-xl font-semibold">RPC methods assigned to Participants</h2>
          <p className="mt-2 text-[color:var(--muted)]">
            These envelopes bound what each Participant may grant. They do not grant workload access
            by themselves.
          </p>
          <p className="mt-2 text-[color:var(--muted)]">
            RPC capability bounds are immutable. To retain selected methods, activate a narrower
            successor before revoking the original envelope.
          </p>
          <p className="mt-3" role="status">
            {status}
          </p>
          <button className={button + ' mt-3'} disabled={busy} onClick={() => void load()}>
            Refresh Platform RPC access
          </button>
          <div className="mt-4 grid gap-4 lg:grid-cols-2">
            {state.items.map(({ participant, envelopes }) => (
              <article
                className="rounded border border-[color:var(--border)] p-3"
                key={participant.participantId}
              >
                <h3 className="font-semibold">{participant.displayName}</h3>
                <p className="break-all text-sm">{participant.participantId}</p>
                <p>
                  {participant.state} · revision {participant.rowVersion}
                </p>
                {envelopes.length === 0 ? (
                  <p className="mt-3">No governed RPC envelopes are recorded.</p>
                ) : (
                  <ul className="mt-3 space-y-2">
                    {envelopes.map(({ effect, operationId }) => (
                      <li
                        className="rounded border border-[color:var(--border)] p-2"
                        key={effect.id}
                      >
                        <p className="break-all text-sm">{effect.id}</p>
                        <p>
                          {effect.state} · revision {effect.revision ?? 'unavailable'} ·{' '}
                          {(effect.capabilityIds ?? []).join(', ') || 'No RPC capabilities'}
                        </p>
                        <p className="break-all text-xs">
                          Operation: {operationId ?? 'pending activation'}
                        </p>
                        {state.actor.role === 'operator' && effect.state === 'DRAFT' ? (
                          <button
                            className={button + ' mt-3'}
                            disabled={busy}
                            onClick={() => void run(() => prepareSubmission(effect.id))}
                          >
                            Review envelope submission
                          </button>
                        ) : null}
                        {state.actor.role === 'operator' && effect.state === 'APPROVED' ? (
                          <button
                            className={button + ' mt-3'}
                            disabled={busy}
                            onClick={() => void run(() => prepareActivation(effect.id))}
                          >
                            Review envelope activation
                          </button>
                        ) : null}
                        {state.actor.role === 'operator' && effect.state === 'ACTIVE' ? (
                          <button
                            className={button + ' mt-3'}
                            disabled={busy}
                            onClick={() => void run(() => prepareRevocation(effect.id))}
                          >
                            Review RPC envelope revocation
                          </button>
                        ) : null}
                      </li>
                    ))}
                  </ul>
                )}
              </article>
            ))}
          </div>
        </section>
      )}
      {state.actor.role === 'operator' && !handoffOnly && (
        <section className={panel} aria-label="Continue RPC envelope creation">
          <form
            onSubmit={(event) => {
              event.preventDefault();
              void run(() => resumeCreation(event));
            }}
            className="space-y-3"
          >
            <h2 className="text-xl font-semibold">Continue an unfinished RPC envelope</h2>
            <p>
              Use the original creation approval ID. The existing access period and requested
              permissions are preserved.
            </p>
            <label className="grid gap-1">
              Original creation approval ID
              <input
                className={field}
                name="approvalRequestId"
                required
                onChange={invalidateInput}
              />
            </label>
            <button className={button} disabled={busy}>
              Resume original envelope creation
            </button>
            {creationCustody && (
              <div className="space-y-3">
                <p className="break-all">
                  Original creation approval: {creationCustody.input.approvalRequestId}
                </p>
                <button
                  className={button}
                  disabled={busy}
                  type="button"
                  onClick={() => void run(reconcileCreation, true)}
                >
                  Read original creation outcome
                </button>
              </div>
            )}
          </form>
        </section>
      )}
      {state.actor.role === 'operator' ? (
        <section className={panel}>
          <h2 className="text-xl font-semibold">
            {handoffOnly ? 'Administration envelope review' : 'Assign RPC methods to a Participant'}
          </h2>
          {!review ? (
            handoffOnly ? (
              <>
                <p>
                  Select a declared administration envelope above, or resume its original activation
                  approval after fresh recovery custody.
                </p>
                <form
                  className="mt-4 grid max-w-2xl gap-4"
                  onChangeCapture={invalidateInput}
                  onSubmit={(event) => {
                    event.preventDefault();
                    void run(() => prepareContinuation(event));
                  }}
                >
                  <label className="grid gap-1">
                    Original activation approval ID
                    <input className={field} name="originalApprovalRequestId" required />
                  </label>
                  <label className="grid gap-1">
                    Receiving recovery enrollment ID
                    <input className={field} name="receivingEnrollmentId" required />
                  </label>
                  <label className="grid gap-1">
                    Receiving recovery case ID
                    <input className={field} name="receivingRecoveryId" required />
                  </label>
                  <button className={button} disabled={busy}>
                    Review original activation continuation
                  </button>
                </form>
              </>
            ) : (
              <form
                className="mt-4 grid max-w-2xl gap-4"
                onChangeCapture={invalidateInput}
                onSubmit={(event) => {
                  event.preventDefault();
                  void run(() => prepare(event));
                }}
              >
                <label className="grid gap-1">
                  Participant
                  <select className={field} name="targetParticipantId" required>
                    {state.items.map(({ participant }) => (
                      <option key={participant.participantId} value={participant.participantId}>
                        {participant.displayName}
                      </option>
                    ))}
                  </select>
                </label>
                <label className="grid gap-1">
                  Participant privacy domain ID
                  <input
                    className={field}
                    name="targetPrivacyDomainId"
                    defaultValue={state.actor.privacyDomainId}
                    required
                  />
                </label>
                <fieldset className="grid gap-2">
                  <legend className="font-medium">RPC methods</legend>
                  <label>
                    <input
                      type="checkbox"
                      name="capabilityIds"
                      value="CALL_RESULT_DISCLOSURE"
                      defaultChecked
                    />{' '}
                    eth_call
                  </label>
                  <label>
                    <input
                      type="checkbox"
                      name="capabilityIds"
                      value="SIGNED_TRANSACTION_SUBMISSION"
                      defaultChecked
                    />{' '}
                    eth_sendRawTransaction
                  </label>
                </fieldset>
                <fieldset className="grid gap-2">
                  <legend className="font-medium">Workload call conditions</legend>
                  <label>
                    <input type="checkbox" name="makerCheckerRequired" defaultChecked /> Require
                    approval for workload calls
                  </label>
                  <label>
                    <input type="checkbox" name="stepUpRequired" defaultChecked /> Require WebAuthn
                    for workload calls
                  </label>
                  <p className="text-sm text-[color:var(--muted)]">
                    Choose the conditions your workloads can meet. The Platform ceiling and contract
                    policy also apply. Managing this envelope requires independent approval and a
                    passkey.
                  </p>
                </fieldset>
                <label className="grid gap-1">
                  Planned envelope ID
                  <input className={field} name="envelopeId" />
                </label>
                <label className="grid gap-1">
                  Runtime binding resource IDs
                  <input
                    className={field}
                    name="resourceIds"
                    placeholder="UUIDs separated by commas"
                    required
                  />
                  <span className="text-sm text-[color:var(--muted)]">
                    Use the authoritative contract runtime-binding IDs. Platform bounds are finite;
                    wildcards are not accepted.
                  </span>
                </label>
                <label className="grid gap-1">
                  Runtime target profile IDs
                  <input
                    className={field}
                    name="targetProfileIds"
                    placeholder="For example devnet-rpc-v1"
                    required
                  />
                </label>
                <label className="grid gap-1">
                  Valid until
                  <input
                    className={field}
                    type="datetime-local"
                    name="validUntil"
                    defaultValue={localTime(86_400_000)}
                    required
                  />
                </label>
                <label className="grid gap-1">
                  Reason
                  <textarea
                    className={field}
                    name="reason"
                    minLength={10}
                    maxLength={1024}
                    defaultValue="Permit this Participant to govern the selected RPC methods."
                    required
                  />
                </label>
                <button className={button} disabled={busy || state.items.length === 0}>
                  Review RPC envelope
                </button>
              </form>
            )
          ) : (
            <div className="mt-4 space-y-3">
              <h3 className="font-semibold">Immutable envelope review</h3>
              <p className="break-all">Participant: {review.review.targetParticipantId}</p>
              <p>{review.review.capabilityIds?.join(', ')}</p>
              {review.review.platformScopeReplacementId && (
                <>
                  <p>Pending Platform replacement: {review.review.platformScopeReplacementId}</p>
                  <p>
                    Administration actions:{' '}
                    {review.review.administrationActionIntentIds?.join(', ')}
                  </p>
                  <p className="break-all">
                    Administration resources: {review.review.administrationResourceIds?.join(', ')}
                  </p>
                  <p>
                    This runtime-free envelope remains unavailable for ordinary authority until the
                    successor root is committed.
                  </p>
                </>
              )}
              {review.review.kind === 'CREATE_ENVELOPE' && (
                <p>
                  {review.review.platformScopeReplacementId ? 'Administration' : 'Workload'}{' '}
                  approval:{' '}
                  {review.review.makerCheckerRequired === false ? 'not required' : 'required'}
                  {' · '}
                  {review.review.platformScopeReplacementId ? 'Administration' : 'Workload'}{' '}
                  WebAuthn: {review.review.stepUpRequired === false ? 'not required' : 'required'}
                </p>
              )}
              <p className="break-all text-xs">{review.review.candidateDigest}</p>
              {review.review.resumeDraft && (
                <div className="space-y-2">
                  <p className="break-all">
                    Original approval: {review.review.resumeDraft.approvalRequestId}
                  </p>
                  <p className="break-all">
                    Receiving recovery case: {review.review.resumeDraft.recoveryId}
                  </p>
                  <p>Receiving authority expires: {review.review.resumeDraft.expiresAt}</p>
                  <p>
                    This renews approval metadata for the same unconsumed activation. A fresh
                    passkey proof and independent checker approval are required.
                  </p>
                </div>
              )}
              {(review.review.resumeDraft || unresolved.current?.review?.review.resumeDraft) && (
                <button
                  className={button}
                  disabled={busy}
                  onClick={() => void run(readResumptionOutcome, true)}
                >
                  Read original activation outcome
                </button>
              )}
              {!review.approvalRequestId ? (
                <button className={button} disabled={busy} onClick={() => void run(submit)}>
                  {review.review.resumeDraft
                    ? 'Verify and resume original activation approval'
                    : review.review.kind === 'SUBMIT_ENVELOPE'
                      ? 'Verify and request submission approval'
                      : review.review.kind === 'ACTIVATE_ENVELOPE'
                        ? 'Verify and request activation approval'
                        : review.review.kind === 'REVOKE_ENVELOPE'
                          ? 'Verify and request revocation approval'
                          : 'Verify and request approval'}
                </button>
              ) : (
                <p>Approval: {currentApproval?.state ?? 'refreshing'}</p>
              )}
              {currentApproval?.state === 'APPROVED' && review.review.kind !== 'SUBMIT_ENVELOPE' ? (
                <button className={button} disabled={busy} onClick={() => void run(commit)}>
                  {review.review.kind === 'ACTIVATE_ENVELOPE'
                    ? 'Verify and commit activation'
                    : review.review.kind === 'REVOKE_ENVELOPE'
                      ? 'Verify and commit revocation'
                      : 'Verify and commit RPC envelope'}
                </button>
              ) : null}
            </div>
          )}
        </section>
      ) : (
        <section className={panel}>
          <h2 className="text-xl font-semibold">
            {handoffOnly ? 'Administration envelope approvals' : 'RPC envelope approvals'}
          </h2>
          {state.approvals.filter((item) => item.state === 'REQUESTED').length === 0 ? (
            <p className="mt-3">
              {handoffOnly && !state.approvalsLoaded
                ? 'Load the exact envelope approval before reviewing a decision.'
                : 'No RPC envelope request currently requires a decision.'}
            </p>
          ) : (
            state.approvals
              .filter((item) => item.state === 'REQUESTED')
              .map((item) => (
                <article
                  className="mt-3 rounded border border-[color:var(--border)] p-3"
                  key={item.approvalRequestId}
                >
                  <p className="break-all text-xs">{item.candidateDigest}</p>
                  <button
                    className={button + ' mt-3'}
                    disabled={busy}
                    onClick={() => void run(() => approve(item))}
                  >
                    Approve with saved passkey
                  </button>
                </article>
              ))
          )}
        </section>
      )}
    </div>
  );
}
