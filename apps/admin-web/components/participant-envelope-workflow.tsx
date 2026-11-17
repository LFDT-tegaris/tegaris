'use client';

import { performWebAuthnStepUp } from '@openpc/ui-shell';
import { useCallback, useEffect, useLayoutEffect, useRef, useState } from 'react';
import { z } from 'zod';

import { LocalSessionSurface } from './local-session';
import { WorkspaceEntry } from './workspace-entry';
import { ParticipantEnvelopeRecovery } from './participant-envelope-recovery';
import { GovernanceContextSummary } from './governance-context-summary';
import { WorkspaceStatus } from './workspace-status';

const participantId = '018f0000-0000-7000-8000-000000000101';
const privacyDomainId = '018f0000-0000-7000-8000-000000000201';
const storageKey = 'openpc:participant-envelope-workflow:v1';
const participantAction = {
  actionIntentId: 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
  actionIntentDigest: 'sha256:bec5bb71e10db36e744f98a55dd6b54a0c42f9f55b73ac322a1de6e8592fd529',
  stepUp: 'FRESH_WEBAUTHN_MAX_5M' as const,
};
const contextAction = {
  actionIntentId: 'ACT-IDENTITY_CREATE_SESSION-V1',
  actionIntentDigest: 'sha256:dbc8290dd60814d5bb4248fefc9550f43d0dc97d6333ac232c8ab8a98c3354d2',
  stepUp: 'FRESH_WEBAUTHN_MAX_5M' as const,
};
const contextDigest = 'sha256:21e6f6ef3dfec5acda58eebd0e07fca2e1394a9777f13157e3e514d611248700';

interface Approval {
  readonly approvalRequestId: string;
  readonly candidateDigest: string;
  readonly state: 'REQUESTED' | 'APPROVED' | 'REJECTED' | 'EXPIRED' | 'CANCELLED';
  readonly revision: string;
  readonly stepUp?: {
    readonly actionIntentId: string;
    readonly actionIntentDigest: string;
    readonly resourceId: string;
    readonly resourceDigest: string;
  };
}

interface WorkbenchState {
  readonly actor: {
    readonly role: 'operator' | 'viewer';
    readonly principalId: string;
    readonly participantId: string;
    readonly privacyDomainId: string;
    readonly contextEpoch: string;
  };
  readonly approvals: readonly Approval[];
  readonly effect?: {
    readonly operationId: string;
    readonly effect: {
      readonly id: string;
      readonly state: string;
      readonly semanticDigest: string;
      readonly participantId: string;
      readonly privacyDomainIds: readonly string[];
    };
  };
}

interface ReviewState {
  readonly reviewToken: string;
  readonly approvalRequestId?: string;
  readonly review: {
    readonly envelopeId: string;
    readonly label: string;
    readonly reason: string;
    readonly candidateDigest: string;
    readonly validFrom: string;
    readonly validUntil: string;
    readonly actionIntentId: string;
    readonly riskClass: string;
    readonly makerCheckerRequired: true;
    readonly stepUpRequired: true;
  };
}

interface SessionState {
  readonly enabled?: boolean;
  readonly authenticated?: boolean;
  readonly contextMode?: 'PLATFORM' | 'PARTICIPANT';
  readonly participantId?: string;
  readonly privacyDomainId?: string;
  readonly sessionId?: string;
  readonly principalId?: string;
  readonly role?: 'operator' | 'viewer';
  readonly contextEpoch?: string;
}

const readFailure = 'The Participant workspace is unavailable. Refresh to check current access.';
const commandFailure =
  'The request was not completed. Reconcile the original review before continuing.';
const unresolvedEffect =
  'The effect is unresolved; refresh authoritative readback before continuing.';
const identifier = z.uuid();
const revision = z.string().regex(/^(0|[1-9][0-9]*)$/u);
const digest = z.string().regex(/^sha256:[0-9a-f]{64}$/u);
const authenticatedSessionSchema = z
  .object({
    enabled: z.literal(true),
    authenticated: z.literal(true),
    sessionId: identifier,
    principalId: identifier,
    participantId: identifier,
    privacyDomainId: identifier.optional(),
    contextMode: z.enum(['PLATFORM', 'PARTICIPANT']),
    contextEpoch: revision,
    role: z.enum(['operator', 'viewer']),
  })
  .refine((value) => value.contextMode !== 'PARTICIPANT' || value.privacyDomainId !== undefined);
const sessionSchema = z.union([
  authenticatedSessionSchema,
  z.object({ enabled: z.literal(true), authenticated: z.literal(false) }),
  z.object({ enabled: z.literal(false), authenticated: z.literal(false).optional() }),
]);
const workbenchSchema = z.object({
  actor: z.object({
    role: z.enum(['operator', 'viewer']),
    principalId: identifier,
    participantId: identifier,
    privacyDomainId: identifier,
    contextEpoch: revision,
  }),
  approvals: z.array(
    z.object({
      approvalRequestId: z.string().regex(/^urn:openpc:resource:[0-9a-f-]{36}$/u),
      candidateDigest: digest,
      state: z.enum(['REQUESTED', 'APPROVED', 'REJECTED', 'EXPIRED', 'CANCELLED']),
      revision,
      stepUp: z
        .object({
          actionIntentId: z.string().min(1),
          actionIntentDigest: digest,
          resourceId: identifier,
          resourceDigest: digest,
        })
        .optional(),
    }),
  ),
  effect: z
    .object({
      operationId: identifier,
      effect: z
        .object({
          id: identifier,
          state: z.enum(['DRAFT', 'SUBMITTED', 'APPROVED', 'ACTIVE', 'SUPERSEDED', 'REVOKED']),
          semanticDigest: digest,
          participantId: identifier,
          privacyDomainIds: z.array(identifier),
        })
        .passthrough(),
    })
    .optional(),
});
const savedReviewSchema = z
  .object({
    reviewToken: z.string().min(80).max(8192),
    approvalRequestId: identifier.optional(),
    review: z
      .object({
        envelopeId: identifier,
        label: z.string().min(3).max(80),
        reason: z.string().min(10).max(1024),
        candidateDigest: digest,
        validFrom: z.string().datetime(),
        validUntil: z.string().datetime(),
        actionIntentId: z.literal(participantAction.actionIntentId),
        riskClass: z.literal('HIGH'),
        makerCheckerRequired: z.literal(true),
        stepUpRequired: z.literal(true),
      })
      .passthrough()
      .refine((value) => Date.parse(value.validUntil) > Date.parse(value.validFrom)),
  })
  .passthrough();
const resourceUrn = z
  .string()
  .refine(
    (value) =>
      value.startsWith('urn:openpc:resource:') && identifier.safeParse(value.slice(20)).success,
  );
const publicOperationSchema = z
  .object({
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
  })
  .passthrough();
const fullApprovalSchema = z
  .object({
    approvalRequestId: resourceUrn,
    actionIntentId: z.string().min(1),
    candidateDigest: digest,
    state: z.enum(['REQUESTED', 'APPROVED', 'REJECTED', 'EXPIRED', 'CANCELLED']),
    makerSubjectRef: resourceUrn,
    checkerSubjectRef: resourceUrn.nullable(),
    revision,
    createdAt: z.string().datetime(),
    updatedAt: z.string().datetime(),
  })
  .passthrough();
const decisionSchema = z.union([
  z.object({ reconciled: z.literal(true), approval: fullApprovalSchema }).strict(),
  z.object({ operation: publicOperationSchema, approval: fullApprovalSchema }).strict(),
]);
const committedEffectSchema = z
  .object({
    id: identifier,
    participantId: z.literal(participantId),
    authorityEpoch: revision,
    state: z.enum(['DRAFT', 'SUBMITTED', 'APPROVED', 'ACTIVE', 'SUPERSEDED', 'REVOKED']),
    semanticDigest: digest,
    privacyDomainIds: z.tuple([z.literal(privacyDomainId)]),
    actionIntentIds: z.tuple([z.literal(participantAction.actionIntentId)]),
    resourceIds: z.tuple([z.literal('*')]),
    riskClasses: z.tuple([z.literal('HIGH')]),
    validFrom: z.string().datetime(),
    validUntil: z.string().datetime(),
    makerCheckerRequired: z.literal(true),
    stepUpRequired: z.literal(true),
    onwardDelegationDepth: z.literal(0),
  })
  .passthrough()
  .refine((value) => Date.parse(value.validUntil) > Date.parse(value.validFrom));
const commitResponseSchema = z.union([
  z.object({
    truthState: z.literal('WRITE_AMBIGUITY'),
    envelopeId: identifier,
    reconciliation: z.literal('READ_AUTHORITATIVE_EFFECT'),
  }),
  z.object({
    operation: z.object({
      operationId: identifier,
      state: z.literal('SUCCEEDED'),
      truthState: z.literal('SUCCESS'),
    }),
    effect: committedEffectSchema,
  }),
]);
function decodeSubmission(value: unknown, original: ReviewState, principal: string) {
  const next = savedReviewSchema
    .extend({ operation: publicOperationSchema, approval: fullApprovalSchema })
    .parse(value);
  if (
    JSON.stringify(savedReviewSchema.shape.review.strip().parse(next.review)) !==
      JSON.stringify(savedReviewSchema.shape.review.strip().parse(original.review)) ||
    next.approval.candidateDigest !== original.review.candidateDigest ||
    next.approval.state !== 'REQUESTED' ||
    next.approval.makerSubjectRef !== `urn:openpc:resource:${principal}` ||
    next.operation.resourceRef !== next.approval.approvalRequestId ||
    next.operation.actionIntentId !== 'ACT-APPROVAL_REQUESTS_CREATE_RESOURCE-V1' ||
    (original.approvalRequestId !== undefined &&
      next.approval.approvalRequestId.slice(-36) !== original.approvalRequestId)
  )
    throw new Error(commandFailure);
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
    throw new Error(commandFailure);
  return next;
}
function sameInstant(left: string, right: string) {
  const normalized = (value: string) => value.replace(/(\.[0-9]*?)0+Z$/u, '$1Z').replace('.Z', 'Z');
  return normalized(left) === normalized(right);
}
function decodeCommit(value: unknown, original: ReviewState) {
  const next = commitResponseSchema.parse(value);
  if (
    'envelopeId' in next
      ? next.envelopeId !== original.review.envelopeId
      : next.effect.id !== original.review.envelopeId ||
        !sameInstant(next.effect.validFrom, original.review.validFrom) ||
        !sameInstant(next.effect.validUntil, original.review.validUntil)
  )
    throw new Error(commandFailure);
  return next;
}
function sessionKey(value?: SessionState) {
  return value?.authenticated
    ? JSON.stringify([
        value.sessionId,
        value.principalId,
        value.participantId,
        value.privacyDomainId,
        value.contextMode,
        value.contextEpoch,
        value.role,
      ])
    : '';
}
async function json<T>(response: Response): Promise<T> {
  if (!response.ok) throw new Error(commandFailure);
  return response.json().catch(() => {
    throw new Error(commandFailure);
  }) as Promise<T>;
}

async function command<T>(body: unknown): Promise<T> {
  return json<T>(
    await fetch('/api/v1/ui/participant-workbench', {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    }),
  );
}

export function ParticipantEnvelopeWorkflow({ evaluationUi = false }: { evaluationUi?: boolean }) {
  const mounted = useRef(false);
  const read = useRef<{ generation: number; controller?: AbortController }>({ generation: 0 });
  const lookup = useRef<ReviewState | undefined>(undefined);
  const savedOriginal = useRef(false);
  const reviewOwner = useRef('');
  const currentActor = useRef('');
  const [session, setSession] = useState<SessionState>();
  const [state, setState] = useState<WorkbenchState>();
  const [watchActor, setWatchActor] = useState('');
  const [review, setReview] = useState<ReviewState>();
  const [status, setStatus] = useState('');
  const [busy, setBusy] = useState(false);
  const lookupActor = useRef<SessionState | undefined>(undefined);
  const originalCommit = useRef<
    | {
        review: ReviewState;
        owner: string;
        body: { command: 'COMMIT'; reviewToken: string; approvalRequestId: string };
        operationId?: string;
        effect?: z.infer<typeof committedEffectSchema>;
      }
    | undefined
  >(undefined);
  const inputRevision = useRef(0);
  const operationRef = useRef<
    | {
        controller: AbortController;
        phase: 'PREPARING' | 'SENT';
        snapshot: string;
        owner: string;
      }
    | undefined
  >(undefined);
  const snapshot = JSON.stringify({ session, state, review, generation: read.current.generation });
  const frame = useRef(snapshot);
  useLayoutEffect(() => {
    frame.current = snapshot;
    const pending = operationRef.current;
    if (pending?.phase === 'PREPARING' && pending.snapshot !== snapshot) pending.controller.abort();
  });
  type Operation = NonNullable<typeof operationRef.current>;
  function alive(operation: Operation) {
    return (
      mounted.current && operationRef.current === operation && !operation.controller.signal.aborted
    );
  }
  function current(operation: Operation, exact = operation.phase === 'PREPARING') {
    return (
      alive(operation) &&
      operation.owner !== '' &&
      currentActor.current === operation.owner &&
      (!exact || frame.current === operation.snapshot)
    );
  }
  function assertCurrent(operation: Operation, exact = operation.phase === 'PREPARING') {
    if (!current(operation, exact))
      throw new DOMException('The operation was cancelled.', 'AbortError');
  }
  const lifecycle = (operation: Operation) => ({
    signal: operation.controller.signal,
    isCurrent: () => current(operation, true),
  });
  async function qualify(operation: Operation) {
    assertCurrent(operation, true);
    try {
      const actual = sessionSchema.parse(
        await fetch('/api/v1/ui/local-session', {
          cache: 'no-store',
          credentials: 'same-origin',
          signal: operation.controller.signal,
        }).then(json<unknown>),
      );
      assertCurrent(operation, true);
      if (sessionKey(actual) !== operation.owner) throw new Error(readFailure);
    } catch (cause) {
      if (current(operation, true)) {
        operation.controller.abort();
        currentActor.current = '';
        read.current.generation++;
        read.current.controller?.abort();
        setState(undefined);
        setReview(undefined);
        setSession(undefined);
        setStatus(readFailure);
      }
      throw cause;
    }
    assertCurrent(operation, true);
  }
  function cancelPreparation() {
    inputRevision.current++;
    read.current.controller?.abort();
    const pending = operationRef.current;
    if (pending?.phase === 'PREPARING') pending.controller.abort();
  }
  function retain(next: ReviewState, operation: Operation) {
    if (!current(operation)) return;
    lookup.current = next;
    lookupActor.current = session;
    reviewOwner.current = operation.owner;
    savedOriginal.current = true;
    setReview(next);
    try {
      localStorage.setItem(storageKey, JSON.stringify(next));
    } catch {
      /* Optional persistence. */
    }
  }
  async function run(
    action: (operation: Operation) => Promise<void>,
    message: string,
    business = true,
  ) {
    if (!mounted.current || operationRef.current) return;
    if (
      business &&
      (originalCommit.current ||
        (savedOriginal.current &&
          (!reviewOwner.current || reviewOwner.current !== sessionKey(session))))
    ) {
      setStatus(unresolvedEffect);
      return;
    }
    const operation: Operation = {
      controller: new AbortController(),
      phase: 'PREPARING',
      snapshot: frame.current,
      owner: sessionKey(session),
    };
    operationRef.current = operation;
    setBusy(true);
    setStatus(message);
    try {
      await action(operation);
    } catch {
      if (current(operation)) setStatus(commandFailure);
    } finally {
      if (operationRef.current === operation) {
        operationRef.current = undefined;
        if (mounted.current) setBusy(false);
      }
    }
  }

  const load = useCallback(async (knownReview?: ReviewState) => {
    if (!mounted.current) return;
    const pending = operationRef.current;
    if (pending?.phase === 'PREPARING') pending.controller.abort();
    read.current.controller?.abort();
    const controller = new AbortController();
    const generation = read.current.generation + 1;
    read.current = { generation, controller };
    const input = inputRevision.current;
    const relevant = () =>
      mounted.current &&
      read.current.generation === generation &&
      !controller.signal.aborted &&
      input === inputRevision.current;
    const original = originalCommit.current;
    const selected = original?.review ?? knownReview ?? lookup.current;
    setState(undefined);
    setReview(undefined);
    setStatus('Loading the authorized Participant workspace.');
    try {
      const readSession = async () =>
        sessionSchema.parse(
          await fetch('/api/v1/ui/local-session', {
            credentials: 'same-origin',
            cache: 'no-store',
            signal: controller.signal,
          }).then(json<unknown>),
        );
      const currentSession = await readSession();
      if (!relevant()) return;
      setSession(currentSession);
      if (!currentSession.authenticated || currentSession.contextMode !== 'PARTICIPANT') {
        currentActor.current = sessionKey(currentSession);
        setWatchActor('');
        setStatus('Choose an authenticated Participant context to read the workspace.');
        return;
      }
      const originalActor = lookupActor.current;
      if (
        selected &&
        originalActor &&
        (originalActor.principalId !== currentSession.principalId ||
          originalActor.participantId !== currentSession.participantId ||
          originalActor.privacyDomainId !== currentSession.privacyDomainId)
      ) {
        currentActor.current = sessionKey(currentSession);
        setWatchActor('');
        setStatus(readFailure);
        return;
      }
      const envelopeId = selected?.review.envelopeId;
      const path = `/api/v1/ui/participant-workbench${envelopeId ? `?envelopeId=${encodeURIComponent(envelopeId)}` : ''}`;
      const next = workbenchSchema.parse(
        await fetch(path, {
          credentials: 'same-origin',
          cache: 'no-store',
          signal: controller.signal,
        }).then(json<unknown>),
      );
      if (!relevant()) return;
      if (
        next.actor.principalId !== currentSession.principalId ||
        next.actor.participantId !== currentSession.participantId ||
        next.actor.privacyDomainId !== currentSession.privacyDomainId ||
        next.actor.contextEpoch !== currentSession.contextEpoch ||
        next.actor.role !== currentSession.role ||
        (next.effect &&
          (!envelopeId ||
            next.effect.effect.id !== envelopeId ||
            next.effect.effect.participantId !== currentSession.participantId ||
            next.effect.effect.privacyDomainIds.some(
              (value) => value !== currentSession.privacyDomainId,
            ))) ||
        next.approvals.some(
          (item) => item.stepUp && item.stepUp.resourceId !== item.approvalRequestId.slice(-36),
        )
      )
        throw new Error(readFailure);
      if (next.effect && selected) {
        const effect = committedEffectSchema.parse(next.effect.effect);
        if (
          !sameInstant(effect.validFrom, selected.review.validFrom) ||
          !sameInstant(effect.validUntil, selected.review.validUntil) ||
          (original?.operationId && next.effect.operationId !== original.operationId) ||
          (original?.effect &&
            (effect.semanticDigest !== original.effect.semanticDigest ||
              effect.authorityEpoch !== original.effect.authorityEpoch))
        )
          throw new Error(readFailure);
      }
      const confirmed = await readSession();
      if (!relevant()) return;
      if (sessionKey(confirmed) !== sessionKey(currentSession)) {
        setSession(confirmed);
        currentActor.current = sessionKey(confirmed);
        throw new Error(readFailure);
      }
      currentActor.current = sessionKey(currentSession);
      setState(next);
      setWatchActor(sessionKey(currentSession));
      // Legacy saved bytes have no public actor/session binding. Keep them for
      // exact readback; only a review prepared in this verified session is actionable.
      if (selected && !original && reviewOwner.current === currentActor.current)
        setReview(selected);
      // The resource read has no historical consumption/unconsumed disposition.
      // A missing effect or approved request cannot release original write custody.
      setStatus(
        original
          ? next.effect && original.operationId && original.owner === currentActor.current
            ? 'The operation succeeded and the authoritative envelope effect was read back.'
            : unresolvedEffect
          : 'The authorized Participant workspace was read back.',
      );
      return next;
    } catch {
      if (relevant()) {
        setWatchActor('');
        setStatus(readFailure);
      }
    }
  }, []);

  useLayoutEffect(() => {
    mounted.current = true;
    try {
      const raw = localStorage.getItem(storageKey);
      savedOriginal.current = raw !== null;
      if (raw) {
        const saved = savedReviewSchema.parse(JSON.parse(raw));
        lookup.current = saved;
        if (saved.approvalRequestId)
          originalCommit.current = {
            review: saved,
            owner: '',
            body: {
              command: 'COMMIT',
              reviewToken: saved.reviewToken,
              approvalRequestId: saved.approvalRequestId,
            },
          };
      }
    } catch {
      // Preserve malformed or unbound originals; never infer execution readiness.
      savedOriginal.current = true;
    }
    void load();
    return () => {
      mounted.current = false;
      operationRef.current?.controller.abort();
      operationRef.current = undefined;
      read.current.generation += 1;
      read.current.controller?.abort();
    };
  }, [load]);

  const notificationActor =
    session?.authenticated &&
    session.contextMode === 'PARTICIPANT' &&
    watchActor === sessionKey(session)
      ? watchActor
      : '';
  const notificationApprovalId = (review ?? lookup.current)?.approvalRequestId;
  useEffect(() => {
    if (busy || !notificationActor) return;
    let active = true;
    const selected = lookup.current;
    const source = new EventSource(
      `/api/v1/ui/participant-workbench/events${notificationApprovalId ? `?approvalRequestId=${encodeURIComponent(notificationApprovalId)}` : ''}`,
    );
    source.addEventListener('snapshot-invalidated', () => {
      if (active && currentActor.current === notificationActor) void load(selected);
    });
    return () => {
      active = false;
      source.close();
    };
  }, [busy, load, notificationActor, notificationApprovalId]);

  const watchedReview = review ?? lookup.current;
  const currentApproval = watchedReview?.approvalRequestId
    ? state?.approvals.find(
        (item) =>
          item.approvalRequestId.slice(-36) === watchedReview.approvalRequestId &&
          item.candidateDigest === watchedReview.review.candidateDigest,
      )
    : undefined;

  useEffect(() => {
    if (
      busy ||
      !state ||
      !session?.authenticated ||
      session.contextMode !== 'PARTICIPANT' ||
      !lookup.current?.approvalRequestId ||
      currentApproval?.state === 'APPROVED' ||
      currentApproval?.state === 'REJECTED' ||
      currentApproval?.state === 'EXPIRED' ||
      currentApproval?.state === 'CANCELLED'
    ) {
      return;
    }
    let active = true;
    const selected = lookup.current;
    const timer = window.setInterval(() => {
      if (active) void load(selected);
    }, 1_500);
    return () => {
      active = false;
      window.clearInterval(timer);
    };
  }, [busy, currentApproval?.state, load, review, state, session]);

  async function selectContext() {
    await run(
      async (operation) => {
        await performWebAuthnStepUp(
          contextAction,
          {
            resourceId: participantId,
            resourceDigest: contextDigest,
          },
          lifecycle(operation),
        );
        assertCurrent(operation, true);
        await qualify(operation);
        operation.phase = 'SENT';
        await json(
          await fetch('/api/v1/ui/session/context', {
            method: 'POST',
            credentials: 'same-origin',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ participantId, privacyDomainId }),
          }),
        );
        assertCurrent(operation);
        if (await load()) {
          if (alive(operation)) setStatus('Participant privacy context is active.');
        }
      },
      'Switching to the Participant privacy context.',
      false,
    );
  }
  async function preview(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const data = new FormData(event.currentTarget);
    const body = {
      command: 'PREVIEW',
      label: data.get('label'),
      reason: data.get('reason'),
      validUntil: String(data.get('validUntil')),
    };
    await run(async (operation) => {
      const response = await command<unknown>({
        ...body,
        validUntil: new Date(body.validUntil).toISOString(),
      });
      assertCurrent(operation, true);
      const next = savedReviewSchema.parse(response);
      if (
        next.approvalRequestId !== undefined ||
        next.review.label !== String(data.get('label')).trim() ||
        next.review.reason !== String(data.get('reason')).trim() ||
        Date.parse(next.review.validUntil) !== Date.parse(String(data.get('validUntil')))
      )
        throw new Error(commandFailure);
      retain(next, operation);
      setStatus('Review is locked. Submit only if every field is correct.');
    }, '');
  }
  async function submit() {
    if (!review) return;
    const original = review;
    const principal = session!.principalId!;
    const body = { command: 'SUBMIT', reviewToken: original.reviewToken };
    await run(async (operation) => {
      assertCurrent(operation);
      operation.phase = 'SENT';
      const response = await command<unknown>(body);
      assertCurrent(operation);
      const result = decodeSubmission(response, original, principal);
      const next = {
        ...result,
        ...original,
        approvalRequestId: result.approval.approvalRequestId.split(':').at(-1)!,
      };
      retain(next, operation);
      setState((current) =>
        current
          ? {
              ...current,
              approvals: [
                result.approval,
                ...current.approvals.filter(
                  (item) => item.approvalRequestId !== result.approval.approvalRequestId,
                ),
              ],
            }
          : current,
      );
      setStatus('Approval requested from the distinct checker.');
    }, 'Submitting the immutable candidate to the checker.');
  }
  async function approve(item: Approval) {
    if (!item.stepUp) return;
    const binding = item.stepUp;
    const principal = session!.principalId!;
    const body = { command: 'APPROVE', approvalRequestId: binding.resourceId };
    await run(async (operation) => {
      await performWebAuthnStepUp(
        { ...binding, stepUp: 'FRESH_WEBAUTHN_MAX_5M' },
        { resourceId: binding.resourceId, resourceDigest: binding.resourceDigest },
        lifecycle(operation),
      );
      assertCurrent(operation, true);
      await qualify(operation);
      operation.phase = 'SENT';
      const response = await command<unknown>(body);
      assertCurrent(operation);
      const result = decodeDecision(response, item, principal);
      setState((current) =>
        current
          ? {
              ...current,
              approvals: current.approvals.map((approval) =>
                approval.approvalRequestId === result.approval.approvalRequestId
                  ? result.approval
                  : approval,
              ),
            }
          : current,
      );
      setStatus('The immutable candidate is approved.');
    }, 'Confirm this exact approval with your security key.');
  }
  async function commit() {
    if (!review?.approvalRequestId) return;
    const original = review;
    const body = {
      command: 'COMMIT' as const,
      reviewToken: original.reviewToken,
      approvalRequestId: original.approvalRequestId!,
    };
    await run(async (operation) => {
      await performWebAuthnStepUp(
        participantAction,
        {
          resourceId: original.review.envelopeId,
          resourceDigest: original.review.candidateDigest,
        },
        lifecycle(operation),
      );
      assertCurrent(operation, true);
      await qualify(operation);
      operation.phase = 'SENT';
      const sent = { review: original, owner: operation.owner, body };
      originalCommit.current = sent;
      const response = await command<unknown>(body);
      assertCurrent(operation);
      const result = decodeCommit(response, original);
      if ('operation' in result && originalCommit.current === sent) {
        originalCommit.current = {
          ...sent,
          operationId: result.operation.operationId,
          effect: result.effect,
        };
      }
      await load(original);
    }, 'Confirm the exact business effect with your security key.');
  }

  const displayStatus = evaluationUi
    ? status === 'Loading the authorized Participant workspace.'
      ? 'Loading organization authority…'
      : status === 'The authorized Participant workspace was read back.'
        ? 'Organization authority workspace refreshed.'
        : status === readFailure
          ? 'Organization authority is unavailable. Refresh to check your current access.'
          : status
    : status;
  const loadingWorkspace = !status || status === 'Loading the authorized Participant workspace.';
  const refresh = (
    <>
      <button
        type="button"
        disabled={busy}
        onClick={() => void load()}
        className="rounded border border-[color:var(--border)] px-3 py-2"
      >
        {evaluationUi ? 'Refresh workspace' : 'Refresh Participant workspace'}
      </button>
      {(originalCommit.current || (savedOriginal.current && lookup.current)) && (
        <button
          type="button"
          disabled={busy}
          onClick={() => void load(originalCommit.current?.review)}
          className="rounded border border-[color:var(--border)] px-3 py-2"
        >
          {evaluationUi ? 'Check original request' : 'Read original envelope outcome'}
        </button>
      )}
    </>
  );
  if (!session)
    return evaluationUi ? (
      <WorkspaceStatus
        state={loadingWorkspace ? 'LOADING' : 'UNAVAILABLE'}
        title={
          loadingWorkspace
            ? 'Loading organization authority'
            : 'Organization authority is unavailable'
        }
        detail={displayStatus || 'Checking your current workspace and access.'}
      >
        {refresh}
      </WorkspaceStatus>
    ) : (
      <div>
        <p role="status">{status || 'Loading the authenticated context.'}</p>
        {refresh}
      </div>
    );
  if (!session.authenticated)
    return (
      <div>
        <LocalSessionSurface />
        <p role="status">{status}</p>
        {refresh}
      </div>
    );
  if (session.contextMode !== 'PARTICIPANT') {
    return (
      <div>
        <ParticipantEnvelopeRecovery />
        <section className="mt-6 rounded border border-[color:var(--warning)] bg-[color:var(--surface)] p-4">
          <h2 className="text-xl font-semibold">
            {evaluationUi ? 'Organization administration' : 'Participant administration'}
          </h2>
          <p className="mt-2 text-[color:var(--muted)]">
            {evaluationUi
              ? "Enter your organization's workspace to create and review authority requests."
              : 'Choose a Participant privacy context to create and review Participant administration requests.'}
          </p>
          <WorkspaceEntry disabled={busy}>
            <button
              className="mt-4 rounded bg-[color:var(--accent)] px-3 py-2 font-medium text-white disabled:opacity-60"
              disabled={busy}
              onClick={() => void selectContext()}
              type="button"
            >
              Enter workspace
            </button>
          </WorkspaceEntry>
          <p aria-live="polite" className="mt-3" role="status">
            {status}
          </p>
          {refresh}
        </section>
      </div>
    );
  }
  if (!state)
    return evaluationUi ? (
      <WorkspaceStatus
        state={loadingWorkspace ? 'LOADING' : 'UNAVAILABLE'}
        title={
          loadingWorkspace
            ? 'Loading organization authority'
            : 'Organization authority is unavailable'
        }
        detail={displayStatus}
      >
        {refresh}
      </WorkspaceStatus>
    ) : (
      <div>
        <p role="status">{status}</p>
        {refresh}
      </div>
    );

  return (
    <div className="mt-6 space-y-6" onChangeCapture={cancelPreparation}>
      {evaluationUi && session.sessionId ? (
        <GovernanceContextSummary
          title="Organization authority"
          description="Prepare and review authority changes for the current organization. Creating a draft envelope does not activate it."
          actor={{ ...state.actor, sessionId: session.sessionId }}
        >
          {refresh}
        </GovernanceContextSummary>
      ) : (
        <section
          aria-label="Current context"
          className="rounded border border-[color:var(--border)] bg-[color:var(--surface)] p-4"
        >
          <h2 className="text-lg font-semibold">Participant context</h2>
          {refresh}
          <dl className="mt-3 grid gap-3 text-sm sm:grid-cols-2 lg:grid-cols-4">
            <div>
              <dt className="font-medium">Role</dt>
              <dd className="text-[color:var(--muted)]">
                {state.actor.role === 'operator' ? 'Maker' : 'Checker'}
              </dd>
            </div>
            <div>
              <dt className="font-medium">Participant</dt>
              <dd className="break-all text-[color:var(--muted)]">{state.actor.participantId}</dd>
            </div>
            <div>
              <dt className="font-medium">Privacy domain</dt>
              <dd className="break-all text-[color:var(--muted)]">{state.actor.privacyDomainId}</dd>
            </div>
            <div>
              <dt className="font-medium">Context generation</dt>
              <dd className="text-[color:var(--muted)]">{state.actor.contextEpoch}</dd>
            </div>
          </dl>
        </section>
      )}

      {state.actor.role === 'operator' ? (
        <section
          aria-labelledby="envelope-heading"
          className="rounded border border-[color:var(--border)] bg-[color:var(--surface)] p-4"
        >
          <h2 className="text-xl font-semibold" id="envelope-heading">
            {evaluationUi ? 'Request an authority envelope' : 'Create an authority envelope'}
          </h2>
          {evaluationUi && (
            <p className="mt-2 text-sm text-[color:var(--muted)]">
              Set the purpose and expiry, review the request, then send it for independent approval.
            </p>
          )}
          {!review && (lookup.current || savedOriginal.current) ? (
            <p>
              {originalCommit.current
                ? 'The original immutable request is retained for authorized readback. Execution remains read-only.'
                : !lookup.current
                  ? 'Saved original custody could not be confirmed. Recover the original review before creating another request.'
                  : 'A saved immutable review is retained for authorized readback. Its actor and session binding must be established before execution can resume.'}
            </p>
          ) : !review ? (
            <form className="mt-4 grid max-w-2xl gap-4" onSubmit={(event) => void preview(event)}>
              <label className="grid gap-1">
                Purpose
                <input
                  className="rounded border border-[color:var(--border)] bg-[color:var(--canvas)] p-2"
                  maxLength={80}
                  minLength={3}
                  name="label"
                  required
                />
              </label>
              <label className="grid gap-1">
                Valid until
                <input
                  className="rounded border border-[color:var(--border)] bg-[color:var(--canvas)] p-2"
                  name="validUntil"
                  required
                  type="datetime-local"
                />
              </label>
              <label className="grid gap-1">
                Reason
                <textarea
                  className="min-h-24 rounded border border-[color:var(--border)] bg-[color:var(--canvas)] p-2"
                  maxLength={1024}
                  minLength={10}
                  name="reason"
                  required
                />
              </label>
              <button
                className="w-fit rounded bg-[color:var(--accent)] px-3 py-2 font-medium text-white disabled:opacity-60"
                disabled={busy}
                type="submit"
              >
                {evaluationUi ? 'Review request' : 'Review immutable candidate'}
              </button>
            </form>
          ) : (
            <div className="mt-4 space-y-4">
              <h3 className="font-semibold">
                {evaluationUi ? 'Review authority request' : 'Immutable review'}
              </h3>
              <dl className="grid gap-3 text-sm sm:grid-cols-2">
                <div>
                  <dt>Purpose</dt>
                  <dd>{review.review.label}</dd>
                </div>
                <div>
                  <dt>Risk</dt>
                  <dd>{review.review.riskClass}</dd>
                </div>
                <div>
                  <dt>Valid until</dt>
                  <dd>{new Date(review.review.validUntil).toLocaleString()}</dd>
                </div>
                <div>
                  <dt>Candidate digest</dt>
                  <dd className="break-all font-mono text-xs">{review.review.candidateDigest}</dd>
                </div>
              </dl>
              {!review.approvalRequestId ? (
                <button
                  className="rounded bg-[color:var(--accent)] px-3 py-2 font-medium text-white disabled:opacity-60"
                  disabled={busy}
                  onClick={() => void submit()}
                  type="button"
                >
                  Send to checker
                </button>
              ) : null}
              {currentApproval?.state === 'APPROVED' && !state.effect && !originalCommit.current ? (
                <button
                  className="rounded bg-[color:var(--success)] px-3 py-2 font-medium text-white disabled:opacity-60"
                  disabled={busy}
                  onClick={() => void commit()}
                  type="button"
                >
                  {evaluationUi ? 'Create approved envelope' : 'Commit approved effect'}
                </button>
              ) : null}
              {currentApproval ? (
                <p>
                  Approval state: <strong>{currentApproval.state}</strong>
                </p>
              ) : null}
            </div>
          )}
        </section>
      ) : (
        <section
          aria-labelledby="checker-heading"
          className="rounded border border-[color:var(--border)] bg-[color:var(--surface)] p-4"
        >
          <h2 className="text-xl font-semibold" id="checker-heading">
            Checker inbox
          </h2>
          {state.approvals.length === 0 ? (
            <p className="mt-3">No candidate currently requires your decision.</p>
          ) : (
            <ul className="mt-4 space-y-3">
              {state.approvals.map((item) => (
                <li
                  className="rounded border border-[color:var(--border)] p-3"
                  key={item.approvalRequestId}
                >
                  <p className="break-all font-mono text-xs">{item.candidateDigest}</p>
                  <p className="mt-2">
                    State: <strong>{item.state}</strong>
                  </p>
                  {item.state === 'REQUESTED' ? (
                    <button
                      className="mt-3 rounded bg-[color:var(--accent)] px-3 py-2 font-medium text-white disabled:opacity-60"
                      disabled={busy}
                      onClick={() => void approve(item)}
                      type="button"
                    >
                      Review and approve with security key
                    </button>
                  ) : null}
                </li>
              ))}
            </ul>
          )}
        </section>
      )}

      {state.effect ? (
        <section
          aria-label="Authoritative effect"
          className="rounded border border-[color:var(--success)] bg-[color:var(--surface)] p-4"
        >
          <h2 className="text-xl font-semibold">Authoritative effect</h2>
          <p className="mt-2">
            Envelope <strong>{state.effect.effect.state}</strong>
          </p>
          <p className="mt-1 break-all text-sm">Operation: {state.effect.operationId}</p>
          <p className="mt-1 break-all text-sm">Effect: {state.effect.effect.id}</p>
        </section>
      ) : null}
      <p
        aria-live="polite"
        className="rounded border border-[color:var(--border)] p-3"
        role="status"
      >
        {displayStatus}
      </p>
    </div>
  );
}
