'use client';

import { PrincipalCatalogue } from './principal-catalogue';
import { PrincipalRoleAssignments } from './principal-role-assignments';

import { performWebAuthnStepUp } from '@openpc/ui-shell';
import { useEffect, useLayoutEffect, useRef, useState } from 'react';
import { z } from 'zod';
import { LocalSessionSurface } from './local-session';
import { WorkspaceEntry } from './workspace-entry';
import { GovernanceContextSummary } from './governance-context-summary';
import { approvalStateLabel } from '../lib/approval-catalogue';
import {
  readBoundPolicyState,
  writeBoundPolicyState,
  type PolicyWorkflowActorBinding as Actor,
} from './policy-workflow-storage';

const storageKey = 'openpc:principal-workflow:v1';
const panel = 'rounded border border-[color:var(--border)] bg-[color:var(--surface)] p-4';
const field = 'rounded border border-[color:var(--border)] bg-[color:var(--canvas)] p-2';
const button =
  'w-fit rounded bg-[color:var(--accent)] px-3 py-2 font-medium text-[color:var(--surface)] disabled:opacity-60';
const principalSchema = z.object({
  principalId: z.uuid(),
  displayLabel: z.string(),
  kind: z.string(),
  state: z.string(),
  revision: z.string().optional(),
  identityEpoch: z.string().optional(),
});
const stepSchema = z.object({
  actionIntentId: z.string(),
  actionIntentDigest: z.string(),
  resourceId: z.string(),
  resourceDigest: z.string(),
});
const proposalSchema = z.object({
  mutation: z.enum(['PROVISION', 'ACTIVATE', 'SUSPEND', 'REMOVE']),
  proposedPrincipal: principalSchema,
  expectedRevision: z.string(),
  candidateDigest: z.string(),
  state: z.string().optional(),
});
const reviewSchema = z.object({
  reviewToken: z.string(),
  approvalRequestId: z.uuid().optional(),
  review: proposalSchema.extend({ reason: z.string(), stepUp: stepSchema }),
});
type Principal = z.infer<typeof principalSchema>;
type Review = z.infer<typeof reviewSchema>;
const principalChangeLabels: Record<Review['review']['mutation'], string> = {
  PROVISION: 'Provision principal',
  ACTIVATE: 'Activate principal',
  SUSPEND: 'Suspend principal',
  REMOVE: 'Remove membership',
};
const revisionSchema = z.string().regex(/^(0|[1-9][0-9]*)$/u);
const committedReadbackSchema = z.object({
  effect: principalSchema.extend({
    participantId: z.uuid(),
    displayLabel: z.string().min(1).max(160),
    kind: z.enum(['USER', 'WALLET', 'WORKLOAD', 'PLATFORM_OPERATOR']),
    state: z.enum(['PROVISIONED', 'ACTIVE', 'SUSPENDED', 'REVOKED', 'OFFBOARDED']),
    revision: revisionSchema,
    identityEpoch: revisionSchema,
    identitySubjectId: z.uuid().optional(),
    membershipId: z.uuid().optional(),
  }),
  operationId: z.uuid(),
  humanIdentity: z
    .object({
      identitySubjectId: z.uuid(),
      createdAt: z.string().min(1),
      membershipId: z.uuid(),
      participantId: z.uuid(),
      state: z.string(),
      revision: revisionSchema,
      membershipEpoch: revisionSchema,
    })
    .optional(),
});
const commitResultSchema = z.discriminatedUnion('truthState', [
  committedReadbackSchema.extend({ truthState: z.literal('SUCCESS') }),
  z.object({
    truthState: z.literal('WRITE_AMBIGUITY'),
    principalId: z.uuid(),
    reconciliation: z.literal('READ_AUTHORITATIVE_EFFECT'),
  }),
  z.object({
    truthState: z.literal('REAUTH_REQUIRED'),
    principalId: z.uuid(),
    reconciliation: z.literal('SIGN_IN_THEN_READ_AUTHORITATIVE_EFFECT'),
  }),
]);
type CommittedReadback = z.infer<typeof committedReadbackSchema>;
type ExpectedOutcome = { actor: Actor; review: Review; acknowledged: CommittedReadback };
interface Approval {
  approvalRequestId: string;
  candidateDigest: string;
  state: string;
  proposal: z.infer<typeof proposalSchema>;
  stepUp: z.infer<typeof stepSchema>;
}
interface State {
  actor: Actor & { role: string };
  approvals: Approval[];
  effect?: {
    effect: Principal;
    operationId: string | null;
    humanIdentity?: {
      identitySubjectId: string;
      createdAt: string;
      membershipId: string;
      participantId: string;
      state: string;
      revision: string;
      membershipEpoch: string;
    };
  };
  nextCursor: string | null;
}
function selectedApproval(approvals: readonly Approval[], review: Review | undefined) {
  if (!review?.approvalRequestId) return undefined;
  return approvals.find(
    (item) =>
      (item.approvalRequestId === review.approvalRequestId ||
        item.approvalRequestId === `urn:openpc:resource:${review.approvalRequestId}`) &&
      item.candidateDigest === review.review.candidateDigest,
  );
}
function requestExecuted(approvals: readonly Approval[], review: Review | undefined) {
  if (!review) return false;
  const item = selectedApproval(approvals, review);
  return (
    item?.proposal.state === 'CONSUMED' &&
    item.proposal.mutation === review?.review.mutation &&
    item.proposal.expectedRevision === review.review.expectedRevision &&
    item.proposal.proposedPrincipal.principalId === review.review.proposedPrincipal.principalId
  );
}
type Session = Partial<Actor> & {
  authenticated?: boolean;
  contextMode?: string;
  availableContexts?: { participantId: string; privacyDomainId: string }[];
};
const contextSelectionSchema = z.object({
  sessionId: z.uuid(),
  availableContexts: z
    .array(z.object({ participantId: z.uuid(), privacyDomainId: z.uuid() }))
    .min(1),
});
type PrincipalCeremony = {
  generation: number;
  actor: string;
  controller: AbortController;
  selection?: () => boolean;
  readFailure?: unknown;
};
function binding(session: Session): Actor | undefined {
  if (
    !session.authenticated ||
    session.contextMode !== 'PARTICIPANT' ||
    !session.sessionId ||
    !session.principalId ||
    !session.participantId ||
    !session.privacyDomainId ||
    !session.contextEpoch
  )
    return undefined;
  return {
    sessionId: session.sessionId,
    principalId: session.principalId,
    participantId: session.participantId,
    privacyDomainId: session.privacyDomainId,
    contextEpoch: session.contextEpoch,
  };
}
const failureMessages = {
  unavailable:
    'Principal request could not be confirmed. Refresh or read the original operation before retrying.',
  authorization:
    'Principal request was not authorized. Refresh the authenticated context before continuing.',
  conflict: 'Principal state changed. Refresh or read the original operation before retrying.',
  input: 'Principal request was rejected. Check the inputs before continuing.',
  context: 'Authenticated context could not be confirmed. Refresh before continuing.',
  approvals: 'Principal approvals could not be confirmed. Refresh before continuing.',
  changed: 'The working context changed. Refresh the principal page before continuing.',
  selection: 'Principal readback belongs to a different selection.',
} as const;
class WorkflowFailure extends Error {
  constructor(readonly kind: keyof typeof failureMessages) {
    super(failureMessages[kind]);
  }
}
function reviewedOutcome(value: unknown, selected: Review, actor: Actor): CommittedReadback {
  const parsed = committedReadbackSchema.safeParse(value);
  if (!parsed.success) throw new WorkflowFailure('conflict');
  const { effect, humanIdentity } = parsed.data;
  const { proposedPrincipal, expectedRevision, mutation } = selected.review;
  const targetState = { PROVISION: 'PROVISIONED', ACTIVATE: 'ACTIVE', SUSPEND: 'SUSPENDED' };
  if (
    mutation === 'REMOVE' ||
    effect.principalId !== proposedPrincipal.principalId ||
    effect.participantId !== actor.participantId ||
    effect.displayLabel !== proposedPrincipal.displayLabel ||
    effect.kind !== proposedPrincipal.kind ||
    effect.state !== proposedPrincipal.state ||
    effect.state !== targetState[mutation] ||
    !revisionSchema.safeParse(expectedRevision).success ||
    BigInt(effect.revision) <= BigInt(expectedRevision) ||
    (effect.identitySubjectId === undefined) !== (effect.membershipId === undefined) ||
    (effect.membershipId !== undefined && effect.membershipId !== effect.principalId) ||
    (humanIdentity !== undefined &&
      (humanIdentity.identitySubjectId !== effect.identitySubjectId ||
        humanIdentity.membershipId !== effect.membershipId ||
        humanIdentity.participantId !== effect.participantId ||
        humanIdentity.state !== effect.state ||
        humanIdentity.revision !== effect.revision ||
        humanIdentity.membershipEpoch !== effect.identityEpoch))
  )
    throw new WorkflowFailure('conflict');
  return parsed.data;
}
function failureMessage(error: unknown) {
  return error instanceof WorkflowFailure
    ? failureMessages[error.kind]
    : failureMessages.unavailable;
}
function httpFailure(status: number) {
  return new WorkflowFailure(
    [401, 403, 404].includes(status)
      ? 'authorization'
      : [409, 412, 428].includes(status)
        ? 'conflict'
        : [400, 422].includes(status)
          ? 'input'
          : 'unavailable',
  );
}
async function json<T>(response: Response): Promise<T> {
  const value = await response.json().catch(() => undefined);
  if (!response.ok) throw httpFailure(response.status);
  if (value === undefined) throw new WorkflowFailure('unavailable');
  return value as T;
}
async function sendCommand<T>(value: unknown) {
  return fetch('/api/v1/ui/principal-workbench', {
    method: 'POST',
    credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(value),
  }).then(json<T>);
}
function Details({ value, proposed = false }: { value: Principal; proposed?: boolean }) {
  return (
    <dl className="mt-3 grid gap-3 text-sm sm:grid-cols-2">
      <div>
        <dt className="font-medium">Principal name</dt>
        <dd>{value.displayLabel}</dd>
      </div>
      <div>
        <dt className="font-medium">Kind</dt>
        <dd>{value.kind}</dd>
      </div>
      <div>
        <dt className="font-medium">{proposed ? 'Proposed state' : 'State'}</dt>
        <dd>
          {value.state}
          {value.revision ? ` · revision ${value.revision}` : ''}
        </dd>
      </div>
      <div>
        <dt className="font-medium">Principal ID</dt>
        <dd className="break-all">{value.principalId}</dd>
      </div>
      {value.identityEpoch !== undefined ? (
        <div>
          <dt className="font-medium">Identity epoch</dt>
          <dd>{value.identityEpoch}</dd>
        </div>
      ) : null}
    </dl>
  );
}
export function PrincipalWorkflow() {
  const [session, setSession] = useState<Session>();
  const [state, setState] = useState<State>();
  const [review, setReview] = useState<Review>();
  const [principalId, setPrincipalId] = useState('');
  const [status, setStatus] = useState('');
  const [busy, setBusy] = useState(false);
  const actorRef = useRef<Actor | undefined>(undefined);
  const generationRef = useRef(0);
  const loadController = useRef<AbortController | undefined>(undefined);
  const runGeneration = useRef(0);
  const mounted = useRef(false);
  const sessionRef = useRef<Session | undefined>(undefined);
  const reviewRef = useRef<Review | undefined>(undefined);
  const approvalsRef = useRef<Approval[]>([]);
  const roleRef = useRef<string | undefined>(undefined);
  const ceremonyGeneration = useRef(0);
  const ceremony = useRef<PrincipalCeremony | undefined>(undefined);
  function contextKey(value: Session | undefined) {
    return JSON.stringify(
      value && {
        authenticated: value.authenticated,
        contextMode: value.contextMode,
        sessionId: value.sessionId,
        principalId: value.principalId,
        participantId: value.participantId,
        privacyDomainId: value.privacyDomainId,
        contextEpoch: value.contextEpoch,
      },
    );
  }
  function cancelCeremony() {
    ceremonyGeneration.current += 1;
    ceremony.current?.controller.abort();
  }
  function isCurrent(token: NonNullable<typeof ceremony.current>) {
    return (
      mounted.current &&
      ceremony.current === token &&
      token.generation === ceremonyGeneration.current &&
      !token.controller.signal.aborted &&
      token.actor === contextKey(sessionRef.current) &&
      (token.selection?.() ?? true)
    );
  }
  function assertCeremony() {
    const token = ceremony.current;
    if (!token || !isCurrent(token))
      throw new DOMException('The operation was cancelled.', 'AbortError');
    return token;
  }
  async function stepUp(value: z.infer<typeof stepSchema>, selected?: Review | Approval) {
    const token = assertCeremony();
    if (selected)
      token.selection =
        'reviewToken' in selected
          ? () =>
              roleRef.current === 'operator' &&
              reviewRef.current === selected &&
              selectedApproval(approvalsRef.current, selected)?.proposal.state !== 'CONSUMED'
          : () =>
              roleRef.current === 'viewer' &&
              selected.proposal.state !== 'CONSUMED' &&
              approvalsRef.current.some(
                (item) => JSON.stringify(item) === JSON.stringify(selected),
              );
    assertCeremony();
    await performWebAuthnStepUp({ ...value, stepUp: 'FRESH_WEBAUTHN_MAX_5M' }, value, {
      signal: token.controller.signal,
      isCurrent: () => isCurrent(token),
    });
    assertCeremony();
  }
  async function command<T>(value: unknown) {
    const token = assertCeremony();
    const result = await sendCommand<T>(value);
    assertCeremony();
    token.selection = undefined;
    return result;
  }
  async function runMutation(action: () => Promise<void>) {
    if (!mounted.current || ceremony.current || !sessionRef.current) return;
    const token: PrincipalCeremony = {
      generation: ++ceremonyGeneration.current,
      actor: contextKey(sessionRef.current),
      controller: new AbortController(),
    };
    ceremony.current = token;
    setBusy(true);
    setStatus('');
    try {
      await action();
    } catch (cause) {
      if (isCurrent(token)) setStatus(failureMessage(cause));
      else if (
        mounted.current &&
        ceremony.current === token &&
        !sessionRef.current &&
        token.readFailure !== undefined
      )
        setStatus(failureMessage(token.readFailure));
    } finally {
      if (ceremony.current === token) ceremony.current = undefined;
      if (mounted.current) setBusy(false);
    }
  }

  async function load(id?: string, cursor?: string, expected?: ExpectedOutcome) {
    if (!mounted.current) return;
    const generation = ++generationRef.current;
    loadController.current?.abort();
    const controller = new AbortController();
    loadController.current = controller;
    setStatus('');
    try {
      if (id) setState((current) => (current ? { ...current, effect: undefined } : current));
      const current = await fetch('/api/v1/ui/local-session', {
        cache: 'no-store',
        signal: controller.signal,
      }).then(json<Session>);
      if (!mounted.current || generation !== generationRef.current || controller.signal.aborted)
        return;
      if (
        !current ||
        typeof current.authenticated !== 'boolean' ||
        (current.authenticated &&
          (!['PLATFORM', 'PARTICIPANT'].includes(current.contextMode ?? '') ||
            ![current.sessionId, current.principalId, current.contextEpoch].every(
              (value) => typeof value === 'string' && value.length > 0,
            ) ||
            (current.contextMode === 'PARTICIPANT' &&
              (!binding(current) ||
                ![current.participantId, current.privacyDomainId].every(
                  (value) => typeof value === 'string' && value.length > 0,
                )))))
      )
        throw new WorkflowFailure('context');
      if (contextKey(sessionRef.current) !== contextKey(current)) cancelCeremony();
      sessionRef.current = current;
      setSession(current);
      const actor = binding(current);
      const changed = JSON.stringify(actorRef.current) !== JSON.stringify(actor);
      actorRef.current = actor;
      if (!actor || changed) {
        setState(undefined);
        reviewRef.current = undefined;
        setReview(undefined);
        setPrincipalId('');
        const saved = actor
          ? readBoundPolicyState(
              storageKey,
              actor,
              (value): value is Review => reviewSchema.safeParse(value).success,
            )
          : undefined;
        if (saved) {
          reviewRef.current = saved;
          setReview(saved);
          setPrincipalId(saved.review.proposedPrincipal.principalId);
        }
      }
      if (!actor) {
        try {
          localStorage.removeItem(storageKey);
        } catch {
          /* Optional storage. */
        }
        return;
      }
      const next = await fetch(
        `/api/v1/ui/principal-workbench?${new URLSearchParams({
          ...(id && !changed ? { principalId: id } : {}),
          ...(cursor && !changed ? { cursor } : {}),
        }).toString()}`,
        { cache: 'no-store', signal: controller.signal },
      ).then(json<State>);
      if (!mounted.current || generation !== generationRef.current || controller.signal.aborted)
        return;
      if (
        !next ||
        !next.actor ||
        typeof next.actor.role !== 'string' ||
        !Array.isArray(next.approvals) ||
        !next.approvals.every(
          (item) =>
            item &&
            typeof item.approvalRequestId === 'string' &&
            typeof item.candidateDigest === 'string' &&
            typeof item.state === 'string' &&
            proposalSchema.safeParse(item.proposal).success &&
            stepSchema.safeParse(item.stepUp).success,
        ) ||
        (next.nextCursor !== null && typeof next.nextCursor !== 'string') ||
        (next.effect !== undefined &&
          (!next.effect ||
            !principalSchema.safeParse(next.effect.effect).success ||
            (next.effect.operationId !== null && typeof next.effect.operationId !== 'string') ||
            (next.effect.humanIdentity !== undefined &&
              !z
                .object({
                  identitySubjectId: z.string(),
                  createdAt: z.string(),
                  membershipId: z.string(),
                  participantId: z.string(),
                  state: z.string(),
                  revision: z.string(),
                  membershipEpoch: z.string(),
                })
                .safeParse(next.effect.humanIdentity).success)))
      )
        throw new WorkflowFailure('approvals');
      if (
        JSON.stringify(actorRef.current) !== JSON.stringify(actor) ||
        Object.keys(actor).some(
          (key) => next.actor[key as keyof Actor] !== actor[key as keyof Actor],
        )
      ) {
        setState(undefined);
        setReview(undefined);
        setPrincipalId('');
        throw new WorkflowFailure('changed');
      }
      if (id && !changed && next.effect?.effect.principalId !== id)
        throw new WorkflowFailure('selection');
      if (expected) {
        if (
          Object.keys(expected.actor).some(
            (key) => expected.actor[key as keyof Actor] !== actor[key as keyof Actor],
          )
        )
          throw new WorkflowFailure('changed');
        const actual = reviewedOutcome(next.effect, expected.review, actor);
        if (JSON.stringify(actual) !== JSON.stringify(expected.acknowledged))
          throw new WorkflowFailure('conflict');
      }
      roleRef.current = next.actor.role;
      approvalsRef.current = next.approvals;
      if (ceremony.current?.selection && !ceremony.current.selection())
        ceremony.current.controller.abort();
      setState(next);
      return next;
    } catch (cause) {
      if (!mounted.current || generation !== generationRef.current || controller.signal.aborted)
        return;
      const token = ceremony.current;
      if (token && isCurrent(token)) token.readFailure = cause;
      generationRef.current += 1;
      cancelCeremony();
      sessionRef.current = undefined;
      approvalsRef.current = [];
      reviewRef.current = undefined;
      actorRef.current = undefined;
      setSession(undefined);
      setState(undefined);
      setReview(undefined);
      setPrincipalId('');
      throw cause;
    } finally {
      if (loadController.current === controller) loadController.current = undefined;
    }
  }
  function save(value: Review) {
    if (!actorRef.current) return;
    writeBoundPolicyState(storageKey, actorRef.current, value);
    reviewRef.current = value;
    setReview(value);
    setPrincipalId(value.review.proposedPrincipal.principalId);
  }
  async function run(action: () => Promise<unknown>) {
    if (!mounted.current) return;
    const generation = ++runGeneration.current;
    setBusy(true);
    setStatus('');
    try {
      await action();
    } catch (error) {
      if (generation === runGeneration.current) setStatus(failureMessage(error));
    } finally {
      if (generation === runGeneration.current) setBusy(Boolean(ceremony.current));
    }
  }
  useLayoutEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
      cancelCeremony();
      generationRef.current++;
      runGeneration.current++;
      loadController.current?.abort();
    };
  }, []);
  useEffect(() => {
    let current = true;
    void load().catch((error) => {
      if (current && mounted.current) setStatus(failureMessage(error));
    });
    return () => {
      current = false;
    };
  }, []);
  const currentApproval = selectedApproval(state?.approvals ?? [], review);
  const executed = requestExecuted(state?.approvals ?? [], review);
  async function selectContext() {
    const token = assertCeremony();
    const selected = contextSelectionSchema.safeParse(sessionRef.current);
    if (!selected.success) throw new WorkflowFailure('context');
    const expectedSessionId = selected.data.sessionId;
    const context = selected.data.availableContexts[0]!;
    token.selection = () => {
      const current = sessionRef.current;
      return (
        current?.sessionId === expectedSessionId &&
        current.availableContexts?.[0]?.participantId === context.participantId &&
        current.availableContexts?.[0]?.privacyDomainId === context.privacyDomainId
      );
    };
    const qualifyContext = async () => {
      const actual = await fetch('/api/v1/ui/local-session', {
        cache: 'no-store',
        credentials: 'same-origin',
        signal: token.controller.signal,
      }).then(json<Session>);
      assertCeremony();
      const confirmed = contextSelectionSchema.safeParse(actual);
      if (
        !confirmed.success ||
        contextKey(actual) !== token.actor ||
        confirmed.data.availableContexts[0]?.participantId !== context.participantId ||
        confirmed.data.availableContexts[0]?.privacyDomainId !== context.privacyDomainId
      )
        throw new WorkflowFailure('changed');
    };
    const resourceDigest = `sha256:${Array.from(
      new Uint8Array(
        await crypto.subtle.digest('SHA-256', new TextEncoder().encode(JSON.stringify(context))),
      ),
    )
      .map((byte) => byte.toString(16).padStart(2, '0'))
      .join('')}`;
    assertCeremony();
    await qualifyContext();
    await stepUp({
      actionIntentId: 'ACT-IDENTITY_CREATE_SESSION-V1',
      actionIntentDigest: 'sha256:dbc8290dd60814d5bb4248fefc9550f43d0dc97d6333ac232c8ab8a98c3354d2',
      resourceId: context.participantId,
      resourceDigest,
    });
    assertCeremony();
    await qualifyContext();
    await fetch('/api/v1/ui/session/context', {
      method: 'POST',
      signal: token.controller.signal,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ...context, expectedSessionId }),
    }).then(json);
    assertCeremony();
    token.selection = undefined;
    await load();
  }
  async function preview(
    event: React.FormEvent<HTMLFormElement>,
    transition?: 'ACTIVATE' | 'SUSPEND' | 'REMOVE',
  ) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    await runMutation(async () => {
      const value = await command<Review>(
        transition
          ? {
              command: `PREVIEW_${transition}`,
              principalId: state?.effect?.effect.principalId,
              reason: form.get('reason'),
            }
          : {
              command: 'PREVIEW_PROVISION',
              displayLabel: form.get('displayLabel'),
              kind: form.get('kind'),
              reason: form.get('reason'),
            },
      );
      save(value);
      setStatus('Review the exact principal change before requesting approval.');
    });
  }
  async function submit() {
    if (!review) return;
    const value = await command<Review & { approval: Approval }>({
      command: 'SUBMIT',
      reviewToken: review.reviewToken,
    });
    save({ ...value, approvalRequestId: value.approval.approvalRequestId.slice(-36) });
    await load();
    assertCeremony();
    setStatus('The principal change is awaiting a distinct checker.');
  }
  async function approve(item: Approval) {
    await stepUp(item.stepUp, item);
    await command({
      command: 'APPROVE',
      approvalRequestId: item.approvalRequestId.slice(-36),
      candidateDigest: item.candidateDigest,
    });
    await load();
    assertCeremony();
    setStatus('The reviewed principal change is approved.');
  }
  async function commit() {
    if (!review?.approvalRequestId) return;
    const selectedReview = review;
    if (selectedApproval(approvalsRef.current, selectedReview)?.proposal.state === 'CONSUMED') {
      setStatus(
        'This request has already been executed. Read the principal for its current state.',
      );
      return;
    }
    await stepUp(selectedReview.review.stepUp, selectedReview);
    const token = assertCeremony();
    const selectedActor = actorRef.current;
    if (!selectedActor) throw new WorkflowFailure('context');
    const readGeneration = generationRef.current;
    // Once dispatched, a removal result must reconcile even if an independent
    // same-context read has superseded its load generation.
    const result = await sendCommand<unknown>({
      command: 'COMMIT',
      reviewToken: selectedReview.reviewToken,
      approvalRequestId: selectedReview.approvalRequestId,
    });
    const parsed = commitResultSchema.safeParse(result);
    if (!parsed.success) throw new WorkflowFailure('unavailable');
    const value = parsed.data;
    if (value.truthState === 'REAUTH_REQUIRED') {
      if (
        selectedReview.review.mutation !== 'REMOVE' ||
        selectedReview.review.proposedPrincipal.state !== 'OFFBOARDED' ||
        value.principalId !== selectedReview.review.proposedPrincipal.principalId
      )
        throw new WorkflowFailure('conflict');
      if (!mounted.current || token.actor !== contextKey(sessionRef.current)) return;
      cancelCeremony();
      sessionRef.current = { authenticated: false };
      actorRef.current = undefined;
      approvalsRef.current = [];
      reviewRef.current = undefined;
      generationRef.current++;
      loadController.current?.abort();
      setState(undefined);
      setReview(undefined);
      setSession({ authenticated: false });
      setStatus(
        `Membership removal committed. Sign in again, select the Participant context, and read membership ${value.principalId}.`,
      );
      return;
    }
    assertCeremony();
    if (readGeneration !== generationRef.current) return;
    token.selection = undefined;
    if (value.truthState === 'WRITE_AMBIGUITY') {
      if (value.principalId !== selectedReview.review.proposedPrincipal.principalId)
        throw new WorkflowFailure('conflict');
      setStatus('The response was lost. Read the principal before retrying.');
      return;
    }
    const acknowledged = reviewedOutcome(value, selectedReview, selectedActor);
    const current = await load(selectedReview.review.proposedPrincipal.principalId, undefined, {
      actor: selectedActor,
      review: selectedReview,
      acknowledged,
    });
    if (!current) return;
    assertCeremony();
    setStatus('Principal change committed and its durable effect read back.');
  }
  if (!session)
    return (
      <div className="mt-6 space-y-3">
        <p role="status">{status || 'Loading the authenticated context.'}</p>
        {status && (
          <button className={button} disabled={busy} onClick={() => void run(() => load())}>
            Refresh principal approvals
          </button>
        )}
      </div>
    );
  if (!session.authenticated)
    return (
      <div>
        <p role="status" className="break-words">
          {status}
        </p>
        <LocalSessionSurface />
      </div>
    );
  return (
    <div className="mt-6 space-y-6">
      <p role="status" aria-live="polite" className="break-words">
        {status}
      </p>
      {session.contextMode !== 'PARTICIPANT' ? (
        <section className={panel}>
          <h2 className="text-xl font-semibold">Choose a working context</h2>
          <p className="my-3">
            Principal changes require an explicit Participant and privacy domain.
          </p>
          <WorkspaceEntry disabled={busy}>
            <button
              className={button}
              disabled={busy}
              onClick={() => void runMutation(selectContext)}
            >
              Enter workspace
            </button>
          </WorkspaceEntry>
        </section>
      ) : null}
      {state ? (
        <>
          <GovernanceContextSummary
            title="Principal governance"
            description="Manage identities and review their membership changes."
            actor={state.actor}
          >
            <button className={button} disabled={busy} onClick={() => void run(() => load())}>
              Refresh principal approvals
            </button>
          </GovernanceContextSummary>
          <PrincipalCatalogue
            key={[
              state.actor.sessionId,
              state.actor.principalId,
              state.actor.participantId,
              state.actor.privacyDomainId,
              state.actor.contextEpoch,
            ].join(':')}
            actor={state.actor}
            onOpen={(id) => void run(() => load(id))}
          />
          {state.actor.role === 'operator' ? (
            <section className={panel}>
              <h2 className="text-xl font-semibold">Provision a principal</h2>
              <p className="mt-2">
                Provisioning creates an identity record. Activation, credentials and authority
                assignments are separate governed steps.
              </p>
              <form className="mt-4 grid max-w-2xl gap-4" onSubmit={(event) => void preview(event)}>
                <label className="grid gap-1">
                  Principal name
                  <input className={field} name="displayLabel" required maxLength={160} />
                </label>
                <label className="grid gap-1">
                  Principal kind
                  <select className={field} name="kind">
                    <option value="USER">User</option>
                    <option value="WALLET">Wallet</option>
                    <option value="WORKLOAD">Workload</option>
                  </select>
                </label>
                <label className="grid gap-1">
                  Reason
                  <textarea
                    className={field}
                    name="reason"
                    required
                    minLength={10}
                    maxLength={1024}
                  />
                </label>
                <button className={button} disabled={busy} type="submit">
                  Review principal provisioning
                </button>
              </form>
            </section>
          ) : null}
          {review && state.actor.role === 'operator' ? (
            <section className={panel} aria-label="Principal change review">
              <h2 className="text-xl font-semibold">
                {executed
                  ? 'Executed request'
                  : `${principalChangeLabels[review.review.mutation]} · review`}
              </h2>
              <Details value={review.review.proposedPrincipal} proposed />
              <p className="mt-3">Reason: {review.review.reason}</p>
              <p>Expected revision: {review.review.expectedRevision}</p>
              <p className="break-all text-xs">Candidate: {review.review.candidateDigest}</p>
              <p className="my-3">
                {review.review.mutation === 'SUSPEND'
                  ? 'Suspension revokes this principal’s active sessions and advances its identity epoch.'
                  : review.review.mutation === 'REMOVE'
                    ? 'Removal permanently offboards this Participant membership and revokes its local sessions, credentials and dependent grants. The global subject and other Participant memberships remain. A new sign-in is required afterward.'
                    : 'This transition grants no credentials or authority assignments.'}
              </p>
              {!review.approvalRequestId ? (
                <button className={button} disabled={busy} onClick={() => void runMutation(submit)}>
                  Send principal to checker
                </button>
              ) : (
                <p>
                  Approval:{' '}
                  {currentApproval ? approvalStateLabel(currentApproval.state) : 'Refresh to check'}
                </p>
              )}
              {executed ? (
                <p role="status" className="mt-3">
                  This request has been executed. Read the principal below for its current state.
                </p>
              ) : null}
              {currentApproval?.state === 'APPROVED' &&
              currentApproval.proposal.state !== 'CONSUMED' ? (
                <button
                  className={`${button} mt-3`}
                  disabled={busy}
                  onClick={() => void runMutation(commit)}
                >
                  Commit approved principal change
                </button>
              ) : null}
            </section>
          ) : null}
          <section className={panel}>
            <h2 className="text-xl font-semibold">Principal approvals</h2>
            {state.approvals.length === 0 ? (
              <p className="mt-3">No visible principal approvals on this page.</p>
            ) : (
              state.approvals.map((item) => (
                <article
                  key={item.approvalRequestId}
                  className="mt-4 border-t border-[color:var(--border)] pt-4"
                >
                  <h3 className="font-semibold">
                    {principalChangeLabels[item.proposal.mutation]} ·{' '}
                    {item.proposal.state === 'CONSUMED' &&
                    item.proposal.candidateDigest === item.candidateDigest
                      ? 'Executed'
                      : approvalStateLabel(item.state)}
                  </h3>
                  <Details value={item.proposal.proposedPrincipal} proposed />
                  <p>Expected revision: {item.proposal.expectedRevision}</p>
                  <p className="my-2 break-all text-xs">Candidate: {item.candidateDigest}</p>
                  {item.proposal.mutation === 'REMOVE' ? (
                    <p className="my-3">
                      Removal permanently revokes this membership’s local sessions, credentials and
                      dependent grants. Its global identity and other Participant memberships
                      remain.
                    </p>
                  ) : null}
                  {item.proposal.mutation === 'SUSPEND' ? (
                    <p className="my-3">
                      Suspension revokes the principal’s active sessions and advances its identity
                      epoch.
                    </p>
                  ) : null}
                  {state.actor.role === 'viewer' &&
                  item.state === 'REQUESTED' &&
                  item.proposal.state !== 'CONSUMED' ? (
                    <button
                      className={button}
                      disabled={busy}
                      onClick={() => void runMutation(() => approve(item))}
                    >
                      Approve {item.proposal.proposedPrincipal.displayLabel}
                    </button>
                  ) : null}
                </article>
              ))
            )}
            {state.nextCursor ? (
              <button
                className={`${button} mt-3`}
                disabled={busy}
                onClick={() => void run(() => load(undefined, state.nextCursor ?? undefined))}
              >
                Next principal approval page
              </button>
            ) : null}
          </section>
          <section className={panel}>
            <h2 className="text-xl font-semibold">Read a principal</h2>
            <form
              className="mt-3 grid max-w-2xl gap-3"
              onSubmit={(event) => {
                event.preventDefault();
                void run(() => load(principalId));
              }}
            >
              <label className="grid gap-1">
                Principal ID
                <input
                  className={field}
                  value={principalId}
                  onChange={(event) => setPrincipalId(event.target.value)}
                  required
                />
              </label>
              <button className={button} disabled={busy} type="submit">
                Find principal
              </button>
            </form>
            {state.effect ? (
              <>
                <Details value={state.effect.effect} />
                <PrincipalRoleAssignments
                  key={`${state.actor.sessionId}:${state.actor.principalId}:${state.actor.participantId}:${state.actor.privacyDomainId}:${state.actor.contextEpoch}:${state.effect.effect.principalId}`}
                  actor={state.actor}
                  principalId={state.effect.effect.principalId}
                />
                {state.effect.humanIdentity ? (
                  <section
                    aria-label="Human identity and membership"
                    className="mt-4 rounded border border-[color:var(--border)] p-3"
                  >
                    <h3 className="font-semibold">Human identity and membership</h3>
                    <p className="mt-2 text-sm">
                      The global subject identifies the person. Authority is limited to this
                      Participant membership.
                    </p>
                    <dl className="mt-3 grid gap-3 text-sm sm:grid-cols-2">
                      <div>
                        <dt className="font-medium">Global identity subject</dt>
                        <dd className="break-all">
                          {state.effect.humanIdentity.identitySubjectId}
                        </dd>
                      </div>
                      <div>
                        <dt className="font-medium">Subject created</dt>
                        <dd>{new Date(state.effect.humanIdentity.createdAt).toLocaleString()}</dd>
                      </div>
                      <div>
                        <dt className="font-medium">Membership ID</dt>
                        <dd className="break-all">{state.effect.humanIdentity.membershipId}</dd>
                      </div>
                      <div>
                        <dt className="font-medium">Membership Participant</dt>
                        <dd className="break-all">{state.effect.humanIdentity.participantId}</dd>
                      </div>
                      <div>
                        <dt className="font-medium">Membership state</dt>
                        <dd>{state.effect.humanIdentity.state}</dd>
                      </div>
                      <div>
                        <dt className="font-medium">Membership revision</dt>
                        <dd>{state.effect.humanIdentity.revision}</dd>
                      </div>
                      <div>
                        <dt className="font-medium">Membership authority epoch</dt>
                        <dd>{state.effect.humanIdentity.membershipEpoch}</dd>
                      </div>
                    </dl>
                  </section>
                ) : null}
                <p className="mt-3 break-all text-sm">
                  Operation:{' '}
                  {state.effect.operationId ??
                    'Initial trust or no operation visible in this privacy domain'}
                </p>
                {state.actor.role === 'operator' &&
                state.effect.humanIdentity &&
                ['PROVISIONED', 'ACTIVE', 'SUSPENDED'].includes(state.effect.effect.state) ? (
                  <form
                    className="mt-4 grid max-w-2xl gap-3"
                    onSubmit={(event) => void preview(event, 'REMOVE')}
                  >
                    <p>
                      Remove this Participant membership permanently. The global identity and other
                      Participant memberships are retained.
                    </p>
                    <label className="grid gap-1">
                      Membership removal reason
                      <textarea
                        className={field}
                        name="reason"
                        required
                        minLength={10}
                        maxLength={1024}
                      />
                    </label>
                    <button className={button} disabled={busy} type="submit">
                      Review membership removal
                    </button>
                  </form>
                ) : null}
                {state.actor.role === 'operator' &&
                ['PROVISIONED', 'ACTIVE'].includes(state.effect.effect.state) ? (
                  <form
                    className="mt-4 grid max-w-2xl gap-3"
                    onSubmit={(event) =>
                      void preview(
                        event,
                        state.effect!.effect.state === 'PROVISIONED' ? 'ACTIVATE' : 'SUSPEND',
                      )
                    }
                  >
                    <label className="grid gap-1">
                      Transition reason
                      <textarea
                        className={field}
                        name="reason"
                        required
                        minLength={10}
                        maxLength={1024}
                      />
                    </label>
                    <button className={button} disabled={busy} type="submit">
                      {state.effect.effect.state === 'PROVISIONED'
                        ? 'Review principal activation'
                        : 'Review principal suspension'}
                    </button>
                  </form>
                ) : null}
              </>
            ) : null}
          </section>
        </>
      ) : null}
    </div>
  );
}
