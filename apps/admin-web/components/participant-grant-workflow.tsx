'use client';

import { performWebAuthnStepUp } from '@openpc/ui-shell';
import { useEffect, useLayoutEffect, useRef, useState } from 'react';
import { z } from 'zod';
import { GrantDetails, GrantFields } from './grant-workflow-fields';
import {
  savedGrantReview,
  type GrantReview as Review,
  type GrantReadback,
  type GrantKind,
} from './grant-workflow-contract';
import {
  readBoundPolicyState as readBoundState,
  writeBoundPolicyState as writeBoundState,
  type PolicyWorkflowActorBinding as ActorBinding,
} from './policy-workflow-storage';
import { LocalSessionSurface } from './local-session';
import { WorkspaceEntry } from './workspace-entry';
import { GovernanceContextSummary } from './governance-context-summary';
import { approvalStateLabel } from '../lib/approval-catalogue';

const storageKey = 'openpc:grant-workflow:v1';
const panel = 'rounded border border-[color:var(--border)] bg-[color:var(--surface)] p-4';
const field = 'rounded border border-[color:var(--border)] bg-[color:var(--canvas)] p-2';
const button =
  'w-fit rounded bg-[color:var(--accent)] px-3 py-2 font-medium text-[color:var(--surface)] disabled:opacity-60';
type Proposal = Review['review'];
type StepUp = Proposal['stepUp'];
interface Approval {
  approvalRequestId: string;
  candidateDigest: string;
  state: string;
  proposal: Proposal;
  stepUp: StepUp;
}
interface State {
  approvalsLoaded?: boolean;
  actor: ActorBinding & { role: string };
  approvals: Approval[];
  effect?: GrantReadback;
  nextCursor: string | null;
}
interface Session {
  sessionId?: string;
  principalId?: string;
  contextEpoch?: string;
  authenticated?: boolean;
  contextMode?: string;
  participantId?: string;
  privacyDomainId?: string;
  availableContexts?: { participantId: string; privacyDomainId: string }[];
}
const contextSelectionSchema = z.object({
  sessionId: z.uuid(),
  availableContexts: z
    .array(z.object({ participantId: z.uuid(), privacyDomainId: z.uuid() }))
    .min(1),
});
function actorBinding(session: Session, platformHandoff = false): ActorBinding | undefined {
  if (
    !session.authenticated ||
    (session.contextMode !== 'PARTICIPANT' &&
      !(platformHandoff && session.contextMode === 'PLATFORM')) ||
    !session.sessionId ||
    !session.principalId ||
    !session.contextEpoch ||
    !session.participantId ||
    !session.privacyDomainId
  )
    return undefined;
  return {
    sessionId: session.sessionId,
    principalId: session.principalId,
    contextEpoch: session.contextEpoch,
    participantId: session.participantId,
    privacyDomainId: session.privacyDomainId,
  };
}
function validReview(value: unknown): value is Review {
  return savedGrantReview.safeParse(value).success;
}
const failureMessages = {
  unavailable:
    'Grant request could not be confirmed. Refresh or read the original operation before retrying.',
  authorization:
    'Grant request was not authorized. Refresh the authenticated context before continuing.',
  conflict: 'Grant state changed. Refresh or read the original operation before retrying.',
  input: 'Grant request was rejected. Check the inputs before continuing.',
  handoff: 'The authenticated handoff context changed. Refresh before continuing.',
} as const;
class WorkflowFailure extends Error {
  constructor(readonly kind: keyof typeof failureMessages) {
    super(failureMessages[kind]);
  }
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
async function command<T>(body: unknown, platformHandoff = false) {
  return json<T>(
    await fetch(`/api/v1/ui/grant-workbench${platformHandoff ? '?mode=platform-handoff' : ''}`, {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    }),
  );
}
export function ParticipantGrantWorkflow({
  platformHandoff = false,
  initialGrant,
  initialPrincipalId,
  initialAuthorityEnvelopeId,
  initialRoleId,
  initialCapabilityIds,
  initialResourceIds,
}: {
  readonly platformHandoff?: boolean;
  readonly initialGrant?: { readonly id: string; readonly kind: GrantKind };
  readonly initialPrincipalId?: string;
  readonly initialAuthorityEnvelopeId?: string;
  readonly initialRoleId?: string;
  readonly initialCapabilityIds?: readonly string[];
  readonly initialResourceIds?: string;
} = {}) {
  const approvalSelection = useRef('');
  const [approvalSelector, setApprovalSelector] = useState('');
  const [session, setSession] = useState<Session>();
  const [state, setState] = useState<State>();
  const [review, setReview] = useState<Review>();
  const [grantId, setGrantId] = useState('');
  const [kind, setKind] = useState<GrantKind>('assignment');
  const [readKind, setReadKind] = useState<GrantKind>('assignment');
  const [status, setStatusValue] = useState('');
  const [busy, setBusy] = useState(false);
  const [reauthenticate, setReauthenticate] = useState(false);
  const actorRef = useRef<ActorBinding | undefined>(undefined);
  const sessionRef = useRef<Session | undefined>(undefined);
  const loadRevision = useRef(0);
  const mounted = useRef(false);
  const locked = useRef(false);
  const selectionRef = useRef('');
  const sentGrant = useRef<
    | {
        id: string;
        kind: GrantKind;
        principalId: string;
        participantId: string;
        privacyDomainId: string;
      }
    | undefined
  >(undefined);
  const operation = useRef<
    | {
        controller: AbortController;
        actor: string;
        selection?: string;
        contextChange?: boolean;
        contextSelection?: () => boolean;
      }
    | undefined
  >(undefined);
  function isCurrent(token: NonNullable<typeof operation.current>) {
    return (
      mounted.current &&
      operation.current === token &&
      !token.controller.signal.aborted &&
      (token.contextChange || token.actor === JSON.stringify(actorRef.current)) &&
      (token.contextSelection?.() ?? true) &&
      (token.selection === undefined || token.selection === selectionRef.current)
    );
  }
  function assertOperation() {
    const token = operation.current;
    if (!token || !isCurrent(token))
      throw new DOMException('The operation was cancelled.', 'AbortError');
    return token;
  }
  function setStatus(value: string) {
    if (mounted.current && (!operation.current || isCurrent(operation.current)))
      setStatusValue(value);
  }
  async function send<T>(body: unknown, retainSentOutcome = false): Promise<T> {
    const token = assertOperation();
    const result = await command<T>(body, platformHandoff);
    // Revocation may invalidate current authority while the original POST is in flight.
    // Its returned reconciliation obligation survives a changed review/read frontier.
    if (
      retainSentOutcome &&
      mounted.current &&
      operation.current === token &&
      token.actor === JSON.stringify(actorRef.current)
    ) {
      token.selection = undefined;
      return result;
    }
    assertOperation();
    token.selection = undefined;
    return result;
  }
  async function stepUp(value: StepUp) {
    const token = assertOperation();
    await performWebAuthnStepUp({ ...value, stepUp: 'FRESH_WEBAUTHN_MAX_5M' }, value, {
      signal: token.controller.signal,
      isCurrent: () => isCurrent(token),
    });
    assertOperation();
  }
  useLayoutEffect(() => {
    selectionRef.current = JSON.stringify([
      platformHandoff,
      session,
      state,
      review,
      kind,
      approvalSelector,
      approvalSelection.current,
    ]);
    if (operation.current && !isCurrent(operation.current)) operation.current.controller.abort();
  });
  useLayoutEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
      operation.current?.controller.abort();
      loadRevision.current++;
      actorRef.current = undefined;
    };
  }, []);
  async function load(
    id?: string,
    cursor?: string,
    selectedKind = readKind,
    originalRead?: NonNullable<typeof sentGrant.current>,
  ) {
    if (!mounted.current) return;
    const generation = ++loadRevision.current;
    let current = await fetch('/api/v1/ui/local-session', { cache: 'no-store' }).then(
      json<Session>,
    );
    if (!mounted.current || generation !== loadRevision.current) return;
    if (
      actorRef.current &&
      ['sessionId', 'principalId', 'contextEpoch'].some(
        (key) => actorRef.current?.[key as keyof ActorBinding] !== current[key as keyof Session],
      )
    ) {
      actorRef.current = undefined;
      approvalSelection.current = '';
      setApprovalSelector('');
      setState(undefined);
      setReview(undefined);
      setGrantId('');
    }
    let initialState: State | undefined;
    if (platformHandoff && current.authenticated && current.contextMode === 'PLATFORM') {
      const bound: State = await fetch(
        `/api/v1/ui/grant-workbench?${new URLSearchParams({ mode: 'platform-handoff', ...(approvalSelection.current ? { approvalRequestId: approvalSelection.current } : {}) })}`,
        {
          cache: 'no-store',
        },
      ).then(json<State>);
      initialState = bound;
      if (!mounted.current || generation !== loadRevision.current) return;
      if (
        bound.actor.sessionId !== current.sessionId ||
        bound.actor.principalId !== current.principalId ||
        bound.actor.contextEpoch !== current.contextEpoch
      )
        throw new WorkflowFailure('handoff');
      current = {
        ...current,
        participantId: bound.actor.participantId,
        privacyDomainId: bound.actor.privacyDomainId,
      };
    }
    sessionRef.current = current;
    setSession(current);
    const actor = actorBinding(current, platformHandoff);
    const changed = JSON.stringify(actorRef.current) !== JSON.stringify(actor);
    actorRef.current = actor;
    if (!actor || changed) {
      approvalSelection.current = '';
      setApprovalSelector('');
      setState(undefined);
      setReview(undefined);
      setGrantId('');
      const saved =
        actor && !originalRead ? readBoundState(storageKey, actor, validReview) : undefined;
      if (saved) {
        approvalSelection.current = saved.approvalRequestId ?? '';
        setReview(saved);
        setGrantId(saved.review.proposedGrant.id);
        setReadKind(saved.review.kind);
      }
    }
    if (!actor) {
      try {
        if (!originalRead) localStorage.removeItem(storageKey);
      } catch {
        /* Optional storage. */
      }
      return;
    }
    const sameOriginalScope =
      originalRead &&
      actor.principalId === originalRead.principalId &&
      actor.participantId === originalRead.participantId &&
      actor.privacyDomainId === originalRead.privacyDomainId;
    const target = sameOriginalScope
      ? { id: originalRead.id, kind: originalRead.kind }
      : id && !changed && !originalRead
        ? { id, kind: selectedKind }
        : generation === 1
          ? initialGrant
          : undefined;
    const next =
      initialState && !target && !cursor
        ? initialState
        : await fetch(
            `/api/v1/ui/grant-workbench?${new URLSearchParams({
              ...(platformHandoff
                ? {
                    mode: 'platform-handoff',
                    ...(approvalSelection.current
                      ? { approvalRequestId: approvalSelection.current }
                      : {}),
                  }
                : {}),
              ...(target ? { grantId: target.id, kind: target.kind } : {}),
              ...(cursor ? { cursor } : {}),
            }).toString()}`,
            { cache: 'no-store' },
          ).then(json<State>);
    if (
      !mounted.current ||
      generation !== loadRevision.current ||
      JSON.stringify(actorRef.current) !== JSON.stringify(actor)
    )
      return;
    if (
      ['sessionId', 'principalId', 'participantId', 'privacyDomainId', 'contextEpoch'].some(
        (key) => next.actor[key as keyof ActorBinding] !== actor[key as keyof ActorBinding],
      )
    )
      return;
    if (target) {
      setGrantId(target.id);
      setReadKind(target.kind);
    }
    setState(next);
    setReauthenticate(false);
  }
  function save(next: Review) {
    assertOperation();
    approvalSelection.current = next.approvalRequestId ?? '';
    const actor = actorRef.current;
    if (!actor) return;
    setReview(next);
    writeBoundState(storageKey, actor, next);
    setGrantId(next.review.proposedGrant.id);
    setReadKind(next.review.kind);
    setState((current) =>
      current?.effect && current.effect.effect.id !== next.review.proposedGrant.id
        ? { ...current, effect: undefined }
        : current,
    );
  }
  async function run(action: () => Promise<void>) {
    if (!mounted.current || locked.current) return;
    locked.current = true;
    const token = {
      controller: new AbortController(),
      actor: JSON.stringify(actorRef.current),
      selection: selectionRef.current,
    };
    operation.current = token;
    setBusy(true);
    setStatus('');
    try {
      assertOperation();
      await action();
    } catch (error) {
      if (isCurrent(token)) setStatus(failureMessage(error));
    } finally {
      if (operation.current === token) {
        operation.current = undefined;
        locked.current = false;
        if (mounted.current) setBusy(false);
      }
    }
  }
  useEffect(() => {
    const generation = loadRevision.current + 1;
    void load().catch((error) => {
      if (mounted.current && generation === loadRevision.current) setStatus(failureMessage(error));
    });
  }, []);
  const currentApproval = state?.approvals.find((item) =>
    item.approvalRequestId.endsWith(review?.approvalRequestId ?? '!'),
  );
  async function selectContext() {
    const token = assertOperation();
    const source = sessionRef.current;
    const selected = contextSelectionSchema.safeParse(source);
    if (!selected.success) throw new WorkflowFailure('unavailable');
    const expectedSessionId = selected.data.sessionId;
    const context = selected.data.availableContexts[0]!;
    const originalSession = JSON.stringify(source);
    token.contextSelection = () => JSON.stringify(sessionRef.current) === originalSession;
    const qualifyContext = async () => {
      const actual = await fetch('/api/v1/ui/local-session', {
        cache: 'no-store',
        credentials: 'same-origin',
        signal: token.controller.signal,
      }).then(json<Session>);
      assertOperation();
      const confirmed = contextSelectionSchema.safeParse(actual);
      if (
        !confirmed.success ||
        !(
          [
            'authenticated',
            'contextMode',
            'sessionId',
            'principalId',
            'participantId',
            'privacyDomainId',
            'contextEpoch',
          ] as const
        ).every((key) => actual[key] === source?.[key]) ||
        confirmed.data.availableContexts[0]?.participantId !== context.participantId ||
        confirmed.data.availableContexts[0]?.privacyDomainId !== context.privacyDomainId
      )
        throw new WorkflowFailure('handoff');
    };
    const resourceDigest = `sha256:${Array.from(
      new Uint8Array(
        await crypto.subtle.digest('SHA-256', new TextEncoder().encode(JSON.stringify(context))),
      ),
    )
      .map((byte) => byte.toString(16).padStart(2, '0'))
      .join('')}`;
    assertOperation();
    await qualifyContext();
    await stepUp({
      actionIntentId: 'ACT-IDENTITY_CREATE_SESSION-V1',
      actionIntentDigest: 'sha256:dbc8290dd60814d5bb4248fefc9550f43d0dc97d6333ac232c8ab8a98c3354d2',
      resourceId: context.participantId,
      resourceDigest,
    });
    assertOperation();
    await qualifyContext();
    await json(
      await fetch('/api/v1/ui/session/context', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ...context, expectedSessionId }),
      }),
    );
    assertOperation();
    token.contextSelection = undefined;
    token.selection = undefined;
    token.contextChange = true;
    await load();
    setStatus('Participant privacy context is active.');
  }
  async function prepare(event: React.FormEvent<HTMLFormElement>, revoke = false) {
    event.preventDefault();
    const input = new FormData(event.currentTarget);
    const list = (name: string) =>
      String(input.get(name) ?? '')
        .split(/[\s,]+/u)
        .filter(Boolean);
    await run(async () => {
      const next = await send<Review>(
        revoke
          ? {
              command: 'PREVIEW_REVOKE',
              resourceReservationId: String(input.get('resourceReservationId') ?? '') || undefined,
              kind:
                state?.effect && 'principalId' in state.effect.effect ? 'assignment' : 'delegation',
              grantId: state?.effect?.effect.id,
              reason: input.get('reason'),
            }
          : {
              ...(kind === 'assignment'
                ? {
                    command: 'PREVIEW_ASSIGN',
                    assignmentId: String(input.get('assignmentId') ?? '') || undefined,
                    principalId: input.get('principalId'),
                    authorityEnvelopeId: input.get('authorityEnvelopeId'),
                    ...(input.get('roleId') ? { roleId: input.get('roleId') } : {}),
                    ...(input.get('groupId') ? { groupId: input.get('groupId') } : {}),
                  }
                : {
                    command: 'PREVIEW_DELEGATE',
                    granteeId: input.get('granteeId'),
                    parentId: input.get('parentId'),
                    parentKind: input.get('parentKind'),
                  }),
              actionIntentIds: list('actions'),
              capabilityIds: input.getAll('capabilityIds'),
              resourceIds: list('resourceIds'),
              riskClasses: list('riskClasses'),
              validFrom: new Date(String(input.get('validFrom'))).toISOString(),
              validUntil: new Date(String(input.get('validUntil'))).toISOString(),
              makerCheckerRequired: input.has('makerCheckerRequired'),
              stepUpRequired: input.has('stepUpRequired'),
              onwardDelegationDepth: Number(input.get('onwardDelegationDepth')),
              resourceReservationId: String(input.get('resourceReservationId') ?? '') || undefined,
              reason: input.get('reason'),
            },
      );
      save(next);
      setStatus('Review the exact grant and its limits before requesting approval.');
    });
  }
  async function submit() {
    if (!review) return;
    const result = await send<Review & { approval: Approval }>({
      command: 'SUBMIT',
      reviewToken: review.reviewToken,
    });
    save({ ...result, approvalRequestId: result.approval.approvalRequestId.slice(-36) });
    await load();
    setStatus('The grant change is awaiting a distinct checker.');
  }
  async function approve(item: Approval) {
    await stepUp(item.stepUp);
    await send({
      command: 'APPROVE',
      approvalRequestId: item.approvalRequestId.slice(-36),
      candidateDigest: item.candidateDigest,
    });
    await load();
    setStatus('The reviewed grant change is approved.');
  }
  async function commit() {
    if (!review?.approvalRequestId) return;
    await stepUp(review.review.stepUp);
    const actor = actorRef.current;
    if (!actor) return;
    sentGrant.current = {
      id: review.review.proposedGrant.id,
      kind: review.review.kind,
      principalId: actor.principalId,
      participantId: actor.participantId,
      privacyDomainId: actor.privacyDomainId,
    };
    const result = await send<{ truthState: string; reauthenticationRequired?: boolean }>(
      {
        command: 'COMMIT',
        reviewToken: review.reviewToken,
        approvalRequestId: review.approvalRequestId,
      },
      true,
    );
    if (result.reauthenticationRequired || result.truthState === 'WRITE_AMBIGUITY') {
      if (!mounted.current) return;
      setState(undefined);
      setReauthenticate(true);
      setStatusValue(
        result.truthState === 'WRITE_AMBIGUITY'
          ? 'The response was lost. Sign in again and read the grant before retrying.'
          : 'Grant revoked, including its descendant delegations. Sign in again to read the new authority state.',
      );
      return;
    }
    await load(review.review.proposedGrant.id, undefined, review.review.kind);
    setStatus('Grant created and its durable effect read back.');
  }
  if (!session) return <p role="status">{status || 'Loading the authenticated context.'}</p>;
  if (!session.authenticated) return <LocalSessionSurface />;
  return (
    <div className="mt-6 space-y-6" onChangeCapture={() => operation.current?.controller.abort()}>
      <p aria-live="polite" role="status" className="break-words">
        {status}
      </p>
      {reauthenticate ? (
        <>
          <LocalSessionSurface />
          <button
            className={button}
            disabled={busy}
            onClick={() =>
              void run(() => {
                const original = sentGrant.current;
                return load(
                  original?.id ?? grantId,
                  undefined,
                  original?.kind ?? readKind,
                  original,
                );
              })
            }
          >
            Read grant after signing in
          </button>
        </>
      ) : null}
      {session.contextMode !== 'PARTICIPANT' &&
      !(platformHandoff && session.contextMode === 'PLATFORM') ? (
        <section className={panel}>
          <h2 className="text-xl font-semibold">Choose a working context</h2>
          <p className="my-3">Grant changes require an explicit Participant and privacy domain.</p>
          <WorkspaceEntry disabled={busy}>
            <button className={button} disabled={busy} onClick={() => void run(selectContext)}>
              Enter workspace
            </button>
          </WorkspaceEntry>
        </section>
      ) : null}
      {state ? (
        <>
          {platformHandoff && (
            <section className={panel} aria-label="Exact assignment approval">
              <label className="grid gap-1">
                Assignment approval ID
                <input
                  className={field}
                  value={approvalSelector}
                  onChange={(event) => setApprovalSelector(event.target.value)}
                />
              </label>
              <button
                className={button + ' mt-3'}
                disabled={busy || !approvalSelector}
                onClick={() => {
                  approvalSelection.current = approvalSelector;
                  void run(() => load());
                }}
              >
                Load assignment approval
              </button>
            </section>
          )}
          {platformHandoff ? (
            <section className={panel} aria-label="Prepare declared successor assignment">
              <h2 className="text-lg font-semibold">
                Prepare a declared successor administration assignment
              </h2>
              <p className="mt-2">
                Activate the declared administration envelope first. The consumed replacement
                preparation binds the exact subject, role, assignment ID, scope and expiry. Normal
                independent approval and security-key verification still apply.
              </p>
              <form
                className="mt-3 grid gap-3 md:grid-cols-2"
                onSubmit={(event) => {
                  event.preventDefault();
                  const input = new FormData(event.currentTarget);
                  void run(async () => {
                    save(
                      await send<Review>({
                        command: 'PREVIEW_PENDING_ASSIGNMENT',
                        approvalRequestId: input.get('replacementPreparationApprovalId'),
                        principalId: input.get('administratorPrincipalId'),
                        reason:
                          'Prepare the exact administration assignment declared by the approved Platform replacement.',
                      }),
                    );
                    setStatus(
                      'The declared successor assignment is ready for independent approval.',
                    );
                  });
                }}
              >
                <label className="grid gap-1">
                  Consumed replacement preparation approval ID
                  <input className={field} name="replacementPreparationApprovalId" required />
                </label>
                <label className="grid gap-1">
                  Declared administrator principal ID
                  <input className={field} name="administratorPrincipalId" required />
                </label>
                <button type="submit" className={`${button} md:col-span-2`} disabled={busy}>
                  Review declared administration assignment
                </button>
              </form>
            </section>
          ) : null}
          <GovernanceContextSummary
            title={platformHandoff ? 'Platform administration assignments' : 'Participant grants'}
            description="Review assignments and delegations within the selected workspace."
            actor={state.actor}
          >
            <button className={button} disabled={busy} onClick={() => void run(() => load())}>
              Refresh approvals
            </button>
          </GovernanceContextSummary>
          {state.actor.role === 'operator' && !platformHandoff ? (
            <section className={panel}>
              <h2 className="text-xl font-semibold">Create a grant</h2>
              <p className="mt-2 text-[color:var(--muted)]">
                Assignments grant authority from an envelope. Delegations pass a narrower grant to
                another principal. Conflicting paths cannot be admitted.
              </p>
              <label className="mt-4 grid max-w-2xl gap-1">
                New grant type
                <select
                  className={field}
                  value={kind}
                  onChange={(event) => setKind(event.target.value as GrantKind)}
                >
                  <option value="assignment">Assignment</option>
                  <option value="delegation">Delegation</option>
                </select>
              </label>
              <form
                key={kind}
                className="mt-4 grid min-w-0 max-w-2xl gap-4"
                onSubmit={(event) => void prepare(event)}
              >
                {kind === 'assignment' ? (
                  <label className="grid gap-1">
                    Planned assignment ID
                    <input className={field} name="assignmentId" />
                  </label>
                ) : null}
                <label className="grid gap-1">
                  Reserved approval operation ID
                  <input className={field} name="resourceReservationId" />
                </label>
                <GrantFields
                  kind={kind}
                  initialPrincipalId={initialPrincipalId}
                  initialAuthorityEnvelopeId={initialAuthorityEnvelopeId}
                  initialRoleId={initialRoleId}
                  initialCapabilityIds={initialCapabilityIds}
                  initialResourceIds={initialResourceIds}
                />
                <button className={button} disabled={busy} type="submit">
                  Review grant creation
                </button>
              </form>
            </section>
          ) : null}
          {review && state.actor.role === 'operator' ? (
            <section className={panel} aria-label="Grant change review">
              <h2 className="text-xl font-semibold">
                {review.review.mutation === 'CREATE' ? 'Create' : 'Revoke'} {review.review.kind} ·
                review
              </h2>
              <GrantDetails value={review.review.proposedGrant} proposed />
              <p className="mt-3">Reason: {review.review.reason}</p>
              <p>Expected revision: {review.review.expectedRevision}</p>
              <p className="break-all text-xs">Candidate: {review.review.candidateDigest}</p>
              {review.review.mutation === 'REVOKE' ? (
                <p className="mt-3">
                  Revoking this grant also revokes its descendant delegations. Existing sessions
                  must refresh their authority.
                </p>
              ) : null}
              <div className="mt-4 flex flex-wrap gap-3">
                {!review.approvalRequestId ? (
                  <button className={button} disabled={busy} onClick={() => void run(submit)}>
                    Send grant to checker
                  </button>
                ) : (
                  <p>
                    Approval:{' '}
                    {currentApproval
                      ? approvalStateLabel(currentApproval.state)
                      : 'Refresh to check'}
                  </p>
                )}
                {currentApproval?.state === 'APPROVED' ? (
                  <button className={button} disabled={busy} onClick={() => void run(commit)}>
                    Commit approved grant change
                  </button>
                ) : null}
              </div>
            </section>
          ) : null}
          <section className={panel}>
            <h2 className="text-xl font-semibold">Grant approvals</h2>
            {state.approvals.length === 0 ? (
              <p className="mt-3">
                {platformHandoff && !state.approvalsLoaded
                  ? 'Load the exact assignment approval before reviewing a decision.'
                  : 'No visible grant approvals on this page.'}
              </p>
            ) : (
              state.approvals.map((item) => (
                <article
                  key={item.approvalRequestId}
                  className="mt-4 border-t border-[color:var(--border)] pt-4"
                >
                  <h3 className="font-semibold">
                    {item.proposal.mutation === 'CREATE' ? 'Create' : 'Revoke'} {item.proposal.kind}{' '}
                    · {approvalStateLabel(item.state)}
                  </h3>
                  <GrantDetails value={item.proposal.proposedGrant} proposed />
                  <p>Expected revision: {item.proposal.expectedRevision}</p>
                  <p className="mt-2 break-all text-xs">Candidate: {item.candidateDigest}</p>
                  {item.proposal.mutation === 'REVOKE' ? (
                    <p className="my-3">
                      This change revokes the grant and its descendant delegations.
                    </p>
                  ) : null}
                  {state.actor.role === 'viewer' && item.state === 'REQUESTED' ? (
                    <button
                      className={`${button} mt-3`}
                      disabled={busy}
                      onClick={() => void run(() => approve(item))}
                    >
                      Approve {item.proposal.proposedGrant.id}
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
                Next approval page
              </button>
            ) : null}
          </section>
          <section className={panel}>
            <h2 className="text-xl font-semibold">Read a grant</h2>
            <form
              className="mt-3 grid max-w-2xl gap-3"
              onSubmit={(event) => {
                event.preventDefault();
                void run(() => load(grantId));
              }}
            >
              <label className="grid gap-1">
                Grant type to read
                <select
                  className={field}
                  value={readKind}
                  onChange={(event) => setReadKind(event.target.value as GrantKind)}
                >
                  <option value="assignment">Assignment</option>
                  <option value="delegation">Delegation</option>
                </select>
              </label>
              <label className="grid gap-1">
                Grant ID
                <input
                  className={field}
                  value={grantId}
                  onChange={(event) => setGrantId(event.target.value)}
                  required
                />
              </label>
              <button className={button} disabled={busy} type="submit">
                Find grant
              </button>
            </form>
            {state.effect ? (
              <>
                <GrantDetails value={state.effect.effect} revision={state.effect.revision} />
                <p className="mt-3 break-all text-sm">
                  Operation: {state.effect.operationId ?? 'No recorded mutation in this context'}
                </p>
                {state.actor.role === 'operator' &&
                ['ACTIVE', 'SUSPENDED'].includes(state.effect.effect.state) ? (
                  <form
                    className="mt-4 grid max-w-2xl gap-3"
                    onSubmit={(event) => void prepare(event, true)}
                  >
                    <label className="grid gap-1">
                      Revocation reason
                      <textarea
                        className={field}
                        name="reason"
                        minLength={10}
                        maxLength={1024}
                        required
                      />
                    </label>
                    <button className={button} disabled={busy} type="submit">
                      Review grant revocation
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
