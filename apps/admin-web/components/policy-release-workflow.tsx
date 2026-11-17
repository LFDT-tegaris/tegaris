'use client';

import { performWebAuthnStepUp } from '@openpc/ui-shell';
import { useCallback, useEffect, useLayoutEffect, useRef, useState } from 'react';
import { z } from 'zod';
import Link from 'next/link';

import { LocalSessionSurface } from './local-session';
import { WorkspaceEntry } from './workspace-entry';
import { WorkspaceStatus } from './workspace-status';
import { WorkflowDetails } from './workflow-details';
import { GovernanceContextSummary } from './governance-context-summary';
import { TransactionWorkflow } from './transaction-workflow';
import { PolicyOccurrenceStage } from './policy-occurrence-stage';
import { AdministrationNamesWorkflow } from './administration-names-workflow';
import {
  clearPolicyWorkflowStorage,
  policyAuthorStorageKey,
  policyReleaseStorageKey,
  readBoundPolicyState,
  writeBoundPolicyState,
  type PolicyWorkflowActorBinding,
} from './policy-workflow-storage';

const contextAction = {
  actionIntentId: 'ACT-IDENTITY_CREATE_SESSION-V1',
  actionIntentDigest: 'sha256:dbc8290dd60814d5bb4248fefc9550f43d0dc97d6333ac232c8ab8a98c3354d2',
  stepUp: 'FRESH_WEBAUTHN_MAX_5M' as const,
};
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const digestPattern = /^sha256:[0-9a-f]{64}$/u;

interface SessionState {
  readonly enabled?: boolean;
  readonly authenticated?: boolean;
  readonly role?: 'operator' | 'viewer';
  readonly sessionId?: string;
  readonly principalId?: string;
  readonly participantId?: string;
  readonly privacyDomainId?: string;
  readonly contextMode?: 'PLATFORM' | 'PARTICIPANT';
  readonly contextEpoch?: string;
  readonly availableContexts?: readonly {
    readonly participantId: string;
    readonly privacyDomainId: string;
  }[];
}

interface ResourceState {
  readonly state: string;
  readonly revision: string;
}

interface StepUpBinding {
  readonly actionIntentId: string;
  readonly actionIntentDigest: string;
  readonly resourceId: string;
  readonly resourceDigest: string;
}

interface WorkbenchState {
  readonly actor: {
    readonly role: 'operator' | 'viewer';
    readonly sessionId: string;
    readonly principalId: string;
    readonly participantId: string;
    readonly privacyDomainId: string;
    readonly contextEpoch: string;
  };
  readonly approval?: ResourceState & {
    readonly approvalRequestId: string;
    readonly candidateDigest: string;
  };
  readonly release?: ResourceState & {
    readonly releaseBundleId: string;
    readonly manifestDigest: string;
  };
  readonly occurrence?: ResourceState & {
    readonly activationOccurrenceId: string;
    readonly releaseBundleId: string;
  };
  readonly approvalStepUp?: StepUpBinding;
  readonly publishStepUp?: StepUpBinding;
  readonly occurrenceStepUp?: StepUpBinding;
}

interface ReviewState {
  readonly reviewToken: string;
  readonly review: {
    readonly policyVersionId: string;
    readonly checkerPrincipalId: string;
    readonly manifestDigest: string;
    readonly dependencyClosureDigest: string;
    readonly reason: string;
  };
}

interface SavedState {
  readonly review?: ReviewState;
  readonly approvalId?: string;
  readonly releaseId?: string;
  readonly occurrenceId?: string;
}

interface AuthoringCandidate {
  readonly policyVersionId?: string;
  readonly normalizedPolicyDigest?: string;
  readonly dependencyClosureDigest?: string;
}

interface OperationResponse {
  readonly resourceRef?: string;
  readonly truthState?: string;
  readonly reconciliation?: string;
}

const uuid = z.uuid();
const sessionReadSchema = z
  .object({
    enabled: z.boolean().optional(),
    authenticated: z.boolean(),
    role: z.enum(['operator', 'viewer']).optional(),
    sessionId: uuid.optional(),
    principalId: uuid.optional(),
    participantId: uuid.optional(),
    privacyDomainId: uuid.optional(),
    contextMode: z.enum(['PLATFORM', 'PARTICIPANT']).optional(),
    contextEpoch: z
      .string()
      .regex(/^(?:0|[1-9][0-9]*)$/u)
      .optional(),
    availableContexts: z
      .array(z.object({ participantId: uuid, privacyDomainId: uuid }).passthrough())
      .optional(),
  })
  .passthrough()
  .refine(
    (value) =>
      !value.authenticated ||
      (value.role !== undefined &&
        value.contextMode !== undefined &&
        (value.contextMode !== 'PARTICIPANT' ||
          [
            value.sessionId,
            value.principalId,
            value.participantId,
            value.privacyDomainId,
            value.contextEpoch,
          ].every((field) => field !== undefined))),
  );
const resourceReadSchema = z
  .object({ state: z.string().min(1), revision: z.string().min(1) })
  .passthrough();
const stepUpReadSchema = z
  .object({
    actionIntentId: z.string().min(1),
    actionIntentDigest: z.string().regex(digestPattern),
    resourceId: uuid,
    resourceDigest: z.string().regex(digestPattern),
  })
  .passthrough();
const workbenchReadSchema = z
  .object({
    actor: z
      .object({
        role: z.enum(['operator', 'viewer']),
        sessionId: uuid,
        principalId: uuid,
        participantId: uuid,
        privacyDomainId: uuid,
        contextEpoch: z.string().regex(/^(?:0|[1-9][0-9]*)$/u),
      })
      .passthrough(),
    approval: resourceReadSchema
      .extend({ approvalRequestId: z.string(), candidateDigest: z.string().regex(digestPattern) })
      .optional(),
    release: resourceReadSchema
      .extend({ releaseBundleId: z.string(), manifestDigest: z.string().regex(digestPattern) })
      .optional(),
    occurrence: resourceReadSchema
      .extend({ activationOccurrenceId: z.string(), releaseBundleId: z.string() })
      .optional(),
    approvalStepUp: stepUpReadSchema.optional(),
    publishStepUp: stepUpReadSchema.optional(),
    occurrenceStepUp: stepUpReadSchema.optional(),
  })
  .passthrough();
function selectorsMatch(left: SavedState, right: SavedState) {
  return (
    left.approvalId === right.approvalId &&
    left.releaseId === right.releaseId &&
    left.occurrenceId === right.occurrenceId
  );
}
function workbenchMatches(state: WorkbenchState, selected: SavedState) {
  const resources = [
    [selected.approvalId, state.approval?.approvalRequestId, state.approvalStepUp],
    [selected.releaseId, state.release?.releaseBundleId, state.publishStepUp],
    [selected.occurrenceId, state.occurrence?.activationOccurrenceId, state.occurrenceStepUp],
  ] as const;
  return resources.every(
    ([id, ref, step]) =>
      (id ? ref === `urn:openpc:resource:${id}` : ref === undefined) &&
      (!step || (id !== undefined && step.resourceId === id)),
  );
}
type ReadAttempt = { revision: number; controller: AbortController; background: boolean };
class MutationResponseLost extends Error {}

const failureMessages = {
  unavailable: 'The policy owner is unavailable. Refresh before continuing.',
  authorization:
    'Policy request was not authorized. Refresh the authenticated context before continuing.',
  conflict: 'Policy state changed. Refresh or read the original operation before retrying.',
  input: 'Policy request was rejected. Check the inputs before continuing.',
  context: 'The authenticated context response is unavailable. Refresh before continuing.',
  workbench: 'The policy workflow response is unavailable. Refresh before continuing.',
  actor: 'The policy workflow does not match the current context.',
  selection: 'The policy workflow does not match the selected references.',
  noContext: 'No server-authorized Participant context is available.',
  approvalId: 'The approval owner did not return a resource identifier.',
  releaseId: 'The release owner did not return a resource identifier.',
  occurrenceId: 'The activation owner did not return a resource identifier.',
  mutationLost: 'The mutation response was not received.',
} as const;
class WorkflowFailure extends Error {
  constructor(readonly kind: keyof typeof failureMessages) {
    super(failureMessages[kind]);
  }
}
function failureMessage(error: unknown) {
  if (error instanceof MutationResponseLost) return failureMessages.mutationLost;
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
  const body = await response.json().catch(() => undefined);
  if (!response.ok) throw httpFailure(response.status);
  if (body === undefined) throw new WorkflowFailure('unavailable');
  return body as T;
}

async function sendCommand<T>(body: unknown): Promise<T> {
  let response: Response;
  try {
    response = await fetch('/api/v1/ui/policy-release-workbench', {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
  } catch {
    throw new MutationResponseLost('The mutation response was not received.');
  }
  return json<T>(response);
}

function resourceId(value: string | undefined): string | undefined {
  return value?.slice(value.lastIndexOf(':') + 1);
}

function actorBinding(session: SessionState): PolicyWorkflowActorBinding | undefined {
  if (
    !session.authenticated ||
    session.contextMode !== 'PARTICIPANT' ||
    !['sessionId', 'principalId', 'participantId', 'privacyDomainId', 'contextEpoch'].every(
      (field) =>
        typeof session[field as keyof SessionState] === 'string' &&
        String(session[field as keyof SessionState]).length > 0,
    )
  )
    return undefined;
  return {
    sessionId: session.sessionId!,
    principalId: session.principalId!,
    participantId: session.participantId!,
    privacyDomainId: session.privacyDomainId!,
    contextEpoch: session.contextEpoch!,
  };
}

function savedState(value: unknown): value is SavedState {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const saved = value as Record<string, unknown>;
  if (
    ['approvalId', 'releaseId', 'occurrenceId'].some(
      (field) => saved[field] !== undefined && !uuidPattern.test(String(saved[field])),
    )
  )
    return false;
  if (saved.review === undefined) return true;
  if (!saved.review || typeof saved.review !== 'object' || Array.isArray(saved.review))
    return false;
  const review = saved.review as Record<string, unknown>;
  const details = review.review;
  return (
    typeof review.reviewToken === 'string' &&
    review.reviewToken.length >= 80 &&
    !!details &&
    typeof details === 'object' &&
    !Array.isArray(details) &&
    uuidPattern.test(String((details as Record<string, unknown>).policyVersionId)) &&
    uuidPattern.test(String((details as Record<string, unknown>).checkerPrincipalId)) &&
    digestPattern.test(String((details as Record<string, unknown>).manifestDigest)) &&
    digestPattern.test(String((details as Record<string, unknown>).dependencyClosureDigest)) &&
    typeof (details as Record<string, unknown>).reason === 'string'
  );
}

function authoringCandidateState(value: unknown): value is AuthoringCandidate {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const candidate = value as Record<string, unknown>;
  return (
    (candidate.policyVersionId === undefined ||
      uuidPattern.test(String(candidate.policyVersionId))) &&
    (candidate.normalizedPolicyDigest === undefined ||
      digestPattern.test(String(candidate.normalizedPolicyDigest))) &&
    (candidate.dependencyClosureDigest === undefined ||
      digestPattern.test(String(candidate.dependencyClosureDigest)))
  );
}

function actorKey(actor: PolicyWorkflowActorBinding): string {
  return [
    actor.sessionId,
    actor.principalId,
    actor.participantId,
    actor.privacyDomainId,
    actor.contextEpoch,
  ].join(':');
}

function StateBadge({ children }: Readonly<{ children: string }>) {
  return (
    <strong className="inline-flex rounded-full border border-[color:var(--border)] px-2 py-1 text-xs">
      {children.replaceAll('_', ' ')}
    </strong>
  );
}

export function PolicyReleaseWorkflow({
  showSessionControls = true,
  evaluationUi = false,
  activeTask = 'releases',
}: {
  readonly showSessionControls?: boolean;
  readonly evaluationUi?: boolean;
  readonly activeTask?: 'releases' | 'activation-renewal';
} = {}) {
  const renewalSelected = evaluationUi && activeTask === 'activation-renewal';
  const [workflow, setWorkflow] = useState<'PREPARE' | 'REVIEW'>('PREPARE');
  const [session, setSession] = useState<SessionState>();
  const [saved, setSaved] = useState<SavedState>({});
  const [state, setState] = useState<WorkbenchState>();
  const [authoringCandidate, setAuthoringCandidate] = useState<AuthoringCandidate>({});
  const [status, setStatusValue] = useState('');
  const [busy, setBusy] = useState(false);
  const actorRef = useRef<PolicyWorkflowActorBinding | undefined>(undefined);
  const loadRevisionRef = useRef(0);
  const readRef = useRef<ReadAttempt | undefined>(undefined);
  const mountedRef = useRef(false);
  const busyRef = useRef(false);
  const [readError, setReadError] = useState('');
  const [reading, setReading] = useState(true);
  const [loadedIdentifiers, setLoadedIdentifiers] = useState<SavedState>({});
  const [childActor, setChildActor] = useState<PolicyWorkflowActorBinding>();
  const selectionRef = useRef('');
  const mutationRef = useRef<
    | {
        controller: AbortController;
        actor: string;
        selection?: string;
        contextChange?: boolean;
        sent: boolean;
      }
    | undefined
  >(undefined);
  function mutationIsCurrent(token: NonNullable<typeof mutationRef.current>) {
    return (
      mountedRef.current &&
      mutationRef.current === token &&
      !token.controller.signal.aborted &&
      (token.contextChange || token.actor === JSON.stringify(actorRef.current)) &&
      (token.selection === undefined || token.selection === selectionRef.current)
    );
  }
  function assertMutation() {
    const token = mutationRef.current;
    if (!token || !mutationIsCurrent(token))
      throw new DOMException('The operation was cancelled.', 'AbortError');
    return token;
  }
  function startMutation(): NonNullable<typeof mutationRef.current> | undefined {
    if (!mountedRef.current || busyRef.current) return undefined;
    const token = {
      controller: new AbortController(),
      actor: JSON.stringify(actorRef.current),
      selection: selectionRef.current,
      sent: false,
    };
    mutationRef.current = token;
    setWorking(true);
    return token;
  }
  function finishMutation(token: NonNullable<typeof mutationRef.current>) {
    if (mutationRef.current !== token) return;
    mutationRef.current = undefined;
    if (mountedRef.current) setWorking(false);
  }
  function setStatus(value: string) {
    if (mountedRef.current && (!mutationRef.current || mutationIsCurrent(mutationRef.current)))
      setStatusValue(value);
  }
  async function command<T>(body: unknown, retainSentReadback = false): Promise<T> {
    const token = assertMutation();
    token.sent = true;
    const result = await sendCommand<T>(body);
    if (
      retainSentReadback &&
      mountedRef.current &&
      mutationRef.current === token &&
      token.actor === JSON.stringify(actorRef.current)
    ) {
      token.selection = undefined;
      return result;
    }
    assertMutation();
    token.selection = undefined;
    return result;
  }
  useLayoutEffect(() => {
    selectionRef.current = JSON.stringify([session, state, saved]);
    if (mutationRef.current && !mutationIsCurrent(mutationRef.current))
      mutationRef.current.controller.abort();
  });
  useLayoutEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
      mutationRef.current?.controller.abort();
      loadRevisionRef.current++;
      readRef.current?.controller.abort();
    };
  }, []);
  function setWorking(value: boolean) {
    if (value && readRef.current?.background) {
      loadRevisionRef.current++;
      readRef.current.controller.abort();
    }
    busyRef.current = value;
    setBusy(value);
  }

  const load = useCallback(
    async (known?: SavedState, background = false): Promise<boolean> => {
      if (!mountedRef.current || (background && busyRef.current)) return false;
      readRef.current?.controller.abort();
      const attempt: ReadAttempt = {
        revision: ++loadRevisionRef.current,
        controller: new AbortController(),
        background,
      };
      readRef.current = attempt;
      const current = () =>
        mountedRef.current &&
        loadRevisionRef.current === attempt.revision &&
        !attempt.controller.signal.aborted;
      const readJson = async (url: string) => {
        const response = await fetch(url, {
          credentials: 'same-origin',
          cache: 'no-store',
          signal: attempt.controller.signal,
        });
        if (!current()) return undefined;
        const body = await json<unknown>(response);
        if (!current()) return undefined;
        return body;
      };
      setReadError('');
      if (!background) {
        setReading(true);
        setState(undefined);
      }
      let sessionKnown = false;
      try {
        const parsedSession = sessionReadSchema.safeParse(
          await readJson('/api/v1/ui/local-session'),
        );
        if (!current()) return false;
        if (!parsedSession.success) throw new WorkflowFailure('context');
        const currentSession = parsedSession.data;
        sessionKnown = true;
        setSession(currentSession);
        const actor = actorBinding(currentSession);
        if (!actor) {
          actorRef.current = undefined;
          setSaved({});
          setState(undefined);
          setAuthoringCandidate({});
          clearPolicyWorkflowStorage();
          return true;
        }
        const priorActor = actorRef.current;
        const actorChanged = !priorActor || actorKey(priorActor) !== actorKey(actor);
        actorRef.current = actor;
        const identifiers = actorChanged
          ? (readBoundPolicyState(policyReleaseStorageKey, actor, savedState) ?? {})
          : (known ?? saved);
        if (actorChanged) {
          setWorkflow(currentSession.role === 'operator' ? 'PREPARE' : 'REVIEW');
          setSaved(identifiers);
          setState(undefined);
          setAuthoringCandidate(
            readBoundPolicyState(policyAuthorStorageKey, actor, authoringCandidateState) ?? {},
          );
        }
        const query = new URLSearchParams();
        if (identifiers.approvalId) query.set('approvalId', identifiers.approvalId);
        if (identifiers.releaseId) query.set('releaseId', identifiers.releaseId);
        if (identifiers.occurrenceId) query.set('occurrenceId', identifiers.occurrenceId);
        const parsedState = workbenchReadSchema.safeParse(
          await readJson(
            `/api/v1/ui/policy-release-workbench${query.size > 0 ? `?${query.toString()}` : ''}`,
          ),
        );
        if (!current()) return false;
        if (!parsedState.success) throw new WorkflowFailure('workbench');
        const nextState = parsedState.data;
        if (
          actorRef.current === undefined ||
          actorKey(actorRef.current) !== actorKey(actor) ||
          actorKey(nextState.actor) !== actorKey(actor)
        )
          throw new WorkflowFailure('actor');
        if (!workbenchMatches(nextState, identifiers)) throw new WorkflowFailure('selection');
        setLoadedIdentifiers({
          approvalId: identifiers.approvalId,
          releaseId: identifiers.releaseId,
          occurrenceId: identifiers.occurrenceId,
        });
        setState(nextState);
        setChildActor((original) => original ?? actor);
        return true;
      } catch (cause) {
        if (!current()) return false;
        setState(undefined);
        if (!sessionKnown) setSession(undefined);
        const message = failureMessage(cause);
        setReadError(message);
        throw cause instanceof WorkflowFailure ? cause : new WorkflowFailure('unavailable');
      } finally {
        if (!background && current()) setReading(false);
      }
    },
    [saved],
  );

  useEffect(() => {
    void load().catch(() => {
      /* load retains a safe, current-generation read error. */
    });
  }, []); // Restore only after authoritative actor/context reconciliation.

  useEffect(() => {
    if (
      busy ||
      !saved.occurrenceId ||
      !state?.occurrence ||
      ['ACTIVE_MATCHED', 'ROLLED_BACK', 'FAILED'].includes(state.occurrence.state)
    )
      return;
    const timer = window.setInterval(() => {
      void load(saved, true).catch(() => {
        /* The current failure is retained in readError. */
      });
    }, 1_500);
    return () => window.clearInterval(timer);
  }, [busy, load, saved, state?.occurrence]);

  async function refresh() {
    if (busyRef.current || !mountedRef.current) return;
    setWorking(true);
    const revision = loadRevisionRef.current + 1;
    try {
      await load(saved);
    } catch {
      /* load keeps the current safe read error and original selectors. */
    } finally {
      if (mountedRef.current && loadRevisionRef.current === revision) setWorking(false);
    }
  }

  function actorIsCurrent(expected: PolicyWorkflowActorBinding): boolean {
    return (
      mountedRef.current &&
      actorRef.current !== undefined &&
      actorKey(actorRef.current) === actorKey(expected)
    );
  }

  function save(next: SavedState, expected: PolicyWorkflowActorBinding) {
    if (
      !actorIsCurrent(expected) ||
      (mutationRef.current && !mutationIsCurrent(mutationRef.current))
    )
      return false;
    setSaved(next);
    writeBoundPolicyState(policyReleaseStorageKey, expected, next);
    return true;
  }

  async function selectContext() {
    const token = startMutation();
    if (!token) return;
    setStatus('Confirming the local Participant privacy context.');
    try {
      const available = session?.availableContexts?.[0];
      if (!available) throw new WorkflowFailure('noContext');
      const expectedSessionId = session?.sessionId;
      if (!expectedSessionId || !uuidPattern.test(expectedSessionId))
        throw new WorkflowFailure('context');
      const context = {
        participantId: available.participantId,
        privacyDomainId: available.privacyDomainId,
      };
      const resourceDigest = `sha256:${Array.from(
        new Uint8Array(
          await crypto.subtle.digest('SHA-256', new TextEncoder().encode(JSON.stringify(context))),
        ),
      )
        .map((byte) => byte.toString(16).padStart(2, '0'))
        .join('')}`;
      assertMutation();
      await performWebAuthnStepUp(
        contextAction,
        {
          resourceId: context.participantId,
          resourceDigest,
        },
        { signal: token.controller.signal, isCurrent: () => mutationIsCurrent(token) },
      );
      assertMutation();
      token.sent = true;
      await json(
        await fetch('/api/v1/ui/session/context', {
          method: 'POST',
          credentials: 'same-origin',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ ...context, expectedSessionId }),
        }),
      );
      assertMutation();
      token.selection = undefined;
      token.contextChange = true;
      clearPolicyWorkflowStorage();
      actorRef.current = undefined;
      await load();
      setStatus('Participant privacy context is active.');
    } catch (error) {
      setStatus(failureMessage(error));
    } finally {
      finishMutation(token);
    }
  }

  async function preview(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const actor = actorRef.current;
    if (!actor) return;
    const token = startMutation();
    if (!token) return;
    try {
      const data = new FormData(event.currentTarget);
      const review = await command<ReviewState>({
        command: 'PREVIEW',
        policyVersionId: data.get('policyVersionId'),
        checkerPrincipalId: data.get('checkerPrincipalId'),
        manifestDigest: data.get('manifestDigest'),
        dependencyClosureDigest: data.get('dependencyClosureDigest'),
        reason: data.get('reason'),
      });
      if (!actorIsCurrent(actor)) return;
      const next = { ...saved, review };
      save(next, actor);
      setStatus('Review locked. Verify the artifact and reason before requesting approval.');
    } catch (error) {
      setStatus(failureMessage(error));
    } finally {
      finishMutation(token);
    }
  }

  async function submitApproval() {
    if (!saved.review) return;
    const actor = actorRef.current;
    if (!actor) return;
    const token = startMutation();
    if (!token) return;
    try {
      const operation = await command<OperationResponse>({
        command: 'SUBMIT_APPROVAL',
        reviewToken: saved.review.reviewToken,
      });
      if (!actorIsCurrent(actor)) return;
      const approvalId = resourceId(operation.resourceRef);
      if (!approvalId) throw new WorkflowFailure('approvalId');
      const next = { ...saved, approvalId };
      save(next, actor);
      await load(next);
      setStatus('Approval requested from the distinct checker.');
    } catch (error) {
      setStatus(failureMessage(error));
    } finally {
      finishMutation(token);
    }
  }

  async function createRelease() {
    if (!saved.review || state?.approval?.state !== 'APPROVED') return;
    const actor = actorRef.current;
    if (!actor) return;
    const token = startMutation();
    if (!token) return;
    try {
      const operation = await command<OperationResponse>({
        command: 'CREATE_RELEASE',
        reviewToken: saved.review.reviewToken,
      });
      if (!actorIsCurrent(actor)) return;
      const releaseId = resourceId(operation.resourceRef);
      if (!releaseId) throw new WorkflowFailure('releaseId');
      const next = { ...saved, releaseId };
      save(next, actor);
      await load(next);
      setStatus('Draft release created from the exact approved artifact.');
    } catch (error) {
      setStatus(failureMessage(error));
    } finally {
      finishMutation(token);
    }
  }

  async function createOccurrence() {
    if (!saved.review || !saved.releaseId || state?.release?.state !== 'PUBLISHED') return;
    const actor = actorRef.current;
    if (!actor) return;
    const token = startMutation();
    if (!token) return;
    try {
      const operation = await command<OperationResponse>({
        command: 'CREATE_OCCURRENCE',
        reviewToken: saved.review.reviewToken,
        releaseId: saved.releaseId,
      });
      if (!actorIsCurrent(actor)) return;
      const occurrenceId = resourceId(operation.resourceRef);
      if (!occurrenceId) throw new WorkflowFailure('occurrenceId');
      const next = { ...saved, occurrenceId };
      save(next, actor);
      await load(next);
      setStatus(
        'Activation staged for the reviewed targets. Check runtime status before using the policy.',
      );
    } catch (error) {
      setStatus(failureMessage(error));
    } finally {
      finishMutation(token);
    }
  }

  async function checkerCommand(
    commandName: 'APPROVE' | 'PUBLISH' | 'ACTIVATE' | 'ROLLBACK' | 'RECOVER' | 'RETIRE',
    binding: StepUpBinding | undefined,
    identifier: string | undefined,
  ) {
    if (!identifier || (commandName !== 'RETIRE' && !binding)) return;
    const actor = actorRef.current;
    if (!actor) return;
    const originalSaved = saved;
    const token = startMutation();
    if (!token) return;
    setStatus(`Confirming ${commandName.toLowerCase()} for the exact reviewed resource.`);
    try {
      if (binding) {
        await performWebAuthnStepUp(
          { ...binding, stepUp: 'FRESH_WEBAUTHN_MAX_5M' },
          { resourceId: binding.resourceId, resourceDigest: binding.resourceDigest },
          { signal: token.controller.signal, isCurrent: () => mutationIsCurrent(token) },
        );
      }
      assertMutation();
      if (!actorIsCurrent(actor)) return;
      const body =
        commandName === 'APPROVE'
          ? { command: commandName, approvalId: identifier }
          : commandName === 'PUBLISH' || commandName === 'RETIRE'
            ? { command: commandName, releaseId: identifier }
            : { command: commandName, occurrenceId: identifier };
      await command<OperationResponse>(body, commandName === 'ACTIVATE');
      if (!actorIsCurrent(actor)) return;
      await load(saved);
      setStatus(`${commandName[0]}${commandName.slice(1).toLowerCase()} accepted by the owner.`);
    } catch (error) {
      if (
        commandName === 'ACTIVATE' &&
        error instanceof MutationResponseLost &&
        token.sent &&
        mountedRef.current &&
        mutationRef.current === token &&
        actorIsCurrent(actor)
      ) {
        setStatus(
          'The activation response was lost. Checking the original operation before continuing.',
        );
        await load(originalSaved).catch(() => undefined);
      } else {
        setStatus(failureMessage(error));
      }
    } finally {
      finishMutation(token);
    }
  }

  async function loadIdentifiers(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!mountedRef.current || busyRef.current) return;
    const actor = actorRef.current;
    if (!actor) return;
    const data = new FormData(event.currentTarget);
    const next = {
      ...saved,
      approvalId: String(data.get('approvalId') || '') || undefined,
      releaseId: String(data.get('releaseId') || '') || undefined,
      occurrenceId: String(data.get('occurrenceId') || '') || undefined,
    };
    if (
      [next.approvalId, next.releaseId, next.occurrenceId].some(
        (id) => id !== undefined && !uuid.safeParse(id).success,
      )
    ) {
      setReadError('Enter exact UUID references before reading policy state.');
      return;
    }
    if (!save(next, actor)) return;
    setWorking(true);
    const revision = loadRevisionRef.current + 1;
    try {
      if (!(await load(next)) || loadRevisionRef.current !== revision) return;
      setStatus('Authoritative workflow state loaded.');
    } catch (error) {
      if (mountedRef.current && loadRevisionRef.current === revision)
        setStatus(failureMessage(error));
    } finally {
      if (mountedRef.current && loadRevisionRef.current === revision) setWorking(false);
    }
  }

  const currentActor = session && actorBinding(session);
  const displayState =
    state &&
    currentActor &&
    actorKey(state.actor) === actorKey(currentActor) &&
    selectorsMatch(saved, loadedIdentifiers)
      ? state
      : undefined;
  const childVisible =
    displayState && childActor && actorKey(childActor) === actorKey(displayState.actor);
  const selectorForm = (
    <form
      key={displayState ? 'verified' : 'unavailable'}
      className="mt-4 grid gap-3 lg:grid-cols-3"
      onSubmit={(event) => void loadIdentifiers(event)}
    >
      <label className="grid gap-1">
        Approval ID
        <input
          className="rounded border p-2 font-mono"
          defaultValue={displayState ? saved.approvalId : undefined}
          name="approvalId"
        />
      </label>
      <label className="grid gap-1">
        Release ID
        <input
          className="rounded border p-2 font-mono"
          defaultValue={displayState ? saved.releaseId : undefined}
          name="releaseId"
        />
      </label>
      <label className="grid gap-1">
        Activation ID
        <input
          className="rounded border p-2 font-mono"
          defaultValue={displayState ? saved.occurrenceId : undefined}
          name="occurrenceId"
        />
      </label>
      <button
        className="w-fit rounded bg-[color:var(--accent)] px-3 py-2 font-medium text-white disabled:opacity-60"
        disabled={busy}
        type="submit"
      >
        Load policy workflow
      </button>
    </form>
  );
  return (
    <div
      className="mt-6 space-y-6"
      aria-busy={reading}
      onChangeCapture={() => mutationRef.current?.controller.abort()}
    >
      {evaluationUi && (
        <nav className="feature-navigation" aria-label="Policy tasks">
          <Link href="/govern/policy-releases" aria-current={!renewalSelected ? 'page' : undefined}>
            Releases &amp; approvals
          </Link>
          <Link
            href="/govern/policy-releases?view=activation-renewal"
            aria-current={renewalSelected ? 'page' : undefined}
          >
            Activation renewal
          </Link>
        </nav>
      )}
      <div className="space-y-6">
        {!session ? (
          <WorkspaceStatus
            state={reading ? 'LOADING' : 'UNAVAILABLE'}
            detail={
              reading
                ? 'Checking your account and workspace access…'
                : 'Your account context could not be loaded. Refresh the workflow to try again.'
            }
          />
        ) : !session.authenticated ? (
          showSessionControls ? (
            <LocalSessionSurface />
          ) : (
            <p>
              Open <Link href="/home/session">Account &amp; workspace</Link> to sign in or check
              your working context.
            </p>
          )
        ) : session.contextMode !== 'PARTICIPANT' ? (
          <section className="mt-6 rounded border border-[color:var(--warning)] bg-[color:var(--surface)] p-4">
            <h2 className="text-xl font-semibold">Choose a working context</h2>
            <p className="mt-2 text-[color:var(--muted)]">
              Policy release requires an explicit Participant and privacy-domain context.
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
          </section>
        ) : !displayState ? (
          reading ? (
            <WorkspaceStatus state="LOADING" detail="Loading approvals and release details…" />
          ) : (
            <p>The policy workflow could not be loaded. Try refreshing it.</p>
          )
        ) : (
          <>
            {evaluationUi ? (
              <GovernanceContextSummary
                title="Policy workspace"
                description="Prepare releases, review approvals and track publication and activation separately."
                actor={displayState.actor}
                includePrincipal
              />
            ) : (
              <section
                aria-label="Current policy context"
                className="rounded border border-[color:var(--border)] bg-[color:var(--surface)] p-4"
              >
                <h2 className="text-lg font-semibold">Policy context</h2>
                <dl className="mt-3 grid gap-3 text-sm sm:grid-cols-2 lg:grid-cols-4">
                  <div>
                    <dt className="font-medium">Principal</dt>
                    <dd className="break-all text-[color:var(--muted)]">
                      {displayState.actor.principalId}
                    </dd>
                  </div>
                  <div>
                    <dt className="font-medium">Participant</dt>
                    <dd className="break-all text-[color:var(--muted)]">
                      {displayState.actor.participantId}
                    </dd>
                  </div>
                  <div>
                    <dt className="font-medium">Privacy domain</dt>
                    <dd className="break-all text-[color:var(--muted)]">
                      {displayState.actor.privacyDomainId}
                    </dd>
                  </div>
                  <div>
                    <dt className="font-medium">Context generation</dt>
                    <dd className="text-[color:var(--muted)]">{displayState.actor.contextEpoch}</dd>
                  </div>
                </dl>
              </section>
            )}

            <div hidden={renewalSelected} className="space-y-6">
              <label className="grid max-w-md gap-1 font-medium">
                Workflow
                <select
                  className="min-w-0 rounded border p-2"
                  value={workflow}
                  onChange={(event) => setWorkflow(event.target.value as typeof workflow)}
                >
                  <option value="PREPARE">Prepare a release</option>
                  <option value="REVIEW">Review and control authority</option>
                </select>
              </label>
              {workflow === 'PREPARE' ? (
                <section
                  aria-labelledby="policy-release-maker"
                  className="rounded border border-[color:var(--border)] bg-[color:var(--surface)] p-4"
                >
                  <h2 className="text-xl font-semibold" id="policy-release-maker">
                    Prepare the release candidate
                  </h2>
                  {!saved.review ? (
                    <form
                      className="mt-4 grid max-w-3xl gap-4"
                      onSubmit={(event) => void preview(event)}
                    >
                      <label className="grid gap-1">
                        Policy version ID
                        <input
                          className="rounded border p-2 font-mono"
                          defaultValue={authoringCandidate.policyVersionId}
                          name="policyVersionId"
                          required
                        />
                      </label>
                      <label className="grid gap-1">
                        Policy artifact digest
                        <input
                          className="rounded border p-2 font-mono"
                          defaultValue={authoringCandidate.normalizedPolicyDigest}
                          name="manifestDigest"
                          pattern="sha256:[0-9a-f]{64}"
                          placeholder="sha256:…"
                          required
                        />
                      </label>
                      <label className="grid gap-1">
                        Dependency closure digest
                        <input
                          className="rounded border p-2 font-mono"
                          defaultValue={authoringCandidate.dependencyClosureDigest}
                          name="dependencyClosureDigest"
                          pattern="sha256:[0-9a-f]{64}"
                          placeholder="sha256:…"
                          required
                        />
                      </label>
                      <label className="grid gap-1">
                        Checker principal ID
                        <input
                          className="min-w-0 rounded border p-2 font-mono"
                          name="checkerPrincipalId"
                          required
                          pattern="[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"
                        />
                      </label>
                      <label className="grid gap-1">
                        Business reason
                        <textarea
                          className="min-h-24 rounded border p-2"
                          minLength={10}
                          name="reason"
                          required
                        />
                      </label>
                      <button
                        className="w-fit rounded bg-[color:var(--accent)] px-3 py-2 font-medium text-white"
                        disabled={busy}
                        type="submit"
                      >
                        Review release details
                      </button>
                    </form>
                  ) : (
                    <div className="mt-4 space-y-4">
                      <h3 className="font-semibold">Release review</h3>
                      <p>{saved.review.review.reason}</p>
                      <dl className="grid gap-3 text-sm sm:grid-cols-2">
                        <div>
                          <dt className="font-medium">Policy version</dt>
                          <dd className="break-all">{saved.review.review.policyVersionId}</dd>
                        </div>
                        <div>
                          <dt className="font-medium">Checker principal</dt>
                          <dd className="break-all">{saved.review.review.checkerPrincipalId}</dd>
                        </div>
                        <div>
                          <dt className="font-medium">Artifact fingerprint</dt>
                          <dd className="break-all font-mono text-xs">
                            {saved.review.review.manifestDigest}
                          </dd>
                        </div>
                      </dl>
                      {!saved.approvalId ? (
                        <button
                          className="rounded bg-[color:var(--accent)] px-3 py-2 font-medium text-white"
                          disabled={busy}
                          onClick={() => void submitApproval()}
                          type="button"
                        >
                          Request checker approval
                        </button>
                      ) : null}
                      {displayState.approval ? (
                        <p>
                          Approval: <StateBadge>{displayState.approval.state}</StateBadge>
                        </p>
                      ) : null}
                      {displayState.approval?.state === 'APPROVED' && !saved.releaseId ? (
                        <button
                          className="rounded bg-[color:var(--accent)] px-3 py-2 font-medium text-white"
                          disabled={busy}
                          onClick={() => void createRelease()}
                          type="button"
                        >
                          Create approved release
                        </button>
                      ) : null}
                      {displayState.release ? (
                        <p>
                          Release: <StateBadge>{displayState.release.state}</StateBadge>
                        </p>
                      ) : null}
                      {displayState.release?.state === 'PUBLISHED' && !saved.occurrenceId ? (
                        <button
                          className="rounded bg-[color:var(--accent)] px-3 py-2 font-medium text-white"
                          disabled={busy}
                          onClick={() => void createOccurrence()}
                          type="button"
                        >
                          Stage target activation
                        </button>
                      ) : null}
                      {displayState.occurrence ? (
                        <p>
                          Activation: <StateBadge>{displayState.occurrence.state}</StateBadge>
                        </p>
                      ) : null}
                      {saved.approvalId ? (
                        <button
                          className="rounded border border-[color:var(--border)] px-3 py-2 font-medium disabled:opacity-60"
                          disabled={busy}
                          onClick={() => void refresh()}
                          type="button"
                        >
                          Refresh policy workflow
                        </button>
                      ) : null}
                    </div>
                  )}
                </section>
              ) : (
                <section
                  aria-labelledby="policy-release-checker"
                  className="rounded border border-[color:var(--border)] bg-[color:var(--surface)] p-4"
                >
                  <h2 className="text-xl font-semibold" id="policy-release-checker">
                    Review and control policy authority
                  </h2>
                  <p className="mt-2 text-[color:var(--muted)]">
                    Load the references supplied by the maker. Every consequential transition is
                    bound to the exact current revision and confirmed with your security key.
                  </p>
                  {selectorForm}
                  <div className="mt-5 grid gap-4 lg:grid-cols-3">
                    <ResourceCard
                      label="Approval"
                      identifier={saved.approvalId}
                      state={displayState.approval?.state}
                    >
                      {displayState.approval?.state === 'REQUESTED' &&
                      displayState.approvalStepUp ? (
                        <LifecycleButton
                          busy={busy}
                          label="Approve with security key"
                          onClick={() =>
                            void checkerCommand(
                              'APPROVE',
                              displayState.approvalStepUp,
                              saved.approvalId,
                            )
                          }
                        />
                      ) : null}
                    </ResourceCard>
                    <ResourceCard
                      label="Release"
                      identifier={saved.releaseId}
                      state={displayState.release?.state}
                    >
                      {displayState.release?.state === 'DRAFT' ? (
                        <LifecycleButton
                          busy={busy}
                          label="Publish with security key"
                          onClick={() =>
                            void checkerCommand(
                              'PUBLISH',
                              displayState.publishStepUp,
                              saved.releaseId,
                            )
                          }
                        />
                      ) : null}
                      {displayState.release?.state === 'ROLLED_BACK' ? (
                        <LifecycleButton
                          busy={busy}
                          label="Retire release"
                          onClick={() => void checkerCommand('RETIRE', undefined, saved.releaseId)}
                        />
                      ) : null}
                    </ResourceCard>
                    <ResourceCard
                      label="Activation record"
                      identifier={saved.occurrenceId}
                      state={displayState.occurrence?.state}
                    >
                      <p className="mt-2 text-sm text-[color:var(--muted)]">
                        Recorded activation outcome. Target authority can expire or be withdrawn
                        after activation.
                      </p>
                      {displayState.occurrence?.state === 'REQUESTED' ? (
                        <LifecycleButton
                          busy={busy}
                          label="Activate with security key"
                          onClick={() =>
                            void checkerCommand(
                              'ACTIVATE',
                              displayState.occurrenceStepUp,
                              saved.occurrenceId,
                            )
                          }
                        />
                      ) : null}
                      {displayState.occurrence &&
                      ['FAILED', 'PARTIAL'].includes(displayState.occurrence.state) ? (
                        <LifecycleButton
                          busy={busy}
                          label="Recover with security key"
                          onClick={() =>
                            void checkerCommand(
                              'RECOVER',
                              displayState.occurrenceStepUp,
                              saved.occurrenceId,
                            )
                          }
                        />
                      ) : null}
                      {displayState.occurrence?.state === 'ACTIVE_MATCHED' ? (
                        <LifecycleButton
                          busy={busy}
                          label="Roll back with security key"
                          onClick={() =>
                            void checkerCommand(
                              'ROLLBACK',
                              displayState.occurrenceStepUp,
                              saved.occurrenceId,
                            )
                          }
                        />
                      ) : null}
                    </ResourceCard>
                  </div>
                </section>
              )}
            </div>
          </>
        )}
      </div>
      {readError && <p role="alert">{readError}</p>}
      {!displayState && currentActor && (
        <section aria-label="Read policy references" className="rounded border p-4">
          <h2 className="font-semibold">Read policy references</h2>
          {selectorForm}
        </section>
      )}
      {!displayState && (
        <button
          type="button"
          className="rounded border px-3 py-2"
          disabled={busy}
          onClick={() => void refresh()}
        >
          Refresh policy workflow
        </button>
      )}
      {childActor && (
        <div hidden={!childVisible}>
          <div hidden={renewalSelected}>
            <WorkflowDetails enabled={evaluationUi} summary="Approval and activation references">
              <AdministrationNamesWorkflow />
            </WorkflowDetails>
            <WorkflowDetails enabled={evaluationUi} summary="Additional activation">
              <PolicyOccurrenceStage />
            </WorkflowDetails>
          </div>
          <div hidden={evaluationUi && !renewalSelected}>
            <TransactionWorkflow
              mode="policy"
              initialKind="policy-activation-renewal"
              showSessionControls={showSessionControls}
              collapseRecoveryControls={evaluationUi}
            />
          </div>
        </div>
      )}
      {displayState && childActor && !childVisible && (
        <p>Other workflows remain hidden until their original context is restored.</p>
      )}
      <p
        hidden={renewalSelected}
        aria-live="polite"
        className="rounded border border-[color:var(--border)] p-3"
        role="status"
      >
        {status ||
          (displayState
            ? 'Ready. No policy authority changes until a named transition is confirmed.'
            : 'Read the current policy workflow before continuing.')}
      </p>
    </div>
  );
}

function ResourceCard({
  children,
  identifier,
  label,
  state,
}: Readonly<{
  children?: React.ReactNode;
  identifier?: string;
  label: string;
  state?: string;
}>) {
  return (
    <article className="rounded border border-[color:var(--border)] p-3">
      <h3 className="font-semibold">{label}</h3>
      <p className="mt-2 break-all text-xs text-[color:var(--muted)]">
        {identifier ?? 'Not loaded'}
      </p>
      <p className="mt-2">State: {state ? <StateBadge>{state}</StateBadge> : 'Unknown'}</p>
      <div className="mt-3">{children}</div>
    </article>
  );
}

function LifecycleButton({
  busy,
  label,
  onClick,
}: Readonly<{ busy: boolean; label: string; onClick: () => void }>) {
  return (
    <button
      className="rounded bg-[color:var(--accent)] px-3 py-2 text-sm font-medium text-white disabled:opacity-60"
      disabled={busy}
      onClick={onClick}
      type="button"
    >
      {label}
    </button>
  );
}
