'use client';

import { performWebAuthnStepUp } from '@openpc/ui-shell';
import { useEffect, useLayoutEffect, useRef, useState } from 'react';
import { z } from 'zod';
import {
  readBoundPolicyState as readBoundState,
  writeBoundPolicyState as writeBoundState,
  type PolicyWorkflowActorBinding as ActorBinding,
} from './policy-workflow-storage';
import { LocalSessionSurface } from './local-session';
import { WorkspaceEntry } from './workspace-entry';
import { GovernanceContextSummary } from './governance-context-summary';
import { approvalStateLabel } from '../lib/approval-catalogue';
import { RoleCatalogue } from './role-catalogue';

const participantId = '018f0000-0000-7000-8000-000000000101';
const privacyDomainId = '018f0000-0000-7000-8000-000000000201';
const storageKey = 'openpc:role-workflow:v1';
const panel = 'rounded border border-[color:var(--border)] bg-[color:var(--surface)] p-4';
const field = 'rounded border border-[color:var(--border)] bg-[color:var(--canvas)] p-2';
const button =
  'w-fit rounded bg-[color:var(--accent)] px-3 py-2 font-medium text-[color:var(--surface)] disabled:opacity-60';
interface Role {
  id: string;
  roleId: string;
  displayName: string;
  actionIntentIds: string[];
  state: string;
  revision?: string;
  origin?: 'GOVERNED' | 'MIGRATED_ASSIGNMENT' | 'BOOTSTRAP';
}
interface StepUp {
  actionIntentId: string;
  actionIntentDigest: string;
  resourceId: string;
  resourceDigest: string;
}
interface Proposal {
  mutation: 'CREATE' | 'ARCHIVE';
  proposedRole: Role;
  expectedRevision: string;
  candidateDigest: string;
}
interface Review {
  reviewToken: string;
  approvalRequestId?: string;
  review: Proposal & { reason: string; stepUp: StepUp };
}
interface Approval {
  approvalRequestId: string;
  candidateDigest: string;
  state: string;
  proposal: Proposal & {
    resourceId: string;
    state: string;
    expiresAt: string;
    consumption: {
      operationId: string;
      effect: Role & { participantId: string; revision: string };
    } | null;
  };
  stepUp: StepUp;
}
interface State {
  actor: ActorBinding & { role: string };
  approvals: Approval[];
  effect?: { effect: Role & { participantId: string }; operationId: string | null };
  nextCursor: string | null;
}
interface Session {
  sessionId?: string;
  principalId?: string;
  contextEpoch?: string;
  role?: string;
  authenticated?: boolean;
  contextMode?: string;
  participantId?: string;
  privacyDomainId?: string;
}
function actorBinding(session: Session): ActorBinding | undefined {
  if (
    !session.authenticated ||
    session.contextMode !== 'PARTICIPANT' ||
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
const savedReview = z.object({
  reviewToken: z.string(),
  approvalRequestId: z.uuid().optional(),
  review: z.object({
    mutation: z.enum(['CREATE', 'ARCHIVE']),
    expectedRevision: z.string(),
    candidateDigest: z.string(),
    reason: z.string(),
    proposedRole: z.object({
      id: z.uuid(),
      roleId: z.string(),
      displayName: z.string(),
      actionIntentIds: z.array(z.string()),
      state: z.string(),
      revision: z.string().optional(),
      origin: z.enum(['GOVERNED', 'MIGRATED_ASSIGNMENT', 'BOOTSTRAP']).optional(),
    }),
    stepUp: z.object({
      actionIntentId: z.string(),
      actionIntentDigest: z.string(),
      resourceId: z.string(),
      resourceDigest: z.string(),
    }),
  }),
});
function validReview(value: unknown): value is Review {
  return savedReview.safeParse(value).success;
}
const sessionProjection = z.union([
  z.object({ authenticated: z.literal(false) }),
  z
    .object({
      authenticated: z.literal(true),
      sessionId: z.string().min(1),
      principalId: z.string().min(1),
      contextEpoch: z.string().min(1),
      contextMode: z.enum(['PLATFORM', 'PARTICIPANT']),
      role: z.string().optional(),
      participantId: z.string().min(1).optional(),
      privacyDomainId: z.string().min(1).optional(),
    })
    .refine(
      (value) =>
        value.contextMode !== 'PARTICIPANT' ||
        Boolean(value.participantId && value.privacyDomainId),
    ),
]);
const revisionProjection = z.string().regex(/^(?:0|[1-9][0-9]*)$/u);
const digestProjection = z.string().regex(/^sha256:[0-9a-f]{64}$/u);
const canonicalRoleProjection = z.strictObject({
  id: z.uuid(),
  participantId: z.literal(participantId),
  roleId: z.string(),
  displayName: z.string().min(1).max(160),
  actionIntentIds: z
    .array(z.string().regex(/^ACT-[A-Z0-9_]+-V[1-9][0-9]*$/u))
    .max(256)
    .refine((values) => new Set(values).size === values.length),
  state: z.enum(['ACTIVE', 'ARCHIVED']),
});
const committedRoleProjection = canonicalRoleProjection.extend({
  revision: revisionProjection,
  origin: z.enum(['GOVERNED', 'MIGRATED_ASSIGNMENT', 'BOOTSTRAP']),
});
const proposedRoleProjection = savedReview.shape.review.shape.proposedRole.extend({
  displayName: z.string().min(1),
  roleId: z.string().min(1),
  state: z.enum(['ACTIVE', 'ARCHIVED']),
  actionIntentIds: z.array(z.string().min(1)),
});
const workbenchProjection = z.object({
  actor: z.object({
    sessionId: z.string(),
    principalId: z.string(),
    participantId: z.string(),
    privacyDomainId: z.string(),
    contextEpoch: z.string(),
    role: z.string().min(1),
  }),
  approvals: z.array(
    z.object({
      approvalRequestId: z.string().min(1),
      candidateDigest: z.string(),
      state: z.string().min(1),
      proposal: savedReview.shape.review.omit({ reason: true, stepUp: true }).extend({
        proposedRole: canonicalRoleProjection,
        resourceId: z.uuid(),
        state: z.string().min(1),
        expiresAt: z.string().datetime(),
        consumption: z
          .strictObject({
            operationId: z.uuid(),
            effect: committedRoleProjection,
          })
          .nullable(),
      }),
      stepUp: savedReview.shape.review.shape.stepUp,
    }),
  ),
  effect: z
    .object({
      effect: proposedRoleProjection.extend({
        participantId: z.literal(participantId),
        revision: z.string().min(1),
        origin: z.enum(['GOVERNED', 'MIGRATED_ASSIGNMENT', 'BOOTSTRAP']),
      }),
      operationId: z.uuid().nullable(),
    })
    .optional(),
  nextCursor: z.string().min(1).nullable(),
});
function sameActor(left: ActorBinding | undefined, right: ActorBinding | undefined) {
  return Boolean(
    left &&
    right &&
    (
      ['sessionId', 'principalId', 'participantId', 'privacyDomainId', 'contextEpoch'] as const
    ).every((key) => left[key] === right[key]),
  );
}
class RoleWorkflowFailure extends Error {}
function safeFailure(cause: unknown, fallback: string) {
  return cause instanceof RoleWorkflowFailure ? cause.message : fallback;
}
const roleAction = {
  id: 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
  digest: 'sha256:bec5bb71e10db36e744f98a55dd6b54a0c42f9f55b73ac322a1de6e8592fd529',
} as const;
const reviewProjection = z
  .object({
    reviewToken: z.string().min(80).max(65536),
    approvalRequestId: z.uuid().optional(),
    review: z.strictObject({
      mutation: z.enum(['CREATE', 'ARCHIVE']),
      expectedRevision: revisionProjection,
      candidateDigest: digestProjection,
      reason: z.string().min(10).max(1024),
      proposedRole: canonicalRoleProjection,
      stepUp: z.strictObject({
        actionIntentId: z.literal(roleAction.id),
        actionIntentDigest: z.literal(roleAction.digest),
        resourceId: z.uuid(),
        resourceDigest: digestProjection,
      }),
    }),
  })
  .refine(
    ({ review }) =>
      review.proposedRole.roleId === `urn:openpc:role:${review.proposedRole.id}` &&
      review.stepUp.resourceId === review.proposedRole.id &&
      review.stepUp.resourceDigest === review.candidateDigest &&
      (review.mutation === 'CREATE'
        ? review.expectedRevision === '0' && review.proposedRole.state === 'ACTIVE'
        : review.expectedRevision !== '0' && review.proposedRole.state === 'ARCHIVED'),
  );
function sameReviewedPlaintext(left: unknown, right: unknown) {
  const first = reviewProjection.safeParse(left),
    second = reviewProjection.safeParse(right);
  return (
    first.success &&
    second.success &&
    JSON.stringify(first.data.review) === JSON.stringify(second.data.review)
  );
}
function originalApproval(value: State, original: Review, actor: ActorBinding) {
  if (
    !sameActor(value.actor, actor) ||
    value.actor.role !== 'operator' ||
    !original.approvalRequestId
  )
    return undefined;
  const matches = value.approvals.filter(
    (item) =>
      item.approvalRequestId === `urn:openpc:resource:${original.approvalRequestId}` &&
      item.state === 'APPROVED' &&
      item.candidateDigest === original.review.candidateDigest &&
      item.proposal.candidateDigest === original.review.candidateDigest &&
      item.proposal.resourceId === original.review.proposedRole.id &&
      sameReviewedPlaintext(original, {
        reviewToken: original.reviewToken,
        review: {
          mutation: item.proposal.mutation,
          proposedRole: item.proposal.proposedRole,
          expectedRevision: item.proposal.expectedRevision,
          candidateDigest: item.proposal.candidateDigest,
          reason: original.review.reason,
          stepUp: original.review.stepUp,
        },
      }),
  );
  return matches.length === 1 ? matches[0] : undefined;
}
function originalRoleDisposition(value: State, original: Review, actor: ActorBinding) {
  const approved = originalApproval(value, original, actor);
  if (!approved) return undefined;
  const proposal = approved.proposal;
  const actual = value.effect?.effect;
  const expected = original.review.proposedRole;
  const sameDefinition = (role: Role) =>
    role.id === expected.id &&
    role.roleId === expected.roleId &&
    role.displayName === expected.displayName &&
    JSON.stringify(role.actionIntentIds) === JSON.stringify(expected.actionIntentIds);
  if (
    proposal.state === 'APPROVED' &&
    proposal.consumption === null &&
    Date.parse(proposal.expiresAt) > Date.now()
  ) {
    // The complete original proposal disposition and approval are required;
    // null consumption or an absent role/page entry alone grants nothing.
    if (proposal.mutation === 'CREATE') return actual ? undefined : 'UNCONSUMED';
    return actual &&
      actual.participantId === actor.participantId &&
      sameDefinition(actual) &&
      actual.state === 'ACTIVE' &&
      actual.revision === proposal.expectedRevision
      ? 'UNCONSUMED'
      : undefined;
  }
  const receipt = proposal.consumption;
  if (
    proposal.state !== 'CONSUMED' ||
    !receipt ||
    !actual ||
    actual.participantId !== actor.participantId ||
    !sameDefinition(receipt.effect) ||
    !sameDefinition(actual) ||
    receipt.effect.participantId !== actor.participantId ||
    receipt.effect.state !== (proposal.mutation === 'CREATE' ? 'ACTIVE' : 'ARCHIVED') ||
    BigInt(receipt.effect.revision) !== BigInt(proposal.expectedRevision) + 1n ||
    (proposal.mutation === 'CREATE' && receipt.effect.origin !== 'GOVERNED') ||
    actual.origin !== receipt.effect.origin ||
    !actual.revision ||
    !revisionProjection.safeParse(actual.revision).success ||
    BigInt(actual.revision) < BigInt(receipt.effect.revision) ||
    (actual.revision === receipt.effect.revision && actual.state !== receipt.effect.state) ||
    (receipt.effect.state === 'ARCHIVED' && actual.state !== 'ARCHIVED')
  )
    return undefined;
  return 'CONSUMED';
}
const approvalResultProjection = z.object({
  approval: workbenchProjection.shape.approvals.element
    .pick({
      candidateDigest: true,
      state: true,
    })
    .extend({
      approvalRequestId: z
        .string()
        .regex(/^urn:openpc:resource:[0-9a-f-]{36}$/u)
        .refine((value) => z.uuid().safeParse(value.slice('urn:openpc:resource:'.length)).success),
    }),
});
const ambiguousCommitProjection = z.strictObject({
  truthState: z.literal('WRITE_AMBIGUITY'),
  roleId: z.uuid(),
  reconciliation: z.literal('READ_AUTHORITATIVE_EFFECT'),
});
const createCommitProjection = z.strictObject({
  truthState: z.literal('SUCCESS'),
  effect: committedRoleProjection,
  operationId: z.uuid().nullable(),
});
const archiveCommitProjection = z.strictObject({
  truthState: z.literal('SUCCESS'),
  effect: committedRoleProjection,
  newEpoch: revisionProjection,
  revokedAssignments: z.number().int().nonnegative(),
  reauthenticationRequired: z.literal(true),
  reconciliation: z.literal('READ_AFTER_REAUTHENTICATION'),
});
function confirmedCommit(value: unknown, original: Review) {
  const ambiguity = ambiguousCommitProjection.safeParse(value);
  if (ambiguity.success) return ambiguity.data.roleId === original.review.proposedRole.id;
  const result =
    original.review.mutation === 'ARCHIVE'
      ? archiveCommitProjection.safeParse(value)
      : createCommitProjection.safeParse(value);
  if (!result.success) return false;
  const expected = original.review.proposedRole,
    effect = result.data.effect;
  return (
    effect.id === expected.id &&
    effect.roleId === `urn:openpc:role:${expected.id}` &&
    effect.state === (original.review.mutation === 'ARCHIVE' ? 'ARCHIVED' : 'ACTIVE') &&
    effect.displayName === expected.displayName &&
    JSON.stringify(effect.actionIntentIds) === JSON.stringify(expected.actionIntentIds)
  );
}
async function json<T>(response: Response): Promise<T> {
  if (!response.ok)
    throw new RoleWorkflowFailure(
      response.status === 401 || response.status === 403
        ? 'The role request was not authorized. Refresh the authenticated context before continuing.'
        : response.status === 409 || response.status === 412
          ? 'The role request could not continue with the current state. Refresh before retrying.'
          : 'The role request was not completed. Refresh before retrying.',
    );
  const value: unknown = await response.json().catch(() => undefined);
  if (!value || typeof value !== 'object' || Array.isArray(value))
    throw new RoleWorkflowFailure(
      'The role response could not be confirmed. Refresh before continuing.',
    );
  return value as T;
}
async function command<T>(body: unknown) {
  const response = await fetch('/api/v1/ui/role-workbench', {
    method: 'POST',
    credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  const kind = body && typeof body === 'object' && 'command' in body ? body.command : undefined;
  const statuses =
    kind === 'APPROVE'
      ? [200, 202]
      : kind === 'PREVIEW_CREATE' || kind === 'PREVIEW_ARCHIVE'
        ? [201]
        : [202];
  if (response.ok && !statuses.includes(response.status))
    throw new RoleWorkflowFailure(
      'The role response could not be confirmed. Refresh before continuing.',
    );
  return json<T>(response);
}
function RoleDetails({ value, proposed = false }: { value: Role; proposed?: boolean }) {
  return (
    <dl className="mt-3 grid gap-3 text-sm sm:grid-cols-2">
      <div>
        <dt className="font-medium">Role name</dt>
        <dd>{value.displayName}</dd>
      </div>
      <div>
        <dt className="font-medium">{proposed ? 'Proposed state' : 'State'}</dt>
        <dd>
          {value.state}
          {value.revision ? ` · revision ${value.revision}` : ''}
        </dd>
      </div>
      <div>
        <dt className="font-medium">Authority role ID</dt>
        <dd className="break-all">{value.id}</dd>
      </div>
      <div>
        <dt className="font-medium">Role reference</dt>
        <dd className="break-all">{value.roleId}</dd>
      </div>
      {value.origin ? (
        <div>
          <dt className="font-medium">Origin</dt>
          <dd>{value.origin}</dd>
        </div>
      ) : null}
      <div>
        <dt className="font-medium">Administrative capabilities</dt>
        <dd>
          {value.actionIntentIds.length === 0 ? 'None' : null}
          <ul className="list-inside list-disc break-all">
            {value.actionIntentIds.map((action) => (
              <li key={action}>{action}</li>
            ))}
          </ul>
        </dd>
      </div>
    </dl>
  );
}

export function ParticipantRoleWorkflow() {
  const [session, setSession] = useState<Session>();
  const [state, setState] = useState<State>();
  const [review, setReview] = useState<Review>();
  const [roleId, setRoleId] = useState('');
  const [selectedRole, setSelectedRole] = useState<string>();
  const [status, setStatus] = useState('');
  const [busy, setBusy] = useState(false);
  const [reauthenticate, setReauthenticate] = useState(false);
  const actorRef = useRef<ActorBinding | undefined>(undefined);
  const loadRevision = useRef(0);
  const loadController = useRef<AbortController | undefined>(undefined);
  const runRevision = useRef(0);
  const reviewRef = useRef<Review | undefined>(undefined);
  const roleDetailsHeading = useRef<HTMLHeadingElement>(null);
  const mounted = useRef(false);
  const operationRef = useRef<
    | {
        controller: AbortController;
        phase: 'PREPARING' | 'SENT' | 'READING';
        snapshot: string;
        actor?: ActorBinding;
        role?: string;
        session?: Session;
        workbenchRole?: string;
      }
    | undefined
  >(undefined);
  const actorRole = useRef<string | undefined>(undefined);
  const sentRole = useRef<{ id: string; actor: ActorBinding } | undefined>(undefined);
  const unresolvedRole = useRef<
    | {
        id: string;
        actor: ActorBinding;
        review: Review;
        body: { command: string; reviewToken: string; approvalRequestId: string };
      }
    | undefined
  >(undefined);
  const inputRevision = useRef(0);
  const snapshot = JSON.stringify({ session, state, review, roleId, selectedRole, reauthenticate });
  const frame = useRef(snapshot);
  useLayoutEffect(() => {
    frame.current = snapshot;
    const pending = operationRef.current;
    if (pending?.phase === 'PREPARING' && pending.snapshot !== snapshot) pending.controller.abort();
  });
  type Operation = NonNullable<typeof operationRef.current>;
  function current(operation: Operation, exact = operation.phase === 'PREPARING') {
    return (
      mounted.current &&
      operationRef.current === operation &&
      !operation.controller.signal.aborted &&
      (operation.phase === 'READING' ||
        ((!operation.actor || sameActor(operation.actor, actorRef.current)) &&
          operation.role === actorRole.current)) &&
      (!exact || frame.current === operation.snapshot)
    );
  }
  function capture() {
    const operation = operationRef.current;
    if (!operation || !current(operation))
      throw new DOMException('The operation was cancelled.', 'AbortError');
    return operation;
  }
  function assertCurrent(operation: Operation, exact = operation.phase === 'PREPARING') {
    if (!current(operation, exact))
      throw new DOMException('The operation was cancelled.', 'AbortError');
  }
  async function qualify(operation: Operation) {
    assertCurrent(operation, true);
    try {
      const actual: Session = sessionProjection.parse(
        await fetch('/api/v1/ui/local-session', {
          cache: 'no-store',
          credentials: 'same-origin',
          signal: operation.controller.signal,
        }).then(json<unknown>),
      );
      assertCurrent(operation, true);
      const expected = operation.session;
      if (
        !actual.authenticated ||
        !expected ||
        !(
          [
            'sessionId',
            'principalId',
            'participantId',
            'privacyDomainId',
            'contextEpoch',
            'contextMode',
          ] as const
        ).every((key) => actual[key] === expected[key]) ||
        (actual.role !== undefined && actual.role !== (expected.role ?? operation.workbenchRole))
      )
        throw new RoleWorkflowFailure(
          'The authenticated role context changed. Refresh before continuing.',
        );
    } catch (cause) {
      if (current(operation, true)) {
        operation.controller.abort();
        actorRef.current = undefined;
        actorRole.current = undefined;
        reviewRef.current = undefined;
        loadRevision.current++;
        loadController.current?.abort();
        setSession(undefined);
        setState(undefined);
        setReview(undefined);
        setRoleId('');
        setSelectedRole(undefined);
        setStatus('The authenticated role context changed. Refresh before continuing.');
      }
      throw cause;
    }
    assertCurrent(operation, true);
  }
  async function stepUp(value: StepUp, operation: Operation) {
    assertCurrent(operation);
    await performWebAuthnStepUp({ ...value, stepUp: 'FRESH_WEBAUTHN_MAX_5M' }, value, {
      signal: operation.controller.signal,
      isCurrent: () => current(operation, true),
    });
    assertCurrent(operation, true);
    await qualify(operation);
  }
  function cancelPreparation() {
    inputRevision.current++;
    const pending = operationRef.current;
    if (pending && pending.phase !== 'SENT') {
      pending.controller.abort();
      loadRevision.current++;
      loadController.current?.abort();
    }
  }
  async function load(id?: string, cursor?: string, outcome = false) {
    if (unresolvedRole.current && !outcome) {
      id = unresolvedRole.current.id;
      cursor = undefined;
    }
    const generation = ++loadRevision.current;
    loadController.current?.abort();
    const controller = new AbortController();
    loadController.current = controller;
    const input = inputRevision.current;
    const currentRead = () =>
      mounted.current &&
      generation === loadRevision.current &&
      !controller.signal.aborted &&
      (operationRef.current?.phase === 'SENT' || input === inputRevision.current);
    setSelectedRole(id);
    try {
      if (id) setState((current) => (current ? { ...current, effect: undefined } : current));
      const value = await fetch('/api/v1/ui/local-session', {
        cache: 'no-store',
        signal: controller.signal,
      }).then(json<unknown>);
      if (!currentRead()) return;
      const parsedSession = sessionProjection.safeParse(value);
      if (!parsedSession.success)
        throw new RoleWorkflowFailure(
          'Authenticated context could not be confirmed. Refresh before continuing.',
        );
      const current: Session = parsedSession.data;
      setSession(current);
      const actor = actorBinding(current);
      const roleChanged = !!actorRef.current && actorRole.current !== current.role;
      const changed = !sameActor(actorRef.current, actor) || roleChanged;
      actorRef.current = actor;
      actorRole.current = current.role;
      if (!actor || changed) {
        setState(undefined);
        setReview(undefined);
        setRoleId('');
        setSelectedRole(undefined);
        // A replacement session may read the sent role, but never rebind its original seal.
        const saved =
          actor && !sentRole.current && !unresolvedRole.current && !roleChanged
            ? readBoundState(storageKey, actor, validReview)
            : undefined;
        reviewRef.current = saved;
        if (saved) {
          setReview(saved);
          setRoleId(saved.review.proposedRole.id);
          if (saved.approvalRequestId && actor) {
            // Old storage cannot distinguish unsent from a lost sent response.
            // Restore only read custody until the original owner proves a disposition.
            unresolvedRole.current ??= {
              id: saved.review.proposedRole.id,
              actor,
              review: saved,
              body: {
                command: 'COMMIT',
                reviewToken: saved.reviewToken,
                approvalRequestId: saved.approvalRequestId,
              },
            };
            if (!outcome && saved.review.mutation === 'ARCHIVE') id = saved.review.proposedRole.id;
          }
        }
      }
      if (!actor) {
        if (sentRole.current) return;
        try {
          localStorage.removeItem(storageKey);
        } catch {
          /* Optional storage. */
        }
        return;
      }
      const original =
        id && unresolvedRole.current?.id === id
          ? unresolvedRole.current
          : id && sentRole.current?.id === id
            ? sentRole.current
            : undefined;
      const historical =
        original &&
        actor.principalId === original.actor.principalId &&
        actor.participantId === original.actor.participantId &&
        actor.privacyDomainId === original.actor.privacyDomainId;
      if (original && !historical) {
        setState(undefined);
        setReview(undefined);
        setRoleId('');
        return;
      }
      const body = await fetch(
        `/api/v1/ui/role-workbench?${new URLSearchParams({
          ...(id && (!changed || historical) ? { roleId: id } : {}),
          ...(cursor && !changed ? { cursor } : {}),
        }).toString()}`,
        { cache: 'no-store', signal: controller.signal },
      ).then(json<unknown>);
      if (!currentRead()) return;
      const parsed = workbenchProjection.safeParse(body);
      if (!parsed.success)
        throw new RoleWorkflowFailure(
          'Role approvals could not be confirmed. Refresh before continuing.',
        );
      const next = parsed.data;
      if (
        !sameActor(actorRef.current, actor) ||
        !sameActor(actor, next.actor) ||
        (current.role !== undefined && current.role !== next.actor.role)
      )
        throw new RoleWorkflowFailure(
          'The working context changed. Refresh the role workflow before continuing.',
        );
      const pending = unresolvedRole.current;
      if (pending) {
        const after = sessionProjection.parse(
          await fetch('/api/v1/ui/local-session', {
            cache: 'no-store',
            credentials: 'same-origin',
            signal: controller.signal,
          }).then(json<unknown>),
        );
        if (!currentRead()) return;
        if (
          !after.authenticated ||
          !sameActor(actorBinding(after), actor) ||
          after.contextMode !== current.contextMode ||
          after.role !== current.role
        )
          throw new RoleWorkflowFailure('The working context changed. Refresh before continuing.');
      }
      const selected = next.effect?.effect;
      if (
        id &&
        (!changed || historical) &&
        (!selected || selected.id !== id || selected.roleId !== `urn:openpc:role:${id}`)
      )
        throw new RoleWorkflowFailure('Role readback belongs to a different selection.');
      setState(next);
      setReauthenticate(false);
      if (
        !outcome &&
        pending &&
        pending === unresolvedRole.current &&
        operationRef.current?.phase !== 'SENT' &&
        input === inputRevision.current &&
        originalRoleDisposition(next, pending.review, pending.actor) === 'UNCONSUMED'
      ) {
        unresolvedRole.current = undefined;
        if (sentRole.current?.id === pending.id && sameActor(sentRole.current.actor, pending.actor))
          sentRole.current = undefined;
      }
      if (unresolvedRole.current)
        setStatus(
          'The original role request remains unconfirmed. Read its authoritative outcome before continuing.',
        );
      return next;
    } catch (cause) {
      if (!currentRead()) return;
      loadRevision.current += 1;
      actorRef.current = undefined;
      actorRole.current = undefined;
      reviewRef.current = undefined;
      setSelectedRole(undefined);
      setSession(undefined);
      setState(undefined);
      setReview(undefined);
      setRoleId('');
      throw cause;
    } finally {
      if (loadController.current === controller) loadController.current = undefined;
    }
  }
  async function readOriginalRoleOutcome() {
    const operation = capture();
    if (operation.phase !== 'READING') return;
    const original = unresolvedRole.current;
    if (
      !original ||
      original.body.command !== 'COMMIT' ||
      original.body.reviewToken !== original.review.reviewToken ||
      original.body.approvalRequestId !== original.review.approvalRequestId
    )
      return;
    const input = inputRevision.current;
    let next = await load(undefined, undefined, true);
    assertCurrent(operation);
    if (!next || input !== inputRevision.current) return;
    const approved = originalApproval(next, original.review, original.actor);
    if (!approved) return;
    if (approved.proposal.state === 'CONSUMED' || approved.proposal.mutation === 'ARCHIVE') {
      next = await load(original.id, undefined, true);
      assertCurrent(operation);
    }
    if (!next || input !== inputRevision.current || !sameActor(actorRef.current, original.actor))
      return;
    const disposition = originalRoleDisposition(next, original.review, original.actor);
    if (!disposition) return;
    if (unresolvedRole.current && unresolvedRole.current !== original) return;
    if (disposition === 'CONSUMED') {
      // Historical consumption is not current authority. Keep the signed bytes
      // in storage, and retire only this exact rendered original review.
      if (
        reviewRef.current?.reviewToken === original.review.reviewToken &&
        reviewRef.current.approvalRequestId === original.review.approvalRequestId &&
        sameReviewedPlaintext(reviewRef.current, original.review)
      ) {
        reviewRef.current = undefined;
        setReview(undefined);
      }
      setStatus('The original role change was committed. Its current role was read separately.');
    } else {
      reviewRef.current = original.review;
      setReview(original.review);
      setRoleId(original.id);
      setStatus(
        'The original role proposal is unconsumed. A fresh proof is required to commit it.',
      );
    }
    if (unresolvedRole.current === original) unresolvedRole.current = undefined;
    if (sentRole.current?.id === original.id && sameActor(sentRole.current.actor, original.actor))
      sentRole.current = undefined;
  }
  function save(next: Review) {
    if (!reviewProjection.safeParse(next).success)
      throw new RoleWorkflowFailure(
        'The role review could not be confirmed. Refresh before continuing.',
      );
    const actor = actorRef.current;
    if (!mounted.current || !actor) return;
    loadRevision.current += 1;
    loadController.current?.abort();
    loadController.current = undefined;
    reviewRef.current = next;
    setSelectedRole(undefined);
    setReview(next);
    writeBoundState(storageKey, actor, next);
    setRoleId(next.review.proposedRole.id);
  }
  async function run(action: () => Promise<unknown>, readOnly = false) {
    if (!mounted.current) return;
    if (!readOnly && unresolvedRole.current) {
      setStatus(
        'The original role request remains unconfirmed. Read its authoritative outcome before continuing.',
      );
      return;
    }
    if (readOnly && operationRef.current && operationRef.current.phase !== 'SENT') {
      operationRef.current.controller.abort();
      operationRef.current = undefined;
    }
    if (operationRef.current) {
      // A sent effect may coexist with a selected read; its finalizer remains the owner.
      if (readOnly && operationRef.current.phase === 'SENT') {
        try {
          await action();
        } catch {
          /* Original sent command owns reconciliation. */
        }
      }
      return;
    }
    const operation: Operation = {
      controller: new AbortController(),
      phase: readOnly ? 'READING' : 'PREPARING',
      snapshot: frame.current,
      actor: actorRef.current,
      role: actorRole.current,
      session: session && { ...session },
      workbenchRole: state?.actor.role,
    };
    operationRef.current = operation;
    const generation = ++runRevision.current;
    setBusy(true);
    setStatus('');
    try {
      await action();
    } catch (error) {
      if (current(operation))
        setStatus(
          safeFailure(error, 'The role request could not be completed. Refresh before retrying.'),
        );
    } finally {
      if (operationRef.current === operation) {
        operationRef.current = undefined;
        if (mounted.current && generation === runRevision.current) setBusy(false);
      }
    }
  }
  useLayoutEffect(() => {
    let active = true;
    mounted.current = true;
    void load().catch((error) => {
      if (active && mounted.current)
        setStatus(
          safeFailure(
            error,
            'The authenticated role context could not be read. Refresh before retrying.',
          ),
        );
    });
    return () => {
      active = false;
      mounted.current = false;
      operationRef.current?.controller.abort();
      operationRef.current = undefined;
      loadRevision.current += 1;
      runRevision.current += 1;
      loadController.current?.abort();
    };
  }, []);
  useEffect(() => {
    if (state?.effect) roleDetailsHeading.current?.focus();
  }, [state?.effect]);
  const currentApproval = state?.approvals.find((item) =>
    item.approvalRequestId.endsWith(review?.approvalRequestId ?? '!'),
  );
  async function selectContext() {
    const operation = capture();
    await stepUp(
      {
        actionIntentId: 'ACT-IDENTITY_CREATE_SESSION-V1',
        actionIntentDigest:
          'sha256:dbc8290dd60814d5bb4248fefc9550f43d0dc97d6333ac232c8ab8a98c3354d2',
        resourceId: participantId,
        resourceDigest: 'sha256:21e6f6ef3dfec5acda58eebd0e07fca2e1394a9777f13157e3e514d611248700',
      },
      operation,
    );
    operation.phase = 'SENT';
    await json(
      await fetch('/api/v1/ui/session/context', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ participantId, privacyDomainId }),
      }),
    );
    assertCurrent(operation);
    if (await load()) {
      if (current(operation)) setStatus('Participant privacy context is active.');
    }
  }
  async function prepare(event: React.FormEvent<HTMLFormElement>, archive = false) {
    event.preventDefault();
    const input = new FormData(event.currentTarget);
    const selected = state?.effect?.effect;
    const expectedReason = String(input.get('reason') ?? '').trim();
    const expectedName = String(input.get('displayName') ?? '').trim();
    const expectedActions = String(input.get('actions'))
      .split(/[\s,]+/u)
      .filter(Boolean)
      .sort();
    await run(async () => {
      const operation = capture();
      const next = await command<Review>(
        archive
          ? {
              command: 'PREVIEW_ARCHIVE',
              roleId: state?.effect?.effect.id,
              reason: input.get('reason'),
            }
          : {
              command: 'PREVIEW_CREATE',
              displayName: input.get('displayName'),
              reason: input.get('reason'),
              actionIntentIds: String(input.get('actions'))
                .split(/[\s,]+/u)
                .filter(Boolean),
            },
      );
      assertCurrent(operation, true);
      const confirmed = reviewProjection.safeParse(next);
      if (
        !confirmed.success ||
        confirmed.data.review.reason !== expectedReason ||
        (archive
          ? !selected ||
            selected.state !== 'ACTIVE' ||
            confirmed.data.review.mutation !== 'ARCHIVE' ||
            confirmed.data.review.expectedRevision !== selected.revision ||
            confirmed.data.review.proposedRole.id !== selected.id ||
            confirmed.data.review.proposedRole.roleId !== selected.roleId ||
            confirmed.data.review.proposedRole.displayName !== selected.displayName ||
            JSON.stringify(confirmed.data.review.proposedRole.actionIntentIds) !==
              JSON.stringify(selected.actionIntentIds)
          : confirmed.data.review.mutation !== 'CREATE' ||
            confirmed.data.review.proposedRole.displayName !== expectedName ||
            JSON.stringify(confirmed.data.review.proposedRole.actionIntentIds) !==
              JSON.stringify(expectedActions))
      )
        throw new RoleWorkflowFailure(
          'The role review could not be confirmed. Refresh before continuing.',
        );
      save(next);
      setStatus('Review the exact role change before requesting approval.');
    });
  }
  async function submit() {
    if (!review) return;
    const selectedReview = review;
    const body = { command: 'SUBMIT', reviewToken: selectedReview.reviewToken };
    const operation = capture();
    operation.phase = 'SENT';
    const result = await command<Review & { approval: Approval }>(body);
    assertCurrent(operation);
    const confirmed = approvalResultProjection.safeParse(result);
    if (
      !sameReviewedPlaintext(result, selectedReview) ||
      !confirmed.success ||
      confirmed.data.approval.candidateDigest !== review.review.candidateDigest ||
      result.review.candidateDigest !== review.review.candidateDigest
    )
      throw new RoleWorkflowFailure(
        'The role submission could not be confirmed. Refresh approvals before retrying.',
      );
    save({ ...result, approvalRequestId: result.approval.approvalRequestId.slice(-36) });
    if (await load()) {
      if (current(operation)) setStatus('The role change is awaiting a distinct checker.');
    }
  }
  async function approve(item: Approval) {
    const body = {
      command: 'APPROVE',
      approvalRequestId: item.approvalRequestId.slice(-36),
      candidateDigest: item.candidateDigest,
    };
    const operation = capture();
    await stepUp(item.stepUp, operation);
    operation.phase = 'SENT';
    const result = await command<unknown>(body);
    assertCurrent(operation);
    const confirmed = approvalResultProjection.safeParse(result);
    if (
      !confirmed.success ||
      confirmed.data.approval.state !== 'APPROVED' ||
      confirmed.data.approval.approvalRequestId.slice(-36) !== item.approvalRequestId.slice(-36) ||
      confirmed.data.approval.candidateDigest !== item.candidateDigest
    )
      throw new RoleWorkflowFailure(
        'The role approval could not be confirmed. Refresh approvals before retrying.',
      );
    if (await load()) {
      if (current(operation)) setStatus('The reviewed role change is approved.');
    }
  }
  async function commit() {
    if (!review?.approvalRequestId) return;
    const selectedReview = review;
    const body = {
      command: 'COMMIT',
      reviewToken: selectedReview.reviewToken,
      approvalRequestId: selectedReview.approvalRequestId!,
    };
    const operation = capture();
    await stepUp(selectedReview.review.stepUp, operation);
    if (!operation.actor) return;
    sentRole.current = { id: selectedReview.review.proposedRole.id, actor: operation.actor };
    operation.phase = 'SENT';
    const original = {
      id: selectedReview.review.proposedRole.id,
      actor: operation.actor,
      review: selectedReview,
      body,
    };
    unresolvedRole.current = original;
    // Even a readback denial can follow a durable CREATE; retain the sent original.
    const result = await command<{ truthState: string; reauthenticationRequired?: boolean }>(body);
    assertCurrent(operation);
    if (!confirmedCommit(result, selectedReview))
      throw new RoleWorkflowFailure(
        'The role change response could not be confirmed. Read the authoritative role before retrying.',
      );
    if (result.truthState !== 'WRITE_AMBIGUITY' && unresolvedRole.current === original)
      unresolvedRole.current = undefined;
    if (result.reauthenticationRequired || result.truthState === 'WRITE_AMBIGUITY') {
      loadRevision.current += 1;
      loadController.current?.abort();
      setState(undefined);
      setReauthenticate(true);
      setStatus(
        result.truthState === 'WRITE_AMBIGUITY'
          ? 'The response was lost. Sign in again and read the role before retrying.'
          : 'Role archived. Its assignments were revoked. Sign in again to read the new authority state.',
      );
      return;
    }
    const fresh = await load(selectedReview.review.proposedRole.id);
    if (current(operation) && fresh && reviewRef.current === selectedReview)
      setStatus('Role created and its durable effect read back.');
  }
  if (!session)
    return (
      <div className="mt-6 space-y-3">
        <p role="status">{status || 'Loading the authenticated context.'}</p>
        {status && (
          <button className={button} disabled={busy} onClick={() => void run(() => load(), true)}>
            Refresh approvals
          </button>
        )}
        {unresolvedRole.current && (
          <button
            className={button}
            disabled={busy}
            onClick={() => void run(readOriginalRoleOutcome, true)}
          >
            Read original role outcome
          </button>
        )}
      </div>
    );
  if (!session.authenticated) return <LocalSessionSurface />;
  return (
    <div className="mt-6 space-y-6" onChangeCapture={cancelPreparation}>
      <p aria-live="polite" role="status" className="break-words">
        {status}
      </p>
      {unresolvedRole.current && (
        <button
          className={button}
          disabled={busy}
          onClick={() => void run(readOriginalRoleOutcome, true)}
        >
          Read original role outcome
        </button>
      )}
      {reauthenticate ? (
        <>
          <LocalSessionSurface />
          <button
            className={button}
            disabled={busy}
            onClick={() => void run(() => load(sentRole.current?.id ?? roleId), true)}
          >
            Read role after signing in
          </button>
        </>
      ) : null}
      {session.contextMode !== 'PARTICIPANT' ? (
        <section className={panel}>
          <h2 className="text-xl font-semibold">Choose a working context</h2>
          <p className="my-3">Role changes require an explicit Participant and privacy domain.</p>
          <WorkspaceEntry disabled={busy}>
            <button className={button} disabled={busy} onClick={() => void run(selectContext)}>
              Enter workspace
            </button>
          </WorkspaceEntry>
        </section>
      ) : null}
      {state && sameActor(actorBinding(session), state.actor) ? (
        <>
          <GovernanceContextSummary
            title="Participant roles"
            description="Define reusable permissions and review changes to existing roles."
            actor={state.actor}
          >
            <button className={button} disabled={busy} onClick={() => void run(() => load(), true)}>
              Refresh approvals
            </button>
          </GovernanceContextSummary>
          <RoleCatalogue
            key={`${state.actor.sessionId}:${state.actor.contextEpoch}`}
            actor={state.actor}
            onOpen={(id) => {
              setRoleId(id);
              void run(() => load(id), true);
            }}
          />
          <section className={panel} aria-label="Role details">
            <h2 className="text-xl font-semibold" ref={roleDetailsHeading} tabIndex={-1}>
              Role details
            </h2>
            <form
              className="mt-3 grid max-w-2xl gap-3"
              onSubmit={(event) => {
                event.preventDefault();
                void run(() => load(roleId), true);
              }}
            >
              <label className="grid gap-1">
                Authority role ID
                <input
                  className={field}
                  value={roleId}
                  onChange={(event) => setRoleId(event.target.value)}
                  required
                />
              </label>
              <button className={button} disabled={busy} type="submit">
                Find role
              </button>
            </form>
            {state.effect && (!selectedRole || state.effect.effect.id === selectedRole) ? (
              <>
                <RoleDetails value={state.effect.effect} />
                <p className="mt-3 break-all text-sm">
                  Operation reference:{' '}
                  {state.effect.operationId ?? 'Initial trust or migrated role'}
                </p>
                {state.actor.role === 'operator' && state.effect.effect.state === 'ACTIVE' ? (
                  <>
                    <p className="mt-4 text-sm text-[color:var(--muted)]">
                      Roles are immutable. To change this role, create a replacement, reassign its
                      principals, and then archive this role. Archival revokes its assignments and
                      descendant delegations.
                    </p>
                    <form
                      className="mt-4 grid max-w-2xl gap-3"
                      aria-label="Archive role"
                      onSubmit={(event) => void prepare(event, true)}
                    >
                      <label className="grid gap-1">
                        Archive reason
                        <textarea
                          className={field}
                          name="reason"
                          minLength={10}
                          maxLength={1024}
                          required
                        />
                      </label>
                      <button className={button} disabled={busy} type="submit">
                        Review role archival
                      </button>
                    </form>
                  </>
                ) : null}
              </>
            ) : (
              <p className="mt-3">
                Select a role from the catalogue to view its authoritative details.
              </p>
            )}
          </section>
          {state.actor.role === 'operator' ? (
            <section className={panel}>
              <h2 className="text-xl font-semibold">Create a role</h2>
              <p className="mt-2 text-[color:var(--muted)]">
                Select administrative capabilities within your authority. Runtime RPC permissions
                require their own policy.
              </p>
              <p className="mt-2 text-sm text-[color:var(--muted)]">
                A role cannot be edited after creation. Create a replacement role when its name or
                administrative capabilities must change.
              </p>
              <form className="mt-4 grid max-w-2xl gap-4" onSubmit={(event) => void prepare(event)}>
                <label className="grid gap-1">
                  Role name
                  <input className={field} name="displayName" required maxLength={160} />
                </label>
                <label className="grid gap-1">
                  Administrative action IDs
                  <textarea
                    className={`${field} min-h-24`}
                    name="actions"
                    aria-describedby="role-actions-help"
                  />
                </label>
                <p id="role-actions-help" className="text-sm text-[color:var(--muted)]">
                  Enter registered action IDs, one per line. An empty role grants no administrative
                  capabilities. For example, ACT-PARTICIPANTS_READ_RESOURCE-V1.
                </p>
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
                  Review role creation
                </button>
              </form>
            </section>
          ) : null}
          {review && state.actor.role === 'operator' ? (
            <section className={panel} aria-label="Role change review">
              <h2 className="text-xl font-semibold">
                {review.review.mutation === 'CREATE' ? 'Create' : 'Archive'} role · review
              </h2>
              <RoleDetails value={review.review.proposedRole} proposed />
              <p className="mt-3">Reason: {review.review.reason}</p>
              <p>Expected revision: {review.review.expectedRevision}</p>
              <p className="break-all text-xs">Candidate: {review.review.candidateDigest}</p>
              {review.review.mutation === 'ARCHIVE' ? (
                <p className="mt-3">
                  Archiving revokes this role’s assignments and descendant delegations. Existing
                  sessions must refresh their authority.
                </p>
              ) : null}
              <div className="mt-4 flex flex-wrap gap-3">
                {!review.approvalRequestId ? (
                  <button className={button} disabled={busy} onClick={() => void run(submit)}>
                    Send role to checker
                  </button>
                ) : (
                  <p>
                    Approval:{' '}
                    {currentApproval
                      ? approvalStateLabel(currentApproval.state)
                      : 'Refresh to check'}
                  </p>
                )}
                {currentApproval?.state === 'APPROVED' && !unresolvedRole.current ? (
                  <button className={button} disabled={busy} onClick={() => void run(commit)}>
                    Commit approved role change
                  </button>
                ) : null}
              </div>
            </section>
          ) : null}
          <section className={panel}>
            <h2 className="text-xl font-semibold">Role approvals</h2>
            {state.approvals.length === 0 ? (
              <p className="mt-3">No visible role approvals on this page.</p>
            ) : (
              state.approvals.map((item) => (
                <article
                  key={item.approvalRequestId}
                  className="mt-4 border-t border-[color:var(--border)] pt-4"
                >
                  <h3 className="font-semibold">
                    {item.proposal.mutation === 'CREATE' ? 'Create' : 'Archive'} role ·{' '}
                    {approvalStateLabel(item.state)}
                  </h3>
                  <RoleDetails value={item.proposal.proposedRole} proposed />
                  <p>Expected revision: {item.proposal.expectedRevision}</p>
                  <p className="mt-2 break-all text-xs">Candidate: {item.candidateDigest}</p>
                  {item.proposal.mutation === 'ARCHIVE' ? (
                    <p className="my-3">
                      This change revokes the role’s assignments and descendant delegations.
                    </p>
                  ) : null}
                  {state.actor.role === 'viewer' && item.state === 'REQUESTED' ? (
                    <button
                      className={`${button} mt-3`}
                      disabled={busy}
                      onClick={() => void run(() => approve(item))}
                    >
                      Approve {item.proposal.proposedRole.displayName}
                    </button>
                  ) : null}
                </article>
              ))
            )}
            {state.nextCursor ? (
              <button
                className={`${button} mt-3`}
                disabled={busy}
                onClick={() => void run(() => load(undefined, state.nextCursor ?? undefined), true)}
              >
                Next approval page
              </button>
            ) : null}
          </section>
        </>
      ) : null}
    </div>
  );
}
