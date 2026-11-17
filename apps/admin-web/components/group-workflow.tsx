'use client';
import { useEffect, useLayoutEffect, useRef, useState } from 'react';
import { z } from 'zod';
import { performWebAuthnStepUp } from '@openpc/ui-shell';
import {
  savedGroupReview,
  groupReadback,
  groupResumeState,
  groupState,
  type GroupReview,
} from '../lib/group-workflow';
import {
  clearBoundPolicyState,
  readBoundPolicyState,
  writeBoundPolicyState,
} from './policy-workflow-storage';
import { LocalSessionSurface } from './local-session';
import { GroupCatalogue } from './group-catalogue';
const endpoint = '/api/v1/ui/group-workbench';
const storageKey = 'openpc:group-workflow:v1';
const panel = 'min-w-0 rounded border border-[color:var(--border)] bg-[color:var(--surface)] p-4';
const field =
  'min-w-0 w-full rounded border border-[color:var(--border)] bg-[color:var(--canvas)] p-2';
const button =
  'w-fit rounded bg-[color:var(--accent)] px-3 py-2 font-medium text-[color:var(--surface)] disabled:opacity-60';
type State = z.infer<typeof groupState>;
type Readback = z.infer<typeof groupReadback>;
const failureMessages = {
  unavailable:
    'Group request could not be confirmed. Refresh or read the original operation before retrying.',
  authorization:
    'Group request was not authorized. Refresh the authenticated context before continuing.',
  conflict: 'Group state changed. Refresh or read the original operation before retrying.',
  input: 'Group request was rejected. Check the inputs before continuing.',
  approvals: 'Group approvals could not be confirmed. Refresh before continuing.',
  readback: 'Group readback belongs to a different context.',
  expired: 'This group review expired. Prepare the group change again.',
  webauthn:
    'WebAuthn verification was not completed. Connect the registered authenticator and retry; no group request was staged.',
  unconfirmed: 'The committed group could not be read back authoritatively.',
  changed: 'Group context changed.',
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
async function json(response: Response): Promise<unknown> {
  const value = await response.json().catch(() => undefined);
  if (!response.ok) throw httpFailure(response.status);
  if (value === undefined) throw new WorkflowFailure('unavailable');
  return value;
}
export function GroupWorkflow() {
  const [state, setState] = useState<State>();
  const [review, setReview] = useState<GroupReview>();
  const [readback, setReadback] = useState<Readback>();
  const [lane, setLane] = useState<'maker' | 'checker'>('checker');
  const [mutation, setMutation] = useState<
    'CREATE' | 'RENAME' | 'ADD_MEMBER' | 'REMOVE_MEMBER' | 'RETIRE'
  >('CREATE');
  const [groupId, setGroupId] = useState('');
  const [groupName, setGroupName] = useState('');
  const [principalId, setPrincipalId] = useState('');
  const [checker, setChecker] = useState('');
  const [reason, setReason] = useState('');
  const [lookupId, setLookupId] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [message, setMessage] = useState('');
  const [catalogueEpoch, setCatalogueEpoch] = useState(0);
  const actor = useRef<State['actor'] | undefined>(undefined);
  const locked = useRef(false);
  const mounted = useRef(false);
  const operationGeneration = useRef(0);
  const operation = useRef<
    | {
        generation: number;
        actor: string;
        controller: AbortController;
        selection?: () => boolean;
        readFailure?: unknown;
      }
    | undefined
  >(undefined);
  const approvalsRef = useRef<State['approvals']>([]);
  function cancelOperation() {
    operationGeneration.current += 1;
    operation.current?.controller.abort();
  }
  function isCurrent(token: NonNullable<typeof operation.current>) {
    return (
      mounted.current &&
      operation.current === token &&
      token.generation === operationGeneration.current &&
      !token.controller.signal.aborted &&
      token.actor === JSON.stringify(actor.current) &&
      (token.selection?.() ?? true)
    );
  }
  function assertOperation() {
    const token = operation.current;
    if (!token || !isCurrent(token))
      throw new DOMException('The operation was cancelled.', 'AbortError');
    return token;
  }
  async function verify(
    step: {
      actionIntentId: string;
      actionIntentDigest: string;
      resourceId: string;
      resourceDigest: string;
    },
    selected: GroupReview | State['approvals'][number],
  ) {
    const token = assertOperation();
    const selection =
      'reviewToken' in selected
        ? () => reviewRef.current === selected
        : () =>
            approvalsRef.current.some((item) => JSON.stringify(item) === JSON.stringify(selected));
    token.selection = selection;
    assertOperation();
    await performWebAuthnStepUp({ ...step, stepUp: 'FRESH_WEBAUTHN_MAX_5M' }, step, {
      signal: token.controller.signal,
      isCurrent: () => isCurrent(token),
    });
    assertOperation();
  }

  const reviewRef = useRef<GroupReview | undefined>(undefined);
  const loadGeneration = useRef(0);
  const loadController = useRef<AbortController | undefined>(undefined);
  const readGeneration = useRef(0);
  const readController = useRef<AbortController | undefined>(undefined);
  const readTarget = useRef<string | undefined>(undefined);
  const resumeGeneration = useRef(0);
  const resumeController = useRef<AbortController | undefined>(undefined);
  function cancelReadback() {
    readGeneration.current += 1;
    readController.current?.abort();
    readController.current = undefined;
  }
  function cancelResume() {
    resumeGeneration.current += 1;
    resumeController.current?.abort();
    resumeController.current = undefined;
  }
  function save(value: GroupReview) {
    if (!actor.current) return;
    cancelResume();
    reviewRef.current = value;
    readTarget.current = undefined;
    setReview(value);
    writeBoundPolicyState(storageKey, actor.current, value);
  }
  function adopt(value: State) {
    approvalsRef.current = value.approvals;
    if (operation.current?.selection && !operation.current.selection())
      operation.current.controller.abort();
    if (JSON.stringify(actor.current) !== JSON.stringify(value.actor)) {
      cancelOperation();
      cancelReadback();
      cancelResume();
      actor.current = value.actor;
      const saved = readBoundPolicyState(
        storageKey,
        value.actor,
        (stored): stored is GroupReview => savedGroupReview.safeParse(stored).success,
      );
      reviewRef.current = saved;
      setReview(saved);
      readTarget.current = undefined;
      setLookupId('');
      setReadback(undefined);
    }
    setState(value);
    return value;
  }
  async function load(selected = lane, cursor?: string) {
    if (!mounted.current) return;
    const generation = ++loadGeneration.current;
    loadController.current?.abort();
    cancelReadback();
    cancelResume();
    const controller = new AbortController();
    loadController.current = controller;
    try {
      const value = await json(
        await fetch(
          `${endpoint}?${new URLSearchParams({ lane: selected, ...(cursor ? { cursor } : {}) })}`,
          { cache: 'no-store', signal: controller.signal },
        ),
      );
      if (!mounted.current || generation !== loadGeneration.current || controller.signal.aborted)
        return;
      const parsed = groupState.safeParse(value);
      if (!parsed.success) throw new WorkflowFailure('approvals');
      return adopt(parsed.data);
    } catch (cause) {
      if (!mounted.current || generation !== loadGeneration.current || controller.signal.aborted)
        return;
      const token = operation.current;
      if (token && isCurrent(token)) token.readFailure = cause;
      loadGeneration.current += 1;
      cancelReadback();
      cancelResume();
      cancelOperation();
      approvalsRef.current = [];
      actor.current = undefined;
      reviewRef.current = undefined;
      readTarget.current = undefined;
      setState(undefined);
      setReview(undefined);
      setReadback(undefined);
      setLookupId('');
      setMessage('');
      throw cause;
    } finally {
      if (loadController.current === controller) loadController.current = undefined;
    }
  }
  useLayoutEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
      cancelOperation();
      loadGeneration.current += 1;
      loadController.current?.abort();
      cancelReadback();
      cancelResume();
    };
  }, []);
  useEffect(() => {
    let current = true;
    void load('checker').catch((cause: unknown) => {
      if (current && mounted.current) setError(failureMessage(cause));
    });
    return () => {
      current = false;
    };
  }, []);
  useEffect(() => {
    if (!state || !review?.approvalRequestId || reviewRef.current !== review) return;
    const binding = JSON.stringify(state.actor);
    if (
      binding !== JSON.stringify(actor.current) ||
      readController.current ||
      (readTarget.current && readTarget.current !== review.review.candidate.groupId)
    )
      return;
    const generation = ++resumeGeneration.current;
    const inventoryGeneration = loadGeneration.current;
    const selectionGeneration = readGeneration.current;
    const controller = new AbortController();
    resumeController.current?.abort();
    resumeController.current = controller;
    const parameters = new URLSearchParams({
      resumeApprovalRequestId: review.approvalRequestId,
      candidateDigest: review.review.candidateDigest,
    });
    void fetch(`${endpoint}?${parameters}`, { cache: 'no-store', signal: controller.signal })
      .then(json)
      .then((value) => {
        if (
          controller.signal.aborted ||
          generation !== resumeGeneration.current ||
          inventoryGeneration !== loadGeneration.current ||
          selectionGeneration !== readGeneration.current ||
          binding !== JSON.stringify(actor.current) ||
          reviewRef.current !== review
        )
          return;
        const resume = groupResumeState.parse(value);
        if (
          resume.candidateDigest !== review.review.candidateDigest ||
          resume.state !== 'CONSUMED' ||
          !resume.operationId ||
          !resume.readback ||
          resume.readback.effect.groupId !== review.review.candidate.groupId ||
          resume.readback.effect.participantId !== state.actor.participantId
        )
          return;
        clearBoundPolicyState(storageKey);
        reviewRef.current = undefined;
        if (operation.current?.selection && !operation.current.selection())
          operation.current.controller.abort();
        setReview(undefined);
        readTarget.current = resume.readback.effect.groupId;
        setReadback(resume.readback);
        setLookupId(resume.readback.effect.groupId);
        setCatalogueEpoch((value) => value + 1);
        setMessage(`Group change already committed. Operation: ${resume.operationId}`);
      })
      .catch(() => {
        // Preserve the bound review when authoritative status cannot be reconciled safely.
      });
    return () => {
      controller.abort();
      if (resumeController.current === controller) {
        resumeGeneration.current += 1;
        resumeController.current = undefined;
      }
    };
  }, [review, state]);
  async function run(work: () => Promise<void>) {
    if (!mounted.current || locked.current) return;
    locked.current = true;
    const token: NonNullable<typeof operation.current> = {
      generation: ++operationGeneration.current,
      actor: JSON.stringify(actor.current),
      controller: new AbortController(),
    };
    operation.current = token;
    setBusy(true);
    setError('');
    setMessage('');
    try {
      await work();
    } catch (cause) {
      if (isCurrent(token)) setError(failureMessage(cause));
      else if (
        mounted.current &&
        operation.current === token &&
        !actor.current &&
        token.readFailure !== undefined
      )
        setError(failureMessage(token.readFailure));
    } finally {
      if (operation.current === token) operation.current = undefined;
      locked.current = false;
      if (mounted.current) setBusy(false);
    }
  }
  async function post(body: unknown) {
    const token = assertOperation();
    const result = await json(
      await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      }),
    );
    assertOperation();
    // The original command response passed its frontier; subsequent owner reads
    // retain actor/lifecycle fencing without treating an accepted update as a new intent.
    token.selection = undefined;
    return result;
  }
  async function readSaved(id: string | undefined, originatingActor: State['actor'] | undefined) {
    if (!mounted.current || !id || !originatingActor) return;
    const binding = JSON.stringify(originatingActor);
    if (binding !== JSON.stringify(actor.current)) return;
    cancelReadback();
    cancelResume();
    const generation = readGeneration.current;
    const controller = new AbortController();
    readController.current = controller;
    readTarget.current = id;
    setReadback(undefined);
    function stale() {
      return (
        controller.signal.aborted ||
        generation !== readGeneration.current ||
        binding !== JSON.stringify(actor.current)
      );
    }
    try {
      const value = await json(
        await fetch(`${endpoint}?groupId=${encodeURIComponent(id)}`, {
          cache: 'no-store',
          signal: controller.signal,
        }),
      );
      if (stale()) return;
      const result = groupReadback.parse(value);
      if (
        result.effect.groupId !== id ||
        result.effect.participantId !== originatingActor.participantId
      )
        throw new WorkflowFailure('readback');
      setReadback(result);
    } catch (cause) {
      if (stale()) return;
      throw cause;
    } finally {
      if (readController.current === controller) readController.current = undefined;
    }
  }
  async function prepare() {
    if (!state) return;
    const input =
      mutation === 'CREATE' || mutation === 'RENAME'
        ? { mutation, ...(groupId ? { groupId } : {}), groupName }
        : mutation === 'ADD_MEMBER' || mutation === 'REMOVE_MEMBER'
          ? { mutation, groupId, principalId }
          : { mutation, groupId };
    save(
      savedGroupReview.parse(
        await post({
          command: 'PREPARE',
          input,
          checkerPrincipalId: checker,
          reason,
          expectedSessionId: state.actor.sessionId,
        }),
      ),
    );
    setReadback(undefined);
    setMessage('Review the exact group change, then request independent approval.');
  }
  async function submit() {
    if (!review) return;
    if (Date.parse(review.review.expiresAt) <= Date.now()) throw new WorkflowFailure('expired');
    setMessage('Verify with the registered authenticator before the group request is staged.');
    try {
      await verify(review.review.stepUp, review);
    } catch {
      throw new WorkflowFailure('webauthn');
    }
    const result = z
      .object({
        reviewToken: savedGroupReview.shape.reviewToken,
        review: savedGroupReview.shape.review,
        approval: z.object({ approvalRequestId: z.string() }),
      })
      .parse(await post({ command: 'SUBMIT', reviewToken: review.reviewToken }));
    save({
      reviewToken: result.reviewToken,
      review: result.review,
      approvalRequestId: result.approval.approvalRequestId.slice(-36),
    });
    setLane('maker');
    await load('maker');
    assertOperation();
    setMessage('Approval requested. The assigned checker must review it in their own session.');
  }
  async function commit() {
    if (!review?.approvalRequestId) return;
    const originatingActor = JSON.stringify(actor.current);
    const selectedReview = review;
    const fresh = await load('maker');
    if (
      !fresh ||
      JSON.stringify(fresh.actor) !== originatingActor ||
      reviewRef.current !== selectedReview
    )
      return;
    const consumed = fresh.approvals.some(
      (item) =>
        item.approvalRequestId.endsWith(review.approvalRequestId!) &&
        item.proposal.state === 'CONSUMED',
    );
    if (!consumed) await verify(review.review.stepUp, review);
    if (reviewRef.current !== selectedReview || JSON.stringify(actor.current) !== originatingActor)
      return;
    try {
      const result = z
        .object({
          truthState: z.enum(['SUCCESS', 'WRITE_AMBIGUITY']),
          operationId: z.uuid().optional(),
          readback: groupReadback.optional(),
        })
        .parse(
          await post({
            command: 'COMMIT',
            reviewToken: review.reviewToken,
            approvalRequestId: review.approvalRequestId,
          }),
        );
      if (
        reviewRef.current !== selectedReview ||
        JSON.stringify(actor.current) !== originatingActor
      )
        return;
      if (
        result.readback &&
        (result.readback.effect.groupId !== selectedReview.review.candidate.groupId ||
          result.readback.effect.participantId !== fresh.actor.participantId)
      )
        throw new WorkflowFailure('readback');
      if (result.readback) setReadback(result.readback);
      await load('maker');
      assertOperation();
      if (result.truthState === 'SUCCESS') {
        if (!result.readback) throw new WorkflowFailure('unconfirmed');
        if (
          JSON.stringify(actor.current) !== originatingActor ||
          (reviewRef.current && reviewRef.current !== selectedReview)
        )
          return;
        clearBoundPolicyState(storageKey);
        reviewRef.current = undefined;
        setReview(undefined);
        setLookupId(result.readback.effect.groupId);
        setCatalogueEpoch((value) => value + 1);
      }
      setMessage(
        result.truthState === 'SUCCESS'
          ? `Group change committed. Operation: ${result.operationId}`
          : 'The response is uncertain. Read the saved operation before retrying.',
      );
    } catch (cause) {
      await load('maker');
      assertOperation();
      throw cause;
    }
  }
  const consumed = state?.approvals.some(
    (item) =>
      item.approvalRequestId.endsWith(review?.approvalRequestId ?? 'no-request') &&
      item.proposal.state === 'CONSUMED',
  );
  return (
    <section aria-label="Participant group lifecycle" className="grid min-w-0 gap-4">
      <LocalSessionSurface />
      <div className={panel}>
        <h2 className="text-xl font-semibold">Participant groups</h2>
        <p>
          Create and maintain Participant-local groups with independent approval. Group membership
          adds no permissions by itself.
        </p>
        <p>
          Removing a member or retiring a group revokes explicit assignments that depend on that
          membership, including their delegations.
        </p>
        {state && (
          <p className="break-all text-sm">Signed-in principal: {state.actor.principalId}</p>
        )}
      </div>
      {error && (
        <p role="alert" className="break-words text-[color:var(--danger)]">
          {error}
        </p>
      )}
      {message && (
        <p role="status" className="break-all">
          {message}
        </p>
      )}
      {state && (
        <GroupCatalogue
          actor={state.actor}
          refreshEpoch={catalogueEpoch}
          onOpen={(id) => {
            void run(async () => {
              setLookupId(id);
              await readSaved(id, actor.current);
            });
          }}
        />
      )}
      <form
        className={`${panel} grid gap-3`}
        onSubmit={(event) => {
          event.preventDefault();
          void run(prepare);
        }}
      >
        <h3 className="font-semibold">Prepare a group change</h3>
        <label>
          Change
          <select
            className={field}
            value={mutation}
            disabled={busy}
            onChange={(event) => setMutation(event.target.value as typeof mutation)}
          >
            <option value="CREATE">Create group</option>
            <option value="RENAME">Rename group</option>
            <option value="ADD_MEMBER">Add member</option>
            <option value="REMOVE_MEMBER">Remove member</option>
            <option value="RETIRE">Retire group</option>
          </select>
        </label>
        <label>
          Group ID
          <input
            className={field}
            required={mutation !== 'CREATE'}
            placeholder={
              mutation === 'CREATE' ? 'Generated when you prepare the change' : undefined
            }
            value={groupId}
            onChange={(event) => setGroupId(event.target.value)}
          />
        </label>
        {(mutation === 'CREATE' || mutation === 'RENAME') && (
          <label>
            Group name
            <input
              className={field}
              required
              maxLength={160}
              value={groupName}
              onChange={(event) => setGroupName(event.target.value)}
            />
          </label>
        )}
        {(mutation === 'ADD_MEMBER' || mutation === 'REMOVE_MEMBER') && (
          <label>
            Member principal ID
            <input
              className={field}
              required
              value={principalId}
              onChange={(event) => setPrincipalId(event.target.value)}
            />
          </label>
        )}
        <label>
          Checker principal ID
          <input
            className={field}
            required
            value={checker}
            onChange={(event) => setChecker(event.target.value)}
          />
        </label>
        <label>
          Reason for group change
          <textarea
            className={field}
            required
            minLength={10}
            maxLength={1024}
            value={reason}
            onChange={(event) => setReason(event.target.value)}
          />
        </label>
        <button className={button} disabled={busy || !state}>
          Prepare group change
        </button>
      </form>
      {review && (
        <div aria-label="Group change review" className={`${panel} grid gap-3 break-all`}>
          <h3 className="font-semibold">Review {review.review.mutation.toLowerCase()}</h3>
          <dl>
            <dt>Group</dt>
            <dd>{review.review.candidate.groupId}</dd>
            <dt>Resource revision</dt>
            <dd>{review.review.expectedRevision}</dd>
            <dt>Checker</dt>
            <dd>{review.review.checkerPrincipalId}</dd>
            <dt>Reason</dt>
            <dd>{review.review.reason}</dd>
            <dt>Candidate digest</dt>
            <dd>{review.review.candidateDigest}</dd>
          </dl>
          <pre className="whitespace-pre-wrap break-all text-sm">
            {JSON.stringify(review.review.candidate, null, 2)}
          </pre>
          <p>
            Review expires:{' '}
            <time dateTime={review.review.expiresAt}>{review.review.expiresAt}</time>
          </p>
          {review.approvalRequestId && <p>Approval request: {review.approvalRequestId}</p>}
          <div className="flex flex-wrap gap-2">
            <button
              type="button"
              className={button}
              disabled={busy || !!review.approvalRequestId || consumed}
              onClick={() => void run(submit)}
            >
              Verify and request group approval
            </button>
            <button
              type="button"
              className={button}
              disabled={busy || !review.approvalRequestId || consumed}
              onClick={() => void run(commit)}
            >
              Verify and commit group change
            </button>
            <button
              type="button"
              className={button}
              disabled={busy}
              onClick={() =>
                void run(async () => {
                  const originatingActor = actor.current;
                  const fresh = await load('maker');
                  if (fresh) await readSaved(review.review.candidate.groupId, originatingActor);
                })
              }
            >
              Read saved group
            </button>
          </div>
        </div>
      )}
      <div className={`${panel} grid gap-3`}>
        <h3 className="font-semibold">Read group and membership history</h3>
        <label>
          Saved group ID
          <input
            className={field}
            value={lookupId}
            onChange={(event) => setLookupId(event.target.value)}
          />
        </label>
        <button
          type="button"
          className={button}
          disabled={busy || !state || !lookupId}
          onClick={() =>
            void run(async () => {
              const originatingActor = actor.current;
              const fresh = await load();
              if (fresh) await readSaved(lookupId, originatingActor);
            })
          }
        >
          Read group
        </button>
        {readback && (
          <div aria-label="Group result" className="grid gap-2 break-all">
            <p>Group: {readback.effect.groupName}</p>
            <p>ID: {readback.effect.groupId}</p>
            <p>
              State: {readback.effect.state} · revision {readback.effect.revision}
            </p>
            <p>Operation: {readback.effect.operationId ?? 'No recorded mutation'}</p>
            {readback.members.length === 0 && <p>No membership history on this page.</p>}
            {readback.members.map((member) => (
              <article key={member.memberId} className={panel}>
                <h4 className="font-semibold">{member.displayName}</h4>
                <p>Principal: {member.principalId}</p>
                <p>
                  {member.current ? 'Current member' : 'Inactive membership'} · {member.state}
                </p>
                <p>Joined: {member.joinedAt}</p>
                {member.revokedAt && <p>Ended: {member.revokedAt}</p>}
              </article>
            ))}
            {readback.nextCursor && (
              <button
                className={button}
                disabled={busy}
                onClick={() =>
                  void run(async () => {
                    const next = groupReadback.parse(
                      await json(
                        await fetch(
                          `${endpoint}?${new URLSearchParams({ groupId: readback.effect.groupId, memberCursor: readback.nextCursor! })}`,
                          { cache: 'no-store' },
                        ),
                      ),
                    );
                    if (
                      next.effect.groupId !== readback.effect.groupId ||
                      next.effect.participantId !== actor.current?.participantId
                    )
                      throw new WorkflowFailure('changed');
                    setReadback(next);
                  })
                }
              >
                Next memberships
              </button>
            )}
          </div>
        )}
      </div>
      <div className={`${panel} grid gap-3`}>
        <h3 className="font-semibold">Group approvals</h3>
        <label>
          Approval lane
          <select
            className={field}
            value={lane}
            disabled={busy}
            onChange={(event) => {
              const selected = event.target.value as typeof lane;
              setLane(selected);
              void run(async () => {
                await load(selected);
                assertOperation();
              });
            }}
          >
            <option value="checker">Assigned to me</option>
            <option value="maker">Requested by me</option>
          </select>
        </label>
        <button
          type="button"
          className={button}
          disabled={busy}
          onClick={() =>
            void run(async () => {
              await load();
              assertOperation();
            })
          }
        >
          Refresh group approvals
        </button>
        {state?.approvals.length === 0 && <p>No group approvals on this page.</p>}
        {state?.approvals.map((item) => (
          <article key={item.approvalRequestId} className={`${panel} grid gap-2 break-all`}>
            <h4 className="font-semibold">
              {item.proposal.catalogOperationId.replace('ID-OP-GROUP-', '')} · {item.state}
            </h4>
            <p>Approval request: {item.approvalRequestId}</p>
            <p>Maker: {item.makerSubjectRef}</p>
            <p>Candidate digest: {item.candidateDigest}</p>
            <p>Resource revision: {item.proposal.expectedRevision}</p>
            <p>Reason: {item.proposal.approval?.reason}</p>
            <pre className="whitespace-pre-wrap break-all text-sm">
              {JSON.stringify(item.proposal.candidate, null, 2)}
            </pre>
            <p>Operation: {item.proposal.operationId ?? 'Not committed'}</p>
            {lane === 'checker' && (
              <button
                type="button"
                className={button}
                disabled={busy || item.state !== 'REQUESTED'}
                onClick={() =>
                  void run(async () => {
                    await verify(item.stepUp, item);
                    await post({
                      command: 'APPROVE',
                      approvalRequestId: item.approvalRequestId.slice(-36),
                      candidateDigest: item.candidateDigest,
                      expectedRevision: item.revision,
                    });
                    await load();
                    assertOperation();
                    setMessage('The group change is approved. The maker can now commit it.');
                  })
                }
              >
                Verify and approve group change
              </button>
            )}
          </article>
        ))}
        {state?.nextCursor && (
          <button
            type="button"
            className={button}
            disabled={busy}
            onClick={() =>
              void run(async () => {
                await load(lane, state.nextCursor!);
                assertOperation();
              })
            }
          >
            Next group approvals
          </button>
        )}
      </div>
    </section>
  );
}
