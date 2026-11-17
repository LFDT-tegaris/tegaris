'use client';
import { useEffect, useLayoutEffect, useRef, useState } from 'react';
import { z } from 'zod';
import { performWebAuthnStepUp } from '@openpc/ui-shell';
import {
  savedWorkloadReview,
  workloadCertificate,
  workloadState,
  type WorkloadReview,
} from '../lib/workload-workflow';
import { readBoundPolicyState, writeBoundPolicyState } from './policy-workflow-storage';
import { LocalSessionSurface } from './local-session';
import { PrincipalCatalogue } from './principal-catalogue';
const endpoint = '/api/v1/ui/workload-workbench';
const storageKey = 'openpc:workload-workflow:v1';
const pendingKey = `${storageKey}:original`;
const pendingCommand = z.strictObject({
  command: z.enum(['SUBMIT', 'COMMIT', 'APPROVE']),
  candidateDigest: savedWorkloadReview.shape.review.shape.candidateDigest,
  expectedRevision: savedWorkloadReview.shape.review.shape.expectedRevision,
  approvalRequestId: z.uuid().optional(),
});
type Pending = z.infer<typeof pendingCommand>;
function originalStorageKey(actor: z.infer<typeof workloadState>['actor']) {
  return `${pendingKey}:${actor.principalId}:${actor.participantId}:${actor.privacyDomainId}`;
}
function readPending(actor: z.infer<typeof workloadState>['actor']): Pending | undefined {
  try {
    const raw = localStorage.getItem(originalStorageKey(actor));
    if (!raw) return;
    const stored = z
      .strictObject({
        actor: workloadState.shape.actor,
        value: pendingCommand.nullable(),
      })
      .parse(JSON.parse(raw));
    // A replacement session may observe the selector, never reuse old authority.
    // The current public owner must confirm its outcome before another mutation.
    if (
      stored.actor.principalId === actor.principalId &&
      stored.actor.participantId === actor.participantId &&
      stored.actor.privacyDomainId === actor.privacyDomainId
    )
      return stored.value ?? undefined;
  } catch {
    /* Browser storage is optional; no raw storage data is displayed. */
  }
}
const panel = 'min-w-0 rounded border border-[color:var(--border)] bg-[color:var(--surface)] p-4';
const field =
  'min-w-0 w-full rounded border border-[color:var(--border)] bg-[color:var(--canvas)] p-2';
const button =
  'w-fit rounded bg-[color:var(--accent)] px-3 py-2 font-medium text-[color:var(--surface)] disabled:opacity-60';
type State = z.infer<typeof workloadState>;
type Certificate = z.infer<typeof workloadCertificate>;
const failureMessages = {
  unavailable: 'Workload request could not be confirmed. Read the saved operation before retrying.',
  authorization:
    'Workload request was not authorized. Refresh the authenticated context before continuing.',
  conflict: 'Workload state changed. Refresh or read the original operation before retrying.',
  input: 'Workload request was rejected. Check the inputs before continuing.',
  readback: 'Certificate readback belongs to a different context.',
} as const;
class WorkflowFailure extends Error {
  constructor(readonly kind: keyof typeof failureMessages) {
    super(failureMessages[kind]);
  }
}
function failureMessage(cause: unknown) {
  return cause instanceof WorkflowFailure
    ? failureMessages[cause.kind]
    : failureMessages.unavailable;
}
async function json(response: Response): Promise<unknown> {
  const value = await response.json().catch(() => undefined);
  if (!response.ok)
    throw new WorkflowFailure(
      [401, 403, 404].includes(response.status)
        ? 'authorization'
        : [409, 412, 428].includes(response.status)
          ? 'conflict'
          : [400, 422].includes(response.status)
            ? 'input'
            : 'unavailable',
    );
  if (value === undefined) throw new WorkflowFailure('unavailable');
  return value;
}
function workloadTime(value: string) {
  return `${new Intl.DateTimeFormat('en-GB', { day: '2-digit', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit', hourCycle: 'h23', timeZone: 'UTC' }).format(new Date(value))} UTC`;
}
function workloadChangeLabel(
  operation: State['approvals'][number]['proposal']['catalogOperationId'],
) {
  return {
    'ID-OP-WORKLOAD-ISSUE': 'Issue certificate',
    'ID-OP-WORKLOAD-ROTATE': 'Rotate certificate',
    'ID-OP-WORKLOAD-REVOKE': 'Revoke certificate',
  }[operation];
}
export function WorkloadWorkflow() {
  const [view, setView] = useState<'certificates' | 'changes' | 'approvals' | 'recovery'>(
    'certificates',
  );
  const [state, setState] = useState<State>();
  const [review, setReview] = useState<WorkloadReview>();
  const [readback, setReadback] = useState<Certificate>();
  const [lane, setLane] = useState<'maker' | 'checker'>('checker');
  const [mutation, setMutation] = useState<'ISSUE' | 'ROTATE' | 'REVOKE'>('ISSUE');
  const [credentialId, setCredentialId] = useState('');
  const [replacedId, setReplacedId] = useState('');
  const [principalId, setPrincipalId] = useState('');
  const [workloadId, setWorkloadId] = useState('');
  const [publicKey, setPublicKey] = useState('');
  const [checker, setChecker] = useState('');
  const [checkerKind, setCheckerKind] = useState<'USER' | 'PLATFORM_OPERATOR'>('USER');
  const [principalLabel, setPrincipalLabel] = useState('');
  const [checkerLabel, setCheckerLabel] = useState('');
  const [chooser, setChooser] = useState<'workload' | 'checker'>();
  const principalChoiceButton = useRef<HTMLButtonElement>(null);
  const checkerChoiceButton = useRef<HTMLButtonElement>(null);
  const [reason, setReason] = useState('');
  const [lookupId, setLookupId] = useState('');
  const [originalId, setOriginalId] = useState('');
  const [pending, setPending] = useState<Pending>();
  const pendingRef = useRef<Pending | undefined>(undefined);
  const errorRef = useRef<HTMLParagraphElement>(null);
  const certificateHeading = useRef<HTMLHeadingElement>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [message, setMessage] = useState('');
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
      }
    | undefined
  >(undefined);
  const approvalsRef = useRef<State['approvals']>([]);
  const reviewRef = useRef<WorkloadReview | undefined>(undefined);
  useLayoutEffect(() => {
    if (readback) certificateHeading.current?.focus();
  }, [readback]);
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
    selected: WorkloadReview | State['approvals'][number],
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

  const loadGeneration = useRef(0);
  const loadController = useRef<AbortController | undefined>(undefined);
  const certificateGeneration = useRef(0);
  const certificateController = useRef<AbortController | undefined>(undefined);
  function cancelCertificateRead() {
    certificateGeneration.current += 1;
    certificateController.current?.abort();
  }
  function save(value: WorkloadReview) {
    if (!actor.current) return;
    reviewRef.current = value;
    setReview(value);
    writeBoundPolicyState(storageKey, actor.current, value);
  }
  function retain(value: Pending | undefined) {
    pendingRef.current = value;
    setPending(value);
    if (actor.current)
      writeBoundPolicyState(originalStorageKey(actor.current), actor.current, value ?? null);
  }
  function clearVisibleContext() {
    if (actor.current) setView('certificates');
    cancelOperation();
    cancelCertificateRead();
    approvalsRef.current = [];
    reviewRef.current = undefined;
    pendingRef.current = undefined;
    actor.current = undefined;
    setState(undefined);
    setReview(undefined);
    setPending(undefined);
    setReadback(undefined);
    setChooser(undefined);
    setPrincipalId('');
    setChecker('');
    setPrincipalLabel('');
    setCheckerLabel('');
    setCredentialId('');
    setReplacedId('');
    setWorkloadId('');
    setPublicKey('');
    setReason('');
    setLookupId('');
    setOriginalId('');
    setMessage('');
  }
  function adopt(value: State) {
    approvalsRef.current = value.approvals;
    if (operation.current?.selection && !operation.current.selection())
      operation.current.controller.abort();
    if (JSON.stringify(actor.current) !== JSON.stringify(value.actor)) {
      clearVisibleContext();
      actor.current = value.actor;
      approvalsRef.current = value.approvals;
      const saved = readBoundPolicyState(
        storageKey,
        value.actor,
        (stored): stored is WorkloadReview => savedWorkloadReview.safeParse(stored).success,
      );
      reviewRef.current = saved;
      setReview(saved);
      setReadback(undefined);
      const retained = readPending(value.actor);
      pendingRef.current = retained;
      setPending(retained);
    }
    setState(value);
    return value;
  }
  async function load(selected = lane, cursor?: string, original?: URLSearchParams) {
    if (!mounted.current) return;
    const generation = ++loadGeneration.current;
    loadController.current?.abort();
    cancelCertificateRead();
    const controller = new AbortController();
    loadController.current = controller;
    try {
      const value = await json(
        await fetch(
          `${endpoint}?${original ?? new URLSearchParams({ lane: selected, ...(cursor ? { cursor } : {}) })}`,
          { cache: 'no-store', signal: controller.signal },
        ),
      );
      if (!mounted.current || generation !== loadGeneration.current || controller.signal.aborted)
        return;
      return adopt(workloadState.parse(value));
    } catch (cause) {
      if (!mounted.current || generation !== loadGeneration.current || controller.signal.aborted)
        return;
      if (cause instanceof WorkflowFailure && cause.kind === 'authorization') {
        clearVisibleContext();
        setError(failureMessage(cause));
      }
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
      cancelCertificateRead();
    };
  }, []);
  useEffect(() => {
    if (error) errorRef.current?.focus();
  }, [error]);
  useEffect(() => {
    let current = true;
    void load('checker').catch((cause: unknown) => {
      if (current && mounted.current) setError(failureMessage(cause));
    });
    return () => {
      current = false;
    };
  }, []);
  async function run(work: () => Promise<void>) {
    if (!mounted.current || locked.current) return;
    locked.current = true;
    const token = {
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
      if (isCurrent(token) && pendingRef.current) {
        // A failed response is not a no-effect receipt. Reconcile only by GET;
        // an unavailable/denied read leaves the original custody intact.
        try {
          await readOriginal();
        } catch {
          /* Preserve the original failure. */
        }
      }
      if (isCurrent(token)) setError(failureMessage(cause));
    } finally {
      if (operation.current === token) operation.current = undefined;
      locked.current = false;
      if (mounted.current) setBusy(false);
    }
  }
  async function post(body: unknown, original?: Pending) {
    const token = assertOperation();
    if (pendingRef.current) throw new WorkflowFailure('unavailable');
    if (original) {
      retain(original);
      // Once dispatched, the captured original owns reconciliation. Its own
      // accepted update may change the catalogue even when the response is lost.
      token.selection = undefined;
    }
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
    cancelCertificateRead();
    const generation = certificateGeneration.current;
    const controller = new AbortController();
    certificateController.current = controller;
    setReadback(undefined);
    function stale() {
      return (
        generation !== certificateGeneration.current ||
        controller.signal.aborted ||
        binding !== JSON.stringify(actor.current)
      );
    }
    try {
      const value = await json(
        await fetch(`${endpoint}?credentialId=${encodeURIComponent(id)}`, {
          cache: 'no-store',
          signal: controller.signal,
        }),
      );
      if (stale()) return;
      const result = workloadCertificate.parse(value);
      if (result.credentialId !== id || result.participantId !== originatingActor.participantId)
        throw new WorkflowFailure('readback');
      setReadback(result);
      setView('certificates');
    } catch (cause) {
      if (stale()) return;
      throw cause;
    } finally {
      if (certificateController.current === controller) certificateController.current = undefined;
    }
  }
  async function prepare() {
    if (!state) return;
    const input =
      mutation === 'ISSUE'
        ? { mutation, credentialId, principalId, workloadId, publicKeySpkiDer: publicKey.trim() }
        : mutation === 'ROTATE'
          ? {
              mutation,
              credentialId,
              replacedCredentialId: replacedId,
              publicKeySpkiDer: publicKey.trim(),
            }
          : { mutation, credentialId };
    save(
      savedWorkloadReview.parse(
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
    setMessage('Review the exact workload change, then request independent approval.');
  }
  async function submit() {
    if (!review) return;
    const result = z
      .object({
        reviewToken: savedWorkloadReview.shape.reviewToken,
        review: savedWorkloadReview.shape.review,
        approval: z.object({ approvalRequestId: z.string() }),
      })
      .parse(
        await post(
          { command: 'SUBMIT', reviewToken: review.reviewToken },
          {
            command: 'SUBMIT',
            candidateDigest: review.review.candidateDigest,
            expectedRevision: review.review.expectedRevision,
          },
        ),
      );
    if (
      JSON.stringify(result.review) !== JSON.stringify(review.review) ||
      !z.uuid().safeParse(result.approval.approvalRequestId.slice(-36)).success
    )
      throw new WorkflowFailure('unavailable');
    save({
      reviewToken: review.reviewToken,
      review: result.review,
      approvalRequestId: result.approval.approvalRequestId.slice(-36),
    });
    retain(undefined);
    setLane('maker');
    await load('maker');
    assertOperation();
    setMessage('Approval requested. The assigned checker must review it in their own session.');
  }
  async function commit() {
    if (!review?.approvalRequestId) return;
    const originatingActor = actor.current;
    const selectedReview = review;
    const fresh = await load(
      'maker',
      undefined,
      new URLSearchParams({
        originalApprovalRequestId: review.approvalRequestId,
      }),
    );
    if (
      !fresh ||
      JSON.stringify(fresh.actor) !== JSON.stringify(originatingActor) ||
      reviewRef.current !== selectedReview
    )
      return;
    const original = fresh.approvals.find(
      (item) =>
        item.approvalRequestId === `urn:openpc:resource:${review.approvalRequestId}` &&
        item.candidateDigest === review.review.candidateDigest &&
        item.proposal.candidateDigest === review.review.candidateDigest &&
        item.proposal.expectedRevision === review.review.expectedRevision &&
        item.proposal.resourceId === review.review.resourceId &&
        item.makerSubjectRef === `urn:openpc:resource:${fresh.actor.principalId}` &&
        item.checkerSubjectRef === `urn:openpc:resource:${review.review.checkerPrincipalId}`,
    );
    if (!original) throw new WorkflowFailure('conflict');
    if (original.proposal.state === 'CONSUMED') {
      if (!original.proposal.operationId) throw new WorkflowFailure('unavailable');
      setMessage(
        `Original workload operation committed: ${original.proposal.operationId}. Certificate readback is available separately.`,
      );
      return;
    }
    if (original.state !== 'APPROVED') throw new WorkflowFailure('conflict');
    await verify(review.review.stepUp, review);
    try {
      const result = z
        .object({
          truthState: z.enum(['SUCCESS', 'WRITE_AMBIGUITY']),
          operationId: z.uuid().optional(),
          readback: workloadCertificate.optional(),
        })
        .parse(
          await post(
            {
              command: 'COMMIT',
              reviewToken: review.reviewToken,
              approvalRequestId: review.approvalRequestId,
            },
            {
              command: 'COMMIT',
              candidateDigest: review.review.candidateDigest,
              expectedRevision: review.review.expectedRevision,
              approvalRequestId: review.approvalRequestId,
            },
          ),
        );
      if (
        result.readback &&
        (result.readback.credentialId !== selectedReview.review.candidate.credentialId ||
          result.readback.participantId !== fresh.actor.participantId)
      )
        throw new WorkflowFailure('readback');
      if (result.readback) {
        setReadback(result.readback);
        setView('certificates');
      }
      if (result.truthState === 'SUCCESS' && result.operationId && result.readback)
        retain(undefined);
      else if (result.truthState === 'SUCCESS') throw new WorkflowFailure('unavailable');
      await load('maker');
      assertOperation();
      setMessage(
        result.truthState === 'SUCCESS'
          ? `Workload change committed. Operation: ${result.operationId}`
          : 'The response is uncertain. Read the saved operation before retrying.',
      );
    } catch (cause) {
      await load('maker');
      assertOperation();
      throw cause;
    }
  }
  async function readOriginal(id?: string) {
    const original = pendingRef.current;
    const saved = reviewRef.current;
    const approvalId = original ? original.approvalRequestId : (id ?? saved?.approvalRequestId);
    if (approvalId && !z.uuid().safeParse(approvalId).success) throw new WorkflowFailure('input');
    const selector = approvalId
      ? new URLSearchParams({ originalApprovalRequestId: approvalId })
      : original
        ? new URLSearchParams({
            candidateDigest: original.candidateDigest,
            expectedRevision: original.expectedRevision,
          })
        : undefined;
    if (!selector) throw new WorkflowFailure('input');
    const binding = JSON.stringify(actor.current);
    const fresh = await load('maker', undefined, selector);
    if (!fresh || JSON.stringify(fresh.actor) !== binding) return;
    assertOperation();
    const item = fresh.approvals.find(
      (entry) =>
        (!approvalId || entry.approvalRequestId === `urn:openpc:resource:${approvalId}`) &&
        entry.candidateDigest === entry.proposal.candidateDigest &&
        (!original ||
          (entry.candidateDigest === original.candidateDigest &&
            entry.proposal.expectedRevision === original.expectedRevision &&
            (original.command === 'APPROVE' ? entry.checkerSubjectRef : entry.makerSubjectRef) ===
              `urn:openpc:resource:${fresh.actor.principalId}`)),
    );
    if (!item) {
      setMessage('The original operation is still unresolved. No new workload mutation was sent.');
      return;
    }
    if (
      original &&
      original.command !== 'APPROVE' &&
      saved &&
      (item.proposal.resourceId !== saved.review.resourceId ||
        item.proposal.makerPrincipalId !== fresh.actor.principalId ||
        item.checkerSubjectRef !== `urn:openpc:resource:${saved.review.checkerPrincipalId}` ||
        item.proposal.catalogOperationId !== `ID-OP-WORKLOAD-${saved.review.mutation}` ||
        JSON.stringify(item.proposal.candidate) !== JSON.stringify(saved.review.candidate))
    )
      throw new WorkflowFailure('readback');
    const resolved =
      original?.command === 'SUBMIT' ||
      (original?.command === 'APPROVE' && item.state === 'APPROVED') ||
      (original?.command === 'COMMIT' &&
        item.proposal.state === 'CONSUMED' &&
        !!item.proposal.operationId);
    if (resolved) {
      if (saved && original?.command !== 'APPROVE')
        save({ ...saved, approvalRequestId: item.approvalRequestId.slice(-36) });
      retain(undefined);
    }
    setMessage(
      item.proposal.state === 'CONSUMED' && item.proposal.operationId
        ? `Original workload operation committed: ${item.proposal.operationId}. Certificate readback is available separately.`
        : original && !resolved
          ? 'The original operation is still unresolved. No new workload mutation was sent.'
          : `Original workload approval: ${item.state}. The workload effect is not confirmed.`,
    );
  }
  const consumed = state?.approvals.some(
    (item) =>
      item.approvalRequestId.endsWith(review?.approvalRequestId ?? 'no-request') &&
      item.proposal.state === 'CONSUMED',
  );
  return (
    <section
      aria-label="Workload credential lifecycle"
      className="workload-workspace grid min-w-0 gap-4"
    >
      <LocalSessionSurface />
      <div className={panel}>
        <h2 className="text-xl font-semibold">Workload certificates</h2>
        <p className="workload-description">
          Manage service certificates, review changes and confirm their saved status.
        </p>
        <details className="workload-audit">
          <summary>Session details</summary>
          {state && (
            <p className="break-all text-sm">Signed-in principal: {state.actor.principalId}</p>
          )}
        </details>
      </div>
      <nav className="feature-navigation" aria-label="Certificate workflow views">
        {(
          [
            ['certificates', 'Certificates'],
            ['changes', 'Changes'],
            ['approvals', 'Approvals'],
            ['recovery', 'Recovery'],
          ] as const
        ).map(([key, label]) => (
          <button
            key={key}
            type="button"
            aria-current={view === key ? 'page' : undefined}
            onClick={() => setView(key)}
          >
            {label}
          </button>
        ))}
      </nav>
      {error && (
        <p
          ref={errorRef}
          tabIndex={-1}
          role="alert"
          className="break-words text-[color:var(--danger)]"
        >
          {error}
        </p>
      )}
      {message && (
        <p role="status" className="break-all">
          {message}
        </p>
      )}
      {pending && (
        <div role="status" className={`${panel} grid gap-2 break-all`}>
          <p>
            The original {pending.command.toLowerCase()} outcome is unresolved. Further workload
            changes are blocked.
          </p>
          <button
            type="button"
            className={button}
            disabled={busy || !state}
            onClick={() => void run(() => readOriginal())}
          >
            Read original workload outcome
          </button>
        </div>
      )}
      <section
        className="workload-certificate-panel"
        aria-label="Certificate records"
        hidden={view !== 'certificates'}
      >
        <div className="workload-records-heading">
          <div>
            <h3 className="font-semibold">Certificate requests</h3>
            <p className="workload-description">
              Open an executed request to confirm its certificate and current state.
            </p>
          </div>
          <button
            type="button"
            className={button}
            disabled={busy || !state}
            onClick={() =>
              void run(async () => {
                setLane('maker');
                await load('maker');
                assertOperation();
              })
            }
          >
            Browse my requests
          </button>
        </div>
        {state && (
          <div className="workload-records-table">
            <table>
              <caption>
                {lane === 'maker' ? 'My certificate requests' : 'Assigned certificate requests'}
              </caption>
              <thead>
                <tr>
                  <th scope="col">Certificate</th>
                  <th scope="col">Change</th>
                  <th scope="col">Request status</th>
                  <th scope="col">Action</th>
                </tr>
              </thead>
              <tbody>
                {state.approvals.length === 0 ? (
                  <tr>
                    <td colSpan={4}>No certificate requests in this selection.</td>
                  </tr>
                ) : (
                  state.approvals.map((item) => (
                    <tr key={item.approvalRequestId}>
                      <th scope="row">
                        Certificate #{item.proposal.candidate.credentialId.slice(-8)}
                      </th>
                      <td>{workloadChangeLabel(item.proposal.catalogOperationId)}</td>
                      <td>
                        {item.proposal.state === 'CONSUMED'
                          ? 'Executed'
                          : item.state === 'APPROVED'
                            ? 'Approved — awaiting execution'
                            : item.state.replaceAll('_', ' ')}
                      </td>
                      <td>
                        <button
                          type="button"
                          className={button}
                          disabled={busy || item.proposal.state !== 'CONSUMED'}
                          onClick={() =>
                            void run(async () => {
                              const originatingActor = actor.current;
                              const fresh = await load();
                              if (fresh)
                                await readSaved(
                                  item.proposal.candidate.credentialId,
                                  originatingActor,
                                );
                            })
                          }
                        >
                          Open certificate #{item.proposal.candidate.credentialId.slice(-8)}
                        </button>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
            {state.nextCursor && (
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
                Next certificate requests
              </button>
            )}
          </div>
        )}
        <h3 className="font-semibold">Certificate record</h3>
        <p className="workload-description">
          Look up a saved certificate to check its status, validity and public download.
        </p>
        {!readback && (
          <p className="workload-empty">
            No certificate selected. Enter the credential reference from your approved request.
          </p>
        )}
        <label>
          Saved credential ID
          <input
            className={field}
            value={lookupId}
            disabled={!state}
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
          Read workload certificate
        </button>
        {readback && (
          <div aria-label="Workload certificate result" className="grid gap-2 break-all">
            <div className="workload-certificate-heading">
              <h4 ref={certificateHeading} tabIndex={-1}>
                Certificate #{readback.credentialId.slice(-8)}
              </h4>
              <span className="workload-state">{readback.state.replaceAll('_', ' ')}</span>
            </div>
            <dl className="workload-certificate-summary">
              <div>
                <dt>Valid from</dt>
                <dd>
                  <time dateTime={readback.notBefore}>{workloadTime(readback.notBefore)}</time>
                </dd>
              </div>
              <div>
                <dt>Expires</dt>
                <dd>
                  <time dateTime={readback.notAfter}>{workloadTime(readback.notAfter)}</time>
                </dd>
              </div>
              <div>
                <dt>Rotate by</dt>
                <dd>
                  <time dateTime={readback.rotateAt}>{workloadTime(readback.rotateAt)}</time>
                </dd>
              </div>
            </dl>
            <p className="workload-description break-all">Credential: {readback.credentialId}</p>
            <details className="workload-audit">
              <summary>Certificate technical details</summary>
              <div className="grid gap-2 break-all">
                <p>
                  State: {readback.state} · epoch {readback.workloadEpoch} · revision{' '}
                  {readback.revision}
                </p>
                <p>Workload: {readback.workloadId}</p>
                <p>Principal: {readback.principalId}</p>
                <p>Participant: {readback.participantId}</p>
                <p>Issuer fingerprint: {readback.issuer}</p>
                <p>Certificate fingerprint: {readback.certificateFingerprint}</p>
                <p>Public-key fingerprint: {readback.keyId}</p>
              </div>
            </details>
            {readback.certificateDer ? (
              <a
                className="underline"
                download={`${readback.credentialId}.der`}
                href={`data:application/pkix-cert;base64,${readback.certificateDer}`}
              >
                Download public certificate (.der)
              </a>
            ) : (
              <p>
                This older credential has no retained certificate. Rotate it to obtain a
                downloadable replacement.
              </p>
            )}
          </div>
        )}
      </section>
      <section
        className="workload-task"
        aria-label="Certificate changes"
        hidden={view !== 'changes'}
      >
        <header className="workload-task-heading">
          <h3>Certificate changes</h3>
          <p>Issue, rotate or revoke with independent approval.</p>
        </header>
        <div className="workload-task-content">
          <form
            className="workload-change-form grid gap-3"
            onSubmit={(event) => {
              event.preventDefault();
              if (!checker || (mutation === 'ISSUE' && !principalId)) {
                setError('Choose the current workload principal and an independent checker first.');
                return;
              }
              void run(prepare);
            }}
          >
            <h3 className="font-semibold">Prepare a workload change</h3>
            <p className="workload-description">
              Choose the service and independent checker. Certificates expire within 24 hours;
              executing an approved rotation revokes the previous certificate.
            </p>
            <label>
              Change
              <select
                className={field}
                value={mutation}
                disabled={busy}
                onChange={(event) => {
                  setChooser(undefined);
                  setMutation(event.target.value as typeof mutation);
                }}
              >
                <option value="ISSUE">Issue certificate</option>
                <option value="ROTATE">Rotate certificate</option>
                <option value="REVOKE">Revoke certificate</option>
              </select>
            </label>
            <label>
              {mutation === 'REVOKE' ? 'Credential ID to revoke' : 'New credential ID'}
              <input
                className={field}
                required
                value={credentialId}
                onChange={(event) => setCredentialId(event.target.value)}
              />
            </label>
            {mutation === 'ROTATE' && (
              <label>
                Credential ID to replace
                <input
                  className={field}
                  required
                  value={replacedId}
                  onChange={(event) => setReplacedId(event.target.value)}
                />
              </label>
            )}
            {mutation === 'ISSUE' && (
              <>
                <label>
                  Workload principal ID
                  <input className={field} required readOnly value={principalId} />
                </label>
                {principalLabel && <p>Selected workload principal: {principalLabel}</p>}
                <button
                  type="button"
                  ref={principalChoiceButton}
                  className={button}
                  disabled={busy || !state}
                  onClick={() => {
                    setPrincipalId('');
                    setPrincipalLabel('');
                    setChooser('workload');
                  }}
                >
                  Choose workload principal
                </button>
                <label>
                  Workload ID
                  <input
                    className={field}
                    required
                    placeholder="urn:openpc:workload:…"
                    value={workloadId}
                    onChange={(event) => setWorkloadId(event.target.value)}
                  />
                </label>
                <a className="underline" href="/govern/memberships?view=principals">
                  Find or provision a workload principal
                </a>
              </>
            )}
            {mutation !== 'REVOKE' && (
              <label>
                Workload public key
                <span className="workload-field-help">
                  Paste the public key in base64 SPKI DER format. Keep the private key on the
                  workload.
                </span>
                <textarea
                  className={field}
                  required
                  rows={3}
                  aria-label="Workload public key"
                  value={publicKey}
                  onChange={(event) => setPublicKey(event.target.value)}
                />
              </label>
            )}
            <label>
              Checker principal type
              <select
                className={field}
                value={checkerKind}
                disabled={busy}
                onChange={(event) => {
                  setChecker('');
                  setCheckerLabel('');
                  setChooser(undefined);
                  setCheckerKind(event.target.value as 'USER' | 'PLATFORM_OPERATOR');
                }}
              >
                <option value="USER">User</option>
                <option value="PLATFORM_OPERATOR">Platform operator</option>
              </select>
            </label>
            <label>
              Checker principal ID
              <input className={field} required readOnly value={checker} />
            </label>
            {checkerLabel && <p>Selected checker: {checkerLabel}</p>}
            <button
              type="button"
              ref={checkerChoiceButton}
              className={button}
              disabled={busy || !state}
              onClick={() => {
                setChecker('');
                setCheckerLabel('');
                setChooser('checker');
              }}
            >
              Choose checker
            </button>
            <label>
              Reason for workload change
              <textarea
                className={field}
                required
                minLength={10}
                maxLength={1024}
                value={reason}
                onChange={(event) => setReason(event.target.value)}
              />
            </label>
            <button className={button} disabled={busy || !state || !!pending}>
              Prepare workload change
            </button>
          </form>
          {state && chooser && (
            <PrincipalCatalogue
              actor={state.actor}
              selection={{
                kind: chooser === 'workload' ? 'WORKLOAD' : checkerKind,
                ...(chooser === 'checker' ? { excludedPrincipalId: state.actor.principalId } : {}),
                disabled: busy,
                onSelect(id, displayLabel) {
                  if (locked.current) return;
                  if (chooser === 'workload') {
                    setPrincipalId(id);
                    setPrincipalLabel(displayLabel);
                  } else {
                    setChecker(id);
                    setCheckerLabel(displayLabel);
                  }
                  setChooser(undefined);
                  (chooser === 'workload'
                    ? principalChoiceButton
                    : checkerChoiceButton
                  ).current?.focus();
                },
              }}
            />
          )}
          {review && (
            <div aria-label="Workload change review" className={`${panel} grid gap-3 break-all`}>
              <h3 className="font-semibold">Review {review.review.mutation.toLowerCase()}</h3>
              <dl className="workload-review-summary">
                <dt>Credential</dt>
                <dd>{review.review.candidate.credentialId}</dd>
                <dt>Resource revision</dt>
                <dd>{review.review.expectedRevision}</dd>
                <dt>Checker</dt>
                <dd>{review.review.checkerPrincipalId}</dd>
                <dt>Reason</dt>
                <dd>{review.review.reason}</dd>
              </dl>
              <details className="workload-audit">
                <summary>Change technical details</summary>
                <p>Candidate digest: {review.review.candidateDigest}</p>
                <pre className="whitespace-pre-wrap break-all text-sm">
                  {JSON.stringify(review.review.candidate, null, 2)}
                </pre>
              </details>
              <p>
                Review expires:{' '}
                <time dateTime={review.review.expiresAt}>
                  {workloadTime(review.review.expiresAt)}
                </time>
              </p>
              {review.approvalRequestId && <p>Approval request: {review.approvalRequestId}</p>}
              <div className="flex flex-wrap gap-2">
                <button
                  type="button"
                  className={button}
                  disabled={busy || !!pending || !!review.approvalRequestId || consumed}
                  onClick={() => void run(submit)}
                >
                  Request workload approval
                </button>
                <button
                  type="button"
                  className={button}
                  disabled={busy || !!pending || !review.approvalRequestId || consumed}
                  onClick={() => void run(commit)}
                >
                  Verify and commit workload change
                </button>
                <button
                  type="button"
                  className={button}
                  disabled={busy || !review.approvalRequestId}
                  onClick={() => void run(() => readOriginal(review.approvalRequestId))}
                >
                  Read saved workload operation
                </button>
                <button
                  type="button"
                  className={button}
                  disabled={busy}
                  onClick={() =>
                    void run(async () => {
                      const originatingActor = actor.current;
                      const fresh = await load('maker');
                      if (fresh)
                        await readSaved(review.review.candidate.credentialId, originatingActor);
                    })
                  }
                >
                  Read saved workload
                </button>
              </div>
            </div>
          )}
        </div>
      </section>
      <section
        className="workload-task"
        aria-label="Certificate approvals"
        hidden={view !== 'approvals'}
      >
        <header className="workload-task-heading">
          <h3>Approval requests</h3>
          <p>Review assigned changes or check the requests you submitted.</p>
        </header>
        <div className="workload-task-content">
          <div className={`${panel} grid gap-3`}>
            <h3 className="font-semibold">Workload approvals</h3>
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
              Refresh workload approvals
            </button>
            {state?.approvals.length === 0 && <p>No workload approvals on this page.</p>}
            {state?.approvals.map((item) => (
              <article key={item.approvalRequestId} className={`${panel} grid gap-2 break-all`}>
                <h4 className="font-semibold">
                  {workloadChangeLabel(item.proposal.catalogOperationId)} ·{' '}
                  {item.proposal.state === 'CONSUMED'
                    ? 'Executed'
                    : item.state === 'APPROVED'
                      ? 'Approved — awaiting execution'
                      : item.state.replaceAll('_', ' ')}
                </h4>
                <p>Reason: {item.proposal.approval?.reason ?? 'No reason recorded'}</p>
                <p className="workload-description">Request #{item.approvalRequestId.slice(-8)}</p>
                <details className="workload-audit">
                  <summary>Request technical details</summary>
                  <div className="grid gap-2">
                    <p>Approval request: {item.approvalRequestId}</p>
                    <p>Maker: {item.makerSubjectRef}</p>
                    <p>Candidate digest: {item.candidateDigest}</p>
                    <p>Resource revision: {item.proposal.expectedRevision}</p>
                    <pre className="whitespace-pre-wrap break-all text-sm">
                      {JSON.stringify(item.proposal.candidate, null, 2)}
                    </pre>
                  </div>
                </details>
                <p>
                  Operation:{' '}
                  {item.proposal.state === 'CONSUMED' && item.proposal.operationId
                    ? item.proposal.operationId
                    : 'Effect not confirmed'}
                </p>
                <button
                  type="button"
                  className={button}
                  disabled={busy || !!pending}
                  onClick={() => void run(() => readOriginal(item.approvalRequestId.slice(-36)))}
                >
                  Read this original workload operation
                </button>
                {item.proposal.state === 'CONSUMED' && item.proposal.operationId && (
                  <button
                    type="button"
                    className={button}
                    disabled={busy || !state}
                    onClick={() =>
                      void run(async () => {
                        const selectedId = item.proposal.candidate.credentialId;
                        const originatingActor = actor.current;
                        const fresh = await load();
                        if (fresh) await readSaved(selectedId, originatingActor);
                      })
                    }
                  >
                    View saved certificate
                  </button>
                )}
                {lane === 'checker' && (
                  <button
                    type="button"
                    className={button}
                    disabled={busy || !!pending || item.state !== 'REQUESTED'}
                    onClick={() =>
                      void run(async () => {
                        await verify(item.stepUp, item);
                        await post(
                          {
                            command: 'APPROVE',
                            approvalRequestId: item.approvalRequestId.slice(-36),
                            candidateDigest: item.candidateDigest,
                            expectedRevision: item.revision,
                          },
                          {
                            command: 'APPROVE',
                            candidateDigest: item.candidateDigest,
                            expectedRevision: item.proposal.expectedRevision,
                            approvalRequestId: item.approvalRequestId.slice(-36),
                          },
                        );
                        await readOriginal(item.approvalRequestId.slice(-36));
                        assertOperation();
                        if (!pendingRef.current)
                          setMessage(
                            'The workload change is approved. The maker can now commit it.',
                          );
                      })
                    }
                  >
                    Verify and approve workload change
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
                Next workload approvals
              </button>
            )}
          </div>
        </div>
      </section>
      <section className="workload-task" aria-label="Request recovery" hidden={view !== 'recovery'}>
        <header className="workload-task-heading">
          <h3>Request recovery</h3>
          <p>Confirm the outcome of an existing request before retrying.</p>
        </header>
        <div className="workload-task-content">
          <form
            className={`${panel} grid gap-3`}
            onSubmit={(event) => {
              event.preventDefault();
              void run(() => readOriginal(originalId.trim()));
            }}
          >
            <h3 className="font-semibold">Find an original workload operation</h3>
            <p>
              Use its approval request ID after signing in again. Reading an original does not renew
              its approval or authorize a retry.
            </p>
            <label>
              Original workload approval ID
              <input
                className={field}
                required
                value={originalId}
                disabled={busy || !!pending}
                onChange={(event) => setOriginalId(event.target.value)}
              />
            </label>
            <button className={button} disabled={busy || !state || !!pending}>
              Read original workload operation
            </button>
          </form>
        </div>
      </section>
    </section>
  );
}
