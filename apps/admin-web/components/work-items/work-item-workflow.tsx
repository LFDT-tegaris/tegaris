'use client';

import { useCallback, useEffect, useId, useRef, useState, type FormEvent } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { LocalSessionSurface } from '../local-session';
import {
  workItemActions,
  workItemCommand,
  workItemEndpoint,
  workItemPending,
  workItemView,
  type WorkItemBinding,
  type WorkItemCommand,
  type WorkItemPending,
  type WorkItemView,
  type Operation,
} from '../../lib/work-item-workflow';

const storageKey = 'openpc:work-item-request:v1';
const lifetimeKey = ['work-item-workflow-lifetime'] as const;
const fieldClass =
  'mt-1 w-full min-w-0 rounded border border-[color:var(--border)] bg-[color:var(--surface)] p-2';
const buttonClass = 'rounded border border-[color:var(--border)] px-3 py-2 disabled:opacity-50';
type Detail = Extract<WorkItemView, { kind: 'DETAIL' }>;
type Listing = Extract<WorkItemView, { kind: 'LIST' }>;

class RequestFailure extends Error {
  constructor(
    readonly status: number,
    readonly code?: string,
  ) {
    super(
      status === 412 || code === 'PC-DATA-6007'
        ? 'The selected revision is stale. Refresh the work item before changing it.'
        : status === 401 || status === 403 || status === 404
          ? 'The requested work item or action is unavailable in this context.'
          : 'The request could not be confirmed. Recover the original result before submitting another request.',
    );
  }
}
async function responseView(response: Response): Promise<WorkItemView> {
  const body: unknown = await response.json().catch(() => undefined);
  if (!response.ok) {
    const code =
      body &&
      typeof body === 'object' &&
      'code' in body &&
      typeof body.code === 'string' &&
      /^PC-[A-Z]+-[0-9]+$/u.test(body.code)
        ? body.code
        : undefined;
    throw new RequestFailure(response.status, code);
  }
  const parsed = workItemView.safeParse(body);
  if (!parsed.success) throw new RequestFailure(503);
  return parsed.data;
}
function stored(): WorkItemPending | undefined {
  try {
    const parsed = workItemPending.safeParse(
      JSON.parse(sessionStorage.getItem(storageKey) ?? 'null'),
    );
    return parsed.success ? parsed.data : undefined;
  } catch {
    return undefined;
  }
}
function retain(value?: WorkItemPending) {
  try {
    if (value) sessionStorage.setItem(storageKey, JSON.stringify(value));
    else sessionStorage.removeItem(storageKey);
  } catch {
    /* The in-memory original still permits recovery in this tab. */
  }
}

/** Work-item lifecycle only. Linked business effects remain with their owning journeys. */
export function WorkItemWorkflow() {
  const queryClient = useQueryClient();
  const formId = useId();
  const generation = useRef(0),
    controller = useRef<AbortController | undefined>(undefined);
  const bound = useRef<WorkItemBinding | undefined>(undefined);
  const active = useRef(false),
    original = useRef<WorkItemPending | undefined>(undefined);
  const heading = useRef<HTMLHeadingElement>(null),
    errorRef = useRef<HTMLParagraphElement>(null);
  const [listing, setListing] = useState<Listing>();
  const [detail, setDetail] = useState<Detail>();
  const [operation, setDisplayedOperation] = useState<Operation>();
  // A superseded read hides its projection, but preserves the accepted receipt
  // for current DETAIL reconciliation of the unchanged original request.
  const operationEvidence = useRef<Operation | undefined>(undefined);
  const setOperation = useCallback((value?: Operation) => {
    operationEvidence.current = value;
    setDisplayedOperation(value);
  }, []);
  const [pending, setPending] = useState<WorkItemPending>();
  const [busy, setBusy] = useState(false),
    [status, setStatus] = useState('Loading work items.');
  const [error, setError] = useState(''),
    [rejected, setRejected] = useState(false);
  const [kind, setKind] = useState<
    'APPROVAL' | 'REMEDIATION' | 'DELIVERY_FAILURE' | 'FLEET_FAILURE' | 'EVIDENCE_BACKLOG'
  >('REMEDIATION');
  const [assigneeRef, setAssigneeRef] = useState(''),
    [replacementDigest, setReplacementDigest] = useState(''),
    [resourceRef, setResourceRef] = useState(''),
    [reason, setReason] = useState('');
  const [transitionReason, setTransitionReason] = useState(''),
    [operationId, setOperationId] = useState('');
  const [filterField, setFilterField] = useState(''),
    [filterValue, setFilterValue] = useState('');
  const [filter, setFilter] = useState(''),
    [sort, setSort] = useState<'updatedAt' | '-updatedAt'>('-updatedAt');
  const [appliedSort, setAppliedSort] = useState<'updatedAt' | '-updatedAt'>('-updatedAt');

  const remember = useCallback((value?: WorkItemPending) => {
    original.current = value;
    setPending(value);
    retain(value);
  }, []);
  const clear = useCallback(
    (hard: boolean) => {
      generation.current++;
      controller.current?.abort();
      active.current = false;
      bound.current = undefined;
      original.current = undefined;
      setListing(undefined);
      setDetail(undefined);
      setOperation(undefined);
      setPending(undefined);
      setBusy(false);
      setError('');
      setRejected(false);
      setAssigneeRef('');
      setReplacementDigest('');
      setKind('REMEDIATION');
      setResourceRef('');
      setReason('');
      setTransitionReason('');
      setOperationId('');
      setFilterField('');
      setFilterValue('');
      setFilter('');
      setStatus('Refresh work items in the current context.');
      if (hard) retain();
    },
    [setOperation],
  );
  const begin = useCallback(() => {
    if (active.current) return undefined;
    active.current = true;
    setBusy(true);
    setError('');
    controller.current?.abort();
    const abort = new AbortController();
    controller.current = abort;
    return { generation: ++generation.current, signal: abort.signal };
  }, []);
  const end = useCallback((current: number) => {
    if (current === generation.current) {
      active.current = false;
      setBusy(false);
    }
  }, []);
  const fail = useCallback(
    (cause: unknown, current: number) => {
      if (current !== generation.current) return;
      if (cause instanceof RequestFailure && [401, 403, 404].includes(cause.status)) {
        clear(false);
        setError(cause.message);
      } else {
        setError(
          cause instanceof RequestFailure
            ? cause.message
            : 'The response is unavailable. Recover the original result if a request was submitted.',
        );
      }
    },
    [clear],
  );
  useEffect(() => {
    if (error) errorRef.current?.focus();
  }, [error]);
  useEffect(() => {
    if (detail) heading.current?.focus();
  }, [detail]);
  function matches(next: WorkItemView, expected: string) {
    if (next.actorKey !== expected || bound.current?.actorKey !== expected) {
      clear(true);
      setError('Context changed. Refresh work items.');
      return false;
    }
    return true;
  }

  const load = useCallback(
    async (
      cursor?: string,
      selectedFilter = '',
      selectedSort: 'updatedAt' | '-updatedAt' = '-updatedAt',
    ) => {
      const task = begin();
      if (!task) return;
      setListing(undefined);
      setDetail(undefined);
      setDisplayedOperation(undefined);
      setStatus('Loading work items.');
      const previous = bound.current?.actorKey;
      try {
        const parameters = new URLSearchParams({ view: 'LIST', limit: '25', sort: selectedSort });
        if (cursor) parameters.set('cursor', cursor);
        if (selectedFilter) parameters.set('filter', selectedFilter);
        const next = await responseView(
          await fetch(`${workItemEndpoint}?${parameters}`, {
            cache: 'no-store',
            credentials: 'same-origin',
            signal: task.signal,
          }),
        );
        if (task.generation !== generation.current) return;
        if (next.kind !== 'LIST') throw new RequestFailure(503);
        if (previous && previous !== next.actorKey) {
          clear(true);
          setError('Context changed. Refresh work items.');
          return;
        }
        bound.current = { actorKey: next.actorKey, actor: next.actor };
        const saved = original.current ?? stored();
        if (saved?.request.actorKey === next.actorKey) {
          original.current = saved;
          setPending(saved);
          setRejected(!saved.uncertain && !saved.operationId);
        } else remember();
        queryClient.setQueryData(lifetimeKey, next.actorKey);
        setListing(next);
        setFilter(selectedFilter);
        setSort(selectedSort);
        setAppliedSort(selectedSort);
        setStatus(
          next.page.authorizedEmpty
            ? 'No authorized work items match this filter.'
            : 'Work-item metadata loaded.',
        );
      } catch (cause) {
        if (task.generation === generation.current) setStatus('Work-item list unavailable.');
        fail(cause, task.generation);
      } finally {
        end(task.generation);
      }
    },
    [begin, clear, end, fail, queryClient, remember],
  );

  useEffect(() => {
    void load();
    const focus = () => void load();
    const blur = () => clear(false);
    const hidden = () => {
      if (document.visibilityState !== 'visible') clear(false);
    };
    const unsubscribe = queryClient.getQueryCache().subscribe((event) => {
      if (event.type === 'removed' && event.query.queryKey[0] === lifetimeKey[0]) clear(true);
    });
    window.addEventListener('focus', focus);
    window.addEventListener('blur', blur);
    document.addEventListener('visibilitychange', hidden);
    return () => {
      unsubscribe();
      window.removeEventListener('focus', focus);
      window.removeEventListener('blur', blur);
      document.removeEventListener('visibilitychange', hidden);
      generation.current++;
      controller.current?.abort();
    };
  }, [clear, load, queryClient]);

  async function inspect(ref: string) {
    const operation = operationEvidence.current;
    const actorKey = bound.current?.actorKey;
    const task = begin();
    if (!task || !actorKey) {
      if (task) end(task.generation);
      return;
    }
    setDetail(undefined);
    try {
      const next = await responseView(
        await fetch(
          `${workItemEndpoint}?${new URLSearchParams({ view: 'DETAIL', actorKey, workItemRef: ref })}`,
          { cache: 'no-store', signal: task.signal },
        ),
      );
      if (task.generation !== generation.current || !matches(next, actorKey)) return;
      if (next.kind !== 'DETAIL' || next.workItem.workItemId !== ref) throw new RequestFailure(503);
      setDetail(next);
      setTransitionReason('');
      if (
        operation?.state === 'SUCCEEDED' &&
        operation.truthState === 'SUCCESS' &&
        operation.resourceRef === ref &&
        BigInt(next.workItem.revision) >= BigInt(operation.revision) &&
        (original.current?.request.command !== 'COMPLETE' || next.workItem.state === 'COMPLETED') &&
        (original.current?.request.command !== 'CLAIM' ||
          ['CLAIMED', 'COMPLETED'].includes(next.workItem.state))
      )
        remember();
      setStatus('Current work-item metadata read. Viewing does not change it.');
    } catch (cause) {
      fail(cause, task.generation);
    } finally {
      end(task.generation);
    }
  }
  async function recoverOperation(id: string) {
    const actorKey = bound.current?.actorKey;
    const task = begin();
    if (!task || !actorKey) {
      if (task) end(task.generation);
      return;
    }
    setDisplayedOperation(undefined);
    setStatus('Reading work-item operation.');
    try {
      const next = await responseView(
        await fetch(
          `${workItemEndpoint}?${new URLSearchParams({ view: 'OPERATION', actorKey, operationId: id })}`,
          { cache: 'no-store', signal: task.signal },
        ),
      );
      if (task.generation !== generation.current || !matches(next, actorKey)) return;
      if (next.kind !== 'OPERATION' || next.operation.operationId !== id)
        throw new RequestFailure(503);
      if (
        original.current &&
        (next.operation.idempotencyKey !==
          `workbench-work-item-${original.current.request.requestKey}` ||
          next.operation.actionIntentId !== workItemActions[original.current.request.command] ||
          (original.current.request.command !== 'CREATE' &&
            next.operation.resourceRef !== original.current.request.workItemRef))
      )
        throw new RequestFailure(503);
      setOperation(next.operation);
      setStatus('Original operation read. Read its work item to confirm current metadata.');
      if (original.current) remember({ ...original.current, operationId: id });
    } catch (cause) {
      if (task.generation === generation.current)
        setStatus('Work-item operation unavailable. Retry the same operation read.');
      fail(cause, task.generation);
    } finally {
      end(task.generation);
    }
  }
  async function submit(input: WorkItemCommand) {
    const parsed = workItemCommand.safeParse(input);
    if (!parsed.success) {
      setError(
        'Check the kind, resource and assignee references, payload digest, revision and reason.',
      );
      return;
    }
    if (input.actorKey !== bound.current?.actorKey) {
      clear(true);
      return;
    }
    const task = begin();
    if (!task) return;
    const wasUncertain = original.current?.uncertain === true;
    remember({ request: parsed.data, uncertain: true });
    setRejected(false);
    setOperation(undefined);
    setStatus('Submitting the original metadata request.');
    try {
      const next = await responseView(
        await fetch(workItemEndpoint, {
          method: 'POST',
          cache: 'no-store',
          credentials: 'same-origin',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(parsed.data),
          signal: task.signal,
        }),
      );
      if (task.generation !== generation.current || !matches(next, input.actorKey)) return;
      if (
        next.kind !== 'OPERATION' ||
        next.operation.idempotencyKey !== `workbench-work-item-${input.requestKey}` ||
        next.operation.actionIntentId !== workItemActions[input.command] ||
        (input.command !== 'CREATE' && next.operation.resourceRef !== input.workItemRef)
      )
        throw new RequestFailure(503);
      remember({ request: parsed.data, operationId: next.operation.operationId, uncertain: false });
      setOperation(next.operation);
      setStatus('Operation returned. Read the work item to confirm its metadata state.');
    } catch (cause) {
      if (
        task.generation === generation.current &&
        !wasUncertain &&
        cause instanceof RequestFailure &&
        [400, 409, 412, 422, 428].includes(cause.status)
      ) {
        remember({ request: parsed.data, uncertain: false });
        setRejected(true);
      }
      fail(cause, task.generation);
    } finally {
      end(task.generation);
    }
  }
  function create(event: FormEvent) {
    event.preventDefault();
    if (!bound.current || original.current) return;
    void submit({
      command: 'CREATE',
      actorKey: bound.current.actorKey,
      requestKey: crypto.randomUUID(),
      kind,
      assigneeRef: assigneeRef || null,
      resourceRef,
      reason,
    });
  }
  function transition(event: FormEvent, command: 'UPDATE' | 'CLAIM' | 'COMPLETE') {
    event.preventDefault();
    if (!detail || original.current) return;
    const selected = {
      actorKey: detail.actorKey,
      requestKey: crypto.randomUUID(),
      workItemRef: detail.workItem.workItemId,
      expectedRevision: detail.workItem.revision,
      etag: detail.etag,
      reason: transitionReason,
    };
    void submit(
      command === 'UPDATE' ? { ...selected, command, replacementDigest } : { ...selected, command },
    );
  }

  return (
    <section aria-labelledby={`${formId}-heading`} className="min-w-0 space-y-5">
      <h2 id={`${formId}-heading`} className="text-xl font-semibold">
        Work items
      </h2>
      <div
        onClickCapture={(event) => {
          if ((event.target as HTMLElement).closest('button')) clear(true);
        }}
        onSubmitCapture={() => clear(true)}
      >
        <LocalSessionSurface />
      </div>
      <p role="status" aria-live="polite">
        {status}
      </p>
      {error ? (
        <p
          ref={errorRef}
          tabIndex={-1}
          role="alert"
          className="break-words text-[color:var(--danger)]"
        >
          {error}
        </p>
      ) : null}
      {listing ? (
        <p className="break-all">
          Participant {listing.actor.participantId} · Privacy domain {listing.actor.privacyDomainId}
        </p>
      ) : null}
      <form
        onSubmit={(event) => {
          event.preventDefault();
          void load(
            undefined,
            filterField && filterValue ? `${filterField}:eq:${filterValue}` : '',
            sort,
          );
        }}
        className="grid gap-3 sm:grid-cols-3"
      >
        <label>
          Filter field
          <select
            className={fieldClass}
            value={filterField}
            onChange={(event) => setFilterField(event.target.value)}
          >
            <option value="">All</option>
            <option value="state">State</option>
            <option value="kind">Kind</option>
            <option value="resourceRef">Resource reference</option>
            <option value="assigneeRef">Assignee reference</option>
          </select>
        </label>
        <label>
          Filter value
          <input
            className={fieldClass}
            value={filterValue}
            maxLength={400}
            onChange={(event) => setFilterValue(event.target.value)}
            required={!!filterField}
          />
        </label>
        <label>
          Sort
          <select
            className={fieldClass}
            value={sort}
            onChange={(event) => setSort(event.target.value as typeof sort)}
          >
            <option value="-updatedAt">Most recently updated</option>
            <option value="updatedAt">Least recently updated</option>
          </select>
        </label>
        <button className={buttonClass} disabled={busy} type="submit">
          Refresh work items
        </button>
      </form>
      {listing ? (
        <>
          <p>
            {listing.page.total === null
              ? 'Total unknown'
              : `${listing.page.total} matching work items`}{' '}
            · Completeness: {listing.page.completeness}
          </p>
          {listing.page.authorizedEmpty ? (
            <p>No authorized work items match this filter.</p>
          ) : listing.page.items.length === 0 ? (
            <p>No rows returned; completeness remains {listing.page.completeness}.</p>
          ) : (
            <ul aria-label="Work-item results" className="space-y-3">
              {listing.page.items.map((item) => (
                <li
                  key={item.workItemId}
                  className="min-w-0 break-words rounded border border-[color:var(--border)] p-3"
                >
                  <p>
                    {item.kind} · {item.state}
                  </p>
                  <p className="break-all">{item.workItemId}</p>
                  <button
                    className={buttonClass}
                    type="button"
                    disabled={busy}
                    onClick={() => void inspect(item.workItemId)}
                  >
                    Inspect {item.workItemId}
                  </button>
                </li>
              ))}
            </ul>
          )}
          <button
            className={buttonClass}
            type="button"
            disabled={busy || !listing.page.nextCursor}
            onClick={() => void load(listing.page.nextCursor ?? undefined, filter, appliedSort)}
          >
            Next page
          </button>
        </>
      ) : null}
      {detail ? (
        <section
          aria-labelledby={`${formId}-detail`}
          className="min-w-0 rounded border border-[color:var(--border)] p-4"
        >
          <h3 ref={heading} tabIndex={-1} id={`${formId}-detail`}>
            Work-item details
          </h3>
          <dl className="grid gap-2 break-words sm:grid-cols-2">
            {Object.entries(detail.workItem).map(([key, value]) => (
              <div key={key} className="min-w-0">
                <dt>{key}</dt>
                <dd className="break-all">{value ?? 'None'}</dd>
              </div>
            ))}
          </dl>
          <p>
            Viewing does not change this work item. Payload digest and reason are not part of public
            detail.
          </p>
          {detail.workItem.kind === 'FLEET_FAILURE' ? (
            <p role="note">
              Completing this Fleet failure work item records its handling. It does not release
              quarantine, acknowledge Fact delivery or recover the source failure.
            </p>
          ) : null}
          {detail.workItem.state === 'OPEN' || detail.workItem.state === 'CLAIMED' ? (
            <div className="mt-3 space-y-3">
              <label>
                Transition reason
                <textarea
                  className={fieldClass}
                  required
                  maxLength={1024}
                  value={transitionReason}
                  onChange={(event) => setTransitionReason(event.target.value)}
                />
              </label>
              <p>
                Use revision {detail.workItem.revision} in the displayed context. The service checks
                current authority and assignment.
              </p>
              {detail.workItem.state === 'OPEN' ? (
                <>
                  <form onSubmit={(event) => transition(event, 'UPDATE')} className="space-y-3">
                    <label>
                      Replacement payload digest
                      <input
                        className={fieldClass}
                        required
                        pattern="sha256:[0-9a-f]{64}"
                        maxLength={71}
                        value={replacementDigest}
                        onChange={(event) => setReplacementDigest(event.target.value)}
                      />
                    </label>
                    <p>
                      Replace the retained payload digest with a reason. Public readback confirms
                      revision and state; it does not disclose that digest.
                    </p>
                    <button
                      className={buttonClass}
                      disabled={busy || !!pending || !transitionReason.trim()}
                      type="submit"
                    >
                      Update work item
                    </button>
                  </form>
                  <form onSubmit={(event) => transition(event, 'CLAIM')}>
                    <button
                      className={buttonClass}
                      disabled={
                        busy ||
                        !!pending ||
                        !transitionReason.trim() ||
                        (detail.workItem.assigneeRef !== null &&
                          detail.workItem.assigneeRef !== detail.actor.principalRef)
                      }
                      type="submit"
                    >
                      Claim work item
                    </button>
                  </form>
                </>
              ) : (
                <form onSubmit={(event) => transition(event, 'COMPLETE')}>
                  <p>Completion requires the original claimant to remain the assignee.</p>
                  <button
                    className={buttonClass}
                    disabled={
                      busy ||
                      !!pending ||
                      !transitionReason.trim() ||
                      detail.workItem.assigneeRef !== detail.actor.principalRef
                    }
                    type="submit"
                  >
                    Complete work item
                  </button>
                </form>
              )}
            </div>
          ) : (
            <p>Current work-item state: {detail.workItem.state}.</p>
          )}
        </section>
      ) : null}
      <form
        onSubmit={create}
        aria-label="Create work item"
        className="grid gap-3 rounded border border-[color:var(--border)] p-4"
      >
        <h3>Create work item</h3>
        <label>
          Kind
          <select
            className={fieldClass}
            value={kind}
            onChange={(event) => setKind(event.target.value as typeof kind)}
          >
            {[
              'APPROVAL',
              'REMEDIATION',
              'DELIVERY_FAILURE',
              'FLEET_FAILURE',
              'EVIDENCE_BACKLOG',
            ].map((value) => (
              <option key={value}>{value}</option>
            ))}
          </select>
        </label>
        <label>
          Resource reference
          <input
            className={fieldClass}
            required
            value={resourceRef}
            maxLength={112}
            onChange={(event) => setResourceRef(event.target.value)}
          />
        </label>
        <label>
          Assignee reference (optional)
          <input
            className={fieldClass}
            value={assigneeRef}
            maxLength={112}
            onChange={(event) => setAssigneeRef(event.target.value)}
          />
        </label>
        <p>
          An optional assignee must be active in this participant. The service validates assignment.
        </p>
        <label>
          Reason
          <textarea
            className={fieldClass}
            required
            maxLength={1024}
            value={reason}
            onChange={(event) => setReason(event.target.value)}
          />
        </label>
        <button className={buttonClass} disabled={busy || !listing || !!pending} type="submit">
          Create work item
        </button>
      </form>
      {pending ? (
        <section aria-label="Original request recovery" className="space-y-2 break-words">
          <p>Original request: {pending.request.requestKey}</p>
          <p>
            New mutations remain unavailable until the original result is resolved. Recovery
            preserves its request identity.
          </p>
          <button
            className={buttonClass}
            type="button"
            disabled={busy || !listing || rejected}
            onClick={() =>
              pending.operationId
                ? void recoverOperation(pending.operationId)
                : void submit(pending.request)
            }
          >
            Recover original result
          </button>
          {rejected ? (
            <button
              className={buttonClass}
              type="button"
              disabled={busy}
              onClick={() => {
                remember();
                setRejected(false);
                void load();
              }}
            >
              Dismiss rejected request and refresh
            </button>
          ) : null}
        </section>
      ) : null}
      <form
        onSubmit={(event) => {
          event.preventDefault();
          void recoverOperation(operationId);
        }}
        className="space-y-2"
      >
        <label>
          Existing operation ID
          <input
            className={fieldClass}
            value={operationId}
            required
            onChange={(event) => setOperationId(event.target.value)}
          />
        </label>
        <button className={buttonClass} disabled={busy || !listing || !!pending} type="submit">
          Read operation
        </button>
      </form>
      {operation ? (
        <section aria-label="Work-item operation" className="space-y-2 break-all">
          <p>Operation {operation.operationId}</p>
          <p>
            {operation.state} · {operation.truthState}
          </p>
          <p>
            This status describes the work-item operation. Read the item to confirm its state.
            Completion does not prove the linked business issue is resolved.
          </p>
          {operation.resourceRef ? (
            <button
              className={buttonClass}
              disabled={busy || !listing}
              type="button"
              onClick={() => void inspect(operation.resourceRef!)}
            >
              Read operation work item
            </button>
          ) : null}
        </section>
      ) : null}
    </section>
  );
}
