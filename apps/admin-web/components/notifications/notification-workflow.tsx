'use client';

import { useCallback, useEffect, useId, useRef, useState, type FormEvent } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { LocalSessionSurface } from '../local-session';
import {
  notificationCommand,
  notificationEndpoint,
  notificationPending,
  notificationView,
  type NotificationBinding,
  type NotificationCommand,
  type NotificationPending,
  type NotificationView,
  type Operation,
} from '../../lib/notification-workflow';

const storageKey = 'openpc:notification-request:v1';
const lifetimeKey = ['notification-workflow-lifetime'] as const;
const fieldClass =
  'mt-1 w-full min-w-0 rounded border border-[color:var(--border)] bg-[color:var(--surface)] p-2';
const buttonClass = 'rounded border border-[color:var(--border)] px-3 py-2 disabled:opacity-50';
type Detail = Extract<NotificationView, { kind: 'DETAIL' }>;
type Listing = Extract<NotificationView, { kind: 'LIST' }>;

class RequestFailure extends Error {
  constructor(
    readonly status: number,
    readonly code?: string,
  ) {
    super(
      status === 412 || code === 'PC-DATA-6007'
        ? 'The selected revision is stale. Refresh the notification before acknowledging.'
        : status === 401 || status === 403 || status === 404
          ? 'The requested notification or action is unavailable in this context.'
          : 'The request could not be confirmed. Recover the original result before submitting another request.',
    );
  }
}
async function responseView(response: Response): Promise<NotificationView> {
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
  const parsed = notificationView.safeParse(body);
  if (!parsed.success) throw new RequestFailure(503);
  return parsed.data;
}
function stored(): NotificationPending | undefined {
  try {
    const parsed = notificationPending.safeParse(
      JSON.parse(sessionStorage.getItem(storageKey) ?? 'null'),
    );
    return parsed.success ? parsed.data : undefined;
  } catch {
    return undefined;
  }
}
function retain(value?: NotificationPending) {
  try {
    if (value) sessionStorage.setItem(storageKey, JSON.stringify(value));
    else sessionStorage.removeItem(storageKey);
  } catch {
    /* The in-memory original still permits recovery in this tab. */
  }
}

/** Metadata only. Delivery, endpoint verification and evidence/ownership joins
 * remain with their respective owners and are not inferred from these records. */
export function NotificationWorkflow() {
  const queryClient = useQueryClient();
  const formId = useId();
  const generation = useRef(0),
    controller = useRef<AbortController | undefined>(undefined);
  const bound = useRef<NotificationBinding | undefined>(undefined);
  const active = useRef(false),
    original = useRef<NotificationPending | undefined>(undefined);
  const heading = useRef<HTMLHeadingElement>(null),
    errorRef = useRef<HTMLParagraphElement>(null);
  const [listing, setListing] = useState<Listing>();
  const [detail, setDetail] = useState<Detail>();
  const [operation, setDisplayedOperation] = useState<Operation>();
  // A superseded read hides its projection, but the accepted receipt still
  // supports reconciliation of the unchanged original through current DETAIL.
  const operationEvidence = useRef<Operation | undefined>(undefined);
  const setOperation = useCallback((value?: Operation) => {
    operationEvidence.current = value;
    setDisplayedOperation(value);
  }, []);
  const [pending, setPending] = useState<NotificationPending>();
  const [busy, setBusy] = useState(false),
    [status, setStatus] = useState('Loading notifications.');
  const [error, setError] = useState(''),
    [rejected, setRejected] = useState(false);
  const [severity, setSeverity] = useState<'INFO' | 'WARNING' | 'ERROR' | 'CRITICAL'>('INFO');
  const [messageKey, setMessageKey] = useState(''),
    [resourceRef, setResourceRef] = useState(''),
    [reason, setReason] = useState('');
  const [ackReason, setAckReason] = useState(''),
    [operationId, setOperationId] = useState('');
  const [filterField, setFilterField] = useState(''),
    [filterValue, setFilterValue] = useState('');
  const [filter, setFilter] = useState(''),
    [sort, setSort] = useState<'updatedAt' | '-updatedAt'>('-updatedAt');
  const [appliedSort, setAppliedSort] = useState<'updatedAt' | '-updatedAt'>('-updatedAt');

  const remember = useCallback((value?: NotificationPending) => {
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
      setMessageKey('');
      setResourceRef('');
      setReason('');
      setAckReason('');
      setOperationId('');
      setFilterField('');
      setFilterValue('');
      setFilter('');
      setStatus('Refresh notifications in the current context.');
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
  function matches(next: NotificationView, expected: string) {
    if (next.actorKey !== expected || bound.current?.actorKey !== expected) {
      clear(true);
      setError('Context changed. Refresh notifications.');
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
      setStatus('Loading notifications.');
      const previous = bound.current?.actorKey;
      try {
        const parameters = new URLSearchParams({ view: 'LIST', limit: '25', sort: selectedSort });
        if (cursor) parameters.set('cursor', cursor);
        if (selectedFilter) parameters.set('filter', selectedFilter);
        const next = await responseView(
          await fetch(`${notificationEndpoint}?${parameters}`, {
            cache: 'no-store',
            credentials: 'same-origin',
            signal: task.signal,
          }),
        );
        if (task.generation !== generation.current) return;
        if (next.kind !== 'LIST') throw new RequestFailure(503);
        if (previous && previous !== next.actorKey) {
          clear(true);
          setError('Context changed. Refresh notifications.');
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
            ? 'No authorized notifications match this filter.'
            : 'Notification metadata loaded.',
        );
      } catch (cause) {
        if (task.generation === generation.current) setStatus('Notification list unavailable.');
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
          `${notificationEndpoint}?${new URLSearchParams({ view: 'DETAIL', actorKey, notificationRef: ref })}`,
          { cache: 'no-store', signal: task.signal },
        ),
      );
      if (task.generation !== generation.current || !matches(next, actorKey)) return;
      if (next.kind !== 'DETAIL' || next.notification.notificationId !== ref)
        throw new RequestFailure(503);
      setDetail(next);
      setAckReason('');
      if (
        operation?.state === 'SUCCEEDED' &&
        operation.truthState === 'SUCCESS' &&
        operation.resourceRef === ref &&
        BigInt(next.notification.revision) >= BigInt(operation.revision) &&
        (original.current?.request.command !== 'ACKNOWLEDGE' ||
          next.notification.state === 'ACKNOWLEDGED')
      )
        remember();
      setStatus('Current notification metadata read. Viewing does not acknowledge it.');
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
    setStatus('Reading notification operation.');
    try {
      const next = await responseView(
        await fetch(
          `${notificationEndpoint}?${new URLSearchParams({ view: 'OPERATION', actorKey, operationId: id })}`,
          { cache: 'no-store', signal: task.signal },
        ),
      );
      if (task.generation !== generation.current || !matches(next, actorKey)) return;
      if (next.kind !== 'OPERATION' || next.operation.operationId !== id)
        throw new RequestFailure(503);
      if (
        original.current &&
        (next.operation.idempotencyKey !==
          `workbench-notification-${original.current.request.requestKey}` ||
          next.operation.actionIntentId !==
            (original.current.request.command === 'CREATE'
              ? 'ACT-NOTIFICATIONS_CREATE_RESOURCE-V1'
              : 'ACT-NOTIFICATION_UPDATE_ACKNOWLEDGE-V1') ||
          (original.current.request.command === 'ACKNOWLEDGE' &&
            next.operation.resourceRef !== original.current.request.notificationRef))
      )
        throw new RequestFailure(503);
      setOperation(next.operation);
      setStatus('Original operation read. Read its notification to confirm current metadata.');
      if (original.current) remember({ ...original.current, operationId: id });
    } catch (cause) {
      if (task.generation === generation.current)
        setStatus('Notification operation unavailable. Retry the same operation read.');
      fail(cause, task.generation);
    } finally {
      end(task.generation);
    }
  }
  async function submit(input: NotificationCommand) {
    const parsed = notificationCommand.safeParse(input);
    if (!parsed.success) {
      setError('Check the message key, resource reference, revision and reason.');
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
        await fetch(notificationEndpoint, {
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
        next.operation.idempotencyKey !== `workbench-notification-${input.requestKey}` ||
        (input.command === 'ACKNOWLEDGE' && next.operation.resourceRef !== input.notificationRef)
      )
        throw new RequestFailure(503);
      remember({ request: parsed.data, operationId: next.operation.operationId, uncertain: false });
      setOperation(next.operation);
      setStatus('Operation returned. Read the notification to confirm its metadata state.');
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
      severity,
      messageKey,
      resourceRef: resourceRef || null,
      reason,
    });
  }
  function acknowledge(event: FormEvent) {
    event.preventDefault();
    if (!detail || original.current) return;
    void submit({
      command: 'ACKNOWLEDGE',
      actorKey: detail.actorKey,
      requestKey: crypto.randomUUID(),
      notificationRef: detail.notification.notificationId,
      expectedRevision: detail.notification.revision,
      etag: detail.etag,
      reason: ackReason,
    });
  }

  return (
    <section aria-labelledby={`${formId}-heading`} className="min-w-0 space-y-5">
      <h2 id={`${formId}-heading`} className="text-xl font-semibold">
        Notifications
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
            <option value="severity">Severity</option>
            <option value="resourceRef">Resource reference</option>
            <option value="messageKey">Message key</option>
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
          Refresh notifications
        </button>
      </form>
      {listing ? (
        <>
          <p>
            {listing.page.total === null
              ? 'Total unknown'
              : `${listing.page.total} matching notifications`}{' '}
            · Completeness: {listing.page.completeness}
          </p>
          {listing.page.authorizedEmpty ? (
            <p>No authorized notifications match this filter.</p>
          ) : listing.page.items.length === 0 ? (
            <p>No rows returned; completeness remains {listing.page.completeness}.</p>
          ) : (
            <ul aria-label="Notification results" className="space-y-3">
              {listing.page.items.map((item) => (
                <li
                  key={item.notificationId}
                  className="min-w-0 break-words rounded border border-[color:var(--border)] p-3"
                >
                  <p>
                    {item.severity} · {item.state} · {item.messageKey}
                  </p>
                  <p className="break-all">{item.notificationId}</p>
                  <button
                    className={buttonClass}
                    type="button"
                    disabled={busy}
                    onClick={() => void inspect(item.notificationId)}
                  >
                    Inspect {item.messageKey}
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
            Notification details
          </h3>
          <dl className="grid gap-2 break-words sm:grid-cols-2">
            {Object.entries(detail.notification).map(([key, value]) => (
              <div key={key} className="min-w-0">
                <dt>{key}</dt>
                <dd className="break-all">{value ?? 'None'}</dd>
              </div>
            ))}
          </dl>
          <p>Viewing does not mark this notification read or acknowledged.</p>
          {detail.notification.state !== 'ACKNOWLEDGED' ? (
            <form onSubmit={acknowledge} className="mt-3 space-y-3">
              <label>
                Acknowledgement reason
                <textarea
                  className={fieldClass}
                  required
                  maxLength={1024}
                  value={ackReason}
                  onChange={(event) => setAckReason(event.target.value)}
                />
              </label>
              <p>Acknowledge revision {detail.notification.revision} in the displayed context.</p>
              <button className={buttonClass} disabled={busy || !!pending} type="submit">
                Acknowledge notification
              </button>
            </form>
          ) : (
            <p>Current metadata state: ACKNOWLEDGED.</p>
          )}
        </section>
      ) : null}
      <form
        onSubmit={create}
        aria-label="Create notification"
        className="grid gap-3 rounded border border-[color:var(--border)] p-4"
      >
        <h3>Create notification metadata</h3>
        <label>
          Severity
          <select
            className={fieldClass}
            value={severity}
            onChange={(event) => setSeverity(event.target.value as typeof severity)}
          >
            {['INFO', 'WARNING', 'ERROR', 'CRITICAL'].map((value) => (
              <option key={value}>{value}</option>
            ))}
          </select>
        </label>
        <label>
          Message key
          <input
            className={fieldClass}
            required
            minLength={3}
            maxLength={128}
            pattern="[a-z][a-z0-9.]{2,127}"
            value={messageKey}
            onChange={(event) => setMessageKey(event.target.value)}
          />
        </label>
        <label>
          Resource reference (optional)
          <input
            className={fieldClass}
            value={resourceRef}
            maxLength={112}
            onChange={(event) => setResourceRef(event.target.value)}
          />
        </label>
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
          Create notification
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
        <section aria-label="Notification operation" className="space-y-2 break-all">
          <p>Operation {operation.operationId}</p>
          <p>
            {operation.state} · {operation.truthState}
          </p>
          <p>This status describes the metadata operation. It does not establish delivery.</p>
          {operation.resourceRef ? (
            <button
              className={buttonClass}
              disabled={busy || !listing}
              type="button"
              onClick={() => void inspect(operation.resourceRef!)}
            >
              Read operation notification
            </button>
          ) : null}
        </section>
      ) : null}
    </section>
  );
}
