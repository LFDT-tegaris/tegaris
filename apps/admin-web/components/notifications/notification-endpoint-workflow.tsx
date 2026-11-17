'use client';

import { useCallback, useEffect, useId, useRef, useState, type FormEvent } from 'react';
import { performWebAuthnStepUp } from '@openpc/ui-shell';
import { useQueryClient } from '@tanstack/react-query';
import { LocalSessionSurface } from '../local-session';
import {
  endpointCommand,
  endpointMutation,
  endpointDefiniteRejection,
  endpointOperationMatches,
  endpointPending,
  endpointProblem,
  endpointView,
  notificationEndpointWorkbench,
  type EndpointBinding,
  type EndpointOperation,
  type EndpointPending,
  type EndpointMutation,
  type EndpointView,
} from '../../lib/notification-endpoint-workflow';

const storageKey = 'openpc:notification-endpoint-request:v1';
const lifetimeKey = ['notification-endpoint-workflow-lifetime'] as const;
const fieldClass =
  'mt-1 w-full min-w-0 rounded border border-[color:var(--border)] bg-[color:var(--surface)] p-2';
const buttonClass = 'rounded border border-[color:var(--border)] px-3 py-2 disabled:opacity-50';
type Listing = Extract<EndpointView, { kind: 'LIST' }>;
type Detail = Extract<EndpointView, { kind: 'DETAIL' }>;
class RequestFailure extends Error {
  constructor(
    readonly status: number,
    readonly problem?: unknown,
  ) {
    const parsed = endpointProblem.safeParse(problem);
    super(
      status === 412
        ? 'The selected revision is stale. Refresh the endpoint.'
        : [401, 403, 404].includes(status)
          ? 'The endpoint or action is unavailable in this context.'
          : parsed.success && parsed.data.truthState === 'UNKNOWN'
            ? 'Endpoint outcome is unknown. Keep the original request; do not submit a replacement.'
            : status === 400
              ? 'Check the endpoint, revision and reason.'
              : 'The endpoint result could not be confirmed. Recover the original result before another request.',
    );
  }
}
async function responseView(response: Response): Promise<EndpointView> {
  const body: unknown = await response.json().catch(() => undefined);
  if (!response.ok) throw new RequestFailure(response.status, body);
  const parsed = endpointView.safeParse(body);
  if (!parsed.success) throw new RequestFailure(503);
  return parsed.data;
}
function stored(): EndpointPending | undefined {
  try {
    const parsed = endpointPending.safeParse(
      JSON.parse(sessionStorage.getItem(storageKey) ?? 'null'),
    );
    return parsed.success ? parsed.data : undefined;
  } catch {
    return undefined;
  }
}
function retain(value?: EndpointPending) {
  try {
    if (value) sessionStorage.setItem(storageKey, JSON.stringify(value));
    else sessionStorage.removeItem(storageKey);
  } catch {
    /* In-memory original remains available in this tab. */
  }
}

/** Endpoint state and non-delivery verification only. Public metadata does not
 * expose credential currentness, delivery eligibility or private proof bytes. */
export function NotificationEndpointWorkflow() {
  const queryClient = useQueryClient(),
    formId = useId();
  const generation = useRef(0),
    abort = useRef<AbortController | undefined>(undefined);
  const bound = useRef<EndpointBinding | undefined>(undefined),
    active = useRef(false);
  const original = useRef<EndpointPending | undefined>(undefined);
  const heading = useRef<HTMLHeadingElement>(null),
    errorRef = useRef<HTMLParagraphElement>(null);
  const [listing, setListing] = useState<Listing>();
  const [detail, setDetail] = useState<Detail>();
  const [operation, setDisplayedOperation] = useState<EndpointOperation>();
  // Hide superseded reads without losing the accepted original receipt needed
  // for its existing CREATE/UPDATE guards and current DETAIL reconciliation.
  const operationEvidence = useRef<EndpointOperation | undefined>(undefined);
  const setOperation = useCallback((value?: EndpointOperation) => {
    operationEvidence.current = value;
    setDisplayedOperation(value);
  }, []);
  const [pending, setPending] = useState<EndpointPending>();
  const [creation, setCreation] = useState<Extract<EndpointView, { kind: 'CREATE_REVIEW' }>>();
  const [choices, setChoices] = useState<Extract<EndpointView, { kind: 'REPLACEMENTS' }>>();
  const [replacementReview, setReplacementReview] =
    useState<Extract<EndpointView, { kind: 'UPDATE_REVIEW' }>>();
  const [replacementDigest, setReplacementDigest] = useState('');
  const [replacementReason, setReplacementReason] = useState('');
  const [channel, setChannel] = useState<'WEBHOOK' | 'EMAIL' | 'OPERATIONS_QUEUE'>('WEBHOOK');
  const [destination, setDestination] = useState('');
  const [createReason, setCreateReason] = useState('');
  const [busy, setBusy] = useState(false),
    [error, setError] = useState('');
  const [status, setStatus] = useState('Loading notification endpoints.');
  const [reason, setReason] = useState(''),
    [operationId, setOperationId] = useState('');
  const [filterField, setFilterField] = useState(''),
    [filterValue, setFilterValue] = useState('');
  const [filter, setFilter] = useState('');
  const [sort, setSort] = useState<'updatedAt' | '-updatedAt'>('-updatedAt');
  const [appliedSort, setAppliedSort] = useState<'updatedAt' | '-updatedAt'>('-updatedAt');
  const remember = useCallback((value?: EndpointPending) => {
    original.current = value;
    setPending(value);
    retain(value);
  }, []);
  const clear = useCallback(
    (hard: boolean) => {
      generation.current++;
      abort.current?.abort();
      active.current = false;
      bound.current = undefined;
      original.current = undefined;
      setListing(undefined);
      setDetail(undefined);
      setOperation(undefined);
      setPending(undefined);
      setCreation(undefined);
      setChoices(undefined);
      setReplacementReview(undefined);
      setReplacementDigest('');
      setReplacementReason('');
      setChannel('WEBHOOK');
      setDestination('');
      setCreateReason('');
      setBusy(false);
      setError('');
      setReason('');
      setOperationId('');
      setFilterField('');
      setFilterValue('');
      setFilter('');
      setStatus('Refresh notification endpoints in the current context.');
      if (hard) retain();
    },
    [setOperation],
  );
  const begin = useCallback(() => {
    if (active.current) return undefined;
    active.current = true;
    setBusy(true);
    setError('');
    abort.current?.abort();
    abort.current = new AbortController();
    return { generation: ++generation.current, signal: abort.current.signal };
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
      if (cause instanceof RequestFailure && [401, 403, 404].includes(cause.status)) clear(false);
      setError(
        cause instanceof RequestFailure
          ? cause.message
          : 'The response was lost. Keep and recover the original request.',
      );
    },
    [clear],
  );
  useEffect(() => {
    if (error) errorRef.current?.focus();
  }, [error]);
  useEffect(() => {
    if (detail) heading.current?.focus();
  }, [detail]);
  function matches(view: EndpointView, expected: string) {
    const current = bound.current;
    if (
      view.actorKey === expected &&
      current?.actorKey === expected &&
      view.actor.participantId === current.actor.participantId &&
      view.actor.privacyDomainId === current.actor.privacyDomainId
    )
      return true;
    clear(true);
    setError('Context changed. Refresh notification endpoints.');
    return false;
  }
  const load = useCallback(
    async (cursor?: string, selectedFilter = '', selectedSort: typeof sort = '-updatedAt') => {
      const task = begin();
      if (!task) return;
      const previous = bound.current?.actorKey;
      setListing(undefined);
      setDetail(undefined);
      setDisplayedOperation(undefined);
      setCreation(undefined);
      setChoices(undefined);
      setReplacementReview(undefined);
      setReplacementDigest('');
      setReplacementReason('');
      setStatus('Loading notification endpoints.');
      try {
        const parameters = new URLSearchParams({ view: 'LIST', limit: '25', sort: selectedSort });
        if (cursor) parameters.set('cursor', cursor);
        if (selectedFilter) parameters.set('filter', selectedFilter);
        const next = await responseView(
          await fetch(`${notificationEndpointWorkbench}?${parameters}`, {
            cache: 'no-store',
            credentials: 'same-origin',
            signal: task.signal,
          }),
        );
        if (task.generation !== generation.current) return;
        if (next.kind !== 'LIST') throw new RequestFailure(503);
        if (previous && previous !== next.actorKey) {
          clear(true);
          setError('Context changed. Refresh notification endpoints.');
          return;
        }
        bound.current = { actor: next.actor, actorKey: next.actorKey };
        const saved = original.current ?? stored();
        if (saved?.request.actorKey === next.actorKey) {
          original.current = saved;
          setPending(saved);
        } else remember();
        queryClient.setQueryData(lifetimeKey, next.actorKey);
        setListing(next);
        setFilter(selectedFilter);
        setSort(selectedSort);
        setAppliedSort(selectedSort);
        setStatus(
          next.page.authorizedEmpty
            ? 'No authorized endpoints match this filter.'
            : 'Endpoint metadata loaded.',
        );
      } catch (cause) {
        if (task.generation === generation.current) setStatus('Endpoint list unavailable.');
        fail(cause, task.generation);
      } finally {
        end(task.generation);
      }
    },
    [begin, clear, end, fail, queryClient, remember],
  );
  useEffect(() => {
    void load();
    const focus = () => void load(),
      blur = () => clear(false);
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
      abort.current?.abort();
    };
  }, [clear, load, queryClient]);

  async function inspect(ref: string) {
    const operation = operationEvidence.current;
    const actorKey = bound.current?.actorKey,
      task = begin();
    if (!task || !actorKey) {
      if (task) end(task.generation);
      return;
    }
    setDetail(undefined);
    setChoices(undefined);
    setReplacementReview(undefined);
    setReplacementDigest('');
    setReplacementReason('');
    try {
      const next = await responseView(
        await fetch(
          `${notificationEndpointWorkbench}?${new URLSearchParams({ view: 'DETAIL', actorKey, endpointRef: ref })}`,
          { cache: 'no-store', credentials: 'same-origin', signal: task.signal },
        ),
      );
      if (task.generation !== generation.current || !matches(next, actorKey)) return;
      if (next.kind !== 'DETAIL' || next.endpoint.notificationEndpointId !== ref)
        throw new RequestFailure(503);
      const originalCreate = original.current?.request;
      if (
        originalCreate?.command === 'CREATE' &&
        operation &&
        endpointOperationMatches(operation, originalCreate) &&
        operation.resourceRef === ref &&
        next.endpoint.revision === '1' &&
        (next.endpoint.state !== 'DISABLED' ||
          next.endpoint.channel !== originalCreate.channel ||
          next.endpoint.destinationRef !== originalCreate.destinationRef)
      )
        throw new RequestFailure(503);
      if (
        originalCreate?.command === 'UPDATE' &&
        operation &&
        endpointOperationMatches(operation, originalCreate) &&
        operation.resourceRef === ref &&
        next.endpoint.revision === operation.revision &&
        !['DISABLED', 'QUARANTINED'].includes(next.endpoint.state)
      )
        throw new RequestFailure(503);
      setDetail(next);
      setReason('');
      // A changed/current endpoint alone cannot settle another original request.
      // Require the original operation result and its matching endpoint revision.
      if (
        original.current &&
        operation &&
        endpointOperationMatches(operation, original.current.request) &&
        operation.state === 'SUCCEEDED' &&
        operation.truthState === 'SUCCESS' &&
        operation.resourceRef === ref &&
        BigInt(next.endpoint.revision) >= BigInt(operation.revision)
      )
        remember();
      setStatus(
        'Current endpoint metadata read. Inspection does not verify or send a notification.',
      );
    } catch (cause) {
      fail(cause, task.generation);
    } finally {
      end(task.generation);
    }
  }
  async function recoverOperation(id: string) {
    const actorKey = bound.current?.actorKey,
      task = begin();
    if (!task || !actorKey) {
      if (task) end(task.generation);
      return;
    }
    setDisplayedOperation(undefined);
    setStatus('Reading endpoint operation.');
    try {
      const next = await responseView(
        await fetch(
          `${notificationEndpointWorkbench}?${new URLSearchParams({ view: 'OPERATION', actorKey, operationId: id })}`,
          { cache: 'no-store', credentials: 'same-origin', signal: task.signal },
        ),
      );
      if (task.generation !== generation.current || !matches(next, actorKey)) return;
      if (
        next.kind !== 'OPERATION' ||
        next.operation.operationId !== id ||
        (original.current && !endpointOperationMatches(next.operation, original.current.request))
      )
        throw new RequestFailure(503);
      setOperation(next.operation);
      if (original.current) remember({ ...original.current, operationId: id });
      setStatus('Original operation read. Read its endpoint to inspect current state.');
    } catch (cause) {
      if (task.generation === generation.current)
        setStatus('Endpoint operation unavailable. Retry the same operation read.');
      fail(cause, task.generation);
    } finally {
      end(task.generation);
    }
  }
  async function submit(input: EndpointMutation) {
    const parsed = endpointMutation.safeParse(input);
    if (!parsed.success) {
      setError('Check the endpoint, revision and verification reason.');
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
    setOperation(undefined);
    setCreation(undefined);
    setReplacementReview(undefined);
    setStatus('Submitting the original endpoint request.');
    try {
      const next = await responseView(
        await fetch(notificationEndpointWorkbench, {
          method: 'POST',
          cache: 'no-store',
          credentials: 'same-origin',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(parsed.data),
          signal: task.signal,
        }),
      );
      if (task.generation !== generation.current || !matches(next, input.actorKey)) return;
      if (next.kind !== 'OPERATION' || !endpointOperationMatches(next.operation, parsed.data))
        throw new RequestFailure(503);
      remember({
        request: parsed.data,
        operationId: next.operation.operationId,
        uncertain: next.operation.truthState !== 'SUCCESS',
      });
      setOperation(next.operation);
      setStatus('Operation returned. Read the endpoint to confirm its current state.');
    } catch (cause) {
      if (
        task.generation === generation.current &&
        !wasUncertain &&
        cause instanceof RequestFailure &&
        endpointDefiniteRejection(cause.problem, cause.status)
      )
        remember({ request: parsed.data, uncertain: false });
      fail(cause, task.generation);
    } finally {
      end(task.generation);
    }
  }
  async function reviewCreation(event: FormEvent) {
    event.preventDefault();
    const actorKey = bound.current?.actorKey;
    if (!actorKey || original.current) return;
    const input = endpointCommand.options[3].safeParse({
      command: 'REVIEW_CREATE',
      actorKey,
      requestKey: crypto.randomUUID(),
      channel,
      destinationRef: destination,
      arbitraryEgress: false,
      reason: createReason,
    });
    if (!input.success) {
      setError('Check the channel, destination reference and creation reason.');
      return;
    }
    const task = begin();
    if (!task) return;
    setCreation(undefined);
    try {
      const next = await responseView(
        await fetch(notificationEndpointWorkbench, {
          method: 'POST',
          cache: 'no-store',
          credentials: 'same-origin',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(input.data),
          signal: task.signal,
        }),
      );
      if (task.generation !== generation.current || !matches(next, actorKey)) return;
      if (
        next.kind !== 'CREATE_REVIEW' ||
        next.request.actorKey !== actorKey ||
        next.request.requestKey !== input.data.requestKey ||
        next.request.channel !== channel ||
        next.request.destinationRef !== destination ||
        next.request.reason !== createReason ||
        next.stepUp.resourceId !== input.data.requestKey ||
        next.stepUp.resourceDigest !== next.request.candidateDigest
      )
        throw new RequestFailure(503);
      setCreation(next);
      setStatus('Review the exact endpoint candidate, then authenticate to create it.');
    } catch (cause) {
      fail(cause, task.generation);
    } finally {
      end(task.generation);
    }
  }
  async function authenticateCandidate(
    selected: Extract<EndpointView, { kind: 'CREATE_REVIEW' | 'UPDATE_REVIEW' }> | undefined,
  ) {
    if (!selected || original.current || selected.actorKey !== bound.current?.actorKey) return;
    const task = begin();
    if (!task) return;
    let authenticated = false;
    try {
      await performWebAuthnStepUp(
        { ...selected.stepUp, stepUp: 'FRESH_WEBAUTHN_MAX_5M' },
        selected.stepUp,
      );
      authenticated =
        task.generation === generation.current && selected.actorKey === bound.current?.actorKey;
    } catch {
      if (task.generation === generation.current)
        setError('Authentication did not complete. No endpoint mutation request was sent.');
    } finally {
      end(task.generation);
    }
    if (authenticated) await submit(selected.request);
  }
  async function loadReplacements() {
    const selected = detail;
    if (!selected || selected.endpoint.state === 'RETIRED' || original.current) return;
    const task = begin();
    if (!task) return;
    setChoices(undefined);
    setReplacementReview(undefined);
    setReplacementDigest('');
    try {
      const next = await responseView(
        await fetch(
          `${notificationEndpointWorkbench}?${new URLSearchParams({
            view: 'REPLACEMENTS',
            actorKey: selected.actorKey,
            endpointRef: selected.endpoint.notificationEndpointId,
          })}`,
          { cache: 'no-store', credentials: 'same-origin', signal: task.signal },
        ),
      );
      if (task.generation !== generation.current || !matches(next, selected.actorKey)) return;
      if (
        next.kind !== 'REPLACEMENTS' ||
        next.choices.notificationEndpointId !== selected.endpoint.notificationEndpointId
      )
        throw new RequestFailure(503);
      if (next.choices.revision !== selected.endpoint.revision) throw new RequestFailure(412);
      setChoices(next);
      setStatus(
        next.choices.items.length
          ? 'Select a replacement for the displayed revision. Choices do not authorize a change.'
          : 'No replacements are available for this revision.',
      );
    } catch (cause) {
      fail(cause, task.generation);
    } finally {
      end(task.generation);
    }
  }
  async function reviewReplacement(event: FormEvent) {
    event.preventDefault();
    const selected = detail;
    if (
      !selected ||
      !choices ||
      original.current ||
      choices.choices.revision !== selected.endpoint.revision ||
      !choices.choices.items.some((item) => item.replacementDigest === replacementDigest)
    )
      return;
    const input = endpointCommand.options[4].safeParse({
      command: 'REVIEW_UPDATE',
      actorKey: selected.actorKey,
      requestKey: crypto.randomUUID(),
      endpointRef: selected.endpoint.notificationEndpointId,
      expectedRevision: selected.endpoint.revision,
      etag: selected.etag,
      replacementDigest,
      reason: replacementReason,
    });
    if (!input.success) {
      setError('Choose a replacement and provide a reason.');
      return;
    }
    const task = begin();
    if (!task) return;
    setReplacementReview(undefined);
    try {
      const next = await responseView(
        await fetch(notificationEndpointWorkbench, {
          method: 'POST',
          cache: 'no-store',
          credentials: 'same-origin',
          signal: task.signal,
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(input.data),
        }),
      );
      if (task.generation !== generation.current || !matches(next, selected.actorKey)) return;
      if (
        next.kind !== 'UPDATE_REVIEW' ||
        next.request.actorKey !== selected.actorKey ||
        next.request.requestKey !== input.data.requestKey ||
        next.request.endpointRef !== input.data.endpointRef ||
        next.request.expectedRevision !== input.data.expectedRevision ||
        next.request.etag !== input.data.etag ||
        next.request.replacementDigest !== replacementDigest ||
        next.request.reason !== replacementReason ||
        next.choice.replacementDigest !== replacementDigest ||
        next.stepUp.resourceId !== input.data.endpointRef.slice(-36) ||
        next.stepUp.resourceDigest !== next.request.candidateDigest
      )
        throw new RequestFailure(503);
      const choice = choices.choices.items.find(
        (item) => item.replacementDigest === replacementDigest,
      );
      if (
        choice?.channel !== next.choice.channel ||
        choice.destinationRef !== next.choice.destinationRef
      )
        throw new RequestFailure(503);
      setReplacementReview(next);
      setStatus('Review the replacement, then authenticate for this exact candidate.');
    } catch (cause) {
      fail(cause, task.generation);
    } finally {
      end(task.generation);
    }
  }
  function verify(event: FormEvent) {
    event.preventDefault();
    if (!detail || original.current || !['ACTIVE', 'DISABLED'].includes(detail.endpoint.state))
      return;
    void submit({
      command: 'VERIFY',
      actorKey: detail.actorKey,
      requestKey: crypto.randomUUID(),
      endpointRef: detail.endpoint.notificationEndpointId,
      expectedRevision: detail.endpoint.revision,
      etag: detail.etag,
      reason,
    });
  }
  const rejected = pending && !pending.uncertain && !pending.operationId;
  return (
    <section aria-labelledby={`${formId}-heading`} className="min-w-0 space-y-5">
      <h2 id={`${formId}-heading`} className="text-xl font-semibold">
        Notification endpoints
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
            <option value="channel">Channel</option>
            <option value="destinationRef">Destination reference</option>
          </select>
        </label>
        <label>
          Filter value
          <input
            className={fieldClass}
            value={filterValue}
            maxLength={400}
            required={!!filterField}
            onChange={(event) => setFilterValue(event.target.value)}
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
          Refresh endpoints
        </button>
      </form>
      {listing ? (
        <>
          <p>
            {listing.page.total === null
              ? 'Total unknown'
              : `${listing.page.total} matching endpoints`}{' '}
            · Completeness: {listing.page.completeness}
          </p>
          {listing.page.authorizedEmpty ? (
            <p>No authorized endpoints match this filter.</p>
          ) : !listing.page.items.length ? (
            <p>No rows returned; completeness remains {listing.page.completeness}.</p>
          ) : (
            <ul aria-label="Endpoint results" className="space-y-3">
              {listing.page.items.map((item) => (
                <li
                  key={item.notificationEndpointId}
                  className="min-w-0 break-words rounded border border-[color:var(--border)] p-3"
                >
                  <p>
                    {item.channel} · {item.state}
                  </p>
                  <p className="break-all">{item.destinationRef}</p>
                  <p className="break-all">{item.notificationEndpointId}</p>
                  <button
                    className={buttonClass}
                    type="button"
                    disabled={busy}
                    onClick={() => void inspect(item.notificationEndpointId)}
                  >
                    Inspect {item.notificationEndpointId}
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
          className="min-w-0 space-y-3 rounded border border-[color:var(--border)] p-4"
        >
          <h3 ref={heading} tabIndex={-1} id={`${formId}-detail`}>
            Endpoint details
          </h3>
          <dl className="grid gap-2 break-words sm:grid-cols-2">
            {[
              ['Endpoint', detail.endpoint.notificationEndpointId],
              ['Channel', detail.endpoint.channel],
              ['Destination', detail.endpoint.destinationRef],
              ['State', detail.endpoint.state],
              ['Revision', detail.endpoint.revision],
              ['Created', detail.endpoint.createdAt],
              ['Updated', detail.endpoint.updatedAt],
            ].map(([label, value]) => (
              <div key={label} className="min-w-0">
                <dt>{label}</dt>
                <dd className="break-all">{value}</dd>
              </div>
            ))}
          </dl>
          <p>Only an admitted destination is used. Arbitrary egress is disabled.</p>
          <p>
            Credential validity is checked by the service during verification. Endpoint state does
            not establish notification delivery.
          </p>
          {detail.endpoint.state !== 'RETIRED' ? (
            <section aria-label="Replace notification endpoint" className="space-y-3">
              <button
                className={buttonClass}
                disabled={busy || !!pending}
                type="button"
                onClick={() => void loadReplacements()}
              >
                Load replacement choices
              </button>
              {choices ? (
                <form className="space-y-3" onSubmit={(event) => void reviewReplacement(event)}>
                  <p>
                    Choices for revision {choices.choices.revision}. Replacement disables
                    verification; quarantine is preserved.
                  </p>
                  {choices.choices.items.length ? (
                    <label>
                      Endpoint replacement
                      <select
                        className={fieldClass}
                        required
                        disabled={busy || !!pending}
                        value={replacementDigest}
                        onChange={(event) => {
                          setReplacementDigest(event.target.value);
                          setReplacementReview(undefined);
                        }}
                      >
                        <option value="">Choose a replacement</option>
                        {choices.choices.items.map((item) => (
                          <option key={item.replacementDigest} value={item.replacementDigest}>
                            {item.channel} · {item.destinationRef} · {item.replacementDigest}
                          </option>
                        ))}
                      </select>
                    </label>
                  ) : (
                    <p>No replacements are available for this revision.</p>
                  )}
                  <label>
                    Replacement reason
                    <textarea
                      className={fieldClass}
                      required
                      maxLength={1024}
                      disabled={busy || !!pending}
                      value={replacementReason}
                      onChange={(event) => {
                        setReplacementReason(event.target.value);
                        setReplacementReview(undefined);
                      }}
                    />
                  </label>
                  <button
                    className={buttonClass}
                    type="submit"
                    disabled={busy || !!pending || !replacementDigest}
                  >
                    Review endpoint replacement
                  </button>
                </form>
              ) : null}
              {replacementReview ? (
                <section aria-label="Endpoint replacement review" className="space-y-2 break-all">
                  <p>
                    {replacementReview.choice.channel} · {replacementReview.choice.destinationRef}
                  </p>
                  <p>
                    Revision {replacementReview.request.expectedRevision} ·{' '}
                    {replacementReview.request.replacementDigest}
                  </p>
                  <p>{replacementReview.request.reason}</p>
                  <p>Candidate digest: {replacementReview.request.candidateDigest}</p>
                  <button
                    className={buttonClass}
                    type="button"
                    disabled={busy || !!pending}
                    onClick={() => void authenticateCandidate(replacementReview)}
                  >
                    Authenticate and replace endpoint
                  </button>
                </section>
              ) : null}
            </section>
          ) : null}
          {['DISABLED', 'ACTIVE'].includes(detail.endpoint.state) ? (
            <form onSubmit={verify} className="space-y-3">
              <label>
                Verification reason
                <textarea
                  className={fieldClass}
                  required
                  maxLength={1024}
                  value={reason}
                  onChange={(event) => setReason(event.target.value)}
                />
              </label>
              <p>
                Verify revision {detail.endpoint.revision} in the displayed context. This does not
                send a notification payload.
              </p>
              <button className={buttonClass} type="submit" disabled={busy || !!pending}>
                Verify endpoint
              </button>
            </form>
          ) : (
            <p>
              {detail.endpoint.state === 'QUARANTINED'
                ? 'This endpoint is quarantined. Verification is unavailable.'
                : 'This endpoint is retired and read-only.'}
            </p>
          )}
        </section>
      ) : null}
      <section aria-label="Create notification endpoint" className="space-y-3">
        <form onSubmit={(event) => void reviewCreation(event)} className="space-y-3">
          <label>
            Endpoint channel
            <select
              className={fieldClass}
              value={channel}
              disabled={busy || !!pending}
              onChange={(event) => {
                setChannel(event.target.value as typeof channel);
                setCreation(undefined);
              }}
            >
              <option value="WEBHOOK">Webhook</option>
              <option value="EMAIL">Email</option>
              <option value="OPERATIONS_QUEUE">Operations queue</option>
            </select>
          </label>
          <label>
            Endpoint destination reference
            <input
              className={fieldClass}
              required
              value={destination}
              disabled={busy || !!pending}
              onChange={(event) => {
                setDestination(event.target.value);
                setCreation(undefined);
              }}
            />
          </label>
          <label>
            Creation reason
            <textarea
              className={fieldClass}
              required
              maxLength={1024}
              value={createReason}
              disabled={busy || !!pending}
              onChange={(event) => {
                setCreateReason(event.target.value);
                setCreation(undefined);
              }}
            />
          </label>
          <p>
            Use a destination registered by your administrator. Creation checks its admission and
            starts the endpoint disabled.
          </p>
          <button className={buttonClass} disabled={busy || !listing || !!pending} type="submit">
            Review endpoint creation
          </button>
        </form>
        {creation ? (
          <section aria-label="Endpoint creation review" className="space-y-2 break-all">
            <p>
              {creation.request.channel} · {creation.request.destinationRef}
            </p>
            <p>{creation.request.reason}</p>
            <p>Candidate digest: {creation.request.candidateDigest}</p>
            <p>
              Authenticate for this exact candidate. Review does not establish destination
              admission.
            </p>
            <button
              className={buttonClass}
              type="button"
              disabled={busy || !!pending}
              onClick={() => void authenticateCandidate(creation)}
            >
              Authenticate and create endpoint
            </button>
          </section>
        ) : null}
      </section>
      {pending ? (
        <section aria-label="Original endpoint request recovery" className="space-y-2 break-words">
          <p className="break-all">Original request: {pending.request.requestKey}</p>
          <p>
            New endpoint requests remain unavailable until the original result is resolved. Recovery
            keeps the original request and does not authorize another dispatch.
          </p>
          <button
            className={buttonClass}
            type="button"
            disabled={busy || !listing || !!rejected}
            onClick={() =>
              pending.operationId
                ? void recoverOperation(pending.operationId)
                : void submit(pending.request)
            }
          >
            {pending.request.command === 'CREATE'
              ? 'Recover original creation'
              : pending.request.command === 'UPDATE'
                ? 'Recover original replacement'
                : 'Recover original verification'}
          </button>
          {rejected ? (
            <button
              className={buttonClass}
              type="button"
              disabled={busy}
              onClick={() => {
                remember();
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
          Existing endpoint operation ID
          <input
            className={fieldClass}
            value={operationId}
            required
            onChange={(event) => setOperationId(event.target.value)}
          />
        </label>
        <button className={buttonClass} disabled={busy || !listing} type="submit">
          Read endpoint operation
        </button>
      </form>
      {operation ? (
        <section aria-label="Endpoint operation" className="space-y-2 break-all">
          <p>Operation {operation.operationId}</p>
          <p>
            {operation.state} · {operation.truthState}
          </p>
          <p>This is an endpoint operation. Read the endpoint to inspect its current state.</p>
          {operation.resourceRef ? (
            <button
              className={buttonClass}
              disabled={busy || !listing}
              type="button"
              onClick={() => void inspect(operation.resourceRef!)}
            >
              Read operation endpoint
            </button>
          ) : null}
        </section>
      ) : null}
    </section>
  );
}
