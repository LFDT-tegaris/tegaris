'use client';

import { useCallback, useEffect, useId, useRef, useState } from 'react';
import { LocalSessionSurface } from './local-session';
import { WorkflowDetails } from './workflow-details';
import { SecondaryPanel } from './secondary-panel';
import type {
  ExplorerIntent,
  ExplorerRead,
  ExplorerStatus,
  ExplorerView,
} from '../app/api/v1/ui/local-privacy-explorer';

const endpoint = '/api/v1/ui/privacy-explorer';
const profileInstruction = 'Enter the registered profile reference from its approved registration.';
const field = 'mt-1 w-full rounded border p-2 bg-[color:var(--surface)]';
const button = 'rounded border px-3 py-2 disabled:opacity-50';
async function decode<T>(response: Response): Promise<T> {
  const body = await response.json();
  if (!response.ok)
    throw new Error(
      `${body.publicTitle ?? body.title ?? 'Request unavailable'} (${body.code ?? 'PC-INTEGRATION-5001'})`,
    );
  return body as T;
}

export function PrivacyExplorerWorkflow({
  evaluationUi = false,
  showSessionControls = true,
}: { evaluationUi?: boolean; showSessionControls?: boolean } = {}) {
  const formId = useId();
  const [view, setView] = useState<ExplorerView>();
  const [profileRef, setProfileRef] = useState('');
  const [purpose, setPurpose] = useState('');
  const [dataClassId, setDataClass] = useState('');
  const [fields, setFields] = useState<string[]>([]);
  const [limit, setLimit] = useState(20);
  const [filters, setFilters] = useState<ExplorerIntent['filters']>([]);
  const [filterValues, setFilterValues] = useState<string[]>([]);
  const [result, setResult] = useState<ExplorerRead>();
  const [cursor, setCursor] = useState<string | null>(null);
  const [occurrenceId, setOccurrenceId] = useState('');
  const [status, setStatus] = useState<ExplorerStatus>();
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState('');
  const generation = useRef(0);
  const pending = useRef<AbortController | undefined>(undefined);
  const selected = view?.profile;
  const profile = selected?.profile;
  const classes =
    profile?.operationVersions.find(
      (item) => item.operationId === 'PXI-READ-GOVERNED-PROJECTION/v1',
    )?.acceptedDataClassIds ?? [];
  const clearResult = useCallback(() => {
    ++generation.current;
    pending.current?.abort();
    setResult(undefined);
    setCursor(null);
    setStatus(undefined);
    setBusy(false);
  }, []);
  const load = useCallback(
    async (reference?: string) => {
      clearResult();
      const current = generation.current;
      const controller = new AbortController();
      pending.current = controller;
      setBusy(true);
      setView(undefined);
      setFields([]);
      setFilters([]);
      setFilterValues([]);
      setDataClass('');
      try {
        const next = await decode<ExplorerView>(
          await fetch(
            `${endpoint}${reference ? `?profileRef=${encodeURIComponent(reference)}` : ''}`,
            { cache: 'no-store', signal: controller.signal },
          ),
        );
        if (generation.current !== current) return;
        setView(next);
        setLimit(Math.min(20, next.profile?.profile.maximumPageSize ?? 20));
        setMessage(
          next.profile
            ? `${next.profile.profile.sourceBinding?.productId ?? next.profile.registrationId} — ${next.profile.state}`
            : profileInstruction,
        );
      } catch (error) {
        if (generation.current === current)
          setMessage(error instanceof Error ? error.message : 'Explorer unavailable.');
      } finally {
        if (generation.current === current) setBusy(false);
      }
    },
    [clearResult],
  );
  useEffect(() => {
    void load();
    const focus = () => {
      void load();
    };
    const hidden = () => {
      if (document.visibilityState !== 'visible') clearResult();
    };
    window.addEventListener('focus', focus);
    window.addEventListener('blur', clearResult);
    document.addEventListener('visibilitychange', hidden);
    return () => {
      clearResult();
      window.removeEventListener('focus', focus);
      window.removeEventListener('blur', clearResult);
      document.removeEventListener('visibilitychange', hidden);
    };
  }, [load, clearResult]);

  async function project(continuation: string | null) {
    if (!view || !profile || selected?.state !== 'REGISTERED') return;
    clearResult();
    const current = generation.current;
    const controller = new AbortController();
    pending.current = controller;
    const id = crypto.randomUUID();
    setOccurrenceId(id);
    setBusy(true);
    setMessage(
      'Request in progress. If the connection is lost, check this occurrence instead of retrying it.',
    );
    const intent: ExplorerIntent = {
      actorKey: view.actorKey,
      profileRef: selected.registrationId,
      purpose,
      dataClassId,
      projectionFields: fields,
      filters,
      limit,
      cursor: continuation,
      occurrenceId: id,
    };
    try {
      const next = await decode<ExplorerRead>(
        await fetch(endpoint, {
          method: 'POST',
          cache: 'no-store',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify(intent),
          signal: controller.signal,
        }),
      );
      if (current !== generation.current) return;
      if (next.actorKey !== view.actorKey || next.occurrenceId !== id)
        throw new Error('The active context changed. Refresh profiles before continuing.');
      setResult(next);
      setCursor(next.result.page.cursor);
      setMessage(
        next.result.outcome === 'COMPLETE' && next.result.records.length === 0
          ? 'The authorized query completed with no visible records.'
          : `${next.result.outcome}: ${next.result.records.length} visible records received.`,
      );
    } catch (error) {
      if (current === generation.current)
        setMessage(
          `${error instanceof Error ? error.message : 'Projection unavailable.'} Check occurrence status for durable state.`,
        );
    } finally {
      if (current === generation.current) setBusy(false);
    }
  }
  async function readStatus() {
    clearResult();
    const current = generation.current;
    const controller = new AbortController();
    pending.current = controller;
    setBusy(true);
    try {
      const next = await decode<ExplorerStatus>(
        await fetch(`${endpoint}?occurrenceId=${encodeURIComponent(occurrenceId)}`, {
          cache: 'no-store',
          signal: controller.signal,
        }),
      );
      if (current !== generation.current) return;
      if (view && next.actorKey !== view.actorKey) {
        setView(undefined);
        throw new Error('The active context changed.');
      }
      setStatus(next);
      setMessage(
        'Occurrence metadata loaded. Release authorization does not establish client receipt.',
      );
    } catch (error) {
      if (current === generation.current)
        setMessage(error instanceof Error ? error.message : 'Status unavailable.');
    } finally {
      if (current === generation.current) setBusy(false);
    }
  }
  const change = (work: () => void) => {
    clearResult();
    work();
  };
  return (
    <div className={`space-y-6${evaluationUi ? ' privacy-explorer-workspace' : ''}`}>
      {showSessionControls && <LocalSessionSurface />}
      <p>
        {evaluationUi
          ? 'Request only the fields needed for your purpose. Each read is checked against current authority before data is released.'
          : 'Request only the fields needed for your purpose. Results are checked against current local authority before release.'}
      </p>
      <div role="status" aria-live="polite" className="break-words">
        {evaluationUi && message === profileInstruction ? null : message}
      </div>
      <section
        className={evaluationUi ? 'privacy-profile-card' : undefined}
        aria-label="Profile selection"
      >
        {evaluationUi && (
          <header>
            <h2>Select a data profile</h2>
            <p id={`${formId}-profile-help`} className="privacy-profile-help">
              Use the reference from an approved registration. Its profile defines the fields,
              filters and page limits available for your request.
            </p>
          </header>
        )}
        <form
          className={evaluationUi ? 'privacy-profile-form' : 'space-y-2'}
          onSubmit={(event) => {
            event.preventDefault();
            void load(profileRef);
          }}
        >
          <label className="block">
            Registered profile reference
            <input
              className={field}
              required
              aria-describedby={evaluationUi ? `${formId}-profile-help` : undefined}
              value={profileRef}
              onChange={(event) =>
                change(() => {
                  setProfileRef(event.target.value);
                  setView(undefined);
                })
              }
            />
          </label>
          <button className={button} disabled={busy || !profileRef}>
            Load profile
          </button>
        </form>
      </section>
      {view ? (
        evaluationUi ? (
          <SecondaryPanel title="Workspace details" closeOnChange={view.actorKey}>
            <p>
              These references identify the current request context. Each read still requires
              current authorization.
            </p>
            <dl className="governance-context-details">
              <div>
                <dt>Participant</dt>
                <dd>{view.actor.participantId}</dd>
              </div>
              <div>
                <dt>Privacy domain</dt>
                <dd>{view.actor.privacyDomainId}</dd>
              </div>
            </dl>
          </SecondaryPanel>
        ) : (
          <p className="break-all">
            Participant {view.actor.participantId} · Privacy domain {view.actor.privacyDomainId}
          </p>
        )
      ) : null}
      <form
        className={evaluationUi ? 'privacy-projection-card space-y-4' : 'space-y-4'}
        hidden={evaluationUi && selected?.state !== 'REGISTERED'}
        onSubmit={(event) => {
          event.preventDefault();
          void project(null);
        }}
      >
        <fieldset disabled={busy || selected?.state !== 'REGISTERED'} className="space-y-4">
          <legend className="text-lg font-semibold">Projection request</legend>
          <label className="block">
            Purpose
            <input
              required
              maxLength={256}
              className={field}
              value={purpose}
              onChange={(event) => change(() => setPurpose(event.target.value))}
            />
          </label>
          <label className="block">
            Data class
            <select
              required
              className={field}
              value={dataClassId}
              onChange={(event) => change(() => setDataClass(event.target.value))}
            >
              <option value="">Choose a data class</option>
              {classes.map((name) => (
                <option key={name}>{name}</option>
              ))}
            </select>
          </label>
          <fieldset className="space-y-2">
            <legend>Requested fields</legend>
            {profile?.allowedFieldIds.map((name) => (
              <label className="flex items-start gap-2 break-all" key={name}>
                <input
                  type="checkbox"
                  checked={fields.includes(name)}
                  onChange={(event) =>
                    change(() =>
                      setFields((current) =>
                        event.target.checked
                          ? [...current, name].sort()
                          : current.filter((value) => value !== name),
                      ),
                    )
                  }
                />
                {name}
              </label>
            ))}
          </fieldset>
          <label className="block">
            Maximum records
            <input
              className={field}
              type="number"
              min={1}
              max={Math.min(1000, profile?.maximumPageSize ?? 1000)}
              required
              value={limit}
              onChange={(event) => change(() => setLimit(Number(event.target.value)))}
            />
          </label>
          <fieldset className="space-y-3">
            <legend>Filters</legend>
            {filters.map((filter, index) => (
              <div key={index} className="grid gap-2 rounded border p-3 sm:grid-cols-2">
                <label>
                  Filter {index + 1} field
                  <select
                    aria-label={`Filter ${index + 1} field`}
                    className={field}
                    value={filter.fieldId}
                    onChange={(event) =>
                      change(() =>
                        setFilters(
                          filters.map((item, i) =>
                            i === index ? { ...item, fieldId: event.target.value } : item,
                          ),
                        ),
                      )
                    }
                  >
                    {fields.map((name) => (
                      <option key={name}>{name}</option>
                    ))}
                  </select>
                </label>
                <label>
                  Filter {index + 1} condition
                  <select
                    className={field}
                    value={filter.filterId}
                    onChange={(event) =>
                      change(() =>
                        setFilters(
                          filters.map((item, i) =>
                            i === index ? { ...item, filterId: event.target.value } : item,
                          ),
                        ),
                      )
                    }
                  >
                    {profile?.allowedFilterIds.map((name) => (
                      <option key={name}>{name}</option>
                    ))}
                  </select>
                </label>
                <label>
                  Filter {index + 1} value (JSON scalar)
                  <input
                    className={field}
                    value={filterValues[index] ?? JSON.stringify(filter.value)}
                    required
                    maxLength={260}
                    onChange={(event) => {
                      clearResult();
                      setFilterValues(
                        filterValues.map((text, i) => (i === index ? event.target.value : text)),
                      );
                      try {
                        const value: unknown = JSON.parse(event.target.value);
                        if (
                          value !== null &&
                          typeof value !== 'string' &&
                          typeof value !== 'boolean' &&
                          !(typeof value === 'number' && Number.isSafeInteger(value))
                        )
                          throw new Error();
                        event.target.setCustomValidity('');
                        setFilters(
                          filters.map((item, i) =>
                            i === index
                              ? {
                                  ...item,
                                  value: value as ExplorerIntent['filters'][number]['value'],
                                }
                              : item,
                          ),
                        );
                      } catch {
                        event.target.setCustomValidity(
                          'Enter a string in quotes, an integer, true, false or null.',
                        );
                      }
                    }}
                  />
                </label>
                <button
                  type="button"
                  className={button}
                  onClick={() =>
                    change(() => {
                      setFilters(filters.filter((_, i) => i !== index));
                      setFilterValues(filterValues.filter((_, i) => i !== index));
                    })
                  }
                >
                  Remove filter {index + 1}
                </button>
              </div>
            ))}
            <button
              type="button"
              className={button}
              disabled={!fields.length || !profile?.allowedFilterIds.length || filters.length >= 32}
              onClick={() =>
                change(() => {
                  setFilters([
                    ...filters,
                    { fieldId: fields[0]!, filterId: profile!.allowedFilterIds[0]!, value: '' },
                  ]);
                  setFilterValues([...filterValues, '""']);
                })
              }
            >
              Add filter
            </button>
          </fieldset>
          <div className="flex flex-wrap gap-3">
            <button className={button} disabled={!fields.length || !profile}>
              Read projection
            </button>
            <button
              type="button"
              className={button}
              disabled={!cursor}
              onClick={() => void project(cursor)}
            >
              Read next page
            </button>
          </div>
        </fieldset>
      </form>
      {result ? (
        <section aria-label="Projection result" className="space-y-3">
          <h2 className="text-lg font-semibold">Visible records — {result.result.outcome}</h2>
          {result.result.records.map((record) => (
            <article key={record.id} className="space-y-2 rounded border p-3 break-words">
              <h3 className="break-all">Record {record.id}</h3>
              <dl>
                {record.fields.map((item) => (
                  <div key={item.fieldId} className="grid gap-1 py-1 sm:grid-cols-2">
                    <dt className="font-medium">{item.fieldId}</dt>
                    <dd className="whitespace-pre-wrap break-all">{JSON.stringify(item.value)}</dd>
                  </div>
                ))}
              </dl>
            </article>
          ))}
        </section>
      ) : null}
      <WorkflowDetails
        key={view?.actorKey ?? 'unavailable'}
        enabled={evaluationUi}
        summary="Check an earlier request"
      >
        <section className="space-y-3" aria-label="Occurrence status">
          <h2 className="text-lg font-semibold">Occurrence status</h2>
          <label className="block">
            Occurrence ID
            <input
              className={field}
              value={occurrenceId}
              onChange={(event) => {
                clearResult();
                setOccurrenceId(event.target.value);
                setStatus(undefined);
              }}
            />
          </label>
          <button
            className={button}
            disabled={busy || !occurrenceId}
            onClick={() => void readStatus()}
          >
            Read occurrence status
          </button>
          {status ? (
            <dl className="space-y-2 break-all">
              <div>
                <dt>Durable state</dt>
                <dd>{status.occurrence.state}</dd>
              </div>
              <div>
                <dt>Client receipt</dt>
                <dd>{status.occurrence.clientReceipt}</dd>
              </div>
              <div>
                <dt>Evidence reference</dt>
                <dd>{status.occurrence.evidenceReference ?? 'No sealed evidence'}</dd>
              </div>
            </dl>
          ) : null}
          <p>
            Interrupted or uncertain reads are never replayed. A new request creates a new
            occurrence and checks current authority.
          </p>
        </section>
      </WorkflowDetails>
    </div>
  );
}
