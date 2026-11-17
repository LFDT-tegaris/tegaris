'use client';

import { useCallback, useEffect, useRef, useState } from 'react';
import { localFactAction, performWebAuthnStepUp } from '@openpc/ui-shell';
import { LocalSessionSurface } from './local-session';
import type {
  FactArtifact,
  FactOperation,
  FactSource,
  FactProjection,
} from '../app/api/v1/ui/local-fact-workbench';

interface Page<T> {
  items: T[];
  nextCursor: string | null;
  total: string | null;
}
interface View {
  actor: {
    sessionId: string;
    participantId: string;
    privacyDomainId: string;
    principalId: string;
    contextEpoch: string;
  };
  artifacts: Page<FactArtifact>;
  sources: Page<FactSource>;
  projections: Page<FactProjection>;
  selected: { artifact: FactArtifact; etag: string } | null;
  operation: FactOperation | null;
}
const endpoint = '/api/v1/ui/fact-workbench';
const field = 'mt-1 w-full rounded border p-2 bg-[color:var(--surface)]';
const button = 'rounded border px-3 py-2 disabled:opacity-50';
async function response<T>(result: Response): Promise<T> {
  const body = await result.json();
  if (!result.ok)
    throw new Error(
      `${body.title ?? 'Request unavailable'} (${body.code ?? 'PC-INTEGRATION-5001'})`,
    );
  return body as T;
}

export function FactWorkflow() {
  const [view, setView] = useState<View>();
  const [resourceRef, setResourceRef] = useState('');
  const [operationId, setOperationId] = useState('');
  const [reason, setReason] = useState('');
  const [command, setCommand] = useState<object>();
  const [message, setMessage] = useState('');
  const [busy, setBusy] = useState(false);
  const requestGeneration = useRef(0);
  const actor = useRef<string | undefined>(undefined);
  function clearContext() {
    actor.current = undefined;
    setView(undefined);
    setCommand(undefined);
    setResourceRef('');
    setOperationId('');
    setReason('');
  }
  const read = useCallback(
    async (
      selected = '',
      operation = '',
      cursor = '',
      sourceCursor = '',
      projectionCursor = '',
    ) => {
      const generation = ++requestGeneration.current;
      setBusy(true);
      try {
        const query = new URLSearchParams();
        if (selected) query.set('resourceRef', selected);
        if (operation) query.set('operationId', operation);
        if (cursor) query.set('cursor', cursor);
        if (sourceCursor) query.set('sourceCursor', sourceCursor);
        if (projectionCursor) query.set('projectionCursor', projectionCursor);
        const next = await response<View>(
          await fetch(`${endpoint}?${query}`, { cache: 'no-store' }),
        );
        if (generation !== requestGeneration.current) return;
        const identity = JSON.stringify(next.actor);
        if (actor.current && actor.current !== identity) {
          clearContext();
          next.selected = null;
          next.operation = null;
        }
        actor.current = identity;
        setView(next);
        setMessage(
          'Current authorized facts loaded. Admission success and policy readiness are separate.',
        );
      } catch (error) {
        if (generation !== requestGeneration.current) return;
        clearContext();
        setMessage(error instanceof Error ? error.message : 'Facts are unavailable.');
      } finally {
        if (generation === requestGeneration.current) setBusy(false);
      }
    },
    [],
  );
  useEffect(() => {
    const refresh = () => {
      void read();
    };
    refresh();
    window.addEventListener('focus', refresh);
    return () => {
      ++requestGeneration.current;
      window.removeEventListener('focus', refresh);
    };
  }, [read]);
  async function admit(replay = false) {
    if (!view?.selected || (!replay && !reason.trim())) return;
    const selected = view.selected;
    const input = replay
      ? command
      : {
          actor: view.actor,
          resourceRef: selected.artifact.factArtifactId,
          etag: selected.etag,
          idempotencyKey: crypto.randomUUID(),
          body: {
            actionIntentId: localFactAction.downstreamActionIntentId,
            actionIntentDigest: localFactAction.downstreamActionIntentDigest,
            expectedRevision: selected.artifact.revision,
            replacementDigest: selected.artifact.artifactDigest,
            reason,
          },
        };
    if (!input) return;
    const expectedActor = JSON.stringify(view.actor);
    setCommand(input);
    setBusy(true);
    try {
      await performWebAuthnStepUp({
        actionIntentId: localFactAction.actionIntentId,
        actionIntentDigest: localFactAction.actionIntentDigest,
        stepUp: 'FRESH_WEBAUTHN_MAX_5M',
      });
      const session = await response<Record<string, unknown>>(
        await fetch('/api/v1/ui/local-session', { cache: 'no-store' }),
      );
      if (
        !session.authenticated ||
        session.contextMode !== 'PARTICIPANT' ||
        Object.entries(view.actor).some(([key, value]) => session[key] !== value) ||
        actor.current !== expectedActor
      ) {
        ++requestGeneration.current;
        clearContext();
        throw new Error('The session or context changed. Refresh before continuing.');
      }
      const operation = await response<FactOperation>(
        await fetch(endpoint, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(input),
        }),
      );
      if (actor.current !== expectedActor) {
        clearContext();
        return;
      }
      setOperationId(operation.operationId);
      await read(selected.artifact.factArtifactId, operation.operationId);
      setMessage(
        `Admission operation ${operation.state}. Read the artifact state for current readiness.`,
      );
    } catch (error) {
      setMessage(
        error instanceof Error
          ? error.message
          : 'Admission result unavailable. Read the operation before submitting new work.',
      );
    } finally {
      setBusy(false);
    }
  }
  return (
    <div className="space-y-5">
      <LocalSessionSurface />
      <p role="status" aria-live="polite">
        {message}
      </p>
      <button
        className={button}
        type="button"
        disabled={busy}
        onClick={() => void read(resourceRef, operationId)}
      >
        Refresh facts
      </button>
      {view ? (
        <>
          <p>
            Participant: {view.actor.participantId} · Privacy domain: {view.actor.privacyDomainId}
          </p>
          <section aria-labelledby="fact-sources-title">
            <h2 id="fact-sources-title" className="text-xl">
              Sources and projection profiles
            </h2>
            <p>
              Sources supply candidates. Qualification and projection readiness do not themselves
              admit a fact.
            </p>
            <ul>
              {view.sources.items.map((source) => (
                <li key={source.indexerProfileId}>
                  {source.indexerProfileId} — {source.engine} — {source.state} — {source.authority}
                </li>
              ))}
            </ul>
            {view.sources.nextCursor ? (
              <button
                className={button}
                disabled={busy}
                onClick={() => void read(resourceRef, operationId, '', view.sources.nextCursor!)}
              >
                Next sources
              </button>
            ) : null}
            <ul>
              {view.projections.items.map((plan) => (
                <li key={plan.projectionPlanId}>
                  {plan.projectionPlanId} — source {plan.indexerProfileId} — {plan.state} —{' '}
                  {plan.readiness}
                </li>
              ))}
            </ul>
            {view.projections.nextCursor ? (
              <button
                className={button}
                disabled={busy}
                onClick={() =>
                  void read(resourceRef, operationId, '', '', view.projections.nextCursor!)
                }
              >
                Next projections
              </button>
            ) : null}
          </section>
          <section aria-labelledby="fact-artifacts-title">
            <h2 id="fact-artifacts-title" className="text-xl">
              Canonical fact artifacts
            </h2>
            <p>
              ADMITTED means current signed readiness. STALE, REORG, INVALIDATED and QUARANTINED
              cannot satisfy policy.
            </p>
            {view.artifacts.items.length ? (
              <div
                role="region"
                aria-label="Fact artifacts"
                tabIndex={0}
                className="overflow-x-auto"
              >
                <table className="w-full">
                  <thead>
                    <tr>
                      <th scope="col">Artifact</th>
                      <th scope="col">State</th>
                      <th scope="col">Revision</th>
                      <th scope="col">Updated</th>
                      <th scope="col">Action</th>
                    </tr>
                  </thead>
                  <tbody>
                    {view.artifacts.items.map((item) => (
                      <tr key={item.factArtifactId}>
                        <th scope="row" className="break-all">
                          {item.factArtifactId}
                        </th>
                        <td>{item.state}</td>
                        <td>{item.revision}</td>
                        <td>
                          <time dateTime={item.updatedAt}>{item.updatedAt}</time>
                        </td>
                        <td>
                          <button
                            type="button"
                            className={button}
                            disabled={busy}
                            onClick={() => {
                              setResourceRef(item.factArtifactId);
                              setCommand(undefined);
                              void read(item.factArtifactId);
                            }}
                            aria-label={`Inspect ${item.factArtifactId}`}
                          >
                            Inspect
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <p>No fact artifacts in this authorized scope.</p>
            )}
            {view.artifacts.nextCursor ? (
              <button
                className={button}
                disabled={busy}
                onClick={() => void read(resourceRef, operationId, view.artifacts.nextCursor!)}
              >
                Next artifacts
              </button>
            ) : null}
          </section>
        </>
      ) : null}
      <form
        onSubmit={(event) => {
          event.preventDefault();
          setCommand(undefined);
          void read(resourceRef, operationId);
        }}
        className="space-y-3"
      >
        <label className="block">
          Candidate or artifact resource reference
          <input
            className={field}
            value={resourceRef}
            onChange={(event) => {
              setResourceRef(event.target.value);
              setCommand(undefined);
            }}
            placeholder="urn:openpc:resource:…"
          />
        </label>
        <label className="block">
          Operation ID for durable readback
          <input
            className={field}
            value={operationId}
            onChange={(event) => setOperationId(event.target.value)}
          />
        </label>
        <button className={button} disabled={busy} type="submit">
          Read selected fact and operation
        </button>
      </form>
      {view?.selected ? (
        <section aria-labelledby="selected-fact-title" className="space-y-3">
          <h2 id="selected-fact-title" className="text-xl">
            Selected fact
          </h2>
          <p className="break-all">{view.selected.artifact.factArtifactId}</p>
          <p>
            Current state: <strong>{view.selected.artifact.state}</strong>; revision{' '}
            {view.selected.artifact.revision}
          </p>
          <p className="break-all">Artifact digest: {view.selected.artifact.artifactDigest}</p>
          <p className="break-all">
            Authority generation: {view.selected.artifact.authorityGeneration}
          </p>
          <label className="block">
            Admission reason
            <textarea
              className={field}
              maxLength={1024}
              value={reason}
              onChange={(event) => setReason(event.target.value)}
            />
          </label>
          <button
            className={button}
            disabled={busy || !reason.trim()}
            type="button"
            onClick={() => void admit()}
          >
            Verify and admit selected candidate
          </button>
          {command ? (
            <button
              className={button}
              disabled={busy}
              type="button"
              onClick={() => void admit(true)}
            >
              Retry exact admission
            </button>
          ) : null}
        </section>
      ) : null}
      {view?.operation ? (
        <section aria-labelledby="fact-operation-title">
          <h2 id="fact-operation-title" className="text-xl">
            Admission operation
          </h2>
          <p>{view.operation.operationId}</p>
          <p>
            {view.operation.state} / {view.operation.truthState}
          </p>
          <p>Resource: {view.operation.resourceRef}</p>
          <p>
            This receipt records admission. Current artifact state determines readiness; replay does
            not renew freshness.
          </p>
        </section>
      ) : null}
    </div>
  );
}
