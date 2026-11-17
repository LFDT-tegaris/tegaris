'use client';

import { useCallback, useEffect, useRef, useState } from 'react';
import {
  protectedCatalogueSchema,
  protectedProofTime,
  type ProtectedCatalogue,
} from '../lib/protected-proof-catalogue';
import { isSessionTransitionPending, observeSessionTransitions } from './session-transition';

export interface ProtectedProofBinding {
  actorKey: string;
  actor: { participantId: string; privacyDomainId: string };
}
const button = 'rounded border border-[color:var(--border)] px-3 py-2 disabled:opacity-50';
const states = { AVAILABLE: 'Access recorded', CONSUMED: 'Delivery consumed', EXPIRED: 'Expired' };
const unavailable = 'This list could not be confirmed. Refresh to try again.';
export function ProtectedProofCatalogue({
  binding,
  enabled,
  disabled,
  refreshToken,
  selectedRef,
  onSelect,
}: {
  binding: ProtectedProofBinding;
  enabled: boolean;
  disabled: boolean;
  refreshToken: number;
  selectedRef?: string;
  onSelect(kind: 'objects' | 'access', ref: string): void;
}) {
  const [kind, setKind] = useState<'objects' | 'access'>('objects');
  const [page, setPage] = useState<ProtectedCatalogue>();
  const [status, setStatus] = useState('Loading protected proof records…');
  const [busy, setBusy] = useState(true),
    [localPage, setLocalPage] = useState(0);
  const generation = useRef(0),
    pending = useRef<AbortController | undefined>(undefined),
    changing = useRef(false);
  const {
    actorKey,
    actor: { participantId, privacyDomainId },
  } = binding;
  const view =
    page?.actorKey === actorKey && page.catalogue === kind && enabled && !changing.current
      ? page
      : undefined;
  const clear = useCallback(() => {
    generation.current++;
    pending.current?.abort();
    setPage(undefined);
    setLocalPage(0);
    setBusy(false);
  }, []);
  const load = useCallback(
    async (cursor?: string) => {
      clear();
      if (!enabled || changing.current || isSessionTransitionPending()) return;
      const current = generation.current,
        controller = new AbortController();
      pending.current = controller;
      setBusy(true);
      setStatus('Loading protected proof records…');
      try {
        const response = await fetch(
          `/api/v1/ui/protected-proof-workbench?${new URLSearchParams({ catalogue: kind, ...(cursor ? { cursor } : {}) })}`,
          { cache: 'no-store', credentials: 'same-origin', signal: controller.signal },
        );
        const value: unknown = await response.json().catch(() => undefined);
        if (current !== generation.current || controller.signal.aborted) return;
        const parsed = protectedCatalogueSchema.safeParse(value);
        if (response.status !== 200 || !parsed.success) throw new Error(unavailable);
        const next = parsed.data;
        if (
          next.actorKey !== actorKey ||
          next.actor.participantId !== participantId ||
          next.actor.privacyDomainId !== privacyDomainId ||
          next.catalogue !== kind
        )
          throw new Error('The workspace changed. Refresh evidence before continuing.');
        if (cursor && next.nextCursor === cursor) throw new Error(unavailable);
        setPage(next);
        setStatus('');
      } catch (error) {
        if (current === generation.current && !controller.signal.aborted)
          setStatus(error instanceof Error ? error.message : unavailable);
      } finally {
        if (current === generation.current) setBusy(false);
      }
    },
    [actorKey, participantId, privacyDomainId, kind, enabled, clear],
  );
  useEffect(() => {
    changing.current = isSessionTransitionPending();
    void load();
    const stop = observeSessionTransitions(
      () => {
        changing.current = true;
        clear();
        setStatus('The workspace is changing.');
      },
      (blocked) => {
        changing.current = blocked;
        if (!blocked) void load();
      },
    );
    const hidden = () => {
      if (document.visibilityState !== 'visible') {
        clear();
        setStatus('Refresh to continue.');
      }
    };
    window.addEventListener('blur', clear);
    document.addEventListener('visibilitychange', hidden);
    return () => {
      generation.current++;
      pending.current?.abort();
      stop();
      window.removeEventListener('blur', clear);
      document.removeEventListener('visibilitychange', hidden);
    };
  }, [load, clear, refreshToken]);
  const lastPage = Math.max(0, Math.ceil((view?.items.length ?? 0) / 6) - 1);
  const locked = disabled || busy || !enabled || changing.current;
  return (
    <section className="space-y-3" aria-label="Authorized protected proof records" aria-busy={busy}>
      <nav className="proof-catalogue-tabs" aria-label="Protected proof collections">
        <button
          type="button"
          disabled={locked}
          aria-pressed={kind === 'objects'}
          onClick={() => setKind('objects')}
        >
          Proof library
        </button>
        <button
          type="button"
          disabled={locked}
          aria-pressed={kind === 'access'}
          onClick={() => setKind('access')}
        >
          Approved access
        </button>
      </nav>
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="text-xl font-semibold">
            {kind === 'objects' ? 'Protected proof records' : 'Approved access requests'}
          </h2>
          <p className="text-sm text-[color:var(--muted)]">
            {kind === 'objects'
              ? 'Select a retained proof record to review its purpose and request governed access.'
              : 'Select access to review its current status and original delivery.'}
          </p>
        </div>
        <button className={button} disabled={locked} onClick={() => void load()}>
          Refresh proof records
        </button>
      </div>
      <p role="status" aria-live="polite">
        {status}
      </p>
      {view ? (
        <>
          {view.authorizedEmpty ? (
            <p className="workflow-empty">
              {view.completeness === 'COMPLETE'
                ? kind === 'objects'
                  ? 'No authorized protected proof records in this snapshot.'
                  : 'No authorized access requests in this snapshot.'
                : 'No records returned. Coverage could not be confirmed.'}
            </p>
          ) : (
            <p className="text-sm text-[color:var(--muted)]">
              Showing {localPage * 6 + 1}–{Math.min((localPage + 1) * 6, view.items.length)} of{' '}
              {view.items.length} loaded records
              {view.completeness === 'UNKNOWN' ? ' · Coverage could not be confirmed' : ''}
            </p>
          )}
          {view.items.length > 6 ? (
            <nav className="flex flex-wrap gap-2" aria-label="Displayed protected proofs">
              <button
                className={button}
                disabled={locked || localPage === 0}
                onClick={() => setLocalPage(localPage - 1)}
              >
                Previous displayed proofs
              </button>
              <button
                className={button}
                disabled={locked || localPage === lastPage}
                onClick={() => setLocalPage(localPage + 1)}
              >
                Next displayed proofs
              </button>
            </nav>
          ) : null}
          <ul className="proof-catalogue-list">
            {view.items.slice(localPage * 6, (localPage + 1) * 6).map((item) => {
              const access = 'accessRef' in item,
                ref = access ? item.accessRef : item.objectRef;
              return (
                <li key={ref} className="proof-catalogue-row">
                  <div>
                    <h3>{item.purpose}</h3>
                    <p>Case {item.caseReference}</p>
                    <p className="text-sm text-[color:var(--muted)]">
                      Ref …{ref.slice(-12)} · Version {item.objectVersion}
                    </p>
                    <p className="text-sm">
                      {access ? states[item.state] : 'Retention until'}
                      {access ? ' · Expires ' : ' '}
                      {protectedProofTime(access ? item.expiresAt : item.retainUntil)}
                    </p>
                    <details>
                      <summary>Record reference</summary>
                      <p className="break-all">{ref}</p>
                    </details>
                  </div>
                  <div className="proof-catalogue-action">
                    <button
                      className={button}
                      disabled={locked}
                      aria-current={selectedRef === ref ? 'true' : undefined}
                      aria-label={`${access ? 'Review access' : 'Review proof'} ${ref.slice(-36)}`}
                      onClick={() => onSelect(kind, ref)}
                    >
                      {access ? 'Review access' : 'Review proof'}
                    </button>
                    {selectedRef === ref ? (
                      <span className="workflow-state-badge">Viewing</span>
                    ) : null}
                  </div>
                </li>
              );
            })}
          </ul>
          {view.nextCursor ? (
            <button
              className={button}
              disabled={locked}
              onClick={() => void load(view.nextCursor!)}
            >
              Next proof records
            </button>
          ) : null}
        </>
      ) : null}
    </section>
  );
}
