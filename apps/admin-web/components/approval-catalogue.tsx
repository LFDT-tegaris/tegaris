'use client';
import { SecondaryPanel } from './secondary-panel';

import { useCallback, useEffect, useRef, useState } from 'react';
import {
  approvalCatalogueSchema,
  approvalRequestLabel,
  approvalStateLabels,
  approvalTime,
  type ApprovalCatalogue as ApprovalCataloguePage,
} from '../lib/approval-catalogue';
import type { TransactionKind } from '../lib/transaction-workflow';
import type { PolicyWorkflowActorBinding } from './policy-workflow-storage';

const buttonClass = 'rounded border border-[color:var(--border)] px-3 py-2 disabled:opacity-50';
const unavailable = 'Requests could not be confirmed. Refresh the list to try again.';

export function ApprovalCatalogue({
  actor,
  supportedKinds,
  disabled = false,
  selectedApprovalId,
  onSelect,
}: {
  actor: PolicyWorkflowActorBinding;
  supportedKinds: readonly TransactionKind[];
  disabled?: boolean;
  selectedApprovalId?: string;
  onSelect(approvalId: string): void;
}) {
  const [page, setPage] = useState<ApprovalCataloguePage>();
  const [status, setStatus] = useState('Loading authorized requests…');
  const [busy, setBusy] = useState(true);
  const [pageIndex, setPageIndex] = useState(0);
  const generation = useRef(0);
  const pending = useRef<AbortController | undefined>(undefined);
  const actorKey = JSON.stringify([
    actor.sessionId,
    actor.principalId,
    actor.participantId,
    actor.privacyDomainId,
    actor.contextEpoch,
  ]);
  const view =
    page &&
    JSON.stringify([
      page.actor.sessionId,
      page.actor.principalId,
      page.actor.participantId,
      page.actor.privacyDomainId,
      page.actor.contextEpoch,
    ]) === actorKey
      ? page
      : undefined;
  const lastPage = Math.max(0, Math.ceil((view?.items.length ?? 0) / 6) - 1);
  const load = useCallback(
    async (cursor?: string) => {
      const current = ++generation.current;
      pending.current?.abort();
      const controller = new AbortController();
      pending.current = controller;
      setPage(undefined);
      setPageIndex(0);
      setBusy(true);
      setStatus('Loading authorized requests…');
      try {
        const response = await fetch(
          `/api/v1/ui/transaction-workbench?${new URLSearchParams({ approvals: '1', ...(cursor ? { approvalsCursor: cursor } : {}) })}`,
          { cache: 'no-store', credentials: 'same-origin', signal: controller.signal },
        );
        const value: unknown = await response.json().catch(() => undefined);
        if (generation.current !== current || controller.signal.aborted) return;
        if (response.status !== 200) throw new Error(unavailable);
        const parsed = approvalCatalogueSchema.safeParse(value);
        if (!parsed.success) throw new Error(unavailable);
        const next = parsed.data;
        if (
          JSON.stringify([
            next.actor.sessionId,
            next.actor.principalId,
            next.actor.participantId,
            next.actor.privacyDomainId,
            next.actor.contextEpoch,
          ]) !== actorKey
        )
          throw new Error('The workspace changed. Refresh the authenticated request context.');
        if (cursor && next.nextCursor === cursor) throw new Error(unavailable);
        setPage(next);
        setStatus('');
      } catch (error) {
        if (generation.current === current && !controller.signal.aborted)
          setStatus(error instanceof Error ? error.message : unavailable);
      } finally {
        if (generation.current === current) setBusy(false);
      }
    },
    [actorKey],
  );
  useEffect(() => {
    const clear = () => {
      generation.current++;
      pending.current?.abort();
      setPage(undefined);
      setBusy(false);
      setStatus('Refresh requests to continue.');
    };
    const focus = () => void load();
    const visibility = () => {
      if (document.visibilityState !== 'visible') clear();
    };
    void load();
    window.addEventListener('blur', clear);
    window.addEventListener('focus', focus);
    document.addEventListener('visibilitychange', visibility);
    return () => {
      generation.current++;
      pending.current?.abort();
      window.removeEventListener('blur', clear);
      window.removeEventListener('focus', focus);
      document.removeEventListener('visibilitychange', visibility);
    };
  }, [load]);
  return (
    <section aria-label="Recent authorized requests" aria-busy={busy} className="my-4 space-y-3">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="text-xl font-semibold">Recent requests</h2>
          <p className="text-sm text-[color:var(--muted)]">
            Choose a request to review its approval and recorded outcome.
          </p>
        </div>
        <button className={buttonClass} disabled={disabled || busy} onClick={() => void load()}>
          Refresh requests
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
                ? 'No authorized requests in this snapshot.'
                : 'No requests returned. Coverage could not be confirmed.'}
            </p>
          ) : (
            <p className="text-sm text-[color:var(--muted)]">
              Showing {pageIndex * 6 + 1}–{Math.min((pageIndex + 1) * 6, view.items.length)} of{' '}
              {view.items.length} loaded authorized requests
              {view.completeness === 'UNKNOWN' ? ' · Coverage could not be confirmed' : ''}
            </p>
          )}
          {view.items.length > 6 ? (
            <nav aria-label="Displayed requests" className="flex flex-wrap gap-2">
              <button
                type="button"
                className={buttonClass}
                disabled={disabled || busy || pageIndex === 0}
                onClick={() => setPageIndex(pageIndex - 1)}
              >
                Previous displayed requests
              </button>
              <button
                type="button"
                className={buttonClass}
                disabled={disabled || busy || pageIndex === lastPage}
                onClick={() => setPageIndex(pageIndex + 1)}
              >
                Next displayed requests
              </button>
            </nav>
          ) : null}
          <ul className="approval-request-list">
            {view.items.slice(pageIndex * 6, (pageIndex + 1) * 6).map((item) => {
              const available = item.kinds.some((kind) => supportedKinds.includes(kind));
              const selected = selectedApprovalId === item.approvalRequestId;
              return (
                <li
                  key={item.approvalRequestId}
                  className="approval-request-row"
                  data-selected={selected || undefined}
                >
                  <div className="approval-request-description">
                    <h3 className="font-semibold">{approvalRequestLabel(item.kinds)}</h3>
                    <p className="approval-request-short-reference">
                      Ref …{item.approvalRequestId.slice(-12)}
                    </p>
                    <SecondaryPanel
                      title="Request reference"
                      className="approval-request-reference"
                    >
                      <div className="mt-2 break-all text-sm">
                        <p>{item.approvalRequestId}</p>
                        <p>Action: {item.actionIntentId}</p>
                        <p>Revision {item.revision}</p>
                      </div>
                    </SecondaryPanel>
                  </div>
                  <div className="approval-request-metadata">
                    <span className="workflow-state-badge">{approvalStateLabels[item.state]}</span>
                    <p>
                      Updated <time dateTime={item.updatedAt}>{approvalTime(item.updatedAt)}</time>
                    </p>
                    <p>
                      {item.relationship === 'MAKER'
                        ? 'Submitted by you'
                        : item.relationship === 'CHECKER'
                          ? 'Assigned to you for review'
                          : 'Authorized review'}
                    </p>
                  </div>
                  <div className="approval-request-action">
                    {selected ? <span className="approval-request-viewing">Viewing</span> : null}
                    {available ? (
                      <button
                        className={buttonClass}
                        disabled={disabled || busy}
                        aria-current={selected ? 'true' : undefined}
                        aria-label={`Review request ${item.approvalRequestId.slice(-36)}`}
                        onClick={() => onSelect(item.approvalRequestId.slice(-36))}
                      >
                        Review request
                      </button>
                    ) : (
                      <p className="text-sm text-[color:var(--muted)]">
                        Open this request in its owning workspace.
                      </p>
                    )}
                  </div>
                </li>
              );
            })}
          </ul>
          {view.nextCursor ? (
            <button
              type="button"
              className={buttonClass}
              disabled={disabled || busy || pageIndex !== lastPage}
              onClick={() => void load(view.nextCursor ?? undefined)}
            >
              Next requests
            </button>
          ) : null}
        </>
      ) : null}
    </section>
  );
}
