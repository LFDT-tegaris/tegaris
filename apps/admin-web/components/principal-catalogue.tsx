'use client';

import Link from 'next/link';
import { useCallback, useEffect, useId, useRef, useState } from 'react';
import { z } from 'zod';
import type { PolicyWorkflowActorBinding as ActorBinding } from './policy-workflow-storage';

const cataloguePage = z
  .object({
    actor: z.object({
      sessionId: z.string(),
      principalId: z.string(),
      participantId: z.string(),
      privacyDomainId: z.string(),
      contextEpoch: z.string(),
    }),
    items: z.array(
      z.object({
        effect: z.object({
          principalId: z.string().min(1),
          displayLabel: z.string().min(1),
          kind: z.string().min(1),
          state: z.string().min(1),
          revision: z.string().min(1),
        }),
      }),
    ),
    nextCursor: z.string().min(1).nullable(),
    observedAt: z.string().datetime(),
    authorizedEmpty: z.boolean(),
  })
  .refine(
    (page) =>
      page.authorizedEmpty === (page.items.length === 0) &&
      (!page.authorizedEmpty || page.nextCursor === null),
  );
type CataloguePage = z.infer<typeof cataloguePage>;
function matchesSelection(
  page: CataloguePage,
  kind: 'USER' | 'WORKLOAD' | 'PLATFORM_OPERATOR',
  after?: string,
) {
  return (
    page.items.length <= 25 &&
    (page.nextCursor === null ||
      (page.items.length === 25 && page.nextCursor === page.items.at(-1)?.effect.principalId)) &&
    page.items.every(
      ({ effect }, index) =>
        z.uuid().safeParse(effect.principalId).success &&
        effect.kind === kind &&
        effect.state === 'ACTIVE' &&
        effect.displayLabel.length <= 160 &&
        /^(?:0|[1-9][0-9]*)$/u.test(effect.revision) &&
        effect.principalId > (page.items[index - 1]?.effect.principalId ?? after ?? ''),
    )
  );
}
interface Query {
  search: string;
  state: string;
  kind: string;
  after?: string;
}
const initialQuery: Query = { search: '', state: 'ACTIVE', kind: 'USER' };
const field = 'min-w-0 rounded border border-[color:var(--border)] bg-[color:var(--canvas)] p-2';
const button =
  'w-fit rounded bg-[color:var(--accent)] px-3 py-2 font-medium text-[color:var(--surface)] disabled:opacity-60';

export function PrincipalCatalogue({
  actor,
  onOpen,
  selection,
}: {
  actor: ActorBinding & { readonly role?: string };
  onOpen?(id: string): void;
  selection?: {
    kind: 'USER' | 'WORKLOAD' | 'PLATFORM_OPERATOR';
    excludedPrincipalId?: string;
    disabled?: boolean;
    onSelect(id: string, displayLabel: string): void;
  };
}) {
  const selectionKind = selection?.kind;
  const title = selectionKind
    ? selectionKind === 'WORKLOAD'
      ? 'Choose a workload principal'
      : 'Choose an independent checker'
    : 'Participant users and principals';
  const stateId = useId();
  const kindId = useId();
  const [page, setPage] = useState<CataloguePage>();
  const [query, setQuery] = useState<Query>(initialQuery);
  const [status, setStatus] = useState('Loading active users in the selected Participant.');
  const [busy, setBusy] = useState(false);
  const generation = useRef(0);
  const activeController = useRef<AbortController | undefined>(undefined);
  const searchInput = useRef<HTMLInputElement>(null);
  const search = useCallback(
    async (next: Query) => {
      const requestGeneration = ++generation.current;
      activeController.current?.abort();
      const controller = new AbortController();
      activeController.current = controller;
      setQuery(next);
      setPage(undefined);
      setBusy(true);
      setStatus('Reading authorized principals.');
      try {
        const response = await fetch(
          `/api/v1/ui/principal-catalogue?${new URLSearchParams({ search: next.search, state: next.state, kind: next.kind, limit: '25', ...(next.after ? { after: next.after } : {}) })}`,
          { cache: 'no-store', signal: controller.signal },
        );
        const body = await response.json().catch(() => undefined);
        if (requestGeneration !== generation.current || controller.signal.aborted) return;
        if (selectionKind && response.status !== 200)
          throw new Error('Principal choices are unavailable. Search again.');
        if (!response.ok)
          throw new Error(
            `${body?.title ?? 'Principal catalogue unavailable.'} (${body?.code ?? 'PC-INTEGRATION-5001'})`,
          );
        const parsed = cataloguePage.safeParse(body);
        if (!parsed.success)
          throw new Error('Principal catalogue could not be confirmed. Search again.');
        const current = parsed.data;
        if (selectionKind && !matchesSelection(current, selectionKind, next.after))
          throw new Error('Principal choices could not be confirmed. Search again.');
        if (
          (
            [
              'sessionId',
              'principalId',
              'participantId',
              'privacyDomainId',
              'contextEpoch',
            ] as const
          ).some((key) => current.actor[key] !== actor[key])
        )
          throw new Error(
            'The working context changed. Refresh the principal workflow before continuing.',
          );
        setPage(current);
        setStatus(
          current.authorizedEmpty
            ? 'No authorized principals match this search.'
            : selectionKind
              ? 'Choose a current principal. The governed owner checks authority before any change.'
              : 'Authorized principals loaded. Open a principal or start a governed role assignment.',
        );
      } catch (error) {
        if (requestGeneration === generation.current && !controller.signal.aborted)
          setStatus(
            selectionKind
              ? 'Principal choices are unavailable. Search again.'
              : error instanceof Error
                ? error.message
                : 'Principal catalogue unavailable.',
          );
      } finally {
        if (requestGeneration === generation.current && !controller.signal.aborted) setBusy(false);
        if (activeController.current === controller) activeController.current = undefined;
      }
    },
    [actor, selectionKind],
  );
  useEffect(() => {
    void search({ ...initialQuery, kind: selectionKind ?? initialQuery.kind });
    if (selectionKind) searchInput.current?.focus();
    return () => {
      generation.current++;
      activeController.current?.abort();
      activeController.current = undefined;
    };
  }, [search, selectionKind]);
  const visiblePage =
    page &&
    (!selectionKind || matchesSelection(page, selectionKind, query.after)) &&
    (
      ['sessionId', 'principalId', 'participantId', 'privacyDomainId', 'contextEpoch'] as const
    ).every((key) => page.actor[key] === actor[key])
      ? page
      : undefined;
  return (
    <section
      className="rounded border border-[color:var(--border)] bg-[color:var(--surface)] p-4"
      aria-label={title}
    >
      <h2 className="text-xl font-semibold">{title}</h2>
      <p className="mt-2 text-[color:var(--muted)]">
        {selectionKind
          ? 'Select an active principal in this Participant. Selection does not approve or authorize the workload change.'
          : 'Policies name required roles. Governed assignments bind those roles to active users or workloads in this Participant.'}
      </p>
      <form
        className="mt-4 grid min-w-0 max-w-2xl gap-3"
        onSubmit={(event) => {
          event.preventDefault();
          const values = new FormData(event.currentTarget);
          void search({
            search: String(values.get('search') ?? ''),
            state: selectionKind ? 'ACTIVE' : String(values.get('state') ?? 'ALL'),
            kind: selectionKind ?? String(values.get('kind') ?? 'ALL'),
          });
        }}
      >
        <label className="grid gap-1">
          Search principal names
          <input ref={searchInput} className={field} name="search" maxLength={160} />
        </label>
        {selectionKind ? (
          <p>
            Active{' '}
            {selectionKind === 'WORKLOAD'
              ? 'workloads'
              : selectionKind === 'PLATFORM_OPERATOR'
                ? 'Platform operators'
                : 'users'}{' '}
            only.
          </p>
        ) : (
          <>
            <div className="grid gap-1">
              <label htmlFor={stateId}>Principal state</label>
              <select id={stateId} className={field} name="state" defaultValue="ACTIVE">
                <option value="ALL">All states</option>
                <option value="PROVISIONED">Provisioned</option>
                <option value="ACTIVE">Active</option>
                <option value="SUSPENDED">Suspended</option>
                <option value="REVOKED">Revoked</option>
                <option value="OFFBOARDED">Offboarded</option>
              </select>
            </div>
            <div className="grid gap-1">
              <label htmlFor={kindId}>Principal type</label>
              <select id={kindId} className={field} name="kind" defaultValue="USER">
                <option value="ALL">All types</option>
                <option value="USER">User</option>
                <option value="WALLET">Wallet</option>
                <option value="WORKLOAD">Workload</option>
                <option value="PLATFORM_OPERATOR">Platform operator</option>
              </select>
            </div>
          </>
        )}
        <button className={button} disabled={busy || selection?.disabled} type="submit">
          Search principals
        </button>
      </form>
      <p className="mt-3 break-words" role="status">
        {status}
      </p>
      {visiblePage ? (
        <>
          <p className="mt-2 text-sm">
            Read at {new Date(visiblePage.observedAt).toLocaleString()}. Each page reflects current
            authorized state.
          </p>
          <div className="mt-4 grid min-w-0 gap-4 lg:grid-cols-2">
            {visiblePage.items.map(({ effect: principal }) => (
              <article
                key={principal.principalId}
                className="min-w-0 rounded border border-[color:var(--border)] p-3"
              >
                <h3 className="break-words font-semibold">{principal.displayLabel}</h3>
                {selectionKind ? (
                  <>
                    <p>
                      Active{' '}
                      {selectionKind === 'WORKLOAD'
                        ? 'workload'
                        : selectionKind === 'PLATFORM_OPERATOR'
                          ? 'Platform operator'
                          : 'user'}
                    </p>
                    <details className="mt-2 text-sm">
                      <summary>Principal details</summary>
                      <p className="mt-2 break-all">{principal.principalId}</p>
                      <p>Revision {principal.revision}</p>
                    </details>
                  </>
                ) : (
                  <>
                    <p>
                      {principal.kind} · {principal.state} · revision {principal.revision}
                    </p>
                    <p className="mt-2 break-all text-sm">{principal.principalId}</p>
                  </>
                )}
                {selectionKind && principal.principalId === selection?.excludedPrincipalId ? (
                  <p>The current maker cannot check their own change.</p>
                ) : (
                  <button
                    type="button"
                    className={`${button} mt-3 max-w-full break-words text-left`}
                    disabled={selection?.disabled || (!selection && !onOpen)}
                    onClick={() =>
                      selection
                        ? selection.onSelect(principal.principalId, principal.displayLabel)
                        : onOpen?.(principal.principalId)
                    }
                  >
                    {selection ? 'Select' : 'Open'} {principal.displayLabel}
                  </button>
                )}
                {!selection && actor.role === 'operator' && principal.state === 'ACTIVE' ? (
                  <Link
                    className={`${button} ml-3 mt-3 inline-block max-w-full break-words`}
                    href={`/govern/memberships?view=grants&principalId=${encodeURIComponent(principal.principalId)}`}
                  >
                    Assign role to {principal.displayLabel}
                  </Link>
                ) : null}
              </article>
            ))}
          </div>
          {visiblePage.nextCursor ? (
            <button
              className={`${button} mt-4`}
              disabled={busy || selection?.disabled}
              onClick={() => void search({ ...query, after: visiblePage.nextCursor! })}
            >
              Next principal page
            </button>
          ) : null}
        </>
      ) : null}
    </section>
  );
}
