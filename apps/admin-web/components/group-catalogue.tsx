'use client';

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
    items: z
      .array(
        z.object({
          effect: z.object({
            groupId: z.uuid(),
            participantId: z.uuid(),
            groupName: z.string().min(1),
            state: z.enum(['ACTIVE', 'RETIRED']),
            revision: z.string().regex(/^(?:0|[1-9][0-9]*)$/u),
            operationId: z.uuid().nullable(),
          }),
        }),
      )
      .max(25),
    nextCursor: z.uuid().nullable(),
    observedAt: z.string().datetime(),
    authorizedEmpty: z.boolean(),
  })
  .refine(
    (page) =>
      page.authorizedEmpty === (page.items.length === 0) &&
      (page.nextCursor === null ||
        (page.items.length === 25 && page.nextCursor === page.items.at(-1)?.effect.groupId)),
  );
type CataloguePage = z.infer<typeof cataloguePage>;
interface Query {
  search: string;
  state: string;
  after?: string;
}
const initialQuery: Query = { search: '', state: 'ACTIVE' };
const field = 'min-w-0 rounded border border-[color:var(--border)] bg-[color:var(--canvas)] p-2';
const button =
  'w-fit rounded bg-[color:var(--accent)] px-3 py-2 font-medium text-[color:var(--surface)] disabled:opacity-60';

export function GroupCatalogue({
  actor,
  refreshEpoch,
  onOpen,
}: {
  actor: ActorBinding;
  refreshEpoch: number;
  onOpen(id: string): void;
}) {
  const stateId = useId();
  const [page, setPage] = useState<CataloguePage>();
  const [query, setQuery] = useState<Query>(initialQuery);
  const [status, setStatus] = useState('Loading active groups in the selected Participant.');
  const [busy, setBusy] = useState(false);
  const generation = useRef(0);
  const activeController = useRef<AbortController | undefined>(undefined);
  const search = useCallback(
    async (next: Query) => {
      const requestGeneration = ++generation.current;
      activeController.current?.abort();
      const controller = new AbortController();
      activeController.current = controller;
      setQuery(next);
      setPage(undefined);
      setBusy(true);
      setStatus('Reading authorized groups.');
      try {
        const response = await fetch(
          `/api/v1/ui/group-catalogue?${new URLSearchParams({ search: next.search, state: next.state, limit: '25', ...(next.after ? { after: next.after } : {}) })}`,
          { cache: 'no-store', signal: controller.signal },
        );
        const body = await response.json().catch(() => undefined);
        if (requestGeneration !== generation.current || controller.signal.aborted) return;
        if (response.status !== 200) {
          setStatus('Group catalogue unavailable. Search again.');
          return;
        }
        const parsed = cataloguePage.safeParse(body);
        if (
          !parsed.success ||
          parsed.data.items.some(
            ({ effect }, index) =>
              effect.participantId !== actor.participantId ||
              (next.state !== 'ALL' && effect.state !== next.state) ||
              !effect.groupName.toLowerCase().includes(next.search.trim().toLowerCase()) ||
              effect.groupId <= (parsed.data.items[index - 1]?.effect.groupId ?? next.after ?? ''),
          )
        ) {
          setStatus('Group catalogue could not be confirmed. Search again.');
          return;
        }
        const current = parsed.data;
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
        ) {
          setStatus('The working context changed. Refresh the group workflow before continuing.');
          return;
        }
        setPage(current);
        setStatus(
          current.authorizedEmpty
            ? next.search === '' && next.state === 'ACTIVE'
              ? 'No active groups exist in this Participant.'
              : 'No authorized groups match the current filters.'
            : 'Authorized groups loaded. Select a group to view its current details.',
        );
      } catch {
        if (requestGeneration === generation.current && !controller.signal.aborted)
          setStatus('Group catalogue unavailable. Search again.');
      } finally {
        if (requestGeneration === generation.current && !controller.signal.aborted) setBusy(false);
        if (activeController.current === controller) activeController.current = undefined;
      }
    },
    [actor],
  );
  useEffect(() => {
    void search(initialQuery);
    return () => {
      generation.current++;
      activeController.current?.abort();
      activeController.current = undefined;
    };
  }, [search, refreshEpoch]);
  const visiblePage =
    page &&
    (
      ['sessionId', 'principalId', 'participantId', 'privacyDomainId', 'contextEpoch'] as const
    ).every((key) => page.actor[key] === actor[key])
      ? page
      : undefined;
  return (
    <section
      className="rounded border border-[color:var(--border)] bg-[color:var(--surface)] p-4"
      aria-label="Group catalogue"
    >
      <h2 className="text-xl font-semibold">Group catalogue</h2>
      <form
        className="mt-4 grid min-w-0 max-w-2xl gap-3"
        onSubmit={(event) => {
          event.preventDefault();
          const values = new FormData(event.currentTarget);
          void search({
            search: String(values.get('search') ?? ''),
            state: String(values.get('state') ?? 'ALL'),
          });
        }}
      >
        <label className="grid gap-1">
          Search group names
          <input className={field} name="search" maxLength={160} />
        </label>
        <div className="grid gap-1">
          <label htmlFor={stateId}>Group state</label>
          <select id={stateId} className={field} name="state" defaultValue="ACTIVE">
            <option value="ALL">All states</option>
            <option value="ACTIVE">Active</option>
            <option value="RETIRED">Retired</option>
          </select>
        </div>
        <button className={button} disabled={busy} type="submit">
          Search groups
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
            {visiblePage.items.map(({ effect: group }) => (
              <article
                key={group.groupId}
                className="min-w-0 rounded border border-[color:var(--border)] p-3"
              >
                <h3 className="break-words font-semibold">{group.groupName}</h3>
                <p>
                  {group.state} · revision {group.revision}
                </p>
                <p className="mt-2 break-all text-sm">{group.groupId}</p>
                <p className="mt-2 break-all text-sm">
                  Operation: {group.operationId ?? 'No recorded mutation'}
                </p>
                <button
                  type="button"
                  className={`${button} mt-3 max-w-full break-words text-left`}
                  onClick={() => onOpen(group.groupId)}
                >
                  View details for {group.groupName}
                </button>
              </article>
            ))}
          </div>
          {visiblePage.nextCursor ? (
            <button
              className={`${button} mt-4`}
              disabled={busy}
              onClick={() => void search({ ...query, after: visiblePage.nextCursor! })}
            >
              Next group page
            </button>
          ) : null}
        </>
      ) : null}
    </section>
  );
}
