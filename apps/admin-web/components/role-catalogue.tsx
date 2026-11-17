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
            id: z.uuid(),
            participantId: z.uuid(),
            roleId: z.string().regex(/^urn:openpc:role:[0-9a-f-]{36}$/u),
            displayName: z.string().min(1),
            state: z.enum(['ACTIVE', 'ARCHIVED']),
            revision: z.string().regex(/^(?:0|[1-9][0-9]*)$/u),
            actionIntentIds: z.array(z.string()),
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
        (page.items.length === 25 && page.nextCursor === page.items.at(-1)?.effect.id)),
  );
export { cataloguePage as roleCataloguePage };
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

export function RoleCatalogue({
  actor,
  onOpen,
}: {
  actor: ActorBinding;
  onOpen(id: string): void;
}) {
  const stateId = useId();
  const [page, setPage] = useState<CataloguePage>();
  const [query, setQuery] = useState<Query>(initialQuery);
  const [status, setStatus] = useState('Loading active roles in the selected Participant.');
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
      setStatus('Reading authorized roles.');
      try {
        const response = await fetch(
          `/api/v1/ui/role-catalogue?${new URLSearchParams({ search: next.search, state: next.state, limit: '25', ...(next.after ? { after: next.after } : {}) })}`,
          { cache: 'no-store', signal: controller.signal },
        );
        const body = await response.json().catch(() => undefined);
        if (requestGeneration !== generation.current || controller.signal.aborted) return;
        if (response.status !== 200) {
          setStatus('Role catalogue unavailable. Search again.');
          return;
        }
        const parsed = cataloguePage.safeParse(body);
        if (
          !parsed.success ||
          parsed.data.items.some(
            ({ effect }, index) =>
              effect.participantId !== actor.participantId ||
              (next.state !== 'ALL' && effect.state !== next.state) ||
              !effect.displayName.toLowerCase().includes(next.search.trim().toLowerCase()) ||
              effect.id <= (parsed.data.items[index - 1]?.effect.id ?? next.after ?? ''),
          )
        ) {
          setStatus('Role catalogue could not be confirmed. Search again.');
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
          setStatus('The working context changed. Refresh the role workflow before continuing.');
          return;
        }
        setPage(current);
        setStatus(
          current.authorizedEmpty
            ? next.search === '' && next.state === 'ACTIVE'
              ? 'No active roles exist in this Participant.'
              : 'No authorized roles match the current filters.'
            : 'Authorized roles loaded. Select a role to view its current details.',
        );
      } catch {
        if (requestGeneration === generation.current && !controller.signal.aborted)
          setStatus('Role catalogue unavailable. Search again.');
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
  }, [search]);
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
      aria-label="Role catalogue"
    >
      <h2 className="text-xl font-semibold">Role catalogue</h2>
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
          Search role names
          <input className={field} name="search" maxLength={160} />
        </label>
        <div className="grid gap-1">
          <label htmlFor={stateId}>Role state</label>
          <select id={stateId} className={field} name="state" defaultValue="ACTIVE">
            <option value="ALL">All states</option>
            <option value="ACTIVE">Active</option>
            <option value="ARCHIVED">Archived</option>
          </select>
        </div>
        <button className={button} disabled={busy} type="submit">
          Search roles
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
            {visiblePage.items.map(({ effect: role }) => (
              <article
                key={role.id}
                className="min-w-0 rounded border border-[color:var(--border)] p-3"
              >
                <h3 className="break-words font-semibold">{role.displayName}</h3>
                <p>
                  {role.state} · revision {role.revision}
                </p>
                <p className="mt-2 break-all text-sm">{role.roleId}</p>
                <details className="mt-3 min-w-0">
                  <summary className="cursor-pointer">
                    Administrative actions ({role.actionIntentIds.length})
                  </summary>
                  {role.actionIntentIds.length ? (
                    <ul className="mt-2 space-y-1">
                      {role.actionIntentIds.map((action) => (
                        <li className="break-all text-sm" key={action}>
                          {action}
                        </li>
                      ))}
                    </ul>
                  ) : (
                    <p>No administrative capabilities.</p>
                  )}
                </details>
                <button
                  type="button"
                  className={`${button} mt-3 max-w-full break-words text-left`}
                  onClick={() => onOpen(role.id)}
                >
                  View details for {role.displayName}
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
              Next role page
            </button>
          ) : null}
        </>
      ) : null}
    </section>
  );
}
