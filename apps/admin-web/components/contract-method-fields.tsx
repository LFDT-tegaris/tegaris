'use client';

import { useCallback, useEffect, useId, useRef, useState } from 'react';
import { z } from 'zod';
import {
  contractMethodChoicesSchema,
  type ContractMethodChoice,
} from '../lib/contract-method-choices';
import { inspectionActorKey, methodPolicyReference } from '../lib/contract-method-inspection';
import type { PolicyWorkflowActorBinding } from './policy-workflow-storage';
import { roleCataloguePage } from './role-catalogue';
import { isSessionTransitionPending, observeSessionTransitions } from './session-transition';

const field =
  'mt-1 min-w-0 w-full rounded border border-[color:var(--border)] bg-[color:var(--surface)] p-2';
const button = 'rounded border border-[color:var(--border)] px-3 py-2 text-sm disabled:opacity-50';
type Bound = { actor: PolicyWorkflowActorBinding };

function useCurrentRead<T extends Bound>(
  actor: PolicyWorkflowActorBinding | undefined,
  url: string | undefined,
  schema: z.ZodType<T>,
) {
  const [revision, setRevision] = useState(0);
  const [paused, setPaused] = useState(isSessionTransitionPending);
  const [read, setRead] = useState<{
    key: string;
    data?: T;
    status: 'loading' | 'loaded' | 'unavailable';
  }>();
  const controller = useRef<AbortController | undefined>(undefined);
  const actorKey = actor ? inspectionActorKey(actor) : '';
  const key = JSON.stringify([actorKey, url, revision, paused]);
  const active = useRef(key);
  active.current = key;
  const changing = paused || isSessionTransitionPending();
  const refresh = useCallback(() => {
    controller.current?.abort();
    setRead(undefined);
    setRevision((value) => value + 1);
  }, []);
  useEffect(
    () =>
      observeSessionTransitions(
        () => {
          setPaused(true);
          refresh();
        },
        (pending) => {
          setPaused(pending);
          refresh();
        },
      ),
    [refresh],
  );
  useEffect(() => {
    controller.current?.abort();
    setRead(undefined);
    if (!actorKey || !url || changing) return;
    const pending = new AbortController();
    controller.current = pending;
    const current = () => !pending.signal.aborted && active.current === key;
    setRead({ key, status: 'loading' });
    void (async () => {
      try {
        const response = await fetch(url, {
          credentials: 'same-origin',
          cache: 'no-store',
          signal: AbortSignal.any([pending.signal, AbortSignal.timeout(20_000)]),
        });
        if (!response.ok) throw new Error('Read unavailable');
        const result = schema.parse(await response.json());
        if (inspectionActorKey(result.actor) !== actorKey) throw new Error('Context changed');
        if (current()) setRead({ key, data: result, status: 'loaded' });
      } catch {
        if (current()) setRead({ key, status: 'unavailable' });
      }
    })();
    return () => pending.abort();
  }, [key, actorKey, url, schema, changing]);
  return { read: read?.key === key && !changing ? read : undefined, refresh, changing };
}

export function ContractMethodSelect({
  actor,
  bindingId,
  abiArtifactId,
  abiDigest,
  value,
  disabled,
  onSelect,
}: {
  actor?: PolicyWorkflowActorBinding;
  bindingId?: string;
  abiArtifactId?: string;
  abiDigest?: string;
  value: string;
  disabled: boolean;
  onSelect(method: ContractMethodChoice): void;
}) {
  const id = useId();
  const reference = bindingId ? methodPolicyReference(bindingId) : undefined;
  const url = reference
    ? `/api/v1/ui/contract-method-choices?${new URLSearchParams({ bindingId: reference })}`
    : undefined;
  const { read, refresh, changing } = useCurrentRead(actor, url, contractMethodChoicesSchema);
  const data = read?.data;
  const confirmed =
    data &&
    data.runtimeBindingId === reference &&
    data.abiArtifactId === abiArtifactId &&
    data.abiDigest === abiDigest
      ? data
      : undefined;
  if (changing || !actor) return null;
  return (
    <div>
      <label className="block" htmlFor={id}>
        Contract method
      </label>
      <select
        id={id}
        className={field}
        value={confirmed?.methods.some((method) => method.signature === value) ? value : ''}
        disabled={disabled || !confirmed?.methods.length}
        onChange={(event) => {
          const method = confirmed?.methods.find((item) => item.signature === event.target.value);
          if (method && !disabled && !isSessionTransitionPending()) onSelect(method);
        }}
      >
        <option value="">Select a method</option>
        {confirmed?.methods.map((method) => (
          <option key={method.signature} value={method.signature}>
            {method.signature} · {method.effect === 'READ' ? 'Read data' : 'Change state'}
          </option>
        ))}
      </select>
      <p className="mt-1 text-sm text-[color:var(--muted)]" role="status">
        {!reference
          ? 'Choose a deployed contract from the library to see its methods.'
          : read?.status === 'loading'
            ? 'Reading the bound ABI…'
            : confirmed
              ? confirmed.methods.length
                ? 'Methods from the ABI attached to this deployed contract.'
                : 'The bound ABI contains no functions.'
              : 'The bound ABI could not be confirmed. Refresh or inspect the method reference below.'}
      </p>
      {reference && !confirmed && read?.status !== 'loading' ? (
        <button type="button" className={button} disabled={disabled} onClick={refresh}>
          Refresh method choices
        </button>
      ) : null}
    </div>
  );
}

export function ContractRoleSelect({
  actor,
  selected,
  disabled,
  onChange,
}: {
  actor?: PolicyWorkflowActorBinding;
  selected: string[];
  disabled: boolean;
  onChange(roles: string[]): void;
}) {
  const id = useId();
  const actorKey = actor ? inspectionActorKey(actor) : '';
  const [draft, setDraft] = useState({ actorKey, search: '' });
  const [storedQuery, setStoredQuery] = useState<{
    actorKey: string;
    search: string;
    after?: string;
  }>({ actorKey, search: '' });
  const search = draft.actorKey === actorKey ? draft.search : '';
  const query: { search: string; after?: string } =
    storedQuery.actorKey === actorKey ? storedQuery : { search: '' };
  const setQuery = (value: { search: string; after?: string }) =>
    setStoredQuery({ actorKey, ...value });
  useEffect(() => {
    const clear = () => {
      setDraft({ actorKey: '', search: '' });
      setStoredQuery({ actorKey: '', search: '' });
    };
    return observeSessionTransitions(clear, (pending) => {
      if (pending) clear();
    });
  }, []);
  const url = `/api/v1/ui/role-catalogue?${new URLSearchParams({ state: 'ACTIVE', limit: '25', search: query.search, ...(query.after ? { after: query.after } : {}) })}`;
  const { read, refresh, changing } = useCurrentRead(actor, url, roleCataloguePage);
  const page = read?.data;
  const valid =
    page &&
    page.items.every(
      ({ effect }, index) =>
        effect.participantId === actor?.participantId &&
        effect.state === 'ACTIVE' &&
        effect.roleId === `urn:openpc:role:${effect.id}` &&
        effect.displayName.toLowerCase().includes(query.search.toLowerCase()) &&
        effect.id > (page.items[index - 1]?.effect.id ?? query.after ?? ''),
    );
  const roles = valid ? page.items.map((item) => item.effect) : [];
  if (changing || !actor) return null;
  return (
    <div className="space-y-2">
      <label className="block" htmlFor={id}>
        Add required role
      </label>
      <select
        id={id}
        className={field}
        value=""
        disabled={disabled || !roles.length}
        onChange={(event) => {
          const role = roles.find((item) => item.roleId === event.target.value);
          if (role && !disabled && !selected.includes(role.roleId) && !isSessionTransitionPending())
            onChange([...selected, role.roleId]);
        }}
      >
        <option value="">Select an active role</option>
        {roles.map((role) => (
          <option key={role.id} value={role.roleId} disabled={selected.includes(role.roleId)}>
            {role.displayName}
          </option>
        ))}
      </select>
      <div className="grid min-w-0 gap-2 sm:grid-cols-[minmax(0,1fr)_auto]">
        <label className="grid gap-1 text-sm">
          Find a role
          <input
            className={field}
            maxLength={160}
            value={search}
            onChange={(event) => setDraft({ actorKey, search: event.target.value })}
          />
        </label>
        <button
          type="button"
          className={button}
          disabled={disabled || read?.status === 'loading'}
          onClick={() => setQuery({ search: search.trim() })}
        >
          Search roles
        </button>
      </div>
      <p className="text-sm text-[color:var(--muted)]" role="status">
        {read?.status === 'loading'
          ? 'Reading authorized roles…'
          : valid
            ? page.authorizedEmpty
              ? 'No authorized active roles match this search.'
              : 'Only active roles authorized in this workspace are listed.'
            : 'Role choices could not be confirmed. Check your account, security key verification and workspace access, then refresh.'}
      </p>
      <div className="flex flex-wrap gap-2">
        {read?.status === 'unavailable' ? (
          <a className={button} href="/home/session">
            Check account & security
          </a>
        ) : null}
        <button
          type="button"
          className={button}
          disabled={disabled || read?.status === 'loading'}
          onClick={refresh}
        >
          Refresh roles
        </button>
        <button
          type="button"
          className={button}
          disabled={disabled || !query.after || read?.status === 'loading'}
          onClick={() => setQuery({ search: query.search })}
        >
          First role page
        </button>
        <button
          type="button"
          className={button}
          disabled={disabled || !valid || !page.nextCursor || read?.status === 'loading'}
          onClick={() => setQuery({ search: query.search, after: page!.nextCursor! })}
        >
          Next role page
        </button>
      </div>
      <p className="text-sm font-medium">
        {selected.length} required {selected.length === 1 ? 'role' : 'roles'} selected
      </p>
      {selected.length ? (
        <ul className="space-y-2">
          {selected.map((value, index) => (
            <li
              key={`${index}:${value}`}
              className="flex min-w-0 flex-wrap items-center justify-between gap-2 rounded border border-[color:var(--border)] p-2"
            >
              <span className="min-w-0 break-words">
                {roles.find((role) => role.roleId === value)?.displayName ??
                  'Existing role reference'}
              </span>
              <button
                type="button"
                className={button}
                disabled={disabled}
                aria-label={`Remove required role ${index + 1}`}
                onClick={() => {
                  if (!isSessionTransitionPending())
                    onChange(selected.filter((_, position) => position !== index));
                }}
              >
                Remove
              </button>
            </li>
          ))}
        </ul>
      ) : null}
    </div>
  );
}
