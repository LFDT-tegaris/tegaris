'use client';

import { useEffect, useId, useRef, useState } from 'react';
import { z } from 'zod';
import type { PolicyWorkflowActorBinding } from './policy-workflow-storage';
import { inspectionActorKey } from '../lib/contract-method-inspection';
import { isSessionTransitionPending, observeSessionTransitions } from './session-transition';
import { readableProviderDate } from './provider-directory';
import { SecondaryPanel } from './secondary-panel';

const actorSchema = z.object({
  sessionId: z.uuid(),
  principalId: z.uuid(),
  participantId: z.uuid(),
  privacyDomainId: z.uuid(),
  contextEpoch: z.string().min(1),
});
const reference = z.string().regex(/^urn:openpc:resource:[0-9a-f-]{36}$/u);
const revision = z.string().regex(/^[1-9][0-9]*$/u);
const targetSchema = z.object({
  targetId: reference,
  participantId: z.string(),
  revision,
  state: z.string(),
  desiredGenerationDigest: z.string().nullable(),
  activeGenerationDigest: z.string().nullable(),
});
const bindingSchema = z.object({
  bindingRef: reference,
  targetRef: reference,
  targetProfileId: z.string().min(1),
  bindingDigest: z.string(),
  publicationOperationRef: reference,
  revision: z.literal('1'),
  runtimePermission: z.literal('NONE_WITHOUT_MATCHING_ENVELOPE'),
  createdAt: z.string(),
});
const page = <T extends z.ZodType>(item: T) =>
  z.object({
    actor: actorSchema,
    result: z.object({
      items: z.array(item),
      nextCursor: z.string().max(2048).nullable(),
      completeness: z.enum(['COMPLETE', 'UNKNOWN']),
      authorizedEmpty: z.boolean(),
    }),
  });
const targets = page(targetSchema),
  bindings = page(bindingSchema);
const inputClass =
  'mt-1 w-full rounded border border-[color:var(--border)] bg-[color:var(--surface)] p-2';
const buttonClass =
  'rounded border border-[color:var(--border)] px-3 py-2 text-sm disabled:opacity-50';
const shortTarget = (value: string) => `Target ${value.slice(-8)}`;

function useProfilePage<T extends { actor: PolicyWorkflowActorBinding }>(
  actor: PolicyWorkflowActorBinding,
  kind: 'runtime' | 'runtime-profiles',
  schema: z.ZodType<T>,
  refreshToken?: string,
) {
  const [cursor, setCursor] = useState<string>();
  const [reload, setReload] = useState(0);
  const [paused, setPaused] = useState(isSessionTransitionPending);
  const [result, setResult] = useState<{ key: string; data?: T; failed?: boolean }>();
  const owner = inspectionActorKey(actor);
  const key = JSON.stringify([owner, cursor, reload, refreshToken, paused]);
  const active = useRef(key);
  active.current = key;
  const changing = paused || isSessionTransitionPending();
  useEffect(
    () =>
      observeSessionTransitions(
        () => {
          setPaused(true);
          setResult(undefined);
        },
        (pending) => {
          setPaused(pending);
          setResult(undefined);
          setCursor(undefined);
          setReload((value) => value + 1);
        },
      ),
    [],
  );
  useEffect(() => {
    setResult(undefined);
    if (changing) return;
    const pending = new AbortController();
    const current = () => !pending.signal.aborted && active.current === key;
    void (async () => {
      try {
        const response = await fetch(
          `/api/v1/ui/setup-workbench?${new URLSearchParams({ kind, ...(cursor ? { cursor } : {}) })}`,
          {
            credentials: 'same-origin',
            cache: 'no-store',
            signal: AbortSignal.any([pending.signal, AbortSignal.timeout(20_000)]),
          },
        );
        if (!response.ok) throw new Error('Owner read unavailable');
        const data = schema.parse(await response.json());
        if (inspectionActorKey(data.actor) !== owner) throw new Error('Context changed');
        if (current()) setResult({ key, data });
      } catch {
        if (current()) setResult({ key, failed: true });
      }
    })();
    return () => pending.abort();
  }, [key, owner, cursor, kind, schema, changing]);
  return {
    data: !changing && result?.key === key ? result.data : undefined,
    failed: !changing && result?.key === key && result.failed,
    changing,
    cursor,
    setCursor,
    refresh: () => {
      setResult(undefined);
      setCursor(undefined);
      setReload((value) => value + 1);
    },
  };
}

export function RuntimeTargetSelect({
  actor,
  value,
  disabled,
  onSelect,
}: {
  actor: PolicyWorkflowActorBinding;
  value: string;
  disabled: boolean;
  onSelect(value: { runtimeTargetRef: string; targetRevision: string }): void;
}) {
  const id = useId();
  const read = useProfilePage(actor, 'runtime', targets);
  const valid = read.data?.result.items.every(
    (item) => item.participantId === `urn:openpc:participant:${actor.participantId}`,
  );
  const eligible = valid
    ? read.data!.result.items.filter(
        (item) =>
          ['OFFLINE', 'DISCOVERED'].includes(item.state) &&
          item.desiredGenerationDigest === null &&
          item.activeGenerationDigest === null,
      )
    : [];
  const selected = eligible.find((item) => item.targetId === value);
  return (
    <div>
      <label className="block font-medium" htmlFor={id}>
        Runtime target
      </label>
      <select
        id={id}
        className={inputClass}
        required
        value={selected?.targetId ?? ''}
        disabled={disabled || read.changing || !eligible.length}
        onChange={(event) => {
          const target = eligible.find((item) => item.targetId === event.target.value);
          if (target && !disabled && !isSessionTransitionPending())
            onSelect({ runtimeTargetRef: target.targetId, targetRevision: target.revision });
        }}
      >
        <option value="">Select a runtime target</option>
        {eligible.map((item) => (
          <option key={item.targetId} value={item.targetId}>
            {shortTarget(item.targetId)} · {item.state === 'DISCOVERED' ? 'Discovered' : 'Offline'}
          </option>
        ))}
      </select>
      <p className="mt-1 text-sm text-[color:var(--muted)]" role="status">
        {read.failed || (read.data && !valid)
          ? 'Runtime targets could not be loaded. Refresh to try again.'
          : !read.data
            ? 'Loading runtime targets…'
            : eligible.length
              ? 'Only targets without an activated configuration can be bound.'
              : 'No eligible targets on this page. Discover a target under Runtime targets before binding a profile.'}
      </p>
      <div className="mt-2 flex gap-2">
        <button
          type="button"
          className={buttonClass}
          disabled={disabled || read.changing}
          onClick={read.refresh}
        >
          Refresh targets
        </button>
        {read.cursor ? (
          <button
            type="button"
            className={buttonClass}
            disabled={disabled || read.changing}
            onClick={() => read.setCursor(undefined)}
          >
            First page
          </button>
        ) : null}
        {read.data?.result.nextCursor ? (
          <button
            type="button"
            className={buttonClass}
            disabled={disabled || read.changing}
            onClick={() => read.setCursor(read.data!.result.nextCursor!)}
          >
            Next page of targets
          </button>
        ) : null}
      </div>
    </div>
  );
}

export function RuntimeProfileSummary({
  value,
  title,
  review = false,
}: {
  value: Record<string, unknown>;
  title: string;
  review?: boolean;
}) {
  const target =
    typeof value.runtimeTargetRef === 'string'
      ? value.runtimeTargetRef
      : typeof value.targetRef === 'string'
        ? value.targetRef
        : '';
  return (
    <section className="contract-record-summary" aria-label={title}>
      <h3>{title}</h3>
      <dl>
        <dt>Permission profile</dt>
        <dd>
          {typeof value.targetProfileId === 'string' ? value.targetProfileId : 'Not available'}
        </dd>
        <dt>Runtime target</dt>
        <dd>{target ? shortTarget(target) : 'Not available'}</dd>
        {review ? (
          <>
            <dt>Target revision</dt>
            <dd>{String(value.targetRevision ?? 'Not available')}</dd>
          </>
        ) : (
          <>
            <dt>Binding</dt>
            <dd>Recorded</dd>
          </>
        )}
      </dl>
      <p>
        {review
          ? 'An independent checker must approve this binding. It cannot be reassigned to another target.'
          : 'This binding does not activate the runtime or grant workload access.'}
      </p>
      <SecondaryPanel title="Binding references">
        <dl>
          <dt>Target</dt>
          <dd>{target}</dd>
          {typeof value.bindingRef === 'string' ? (
            <>
              <dt>Binding</dt>
              <dd>{value.bindingRef}</dd>
              <dt>Digest</dt>
              <dd>{String(value.bindingDigest)}</dd>
            </>
          ) : null}
        </dl>
      </SecondaryPanel>
    </section>
  );
}

export function RuntimeProfileDirectory({
  actor,
  disabled,
  onCreate,
  refreshToken,
}: {
  actor: PolicyWorkflowActorBinding;
  disabled: boolean;
  onCreate(): void;
  refreshToken?: string;
}) {
  const read = useProfilePage(actor, 'runtime-profiles', bindings, refreshToken);
  return (
    <section className="contract-library-panel" aria-label="Permission profile bindings">
      <div className="flex items-center justify-between gap-3">
        <h2 className="text-xl font-semibold">Permission profile bindings</h2>
        <button
          type="button"
          className={`${buttonClass} workflow-primary`}
          disabled={disabled || read.changing}
          onClick={onCreate}
        >
          Bind profile
        </button>
      </div>
      <p className="mt-2 text-sm text-[color:var(--muted)]">
        Each profile belongs to one runtime target. Workload permissions and activation are managed
        separately.
      </p>
      <p className="my-3" role="status">
        {read.failed
          ? 'Bindings could not be loaded. Refresh to try again.'
          : !read.data
            ? 'Loading profile bindings…'
            : read.data.result.items.length
              ? `${read.data.result.items.length} bindings on this page.`
              : read.data.result.authorizedEmpty && read.data.result.completeness === 'COMPLETE'
                ? 'No profile bindings have been recorded in this workspace.'
                : 'No bindings were returned on this page. Coverage is unconfirmed.'}
      </p>
      {read.data?.result.items.length ? (
        <div className="overflow-x-auto">
          <table className="w-full text-left" aria-label="Recorded permission profiles">
            <thead>
              <tr>
                <th className="py-3">Profile</th>
                <th>Runtime target</th>
                <th>Recorded</th>
              </tr>
            </thead>
            <tbody>
              {read.data.result.items.map((item) => (
                <tr className="border-t border-[color:var(--border)]" key={item.bindingRef}>
                  <td className="py-3 font-medium">{item.targetProfileId}</td>
                  <td>{shortTarget(item.targetRef)}</td>
                  <td>{readableProviderDate(item.createdAt)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}
      <div className="mt-3 flex gap-2">
        <button
          type="button"
          className={buttonClass}
          disabled={disabled || read.changing}
          onClick={read.refresh}
        >
          Refresh bindings
        </button>
        {read.cursor ? (
          <button
            type="button"
            className={buttonClass}
            disabled={disabled || read.changing}
            onClick={() => read.setCursor(undefined)}
          >
            First page
          </button>
        ) : null}
        {read.data?.result.nextCursor ? (
          <button
            type="button"
            className={buttonClass}
            disabled={disabled || read.changing}
            onClick={() => read.setCursor(read.data!.result.nextCursor!)}
          >
            Next page of bindings
          </button>
        ) : null}
      </div>
    </section>
  );
}
