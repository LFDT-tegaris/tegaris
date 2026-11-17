'use client';

import { useCallback, useEffect, useRef, useState } from 'react';
import {
  policyVersionCatalogueSchema,
  policyVersionSelectionSchema,
  policyVersionTime,
  type PolicyVersionCatalogue,
  type PolicyVersionSelection,
} from '../lib/policy-version-catalogue';
import { isSessionTransitionPending, observeSessionTransitions } from './session-transition';
import {
  policyWorkflowPrivacyRevision,
  transactionWorkflowPrivacyEvent,
  type PolicyWorkflowActorBinding,
} from './policy-workflow-storage';

type Version = PolicyVersionSelection['version'];
const unavailable = 'Policy versions could not be confirmed. Refresh to try again.';
const button =
  'rounded border border-[color:var(--border)] px-3 py-2 font-medium disabled:opacity-50';

export function PolicyVersionPicker({
  actor,
  policySetId,
  enabled,
  selected,
  onVerified,
  onInvalidated,
}: {
  actor: PolicyWorkflowActorBinding;
  policySetId: string;
  enabled: boolean;
  selected: string;
  onVerified(selection: PolicyVersionSelection): void;
  onInvalidated(): void;
}) {
  const [page, setPage] = useState<PolicyVersionCatalogue>();
  const [version, setVersion] = useState<Version>();
  const [localPage, setLocalPage] = useState(0);
  const [status, setStatus] = useState(''),
    [busy, setBusy] = useState(false);
  const generation = useRef(0),
    selectionGeneration = useRef(0);
  const pending = useRef<AbortController | undefined>(undefined),
    detailPending = useRef<AbortController | undefined>(undefined);
  const callbacks = useRef({ onVerified, onInvalidated });
  callbacks.current = { onVerified, onInvalidated };
  const confirmed = useRef<Version | undefined>(undefined);
  const changing = useRef(false),
    privacyRevision = useRef(policyWorkflowPrivacyRevision());
  const matches = useCallback(
    (value: PolicyWorkflowActorBinding) =>
      (
        ['sessionId', 'principalId', 'participantId', 'privacyDomainId', 'contextEpoch'] as const
      ).every((field) => value[field] === actor[field]),
    [actor],
  );
  const invalidate = useCallback(() => {
    selectionGeneration.current++;
    detailPending.current?.abort();
    confirmed.current = undefined;
    setVersion(undefined);
    callbacks.current.onInvalidated();
  }, []);
  const clear = useCallback(() => {
    generation.current++;
    pending.current?.abort();
    setPage(undefined);
    setLocalPage(0);
    setBusy(false);
    invalidate();
  }, [invalidate]);
  const verify = useCallback(
    async (ref: string, listed?: Version) => {
      invalidate();
      if (
        !enabled ||
        !ref ||
        changing.current ||
        isSessionTransitionPending() ||
        privacyRevision.current !== policyWorkflowPrivacyRevision()
      )
        return;
      const current = generation.current,
        selection = selectionGeneration.current;
      const controller = new AbortController();
      detailPending.current = controller;
      setBusy(true);
      setStatus('Checking the selected version…');
      try {
        const response = await fetch(
          `/api/v1/ui/policy-versions?${new URLSearchParams({ policySetId, policyVersionId: ref })}`,
          {
            cache: 'no-store',
            credentials: 'same-origin',
            signal: controller.signal,
          },
        );
        const parsed = policyVersionSelectionSchema.safeParse(
          await response.json().catch(() => undefined),
        );
        if (
          controller.signal.aborted ||
          current !== generation.current ||
          selection !== selectionGeneration.current
        )
          return;
        if (
          response.status !== 200 ||
          !parsed.success ||
          !matches(parsed.data.actor) ||
          parsed.data.version.policyVersionId !== ref ||
          parsed.data.version.policySetId !== policySetId ||
          (listed &&
            (listed.normalizedPolicyDigest !== parsed.data.version.normalizedPolicyDigest ||
              listed.dependencyClosureDigest !== parsed.data.version.dependencyClosureDigest ||
              listed.semanticVersion !== parsed.data.version.semanticVersion))
        )
          throw new Error(unavailable);
        confirmed.current = parsed.data.version;
        setVersion(parsed.data.version);
        setStatus('Version checked. Ready to prepare a simulation.');
        callbacks.current.onVerified(parsed.data);
      } catch {
        if (
          current === generation.current &&
          selection === selectionGeneration.current &&
          !controller.signal.aborted
        )
          setStatus(unavailable);
      } finally {
        if (current === generation.current && selection === selectionGeneration.current)
          setBusy(false);
      }
    },
    [enabled, policySetId, matches, invalidate],
  );
  const load = useCallback(
    async (cursor?: string) => {
      clear();
      if (!enabled || !policySetId || changing.current || isSessionTransitionPending()) return;
      privacyRevision.current = policyWorkflowPrivacyRevision();
      const current = generation.current,
        controller = new AbortController();
      pending.current = controller;
      setBusy(true);
      setStatus('Loading policy versions…');
      try {
        const response = await fetch(
          `/api/v1/ui/policy-versions?${new URLSearchParams({ policySetId, ...(cursor ? { cursor } : {}) })}`,
          {
            cache: 'no-store',
            credentials: 'same-origin',
            signal: controller.signal,
          },
        );
        const parsed = policyVersionCatalogueSchema.safeParse(
          await response.json().catch(() => undefined),
        );
        if (current !== generation.current || controller.signal.aborted) return;
        if (
          response.status !== 200 ||
          !parsed.success ||
          !matches(parsed.data.actor) ||
          parsed.data.policySetId !== policySetId
        )
          throw new Error(unavailable);
        setPage(parsed.data);
        setStatus('');
      } catch {
        if (current === generation.current && !controller.signal.aborted) setStatus(unavailable);
      } finally {
        if (current === generation.current) setBusy(false);
      }
    },
    [enabled, policySetId, clear, matches],
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
    window.addEventListener(transactionWorkflowPrivacyEvent, clear);
    document.addEventListener('visibilitychange', hidden);
    return () => {
      generation.current++;
      pending.current?.abort();
      selectionGeneration.current++;
      detailPending.current?.abort();
      stop();
      window.removeEventListener('blur', clear);
      window.removeEventListener(transactionWorkflowPrivacyEvent, clear);
      document.removeEventListener('visibilitychange', hidden);
    };
  }, [load, clear]);
  useEffect(() => {
    if (
      page &&
      selected &&
      confirmed.current?.policyVersionId !== `urn:openpc:policy-version:${selected}`
    )
      void verify(`urn:openpc:policy-version:${selected}`);
  }, [selected, page, verify]);
  const visible =
    enabled && !changing.current && page && matches(page.actor) && page.policySetId === policySetId
      ? page
      : undefined;
  return (
    <section
      className="mt-5 rounded-lg border border-[color:var(--border)] bg-[color:var(--panel)] p-5"
      aria-label="Policy version selection"
      aria-busy={busy}
    >
      <div className="flex items-start justify-between gap-4">
        <div>
          <h3 className="text-lg font-semibold">Choose a policy version</h3>
          <p className="mt-1 text-sm text-[color:var(--muted)]">
            Review a saved version before testing its rules.
          </p>
        </div>
        <button
          className={button}
          type="button"
          disabled={busy || !enabled}
          onClick={() => void load()}
        >
          Refresh versions
        </button>
      </div>
      {!enabled && (
        <p className="mt-4 text-sm text-[color:var(--muted)]">
          Select a policy set to view its versions.
        </p>
      )}
      <p className="mt-3 text-sm" role="status">
        {status}
      </p>
      {visible && (
        <>
          <p className="mb-3 text-sm text-[color:var(--muted)]">
            {visible.total === null
              ? 'Total unavailable'
              : `${visible.total} accessible ${visible.total === '1' ? 'version' : 'versions'}`}
            {visible.completeness === 'UNKNOWN' ? ' · Coverage unconfirmed' : ''}
          </p>
          {visible.authorizedEmpty && (
            <p className="rounded border border-[color:var(--border)] p-4 text-sm">
              No versions are available in this policy set for your current access.
            </p>
          )}
          <div className="grid gap-2">
            {visible.items.slice(localPage * 6, (localPage + 1) * 6).map((item) => (
              <button
                key={item.policyVersionId}
                data-policy-version-ref={item.policyVersionId}
                type="button"
                className={`${button} flex items-center justify-between gap-4 text-left`}
                disabled={busy}
                aria-label={`Review version ${item.semanticVersion}, created ${policyVersionTime(item.createdAt)}`}
                aria-pressed={version?.policyVersionId === item.policyVersionId}
                onClick={() => void verify(item.policyVersionId, item)}
              >
                <span>
                  <span className="block font-semibold">Version {item.semanticVersion}</span>
                  <span className="mt-1 block text-xs font-normal text-[color:var(--muted)]">
                    Created {policyVersionTime(item.createdAt)}
                  </span>
                </span>
                <span className="rounded bg-[color:var(--canvas)] px-2 py-1 text-xs">
                  {version?.policyVersionId === item.policyVersionId
                    ? 'Selected'
                    : 'Review version'}
                </span>
              </button>
            ))}
          </div>
          <nav className="mt-3 flex items-center gap-3" aria-label="Policy version pages">
            <button
              className={button}
              type="button"
              disabled={busy || localPage === 0}
              onClick={() => setLocalPage((page) => page - 1)}
            >
              Previous versions
            </button>
            <span className="text-xs text-[color:var(--muted)]">
              {visible.items.length
                ? `${localPage * 6 + 1}–${Math.min((localPage + 1) * 6, visible.items.length)} of ${visible.items.length} loaded`
                : '0 loaded'}
            </span>
            <button
              className={button}
              type="button"
              disabled={
                busy || ((localPage + 1) * 6 >= visible.items.length && !visible.nextCursor)
              }
              onClick={() => {
                if ((localPage + 1) * 6 < visible.items.length) setLocalPage((page) => page + 1);
                else if (visible.nextCursor) void load(visible.nextCursor);
              }}
            >
              Next versions
            </button>
          </nav>
        </>
      )}
      {version && visible && version.policySetId === policySetId && (
        <div className="mt-4 rounded border border-[color:var(--border)] bg-[color:var(--canvas)] p-4">
          <h4 className="font-semibold">Version {version.semanticVersion} selected</h4>
          <p className="mt-1 text-sm text-[color:var(--muted)]">
            Record state: {version.state.toLowerCase()}. Check release and activation status in
            Releases before relying on it for live access.
          </p>
          <details className="mt-3 text-xs">
            <summary className="cursor-pointer font-medium">Version references</summary>
            <dl className="mt-2 grid gap-2 break-all">
              <dt>Version ID</dt>
              <dd className="font-mono">{version.policyVersionId}</dd>
              <dt>Policy digest</dt>
              <dd className="font-mono">{version.normalizedPolicyDigest}</dd>
              <dt>Dependency digest</dt>
              <dd className="font-mono">{version.dependencyClosureDigest}</dd>
            </dl>
          </details>
        </div>
      )}
    </section>
  );
}
