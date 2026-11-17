'use client';

import { useEffect, useId, useRef, useState } from 'react';
import { policyDocumentMaximumBytes, reviewPolicyDocument } from '../lib/policy-document-review';
import { inspectionActorKey } from '../lib/contract-method-inspection';
import { changeDisclosureDraft, readDisclosureDraft } from '../lib/policy-disclosure-draft';
import { PolicyDisclosureEditor } from './policy-disclosure-editor';
import { isSessionTransitionPending, observeSessionTransitions } from './session-transition';
import {
  policyWorkflowPrivacyRevision,
  transactionWorkflowPrivacyEvent,
  type PolicyWorkflowActorBinding,
} from './policy-workflow-storage';

export function PolicyDocumentInput({
  actor,
  value,
  originalValue,
  onChange,
}: Readonly<{
  actor?: PolicyWorkflowActorBinding;
  value: string;
  originalValue?: string;
  onChange(value: string, originalValue?: string): void;
}>) {
  const id = useId(),
    actorKey = actor ? inspectionActorKey(actor) : '';
  const currentKey = useRef(actorKey);
  currentKey.current = actorKey;
  const callback = useRef(onChange);
  callback.current = onChange;
  const generation = useRef(0),
    reader = useRef<FileReader | undefined>(undefined),
    input = useRef<HTMLInputElement | null>(null),
    verification = useRef(0),
    sessionRead = useRef<AbortController | undefined>(undefined),
    ready = useRef(!!actor && !isSessionTransitionPending());
  const [busy, setBusy] = useState(false),
    [paused, setPaused] = useState(isSessionTransitionPending()),
    [error, setError] = useState('');
  const [importedFile, setImportedFile] = useState<{
    name: string;
    source: string;
    actorKey: string;
    privacy: number;
  }>();
  const valueScope = useRef({
    value,
    original: originalValue ?? value,
    actorKey,
    privacy: policyWorkflowPrivacyRevision(),
    valid: true,
  });
  if (
    valueScope.current.value !== value ||
    (originalValue !== undefined && valueScope.current.original !== originalValue) ||
    (actorKey &&
      actorKey !== valueScope.current.actorKey &&
      !value.trim() &&
      !valueScope.current.original.trim() &&
      valueScope.current.valid &&
      valueScope.current.privacy === policyWorkflowPrivacyRevision())
  )
    valueScope.current = {
      value,
      original: originalValue ?? value,
      actorKey,
      privacy: policyWorkflowPrivacyRevision(),
      valid: true,
    };
  const projectionCurrent =
    !!actor &&
    ready.current &&
    valueScope.current.valid &&
    valueScope.current.privacy === policyWorkflowPrivacyRevision() &&
    actorKey === valueScope.current.actorKey &&
    !paused &&
    !isSessionTransitionPending();
  const reviewed = projectionCurrent ? reviewPolicyDocument(value, actor!) : undefined;
  const disclosure = projectionCurrent ? readDisclosureDraft(value, actor!) : undefined;
  const originalDisclosure = projectionCurrent
    ? readDisclosureDraft(valueScope.current.original, actor!)
    : undefined;
  useEffect(() => {
    const cancel = () => {
      generation.current++;
      reader.current?.abort();
      reader.current = undefined;
      if (input.current) input.current.value = '';
      setImportedFile(undefined);
      setBusy(false);
      setError('');
    };
    cancel();
    ready.current = !!actorKey && !isSessionTransitionPending();
    setPaused(!ready.current);
    const conceal = () => {
      ready.current = false;
      setPaused(true);
      verification.current++;
      sessionRead.current?.abort();
      sessionRead.current = undefined;
      cancel();
    };
    const revalidate = async (pending: boolean) => {
      conceal();
      if (pending || !actorKey) return;
      const operation = verification.current,
        privacy = policyWorkflowPrivacyRevision(),
        controller = new AbortController();
      sessionRead.current = controller;
      try {
        const response = await fetch('/api/v1/ui/local-session', {
          cache: 'no-store',
          credentials: 'same-origin',
          signal: controller.signal,
        });
        const value: unknown = await response.json();
        if (
          controller.signal.aborted ||
          operation !== verification.current ||
          actorKey !== currentKey.current ||
          privacy !== policyWorkflowPrivacyRevision() ||
          isSessionTransitionPending() ||
          response.status !== 200 ||
          !value ||
          typeof value !== 'object' ||
          Array.isArray(value)
        )
          return;
        const session = value as Record<string, unknown>;
        const fields = [
          'sessionId',
          'principalId',
          'participantId',
          'privacyDomainId',
          'contextEpoch',
        ] as const;
        if (
          session.authenticated !== true ||
          session.contextMode !== 'PARTICIPANT' ||
          fields.some((field) => typeof session[field] !== 'string' || !session[field]) ||
          fields.map((field) => session[field]).join(':') !== actorKey
        )
          return;
        ready.current = true;
        setPaused(false);
      } catch {
        // Notifications and failed reads never confirm the current account.
      } finally {
        if (sessionRead.current === controller) sessionRead.current = undefined;
      }
    };
    const privacyClear = () => {
      valueScope.current.valid = false;
      void revalidate(isSessionTransitionPending());
    };
    const hidden = () => {
      if (document.visibilityState !== 'visible') conceal();
    };
    const stop = observeSessionTransitions(conceal, (pending) => void revalidate(pending));
    window.addEventListener('blur', conceal);
    window.addEventListener(transactionWorkflowPrivacyEvent, privacyClear);
    document.addEventListener('visibilitychange', hidden);
    return () => {
      generation.current++;
      reader.current?.abort();
      verification.current++;
      sessionRead.current?.abort();
      stop();
      window.removeEventListener('blur', conceal);
      window.removeEventListener(transactionWorkflowPrivacyEvent, privacyClear);
      document.removeEventListener('visibilitychange', hidden);
    };
  }, [actorKey]);
  async function load(file: File) {
    if (!actorKey || !ready.current || isSessionTransitionPending()) {
      if (input.current) input.current.value = '';
      return;
    }
    reader.current?.abort();
    const operation = ++generation.current,
      key = actorKey,
      privacy = policyWorkflowPrivacyRevision();
    const current = () =>
      operation === generation.current &&
      key === currentKey.current &&
      privacy === policyWorkflowPrivacyRevision() &&
      !!key &&
      ready.current &&
      !isSessionTransitionPending();
    setError('');
    setBusy(true);
    try {
      if (!current() || !/\.json$/iu.test(file.name)) throw Error('Choose a JSON policy file.');
      if (file.size > policyDocumentMaximumBytes)
        throw Error('The policy file must be no larger than 1 MiB.');
      const bytes = await new Promise<ArrayBuffer>((resolve, reject) => {
        const next = new FileReader();
        reader.current = next;
        next.onload = () => resolve(next.result as ArrayBuffer);
        next.onerror = () => reject(Error('The policy file could not be read.'));
        next.onabort = () => reject(Error('File read cancelled.'));
        next.readAsArrayBuffer(file);
      });
      if (!current()) return;
      let text: string;
      try {
        text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
      } catch {
        throw Error('Use a UTF-8 JSON policy file.');
      }
      const result = reviewPolicyDocument(text, actor!);
      if ('error' in result) throw Error(result.error);
      if (current()) {
        valueScope.current = { value: text, original: text, actorKey: key, privacy, valid: true };
        setImportedFile({ name: file.name, source: text, actorKey: key, privacy });
        callback.current(text, text);
      }
    } catch (failure) {
      if (current())
        setError(failure instanceof Error ? failure.message : 'The policy file could not be read.');
    } finally {
      if (current()) {
        setBusy(false);
        reader.current = undefined;
        if (input.current) input.current.value = '';
      }
    }
  }
  return (
    <section
      className="min-w-0 rounded-lg border border-[color:var(--border)] p-5 lg:col-span-2"
      aria-label="Policy document"
      aria-busy={busy}
    >
      <h3 className="text-lg font-semibold">Review a policy file</h3>
      <p className="mt-1 text-sm text-[color:var(--muted)]">
        Import the rules for this workspace. Creating a version leaves active permissions unchanged.
      </p>
      <label className="mt-4 grid gap-2 font-medium" htmlFor={id}>
        Policy file
        <input
          ref={input}
          id={id}
          type="file"
          accept=".json,application/json"
          disabled={!actor || paused || busy || isSessionTransitionPending()}
          onChange={(event) => {
            const file = event.currentTarget.files?.[0];
            if (file) void load(file);
          }}
          className="policy-file-input block max-w-full rounded border border-[color:var(--border)] bg-[color:var(--canvas)] p-3 text-sm file:mr-3 file:rounded file:border-0 file:bg-[color:var(--accent)] file:px-3 file:py-2 file:font-medium file:text-[color:var(--surface)]"
          aria-describedby={`${id}-help`}
        />
      </label>
      <p className="policy-file-name">
        {projectionCurrent &&
        importedFile?.actorKey === actorKey &&
        importedFile.privacy === policyWorkflowPrivacyRevision() &&
        importedFile.source === value ? (
          <>
            Imported file: <bdi>{importedFile.name}</bdi>
          </>
        ) : (
          'No file imported.'
        )}
      </p>
      <p id={`${id}-help`} className="mt-2 text-sm text-[color:var(--muted)]">
        UTF-8 JSON, up to 1 MiB. Workspace references must match your current participant and
        privacy domain.
      </p>
      {error && (
        <p className="mt-3 text-sm text-[color:var(--danger)]" role="alert">
          {error} The existing draft has been kept.
        </p>
      )}
      <p className="mt-3 text-sm" role="status">
        {busy
          ? 'Reading policy file…'
          : !actor || paused
            ? 'Load the current workspace before importing a file.'
            : projectionCurrent && !value.trim()
              ? 'Choose a policy file to begin.'
              : reviewed && 'error' in reviewed
                ? reviewed.error
                : reviewed
                  ? 'Draft loaded for review. Its dependencies and rules still require validation when you create the version.'
                  : 'Reload the current workspace to review this draft.'}
      </p>
      {reviewed && !('error' in reviewed) && !busy && (
        <section className="mt-4" aria-label="Policy draft review">
          <dl className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
            {reviewed.counts.map(({ label, count }) => (
              <div key={label} className="rounded bg-[color:var(--canvas)] p-3">
                <dt className="text-sm text-[color:var(--muted)]">{label}</dt>
                <dd className="mt-1 text-xl font-semibold">{count}</dd>
              </div>
            ))}
          </dl>
          {reviewed.rpcRuleCount > 0 && (
            <>
              <h4 className="mt-4 font-semibold">RPC rules</h4>
              <ul className="mt-2 grid gap-2">
                {reviewed.rpcRules.map((rule, index) => (
                  <li
                    key={index}
                    className="flex items-center justify-between gap-4 rounded border border-[color:var(--border)] px-3 py-2"
                  >
                    <span className="break-all text-sm">{rule.method}</span>
                    <span className="text-sm font-medium">
                      {rule.effect === 'ALLOW' ? 'Allow' : 'Deny'}
                    </span>
                  </li>
                ))}
              </ul>
              {reviewed.rpcRuleCount > reviewed.rpcRules.length && (
                <p className="mt-2 text-sm text-[color:var(--muted)]">
                  Showing {reviewed.rpcRules.length} of {reviewed.rpcRuleCount} rules. Review the
                  complete document below.
                </p>
              )}
            </>
          )}
        </section>
      )}
      {disclosure && originalDisclosure && projectionCurrent && !busy && (
        <PolicyDisclosureEditor
          rules={disclosure.rules}
          original={originalDisclosure.rules}
          onChange={(policyId, change) => {
            if (
              !ready.current ||
              !valueScope.current.valid ||
              valueScope.current.actorKey !== currentKey.current ||
              valueScope.current.privacy !== policyWorkflowPrivacyRevision() ||
              isSessionTransitionPending()
            )
              return;
            const next = changeDisclosureDraft(
              valueScope.current.value,
              valueScope.current.original,
              actor!,
              policyId,
              change,
            );
            if ('error' in next) {
              setError(next.error);
              return;
            }
            generation.current++;
            reader.current?.abort();
            setError('');
            valueScope.current = { ...valueScope.current, value: next.value };
            callback.current(next.value, valueScope.current.original);
          }}
        />
      )}
      {reviewed && !('error' in reviewed) && !disclosure && !busy && (
        <p className="mt-4 text-sm text-[color:var(--muted)]">
          These disclosure rules need advanced editing. The complete document is preserved below and
          will be checked by native validation.
        </p>
      )}
      <details className="mt-4">
        <summary className="cursor-pointer text-sm font-medium">Edit policy JSON</summary>
        <div className="mt-3 grid gap-2 text-sm font-medium">
          <label htmlFor={`${id}-json`}>Typed policy document (JSON)</label>
          <textarea
            id={`${id}-json`}
            value={projectionCurrent ? value : ''}
            disabled={!actor || paused || busy}
            maxLength={policyDocumentMaximumBytes}
            rows={10}
            onChange={(event) => {
              if (!ready.current || isSessionTransitionPending()) return;
              generation.current++;
              reader.current?.abort();
              setBusy(false);
              setError('');
              valueScope.current = {
                value: event.currentTarget.value,
                original: event.currentTarget.value,
                actorKey,
                privacy: policyWorkflowPrivacyRevision(),
                valid: true,
              };
              callback.current(event.currentTarget.value, event.currentTarget.value);
            }}
            className="min-w-0 rounded border border-[color:var(--border)] bg-[color:var(--canvas)] p-3 font-mono text-xs"
          />
        </div>
      </details>
    </section>
  );
}
