'use client';

import {
  invokeAction,
  performWebAuthnStepUp,
  type AuthorizedAction,
  type UiSessionBootstrap,
} from '@openpc/ui-shell';
import { useState } from 'react';

export function ActionPanel({
  actions,
  session,
  onCompleted,
}: Readonly<{
  actions: readonly AuthorizedAction[];
  session?: UiSessionBootstrap;
  onCompleted?: () => Promise<unknown>;
}>) {
  const [result, setResult] = useState<string>();

  async function submit(action: AuthorizedAction) {
    if (!session) return;
    setResult(`Submitting ${action.operationId}.`);
    try {
      if (action.stepUp === 'FRESH_WEBAUTHN_MAX_5M') {
        setResult(`Confirm ${action.operationId} with your security key.`);
        await performWebAuthnStepUp(action);
      }
      const domain = action.path.split('/')[5];
      if (!domain) throw new Error('The action path does not identify a process domain.');
      await invokeAction(domain, action, {
        csrfToken: session.csrfToken,
        idempotencyKey: session.idempotencyKey,
        etag: session.etag,
      });
      await onCompleted?.();
      setResult(`${action.operationId} completed.`);
    } catch {
      setResult(`${action.operationId} could not be completed safely.`);
    }
  }

  if (actions.length === 0) {
    return (
      <section
        aria-label="Available actions"
        className="rounded border border-[color:var(--border)] p-4"
      >
        <h2 className="text-xl font-semibold">Available actions</h2>
        <p className="mt-2 text-[color:var(--muted)]">
          No action is currently authorized for this process.
        </p>
      </section>
    );
  }
  return (
    <section
      aria-label="Available actions"
      className="rounded border border-[color:var(--border)] bg-[color:var(--surface)] p-4"
    >
      <h2 className="text-xl font-semibold">Available actions</h2>
      <p className="mt-2 text-[color:var(--muted)]">
        Only server-declared action contracts are listed. A registered closed schema form is
        required before the action can be submitted.
      </p>
      <ul className="mt-4 space-y-3">
        {actions.map((action) => (
          <li
            className="rounded border border-[color:var(--border)] p-3"
            key={action.actionIntentId}
          >
            <strong className="break-all">{action.operationId}</strong>
            <dl className="mt-2 grid gap-2 text-sm sm:grid-cols-2">
              <div>
                <dt className="font-medium">Intent</dt>
                <dd className="break-all text-[color:var(--muted)]">{action.actionIntentId}</dd>
              </div>
              <div>
                <dt className="font-medium">Risk</dt>
                <dd className="text-[color:var(--muted)]">{action.riskClass}</dd>
              </div>
              <div>
                <dt className="font-medium">Step-up</dt>
                <dd className="text-[color:var(--muted)]">{action.stepUp}</dd>
              </div>
              <div>
                <dt className="font-medium">Replay protection</dt>
                <dd className="text-[color:var(--muted)]">{action.idempotency}</dd>
              </div>
            </dl>
            <button
              className="mt-4 max-w-full break-all rounded bg-[color:var(--accent)] px-3 py-2 font-medium text-[color:var(--surface)] disabled:opacity-60"
              disabled={!session}
              onClick={() => void submit(action)}
              type="button"
            >
              {session ? `Run ${action.operationId}` : 'Action unavailable'}
            </button>
          </li>
        ))}
      </ul>
      <p aria-live="polite" className="mt-3 text-sm" role="status">
        {result}
      </p>
    </section>
  );
}
