'use client';

import { useEffect, useRef, useState } from 'react';
import {
  evidenceOperationEndpoint,
  evidenceOperationQuery,
  evidenceOperationView,
  type EvidenceOperationView,
} from '../lib/evidence-operation-correlation';

export interface EvidenceOperationCorrelationProps {
  readonly evidenceId: string;
  readonly actorKey: string;
}

/** Mount only beside a selected VERIFIED_BUSINESS_TRANSITION. Keying the child
 * by both selectors also prevents an old result flashing on a context change. */
export function EvidenceOperationCorrelation(props: EvidenceOperationCorrelationProps) {
  if (!evidenceOperationQuery.safeParse(props).success) return null;
  return <BoundCorrelation key={`${props.actorKey}:${props.evidenceId}`} {...props} />;
}
function BoundCorrelation({ evidenceId, actorKey }: EvidenceOperationCorrelationProps) {
  const [result, setResult] = useState<EvidenceOperationView>();
  const [status, setStatus] = useState('');
  const [busy, setBusy] = useState(false);
  const generation = useRef(0),
    active = useRef<AbortController | undefined>(undefined);
  const output = useRef<HTMLHeadingElement>(null);
  useEffect(() => {
    const clear = () => {
      generation.current++;
      active.current?.abort();
      active.current = undefined;
      setResult(undefined);
      setStatus('');
      setBusy(false);
    };
    const hidden = () => {
      if (document.visibilityState !== 'visible') clear();
    };
    window.addEventListener('blur', clear);
    document.addEventListener('visibilitychange', hidden);
    return () => {
      clear();
      window.removeEventListener('blur', clear);
      document.removeEventListener('visibilitychange', hidden);
    };
  }, []);
  async function read() {
    if (active.current) return;
    const current = ++generation.current,
      controller = new AbortController();
    active.current = controller;
    setResult(undefined);
    setBusy(true);
    setStatus('Reading linked operation…');
    try {
      const response = await fetch(
        `${evidenceOperationEndpoint}?${new URLSearchParams({ evidenceId, actorKey })}`,
        {
          method: 'GET',
          cache: 'no-store',
          redirect: 'error',
          signal: AbortSignal.any([controller.signal, AbortSignal.timeout(16000)]),
        },
      );
      if (!response.ok) throw new Error('Unavailable');
      const parsed = evidenceOperationView.safeParse(await response.json());
      if (
        !parsed.success ||
        parsed.data.evidenceId !== evidenceId ||
        parsed.data.actorKey !== actorKey
      )
        throw new Error('Unavailable');
      if (generation.current !== current) return;
      setResult(parsed.data);
      setStatus('Linked operation read.');
    } catch {
      if (generation.current === current)
        setStatus(
          'Linked operation unavailable in the current context. No current status is established.',
        );
    } finally {
      if (generation.current === current) {
        active.current = undefined;
        setBusy(false);
      }
    }
  }
  useEffect(() => {
    if (result) output.current?.focus();
  }, [result]);
  return (
    <section
      aria-label="Evidence operation correlation"
      className="space-y-3 break-all rounded border border-[color:var(--border)] p-4"
    >
      <h3 className="font-semibold">Linked operation</h3>
      <p className="break-normal">
        Reading the linked operation requires current permission. The historical receipt grants no
        authority.
      </p>
      <button
        type="button"
        disabled={busy}
        onClick={() => void read()}
        className="rounded border border-[color:var(--border)] px-3 py-2 disabled:opacity-50"
      >
        Read linked operation
      </button>
      <p role="status" className="break-normal">
        {status}
      </p>
      {result ? (
        <section aria-label="Linked operation result" className="space-y-2">
          <h4 ref={output} tabIndex={-1} className="font-semibold">
            Current operation status
          </h4>
          <dl>
            <dt>Original receipt</dt>
            <dd>{result.receiptId}</dd>
            <dt>Evidence record</dt>
            <dd>{result.evidenceId}</dd>
            <dt>Receipt digest</dt>
            <dd>{result.recordDigest}</dd>
            <dt>Historical committed revision</dt>
            <dd>{result.historicalRevision}</dd>
            <dt>Receipt recorded</dt>
            <dd>{result.recordedAt}</dd>
            <dt>Operation</dt>
            <dd>{result.operation.operationId}</dd>
            <dt>Action</dt>
            <dd>{result.operation.actionIntentId}</dd>
            <dt>Resource</dt>
            <dd>{result.operation.resourceRef}</dd>
            <dt>Operation state / truth</dt>
            <dd>
              {result.operation.state} / {result.operation.truthState}
            </dd>
            <dt>Operation revision</dt>
            <dd>{result.operation.revision}</dd>
            <dt>Operation created</dt>
            <dd>{result.operation.createdAt}</dd>
            <dt>Operation updated</dt>
            <dd>{result.operation.updatedAt}</dd>
          </dl>
          <p className="break-normal">
            Historical receipt and current operation status are separate observations. Current
            object state and provider effects have not been checked. This view performs no mutation
            or export.
          </p>
        </section>
      ) : null}
    </section>
  );
}
