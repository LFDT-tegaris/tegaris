'use client';

import { CopyReference } from './copy-reference';
import { SecondaryPanel } from './secondary-panel';

const stateLabels: Record<string, string> = {
  OFFLINE: 'Offline',
  DISCOVERED: 'Discovered',
  STAGING: 'Staging',
  PREPARED: 'Prepared',
  XDS_PENDING: 'Delivery pending',
  XDS_ACKED_NOT_ACTIVE: 'Delivery acknowledged',
  ACTIVATING: 'Activating',
  ACTIVE_MATCHED: 'Configuration matched',
  ACTIVE_MISMATCH: 'Configuration mismatch',
  NACKED: 'Delivery rejected',
  FAILED: 'Failed',
  ROLLING_BACK: 'Rolling back',
  ROLLED_BACK: 'Rolled back',
  QUARANTINED: 'Quarantined',
  INCOMPATIBLE: 'Incompatible',
};
const resourceReference =
  /^urn:openpc:resource:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;

function observationLabel(value: string) {
  const date = new Date(value);
  return Number.isFinite(date.getTime())
    ? new Intl.DateTimeFormat('en-GB', {
        day: '2-digit',
        month: 'short',
        year: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
        timeZone: 'UTC',
        timeZoneName: 'short',
      }).format(date)
    : undefined;
}

export function RuntimeTargetDirectory({
  items,
  busy,
  onRead,
}: {
  items: readonly Record<string, unknown>[];
  busy: boolean;
  onRead: (reference: string) => void;
}) {
  return (
    <ul className="catalogue-record-list" aria-label="Runtime targets in the current workspace">
      {items.map((item, index) => {
        const reference = typeof item.targetId === 'string' ? item.targetId : '';
        const state = typeof item.state === 'string' ? item.state : '';
        const observedAt = typeof item.observedAt === 'string' ? item.observedAt : undefined;
        const observedLabel = observedAt ? observationLabel(observedAt) : undefined;
        const stateLabel = Object.hasOwn(stateLabels, state)
          ? stateLabels[state]
          : 'Status not reported';
        const canRead = resourceReference.test(reference);
        return (
          <li className="catalogue-record-card" key={reference || index}>
            <header className="flex flex-wrap items-start justify-between gap-3">
              <h3 className="catalogue-record-title">Runtime target {index + 1}</h3>
              <span
                className="workflow-state-badge"
                data-state={state}
                aria-label={`Reported state: ${stateLabel}`}
              >
                {stateLabel}
              </span>
            </header>
            <dl className="registry-record-details">
              <div>
                <dt>Desired configuration</dt>
                <dd>
                  {typeof item.desiredGenerationDigest === 'string' ? 'Selected' : 'Not reported'}
                </dd>
              </div>
              <div>
                <dt>Active configuration</dt>
                <dd>
                  {typeof item.activeGenerationDigest === 'string' ? 'Recorded' : 'Not confirmed'}
                </dd>
              </div>
              {observedAt ? (
                <div>
                  <dt>Last observed</dt>
                  <dd>
                    {observedLabel ? (
                      <time dateTime={observedAt}>{observedLabel}</time>
                    ) : (
                      'Date unavailable'
                    )}
                  </dd>
                </div>
              ) : null}
            </dl>
            <div className="catalogue-record-actions">
              <button
                type="button"
                className="catalogue-button"
                disabled={busy || !canRead}
                aria-label={`View runtime target ${index + 1}`}
                onClick={() => onRead(reference)}
              >
                View target
              </button>
              <SecondaryPanel
                title={`Runtime target ${index + 1} details`}
                triggerLabel="Technical details"
              >
                {canRead ? (
                  <CopyReference label="runtime target reference" value={reference} />
                ) : null}
                <pre
                  tabIndex={0}
                  aria-label={`Technical details for runtime target ${index + 1}`}
                  className="max-h-96 overflow-auto whitespace-pre-wrap break-all rounded border p-3 text-sm"
                >
                  {JSON.stringify(item, null, 2)}
                </pre>
              </SecondaryPanel>
            </div>
          </li>
        );
      })}
    </ul>
  );
}
