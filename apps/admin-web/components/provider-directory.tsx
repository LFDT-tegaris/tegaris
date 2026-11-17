'use client';
import { SecondaryPanel } from './secondary-panel';

interface ProviderDirectoryProps {
  items: Record<string, unknown>[];
  busy: boolean;
  onRead: (reference: string) => void;
}
const states: Record<string, string> = {
  REGISTERED: 'Registered',
  SHADOW: 'Observation recorded',
  QUALIFIED: 'Qualified',
  ACTIVE: 'Active',
  QUARANTINED: 'Quarantined',
  RETIRED: 'Retired',
};

export function providerStateLabel(value: string): string {
  return states[value] ?? 'Status not reported';
}

export function readableProviderDate(value: string): string {
  const date = new Date(value);
  if (!Number.isFinite(date.getTime())) return 'Date unavailable';
  return new Intl.DateTimeFormat('en-GB', {
    day: '2-digit',
    month: 'short',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    timeZone: 'UTC',
    timeZoneName: 'short',
  }).format(date);
}

export function ProviderDirectory({ items, busy, onRead }: ProviderDirectoryProps) {
  return (
    <section className="provider-directory" aria-label="Provider records">
      {items.map((item, index) => {
        const reference = typeof item.providerProfileId === 'string' ? item.providerProfileId : '';
        const chainId = typeof item.chainId === 'string' ? item.chainId : undefined;
        const state = typeof item.state === 'string' ? item.state : '';
        const canRead =
          /^urn:openpc:resource:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u.test(
            reference,
          );
        const updatedAt = typeof item.updatedAt === 'string' ? item.updatedAt : undefined;
        return (
          <article className="provider-card" key={reference || index} data-provider-ref={reference}>
            <header>
              <div>
                <p className="provider-eyebrow">RPC provider {index + 1}</p>
                <h3>{chainId ? `Chain ${chainId}` : 'Provider record'}</h3>
              </div>
              <span
                className="provider-state"
                data-tone={
                  ['QUARANTINED', 'RETIRED'].includes(state)
                    ? 'warning'
                    : ['QUALIFIED', 'ACTIVE'].includes(state)
                      ? 'success'
                      : 'neutral'
                }
              >
                {providerStateLabel(state)}
              </span>
            </header>
            <dl>
              <div>
                <dt>Qualification coverage</dt>
                <dd>
                  {item.admissionScope === 'BOUNDED_QA'
                    ? 'Bounded evaluation'
                    : item.admissionScope === 'FULL_CORPUS'
                      ? 'Full corpus'
                      : 'Not reported'}
                </dd>
              </div>
              <div>
                <dt>Historical reorg checks</dt>
                <dd>
                  {item.historicalReorgConformance === 'OBSERVED' ? 'Observed' : 'Not verified'}
                </dd>
              </div>
              {updatedAt ? (
                <div>
                  <dt>Last updated</dt>
                  <dd>
                    <time dateTime={updatedAt}>{readableProviderDate(updatedAt)}</time>
                  </dd>
                </div>
              ) : null}
            </dl>
            <footer>
              {canRead ? (
                <button
                  type="button"
                  className="provider-read"
                  disabled={busy}
                  onClick={() => onRead(reference)}
                  aria-label={`View provider ${index + 1}${chainId ? ` for chain ${chainId}` : ''}`}
                >
                  View provider
                </button>
              ) : null}
              <SecondaryPanel title="Technical details" className="provider-details">
                <pre tabIndex={0} aria-label={`Technical details for provider ${index + 1}`}>
                  {JSON.stringify(item, null, 2)}
                </pre>
              </SecondaryPanel>
            </footer>
          </article>
        );
      })}
    </section>
  );
}
