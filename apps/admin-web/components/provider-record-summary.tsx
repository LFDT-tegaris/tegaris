import type { ReactNode } from 'react';
import { providerStateLabel, readableProviderDate } from './provider-directory';

export function ProviderRecordSummary({
  value,
  title,
  review = false,
}: {
  value: Record<string, unknown>;
  title: string;
  review?: boolean;
}) {
  const entries: [string, ReactNode][] = [];
  if (typeof value.chainId === 'string') entries.push(['Chain ID', value.chainId]);
  if (typeof value.state === 'string')
    entries.push(['Provider status', providerStateLabel(value.state)]);
  if (review && typeof value.reason === 'string')
    entries.push(['Reason for this change', value.reason]);
  if (!review && typeof value.revision === 'string')
    entries.push(['Record revision', value.revision]);
  if (!review && typeof value.createdAt === 'string')
    entries.push([
      'Registered at',
      <time key="recorded-at" dateTime={value.createdAt}>
        {readableProviderDate(value.createdAt)}
      </time>,
    ]);
  if (!review && typeof value.updatedAt === 'string')
    entries.push([
      'Last updated',
      <time key="updated-at" dateTime={value.updatedAt}>
        {readableProviderDate(value.updatedAt)}
      </time>,
    ]);
  return (
    <section className="contract-record-summary" aria-label={title}>
      <h3>{title}</h3>
      <dl>
        {entries.map(([label, content]) => (
          <div key={label}>
            <dt>{label}</dt>
            <dd>{content}</dd>
          </div>
        ))}
      </dl>
      <p className="mt-3 text-sm">Qualification and governed routing are managed separately.</p>
    </section>
  );
}
