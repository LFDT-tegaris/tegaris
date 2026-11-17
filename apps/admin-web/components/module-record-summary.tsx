import type { ReactNode } from 'react';
import type { TransactionKind } from '../lib/transaction-workflow';
import { readableProviderDate } from './provider-directory';

const stateLabels: Record<string, string> = {
  REGISTERED: 'Registered',
  INSTALLED: 'Installed',
  ACTIVE: 'Active',
  DISABLED: 'Disabled',
};

export function ModuleRecordSummary({
  kind,
  value,
  title,
  review = false,
}: {
  kind: TransactionKind;
  value: Record<string, unknown>;
  title: string;
  review?: boolean;
}) {
  if (!kind.startsWith('module-')) return null;
  const text = (field: string) =>
    typeof value[field] === 'string' && value[field].length ? value[field] : 'Not available';
  const entries: [string, ReactNode][] = [];
  if (kind === 'module-registration' || !review) {
    entries.push(['Module', text('name')], ['Version', text('semanticVersion')]);
  } else {
    entries.push(
      ['Module reference', text('targetRef')],
      ['Expected revision', text('expectedRevision')],
    );
  }
  if (typeof value.supportProfile === 'string')
    entries.push(['Support profile', value.supportProfile]);
  if (review && typeof value.reason === 'string')
    entries.push(['Reason for this change', value.reason]);
  if (!review) {
    entries.push([
      'Module status',
      typeof value.state === 'string'
        ? (stateLabels[value.state] ?? 'Status not reported')
        : 'Status not reported',
    ]);
    if (typeof value.revision === 'string') entries.push(['Record revision', value.revision]);
    if (typeof value.updatedAt === 'string')
      entries.push([
        'Updated at',
        <time key="updated-at" dateTime={value.updatedAt}>
          {readableProviderDate(value.updatedAt)}
        </time>,
      ]);
  }
  return (
    <section className="contract-record-summary" aria-label={title}>
      <h3>{title}</h3>
      <dl>
        {entries.map(([label, content]) => (
          <div
            key={label}
            className={
              ['Module reference', 'Reason for this change'].includes(label)
                ? 'contract-record-wide'
                : undefined
            }
          >
            <dt>{label}</dt>
            <dd>{content}</dd>
          </div>
        ))}
      </dl>
      {typeof value.manifestDigest === 'string' ? (
        <details className="contract-request-references">
          <summary>Release fingerprint</summary>
          <p className="break-all">Manifest digest: {value.manifestDigest}</p>
        </details>
      ) : null}
      <p className="mt-3 text-sm">Runtime access is governed separately.</p>
    </section>
  );
}
