import type { ReactNode } from 'react';
import type { TransactionKind } from '../lib/transaction-workflow';
import { approvalStateLabel, approvalTime } from '../lib/approval-catalogue';

const sourceLabels: Record<string, string> = {
  AUTHENTICATED_REGISTRY: 'Authenticated registry',
  SOURCE_REPOSITORY: 'Source repository',
  LOCAL_FIXTURE: 'Local artifact',
};
const choiceLabels: Record<string, string> = {
  READ: 'Read data',
  WRITE: 'Change state',
  NONE: 'None required by this record',
  SINGLE: 'One approver',
  MAKER_CHECKER: 'Independent maker and checker',
  WEBAUTHN: 'Security key verification',
};

const stateLabels: Record<string, string> = {
  PROPOSED: 'Prepared for review',
  APPROVAL_REQUESTED: 'Awaiting approval',
  APPROVED: 'Approved',
  CONSUMED: 'Approval used',
  CANCELLED: 'Cancelled',
  EXPIRED: 'Expired',
  ACCEPTED: 'Accepted for processing',
  ADMITTED: 'Accepted for processing',
  APPLIED: 'Applied',
  REJECTED_NO_EFFECT: 'Rejected without changes',
  CANCELLED_NO_EFFECT: 'Cancelled without changes',
  RUNNING: 'In progress',
  SUCCEEDED: 'Completed',
  FAILED: 'Failed',
  SUCCESS: 'Effect confirmed',
  UNKNOWN: 'Unconfirmed',
  WRITE_AMBIGUITY: 'Outcome uncertain',
  DENIED: 'Denied',
  BOUND: 'Bound',
  PREPARED: 'Prepared',
  ACTIVE: 'Active',
  RETIRED: 'Retired',
  QUARANTINED: 'Quarantined',
};
export function recordStateLabel(value: string) {
  return stateLabels[value] ?? approvalStateLabel(value);
}

export function ContractRecordSummary({
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
  if (!kind.startsWith('contract-')) return null;
  const text = (field: string, labels?: Record<string, string>) => {
    const raw = value[field];
    return typeof raw === 'string' && raw.length ? (labels?.[raw] ?? raw) : 'Not available';
  };
  const list = (field: string) => {
    const raw = value[field];
    return Array.isArray(raw) && raw.every((item) => typeof item === 'string')
      ? raw.join(', ') || 'None listed in this record'
      : 'Not available';
  };
  const entries: [string, ReactNode][] = [];
  if (kind === 'contract-asset') {
    entries.push(['Contract', text('displayName')], ['Contract identifier', text('logicalName')]);
  } else if (kind === 'contract-abi') {
    const provenance = value.provenance;
    const source =
      provenance && typeof provenance === 'object' && !Array.isArray(provenance)
        ? (provenance as Record<string, unknown>)
        : undefined;
    const abi = value.abi ?? value.canonicalAbi;
    entries.push(
      [
        'Source',
        typeof source?.source === 'string'
          ? (sourceLabels[source.source] ?? source.source)
          : 'Not available',
      ],
      ['Source location', typeof source?.locator === 'string' ? source.locator : 'Not available'],
      ['ABI entries', Array.isArray(abi) ? String(abi.length) : 'Not available'],
    );
  } else if (kind === 'contract-binding') {
    entries.push(
      ['Network', text('networkId')],
      ['Chain ID', text('chainId')],
      ['Contract address', text('contractAddress')],
      ['ABI version', text('abiVersion')],
    );
    if (typeof value.state === 'string')
      entries.push(['Binding state', recordStateLabel(value.state)]);
  } else if (kind === 'contract-method') {
    entries.push(
      ['Method', text('canonicalSignature')],
      ['Effect', text('effect', choiceLabels)],
      ['Required roles', list('requiredRoles')],
      ['Execution approval', text('approvalRequirement', choiceLabels)],
      ['Execution authentication', text('mfaRequirement', choiceLabels)],
      ['Allowed environments', list('environments')],
    );
    if (typeof value.state === 'string')
      entries.push(['Policy record state', recordStateLabel(value.state)]);
  }
  if (review && typeof value.reason === 'string')
    entries.push(['Reason for this change', value.reason]);
  if (!review) {
    if (typeof value.revision === 'string') entries.push(['Record revision', value.revision]);
    if (typeof value.createdAt === 'string')
      entries.push([
        'Recorded at',
        Number.isFinite(Date.parse(value.createdAt))
          ? approvalTime(value.createdAt)
          : 'Not available',
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
              [
                'Contract address',
                'Method',
                'Required roles',
                'Reason for this change',
                'Recorded at',
              ].includes(label)
                ? 'contract-record-wide'
                : undefined
            }
          >
            <dt>{label}</dt>
            <dd>{content}</dd>
          </div>
        ))}
      </dl>
    </section>
  );
}
