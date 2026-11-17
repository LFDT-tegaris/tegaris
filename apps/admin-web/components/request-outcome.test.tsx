import { cleanup, render, screen } from '@testing-library/react';
import { afterEach, expect, it } from 'vitest';
import { RequestOutcome } from './request-outcome';
import type { TransactionKind } from '../lib/transaction-workflow';

afterEach(cleanup);
const actor = {
  sessionId: '018f0000-0000-7000-8000-000000000111',
  principalId: '018f0000-0000-7000-8000-000000000112',
  participantId: '018f0000-0000-7000-8000-000000000101',
  privacyDomainId: '018f0000-0000-7000-8000-000000000201',
  contextEpoch: '2',
};
const ref = 'urn:openpc:resource:018f0000-0000-7000-8000-000000000401';
const result = {
  deletionJobId: ref,
  participantId: `urn:openpc:participant:${actor.participantId}`,
  selection: {
    participantId: `urn:openpc:participant:${actor.participantId}`,
    privacyDomainId: actor.privacyDomainId,
    dataClass: 'SEARCH_PROJECTION',
    batchIndex: 0,
    targets: [{}, {}],
  },
  state: 'SUCCEEDED',
  revision: '1',
  deletedCount: '1',
  deletedBytes: '632',
  retainedAliasCount: '0',
  externalAttemptState: 'NOT_STARTED',
  receiptDigest: `sha256:${'a'.repeat(64)}`,
  beforeDigest: `sha256:${'b'.repeat(64)}`,
  afterDigest: `sha256:${'c'.repeat(64)}`,
  completedAt: '2026-10-10T22:31:33.123456Z',
};
function show(
  value: Record<string, unknown> = result,
  kind: TransactionKind = 'evidence-deletion-search',
  resourceRef = ref,
) {
  render(<RequestOutcome value={value} kind={kind} actor={actor} resourceRef={resourceRef} />);
}

it('limits the physical completion claim to the original recorded local batch', () => {
  show();
  expect(screen.getByRole('heading', { name: 'Local data removed' })).toBeVisible();
  expect(screen.getByText('Search index · 1 local object · 632 bytes')).toBeVisible();
  expect(
    screen.getByText('Confirmed batch 1 of 2. Other batches have separate requests.'),
  ).toBeVisible();
  expect(
    screen.getByText('Original receipts and archived evidence retain their separate lifetimes.'),
  ).toBeVisible();
  expect(screen.getByText(result.receiptDigest)).not.toBeVisible();
});

const walletBinding = {
  walletBindingId: ref.slice(-36),
  subjectId: '018f0000-0000-7000-8000-000000000501',
  chainId: '92870',
  walletAddress: `0x${'a'.repeat(40)}`,
  participantId: actor.participantId,
  privacyDomainId: actor.privacyDomainId,
  state: 'ACTIVE',
  bindingEpoch: '1',
  revision: '1',
  operationId: '018f0000-0000-7000-8000-000000000601',
  permissionEffect: 'NONE_WITHOUT_EFFECTIVE_AUTHORITY',
};
function showWallet(
  value: Record<string, unknown> = walletBinding,
  operationRef = `urn:openpc:operation:${walletBinding.operationId}`,
) {
  render(
    <RequestOutcome
      kind="wallet-binding"
      value={value}
      actor={actor}
      resourceRef={ref}
      operationRef={operationRef}
    />,
  );
}
it.each(['ACTIVE', 'REVOKED'])(
  'shows the original %s wallet binding without granting access or requiring a queue operation',
  (state) => {
    showWallet({ ...walletBinding, state });
    expect(
      screen.getByRole('heading', {
        name: state === 'ACTIVE' ? 'Wallet bound' : 'Wallet binding revoked',
      }),
    ).toBeVisible();
    expect(screen.getByText(walletBinding.walletAddress)).toBeVisible();
    expect(screen.getByText(walletBinding.operationId)).toBeVisible();
    expect(screen.getByText('Bound identity')).toBeVisible();
    expect(screen.queryByText('Application runtime')).toBeNull();
    expect(
      screen.getByText('Access is controlled by the active grants and policies.'),
    ).toBeVisible();
    expect(screen.queryByText('Completed')).toBeNull();
  },
);
it.each([
  { ...walletBinding, participantId: '018f0000-0000-7000-8000-000000000102' },
  { ...walletBinding, privacyDomainId: '018f0000-0000-7000-8000-000000000202' },
  { ...walletBinding, walletBindingId: '018f0000-0000-7000-8000-000000000402' },
  { ...walletBinding, operationId: '018f0000-0000-7000-8000-000000000602' },
  { ...walletBinding, permissionEffect: 'ALLOW' },
  { ...walletBinding, state: 'PENDING' },
])('does not display an unconfirmed or differently bound wallet result', (value) => {
  showWallet(value);
  expect(screen.getByRole('alert')).toHaveTextContent('The wallet binding could not be confirmed.');
  expect(screen.queryByText(walletBinding.walletAddress)).toBeNull();
  expect(screen.queryByRole('region', { name: 'Recorded outcome' })).toBeNull();
});

it.each([
  ['evidence-deletion', 'AUDIT_EVIDENCE', 'Stored evidence'],
  ['evidence-deletion-normalized', 'NORMALIZED_JSON_PROJECTION', 'Normalized record'],
  ['evidence-deletion-raw', 'RAW_SOURCE_BODY', 'Protected source body'],
  ['evidence-deletion-runtime', 'RUNTIME_ARTIFACT', 'Runtime artifact'],
] as const)('names the actual local data class for %s', (kind, dataClass, label) => {
  show({ ...result, selection: { ...result.selection, dataClass } }, kind);
  expect(screen.getByText(`${label} · 1 local object · 632 bytes`)).toBeVisible();
});

it.each([
  { ...result, state: 'RUNNING' },
  { ...result, deletedCount: '0' },
  { ...result, retainedAliasCount: '1' },
  { ...result, receiptDigest: 'unverified' },
  { ...result, deletedBytes: '18446744073709551616' },
  { ...result, participantId: 'urn:openpc:participant:018f0000-0000-7000-8000-000000000102' },
  {
    ...result,
    selection: { ...result.selection, privacyDomainId: '018f0000-0000-7000-8000-000000000202' },
  },
  {
    ...result,
    selection: {
      ...result.selection,
      participantId: 'urn:openpc:participant:018f0000-0000-7000-8000-000000000102',
    },
  },
  { ...result, selection: { ...result.selection, batchIndex: 2 } },
  { ...result, selection: { ...result.selection, dataClass: 'UNKNOWN_SOURCE' } },
])('does not label incomplete, foreign or inconsistent metadata as physically removed', (value) => {
  show(value);
  expect(screen.queryByRole('heading', { name: 'Local data removed' })).toBeNull();
  expect(screen.getByText('Not reported')).toBeVisible();
});

it('does not apply deletion success to a different resource or an admission-only operation', () => {
  show(result, 'evidence-deletion-fact');
  expect(screen.queryByText('Local data removed')).toBeNull();
  cleanup();
  show(
    result,
    'evidence-deletion-search',
    'urn:openpc:resource:018f0000-0000-7000-8000-000000000402',
  );
  expect(screen.queryByText('Local data removed')).toBeNull();
});

it.each([
  ['UNKNOWN', 'Unconfirmed'],
  ['APPLIED', 'Applied'],
  ['REJECTED_NO_EFFECT', 'Rejected without changes'],
  ['CANCELLED_NO_EFFECT', 'Cancelled without changes'],
] as const)('keeps admission distinct from physical outcome %s', (physicalState, label) => {
  show({ admissionState: 'ADMITTED', physicalState }, 'evidence-deletion-fact');
  expect(screen.getByText('Accepted for processing')).toBeVisible();
  expect(screen.getByText(label)).toBeVisible();
  expect(screen.queryByText('Local data removed')).toBeNull();
});
