import { cleanup, render, screen } from '@testing-library/react';
import { afterEach, expect, it } from 'vitest';
import { ContractRecordSummary, recordStateLabel } from './contract-record-summary';

afterEach(cleanup);

it('shows the exact reviewed business change without making permission or completion claims', () => {
  render(
    <ContractRecordSummary
      kind="contract-asset"
      title="Review this change"
      review
      value={{
        displayName: 'Example payment registry',
        logicalName: 'example.payment-registry',
        reason: 'Enable the payment application for review.',
        resourceId: 'internal-only-reference',
        sourceDocument: 'raw-private-source',
      }}
    />,
  );
  expect(screen.getByText('Example payment registry')).toBeVisible();
  expect(screen.getByText('example.payment-registry')).toBeVisible();
  expect(screen.getByText('Enable the payment application for review.')).toBeVisible();
  expect(screen.queryByText('internal-only-reference')).toBeNull();
  expect(screen.queryByText('raw-private-source')).toBeNull();
  expect(screen.queryByText(/ready|completed|permitted/i)).toBeNull();
});

it('summarizes imported ABI provenance from the native candidate and result shapes', () => {
  const value = {
    provenance: { source: 'SOURCE_REPOSITORY', locator: 'Customer PaymentRegistry.sol' },
    canonicalAbi: [{ type: 'function' }, { type: 'event' }],
    revision: '2',
    createdAt: '2026-10-10T00:00:00Z',
  };
  render(<ContractRecordSummary kind="contract-abi" title="Recorded outcome" value={value} />);
  expect(screen.getByText('Source repository')).toBeVisible();
  expect(screen.getByText('10 Oct 2026, 00:00 UTC')).toBeVisible();
  expect(screen.getByText('Customer PaymentRegistry.sol')).toBeVisible();
  expect(screen.getByText('ABI entries').nextElementSibling).toHaveTextContent('2');
  expect(screen.getByText('Record revision').nextElementSibling).toHaveTextContent('2');
});

it('shows method execution requirements and missing values without inventing defaults', () => {
  render(
    <ContractRecordSummary
      kind="contract-method"
      title="Change under review"
      review
      value={{
        canonicalSignature: 'createPayment(bytes32)',
        effect: 'WRITE',
        requiredRoles: ['Debtor'],
        approvalRequirement: 'MAKER_CHECKER',
        mfaRequirement: 'WEBAUTHN',
        environments: ['TEST'],
      }}
    />,
  );
  expect(screen.getByText('createPayment(bytes32)')).toBeVisible();
  expect(screen.getByText('Independent maker and checker')).toBeVisible();
  expect(screen.getByText('Security key verification')).toBeVisible();
  expect(screen.getByText('Debtor')).toBeVisible();
  expect(screen.getByText('TEST')).toBeVisible();
});

it('does not equate used approval or accepted operation with a confirmed business effect', () => {
  expect(recordStateLabel('CONSUMED')).toBe('Approval used');
  expect(recordStateLabel('ACCEPTED')).toBe('Accepted for processing');
  expect(recordStateLabel('UNKNOWN')).toBe('Unconfirmed');
  expect(recordStateLabel('WRITE_AMBIGUITY')).toBe('Outcome uncertain');
  expect(recordStateLabel('UNRECOGNIZED_STATE')).toBe('UNRECOGNIZED_STATE');
});
