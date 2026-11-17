import { cleanup, render, screen } from '@testing-library/react';
import { afterEach, expect, it } from 'vitest';
import { ProviderRecordSummary } from './provider-record-summary';

afterEach(cleanup);

it('shows the exact proposed chain and reason without inventing qualification or exposing references', () => {
  render(
    <ProviderRecordSummary
      title="Review this change"
      review
      value={{
        chainId: '92870',
        reason: 'Add the approved testnet endpoint.',
        endpointSecretRef: 'private-source-reference',
        behaviorFingerprint: 'internal-artifact-digest',
        arbitraryField: 'unexpected-source-material',
      }}
    />,
  );
  expect(screen.getByText('92870')).toBeVisible();
  expect(screen.getByText('Add the approved testnet endpoint.')).toBeVisible();
  expect(
    screen.queryByText(
      /private-source-reference|internal-artifact-digest|unexpected-source-material/,
    ),
  ).toBeNull();
  expect(screen.queryByText(/Qualified|Active|Completed/)).toBeNull();
});

it('distinguishes a registered record from qualification and routing with a readable native timestamp', () => {
  render(
    <ProviderRecordSummary
      title="Recorded outcome"
      value={{ state: 'REGISTERED', revision: '1', createdAt: '2026-10-10T19:02:53.027000Z' }}
    />,
  );
  expect(screen.getByText('Registered')).toBeVisible();
  expect(screen.getByText('Record revision').nextElementSibling).toHaveTextContent('1');
  expect(screen.getByText('Registered at').nextElementSibling).toHaveTextContent(
    '10 Oct 2026, 19:02 UTC',
  );
  expect(screen.queryByText('Qualified')).toBeNull();
  expect(
    screen.getByText('Qualification and governed routing are managed separately.'),
  ).toBeVisible();
});

it('keeps registration and qualification update dates distinct', () => {
  render(
    <ProviderRecordSummary
      title="Recorded outcome"
      value={{
        state: 'QUALIFIED',
        revision: '4',
        createdAt: '2026-10-11T22:12:19.064000Z',
        updatedAt: '2026-10-11T23:00:48.897000Z',
      }}
    />,
  );
  expect(screen.getByText('Registered at').nextElementSibling).toHaveTextContent(
    '11 Oct 2026, 22:12 UTC',
  );
  expect(screen.getByText('Last updated').nextElementSibling).toHaveTextContent(
    '11 Oct 2026, 23:00 UTC',
  );
  expect(
    screen.getByText('Last updated').nextElementSibling?.querySelector('time'),
  ).toHaveAttribute('dateTime', '2026-10-11T23:00:48.897000Z');
});

it('does not substitute the registration date for an unavailable update date', () => {
  render(
    <ProviderRecordSummary
      title="Recorded outcome"
      value={{ createdAt: '2026-10-11T22:12:19.064000Z', updatedAt: 'unknown' }}
    />,
  );
  expect(screen.getByText('Registered at').nextElementSibling).toHaveTextContent(
    '11 Oct 2026, 22:12 UTC',
  );
  expect(screen.getByText('Last updated').nextElementSibling).toHaveTextContent('Date unavailable');
});

it('keeps unknown status and malformed timestamps visibly unconfirmed', () => {
  render(
    <ProviderRecordSummary
      title="Recorded outcome"
      value={{ state: 'NEW_STATE', createdAt: 'unknown' }}
    />,
  );
  expect(screen.getByText('Status not reported')).toBeVisible();
  expect(screen.getByText('Date unavailable')).toBeVisible();
  expect(screen.queryByText(/^(Qualified|Registered|Active)$/u)).toBeNull();
});
