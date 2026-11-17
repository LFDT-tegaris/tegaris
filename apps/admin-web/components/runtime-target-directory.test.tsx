import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import { RuntimeTargetDirectory } from './runtime-target-directory';

const target = {
  targetId: 'urn:openpc:resource:018f0000-0000-7000-8000-000000000321',
  state: 'STAGING',
  desiredGenerationDigest: `sha256:${'a'.repeat(64)}`,
  activeGenerationDigest: null,
  observedAt: '2026-11-09T13:12:00.000Z',
};
afterEach(cleanup);

it('shows reported target state and keeps the original record in optional technical details', () => {
  const onRead = vi.fn();
  render(<RuntimeTargetDirectory items={[target]} busy={false} onRead={onRead} />);
  expect(screen.getByRole('heading', { name: 'Runtime target 1' })).toBeVisible();
  expect(screen.getByText('Staging')).toBeVisible();
  expect(screen.getByText('Selected')).toBeVisible();
  expect(screen.getByText('Not confirmed')).toBeVisible();
  expect(screen.getByText(/09 Nov 2026/)).toBeVisible();
  const raw = screen.getByLabelText('Technical details for runtime target 1');
  expect(raw).not.toBeVisible();
  expect(raw).toHaveTextContent(target.targetId);
  expect(raw).toHaveTextContent(target.desiredGenerationDigest);
  fireEvent.click(screen.getByRole('button', { name: 'View runtime target 1' }));
  expect(onRead).toHaveBeenCalledTimes(1);
  expect(onRead).toHaveBeenCalledWith(target.targetId);
  fireEvent.click(screen.getByRole('button', { name: 'Runtime target 1 details' }));
  expect(raw).toBeVisible();
  expect(screen.getByRole('button', { name: 'Copy runtime target reference' })).toBeVisible();
});

it('keeps configuration matching separate from a claim of current runtime access', () => {
  render(
    <RuntimeTargetDirectory
      items={[
        {
          ...target,
          state: 'ACTIVE_MATCHED',
          activeGenerationDigest: target.desiredGenerationDigest,
        },
      ]}
      busy={false}
      onRead={vi.fn()}
    />,
  );
  expect(screen.getByText('Configuration matched')).toBeVisible();
  expect(screen.getByText('Recorded')).toBeVisible();
  expect(screen.queryByText(/^Ready$|^Serving$|^Access granted$/i)).toBeNull();
});

it('does not issue a lookup for a malformed reference or fabricate a status for an unknown state', () => {
  const onRead = vi.fn();
  render(
    <RuntimeTargetDirectory
      items={[
        {
          ...target,
          targetId: 'invalid-reference',
          state: 'UNRECOGNIZED',
          observedAt: 'invalid-date',
        },
      ]}
      busy={false}
      onRead={onRead}
    />,
  );
  expect(screen.getByText('Status not reported')).toBeVisible();
  expect(screen.getByText('Date unavailable')).toBeVisible();
  const button = screen.getByRole('button', { name: 'View runtime target 1' });
  expect(button).toBeDisabled();
  fireEvent.click(button);
  expect(onRead).not.toHaveBeenCalled();
});

it('prevents another lookup while the owning workflow is busy', () => {
  const onRead = vi.fn();
  render(<RuntimeTargetDirectory items={[target]} busy onRead={onRead} />);
  const button = screen.getByRole('button', { name: 'View runtime target 1' });
  expect(button).toBeDisabled();
  fireEvent.click(button);
  expect(onRead).not.toHaveBeenCalled();
});
