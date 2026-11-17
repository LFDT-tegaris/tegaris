import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import { WorkspaceStatus } from './workspace-status';

afterEach(cleanup);

it('keeps a hidden-or-denied page neutral and exposes only deliberate support references', () => {
  render(
    <WorkspaceStatus
      state="DENIED"
      title="Page not available"
      detail="Check your account and workspace access."
      support={{ code: 'PC-AUTH-0005', traceId: '018f0000-0000-7000-8000-000000000701' }}
    />,
  );
  expect(screen.getByRole('heading', { name: 'Page not available' })).toBeVisible();
  expect(screen.queryByText('Access denied')).toBeNull();
  expect(screen.getByText('PC-AUTH-0005')).not.toBeVisible();
  expect(screen.queryByRole('button', { name: 'Try again' })).toBeNull();
  fireEvent.click(screen.getByText('Support reference'));
  expect(screen.getByText('PC-AUTH-0005')).toBeVisible();
  expect(screen.getByText('018f0000-0000-7000-8000-000000000701')).toBeVisible();
});

it('keeps a pending refresh disabled and invokes only the supplied read action', () => {
  const retry = vi.fn();
  const view = (retrying = false) => (
    <WorkspaceStatus
      state="UNAVAILABLE"
      detail="The workspace could not be loaded."
      onRetry={retry}
      retrying={retrying}
    />
  );
  const rendered = render(view());
  fireEvent.click(screen.getByRole('button', { name: 'Try again' }));
  expect(retry).toHaveBeenCalledTimes(1);
  rendered.rerender(view(true));
  expect(screen.getByRole('button', { name: 'Refreshing…' })).toBeDisabled();
  fireEvent.click(screen.getByRole('button', { name: 'Refreshing…' }));
  expect(retry).toHaveBeenCalledTimes(1);
});

it('does not describe an ambiguous write outcome as a success', () => {
  render(
    <WorkspaceStatus
      state="WRITE_AMBIGUITY"
      detail="Read the original operation before trying again."
    />,
  );
  expect(screen.getByRole('heading', { name: 'Outcome not confirmed' })).toBeVisible();
  expect(screen.getByText('Read the original operation before trying again.')).toBeVisible();
  expect(screen.queryByText('Available')).toBeNull();
});
