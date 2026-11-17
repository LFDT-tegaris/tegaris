import { cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import userEvent from '@testing-library/user-event';
import { act } from 'react';
import { GovernanceContextSummary } from './governance-context-summary';

const actor = {
  sessionId: '018f0000-0000-7000-8000-000000000117',
  principalId: '018f0000-0000-7000-8000-000000000111',
  participantId: '018f0000-0000-7000-8000-000000000101',
  privacyDomainId: '018f0000-0000-7000-8000-000000000201',
  contextEpoch: '2',
  role: 'operator',
};
afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

it('keeps workspace inspection separate from the current task action', () => {
  const refresh = vi.fn();
  render(
    <GovernanceContextSummary title="Participant roles" description="Review roles." actor={actor}>
      <button onClick={refresh}>Refresh approvals</button>
    </GovernanceContextSummary>,
  );
  expect(screen.getByText('Maker')).toBeVisible();
  expect(screen.getByText(actor.participantId)).not.toBeVisible();
  fireEvent.click(screen.getByRole('button', { name: 'Workspace details' }));
  expect(
    within(screen.getByRole('dialog', { name: 'Workspace details' })).getByText(
      actor.participantId,
    ),
  ).toBeVisible();
  expect(refresh).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole('button', { name: 'Close Workspace details' }));
  expect(screen.getByRole('button', { name: 'Workspace details' })).toHaveFocus();
  fireEvent.click(screen.getByRole('button', { name: 'Refresh approvals' }));
  expect(refresh).toHaveBeenCalledTimes(1);
});

it('closes inspection and removes the previous workspace identifiers when context changes', () => {
  const view = (current: typeof actor) => (
    <GovernanceContextSummary title="Participant roles" description="Review roles." actor={current}>
      <button>Refresh approvals</button>
    </GovernanceContextSummary>
  );
  const { rerender } = render(view(actor));
  fireEvent.click(screen.getByRole('button', { name: 'Workspace details' }));
  expect(screen.getByRole('dialog', { name: 'Workspace details' })).toBeVisible();
  const next = {
    ...actor,
    role: 'viewer',
    privacyDomainId: '018f0000-0000-7000-8000-000000000202',
    contextEpoch: '3',
  };
  rerender(view(next));
  expect(screen.queryByRole('dialog', { name: 'Workspace details' })).not.toBeInTheDocument();
  expect(screen.queryByText(actor.privacyDomainId)).not.toBeInTheDocument();
  expect(screen.getByText('Checker')).toBeVisible();
  fireEvent.click(screen.getByRole('button', { name: 'Workspace details' }));
  expect(
    within(screen.getByRole('dialog', { name: 'Workspace details' })).getByText(
      next.privacyDomainId,
    ),
  ).toBeVisible();
});

it('discards pending copy feedback when the session changes within the same workspace', async () => {
  const user = userEvent.setup();
  let complete!: () => void;
  vi.spyOn(navigator.clipboard, 'writeText').mockImplementation(
    () =>
      new Promise<void>((resolve) => {
        complete = resolve;
      }),
  );
  const view = (current: typeof actor) => (
    <GovernanceContextSummary
      title="Participant roles"
      description="Review roles."
      actor={current}
    />
  );
  const rendered = render(view(actor));
  await user.click(screen.getByRole('button', { name: 'Workspace details' }));
  await user.click(screen.getByRole('button', { name: 'Copy participant reference' }));
  rendered.rerender(view({ ...actor, sessionId: '018f0000-0000-7000-8000-000000000118' }));
  await act(async () => complete());
  await user.click(screen.getByRole('button', { name: 'Workspace details' }));
  expect(screen.getByRole('button', { name: 'Copy participant reference' })).toBeEnabled();
  expect(screen.getByRole('button', { name: 'Copy participant reference' })).toHaveTextContent(
    'Copy',
  );
  expect(screen.getAllByRole('status').every((status) => status.textContent === '')).toBe(true);
});
