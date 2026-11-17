import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { act, type FormEvent } from 'react';
import { afterEach, expect, it, vi } from 'vitest';
import { CopyReference } from './copy-reference';

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

it('copies the exact visible value with the keyboard without submitting its form', async () => {
  const user = userEvent.setup();
  const write = vi.spyOn(navigator.clipboard, 'writeText').mockResolvedValue(undefined);
  const submit = vi.fn((event: FormEvent) => event.preventDefault());
  render(
    <form onSubmit={submit}>
      <CopyReference label="participant reference" value="018f0000-0000-7000-8000-000000000101" />
    </form>,
  );
  await user.tab();
  expect(screen.getByRole('button', { name: 'Copy participant reference' })).toHaveFocus();
  await user.keyboard('{Enter}');
  expect(write).toHaveBeenCalledExactlyOnceWith('018f0000-0000-7000-8000-000000000101');
  expect(screen.getByRole('status')).toHaveTextContent('participant reference copied.');
  expect(screen.getByText('018f0000-0000-7000-8000-000000000101')).toBeVisible();
  expect(submit).not.toHaveBeenCalled();
});

it('keeps the value selectable and explains a denied clipboard request', async () => {
  const user = userEvent.setup();
  vi.spyOn(navigator.clipboard, 'writeText').mockRejectedValue(new Error('private browser detail'));
  render(<CopyReference label="request reference" value="request-123" />);
  await user.click(screen.getByRole('button', { name: 'Copy request reference' }));
  expect(screen.getByRole('status')).toHaveTextContent(
    'Could not copy. Select and copy the reference.',
  );
  expect(screen.getByText('request-123')).toBeVisible();
  expect(screen.queryByText('private browser detail')).toBeNull();
  expect(screen.getByRole('button', { name: 'Copy request reference' })).toBeEnabled();
});

it('provides the same manual path when the Clipboard API is unavailable', async () => {
  vi.stubGlobal('navigator', { clipboard: undefined });
  render(<CopyReference label="request reference" value="request-123" />);
  await act(async () =>
    fireEvent.click(screen.getByRole('button', { name: 'Copy request reference' })),
  );
  expect(screen.getByRole('status')).toHaveTextContent(
    'Could not copy. Select and copy the reference.',
  );
  expect(screen.getByText('request-123')).toBeVisible();
});

it('prevents duplicate clipboard requests while the browser is responding', async () => {
  const user = userEvent.setup();
  let complete!: () => void;
  const write = vi.spyOn(navigator.clipboard, 'writeText').mockImplementation(
    () =>
      new Promise<void>((resolve) => {
        complete = resolve;
      }),
  );
  render(<CopyReference label="request reference" value="request-123" />);
  const button = screen.getByRole('button', { name: 'Copy request reference' });
  await user.dblClick(button);
  expect(write).toHaveBeenCalledTimes(1);
  expect(button).toBeDisabled();
  expect(button).toHaveTextContent('Copying…');
  await act(async () => complete());
  expect(button).toBeEnabled();
  expect(screen.getByRole('status')).toHaveTextContent('request reference copied.');
});

it('does not carry successful feedback to a changed reference', async () => {
  const user = userEvent.setup();
  vi.spyOn(navigator.clipboard, 'writeText').mockResolvedValue(undefined);
  const view = render(<CopyReference label="request reference" value="first-request" />);
  await user.click(screen.getByRole('button', { name: 'Copy request reference' }));
  expect(screen.getByRole('status')).not.toBeEmptyDOMElement();
  view.rerender(<CopyReference label="request reference" value="second-request" />);
  expect(screen.getByRole('status')).toBeEmptyDOMElement();
  expect(screen.getByRole('button', { name: 'Copy request reference' })).toHaveTextContent('Copy');
  expect(screen.queryByText('first-request')).toBeNull();
});

it.each(['resolve', 'reject'] as const)(
  'ignores a late %s after leaving and returning to a reference',
  async (outcome) => {
    const user = userEvent.setup();
    let complete!: () => void;
    vi.spyOn(navigator.clipboard, 'writeText').mockImplementation(
      () =>
        new Promise<void>((resolve, reject) => {
          complete = outcome === 'resolve' ? resolve : () => reject(new Error('old request'));
        }),
    );
    const view = render(<CopyReference label="request reference" value="first-request" />);
    await user.click(screen.getByRole('button', { name: 'Copy request reference' }));
    view.rerender(<CopyReference label="request reference" value="second-request" />);
    view.rerender(<CopyReference label="request reference" value="first-request" />);
    await act(async () => complete());
    expect(screen.getByRole('status')).toBeEmptyDOMElement();
    expect(screen.getByRole('button', { name: 'Copy request reference' })).toBeEnabled();
    expect(screen.getByRole('button', { name: 'Copy request reference' })).toHaveTextContent(
      'Copy',
    );
  },
);
