import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import { CentralSessionContext } from './central-session-context';
import { WorkspaceEntry } from './workspace-entry';

afterEach(cleanup);

it('routes central workspace selection to the account surface without mounting the inline action', () => {
  const fallback = vi.fn(() => <button>Inline context selection</button>);
  function InlineAction() {
    return fallback();
  }
  render(
    <CentralSessionContext.Provider value={true}>
      <WorkspaceEntry>
        <InlineAction />
      </WorkspaceEntry>
    </CentralSessionContext.Provider>,
  );
  expect(screen.getByRole('link', { name: 'Choose workspace' })).toHaveAttribute(
    'href',
    '/home/session',
  );
  expect(screen.queryByRole('button')).toBeNull();
  expect(fallback).not.toHaveBeenCalled();
});

it('preserves the existing inline flow outside a centralized console', () => {
  const select = vi.fn();
  render(
    <WorkspaceEntry>
      <button onClick={select}>Existing context selection</button>
    </WorkspaceEntry>,
  );
  fireEvent.click(screen.getByRole('button', { name: 'Existing context selection' }));
  expect(select).toHaveBeenCalledTimes(1);
  expect(screen.queryByRole('link')).toBeNull();
});

it('does not offer a navigable workspace action while its owner is busy', () => {
  render(
    <CentralSessionContext.Provider value={true}>
      <WorkspaceEntry disabled>
        <button>Inline context selection</button>
      </WorkspaceEntry>
    </CentralSessionContext.Provider>,
  );
  const action = screen.getByRole('link', { name: 'Choose workspace' });
  expect(action).toHaveAttribute('aria-disabled', 'true');
  expect(action).not.toHaveAttribute('href');
  expect(screen.queryByRole('button')).toBeNull();
});
