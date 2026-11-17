import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { useQueryClient } from '@tanstack/react-query';
import { afterEach, expect, it, vi } from 'vitest';

import { UiRuntimeProvider, useUiRuntime } from './runtime';

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

function eventSource() {
  const sources: {
    close: ReturnType<typeof vi.fn>;
    onmessage?: (message: { data: string }) => void;
  }[] = [];
  const constructor = vi.fn(function () {
    const source = { close: vi.fn() };
    sources.push(source);
    return source;
  });
  vi.stubGlobal('EventSource', constructor);
  return { constructor, sources };
}

it('keeps the existing event subscription when enabled', () => {
  const events = eventSource();
  const { unmount } = render(<UiRuntimeProvider>Workspace</UiRuntimeProvider>);
  expect(events.constructor).toHaveBeenCalledWith('/api/v1/ui/events', { withCredentials: true });
  unmount();
  expect(events.sources[0]?.close).toHaveBeenCalledOnce();
});

it('does not call the fixture-only event endpoint when disabled', () => {
  const events = eventSource();
  render(<UiRuntimeProvider processEventsEnabled={false}>Workspace</UiRuntimeProvider>);
  expect(screen.getByText('Workspace')).toBeVisible();
  expect(events.constructor).not.toHaveBeenCalled();
});

it('closes an existing subscription when its capability is removed', () => {
  const events = eventSource();
  const { rerender } = render(<UiRuntimeProvider>Workspace</UiRuntimeProvider>);
  rerender(<UiRuntimeProvider processEventsEnabled={false}>Workspace</UiRuntimeProvider>);
  expect(events.sources[0]?.close).toHaveBeenCalledOnce();
  expect(events.constructor).toHaveBeenCalledOnce();
});

it('retains explicit protected-state clearing without a fixture subscription', () => {
  const events = eventSource();
  let client: ReturnType<typeof useQueryClient> | undefined;
  function Workspace() {
    client = useQueryClient();
    const runtime = useUiRuntime();
    return <button onClick={runtime.resetProtectedState}>Clear workspace</button>;
  }
  render(
    <UiRuntimeProvider processEventsEnabled={false}>
      <Workspace />
    </UiRuntimeProvider>,
  );
  if (!client) throw new Error('Workspace query client is missing');
  client.setQueryData(['ui-process', 'records'], { protectedRecord: 'selected' });
  fireEvent.click(screen.getByRole('button', { name: 'Clear workspace' }));
  expect(client.getQueryData(['ui-process', 'records'])).toBeUndefined();
  expect(events.constructor).not.toHaveBeenCalled();
});
