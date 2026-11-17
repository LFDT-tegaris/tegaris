import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import { EvaluationContext } from './evaluation-context';
import {
  notifySessionTransition,
  sessionTransitionEvent,
  sessionTransitionStorageKey,
} from './session-transition';

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  const owner = notifySessionTransition('changing');
  notifySessionTransition('settled', owner);
});

const actor = {
  enabled: true,
  authenticated: true,
  contextMode: 'PARTICIPANT',
  sessionId: '018f0000-0000-7000-8000-000000000701',
  contextEpoch: '2',
  role: 'viewer',
  availableContexts: [],
  principalId: '018f0000-0000-7000-8000-000000000111',
  participantId: '018f0000-0000-7000-8000-000000000101',
  privacyDomainId: '018f0000-0000-7000-8000-000000000201',
};
function mount(client = new QueryClient({ defaultOptions: { queries: { retry: false } } })) {
  render(
    <QueryClientProvider client={client}>
      <EvaluationContext routeKey="policies" />
    </QueryClientProvider>,
  );
  return client;
}

it('displays context identifiers from authenticated server readback', async () => {
  vi.spyOn(globalThis, 'fetch').mockResolvedValue(Response.json(actor));
  mount();
  await screen.findByText('Participant workspace');
  expect(screen.getByText(actor.participantId)).toBeInTheDocument();
  expect(screen.getByText(actor.privacyDomainId)).toBeInTheDocument();
});

it('conceals cached context after navigation during an unfinished transition', async () => {
  const fetcher = vi
    .spyOn(globalThis, 'fetch')
    .mockImplementation(async () => Response.json(actor));
  const client = mount();
  await screen.findByText(actor.privacyDomainId);
  let owner: string | undefined;
  act(() => {
    owner = notifySessionTransition('changing');
  });
  cleanup();
  mount(client);
  expect(screen.getByText('Checking session…')).toBeVisible();
  expect(screen.queryByText(actor.privacyDomainId)).toBeNull();
  fireEvent.focus(window);
  await act(async () => {});
  expect(screen.queryByText(actor.privacyDomainId)).toBeNull();
  expect(fetcher.mock.calls.every(([, init]) => !init?.method)).toBe(true);
  act(() => {
    notifySessionTransition('settled', owner);
  });
  await screen.findByText(actor.privacyDomainId);
});

it('reads current context after a cross-tab settlement was missed during navigation', async () => {
  const fetcher = vi
    .spyOn(globalThis, 'fetch')
    .mockImplementation(async () => Response.json(actor));
  mount();
  await screen.findByText(actor.privacyDomainId);
  act(() =>
    window.dispatchEvent(
      new StorageEvent('storage', {
        key: sessionTransitionStorageKey,
        newValue: JSON.stringify({ phase: 'changing', nonce: 'external-owner' }),
      }),
    ),
  );
  cleanup();
  localStorage.setItem(
    sessionTransitionStorageKey,
    JSON.stringify({ phase: 'settled', nonce: 'external-owner' }),
  );
  mount();
  await screen.findByText(actor.privacyDomainId);
  expect(fetcher).toHaveBeenCalledTimes(2);
});

it('clears previously displayed context when revalidation fails', async () => {
  const request = vi.spyOn(globalThis, 'fetch').mockResolvedValue(Response.json(actor));
  const client = mount();
  await screen.findByText('Participant workspace');
  request.mockResolvedValue(new Response(null, { status: 503 }));
  await client.invalidateQueries({ queryKey: ['evaluation-session-context'] });
  await screen.findByText('Context unavailable');
  await waitFor(() => expect(screen.queryByText(actor.participantId)).not.toBeInTheDocument());
});

it('does not present a participant context without its privacy domain', async () => {
  vi.spyOn(globalThis, 'fetch').mockResolvedValue(
    Response.json({ ...actor, privacyDomainId: undefined }),
  );
  mount();
  await screen.findByText('Context unavailable');
  expect(screen.queryByText('Participant workspace')).not.toBeInTheDocument();
});

it('conceals context at a transition and rejects an older response after native revalidation', async () => {
  let resolve!: (response: Response) => void;
  const old = new Promise<Response>((done) => {
    resolve = done;
  });
  const next = {
    ...actor,
    sessionId: '018f0000-0000-7000-8000-000000000702',
    privacyDomainId: '018f0000-0000-7000-8000-000000000202',
    contextEpoch: '3',
  };
  const fetcher = vi
    .spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(Response.json(actor))
    .mockReturnValueOnce(old)
    .mockResolvedValueOnce(Response.json(next));
  mount();
  await screen.findByText(actor.privacyDomainId);
  fireEvent.focus(window);
  expect(screen.queryByText(actor.privacyDomainId)).toBeNull();
  act(() =>
    window.dispatchEvent(
      new CustomEvent(sessionTransitionEvent, { detail: { phase: 'changing' } }),
    ),
  );
  expect(screen.getByText('Checking session…')).toBeVisible();
  act(() =>
    window.dispatchEvent(
      new StorageEvent('storage', {
        key: sessionTransitionStorageKey,
        newValue: JSON.stringify({ phase: 'settled' }),
      }),
    ),
  );
  await screen.findByText(next.privacyDomainId);
  await act(async () => resolve(Response.json(actor)));
  expect(screen.queryByText(actor.privacyDomainId)).toBeNull();
  expect(fetcher.mock.calls.every(([, init]) => !init?.method)).toBe(true);
});

it('rechecks sign-out on visible focus without relying on a cross-tab notification', async () => {
  const fetcher = vi
    .spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(Response.json(actor))
    .mockResolvedValueOnce(Response.json({ enabled: true, authenticated: false }));
  mount();
  await screen.findByText(actor.privacyDomainId);
  fireEvent.focus(window);
  await screen.findByText('Signed out');
  expect(screen.queryByText(actor.privacyDomainId)).toBeNull();
  expect(fetcher).toHaveBeenCalledTimes(2);
});

it('keeps the workspace header concealed through focus until the matching transition settles', async () => {
  vi.spyOn(globalThis, 'fetch').mockImplementation(async () => Response.json(actor));
  mount();
  await screen.findByText(actor.privacyDomainId);
  let owner: string | undefined;
  act(() => {
    owner = notifySessionTransition('changing');
  });
  fireEvent.focus(window);
  expect(screen.queryByText(actor.privacyDomainId)).toBeNull();
  act(() =>
    window.dispatchEvent(
      new CustomEvent(sessionTransitionEvent, {
        detail: { phase: 'settled', nonce: 'older-transition' },
      }),
    ),
  );
  expect(screen.queryByText(actor.privacyDomainId)).toBeNull();
  act(() => {
    notifySessionTransition('settled', owner);
  });
  await screen.findByText(actor.privacyDomainId);
});
