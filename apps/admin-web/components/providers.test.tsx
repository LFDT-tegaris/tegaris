import type { ReactNode } from 'react';
import { act, cleanup, render, screen, waitFor } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import { Providers } from './providers';
import { notifySessionTransition } from './session-transition';

const navigation = vi.hoisted(() => ({ path: '/operate/evidence', query: '', replace: vi.fn() }));
const router = { replace: navigation.replace };
vi.mock('next/navigation', () => ({
  usePathname: () => navigation.path,
  useSearchParams: () => new URLSearchParams(navigation.query),
  useRouter: () => router,
}));
vi.mock('@openpc/ui-shell', async (original) => ({
  ...(await original<typeof import('@openpc/ui-shell')>()),
  UiRuntimeProvider: ({ children }: { children: ReactNode }) => children,
}));
const actor = {
  enabled: true,
  authenticated: true,
  role: 'viewer',
  contextMode: 'PLATFORM',
  contextEpoch: '2',
  availableContexts: [],
  sessionId: '018f0000-0000-7000-8000-000000000701',
  principalId: '018f0000-0000-7000-8000-000000000112',
  participantId: '018f0000-0000-7000-8000-000000000101',
};
const workspace = (name = 'Current task') => (
  <Providers processEventsEnabled={false}>
    <button>{name}</button>
  </Providers>
);
afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  navigation.replace.mockReset();
  navigation.path = '/operate/evidence';
  navigation.query = '';
  localStorage.clear();
  const owner = notifySessionTransition('changing');
  notifySessionTransition('settled', owner);
});

it('keeps the verified workspace visible while rechecking a screen switch', async () => {
  const fetcher = vi.spyOn(globalThis, 'fetch').mockResolvedValue(Response.json(actor));
  const view = render(workspace());
  await waitFor(() => expect(screen.getByRole('button', { name: 'Current task' })).toBeVisible());
  let resolve!: (response: Response) => void;
  fetcher.mockImplementation(
    () =>
      new Promise((done) => {
        resolve = done;
      }),
  );
  navigation.path = '/govern/memberships';
  view.rerender(workspace('Next task'));
  expect(screen.queryByText('Checking your session…')).toBeNull();
  expect(screen.getByRole('button', { name: 'Next task' })).toBeVisible();
  expect(fetcher).toHaveBeenCalledTimes(2);
  await act(async () => resolve(Response.json(actor)));
  expect(screen.getByRole('button', { name: 'Next task' })).toBeVisible();
});

it('uses the new screen and query when navigation finds an ended session', async () => {
  const fetcher = vi.spyOn(globalThis, 'fetch').mockResolvedValue(Response.json(actor));
  const view = render(workspace());
  await waitFor(() => expect(screen.getByText('Current task')).toBeVisible());
  fetcher.mockResolvedValue(Response.json({ enabled: true, authenticated: false }));
  navigation.path = '/govern/memberships';
  navigation.query = 'view=principals';
  view.rerender(workspace('Next task'));
  await waitFor(() =>
    expect(navigation.replace).toHaveBeenCalledWith(
      '/signin?returnTo=%2Fgovern%2Fmemberships%3Fview%3Dprincipals&reason=session-ended',
    ),
  );
  expect(screen.queryByText('Next task')).toBeNull();
});

it('conceals the current screen when its background session check fails', async () => {
  const fetcher = vi.spyOn(globalThis, 'fetch').mockResolvedValue(Response.json(actor));
  const view = render(workspace());
  await waitFor(() => expect(screen.getByText('Current task')).toBeVisible());
  fetcher.mockRejectedValue(new Error('Unavailable'));
  navigation.path = '/govern/memberships';
  view.rerender(workspace('Next task'));
  await screen.findByRole('button', { name: 'Retry session check' });
  expect(screen.getByText('Next task')).not.toBeVisible();
  expect(navigation.replace).not.toHaveBeenCalled();
});

it('still conceals a verified screen during an account or workspace transition', async () => {
  vi.spyOn(globalThis, 'fetch').mockImplementation(async () => Response.json(actor));
  const view = render(workspace());
  await waitFor(() => expect(screen.getByText('Current task')).toBeVisible());
  let owner: string | undefined;
  act(() => {
    owner = notifySessionTransition('changing');
  });
  navigation.path = '/govern/memberships';
  view.rerender(workspace('Next task'));
  expect(screen.getByText('Next task')).not.toBeVisible();
  act(() => {
    notifySessionTransition('settled', owner);
  });
  await waitFor(() => expect(screen.getByText('Next task')).toBeVisible());
});

it.each(['/signin', '/govern/memberships?view=invitation-acceptance'])(
  'leaves the public entry %s outside the workspace session check',
  (url) => {
    const parsed = new URL(url, 'https://example.org');
    navigation.path = parsed.pathname;
    navigation.query = parsed.search.slice(1);
    const fetcher = vi.spyOn(globalThis, 'fetch');
    render(workspace('Public entry'));
    expect(screen.getByRole('button', { name: 'Public entry' })).toBeVisible();
    expect(fetcher).not.toHaveBeenCalled();
  },
);

it('does not bypass the workspace check for an oversized query string', () => {
  navigation.query = 'filter=' + 'a'.repeat(2100);
  vi.spyOn(globalThis, 'fetch').mockReturnValue(new Promise(() => {}));
  render(workspace());
  expect(screen.getByText('Current task')).not.toBeVisible();
  expect(screen.getByText('Checking your session…')).toBeVisible();
});

it('does not treat duplicate invitation views as a public entry', () => {
  navigation.path = '/govern/memberships';
  navigation.query = 'view=invitation-acceptance&view=principals';
  vi.spyOn(globalThis, 'fetch').mockReturnValue(new Promise(() => {}));
  render(workspace());
  expect(screen.getByText('Current task')).not.toBeVisible();
  expect(screen.getByText('Checking your session…')).toBeVisible();
});

it.each([
  [
    'PARTICIPANT',
    'PLATFORM',
    '/govern/participants?view=rpc-access',
    '/govern/participants?view=rpc-access',
  ],
  ['PLATFORM', 'PARTICIPANT', '/develop/modules', '/develop/modules'],
  [
    'PARTICIPANT',
    'PLATFORM',
    '/govern/participants?view=rpc-access',
    '/govern/memberships?view=principals',
  ],
] as const)(
  'verifies a %s to %s context switch targeting %s on arrival at %s without remounting',
  async (before, after, destination, arrival) => {
    const status = (contextMode: string) => ({
      ...actor,
      contextMode,
      functionalTest: true,
      privacyDomainId: '018f0000-0000-7000-8000-000000000201',
    });
    const fetcher = vi
      .spyOn(globalThis, 'fetch')
      .mockImplementation(async () => Response.json(status(before)));
    const view = render(workspace());
    await waitFor(() => expect(screen.getByText('Current task')).toBeVisible());
    let owner: string | undefined;
    act(() => {
      owner = notifySessionTransition('changing');
    });
    fetcher.mockImplementation(async () => Response.json(status(after)));
    act(() => {
      notifySessionTransition('settled', owner);
    });
    await waitFor(() => expect(navigation.replace).toHaveBeenCalledWith(destination));
    expect(screen.getByText('Current task')).not.toBeVisible();
    const parsed = new URL(arrival, 'https://example.org');
    navigation.path = parsed.pathname;
    navigation.query = parsed.search.slice(1);
    view.rerender(workspace('Destination task'));
    await waitFor(() =>
      expect(screen.getByRole('button', { name: 'Destination task' })).toBeVisible(),
    );
    fetcher.mockResolvedValue(Response.json({ enabled: true, authenticated: false }));
    act(() => {
      window.dispatchEvent(new Event('focus'));
    });
    await waitFor(() => expect(screen.queryByText('Destination task')).toBeNull());
  },
);
