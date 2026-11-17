import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';

import {
  BffProblem,
  routes,
  type ProcessSnapshot,
  type UiSessionBootstrap,
} from '@openpc/ui-shell';

import { i08PreferenceTransitionEvent, Workbench } from './workbench';

const navigation = vi.hoisted(() => ({
  parameters: 'i08-validation=initial-token',
  replace: vi.fn(),
}));

const bff = vi.hoisted(() => ({
  readSessionBootstrap: vi.fn(),
  readSnapshot: vi.fn(),
}));

vi.mock('next/navigation', () => ({
  usePathname: () => '/home/session',
  useRouter: () => ({ replace: navigation.replace }),
  useSearchParams: () => new URLSearchParams(navigation.parameters),
}));

vi.mock('@openpc/ui-shell', async () => ({
  ...(await vi.importActual<typeof import('@openpc/ui-shell')>('@openpc/ui-shell')),
  readSessionBootstrap: bff.readSessionBootstrap,
  readSnapshot: bff.readSnapshot,
}));

const route = {
  id: 'ROUTE-LOGIN-CONTEXT-SESSION',
  path: '/home/session',
  domain: 'login-context-session',
  processDomainId: 'LOGIN_CONTEXT_SESSION',
  primaryPersonaId: 'AUTHENTICATED_END_USER',
  destination: 'HOME',
  title: 'Session and context',
} as const;

function snapshot(truthState: 'SUCCESS' | 'DENIED'): ProcessSnapshot {
  return {
    snapshotId:
      truthState === 'SUCCESS'
        ? '00000000-0000-4000-8000-000000000001'
        : '00000000-0000-4000-8000-000000000002',
    routeId: route.id,
    processDomainId: route.processDomainId,
    contextDigest: `sha256:${'1'.repeat(64)}`,
    authorityGeneration: '1',
    policyGeneration: '1',
    truthState,
    scope: { plane: 'PLATFORM', participantId: null, privacyDomainId: null },
    observedAt: '2026-09-07T00:00:00.000Z',
    freshness: { observedAt: '2026-09-07T00:00:00.000Z', state: 'CURRENT' },
    completeness: 'COMPLETE',
    items: [],
    authorizedActions: [],
    evidenceRefs: [],
  };
}

function session(locale: string): UiSessionBootstrap {
  return {
    csrfToken: 'csrf',
    etag: 'etag',
    idempotencyKey: 'idempotency',
    locale,
    timeZone: 'UTC',
    density: 'comfortable',
    theme: 'light',
  };
}

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((resolvePromise) => {
    resolve = resolvePromise;
  });
  return { promise, resolve };
}

beforeEach(() => {
  navigation.parameters = 'i08-validation=initial-token';
  navigation.replace.mockReset();
  navigation.replace.mockImplementation((url: string) => {
    navigation.parameters = new URL(url, 'http://openpc.test').search.slice(1);
  });
  bff.readSnapshot.mockReset();
  bff.readSessionBootstrap.mockReset();
});

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

it('uses the application router, refetches both owners, and rejects stale transition data', async () => {
  const nextSnapshot = deferred<ProcessSnapshot>();
  const nextSession = deferred<UiSessionBootstrap>();
  bff.readSnapshot
    .mockResolvedValueOnce(snapshot('SUCCESS'))
    .mockReturnValueOnce(nextSnapshot.promise);
  bff.readSessionBootstrap
    .mockResolvedValueOnce(session('en-US'))
    .mockReturnValueOnce(nextSession.promise);
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  const view = () => (
    <QueryClientProvider client={queryClient}>
      <Workbench route={route} />
    </QueryClientProvider>
  );
  const rendered = render(view());

  await screen.findByText(/server reported complete data/i);
  expect(document.querySelector('[data-i08-transition-ready]')).toHaveAttribute(
    'data-i08-transition-ready',
    'true',
  );

  act(() => {
    window.dispatchEvent(
      new CustomEvent(i08PreferenceTransitionEvent, {
        detail: { validationToken: '../not-admitted' },
      }),
    );
  });
  expect(navigation.replace).not.toHaveBeenCalled();

  act(() => {
    window.dispatchEvent(
      new CustomEvent(i08PreferenceTransitionEvent, {
        detail: { validationToken: 'next-token' },
      }),
    );
  });
  expect(navigation.replace).toHaveBeenCalledWith('/home/session?i08-validation=next-token', {
    scroll: false,
  });
  rendered.rerender(view());

  await waitFor(() => expect(bff.readSnapshot).toHaveBeenCalledTimes(2));
  expect(bff.readSessionBootstrap).toHaveBeenCalledTimes(2);
  expect(document.querySelector('[data-i08-transition-ready]')).toHaveAttribute(
    'data-i08-transition-ready',
    'false',
  );
  expect(screen.queryByText(/^SUCCESS$/)).not.toBeInTheDocument();

  await act(async () => {
    nextSnapshot.resolve(snapshot('DENIED'));
    nextSession.resolve(session('fr-FR'));
    await Promise.all([nextSnapshot.promise, nextSession.promise]);
  });

  await waitFor(() =>
    expect(document.querySelector('[data-i08-transition-ready]')).toHaveAttribute(
      'data-i08-transition-ready',
      'true',
    ),
  );
  expect(document.querySelector('[data-i08-snapshot-transition-token]')).toHaveAttribute(
    'data-i08-snapshot-transition-token',
    'next-token',
  );
  expect(document.querySelector('[data-i08-session-transition-token]')).toHaveAttribute(
    'data-i08-session-transition-token',
    'next-token',
  );
  expect(document.querySelector('[data-locale]')).toHaveAttribute('data-locale', 'fr-FR');
  expect(screen.getByText(/^DENIED$/)).toBeInTheDocument();
});

it('keeps authenticator enrollment mounted when the process snapshot arrives', async () => {
  const pending = deferred<ProcessSnapshot>();
  bff.readSnapshot.mockReturnValueOnce(pending.promise);
  bff.readSessionBootstrap.mockResolvedValueOnce(session('en-US'));
  vi.spyOn(globalThis, 'fetch').mockResolvedValue(
    Response.json({
      enabled: true,
      authenticated: true,
      role: 'operator',
      sessionId: '018f0000-0000-7000-8000-000000000701',
      principalId: '018f0000-0000-7000-8000-000000000111',
      participantId: '018f0000-0000-7000-8000-000000000101',
      contextMode: 'PLATFORM',
      contextEpoch: '2',
      availableContexts: [],
    }),
  );
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={queryClient}>
      <Workbench route={route} />
    </QueryClientProvider>,
  );
  await screen.findByText('Platform workspace');
  fireEvent.click(screen.getByText('Security & workspace'));
  const register = await screen.findByRole('button', {
    name: 'Register authenticator',
  });
  await act(async () => {
    pending.resolve(snapshot('SUCCESS'));
    await pending.promise;
  });
  await screen.findByText(/server reported complete data/i);
  expect(register).toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Register authenticator' })).toBe(register);
});

it('uses the real access review owner at the registered Access review route', async () => {
  bff.readSessionBootstrap.mockResolvedValue(session('en-US'));
  vi.spyOn(globalThis, 'fetch').mockImplementation(async () =>
    Response.json({ authenticated: false, enabled: false }),
  );
  const accessRoute = routes.find((item) => item.path === '/govern/access')!;
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={client}>
      <Workbench route={accessRoute} />
    </QueryClientProvider>,
  );
  await screen.findByRole('heading', { name: 'Review administrative access' });
  expect(bff.readSnapshot).not.toHaveBeenCalled();
});

it('uses the work-item owner without fetching a generic support snapshot', async () => {
  navigation.parameters = 'view=work-items';
  bff.readSessionBootstrap.mockResolvedValue(session('en-US'));
  vi.spyOn(globalThis, 'fetch').mockImplementation(async () =>
    Response.json({ authenticated: false, enabled: false }),
  );
  const supportRoute = routes.find((item) => item.path === '/operate/support')!;
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={client}>
      <Workbench route={supportRoute} />
    </QueryClientProvider>,
  );
  await screen.findByRole('heading', { name: 'Work items' });
  expect(bff.readSnapshot).not.toHaveBeenCalled();
});

it('mounts governed notification endpoints without fetching a generic session snapshot', async () => {
  navigation.parameters = 'view=notification-endpoints';
  bff.readSessionBootstrap.mockResolvedValue(session('en-US'));
  vi.spyOn(globalThis, 'fetch').mockImplementation(async () =>
    Response.json({ authenticated: false, enabled: false }),
  );
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={client}>
      <Workbench route={route} />
    </QueryClientProvider>,
  );
  await screen.findByRole('heading', { name: 'Notification endpoints' });
  expect(bff.readSnapshot).not.toHaveBeenCalled();
  expect(screen.getByRole('link', { name: 'Notification endpoints' })).toHaveAttribute(
    'href',
    '/home/session?view=notification-endpoints',
  );
});

it.each([
  ['', 'ceiling', 'Ceiling recovery', '/api/v1/ui/platform-ceiling-workbench'],
  ['&phase=ceiling', 'ceiling', 'Ceiling recovery', '/api/v1/ui/platform-ceiling-workbench'],
  ['&phase=envelopes', 'envelopes', 'Administrator envelopes', '/api/v1/ui/rpc-access-workbench'],
  ['&phase=assignments', 'assignments', 'Administrator assignments', '/api/v1/ui/grant-workbench'],
  ['&phase=unrecognized', 'ceiling', 'Ceiling recovery', '/api/v1/ui/platform-ceiling-workbench'],
])(
  'reads only the selected Platform handoff owner for %s',
  async (query, phase, label, endpoint) => {
    navigation.parameters = `view=platform-ceiling${query}`;
    bff.readSessionBootstrap.mockResolvedValue(session('en-US'));
    const requests = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      if (String(input) === '/api/v1/ui/local-session')
        return Response.json({
          enabled: true,
          authenticated: true,
          role: 'operator',
          sessionId: '018f0000-0000-7000-8000-000000000701',
          principalId: '018f0000-0000-7000-8000-000000000111',
          participantId: '018f0000-0000-7000-8000-000000000101',
          privacyDomainId: '018f0000-0000-7000-8000-000000000301',
          contextMode: 'PLATFORM',
          contextEpoch: '1',
          availableContexts: [],
        });
      return Response.json({ code: 'PC-AUTH-0005', truthState: 'DENIED' }, { status: 403 });
    });
    const participantRoute = routes.find((item) => item.path === '/govern/participants')!;
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(
      <QueryClientProvider client={client}>
        <Workbench route={participantRoute} />
      </QueryClientProvider>,
    );
    await waitFor(() =>
      expect(requests.mock.calls.some(([input]) => String(input).startsWith(endpoint))).toBe(true),
    );
    expect(screen.getByRole('link', { name: label })).toHaveAttribute('aria-current', 'page');
    for (const [name, target] of [
      ['Ceiling recovery', '/govern/participants?view=platform-ceiling'],
      ['Administrator envelopes', '/govern/participants?view=platform-ceiling&phase=envelopes'],
      ['Administrator assignments', '/govern/participants?view=platform-ceiling&phase=assignments'],
    ])
      expect(screen.getByRole('link', { name })).toHaveAttribute('href', target);
    const owners = requests.mock.calls
      .map(([input]) => String(input).split('?')[0] ?? '')
      .filter((path) =>
        [
          '/api/v1/ui/platform-ceiling-workbench',
          '/api/v1/ui/rpc-access-workbench',
          '/api/v1/ui/grant-workbench',
        ].includes(path),
      );
    expect(owners).toEqual([endpoint]);
    if (phase !== 'ceiling')
      expect(
        screen.queryByRole('heading', { name: 'Replace the Platform authority ceiling' }),
      ).toBeNull();
    expect(
      requests.mock.calls.every(([, options]) => !options?.method || options.method === 'GET'),
    ).toBe(true);
    expect(bff.readSnapshot).not.toHaveBeenCalled();
  },
);

it('provides the ten task destinations without development labels', () => {
  bff.readSnapshot.mockReturnValue(new Promise(() => {}));
  bff.readSessionBootstrap.mockReturnValue(new Promise(() => {}));
  vi.spyOn(globalThis, 'fetch').mockResolvedValue(Response.json({ authenticated: false }));
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={queryClient}>
      <Workbench route={route} evaluationUi />
    </QueryClientProvider>,
  );
  const primary = screen.getByRole('navigation', { name: 'Primary navigation' });
  const toggle = screen.getByRole('button', { name: /Navigation/ });
  expect(toggle).toHaveAttribute('aria-expanded', 'false');
  expect(toggle).toHaveAttribute('aria-controls', primary.id);
  fireEvent.click(toggle);
  expect(toggle).toHaveAttribute('aria-expanded', 'true');
  const contractsLink = screen.getByRole('link', { name: /Contracts & ABI/ });
  fireEvent.pointerDown(contractsLink);
  expect(toggle).toHaveAttribute('aria-expanded', 'true');
  contractsLink.focus();
  fireEvent.keyDown(contractsLink, { key: 'Escape' });
  expect(toggle).toHaveAttribute('aria-expanded', 'false');
  expect(toggle).toHaveFocus();
  fireEvent.click(toggle);
  fireEvent.pointerDown(document.body);
  expect(toggle).toHaveAttribute('aria-expanded', 'false');
  fireEvent.click(toggle);
  fireEvent.click(contractsLink);
  expect(toggle).toHaveAttribute('aria-expanded', 'false');
  expect(primary.querySelectorAll('a')).toHaveLength(10);
  expect(primary.querySelector('[aria-current="page"]')).toHaveTextContent('Account & workspace');
  expect(screen.getByRole('link', { name: /Simulation/ })).toHaveAttribute(
    'href',
    '/configure/policies?view=simulation',
  );
  expect(screen.queryByText('Development')).toBeNull();
  expect(screen.getByText('Policy management')).toBeVisible();
  expect(screen.getByText('Operations', { selector: 'p' })).toBeVisible();
  expect(screen.getByRole('link', { name: 'Skip to main content' })).toHaveAttribute(
    'href',
    '#workbench-main',
  );
});

it('uses the account surface for evaluation sign-in without requesting a protected process snapshot', async () => {
  bff.readSnapshot.mockRejectedValue(new Error('Protected process unavailable'));
  bff.readSessionBootstrap.mockResolvedValue(session('en-US'));
  vi.spyOn(globalThis, 'fetch').mockImplementation(async () =>
    Response.json({ enabled: true, authenticated: false }),
  );
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={client}>
      <Workbench route={route} evaluationUi />
    </QueryClientProvider>,
  );
  expect(await screen.findByRole('button', { name: 'Sign in' })).toBeEnabled();
  expect(bff.readSnapshot).not.toHaveBeenCalled();
  expect(bff.readSessionBootstrap).toHaveBeenCalled();
  expect(screen.queryByText('UNAVAILABLE')).toBeNull();
  expect(screen.queryByText('The process could not be loaded safely.')).toBeNull();
  expect(screen.queryByRole('region', { name: 'Process status' })).toBeNull();
  await waitFor(() =>
    expect(document.querySelector('[data-i08-transition-ready]')).toHaveAttribute(
      'data-i08-transition-ready',
      'true',
    ),
  );
});

it('retains protected process failures in the full account workbench', async () => {
  bff.readSnapshot.mockRejectedValue(new Error('Protected process unavailable'));
  bff.readSessionBootstrap.mockResolvedValue(session('en-US'));
  vi.spyOn(globalThis, 'fetch').mockImplementation(async () =>
    Response.json({ enabled: true, authenticated: false }),
  );
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={client}>
      <Workbench route={route} />
    </QueryClientProvider>,
  );
  expect(await screen.findByText('The process could not be loaded safely.')).toBeVisible();
  expect(bff.readSnapshot).toHaveBeenCalled();
});

it('keeps evaluation session management on its destination while preserving the full workbench', async () => {
  bff.readSnapshot.mockReturnValue(new Promise(() => {}));
  bff.readSessionBootstrap.mockReturnValue(new Promise(() => {}));
  vi.spyOn(globalThis, 'fetch').mockImplementation(async () =>
    Response.json({ enabled: true, authenticated: false }),
  );
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const policyRoute = routes.find((item) => item.path === '/configure/policies')!;
  const view = (selected = policyRoute, evaluationUi = true) => (
    <QueryClientProvider client={client}>
      <Workbench route={selected} evaluationUi={evaluationUi} />
    </QueryClientProvider>
  );
  const rendered = render(view());
  expect(screen.queryByRole('heading', { name: 'Account & workspace', level: 2 })).toBeNull();
  expect(screen.getByRole('link', { name: 'Sign in' })).toHaveAttribute('href', '/home/session');
  rendered.rerender(view(routes.find((item) => item.path === '/develop/modules')!));
  await waitFor(() =>
    expect(screen.getByRole('button', { name: 'Refresh workspace' })).toBeEnabled(),
  );
  expect(screen.queryByRole('heading', { name: 'Account & workspace', level: 2 })).toBeNull();
  const providerRoute = routes.find((item) => item.path === '/operate/multi-rpc')!;
  rendered.rerender(view(providerRoute));
  await screen.findByRole('button', { name: 'Register or update a provider' });
  expect(screen.queryByRole('heading', { name: 'Account & workspace', level: 2 })).toBeNull();
  rendered.rerender(view(providerRoute, false));
  expect(
    await screen.findByRole('heading', { name: 'Account & workspace', level: 2 }),
  ).toBeVisible();
  rendered.rerender(view(route));
  expect(await screen.findByRole('heading', { name: 'Your account', level: 2 })).toBeVisible();
  expect(screen.queryByText('Account settings')).toBeNull();
  expect(screen.queryByRole('region', { name: 'Security & workspace' })).toBeNull();
  rendered.rerender(view(policyRoute, false));
  expect(
    await screen.findByRole('heading', { name: 'Account & workspace', level: 2 }),
  ).toBeVisible();
  expect(screen.getByText('Account settings').closest('details')!.open).toBe(false);
});

it('preserves an opaque denial while offering account help and a collapsed support reference', async () => {
  bff.readSnapshot.mockRejectedValue(
    new BffProblem(
      {
        type: 'https://errors.openpc.local/hidden-or-not-found',
        title: 'The requested process is unavailable.',
        status: 404,
        code: 'PC-AUTH-0005',
        traceId: '018f0000-0000-7000-8000-000000000701',
        truthState: 'DENIED',
        retryable: false,
      },
      404,
    ),
  );
  bff.readSessionBootstrap.mockResolvedValue(session('en-US'));
  vi.spyOn(globalThis, 'fetch').mockResolvedValue(
    Response.json({ enabled: true, authenticated: false }),
  );
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={client}>
      <Workbench route={routes.find((item) => item.path === '/configure/policies')!} evaluationUi />
    </QueryClientProvider>,
  );
  const heading = await screen.findByRole('heading', { name: 'Page not available' });
  expect(heading.closest('[data-state]')).toHaveAttribute('data-state', 'DENIED');
  expect(screen.getByText('PC-AUTH-0005')).not.toBeVisible();
  expect(screen.queryByRole('button', { name: 'Try again' })).toBeNull();
  expect(
    screen
      .getAllByRole('link', { name: 'Account & workspace' })
      .every((link) => link.getAttribute('href') === '/home/session'),
  ).toBe(true);
  fireEvent.click(screen.getByText('Support reference'));
  expect(screen.getByText('018f0000-0000-7000-8000-000000000701')).toBeVisible();
});
