import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import { SignIn } from './sign-in';
import { notifySessionTransition } from './session-transition';
const router = vi.hoisted(() => ({ replace: vi.fn() }));
vi.mock('next/navigation', () => ({ useRouter: () => router }));
afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  router.replace.mockReset();
});
const authenticatedSession = {
  enabled: true,
  authenticated: true,
  role: 'operator',
  sessionId: '018f0000-0000-7000-8000-000000000301',
  principalId: '018f0000-0000-7000-8000-000000000111',
  participantId: '018f0000-0000-7000-8000-000000000101',
  contextMode: 'PLATFORM',
  contextEpoch: '1',
  availableContexts: [],
};
it('finishes a provider return after native authentication even when the first navigation omits a Strict cookie', async () => {
  localStorage.setItem('openpc:transaction-workbench:v1:cigl', 'retained-request');
  vi.spyOn(globalThis, 'fetch').mockImplementation(async () => Response.json(authenticatedSession));
  render(<SignIn returnPath="/configure/policies?view=simulation" />);
  await waitFor(() =>
    expect(router.replace).toHaveBeenCalledWith('/configure/policies?view=simulation'),
  );
  expect(localStorage.getItem('openpc:transaction-workbench:v1:cigl')).toBe('retained-request');
});

it.each(['https://example.test', '//example.test', '/api/v1/ui/local-session'])(
  'rejects an unsafe return destination after native authentication',
  async (returnPath) => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(async () =>
      Response.json(authenticatedSession),
    );
    render(<SignIn returnPath={returnPath} />);
    await waitFor(() => expect(router.replace).toHaveBeenCalledWith('/home/session'));
  },
);

it.each([
  { enabled: true, authenticated: false },
  { enabled: false },
  { enabled: true, authenticated: true },
  { error: 'unavailable' },
])('does not navigate to the workspace without a validated native session', async (result) => {
  const fetcher = vi
    .spyOn(globalThis, 'fetch')
    .mockImplementation(async () => Response.json(result));
  render(<SignIn returnPath="/operate/evidence" />);
  await waitFor(() => expect(fetcher).toHaveBeenCalled());
  expect(router.replace).not.toHaveBeenCalled();
});

it('does not navigate on a stale authenticated response during a session transition', async () => {
  let resolve!: (value: Response) => void;
  vi.spyOn(globalThis, 'fetch').mockReturnValue(
    new Promise((done) => {
      resolve = done;
    }),
  );
  render(<SignIn returnPath="/operate/evidence" />);
  let owner: string | undefined;
  act(() => {
    owner = notifySessionTransition('changing');
  });
  await act(async () => resolve(Response.json(authenticatedSession)));
  expect(router.replace).not.toHaveBeenCalled();
  cleanup();
  notifySessionTransition('settled', owner);
});
it('has one sign-in action and no workspace navigation, organization IDs or developer controls', () => {
  render(<SignIn returnPath="/operate/evidence" />);
  expect(screen.getByRole('heading', { name: 'Sign in to Tegaris' })).toBeVisible();
  expect(screen.getAllByRole('button')).toHaveLength(1);
  expect(screen.queryByRole('navigation')).toBeNull();
  expect(screen.queryByRole('textbox')).toBeNull();
  expect(screen.queryByText('Local account sign-in')).toBeNull();
});
it('uses the intended workspace destination and permits a new attempt after a safe failure', async () => {
  const fetcher = vi
    .spyOn(globalThis, 'fetch')
    .mockResolvedValue(Response.json({}, { status: 503 }));
  render(<SignIn returnPath="/configure/policies?view=simulation" />);
  fireEvent.click(screen.getByRole('button', { name: 'Sign in' }));
  await screen.findByRole('alert');
  expect(
    JSON.parse(fetcher.mock.calls.find(([, init]) => init?.method === 'POST')?.[1]?.body as string),
  ).toEqual({
    returnPath: '/configure/policies?view=simulation',
  });
  expect(screen.getByRole('button', { name: 'Sign in' })).toBeEnabled();
  fireEvent.click(screen.getByRole('button', { name: 'Sign in' }));
  await waitFor(() =>
    expect(fetcher.mock.calls.filter(([, init]) => init?.method === 'POST')).toHaveLength(2),
  );
});
it('shows authentication failure and session-ended messages without technical inputs', () => {
  const { rerender } = render(<SignIn returnPath="/home/session" sessionEnded />);
  expect(screen.getByRole('status')).toHaveTextContent('Your session has ended');
  rerender(<SignIn returnPath="/home/session" authenticationFailed key="failed" />);
  expect(screen.getByRole('alert')).toHaveTextContent('Sign-in could not be completed');
});

it('clears private transaction caches only after a native signed-out read on direct entry', async () => {
  localStorage.setItem('openpc:transaction-workbench:v1:cigl', 'private-request');
  vi.spyOn(globalThis, 'fetch').mockImplementation(async () =>
    Response.json({ enabled: true, authenticated: false }),
  );
  render(<SignIn returnPath="/operate/evidence" />);
  await waitFor(() =>
    expect(localStorage.getItem('openpc:transaction-workbench:v1:cigl')).toBeNull(),
  );
});

it.each([
  { enabled: false },
  { enabled: true, authenticated: 'unknown' },
  { error: 'unavailable' },
])('preserves retained custody when direct-entry native state is indeterminate', async (result) => {
  localStorage.setItem('openpc:transaction-workbench:v1:cigl', 'private-request');
  vi.spyOn(globalThis, 'fetch').mockImplementation(async () => Response.json(result));
  render(<SignIn returnPath="/operate/evidence" />);
  await waitFor(() => expect(screen.getByRole('button', { name: 'Sign in' })).toBeVisible());
  expect(localStorage.getItem('openpc:transaction-workbench:v1:cigl')).toBe('private-request');
});

it('rejects a held signed-out response after another tab changes the session and creates new custody', async () => {
  let resolve!: (value: Response) => void;
  vi.spyOn(globalThis, 'fetch').mockReturnValue(
    new Promise((done) => {
      resolve = done;
    }),
  );
  render(<SignIn returnPath="/operate/evidence" />);
  let owner: string | undefined;
  act(() => {
    owner = notifySessionTransition('changing');
  });
  localStorage.setItem('openpc:transaction-workbench:v1:cigl', 'new-session-private-request');
  await act(async () => resolve(Response.json({ enabled: true, authenticated: false })));
  expect(localStorage.getItem('openpc:transaction-workbench:v1:cigl')).toBe(
    'new-session-private-request',
  );
  cleanup();
  notifySessionTransition('settled', owner);
});

it('passes the organization from a sign-in link without showing technical controls', async () => {
  const participantId = '018f0000-0000-7000-8000-000000000102';
  const fetcher = vi
    .spyOn(globalThis, 'fetch')
    .mockResolvedValue(Response.json({}, { status: 503 }));
  render(<SignIn returnPath="/operate/evidence" participantId={participantId} />);
  fireEvent.click(screen.getByRole('button', { name: 'Sign in' }));
  await screen.findByRole('alert');
  const post = fetcher.mock.calls.find(([, init]) => init?.method === 'POST');
  expect(JSON.parse(post?.[1]?.body as string)).toEqual({
    returnPath: '/operate/evidence',
    participantId,
  });
  expect(document.body).not.toHaveTextContent(participantId);
  expect(screen.queryByRole('textbox')).not.toBeInTheDocument();
});

it('holds an invalid organization link without starting a fallback sign-in', () => {
  const fetcher = vi.spyOn(globalThis, 'fetch');
  render(<SignIn returnPath="/home/session" organizationContextInvalid />);
  expect(screen.getByRole('alert')).toHaveTextContent('Your organization sign-in link is invalid');
  expect(screen.getByRole('button', { name: 'Sign in' })).toBeDisabled();
  fireEvent.click(screen.getByRole('button', { name: 'Sign in' }));
  expect(fetcher).not.toHaveBeenCalled();
});

it('keeps the requested organization and existing custody when another organization is signed in', async () => {
  localStorage.setItem('openpc:transaction-workbench:v1:cigl', 'original-organization-request');
  const fetcher = vi
    .spyOn(globalThis, 'fetch')
    .mockResolvedValue(Response.json(authenticatedSession));
  render(
    <SignIn returnPath="/operate/evidence" participantId="018f0000-0000-7000-8000-000000000102" />,
  );
  await waitFor(() => expect(fetcher).toHaveBeenCalled());
  expect(router.replace).not.toHaveBeenCalled();
  expect(localStorage.getItem('openpc:transaction-workbench:v1:cigl')).toBe(
    'original-organization-request',
  );
  expect(screen.getByRole('button', { name: 'Sign in' })).toBeEnabled();
});

it('uses an existing native session only when it matches the requested organization', async () => {
  vi.spyOn(globalThis, 'fetch').mockResolvedValue(Response.json(authenticatedSession));
  render(
    <SignIn returnPath="/operate/evidence" participantId={authenticatedSession.participantId} />,
  );
  await waitFor(() => expect(router.replace).toHaveBeenCalledWith('/operate/evidence'));
});

it('cancels the old authorization request when the organization changes', async () => {
  let resolve!: (value: Response) => void;
  let requestSignal: AbortSignal | undefined;
  vi.spyOn(globalThis, 'fetch').mockImplementation(async (_input, init) => {
    if (init?.method === 'POST') {
      requestSignal = init.signal as AbortSignal;
      return new Promise<Response>((done) => {
        resolve = done;
      });
    }
    return Response.json({ enabled: true, authenticated: false });
  });
  const { rerender } = render(
    <SignIn returnPath="/home/session" participantId="018f0000-0000-7000-8000-000000000101" />,
  );
  fireEvent.click(screen.getByRole('button', { name: 'Sign in' }));
  await waitFor(() => expect(requestSignal).toBeDefined());
  rerender(
    <SignIn returnPath="/home/session" participantId="018f0000-0000-7000-8000-000000000102" />,
  );
  expect(requestSignal?.aborted).toBe(true);
  await act(async () => resolve(Response.json({}, { status: 503 })));
  expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Sign in' })).toBeEnabled();
});
