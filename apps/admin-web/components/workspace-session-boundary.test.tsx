import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import { WorkspaceSessionBoundary } from './workspace-session-boundary';
import { notifySessionTransition } from './session-transition';
const replace = vi.hoisted(() => vi.fn());
const router = { replace };
vi.mock('next/navigation', () => ({ useRouter: () => router }));
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
afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  replace.mockReset();
  localStorage.clear();
  const owner = notifySessionTransition('changing');
  notifySessionTransition('settled', owner);
});
function mount() {
  render(
    <WorkspaceSessionBoundary returnPath="/operate/evidence">
      <button>Protected action</button>
    </WorkspaceSessionBoundary>,
  );
}
it('conceals the workspace until the current native session is verified', async () => {
  let resolve!: (value: Response) => void;
  vi.spyOn(globalThis, 'fetch').mockReturnValue(
    new Promise((done) => {
      resolve = done;
    }),
  );
  mount();
  expect(screen.getByText('Protected action')).not.toBeVisible();
  await act(async () => resolve(Response.json(actor)));
  expect(screen.getByRole('button', { name: 'Protected action' })).toBeVisible();
});
it('returns a revoked session to the central sign-in page and removes protected content', async () => {
  const fetcher = vi
    .spyOn(globalThis, 'fetch')
    .mockImplementation(async () => Response.json(actor));
  mount();
  await waitFor(() => expect(screen.getByText('Protected action')).toBeVisible());
  fetcher.mockResolvedValue(Response.json({ enabled: true, authenticated: false }));
  fireEvent.focus(window);
  await waitFor(() =>
    expect(replace).toHaveBeenCalledWith(
      '/signin?returnTo=%2Foperate%2Fevidence&reason=session-ended',
    ),
  );
  expect(screen.queryByText('Protected action')).toBeNull();
});
it('conceals on an unavailable session without inventing sign-out or deleting retained custody', async () => {
  localStorage.setItem('openpc:policy-author-workflow:v2', 'retained-encrypted-custody');
  const fetcher = vi
    .spyOn(globalThis, 'fetch')
    .mockImplementation(async () => Response.json(actor));
  mount();
  await waitFor(() => expect(screen.getByText('Protected action')).toBeVisible());
  fetcher.mockRejectedValue(new Error('unavailable'));
  fireEvent.focus(window);
  await screen.findByRole('button', { name: 'Retry session check' });
  expect(screen.getByText('Protected action')).not.toBeVisible();
  expect(replace).not.toHaveBeenCalled();
  expect(localStorage.getItem('openpc:policy-author-workflow:v2')).toBe(
    'retained-encrypted-custody',
  );
  fetcher.mockImplementation(async () => Response.json(actor));
  fireEvent.click(screen.getByRole('button', { name: 'Retry session check' }));
  await waitFor(() => expect(screen.getByText('Protected action')).toBeVisible());
});
it('retains mounted controls behind concealment until an original transition settles', async () => {
  vi.spyOn(globalThis, 'fetch').mockImplementation(async () => Response.json(actor));
  mount();
  await waitFor(() => expect(screen.getByText('Protected action')).toBeVisible());
  let owner: string | undefined;
  act(() => {
    owner = notifySessionTransition('changing');
  });
  expect(screen.getByText('Protected action')).not.toBeVisible();
  expect(screen.getByText('Protected action').closest('[inert]')).not.toBeNull();
  expect(screen.getByText('Updating your session…')).toBeVisible();
  expect(
    screen.getByText(
      'If your browser is showing a sign-in or authenticator prompt, complete it to continue.',
    ),
  ).toBeVisible();
  expect(screen.queryByText('Checking your session…')).toBeNull();
  fireEvent.focus(window);
  await act(async () => {});
  expect(screen.getByText('Protected action')).not.toBeVisible();
  expect(screen.getByText('Updating your session…')).toBeVisible();
  act(() => {
    notifySessionTransition('settled', owner);
  });
  await waitFor(() => expect(screen.getByText('Protected action')).toBeVisible());
  expect(screen.queryByText('Updating your session…')).toBeNull();
});

it.each([
  ['PARTICIPANT', 'PLATFORM', '/govern/participants?view=rpc-access'],
  ['PLATFORM', 'PARTICIPANT', '/develop/modules'],
] as const)(
  'routes a verified private context change from %s to %s after concurrent focus checks',
  async (before, after, destination) => {
    const fetcher = vi.spyOn(globalThis, 'fetch').mockImplementation(async () =>
      Response.json({
        ...actor,
        contextMode: before,
        privacyDomainId: '018f0000-0000-7000-8000-000000000201',
        functionalTest: true,
      }),
    );
    mount();
    await waitFor(() => expect(screen.getByText('Protected action')).toBeVisible());
    let owner: string | undefined;
    act(() => {
      owner = notifySessionTransition('changing');
    });
    fetcher.mockResolvedValue(
      Response.json({
        ...actor,
        contextMode: after,
        privacyDomainId: '018f0000-0000-7000-8000-000000000201',
        functionalTest: true,
      }),
    );
    fireEvent.focus(window);
    await act(async () => {});
    expect(screen.getByText('Protected action')).not.toBeVisible();
    expect(replace).not.toHaveBeenCalled();
    act(() => {
      notifySessionTransition('settled', owner);
    });
    await waitFor(() => expect(replace).toHaveBeenCalledWith(destination));
    expect(screen.getByText('Protected action')).not.toBeVisible();
  },
);

it('does not route a private context change until its native session is verified', async () => {
  const fetcher = vi
    .spyOn(globalThis, 'fetch')
    .mockImplementation(async () => Response.json({ ...actor, functionalTest: true }));
  mount();
  await waitFor(() => expect(screen.getByText('Protected action')).toBeVisible());
  let owner: string | undefined;
  act(() => {
    owner = notifySessionTransition('changing');
  });
  fetcher.mockResolvedValue(Response.json({ enabled: true, authenticated: false }));
  act(() => {
    notifySessionTransition('settled', owner);
  });
  await waitFor(() =>
    expect(replace).toHaveBeenCalledWith(
      '/signin?returnTo=%2Foperate%2Fevidence&reason=session-ended',
    ),
  );
  expect(replace).not.toHaveBeenCalledWith('/develop/modules');
});
