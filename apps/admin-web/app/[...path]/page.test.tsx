import { renderToStaticMarkup } from 'react-dom/server';
import { beforeEach, expect, it, vi } from 'vitest';
const auth = vi.hoisted(() => ({ read: vi.fn(), cookie: vi.fn(), workbench: vi.fn() }));
vi.mock('next/headers', () => ({ cookies: async () => ({ get: auth.cookie }) }));
vi.mock('next/navigation', () => ({
  useRouter: () => ({ replace: vi.fn(), refresh: vi.fn() }),
  redirect: (path: string) => {
    throw new Error(`REDIRECT:${path}`);
  },
  notFound: () => {
    throw new Error('NOT_FOUND');
  },
}));
vi.mock('../api/v1/ui/workspace-session', () => ({ readWorkspaceSession: auth.read }));
vi.mock('../../components/workbench', () => ({ Workbench: auth.workbench }));
vi.mock('../../components/workspace-session-boundary', () => ({
  WorkspaceSessionBoundary: ({ children }: { children: React.ReactNode }) => children,
}));
vi.mock('../../components/invitation-acceptance', () => ({
  InvitationAcceptanceWorkflow: () => <p>Invitation proof</p>,
}));
import RoutePage from './page';
import SignInPage from '../signin/page';
beforeEach(() => {
  vi.resetAllMocks();
  auth.cookie.mockImplementation((name: string) => ({
    value:
      name === 'openpc_local_runtime_session'
        ? 'sealed-browser-cookie'
        : name === 'openpc_functional_actor'
          ? 'viewer'
          : 'PLATFORM',
  }));
  auth.workbench.mockReturnValue(<nav>Protected workspace</nav>);
});
it('redirects anonymous deep links before rendering or serializing the workspace', async () => {
  await expect(
    RoutePage({
      params: Promise.resolve({ path: ['configure', 'policies'] }),
      searchParams: Promise.resolve({ view: 'simulation' }),
    }),
  ).rejects.toThrow('REDIRECT:/signin?returnTo=%2Fconfigure%2Fpolicies%3Fview%3Dsimulation');
  expect(auth.workbench).not.toHaveBeenCalled();
});
it('renders the workspace only after the native session is accepted', async () => {
  auth.read.mockResolvedValue({ authenticated: true });
  const page = await RoutePage({
    params: Promise.resolve({ path: ['operate', 'evidence'] }),
    searchParams: Promise.resolve({}),
  });
  expect(renderToStaticMarkup(page)).toContain('Protected workspace');
  expect(auth.read).toHaveBeenCalledWith('sealed-browser-cookie', 'viewer', 'PLATFORM');
});
it('keeps invitation proof public without exposing workspace navigation', async () => {
  const page = await RoutePage({
    params: Promise.resolve({ path: ['govern', 'memberships'] }),
    searchParams: Promise.resolve({ view: 'invitation-acceptance' }),
  });
  const html = renderToStaticMarkup(page);
  expect(html).toContain('Invitation proof');
  expect(html).not.toContain('Protected workspace');
  expect(auth.read).not.toHaveBeenCalled();
});
it('redirects a signed-in visitor from sign-in to a safe deep link', async () => {
  auth.read.mockResolvedValue({ authenticated: true });
  await expect(
    SignInPage({ searchParams: Promise.resolve({ returnTo: '/operate/evidence' }) }),
  ).rejects.toThrow('REDIRECT:/operate/evidence');
  expect(auth.read).toHaveBeenCalledWith('sealed-browser-cookie', 'viewer', 'PLATFORM');
  await expect(
    SignInPage({ searchParams: Promise.resolve({ returnTo: '//evil.test' }) }),
  ).rejects.toThrow('REDIRECT:/home/session');
});
it('renders the central entry for anonymous users with a safe default destination', async () => {
  const page = await SignInPage({ searchParams: Promise.resolve({ returnTo: '//evil.test' }) });
  const html = renderToStaticMarkup(page);
  expect(html).toContain('Sign in to Tegaris');
  expect(html).not.toContain('Protected workspace');
});
