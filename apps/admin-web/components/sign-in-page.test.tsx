import { beforeEach, expect, it, vi } from 'vitest';
import SignInPage from '../app/signin/page';
import { SignIn } from './sign-in';

const owner = vi.hoisted(() => ({ session: vi.fn(), redirect: vi.fn() }));
vi.mock('next/headers', () => ({ cookies: async () => ({ get: () => undefined }) }));
vi.mock('next/navigation', () => ({
  redirect: (path: string) => {
    owner.redirect(path);
    throw new Error('redirected');
  },
  useRouter: () => ({ replace: vi.fn() }),
}));
vi.mock('../app/api/v1/ui/workspace-session', () => ({ readWorkspaceSession: owner.session }));
beforeEach(() => {
  owner.session.mockReset().mockResolvedValue(undefined);
  owner.redirect.mockReset();
});

it('preserves the original unselected sign-in entry', async () => {
  const page = await SignInPage({
    searchParams: Promise.resolve({ returnTo: '/operate/evidence' }),
  });
  expect(page.type).toBe(SignIn);
  expect(page.props).toMatchObject({
    returnPath: '/operate/evidence',
    organizationContextInvalid: false,
  });
  expect(page.props.participantId).toBeUndefined();
});

it('forwards a valid organization hint with a validated local return path', async () => {
  const participantId = '018f0000-0000-7000-8000-000000000102';
  const page = await SignInPage({
    searchParams: Promise.resolve({ participantId, returnTo: 'https://evil.test' }),
  });
  expect(page.props).toMatchObject({
    participantId,
    returnPath: '/home/session',
    organizationContextInvalid: false,
  });
  expect(page.key).toBe(participantId);
});

it.each([
  { value: '' },
  { value: 'invalid' },
  { value: ['018f0000-0000-7000-8000-000000000101'] },
  { value: ['018f0000-0000-7000-8000-000000000101', '018f0000-0000-7000-8000-000000000102'] },
])(
  'blocks malformed or repeated organization hints instead of ignoring them: %j',
  async ({ value: participantId }) => {
    const page = await SignInPage({ searchParams: Promise.resolve({ participantId }) });
    expect(page.props.organizationContextInvalid).toBe(true);
    expect(page.props.participantId).toBeUndefined();
    expect(page.key).toBe('invalid-organization');
  },
);

it('keeps sign-in available when the native session belongs to another organization', async () => {
  owner.session.mockResolvedValue({ participantId: '018f0000-0000-7000-8000-000000000101' });
  const page = await SignInPage({
    searchParams: Promise.resolve({ participantId: '018f0000-0000-7000-8000-000000000102' }),
  });
  expect(page.type).toBe(SignIn);
  expect(owner.redirect).not.toHaveBeenCalled();
});

it('uses the existing native session for the matching organization', async () => {
  const participantId = '018f0000-0000-7000-8000-000000000102';
  owner.session.mockResolvedValue({ participantId });
  await expect(
    SignInPage({ searchParams: Promise.resolve({ participantId, returnTo: '/operate/evidence' }) }),
  ).rejects.toThrow('redirected');
  expect(owner.redirect).toHaveBeenCalledWith('/operate/evidence');
});
