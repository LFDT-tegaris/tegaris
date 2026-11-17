import { StrictMode } from 'react';
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, expect, it, vi } from 'vitest';

import { LocalSessionSurface } from './local-session';
import {
  notifySessionTransition,
  sessionTransitionEvent,
  sessionTransitionStorageKey,
} from './session-transition';

const signedIn = {
  enabled: true,
  authenticated: true,
  role: 'viewer',
  sessionId: '018f0000-0000-7000-8000-000000000701',
  principalId: '018f0000-0000-7000-8000-000000000112',
  participantId: '018f0000-0000-7000-8000-000000000101',
  contextMode: 'PLATFORM',
  contextEpoch: '2',
  privacyDomainId: '018f0000-0000-7000-8000-000000000201',
  availableContexts: [],
};

it('shows managed test roles without sign-in, sign-out or account-security procedures in functional mode', async () => {
  vi.stubGlobal(
    'fetch',
    vi.fn(async () =>
      Response.json({ ...signedIn, contextMode: 'PARTICIPANT', functionalTest: true }),
    ),
  );
  render(<LocalSessionSurface appearance="menu" />);
  expect(await screen.findByText('Private test workspace')).toBeVisible();
  fireEvent.click(screen.getByText('Account', { exact: true }));
  expect(screen.getByRole('button', { name: 'Switch to Administrator' })).toBeVisible();
  expect(screen.queryByRole('button', { name: 'Sign in' })).toBeNull();
  expect(screen.queryByRole('button', { name: 'Sign out' })).toBeNull();
  expect(screen.queryByRole('link', { name: 'Account & security' })).toBeNull();
});
it('offers Platform selection only for a configured private profile and sends the exact workspace selection', async () => {
  const fetcher = vi.fn(async (_url: string, options?: RequestInit) =>
    options?.method === 'POST'
      ? Response.json({ status: 'selected', role: 'viewer', contextMode: 'PLATFORM' })
      : Response.json({
          ...signedIn,
          contextMode: 'PARTICIPANT',
          functionalTest: true,
          functionalPlatformConfigured: true,
        }),
  );
  vi.stubGlobal('fetch', fetcher);
  render(<LocalSessionSurface appearance="menu" />);
  expect(await screen.findByText('Private test workspace')).toBeVisible();
  fireEvent.click(screen.getByText('Account', { exact: true }));
  fireEvent.click(screen.getByRole('button', { name: 'Switch to Platform workspace' }));
  await waitFor(() =>
    expect(fetcher).toHaveBeenCalledWith(
      '/api/v1/ui/functional-session',
      expect.objectContaining({
        method: 'POST',
        body: JSON.stringify({ role: 'viewer', context: 'PLATFORM' }),
      }),
    ),
  );
  expect(screen.queryByRole('button', { name: 'Sign in' })).toBeNull();
});
function deferredResponse() {
  let resolve!: (value: Response) => void;
  let reject!: (cause: Error) => void;
  const promise = new Promise<Response>((yes, no) => {
    resolve = yes;
    reject = no;
  });
  return { promise, resolve, reject };
}
const methods = ['POST', 'DELETE', 'PATCH'] as const;
type LocalMethod = (typeof methods)[number];
const clearedKeys = [
  'openpc:policy-set-draft:v1',
  'openpc:policy-author-workflow:v2',
  'openpc:policy-release-workflow:v2',
  'openpc:policy-author-workflow:v1',
  'openpc:policy-release-workflow:v1',
  'openpc:role-workflow:v1',
  'openpc:grant-workflow:v1',
  'openpc:principal-workflow:v1',
  'openpc:recovery-workflow:v1',
  'openpc:transaction-workbench:v1:deployment',
  'openpc:transaction-workbench:v1:cigl',
  'openpc:transaction-workbench:v1:modules',
  'openpc:transaction-workbench:v1:policy',
  'openpc:transaction-workbench:v1:evidence:evidence-deletion:original-record',
];
const protectedKey = 'openpc:rpc-platform-envelope:v1';
function saveCustody() {
  for (const key of [...clearedKeys, protectedKey]) localStorage.setItem(key, `original:${key}`);
  sessionStorage.setItem('openpc:first-admin-review', 'first-original-ciphertext');
}
function expectCustody() {
  for (const key of [...clearedKeys, protectedKey])
    expect(localStorage.getItem(key)).toBe(`original:${key}`);
  expect(sessionStorage.getItem('openpc:first-admin-review')).toBe('first-original-ciphertext');
}
function mutationResult(method: LocalMethod) {
  return method === 'POST'
    ? { status: 'authenticated', role: signedIn.role }
    : {
        operationId: '018f0000-0000-7000-8000-000000000901',
        resourceRef: `urn:openpc:resource:${signedIn.sessionId}`,
        actionIntentId:
          method === 'DELETE' ? 'ACT-IDENTITY_DELETE_SESSION-V1' : 'ACT-IDENTITY_CREATE_SESSION-V1',
        intentDigest: `sha256:${'a'.repeat(64)}`,
        idempotencyKey: 'original-local-session-operation',
        state: 'SUCCEEDED',
        truthState: 'SUCCESS',
        createdAt: '2026-10-04T00:00:00.000000Z',
        updatedAt: '2026-10-04T00:00:01.000000Z',
        revision: '1',
      };
}
const actionName = (method: LocalMethod) =>
  method === 'POST'
    ? 'Sign in with local credential'
    : method === 'DELETE'
      ? 'Sign out'
      : 'Refresh session';
async function startLocalMutation(method: LocalMethod) {
  const user = userEvent.setup();
  await screen.findByRole('button', { name: 'Sign out' });
  if (method === 'POST')
    await user.type(screen.getByLabelText('Local access credential'), 'generated-secret');
  await user.click(screen.getByRole('button', { name: actionName(method) }));
}

afterEach(() => {
  cleanup();
  localStorage.clear();
  sessionStorage.clear();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
  const owner = notifySessionTransition('changing');
  notifySessionTransition('settled', owner);
});

it('removes cached transaction requests when the current native read confirms sign-out', async () => {
  saveCustody();
  vi.spyOn(globalThis, 'fetch').mockResolvedValue(
    Response.json({ enabled: true, authenticated: false }),
  );
  render(<LocalSessionSurface compactAuthenticated={false} />);
  await screen.findByRole('button', { name: 'Sign in' });
  for (const key of clearedKeys.filter((value) =>
    value.startsWith('openpc:transaction-workbench:'),
  ))
    expect(localStorage.getItem(key)).toBeNull();
  expect(localStorage.getItem(protectedKey)).toBe(`original:${protectedKey}`);
  expect(localStorage.getItem('openpc:policy-author-workflow:v2')).toBe(
    'original:openpc:policy-author-workflow:v2',
  );
});

it.each([503, 404])(
  'retains transaction custody when session status fails with %s',
  async (status) => {
    saveCustody();
    const pending = deferredResponse();
    vi.spyOn(globalThis, 'fetch').mockReturnValue(pending.promise);
    render(<LocalSessionSurface compactAuthenticated={false} />);
    await act(async () => pending.resolve(new Response(null, { status })));
    expectCustody();
  },
);

it('does not clear custody from a stale signed-out read after a newer signed-in result', async () => {
  saveCustody();
  const old = deferredResponse();
  vi.spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(Response.json(signedIn))
    .mockReturnValueOnce(old.promise)
    .mockResolvedValueOnce(Response.json(signedIn));
  render(<LocalSessionSurface compactAuthenticated={false} />);
  await screen.findByText(`Signed-in account: ${signedIn.principalId}`);
  fireEvent.focus(window);
  fireEvent.focus(window);
  await screen.findByRole('button', { name: 'Sign out' });
  await act(async () => old.resolve(Response.json({ enabled: true, authenticated: false })));
  expect(screen.getByRole('button', { name: 'Sign out' })).toBeVisible();
  expectCustody();
});

it('keeps a remounted account concealed until the active context change settles', async () => {
  const fetcher = vi
    .spyOn(globalThis, 'fetch')
    .mockImplementation(async () => Response.json(signedIn));
  render(<LocalSessionSurface compactAuthenticated={false} />);
  await screen.findByText(`Signed-in account: ${signedIn.principalId}`);
  let owner: string | undefined;
  act(() => {
    owner = notifySessionTransition('changing');
  });
  cleanup();
  render(<LocalSessionSurface compactAuthenticated={false} />);
  fireEvent.focus(window);
  await act(async () => {});
  expect(screen.queryByRole('button', { name: 'Sign out' })).toBeNull();
  const references = screen.queryByText(`Signed-in account: ${signedIn.principalId}`);
  if (references) expect(references).not.toBeVisible();
  expect(fetcher.mock.calls.every(([, init]) => !init?.method)).toBe(true);
  act(() => {
    notifySessionTransition('settled', owner);
  });
  await waitFor(() => expect(screen.getByRole('button', { name: 'Sign out' })).toBeVisible());
});

it('keeps account references and developer inputs out of the ordinary Participant workflow', async () => {
  const fetcher = vi
    .spyOn(globalThis, 'fetch')
    .mockResolvedValue(Response.json({ ...signedIn, contextMode: 'PARTICIPANT' }));
  const user = userEvent.setup();
  render(<LocalSessionSurface />);
  await screen.findByText('Organization workspace');
  expect(screen.getByRole('button', { name: 'Sign out' })).toBeVisible();
  expect(screen.getByText(`Signed-in account: ${signedIn.principalId}`)).not.toBeVisible();
  expect(screen.getByLabelText('Local access credential')).not.toBeVisible();
  expect(screen.getByText('Security & workspace').closest('details')!.open).toBe(false);
  expect(screen.getByText('Account settings').closest('details')!.open).toBe(false);
  await user.click(screen.getByText('Account settings'));
  await user.click(screen.getByText('Sign-in options'));
  const hint = screen.getByLabelText('OIDC account hint (optional)');
  await user.type(hint, 'another-account');
  await user.click(screen.getByText('Sign-in options'));
  await user.click(screen.getByText('Sign-in options'));
  expect(screen.getByLabelText('OIDC account hint (optional)')).toBe(hint);
  expect(hint).toHaveValue('another-account');
  expect(fetcher).toHaveBeenCalledTimes(1);
});

it.each([{ enabled: true, authenticated: false }, signedIn])(
  'keeps ordinary authentication visible and developer access collapsed (%j)',
  async (status) => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(Response.json(status));
    render(<LocalSessionSurface />);
    await screen.findByRole('heading', { name: 'Account & workspace' });
    expect(screen.getByRole('button', { name: /^(Sign in|Switch account)$/ })).toBeVisible();
    expect(screen.getByLabelText('Local access credential')).not.toBeVisible();
    expect(screen.getByText('Local account sign-in').closest('details')!.open).toBe(false);
  },
);

it('prioritizes workspace access and keeps account references collapsed', async () => {
  const fetcher = vi.spyOn(globalThis, 'fetch').mockResolvedValue(Response.json(signedIn));
  render(<LocalSessionSurface showAccountSettings />);
  await screen.findByText('Platform workspace');
  expect(screen.getByRole('heading', { name: 'Your account', level: 2 })).toBeVisible();
  expect(screen.queryByRole('heading', { name: 'Account & workspace', level: 2 })).toBeNull();
  expect(screen.queryByText('Account settings')).toBeNull();
  const references = screen.getByText('Account references').closest('details')!;
  const security = screen.getByRole('region', { name: 'Security & workspace' });
  expect(security).toBeVisible();
  expect(
    security.compareDocumentPosition(references) & Node.DOCUMENT_POSITION_FOLLOWING,
  ).toBeTruthy();
  expect(references.open).toBe(false);
  expect(references.querySelector('dl')).not.toBeVisible();
  expect(references).toHaveTextContent(signedIn.principalId);
  expect(screen.queryByText('Account details')).toBeNull();
  expect(screen.getByRole('button', { name: 'Refresh session' })).not.toBeVisible();
  await userEvent.click(screen.getByText('Account references'));
  expect(references.open).toBe(true);
  expect(references.querySelector('dl')).toBeVisible();
  expect(screen.getByRole('button', { name: 'Refresh session' })).toBeVisible();
  expect(screen.getByText('Local account sign-in').closest('details')!.open).toBe(false);
  expect(screen.getByLabelText('Local access credential')).not.toBeVisible();
  expect(screen.getByRole('button', { name: 'Sign out' })).toBeVisible();
  expect(fetcher).toHaveBeenCalledTimes(1);
});

it('shows an unconfirmed sign-out result outside collapsed account settings', async () => {
  const pending = deferredResponse();
  const fetcher = vi
    .spyOn(globalThis, 'fetch')
    .mockImplementation(async (_input, init) =>
      init?.method === 'DELETE'
        ? pending.promise
        : Response.json({ ...signedIn, contextMode: 'PARTICIPANT' }),
    );
  const user = userEvent.setup();
  render(<LocalSessionSurface />);
  await screen.findByText('Organization workspace');
  await user.click(screen.getByRole('button', { name: 'Sign out' }));
  expect(screen.getByText('Security & workspace').closest('details')!.open).toBe(false);
  await act(async () => pending.resolve(Response.json({}, { status: 503 })));
  expect(
    screen.getByText(
      'Sign-out could not be confirmed. Reload the page to check your current session.',
    ),
  ).toBeVisible();
  expect(fetcher.mock.calls.filter(([, init]) => init?.method === 'DELETE')).toHaveLength(1);
});

it.each(methods)(
  'notifies private workflows around a %s session attempt without account data',
  async (method) => {
    const pending = deferredResponse();
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (_input, init) =>
      init?.method === method ? pending.promise : Response.json(signedIn),
    );
    const notifications: unknown[] = [];
    const listener = (event: Event) => notifications.push((event as CustomEvent).detail);
    window.addEventListener(sessionTransitionEvent, listener);
    try {
      render(<LocalSessionSurface compactAuthenticated={false} />);
      await startLocalMutation(method);
      expect(notifications).toHaveLength(1);
      expect(notifications[0]).toEqual({ phase: 'changing', nonce: expect.any(String) });
      await act(async () => pending.resolve(Response.json({}, { status: 503 })));
      expect(notifications).toHaveLength(2);
      expect(notifications[1]).toEqual({ phase: 'settled', nonce: expect.any(String) });
      expect(JSON.stringify(notifications)).not.toContain(signedIn.principalId);
      expect(JSON.parse(localStorage.getItem(sessionTransitionStorageKey)!)).toEqual(
        notifications[1],
      );
    } finally {
      window.removeEventListener(sessionTransitionEvent, listener);
    }
  },
);

it.each([undefined, '018f0000-0000-7000-8000-000000000999'])(
  'requests fresh OIDC authentication bound to the selected Participant (%s)',
  async (participantId) => {
    const fetchMock = vi
      .spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(Response.json({ enabled: true, authenticated: false }))
      .mockResolvedValueOnce(
        Response.json({
          authorizationUri: 'http://127.0.0.1:53006/authorize?state=opaque-state',
        }),
      );
    const assign = vi.fn();
    vi.stubGlobal('location', {
      pathname: '/configure/policies',
      search: '?tab=author',
      assign,
      reload: vi.fn(),
    });
    const user = userEvent.setup();
    render(<LocalSessionSurface compactAuthenticated={false} participantId={participantId} />);

    await screen.findByRole('heading', { name: 'Account & workspace' });
    expect(
      screen.getByText(
        'Leave blank for normal sign-in. This is the Participant ID, not the user/principal ID.',
      ),
    ).toBeVisible();
    await user.click(screen.getByLabelText('Require fresh authentication after account recovery'));
    await user.click(screen.getByRole('button', { name: /^(Sign in|Switch account)$/ }));

    await waitFor(() => expect(assign).toHaveBeenCalledTimes(1));
    expect(fetchMock).toHaveBeenNthCalledWith(2, '/api/v1/ui/oidc-session', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        returnPath: '/configure/policies?tab=author',
        ...(participantId ? { participantId } : {}),
        freshAuthentication: true,
      }),
    });
    expect(assign).toHaveBeenCalledWith('http://127.0.0.1:53006/authorize?state=opaque-state');
  },
);

it('keeps the generated development credential flow explicitly separate', async () => {
  const fetchMock = vi
    .spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(Response.json({ enabled: true, authenticated: false }))
    .mockResolvedValueOnce(Response.json({ status: 'authenticated', role: 'viewer' }));
  const reload = vi.fn();
  vi.stubGlobal('location', { pathname: '/', search: '', assign: vi.fn(), reload });
  const user = userEvent.setup();
  render(<LocalSessionSurface compactAuthenticated={false} />);

  await screen.findByRole('heading', { name: 'Account & workspace' });
  await user.selectOptions(screen.getByLabelText('Account role'), 'viewer');
  await user.type(screen.getByLabelText('Local access credential'), 'generated-secret');
  await user.click(screen.getByRole('button', { name: 'Sign in with local credential' }));

  await waitFor(() => expect(reload).toHaveBeenCalledTimes(1));
  expect(fetchMock).toHaveBeenNthCalledWith(2, '/api/v1/ui/local-session', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ role: 'viewer', credential: 'generated-secret' }),
  });
});

it('keeps fresh sign-in on the authenticated profile and identifies the actual account', async () => {
  vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(
    Response.json({
      enabled: true,
      authenticated: true,
      role: 'viewer',
      sessionId: '018f0000-0000-7000-8000-000000000701',
      principalId: '018f0000-0000-7000-8000-000000000112',
      participantId: '018f0000-0000-7000-8000-000000000101',
      contextMode: 'PLATFORM',
      contextEpoch: '2',
      privacyDomainId: '018f0000-0000-7000-8000-000000000201',
      availableContexts: [],
    }),
  );
  render(<LocalSessionSurface compactAuthenticated={false} />);
  await screen.findByText('Signed-in account: 018f0000-0000-7000-8000-000000000112');
  expect(screen.getByLabelText('Account role')).toHaveValue('viewer');
});

it.each(['PLATFORM', 'PARTICIPANT'])(
  'keeps server-advertised privacy contexts selectable from a %s session',
  async (contextMode) => {
    const participantId = '018f0000-0000-7000-8000-000000000101';
    const privacyDomainId = '018f0000-0000-7000-8000-000000007201';
    const fetcher = vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(
      Response.json({
        enabled: true,
        authenticated: true,
        role: 'viewer',
        sessionId: '018f0000-0000-7000-8000-000000000701',
        principalId: '018f0000-0000-7000-8000-000000000112',
        participantId,
        contextMode,
        contextEpoch: '2',
        privacyDomainId: contextMode === 'PARTICIPANT' ? privacyDomainId : undefined,
        availableContexts: [{ participantId, privacyDomainId }],
      }),
    );
    const user = userEvent.setup();
    render(<LocalSessionSurface compactAuthenticated={false} />);
    const choices = await screen.findByRole('combobox', { name: 'Organization workspace' });
    const enter = screen.getByRole('button', {
      name:
        contextMode === 'PARTICIPANT' ? 'Verify and renew session' : 'Verify and enter workspace',
    });
    expect(screen.getByRole('button', { name: 'Sign out' })).toBeEnabled();
    expect(choices).toHaveValue(privacyDomainId);
    expect(enter).toBeEnabled();
    expect(fetcher).toHaveBeenCalledTimes(1);
    expect(choices.querySelectorAll('option')).toHaveLength(2);
    await user.selectOptions(choices, '');
    expect(enter).toBeDisabled();
    await user.selectOptions(choices, privacyDomainId);
    expect(enter).toBeEnabled();
    expect(fetcher).toHaveBeenCalledTimes(1);
  },
);

it('binds a manually selected QA Participant and named account before OIDC redirect', async () => {
  const fetchMock = vi
    .spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(Response.json({ enabled: true, authenticated: false }))
    .mockResolvedValueOnce(
      Response.json({ authorizationUri: 'http://127.0.0.1:53006/authorize?state=opaque' }),
    );
  vi.stubGlobal('location', {
    pathname: '/configure/policies',
    search: '',
    assign: vi.fn(),
    reload: vi.fn(),
  });
  const user = userEvent.setup();
  render(<LocalSessionSurface compactAuthenticated={false} />);
  await screen.findByRole('heading', { name: 'Account & workspace' });
  await user.type(
    screen.getByLabelText('Expected Participant/organization ID (optional)'),
    '018f0000-0000-7000-8000-000000000102',
  );
  await user.type(screen.getByLabelText('OIDC account hint (optional)'), 'qa-b-checker');
  await user.click(screen.getByRole('button', { name: /^(Sign in|Switch account)$/ }));
  await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(2));
  expect(JSON.parse(String(fetchMock.mock.calls[1]?.[1]?.body))).toMatchObject({
    participantId: '018f0000-0000-7000-8000-000000000102',
    loginHint: 'qa-b-checker',
  });
});

it('allows only one OIDC begin request while navigation is pending', async () => {
  let finishBegin: ((response: Response) => void) | undefined;
  const begin = new Promise<Response>((resolve) => {
    finishBegin = resolve;
  });
  const fetchMock = vi
    .spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(Response.json({ enabled: true, authenticated: false }))
    .mockReturnValueOnce(begin);
  const assign = vi.fn();
  vi.stubGlobal('location', {
    pathname: '/home/session',
    search: '',
    hash: '',
    assign,
    reload: vi.fn(),
  });
  render(<LocalSessionSurface compactAuthenticated={false} />);

  const button = await screen.findByRole('button', { name: /^(Sign in|Switch account)$/ });
  fireEvent.click(button);
  fireEvent.click(button);

  expect(fetchMock).toHaveBeenCalledTimes(2);
  expect(await screen.findByRole('button', { name: 'Starting sign-in…' })).toBeDisabled();
  finishBegin?.(
    Response.json({ authorizationUri: 'http://127.0.0.1:53006/authorize?state=opaque' }),
  );
  await waitFor(() => expect(assign).toHaveBeenCalledTimes(1));
  expect(fetchMock).toHaveBeenCalledTimes(2);
});

it('restores OIDC controls when begin fails', async () => {
  vi.spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(Response.json({ enabled: true, authenticated: false }))
    .mockResolvedValueOnce(Response.json({}, { status: 503 }));
  vi.stubGlobal('location', {
    pathname: '/home/session',
    search: '',
    hash: '',
    assign: vi.fn(),
    reload: vi.fn(),
  });
  const user = userEvent.setup();
  render(<LocalSessionSurface compactAuthenticated={false} />);

  await user.click(await screen.findByRole('button', { name: /^(Sign in|Switch account)$/ }));
  expect(
    await screen.findByText(
      'Sign-in could not be started. Try again or contact your administrator.',
    ),
  ).toBeVisible();
  expect(screen.getByRole('button', { name: /^(Sign in|Switch account)$/ })).toBeEnabled();
  expect(screen.getByLabelText('Expected Participant/organization ID (optional)')).toBeEnabled();
});

it('shows a callback failure once and removes its URL marker', async () => {
  vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(
    Response.json({ enabled: true, authenticated: false }),
  );
  const replaceState = vi.spyOn(window.history, 'replaceState').mockImplementation(() => undefined);
  vi.stubGlobal('location', {
    pathname: '/home/session',
    search: '?view=groups&oidcError=authentication_failed',
    hash: '#login',
    assign: vi.fn(),
    reload: vi.fn(),
  });
  render(<LocalSessionSurface compactAuthenticated={false} />);

  expect(
    await screen.findByText(
      'Sign-in failed. Start a new attempt. Leave the Participant field blank unless you are intentionally restricting sign-in to a known Participant ID.',
    ),
  ).toBeVisible();
  expect(replaceState).toHaveBeenCalledWith(null, '', '/home/session?view=groups#login');
});

it.each([
  'non-success carrying authenticated flags',
  'network',
  'invalid JSON',
  'flags without session',
  'invalid enabled type',
  'missing authenticated flag',
  'invalid role',
])('keeps authentication and enrollment unavailable after %s status', async (failure) => {
  const pending = deferredResponse();
  const fetch = vi.spyOn(globalThis, 'fetch').mockReturnValueOnce(pending.promise);
  render(<LocalSessionSurface compactAuthenticated={false} />);
  await act(async () => {
    if (failure === 'network') pending.reject(new Error('SECRET status exception'));
    else if (failure === 'invalid JSON') pending.resolve(new Response('SECRET invalid JSON'));
    else
      pending.resolve(
        Response.json(
          failure === 'flags without session'
            ? { enabled: true, authenticated: true, role: 'viewer' }
            : failure === 'invalid enabled type'
              ? { ...signedIn, enabled: 'true' }
              : failure === 'missing authenticated flag'
                ? { enabled: true }
                : failure === 'invalid role'
                  ? { ...signedIn, role: 'administrator' }
                  : signedIn,
          { status: failure === 'non-success carrying authenticated flags' ? 503 : 200 },
        ),
      );
  });
  expect(screen.queryByRole('heading', { name: 'Account & workspace' })).toBeNull();
  expect(screen.queryByRole('button', { name: 'Sign out' })).toBeNull();
  expect(screen.queryByText(/Signed-in account|SECRET/u)).toBeNull();
  expect(screen.queryByRole('combobox', { name: 'Organization workspace' })).toBeNull();
  expect(fetch).toHaveBeenCalledTimes(1);
});

it.each(['success', 'failure'])(
  'aborts an obsolete initial status and ignores its late %s',
  async (outcome) => {
    const old = deferredResponse();
    const fetch = vi
      .spyOn(globalThis, 'fetch')
      .mockReturnValueOnce(old.promise)
      .mockResolvedValueOnce(Response.json(signedIn));
    const view = render(
      <LocalSessionSurface compactAuthenticated={false} participantId="original-selection" />,
    );
    const signal = fetch.mock.calls[0]?.[1]?.signal;
    view.rerender(
      <LocalSessionSurface compactAuthenticated={false} participantId="next-selection" />,
    );
    await screen.findByText(`Signed-in account: ${signedIn.principalId}`);
    expect(signal?.aborted).toBe(true);
    await act(async () =>
      outcome === 'success'
        ? old.resolve(
            Response.json({
              ...signedIn,
              role: 'operator',
              principalId: '018f0000-0000-7000-8000-000000000113',
            }),
          )
        : old.reject(new Error('SECRET obsolete status failure')),
    );
    expect(screen.getByText(`Signed-in account: ${signedIn.principalId}`)).toBeVisible();
    expect(screen.getByLabelText('Account role')).toHaveValue('viewer');
    expect(screen.queryByText(/000000000113|SECRET/u)).toBeNull();
    expect(fetch).toHaveBeenCalledTimes(2);
  },
);

it('uses only the current initial status during StrictMode effect replay', async () => {
  const old = deferredResponse();
  const fetch = vi
    .spyOn(globalThis, 'fetch')
    .mockReturnValueOnce(old.promise)
    .mockResolvedValueOnce(Response.json({ enabled: true, authenticated: false }));
  render(
    <StrictMode>
      <LocalSessionSurface compactAuthenticated={false} />
    </StrictMode>,
  );
  await screen.findByRole('heading', { name: 'Account & workspace' });
  expect(fetch.mock.calls[0]?.[1]?.signal?.aborted).toBe(true);
  await act(async () => old.resolve(Response.json(signedIn)));
  expect(screen.queryByRole('button', { name: 'Sign out' })).toBeNull();
  expect(screen.queryByText(/Signed-in account/u)).toBeNull();
  expect(fetch).toHaveBeenCalledTimes(2);
});

it.each(['success', 'failure'])(
  'aborts an unmounted initial status and ignores late %s',
  async (outcome) => {
    const old = deferredResponse();
    const fetch = vi.spyOn(globalThis, 'fetch').mockReturnValueOnce(old.promise);
    const view = render(<LocalSessionSurface compactAuthenticated={false} />);
    const signal = fetch.mock.calls[0]?.[1]?.signal;
    view.unmount();
    expect(signal?.aborted).toBe(true);
    await act(async () =>
      outcome === 'success'
        ? old.resolve(Response.json(signedIn))
        : old.reject(new Error('SECRET unmounted status failure')),
    );
    expect(screen.queryByText(/Signed-in account|SECRET/u)).toBeNull();
    expect(fetch).toHaveBeenCalledTimes(1);
  },
);

it.each([
  ...methods.flatMap((method) =>
    [
      'network',
      'response',
      'malformed success',
      'foreign binding',
      'non-success effect',
      'empty success',
      'invalid JSON success',
    ].map((failure) => ({ method, failure })),
  ),
  ...(['DELETE', 'PATCH'] as const).map((method) => ({ method, failure: 'wrong action' })),
])(
  'retains custody after $method $failure without replay or reload',
  async ({ method, failure }) => {
    saveCustody();
    const pending = deferredResponse();
    const fetch = vi
      .spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(Response.json(signedIn))
      .mockReturnValueOnce(pending.promise);
    const reload = vi.fn();
    vi.stubGlobal('location', { pathname: '/', search: '', assign: vi.fn(), reload });
    render(<LocalSessionSurface compactAuthenticated={false} />);
    await startLocalMutation(method);
    expect(screen.getByRole('button', { name: actionName(method) })).toBeDisabled();
    await act(async () => {
      if (failure === 'network') pending.reject(new Error('SECRET local mutation exception'));
      else if (failure === 'empty success') pending.resolve(new Response(null, { status: 204 }));
      else if (failure === 'invalid JSON success')
        pending.resolve(new Response('SECRET invalid JSON'));
      else {
        const valid = mutationResult(method);
        pending.resolve(
          Response.json(
            failure === 'response'
              ? { ...valid, title: 'SECRET mutation title', code: 'SECRET mutation code' }
              : failure === 'malformed success'
                ? {}
                : failure === 'foreign binding'
                  ? method === 'POST'
                    ? { ...valid, role: 'operator' }
                    : {
                        ...valid,
                        resourceRef: 'urn:openpc:resource:018f0000-0000-7000-8000-000000000999',
                      }
                  : failure === 'wrong action'
                    ? {
                        ...valid,
                        actionIntentId:
                          method === 'DELETE'
                            ? 'ACT-IDENTITY_CREATE_SESSION-V1'
                            : 'ACT-IDENTITY_DELETE_SESSION-V1',
                      }
                    : method === 'POST'
                      ? { ...valid, status: 'requested' }
                      : { ...valid, state: 'ACCEPTED' },
            { status: failure === 'response' ? 503 : 200 },
          ),
        );
      }
    });
    expect(
      screen.getByText(
        method === 'POST'
          ? 'Sign-in could not be confirmed. Reload the page to check your current session.'
          : `${method === 'DELETE' ? 'Sign-out' : 'Session refresh'} could not be confirmed. Reload the page to check your current session.`,
      ),
    ).toBeVisible();
    expect(screen.queryByText(/SECRET/u)).toBeNull();
    expect(screen.getByRole('button', { name: actionName(method) })).toBeEnabled();
    expectCustody();
    expect(reload).not.toHaveBeenCalled();
    expect(fetch).toHaveBeenCalledTimes(2);
    expect(fetch.mock.calls[1]?.[0]).toBe('/api/v1/ui/local-session');
    expect(fetch.mock.calls[1]?.[1]).toEqual(
      method === 'POST'
        ? {
            method,
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ role: 'viewer', credential: 'generated-secret' }),
          }
        : { method },
    );
  },
);

it.each(methods)('preserves the successful %s custody and reload sequence', async (method) => {
  saveCustody();
  const pending = deferredResponse();
  const fetch = vi
    .spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(Response.json(signedIn))
    .mockReturnValueOnce(pending.promise);
  const reload = vi.fn(() => ({
    custody: clearedKeys.map((key) => localStorage.getItem(key)),
    firstAdmin: sessionStorage.getItem('openpc:first-admin-review'),
    protected: localStorage.getItem(protectedKey),
  }));
  vi.stubGlobal('location', { pathname: '/', search: '', assign: vi.fn(), reload });
  render(<LocalSessionSurface compactAuthenticated={false} />);
  await startLocalMutation(method);
  expectCustody();
  await act(async () => pending.resolve(Response.json(mutationResult(method))));
  expect(reload).toHaveBeenCalledTimes(1);
  expect(reload.mock.results[0]?.value).toEqual({
    custody: clearedKeys.map((key) => (method === 'POST' ? `original:${key}` : null)),
    firstAdmin: method === 'POST' ? 'first-original-ciphertext' : null,
    protected: `original:${protectedKey}`,
  });
  expect(fetch).toHaveBeenCalledTimes(2);
});

it.each(methods)('serializes %s with all other local and OIDC requests', async (method) => {
  const pending = deferredResponse();
  const fetch = vi
    .spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(Response.json(signedIn))
    .mockReturnValueOnce(pending.promise);
  render(<LocalSessionSurface compactAuthenticated={false} />);
  await startLocalMutation(method);
  for (const other of methods)
    fireEvent.click(screen.getByRole('button', { name: actionName(other) }));
  fireEvent.click(screen.getByRole('button', { name: /^(Sign in|Switch account)$/ }));
  fireEvent.submit(screen.getByRole('button', { name: actionName('POST') }).closest('form')!);
  expect(fetch).toHaveBeenCalledTimes(2);
  await act(async () => pending.reject(new Error('SECRET pending local failure')));
  expect(screen.getByRole('button', { name: /^(Sign in|Switch account)$/ })).toBeEnabled();
  expect(fetch).toHaveBeenCalledTimes(2);
});

it.each(
  methods.flatMap((method) => ['success', 'failure'].map((outcome) => ({ method, outcome }))),
)(
  'ignores late $method $outcome after unmount without clearing custody',
  async ({ method, outcome }) => {
    saveCustody();
    const pending = deferredResponse();
    const fetch = vi
      .spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(Response.json(signedIn))
      .mockReturnValueOnce(pending.promise);
    const reload = vi.fn();
    vi.stubGlobal('location', { pathname: '/', search: '', assign: vi.fn(), reload });
    const view = render(<LocalSessionSurface compactAuthenticated={false} />);
    await startLocalMutation(method);
    view.unmount();
    await act(async () =>
      outcome === 'success'
        ? pending.resolve(Response.json(mutationResult(method)))
        : pending.reject(new Error('SECRET unmounted local failure')),
    );
    expectCustody();
    expect(reload).not.toHaveBeenCalled();
    expect(fetch).toHaveBeenCalledTimes(2);
  },
);

it.each(methods)('keeps a new selection concealed until its pending %s settles', async (method) => {
  saveCustody();
  const pending = deferredResponse();
  const next = {
    ...signedIn,
    sessionId: '018f0000-0000-7000-8000-000000000702',
    principalId: '018f0000-0000-7000-8000-000000000113',
    role: 'operator',
  };
  const fetch = vi
    .spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(Response.json(signedIn))
    .mockReturnValueOnce(pending.promise)
    .mockImplementation(async () => Response.json(next));
  const reload = vi.fn();
  vi.stubGlobal('location', { pathname: '/', search: '', assign: vi.fn(), reload });
  const view = render(
    <LocalSessionSurface compactAuthenticated={false} participantId="original-selection" />,
  );
  await startLocalMutation(method);
  view.rerender(
    <LocalSessionSurface compactAuthenticated={false} participantId="next-selection" />,
  );
  expect(screen.queryByRole('button', { name: 'Sign out' })).toBeNull();
  await act(async () => {});
  expect(screen.queryByRole('button', { name: 'Sign out' })).toBeNull();
  await act(async () => pending.resolve(Response.json(mutationResult(method))));
  await screen.findByText(`Signed-in account: ${next.principalId}`);
  expect(screen.getByText(`Signed-in account: ${next.principalId}`)).toBeVisible();
  expect(screen.getByLabelText('Account role')).toHaveValue('operator');
  expect(screen.queryByText(/Signing in to|Revoking|Rotating/u)).toBeNull();
  expectCustody();
  expect(reload).not.toHaveBeenCalled();
  expect(fetch).toHaveBeenCalledTimes(4);
  expect(fetch.mock.calls.filter(([, init]) => init?.method === method)).toHaveLength(1);
});

it('conceals the previous account at a cross-tab transition and reads the native session again', async () => {
  const next = {
    ...signedIn,
    sessionId: '018f0000-0000-7000-8000-000000000702',
    principalId: '018f0000-0000-7000-8000-000000000113',
    contextEpoch: '3',
  };
  const pending = deferredResponse();
  const fetcher = vi
    .spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(Response.json(signedIn))
    .mockReturnValueOnce(pending.promise);
  render(<LocalSessionSurface compactAuthenticated={false} />);
  await screen.findByText(`Signed-in account: ${signedIn.principalId}`);
  fireEvent.change(screen.getByLabelText('Local access credential'), {
    target: { value: 'old-account-secret' },
  });
  act(() =>
    window.dispatchEvent(
      new StorageEvent('storage', {
        key: sessionTransitionStorageKey,
        newValue: JSON.stringify({ phase: 'changing', nonce: 'notification-only' }),
      }),
    ),
  );
  expect(screen.getByText(`Signed-in account: ${signedIn.principalId}`)).not.toBeVisible();
  expect(screen.queryByRole('button', { name: 'Sign out' })).toBeNull();
  expect(screen.getByLabelText('Local access credential')).toHaveValue('');
  act(() =>
    window.dispatchEvent(
      new StorageEvent('storage', {
        key: sessionTransitionStorageKey,
        newValue: JSON.stringify({ phase: 'settled', nonce: 'notification-only' }),
      }),
    ),
  );
  await act(async () => pending.resolve(Response.json(next)));
  expect(screen.getByText(`Signed-in account: ${next.principalId}`)).toBeVisible();
  expect(fetcher).toHaveBeenCalledTimes(2);
  expect(fetcher.mock.calls.every(([, init]) => !init?.method)).toBe(true);
});

it('preserves same-account unsent settings while focus revalidation hides private controls', async () => {
  const pending = deferredResponse();
  vi.spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(Response.json(signedIn))
    .mockReturnValueOnce(pending.promise);
  const user = userEvent.setup();
  render(<LocalSessionSurface />);
  await screen.findByText('Platform workspace');
  await user.click(screen.getByText('Account settings'));
  await user.click(screen.getByText('Sign-in options'));
  const hint = screen.getByLabelText('OIDC account hint (optional)');
  await user.type(hint, 'unsent-account-hint');
  fireEvent.focus(window);
  expect(hint).not.toBeVisible();
  expect(screen.queryByRole('button', { name: 'Sign out' })).toBeNull();
  await act(async () => pending.resolve(Response.json(signedIn)));
  expect(screen.getByLabelText('OIDC account hint (optional)')).toBe(hint);
  expect(hint).toHaveValue('unsent-account-hint');
  expect(hint).toBeVisible();
});

it('ignores an older focus completion while a newer native read is still pending', async () => {
  const old = deferredResponse(),
    newest = deferredResponse();
  const fetcher = vi
    .spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(Response.json(signedIn))
    .mockReturnValueOnce(old.promise)
    .mockReturnValueOnce(newest.promise);
  render(<LocalSessionSurface compactAuthenticated={false} />);
  await screen.findByText(`Signed-in account: ${signedIn.principalId}`);
  fireEvent.focus(window);
  const signal = fetcher.mock.calls[1]![1]!.signal;
  fireEvent.focus(window);
  expect(signal?.aborted).toBe(true);
  await act(async () => old.resolve(Response.json(signedIn)));
  expect(screen.getByText(`Signed-in account: ${signedIn.principalId}`)).not.toBeVisible();
  expect(screen.queryByRole('button', { name: 'Sign out' })).toBeNull();
  await act(async () => newest.resolve(Response.json({ enabled: true, authenticated: false })));
  expect(screen.queryByText(`Signed-in account: ${signedIn.principalId}`)).toBeNull();
  expect(screen.getByRole('button', { name: 'Sign in' })).toBeEnabled();
});

it.each(methods)(
  'does not replay or clear custody for a late %s result after focus changes the account',
  async (method) => {
    saveCustody();
    const pending = deferredResponse();
    const next = {
      ...signedIn,
      sessionId: '018f0000-0000-7000-8000-000000000702',
      principalId: '018f0000-0000-7000-8000-000000000113',
      contextEpoch: '3',
    };
    const fetcher = vi
      .spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(Response.json(signedIn))
      .mockReturnValueOnce(pending.promise)
      .mockResolvedValueOnce(Response.json(next))
      .mockImplementation(async () => Response.json(next));
    const reload = vi.fn();
    vi.stubGlobal('location', { pathname: '/', search: '', assign: vi.fn(), reload });
    render(<LocalSessionSurface compactAuthenticated={false} />);
    await startLocalMutation(method);
    expect(fetcher.mock.calls[1]![1]?.signal).toBeUndefined();
    fireEvent.focus(window);
    await screen.findByText(`Signed-in account: ${next.principalId}`);
    await act(async () => pending.resolve(Response.json(mutationResult(method))));
    expect(screen.getByText(`Signed-in account: ${next.principalId}`)).toBeVisible();
    expectCustody();
    expect(reload).not.toHaveBeenCalled();
    expect(fetcher.mock.calls.filter(([, init]) => init?.method === method)).toHaveLength(1);
  },
);

it.each(['malformed notification', 'malformed session'])(
  'fails closed after %s without keeping stale account controls',
  async (failure) => {
    vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(Response.json(signedIn))
      .mockResolvedValueOnce(Response.json({ ...signedIn, contextEpoch: '0' }));
    render(<LocalSessionSurface compactAuthenticated={false} />);
    await screen.findByText(`Signed-in account: ${signedIn.principalId}`);
    if (failure === 'malformed notification')
      act(() =>
        window.dispatchEvent(
          new StorageEvent('storage', { key: sessionTransitionStorageKey, newValue: '{broken' }),
        ),
      );
    else fireEvent.focus(window);
    await screen.findByRole('button', { name: 'Retry session check' });
    expect(screen.getByText(`Signed-in account: ${signedIn.principalId}`)).not.toBeVisible();
    expect(screen.queryByRole('button', { name: 'Sign out' })).toBeNull();
  },
);

it('keeps a changing transition concealed after focus returns an unchanged native session', async () => {
  const native = vi
    .spyOn(globalThis, 'fetch')
    .mockImplementation(async () => Response.json(signedIn));
  render(<LocalSessionSurface compactAuthenticated={false} />);
  await screen.findByText(`Signed-in account: ${signedIn.principalId}`);
  let owner: string | undefined;
  act(() => {
    owner = notifySessionTransition('changing');
  });
  fireEvent.focus(window);
  await waitFor(() => expect(native).toHaveBeenCalledTimes(2));
  expect(screen.getByText(`Signed-in account: ${signedIn.principalId}`)).not.toBeVisible();
  expect(screen.queryByRole('button', { name: 'Sign out' })).toBeNull();
  act(() => {
    notifySessionTransition('settled', owner);
  });
  await waitFor(() =>
    expect(screen.getByText(`Signed-in account: ${signedIn.principalId}`)).toBeVisible(),
  );
});

it('does not let an older request settle a newer account transition', async () => {
  saveCustody();
  const pending = deferredResponse();
  let native = signedIn;
  const fetcher = vi
    .spyOn(globalThis, 'fetch')
    .mockImplementation(async (_, init) =>
      init?.method === 'DELETE' ? pending.promise : Response.json(native),
    );
  const reload = vi.fn();
  vi.stubGlobal('location', { pathname: '/', search: '', reload });
  const notifications: { phase: string; nonce: string }[] = [];
  const listener = (event: Event) => notifications.push((event as CustomEvent).detail);
  window.addEventListener(sessionTransitionEvent, listener);
  try {
    render(<LocalSessionSurface compactAuthenticated={false} />);
    await startLocalMutation('DELETE');
    let newer: string | undefined;
    act(() => {
      newer = notifySessionTransition('changing');
    });
    await act(async () => pending.resolve(Response.json(mutationResult('DELETE'))));
    expect(notifications.map((value) => value.phase)).toEqual(['changing', 'changing']);
    fireEvent.focus(window);
    await waitFor(() => expect(fetcher.mock.calls.length).toBeGreaterThan(2));
    expect(screen.getByText(`Signed-in account: ${signedIn.principalId}`)).not.toBeVisible();
    expectCustody();
    expect(reload).not.toHaveBeenCalled();
    native = {
      ...signedIn,
      sessionId: '018f0000-0000-7000-8000-000000000702',
      principalId: '018f0000-0000-7000-8000-000000000113',
    };
    act(() => {
      notifySessionTransition('settled', newer);
    });
    await screen.findByText(`Signed-in account: ${native.principalId}`);
    expect(notifications.at(-1)?.nonce).toBe(newer);
    expect(fetcher.mock.calls.filter(([, init]) => init?.method === 'DELETE')).toHaveLength(1);
  } finally {
    window.removeEventListener(sessionTransitionEvent, listener);
  }
});

it('retains an in-progress authenticator registration through a temporary focus failure', async () => {
  const options = deferredResponse();
  let unavailable = false;
  const fetcher = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
    if (String(input).includes('initial-registration/options')) return options.promise;
    return unavailable ? Response.json({}, { status: 503 }) : Response.json(signedIn);
  });
  const user = userEvent.setup();
  render(<LocalSessionSurface />);
  await screen.findByText('Platform workspace');
  await user.click(screen.getByText('Account settings'));
  await user.click(screen.getByText('Security & workspace'));
  const register = screen.getByRole('button', { name: 'Register authenticator' });
  await user.click(register);
  expect(register).toBeDisabled();
  unavailable = true;
  fireEvent.focus(window);
  await screen.findByRole('button', { name: 'Retry session check' });
  expect(register).not.toBeVisible();
  unavailable = false;
  await user.click(screen.getByRole('button', { name: 'Retry session check' }));
  await waitFor(() => expect(register).toBeVisible());
  expect(screen.getByRole('button', { name: 'Register authenticator' })).toBe(register);
  expect(register).toBeDisabled();
  expect(screen.getByText('Follow your browser’s authenticator prompt.')).toBeVisible();
  await act(async () => options.resolve(Response.json({}, { status: 503 })));
  expect(register).toBeEnabled();
  expect(
    fetcher.mock.calls.filter(([input]) => String(input).includes('initial-registration/options')),
  ).toHaveLength(1);
});

it('keeps retry readback concealed until an unfinished context transition settles', async () => {
  let fail = false;
  vi.spyOn(globalThis, 'fetch').mockImplementation(async () =>
    fail ? Response.json({}, { status: 503 }) : Response.json(signedIn),
  );
  const user = userEvent.setup();
  render(<LocalSessionSurface compactAuthenticated={false} />);
  await screen.findByText(`Signed-in account: ${signedIn.principalId}`);
  let owner: string | undefined;
  act(() => {
    owner = notifySessionTransition('changing');
  });
  fail = true;
  fireEvent.focus(window);
  await screen.findByRole('button', { name: 'Retry session check' });
  fail = false;
  await user.click(screen.getByRole('button', { name: 'Retry session check' }));
  await waitFor(() =>
    expect(screen.queryByRole('button', { name: 'Retry session check' })).toBeNull(),
  );
  expect(screen.getByText(`Signed-in account: ${signedIn.principalId}`)).not.toBeVisible();
  expect(screen.queryByRole('button', { name: 'Sign out' })).toBeNull();
  act(() => {
    notifySessionTransition('settled', owner);
  });
  await waitFor(() => expect(screen.getByRole('button', { name: 'Sign out' })).toBeVisible());
});

it('uses one account menu in a central workspace and suppresses embedded sign-in panels', async () => {
  vi.spyOn(globalThis, 'fetch').mockResolvedValue(Response.json(signedIn));
  const { CentralSessionContext } = await import('./central-session-context');
  render(
    <CentralSessionContext.Provider value={true}>
      <LocalSessionSurface />
      <LocalSessionSurface appearance="menu" />
    </CentralSessionContext.Provider>,
  );
  await screen.findByText('Account');
  fireEvent.click(screen.getByText('Account'));
  expect(screen.getAllByRole('button', { name: 'Sign out' })).toHaveLength(1);
  expect(screen.queryByRole('button', { name: 'Sign in' })).toBeNull();
  expect(screen.queryByText('Local account sign-in')).toBeNull();
  expect(screen.queryByText('Sign-in options')).toBeNull();
});

it('dismisses the central account menu without changing the authenticated session', async () => {
  const fetcher = vi.spyOn(globalThis, 'fetch').mockResolvedValue(Response.json(signedIn));
  const { CentralSessionContext } = await import('./central-session-context');
  const user = userEvent.setup();
  render(
    <CentralSessionContext.Provider value={true}>
      <LocalSessionSurface appearance="menu" />
    </CentralSessionContext.Provider>,
  );
  const toggle = await screen.findByText('Account', { exact: true });
  await user.click(toggle);
  screen.getByRole('link', { name: 'Account & security' }).focus();
  await user.keyboard('{Escape}');
  expect(screen.getByText('Sign out', { exact: true })).not.toBeVisible();
  expect(toggle.closest('details')).toHaveProperty('open', false);
  expect(toggle).toHaveFocus();
  expect(fetcher.mock.calls.every(([, init]) => !init?.method)).toBe(true);
});
