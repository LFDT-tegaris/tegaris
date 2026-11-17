import { webcrypto } from 'node:crypto';
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { performWebAuthnStepUp } from '@openpc/ui-shell';
import { AuthenticatorEnrollment } from './authenticator-enrollment';
import { LocalSessionSurface } from './local-session';
import { notifySessionTransition } from './session-transition';
import type { EnrollmentSession } from '../lib/authenticator-enrollment';

vi.mock('@openpc/ui-shell', async (original) => ({
  ...(await original<typeof import('@openpc/ui-shell')>()),
  performWebAuthnStepUp: vi.fn(),
}));

const session: EnrollmentSession = {
  authenticated: true,
  sessionId: '018f0000-0000-7000-8000-000000000701',
  principalId: '018f0000-0000-7000-8000-000000000112',
  participantId: '018f0000-0000-7000-8000-000000000101',
  privacyDomainId: '018f0000-0000-7000-8000-000000007201',
  contextMode: 'PARTICIPANT',
  availableContexts: [],
};
const replacement = {
  sessionId: '018f0000-0000-7000-8000-000000000702',
  participantId: session.participantId,
  privacyDomainId: session.privacyDomainId,
  contextMode: 'PARTICIPANT',
  contextEpoch: '3',
};
const nativeStatus = { ...session, enabled: true, role: 'viewer', contextEpoch: '2' };
const name = 'Verify and renew session';
const stepUp = vi.mocked(performWebAuthnStepUp);

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((yes) => {
    resolve = yes;
  });
  return { promise, resolve };
}

beforeEach(() => {
  vi.stubGlobal('crypto', webcrypto);
  vi.stubGlobal('location', { pathname: '/', search: '', reload: vi.fn() });
  stepUp.mockReset().mockResolvedValue(undefined);
});

afterEach(() => {
  cleanup();
  localStorage.clear();
  sessionStorage.clear();
  const owner = notifySessionTransition('changing');
  notifySessionTransition('settled', owner);
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

it('offers renewal for the authenticated Participant workspace even without discovery choices', () => {
  render(<AuthenticatorEnrollment session={session} />);
  expect(screen.getByRole('button', { name })).toBeEnabled();
  expect(screen.queryByRole('combobox', { name: 'Organization workspace' })).toBeNull();
  expect(screen.getByRole('heading', { name: 'Current workspace' })).toBeVisible();
  expect(screen.queryByRole('heading', { name: 'No organization workspace available' })).toBeNull();
  expect(screen.getByRole('button', { name: 'Copy Workspace reference' })).toBeEnabled();
  expect(screen.queryByRole('heading', { name: 'Verify your identity' })).toBeNull();
});

it('offers one neutral renewal action when discovery includes the current workspace', () => {
  const fetcher = vi.spyOn(globalThis, 'fetch');
  render(
    <AuthenticatorEnrollment
      session={{
        ...session,
        availableContexts: [
          { participantId: session.participantId, privacyDomainId: session.privacyDomainId! },
        ],
      }}
    />,
  );
  expect(screen.getByRole('button', { name })).toBeEnabled();
  expect(screen.queryByRole('button', { name: 'Verify and enter workspace' })).toBeNull();
  expect(screen.getByRole('combobox', { name: 'Organization workspace' })).toHaveValue(
    session.privacyDomainId,
  );
  expect(screen.getByRole('option', { name: 'Current workspace' })).toHaveValue(
    session.privacyDomainId,
  );
  expect(stepUp).not.toHaveBeenCalled();
  expect(fetcher).not.toHaveBeenCalled();
});

it('keeps the current workspace selected among alternatives until the user chooses another', async () => {
  const fetcher = vi.spyOn(globalThis, 'fetch');
  const alternative = session.principalId;
  render(
    <AuthenticatorEnrollment
      session={{
        ...session,
        availableContexts: [
          { participantId: session.participantId, privacyDomainId: alternative },
          { participantId: session.participantId, privacyDomainId: session.privacyDomainId! },
        ],
      }}
    />,
  );
  const select = screen.getByRole('combobox', { name: 'Organization workspace' });
  expect(select).toHaveValue(session.privacyDomainId);
  expect(screen.getByRole('option', { name: 'Current workspace · 000000007201' })).toHaveValue(
    session.privacyDomainId,
  );
  expect(screen.getByRole('button', { name })).toBeEnabled();
  await userEvent.selectOptions(select, alternative);
  expect(screen.getByRole('option', { name: 'Workspace · 000000000112' })).toHaveValue(alternative);
  expect(screen.getByText(alternative, { selector: 'code' })).toBeVisible();
  expect(screen.queryByText(session.privacyDomainId!, { selector: 'code' })).toBeNull();
  expect(screen.queryByRole('button', { name })).toBeNull();
  expect(screen.getByRole('button', { name: 'Verify and enter workspace' })).toBeEnabled();
  expect(stepUp).not.toHaveBeenCalled();
  expect(fetcher).not.toHaveBeenCalled();
});

it('keeps full workspace references when abbreviated choices would be ambiguous', () => {
  const alternative = '018f0000-0000-7000-8001-000000007201';
  render(
    <AuthenticatorEnrollment
      session={{
        ...session,
        availableContexts: [{ participantId: session.participantId, privacyDomainId: alternative }],
      }}
    />,
  );
  expect(
    screen.getByRole('option', { name: `Current workspace · ${session.privacyDomainId}` }),
  ).toHaveValue(session.privacyDomainId);
  expect(screen.getByRole('option', { name: `Workspace · ${alternative}` })).toHaveValue(
    alternative,
  );
  expect(stepUp).not.toHaveBeenCalled();
});

it('preserves current-workspace renewal when discovery lists only other workspaces', () => {
  render(
    <AuthenticatorEnrollment
      session={{
        ...session,
        availableContexts: [
          { participantId: session.participantId, privacyDomainId: session.principalId },
        ],
      }}
    />,
  );
  expect(screen.getByRole('combobox', { name: 'Organization workspace' })).toHaveValue(
    session.privacyDomainId,
  );
  expect(screen.getByRole('button', { name })).toBeEnabled();
  expect(stepUp).not.toHaveBeenCalled();
});

it.each([
  { ...session, contextMode: 'PLATFORM' as const },
  { ...session, privacyDomainId: undefined },
])('does not manufacture a current privacy workspace for %j', (current) => {
  const fetcher = vi.spyOn(globalThis, 'fetch');
  render(<AuthenticatorEnrollment session={current} />);
  expect(
    screen.getByRole('heading', { name: 'No organization workspace available' }),
  ).toBeVisible();
  expect(
    screen.getByText('Registering another authenticator does not grant workspace access.'),
  ).toBeVisible();
  expect(screen.queryByRole('button', { name })).toBeNull();
  expect(screen.queryByRole('button', { name: 'Verify and enter workspace' })).toBeNull();
  expect(fetcher).not.toHaveBeenCalled();
  expect(stepUp).not.toHaveBeenCalled();
});

it('labels workspace selection independently of its choices and verifies only the chosen context', async () => {
  const contexts = [
    { participantId: session.participantId, privacyDomainId: session.privacyDomainId! },
    { participantId: session.participantId, privacyDomainId: session.principalId },
  ];
  const fetcher = vi
    .spyOn(globalThis, 'fetch')
    .mockResolvedValue(Response.json(replacement, { status: 201 }));
  render(
    <AuthenticatorEnrollment
      session={{
        ...session,
        contextMode: 'PLATFORM',
        privacyDomainId: undefined,
        availableContexts: contexts,
      }}
    />,
  );
  const select = screen.getByRole('combobox', { name: 'Organization workspace' });
  expect(select).toHaveAccessibleName('Organization workspace');
  expect(select).toHaveValue('');
  expect(fetcher).not.toHaveBeenCalled();
  await userEvent.selectOptions(select, contexts[0]!.privacyDomainId);
  await userEvent.click(screen.getByRole('button', { name: 'Verify and enter workspace' }));
  await waitFor(() => expect(location.reload).toHaveBeenCalledTimes(1));
  expect(stepUp).toHaveBeenCalledTimes(1);
  expect(fetcher).toHaveBeenCalledTimes(1);
  expect(fetcher).toHaveBeenCalledWith(
    '/api/v1/ui/session/context',
    expect.objectContaining({
      method: 'POST',
      body: JSON.stringify({ ...contexts[0], expectedSessionId: session.sessionId }),
    }),
  );
});

it('selects the only authorized workspace after sign-in without starting verification', () => {
  const fetcher = vi.spyOn(globalThis, 'fetch');
  render(
    <AuthenticatorEnrollment
      session={{
        ...session,
        contextMode: 'PLATFORM',
        privacyDomainId: undefined,
        availableContexts: [
          { participantId: session.participantId, privacyDomainId: session.privacyDomainId! },
        ],
      }}
    />,
  );
  expect(screen.getByRole('combobox', { name: 'Organization workspace' })).toHaveValue(
    session.privacyDomainId,
  );
  expect(screen.getByRole('button', { name: 'Verify and enter workspace' })).toBeEnabled();
  expect(
    screen.getByText(
      'Use your existing authenticator to continue. For first-time registration, use the Authenticator registration panel.',
    ),
  ).toBeVisible();
  expect(stepUp).not.toHaveBeenCalled();
  expect(fetcher).not.toHaveBeenCalled();
});

it('explains why verification is disabled when a workspace must be chosen', () => {
  render(
    <AuthenticatorEnrollment
      session={{
        ...session,
        contextMode: 'PLATFORM',
        privacyDomainId: undefined,
        availableContexts: [
          { participantId: session.participantId, privacyDomainId: session.privacyDomainId! },
          { participantId: session.participantId, privacyDomainId: session.principalId },
        ],
      }}
    />,
  );
  expect(screen.getByRole('button', { name: 'Verify and enter workspace' })).toBeDisabled();
  expect(
    screen.getByRole('combobox', { name: 'Organization workspace' }),
  ).toHaveAccessibleDescription('Choose a workspace to enable verification.');
  expect(stepUp).not.toHaveBeenCalled();
});

it('denies an old selection when the account no longer has that workspace', async () => {
  const original = {
    ...session,
    contextMode: 'PLATFORM' as const,
    privacyDomainId: undefined,
    availableContexts: [
      { participantId: session.participantId, privacyDomainId: session.privacyDomainId! },
    ],
  };
  const view = render(<AuthenticatorEnrollment session={original} />);
  view.rerender(
    <AuthenticatorEnrollment
      session={{
        ...original,
        availableContexts: [
          { participantId: session.participantId, privacyDomainId: session.principalId },
        ],
      }}
    />,
  );
  const verify = screen.getByRole('button', { name: 'Verify and enter workspace' });
  expect(verify).toBeDisabled();
  await userEvent.click(verify);
  expect(stepUp).not.toHaveBeenCalled();
});

it('verifies the exact existing context and rotates only its original session once', async () => {
  const fetcher = vi
    .spyOn(globalThis, 'fetch')
    .mockResolvedValue(Response.json(replacement, { status: 201 }));
  render(<AuthenticatorEnrollment session={session} />);
  fireEvent.click(screen.getByRole('button', { name }));
  fireEvent.click(screen.getByRole('button', { name }));
  await waitFor(() => expect(location.reload).toHaveBeenCalledTimes(1));
  const context = {
    participantId: session.participantId,
    privacyDomainId: session.privacyDomainId,
  };
  const bytes = await webcrypto.subtle.digest(
    'SHA-256',
    new TextEncoder().encode(JSON.stringify(context)),
  );
  const digest =
    'sha256:' +
    Array.from(new Uint8Array(bytes), (byte) => byte.toString(16).padStart(2, '0')).join('');
  expect(stepUp).toHaveBeenCalledTimes(1);
  expect(stepUp).toHaveBeenCalledWith(
    {
      actionIntentId: 'ACT-IDENTITY_CREATE_SESSION-V1',
      actionIntentDigest: 'sha256:dbc8290dd60814d5bb4248fefc9550f43d0dc97d6333ac232c8ab8a98c3354d2',
      stepUp: 'FRESH_WEBAUTHN_MAX_5M',
    },
    { resourceId: session.participantId, resourceDigest: digest },
    {
      signal: expect.any(AbortSignal),
      isCurrent: expect.any(Function),
    },
  );
  expect(fetcher).toHaveBeenCalledTimes(1);
  expect(fetcher).toHaveBeenCalledWith(
    '/api/v1/ui/session/context',
    expect.objectContaining({
      method: 'POST',
      body: JSON.stringify({ ...context, expectedSessionId: session.sessionId }),
    }),
  );
});

it.each(['Challenge denied', 'Verification denied', 'The operation was cancelled.'])(
  'does not rotate or reload after security-key failure: %s',
  async (message) => {
    stepUp.mockRejectedValueOnce(new Error(message));
    const fetcher = vi.spyOn(globalThis, 'fetch');
    render(<AuthenticatorEnrollment session={session} />);
    await userEvent.click(screen.getByRole('button', { name }));
    await screen.findByText(message);
    expect(fetcher).not.toHaveBeenCalled();
    expect(location.reload).not.toHaveBeenCalled();
  },
);

it.each([
  { status: 403, body: {} },
  { status: 200, body: replacement },
  { status: 201, body: {} },
  { status: 201, body: { ...replacement, sessionId: session.sessionId } },
  { status: 201, body: { ...replacement, participantId: session.principalId } },
  { status: 201, body: { ...replacement, privacyDomainId: session.principalId } },
])(
  'retains a safe unconfirmed state for a $status response without replay',
  async ({ status, body }) => {
    const fetcher = vi
      .spyOn(globalThis, 'fetch')
      .mockResolvedValue(Response.json(body, { status }));
    render(<AuthenticatorEnrollment session={session} />);
    await userEvent.click(screen.getByRole('button', { name }));
    await screen.findByText(/could not be confirmed|Context selection was not confirmed/);
    expect(fetcher).toHaveBeenCalledTimes(1);
    expect(location.reload).not.toHaveBeenCalled();
  },
);

it.each(['unmount', 'session changed', 'another tab changes the account'])(
  'cancels a held security-key operation after %s without continuing it',
  async (event) => {
    const pending = deferred<void>();
    stepUp.mockReturnValueOnce(pending.promise);
    const fetcher = vi.spyOn(globalThis, 'fetch');
    const view = render(<AuthenticatorEnrollment session={session} />);
    await userEvent.click(screen.getByRole('button', { name }));
    await waitFor(() => expect(stepUp).toHaveBeenCalledTimes(1));
    const lifecycle = stepUp.mock.calls[0]![2]!;
    if (event === 'unmount') view.unmount();
    else if (event === 'session changed')
      view.rerender(
        <AuthenticatorEnrollment session={{ ...session, sessionId: replacement.sessionId }} />,
      );
    else
      act(() => {
        notifySessionTransition('changing');
      });
    expect(lifecycle.signal?.aborted).toBe(true);
    expect(lifecycle.isCurrent?.()).toBe(false);
    await act(async () => pending.resolve(undefined));
    expect(fetcher).not.toHaveBeenCalled();
    expect(location.reload).not.toHaveBeenCalled();
  },
);

it.each(
  ['context POST', 'response JSON'].flatMap((stage) =>
    ['unmount', 'session changed', 'another tab changes the account'].map((event) => ({
      stage,
      event,
    })),
  ),
)('does not reload or replay a late $stage completion after $event', async ({ stage, event }) => {
  const pendingResponse = deferred<Response>();
  const pendingBody = deferred<typeof replacement>();
  const response = Response.json(replacement, { status: 201 });
  const parse = vi.spyOn(response, 'json').mockReturnValue(pendingBody.promise);
  const fetcher = vi
    .spyOn(globalThis, 'fetch')
    .mockReturnValue(
      stage === 'context POST' ? pendingResponse.promise : Promise.resolve(response),
    );
  const view = render(<AuthenticatorEnrollment session={session} />);
  await userEvent.click(screen.getByRole('button', { name }));
  await waitFor(() => expect(fetcher).toHaveBeenCalledTimes(1));
  if (stage === 'response JSON') await waitFor(() => expect(parse).toHaveBeenCalledTimes(1));
  const lifecycle = stepUp.mock.calls[0]![2]!;
  if (event === 'unmount') view.unmount();
  else if (event === 'session changed')
    view.rerender(
      <AuthenticatorEnrollment session={{ ...session, sessionId: replacement.sessionId }} />,
    );
  else
    act(() => {
      notifySessionTransition('changing');
    });
  expect(lifecycle.signal?.aborted).toBe(true);
  await act(async () => {
    pendingResponse.resolve(response);
    pendingBody.resolve(replacement);
  });
  expect(fetcher).toHaveBeenCalledTimes(1);
  expect(location.reload).not.toHaveBeenCalled();
  if (stage === 'context POST') expect(parse).not.toHaveBeenCalled();
});

it('keeps its own key verification alive during same-account focus checks and rereads on settlement', async () => {
  const pending = deferred<void>();
  stepUp.mockReturnValueOnce(pending.promise);
  const fetcher = vi
    .spyOn(globalThis, 'fetch')
    .mockImplementation(async (url, init) =>
      init?.method === 'POST' ? Response.json({}, { status: 403 }) : Response.json(nativeStatus),
    );
  render(<LocalSessionSurface compactAuthenticated={false} />);
  const renew = await screen.findByRole('button', { name });
  await userEvent.click(renew);
  await waitFor(() => expect(stepUp).toHaveBeenCalledTimes(1));
  const lifecycle = stepUp.mock.calls[0]![2]!;
  expect(lifecycle.signal?.aborted).toBe(false);
  fireEvent.focus(window);
  await waitFor(() => expect(fetcher).toHaveBeenCalledTimes(2));
  expect(lifecycle.signal?.aborted).toBe(false);
  await act(async () => pending.resolve(undefined));
  await waitFor(() => expect(renew).toBeEnabled());
  expect(fetcher.mock.calls.filter(([, init]) => init?.method === 'POST')).toHaveLength(1);
  expect(fetcher.mock.calls.filter(([, init]) => !init?.method)).toHaveLength(3);
  expect(location.reload).not.toHaveBeenCalled();
});

it('does not rotate after native focus readback changes the authenticated account', async () => {
  const pending = deferred<void>();
  stepUp.mockReturnValueOnce(pending.promise);
  const fetcher = vi
    .spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(Response.json(nativeStatus))
    .mockResolvedValue(
      Response.json({
        ...nativeStatus,
        principalId: replacement.sessionId,
        sessionId: replacement.sessionId,
      }),
    );
  render(<LocalSessionSurface compactAuthenticated={false} />);
  await userEvent.click(await screen.findByRole('button', { name }));
  await waitFor(() => expect(stepUp).toHaveBeenCalledTimes(1));
  const lifecycle = stepUp.mock.calls[0]![2]!;
  fireEvent.focus(window);
  await screen.findByText(`Signed-in account: ${replacement.sessionId}`);
  await waitFor(() => expect(lifecycle.signal?.aborted).toBe(true));
  await act(async () => pending.resolve(undefined));
  expect(fetcher.mock.calls.every(([, init]) => !init?.method)).toBe(true);
  expect(location.reload).not.toHaveBeenCalled();
});

it('keeps authenticator verification owned while the central account menu is concealed', async () => {
  const pending = deferred<void>();
  stepUp.mockReturnValueOnce(pending.promise);
  const { CentralSessionContext } = await import('./central-session-context');
  const fetcher = vi
    .spyOn(globalThis, 'fetch')
    .mockImplementation(async (_input, init) =>
      init?.method === 'POST'
        ? Response.json(replacement, { status: 201 })
        : Response.json(nativeStatus),
    );
  render(
    <CentralSessionContext.Provider value={true}>
      <LocalSessionSurface appearance="menu" />
      <AuthenticatorEnrollment session={session} />
    </CentralSessionContext.Provider>,
  );
  const toggle = await screen.findByText('Account', { exact: true });
  fireEvent.click(toggle);
  expect(screen.getByRole('button', { name: 'Sign out' })).toBeVisible();
  fireEvent.click(screen.getByRole('button', { name }));
  await waitFor(() => expect(stepUp).toHaveBeenCalledTimes(1));
  expect(screen.queryByRole('button', { name: 'Sign out' })).toBeNull();
  const lifecycle = stepUp.mock.calls[0]![2]!;
  expect(lifecycle.signal?.aborted).toBe(false);
  expect(lifecycle.isCurrent?.()).toBe(true);
  await act(async () => pending.resolve(undefined));
  await waitFor(() => expect(location.reload).toHaveBeenCalledTimes(1));
  const posts = fetcher.mock.calls.filter(([, init]) => init?.method === 'POST');
  expect(posts).toHaveLength(1);
  expect(posts[0]![0]).toBe('/api/v1/ui/session/context');
  expect(JSON.parse(String(posts[0]![1]!.body))).toEqual({
    participantId: session.participantId,
    privacyDomainId: session.privacyDomainId,
    expectedSessionId: session.sessionId,
  });
});
