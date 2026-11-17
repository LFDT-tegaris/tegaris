import { createHash, webcrypto } from 'node:crypto';
import { StrictMode } from 'react';
import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { performWebAuthnStepUp } from '@openpc/ui-shell';
import { PrincipalWorkflow } from './principal-workflow';

vi.mock('@openpc/ui-shell', () => ({ performWebAuthnStepUp: vi.fn() }));

type StepUpLifecycle = { readonly signal?: AbortSignal; readonly isCurrent?: () => boolean };
function assertStepUpCurrent(lifecycle?: StepUpLifecycle) {
  if (!lifecycle || lifecycle.signal?.aborted || lifecycle.isCurrent?.() !== true)
    throw new DOMException('The operation was cancelled.', 'AbortError');
}
beforeEach(() => {
  vi.stubGlobal('crypto', webcrypto);
  vi.mocked(performWebAuthnStepUp)
    .mockReset()
    .mockImplementation(async (_action, _binding, lifecycle?: StepUpLifecycle) => {
      assertStepUpCurrent(lifecycle);
    });
});
function holdStepUp() {
  let release!: () => void;
  let lifecycle!: StepUpLifecycle;
  const entered = vi.fn();
  vi.mocked(performWebAuthnStepUp).mockImplementation(
    (_action, _binding, control?: StepUpLifecycle) => {
      assertStepUpCurrent(control);
      lifecycle = control!;
      entered();
      return new Promise<void>((resolve) => {
        release = resolve;
      }).then(() => assertStepUpCurrent(control));
    },
  );
  return {
    entered,
    release: () => release(),
    lifecycle: () => lifecycle,
    completion: () => vi.mocked(performWebAuthnStepUp).mock.results[0]!.value as Promise<void>,
  };
}

vi.mock('./local-session', () => ({
  LocalSessionSurface: () => <p>Authenticated session controls</p>,
}));
vi.mock('./principal-role-assignments', () => ({
  PrincipalRoleAssignments: () => <p>Governed role assignments</p>,
}));
vi.mock('./principal-catalogue', () => ({
  PrincipalCatalogue: ({ onOpen }: { onOpen(id: string): void }) => (
    <div>
      <button onClick={() => onOpen('018f0000-0000-7000-8000-000000000891')}>
        Open first principal
      </button>
      <button onClick={() => onOpen('018f0000-0000-7000-8000-000000000892')}>
        Open second principal
      </button>
    </div>
  ),
}));

const actor = {
  sessionId: '018f0000-0000-7000-8000-000000000117',
  principalId: '018f0000-0000-7000-8000-000000000111',
  participantId: '018f0000-0000-7000-8000-000000000101',
  privacyDomainId: '018f0000-0000-7000-8000-000000000201',
  contextEpoch: '2',
};
const principalId = '018f0000-0000-7000-8000-000000000891';
const secondId = '018f0000-0000-7000-8000-000000000892';
const fixtureContexts = [
  { participantId: actor.participantId, privacyDomainId: actor.privacyDomainId },
];
const session = {
  ...actor,
  authenticated: true,
  contextMode: 'PARTICIPANT',
  availableContexts: fixtureContexts,
};
const state = { actor: { ...actor, role: 'operator' }, approvals: [], nextCursor: null };
function selectedState(id: string, label: string) {
  return {
    ...state,
    effect: {
      effect: {
        principalId: id,
        displayLabel: label,
        kind: 'USER',
        state: 'ACTIVE',
        revision: '2',
      },
      operationId: null,
    },
  };
}
function deferredResponse() {
  let resolve!: (response: Response) => void;
  let reject!: (cause: Error) => void;
  const promise = new Promise<Response>((accept, fail) => {
    resolve = accept;
    reject = fail;
  });
  return { promise, resolve, reject };
}
function savedReview() {
  return {
    reviewToken: 'sealed-review',
    review: {
      mutation: 'PROVISION',
      expectedRevision: '0',
      candidateDigest: 'sha256:review',
      reason: 'Private maker-only proposal.',
      proposedPrincipal: {
        principalId,
        displayLabel: 'Private draft principal',
        kind: 'USER',
        state: 'PROVISIONED',
      },
      stepUp: {
        actionIntentId: 'test-action',
        actionIntentDigest: 'sha256:action',
        resourceId: principalId,
        resourceDigest: 'sha256:review',
      },
    },
  };
}
function principalCommitCase(
  mutation: 'PROVISION' | 'ACTIVATE' | 'SUSPEND' | 'REMOVE' = 'PROVISION',
) {
  const original = savedReview();
  const targetState = {
    PROVISION: 'PROVISIONED',
    ACTIVATE: 'ACTIVE',
    SUSPEND: 'SUSPENDED',
    REMOVE: 'OFFBOARDED',
  };
  const value = {
    ...original,
    approvalRequestId: '018f0000-0000-7000-8000-000000000801',
    review: {
      ...original.review,
      mutation,
      expectedRevision: mutation === 'PROVISION' ? '0' : '9007199254740993',
      proposedPrincipal: { ...original.review.proposedPrincipal, state: targetState[mutation] },
    },
  };
  const stored = JSON.stringify({ actor, value });
  localStorage.setItem('openpc:principal-workflow:v1', stored);
  const readback = {
    effect: {
      ...value.review.proposedPrincipal,
      participantId: actor.participantId,
      revision: mutation === 'PROVISION' ? '1' : '9007199254740995',
      identityEpoch: '4',
    },
    operationId: '018f0000-0000-7000-8000-000000000851',
  };
  const approved = {
    ...state,
    approvals: [
      {
        approvalRequestId: value.approvalRequestId,
        candidateDigest: value.review.candidateDigest,
        state: 'APPROVED',
        proposal: value.review,
        stepUp: value.review.stepUp,
      },
    ],
  };
  return { value, stored, readback, approved };
}
function humanPrincipalOutcome(readback: ReturnType<typeof principalCommitCase>['readback']) {
  const identitySubjectId = '018f0000-0000-7000-8000-000000000881';
  return {
    ...readback,
    effect: { ...readback.effect, identitySubjectId, membershipId: principalId },
    humanIdentity: {
      identitySubjectId,
      createdAt: '2026-10-08T00:00:00.000Z',
      membershipId: principalId,
      participantId: actor.participantId,
      state: readback.effect.state,
      revision: readback.effect.revision,
      membershipEpoch: readback.effect.identityEpoch,
    },
  };
}
function mockPrincipalCommit(
  fixture: ReturnType<typeof principalCommitCase>,
  result: unknown,
  readback: unknown = fixture.readback,
) {
  return vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
    if (init?.method === 'POST') return Response.json(result, { status: 202 });
    if (String(input) === '/api/v1/ui/local-session') return Response.json(session);
    return Response.json({
      ...fixture.approved,
      ...(String(input).includes('principalId=') ? { effect: readback } : {}),
    });
  });
}
function expectOriginalPrincipalCommit(
  fetcher: ReturnType<typeof mockPrincipalCommit>,
  fixture: ReturnType<typeof principalCommitCase>,
) {
  const posts = fetcher.mock.calls.filter(([, init]) => init?.method === 'POST');
  expect(posts).toHaveLength(1);
  expect(String(posts[0]![0])).toBe('/api/v1/ui/principal-workbench');
  expect(JSON.parse(String(posts[0]![1]!.body))).toEqual({
    command: 'COMMIT',
    reviewToken: fixture.value.reviewToken,
    approvalRequestId: fixture.value.approvalRequestId,
  });
  expect(performWebAuthnStepUp).toHaveBeenCalledOnce();
  expect(localStorage.getItem('openpc:principal-workflow:v1')).toBe(fixture.stored);
}
afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  localStorage.clear();
  vi.clearAllMocks();
  vi.unstubAllGlobals();
});

it('clears another actor’s persisted proposal before displaying an authenticated principal page', async () => {
  localStorage.setItem(
    'openpc:principal-workflow:v1',
    JSON.stringify({ actor, value: savedReview() }),
  );
  const checker = {
    ...actor,
    principalId: '018f0000-0000-7000-8000-000000000112',
    sessionId: '018f0000-0000-7000-8000-000000000118',
  };
  vi.spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(
      Response.json({ ...checker, authenticated: true, contextMode: 'PARTICIPANT' }),
    )
    .mockResolvedValueOnce(
      Response.json({ actor: { ...checker, role: 'viewer' }, approvals: [], nextCursor: null }),
    );
  render(<PrincipalWorkflow />);
  await screen.findByRole('heading', { name: 'Principal governance' });
  expect(screen.queryByText('Private draft principal')).not.toBeInTheDocument();
  expect(screen.getByLabelText('Principal ID')).toHaveValue('');
  expect(localStorage.getItem('openpc:principal-workflow:v1')).toBeNull();
});

it('restores a valid review only after the same actor and context are read from Identity', async () => {
  localStorage.setItem(
    'openpc:principal-workflow:v1',
    JSON.stringify({ actor, value: savedReview() }),
  );
  vi.spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(
      Response.json({ ...actor, authenticated: true, contextMode: 'PARTICIPANT' }),
    )
    .mockResolvedValueOnce(
      Response.json({ actor: { ...actor, role: 'operator' }, approvals: [], nextCursor: null }),
    );
  render(<PrincipalWorkflow />);
  await waitFor(() => expect(screen.getByText('Private draft principal')).toBeVisible());
  expect(screen.getByLabelText('Principal ID')).toHaveValue(principalId);
});

it.each(['success', 'failure'])(
  'ignores an obsolete initial session %s after StrictMode restarts the read',
  async (outcome) => {
    const pending = deferredResponse();
    let sessionReads = 0;
    const fetch = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      if (String(input) === '/api/v1/ui/local-session') {
        sessionReads += 1;
        return sessionReads === 1 ? pending.promise : Response.json(session);
      }
      return Response.json(state);
    });
    render(
      <StrictMode>
        <PrincipalWorkflow />
      </StrictMode>,
    );
    await screen.findByRole('heading', { name: 'Principal governance' });
    expect(fetch.mock.calls[0]?.[1]?.signal?.aborted).toBe(true);
    await act(async () => {
      if (outcome === 'success') pending.resolve(Response.json({ authenticated: false }));
      else pending.reject(new Error('Obsolete session failed.'));
    });
    expect(screen.getByRole('heading', { name: 'Principal governance' })).toBeVisible();
    expect(screen.queryByText('Obsolete session failed.')).not.toBeInTheDocument();
    expect(fetch.mock.calls.some(([, options]) => options?.method === 'POST')).toBe(false);
  },
);
it.each(['success', 'failure'])(
  'keeps a newer principal selection and busy state when the old read ends with %s',
  async (outcome) => {
    const old = deferredResponse(),
      current = deferredResponse();
    const fetch = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      const url = String(input);
      if (url === '/api/v1/ui/local-session') return Response.json(session);
      if (url.includes(`principalId=${principalId}`)) return old.promise;
      if (url.includes(`principalId=${secondId}`)) return current.promise;
      return Response.json(state);
    });
    const user = userEvent.setup();
    render(<PrincipalWorkflow />);
    await user.click(await screen.findByRole('button', { name: 'Open first principal' }));
    await waitFor(() =>
      expect(
        fetch.mock.calls.some(([url]) => String(url).includes(`principalId=${principalId}`)),
      ).toBe(true),
    );
    await user.click(screen.getByRole('button', { name: 'Open second principal' }));
    await waitFor(() =>
      expect(
        fetch.mock.calls.some(([url]) => String(url).includes(`principalId=${secondId}`)),
      ).toBe(true),
    );
    expect(
      fetch.mock.calls.find(([url]) => String(url).includes(`principalId=${principalId}`))?.[1]
        ?.signal?.aborted,
    ).toBe(true);
    await act(async () => {
      if (outcome === 'success')
        old.resolve(Response.json(selectedState(principalId, 'Old principal')));
      else old.reject(new Error('Obsolete principal read failed.'));
    });
    expect(screen.getByRole('button', { name: 'Refresh principal approvals' })).toBeDisabled();
    expect(screen.queryByText('Old principal')).not.toBeInTheDocument();
    expect(screen.queryByText('Obsolete principal read failed.')).not.toBeInTheDocument();
    await act(async () =>
      current.resolve(Response.json(selectedState(secondId, 'Current principal'))),
    );
    expect(screen.getByText('Current principal')).toBeVisible();
    expect(screen.getByRole('button', { name: 'Refresh principal approvals' })).toBeEnabled();
    expect(fetch.mock.calls.some(([, options]) => options?.method === 'POST')).toBe(false);
  },
);
it('drops an old approval cursor and saved selection when refreshed Identity reports a different actor', async () => {
  localStorage.setItem(
    'openpc:principal-workflow:v1',
    JSON.stringify({ actor, value: savedReview() }),
  );
  const nextActor = {
    ...actor,
    sessionId: '018f0000-0000-7000-8000-000000000118',
    contextEpoch: '3',
  };
  let sessionReads = 0;
  const fetch = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
    if (String(input) === '/api/v1/ui/local-session') {
      sessionReads += 1;
      return Response.json(sessionReads === 1 ? session : { ...session, ...nextActor });
    }
    return Response.json(
      sessionReads === 1
        ? { ...state, nextCursor: 'old-context-cursor' }
        : { ...state, actor: { ...nextActor, role: 'operator' } },
    );
  });
  const user = userEvent.setup();
  render(<PrincipalWorkflow />);
  await screen.findByText('Private draft principal');
  await user.click(screen.getByRole('button', { name: 'Next principal approval page' }));
  fireEvent.click(screen.getByRole('button', { name: 'Workspace details' }));
  await within(screen.getByRole('dialog', { name: 'Workspace details' })).findByText('3');
  fireEvent.click(screen.getByRole('button', { name: 'Close Workspace details' }));
  expect(screen.queryByText('Private draft principal')).not.toBeInTheDocument();
  expect(screen.getByLabelText('Principal ID')).toHaveValue('');
  expect(String(fetch.mock.calls.at(-1)?.[0])).not.toContain('cursor=');
  expect(localStorage.getItem('openpc:principal-workflow:v1')).toBeNull();
  expect(fetch.mock.calls.some(([, options]) => options?.method === 'POST')).toBe(false);
});
it('clears the selected effect and displays a current owner denial instead of retaining stale principal data', async () => {
  let denied = false;
  const fetch = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
    const url = String(input);
    if (url === '/api/v1/ui/local-session') return Response.json(session);
    if (url.includes('principalId='))
      return denied
        ? Response.json(
            { title: 'Current principal read denied', code: 'PC-AUTH-0005' },
            { status: 403 },
          )
        : Response.json(selectedState(principalId, 'Previously visible principal'));
    return Response.json(state);
  });
  const user = userEvent.setup();
  render(<PrincipalWorkflow />);
  await user.click(await screen.findByRole('button', { name: 'Open first principal' }));
  await screen.findByText('Previously visible principal');
  denied = true;
  await user.click(screen.getByRole('button', { name: 'Open first principal' }));
  await screen.findByText(
    'Principal request was not authorized. Refresh the authenticated context before continuing.',
  );
  expect(screen.queryByText('Previously visible principal')).not.toBeInTheDocument();
  expect(screen.queryByRole('heading', { name: 'Principal governance' })).not.toBeInTheDocument();
  expect(screen.queryByText('Governed role assignments')).not.toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Refresh principal approvals' })).toBeEnabled();
  expect(fetch.mock.calls.some(([, options]) => options?.method === 'POST')).toBe(false);
});
it.each([
  ['session', 'denial'],
  ['session', 'malformed'],
  ['session', 'missing context'],
  ['session', 'unknown context'],
  ['session', 'unavailable'],
  ['workbench', 'denial'],
  ['workbench', 'malformed'],
  ['workbench', 'malformed effect'],
  ['workbench', 'unavailable'],
])(
  'invalidates principal projections on current %s %s and restores only an Identity-bound original',
  async (phase, failure) => {
    localStorage.setItem(
      'openpc:principal-workflow:v1',
      JSON.stringify({ actor, value: savedReview() }),
    );
    const storedOriginal = localStorage.getItem('openpc:principal-workflow:v1');
    const oldSelection = deferredResponse();
    let denied = false;
    const fetch = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      const url = String(input);
      const isSession = url === '/api/v1/ui/local-session';
      if (denied && isSession === (phase === 'session')) {
        if (failure === 'unavailable') throw new Error('Current principal read unavailable.');
        return failure === 'denial'
          ? Response.json({ title: 'Current principal read denied' }, { status: 403 })
          : Response.json(
              failure === 'missing context'
                ? { ...session, privacyDomainId: undefined }
                : failure === 'unknown context'
                  ? { ...session, contextMode: 'UNKNOWN' }
                  : failure === 'malformed effect'
                    ? { ...state, effect: { effect: {} } }
                    : {},
            );
      }
      if (isSession) return Response.json(session);
      if (url.includes(secondId)) return oldSelection.promise;
      return Response.json(
        url.includes(principalId)
          ? selectedState(principalId, 'Previously visible principal')
          : state,
      );
    });
    const user = userEvent.setup();
    render(<PrincipalWorkflow />);
    await screen.findByText('Private draft principal');
    await user.click(screen.getByRole('button', { name: 'Open first principal' }));
    await screen.findByText('Previously visible principal');
    expect(screen.getByText('Governed role assignments')).toBeVisible();
    await user.click(screen.getByRole('button', { name: 'Open second principal' }));
    await waitFor(() =>
      expect(fetch.mock.calls.some(([url]) => String(url).includes(secondId))).toBe(true),
    );
    const oldSignal = fetch.mock.calls.find(([url]) => String(url).includes(secondId))?.[1]?.signal;
    denied = true;
    await user.click(screen.getByRole('button', { name: 'Open first principal' }));
    expect(await screen.findByRole('status')).toHaveTextContent(
      failure === 'denial'
        ? 'Principal request was not authorized. Refresh the authenticated context before continuing.'
        : failure === 'unavailable'
          ? 'Principal request could not be confirmed. Refresh or read the original operation before retrying.'
          : phase === 'session'
            ? 'Authenticated context could not be confirmed. Refresh before continuing.'
            : 'Principal approvals could not be confirmed. Refresh before continuing.',
    );
    expect(oldSignal?.aborted).toBe(true);
    expect(screen.queryByRole('heading', { name: 'Principal governance' })).not.toBeInTheDocument();
    expect(screen.queryByText('Private draft principal')).not.toBeInTheDocument();
    expect(screen.queryByText('Previously visible principal')).not.toBeInTheDocument();
    expect(screen.queryByText('Governed role assignments')).not.toBeInTheDocument();
    expect(screen.queryByText('Authenticated session controls')).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Open first principal' })).not.toBeInTheDocument();
    expect(localStorage.getItem('openpc:principal-workflow:v1')).toBe(storedOriginal);
    await act(async () =>
      oldSelection.resolve(Response.json(selectedState(secondId, 'Late obsolete principal'))),
    );
    expect(screen.queryByText('Late obsolete principal')).not.toBeInTheDocument();
    expect(screen.queryByText('Private draft principal')).not.toBeInTheDocument();
    expect(localStorage.getItem('openpc:principal-workflow:v1')).toBe(storedOriginal);
    denied = false;
    await user.click(screen.getByRole('button', { name: 'Refresh principal approvals' }));
    await screen.findByText('Private draft principal');
    fireEvent.click(screen.getByRole('button', { name: 'Workspace details' }));
    expect(
      within(screen.getByRole('dialog', { name: 'Workspace details' })).getByText('2'),
    ).toBeVisible();
    fireEvent.click(screen.getByRole('button', { name: 'Close Workspace details' }));
    expect(screen.getByLabelText('Principal ID')).toHaveValue(principalId);
    expect(screen.queryByText('Previously visible principal')).not.toBeInTheDocument();
    expect(screen.queryByText('Late obsolete principal')).not.toBeInTheDocument();
    expect(screen.queryByText('Governed role assignments')).not.toBeInTheDocument();
    expect(localStorage.getItem('openpc:principal-workflow:v1')).toBe(storedOriginal);
    expect(fetch.mock.calls.some(([, options]) => options?.method === 'POST')).toBe(false);
    expect(performWebAuthnStepUp).not.toHaveBeenCalled();
  },
);
it('rejects a current readback for another selected principal', async () => {
  const fetch = vi
    .spyOn(globalThis, 'fetch')
    .mockImplementation(async (input) =>
      Response.json(
        String(input) === '/api/v1/ui/local-session'
          ? session
          : String(input).includes('principalId=')
            ? selectedState(secondId, 'Foreign selection')
            : state,
      ),
    );
  const user = userEvent.setup();
  render(<PrincipalWorkflow />);
  await user.click(await screen.findByRole('button', { name: 'Open first principal' }));
  await screen.findByText('Principal readback belongs to a different selection.');
  expect(screen.queryByText('Foreign selection')).not.toBeInTheDocument();
  expect(fetch.mock.calls.some(([, options]) => options?.method === 'POST')).toBe(false);
});
it('exposes a current initial session failure without claiming an authenticated context', async () => {
  const fetch = vi
    .spyOn(globalThis, 'fetch')
    .mockRejectedValue(new Error('Authenticated context read unavailable.'));
  render(<PrincipalWorkflow />);
  expect(await screen.findByRole('status')).toHaveTextContent(
    'Principal request could not be confirmed. Refresh or read the original operation before retrying.',
  );
  expect(screen.queryByRole('heading', { name: 'Principal governance' })).not.toBeInTheDocument();
  expect(fetch).toHaveBeenCalledTimes(1);
});
it('removes old principal controls when the current workbench response no longer matches Identity', async () => {
  localStorage.setItem(
    'openpc:principal-workflow:v1',
    JSON.stringify({ actor, value: savedReview() }),
  );
  let workbenchReads = 0;
  const fetch = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
    if (String(input) === '/api/v1/ui/local-session') return Response.json(session);
    workbenchReads += 1;
    return Response.json(
      workbenchReads === 1 ? state : { ...state, actor: { ...state.actor, contextEpoch: '3' } },
    );
  });
  const user = userEvent.setup();
  render(<PrincipalWorkflow />);
  await screen.findByText('Private draft principal');
  await user.click(screen.getByRole('button', { name: 'Refresh principal approvals' }));
  await screen.findByText(
    'The working context changed. Refresh the principal page before continuing.',
  );
  expect(screen.queryByText('Private draft principal')).not.toBeInTheDocument();
  expect(screen.queryByRole('heading', { name: 'Principal governance' })).not.toBeInTheDocument();
  expect(localStorage.getItem('openpc:principal-workflow:v1')).not.toBeNull();
  expect(fetch.mock.calls.some(([, options]) => options?.method === 'POST')).toBe(false);
});
it.each(['session', 'workbench'])(
  'cancels an active principal %s read on unmount',
  async (phase) => {
    const pending = deferredResponse();
    const fetch = vi
      .spyOn(globalThis, 'fetch')
      .mockImplementation(async (input) =>
        phase === 'session' || String(input) !== '/api/v1/ui/local-session'
          ? pending.promise
          : Response.json(session),
      );
    const view = render(<PrincipalWorkflow />);
    if (phase === 'workbench') await waitFor(() => expect(fetch).toHaveBeenCalledTimes(2));
    const signal = fetch.mock.calls.at(-1)?.[1]?.signal;
    expect(signal?.aborted).toBe(false);
    view.unmount();
    expect(signal?.aborted).toBe(true);
    await act(async () => pending.reject(new Error('Unmounted read failed.')));
    expect(fetch.mock.calls.some(([, options]) => options?.method === 'POST')).toBe(false);
  },
);
it('keeps membership-removal reauthentication intact when an older read arrives afterward', async () => {
  const mutation = deferredResponse(),
    oldRead = deferredResponse();
  const original = savedReview();
  const review = {
    ...original,
    approvalRequestId: '018f0000-0000-7000-8000-000000000801',
    review: {
      ...original.review,
      mutation: 'REMOVE',
      expectedRevision: '2',
      proposedPrincipal: { ...original.review.proposedPrincipal, state: 'OFFBOARDED' },
    },
  };
  localStorage.setItem('openpc:principal-workflow:v1', JSON.stringify({ actor, value: review }));
  const approved = {
    ...state,
    approvals: [
      {
        approvalRequestId: review.approvalRequestId,
        candidateDigest: review.review.candidateDigest,
        state: 'APPROVED',
        proposal: review.review,
        stepUp: review.review.stepUp,
      },
    ],
  };
  const fetch = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
    if (init?.method === 'POST') return mutation.promise;
    if (String(input) === '/api/v1/ui/local-session') return Response.json(session);
    if (String(input).includes('principalId=')) return oldRead.promise;
    return Response.json(approved);
  });
  const user = userEvent.setup();
  render(<PrincipalWorkflow />);
  await user.click(await screen.findByRole('button', { name: 'Commit approved principal change' }));
  await waitFor(() =>
    expect(fetch.mock.calls.some(([, options]) => options?.method === 'POST')).toBe(true),
  );
  await user.click(screen.getByRole('button', { name: 'Open first principal' }));
  await waitFor(() =>
    expect(fetch.mock.calls.some(([url]) => String(url).includes('principalId='))).toBe(true),
  );
  const signal = fetch.mock.calls.find(([url]) => String(url).includes('principalId='))?.[1]
    ?.signal;
  await act(async () =>
    mutation.resolve(
      Response.json({
        truthState: 'REAUTH_REQUIRED',
        principalId,
        reconciliation: 'SIGN_IN_THEN_READ_AUTHORITATIVE_EFFECT',
      }),
    ),
  );
  expect(signal?.aborted).toBe(true);
  await act(async () =>
    oldRead.resolve(Response.json(selectedState(principalId, 'Removed membership'))),
  );
  expect(screen.queryByRole('heading', { name: 'Principal governance' })).not.toBeInTheDocument();
  expect(screen.queryByText('Removed membership')).not.toBeInTheDocument();
  expect(screen.getByText(/Membership removal committed/u)).toBeVisible();
  expect(fetch.mock.calls.filter(([, options]) => options?.method === 'POST')).toHaveLength(1);
  expect(
    JSON.parse(
      String(fetch.mock.calls.find(([, options]) => options?.method === 'POST')?.[1]?.body),
    ),
  ).toEqual({
    command: 'COMMIT',
    reviewToken: review.reviewToken,
    approvalRequestId: review.approvalRequestId,
  });
  expect(performWebAuthnStepUp).toHaveBeenCalledOnce();
});

const unsafePrincipalMarker = 'PRIVATE_PRINCIPAL_SERVER_OR_TRANSPORT_DETAIL';
const principalUnavailable =
  'Principal request could not be confirmed. Refresh or read the original operation before retrying.';
const principalFailures = [
  {
    name: 'authorization',
    status: 403,
    message:
      'Principal request was not authorized. Refresh the authenticated context before continuing.',
  },
  {
    name: 'conflict',
    status: 409,
    message: 'Principal state changed. Refresh or read the original operation before retrying.',
  },
  {
    name: 'input',
    status: 422,
    message: 'Principal request was rejected. Check the inputs before continuing.',
  },
  { name: 'unknown code', status: 503, message: principalUnavailable },
  { name: 'transport', message: principalUnavailable },
  { name: 'unknown thrown object', message: principalUnavailable },
  { name: 'non-JSON success', message: principalUnavailable },
] as const;
function failPrincipal(failure: (typeof principalFailures)[number]): Response {
  if ('status' in failure)
    return Response.json(
      { title: unsafePrincipalMarker, code: unsafePrincipalMarker },
      { status: failure.status },
    );
  if (failure.name === 'transport') throw new Error(unsafePrincipalMarker);
  if (failure.name === 'unknown thrown object')
    throw { message: unsafePrincipalMarker, details: unsafePrincipalMarker };
  return new Response(unsafePrincipalMarker, { status: 200 });
}
it.each(
  principalFailures.flatMap((failure) =>
    ['session', 'workbench'].map((phase) => ({ ...failure, phase })),
  ),
)('hides $name at the initial $phase reader without losing stored custody', async (failure) => {
  const original = JSON.stringify({ actor, value: savedReview() });
  localStorage.setItem('openpc:principal-workflow:v1', original);
  const fetcher = vi
    .spyOn(globalThis, 'fetch')
    .mockImplementation(async (input) =>
      String(input) === '/api/v1/ui/local-session' && failure.phase === 'workbench'
        ? Response.json(session)
        : failPrincipal(failure),
    );
  render(<PrincipalWorkflow />);
  await screen.findByText(failure.message);
  expect(document.body.textContent).not.toContain(unsafePrincipalMarker);
  expect(screen.queryByRole('heading', { name: 'Principal governance' })).not.toBeInTheDocument();
  expect(
    screen.queryByText('No visible principal approvals on this page.'),
  ).not.toBeInTheDocument();
  expect(localStorage.getItem('openpc:principal-workflow:v1')).toBe(original);
  expect(fetcher.mock.calls.some(([, init]) => init?.method === 'POST')).toBe(false);
});
it.each(['refresh', 'selected principal', 'approval cursor'] as const)(
  'hides a transport failure at the %s reader',
  async (boundary) => {
    const original = JSON.stringify({ actor, value: savedReview() });
    localStorage.setItem('openpc:principal-workflow:v1', original);
    let fail = false;
    const fetcher = vi
      .spyOn(globalThis, 'fetch')
      .mockImplementation(async (input) =>
        String(input) === '/api/v1/ui/local-session'
          ? Response.json(session)
          : fail
            ? failPrincipal({ name: 'transport', message: principalUnavailable })
            : Response.json({ ...state, nextCursor: 'next-principal-page' }),
      );
    render(<PrincipalWorkflow />);
    await screen.findByRole('heading', { name: 'Principal governance' });
    fail = true;
    fireEvent.click(
      screen.getByRole('button', {
        name:
          boundary === 'refresh'
            ? 'Refresh principal approvals'
            : boundary === 'selected principal'
              ? 'Open first principal'
              : 'Next principal approval page',
      }),
    );
    await screen.findByText(principalUnavailable);
    expect(document.body.textContent).not.toContain(unsafePrincipalMarker);
    expect(localStorage.getItem('openpc:principal-workflow:v1')).toBe(original);
    expect(screen.queryByRole('heading', { name: 'Principal governance' })).not.toBeInTheDocument();
    expect(fetcher.mock.calls.some(([, init]) => init?.method === 'POST')).toBe(false);
  },
);
const principalApprovalId = '018f0000-0000-7000-8000-000000000801';
function principalApproval(approvalState: string) {
  const value = savedReview();
  return {
    approvalRequestId: `urn:openpc:resource:${principalApprovalId}`,
    candidateDigest: value.review.candidateDigest,
    state: approvalState,
    proposal: value.review,
    stepUp: value.review.stepUp,
  };
}
it.each(
  principalFailures.flatMap((failure) =>
    ['preview', 'submit', 'approve', 'commit'].map((boundary) => ({ ...failure, boundary })),
  ),
)(
  'hides $name from principal $boundary without replacing or replaying the original review',
  async (failure) => {
    const value = {
      ...savedReview(),
      ...(failure.boundary === 'commit' ? { approvalRequestId: principalApprovalId } : {}),
    };
    const original = JSON.stringify({ actor, value });
    localStorage.setItem('openpc:principal-workflow:v1', original);
    const reader = {
      ...state,
      actor: { ...actor, role: failure.boundary === 'approve' ? 'viewer' : 'operator' },
      approvals:
        failure.boundary === 'approve' || failure.boundary === 'commit'
          ? [principalApproval(failure.boundary === 'approve' ? 'REQUESTED' : 'APPROVED')]
          : [],
    };
    const fetcher = vi
      .spyOn(globalThis, 'fetch')
      .mockImplementation(async (input, init) =>
        init?.method === 'POST'
          ? failPrincipal(failure)
          : Response.json(String(input) === '/api/v1/ui/local-session' ? session : reader),
      );
    render(<PrincipalWorkflow />);
    await screen.findByRole('heading', { name: 'Principal governance' });
    const names = {
      preview: 'Review principal provisioning',
      submit: 'Send principal to checker',
      approve: 'Approve Private draft principal',
      commit: 'Commit approved principal change',
    };
    const control = screen.getByRole('button', {
      name: names[failure.boundary as keyof typeof names],
    });
    if (failure.boundary === 'preview') {
      fireEvent.change(screen.getByLabelText('Principal name', { selector: 'input' }), {
        target: { value: 'New principal' },
      });
      fireEvent.change(control.closest('form')!.querySelector('[name=reason]')!, {
        target: { value: 'Review this exact principal provision.' },
      });
      fireEvent.submit(control.closest('form')!);
    } else fireEvent.click(control);
    await screen.findByText(failure.message);
    expect(document.body.textContent).not.toContain(unsafePrincipalMarker);
    expect(localStorage.getItem('openpc:principal-workflow:v1')).toBe(original);
    expect(
      screen.queryByText('Principal change committed and its durable effect read back.'),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByText('The principal change is awaiting a distinct checker.'),
    ).not.toBeInTheDocument();
    const posts = fetcher.mock.calls.filter(([, init]) => init?.method === 'POST');
    expect(posts).toHaveLength(1);
    const body = JSON.parse(String(posts[0]![1]!.body));
    if (failure.boundary === 'submit')
      expect(body).toEqual({ command: 'SUBMIT', reviewToken: value.reviewToken });
    else if (failure.boundary === 'commit')
      expect(body).toEqual({
        command: 'COMMIT',
        reviewToken: value.reviewToken,
        approvalRequestId: principalApprovalId,
      });
    else if (failure.boundary === 'approve')
      expect(body).toEqual({
        command: 'APPROVE',
        approvalRequestId: principalApprovalId,
        candidateDigest: value.review.candidateDigest,
      });
    else
      expect(body).toMatchObject({ command: 'PREVIEW_PROVISION', displayLabel: 'New principal' });
  },
);
it('hides authenticator exceptions and prevents principal commit before step-up succeeds', async () => {
  const original = JSON.stringify({
    actor,
    value: { ...savedReview(), approvalRequestId: principalApprovalId },
  });
  localStorage.setItem('openpc:principal-workflow:v1', original);
  vi.mocked(performWebAuthnStepUp).mockRejectedValueOnce(new Error(unsafePrincipalMarker));
  const fetcher = vi
    .spyOn(globalThis, 'fetch')
    .mockImplementation(async (input) =>
      Response.json(
        String(input) === '/api/v1/ui/local-session'
          ? session
          : { ...state, approvals: [principalApproval('APPROVED')] },
      ),
    );
  render(<PrincipalWorkflow />);
  fireEvent.click(await screen.findByRole('button', { name: 'Commit approved principal change' }));
  await screen.findByText(principalUnavailable);
  expect(document.body.textContent).not.toContain(unsafePrincipalMarker);
  expect(localStorage.getItem('openpc:principal-workflow:v1')).toBe(original);
  expect(fetcher.mock.calls.some(([, init]) => init?.method === 'POST')).toBe(false);
});
it('hides context-selection denial without claiming a Participant context was activated', async () => {
  const fetcher = vi
    .spyOn(globalThis, 'fetch')
    .mockImplementation(async (_input, init) =>
      init?.method === 'POST'
        ? failPrincipal(principalFailures[0])
        : Response.json({ ...session, contextMode: 'PLATFORM' }),
    );
  render(<PrincipalWorkflow />);
  fireEvent.click(await screen.findByRole('button', { name: 'Enter workspace' }));
  await screen.findByText(principalFailures[0].message);
  expect(document.body.textContent).not.toContain(unsafePrincipalMarker);
  expect(screen.queryByText('Participant privacy context is active.')).not.toBeInTheDocument();
  expect(fetcher.mock.calls.filter(([, init]) => init?.method === 'POST')).toHaveLength(1);
});

it.each([200, 201])(
  'preserves a valid HTTP %s principal preview without claiming approval or commitment',
  async (status) => {
    const value = savedReview();
    const fetcher = vi
      .spyOn(globalThis, 'fetch')
      .mockImplementation(async (input, init) =>
        Response.json(
          init?.method === 'POST'
            ? value
            : String(input) === '/api/v1/ui/local-session'
              ? session
              : state,
          { status: init?.method === 'POST' ? status : 200 },
        ),
      );
    render(<PrincipalWorkflow />);
    const control = await screen.findByRole('button', { name: 'Review principal provisioning' });
    const form = control.closest('form')!;
    fireEvent.change(form.querySelector('[name=displayLabel]')!, {
      target: { value: value.review.proposedPrincipal.displayLabel },
    });
    fireEvent.change(form.querySelector('[name=reason]')!, {
      target: { value: value.review.reason },
    });
    fireEvent.submit(form);
    await screen.findByText('Review the exact principal change before requesting approval.');
    expect(JSON.parse(localStorage.getItem('openpc:principal-workflow:v1')!).value).toEqual(value);
    expect(screen.getByRole('button', { name: 'Send principal to checker' })).toBeEnabled();
    expect(
      screen.queryByRole('button', { name: 'Commit approved principal change' }),
    ).not.toBeInTheDocument();
    const posts = fetcher.mock.calls.filter(([, init]) => init?.method === 'POST');
    expect(posts).toHaveLength(1);
    expect(JSON.parse(String(posts[0]![1]!.body))).toEqual({
      command: 'PREVIEW_PROVISION',
      displayLabel: value.review.proposedPrincipal.displayLabel,
      kind: 'USER',
      reason: value.review.reason,
    });
  },
);

it.each(['maker', 'checker', 'context'] as const)(
  'cancels held principal %s proof on unmount before its original command',
  async (kind) => {
    const value = { ...savedReview(), approvalRequestId: principalApprovalId };
    localStorage.setItem('openpc:principal-workflow:v1', JSON.stringify({ actor, value }));
    const original = localStorage.getItem('openpc:principal-workflow:v1'),
      held = holdStepUp();
    const fetcher = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) =>
      Response.json(
        String(input) === '/api/v1/ui/local-session'
          ? {
              ...session,
              contextMode: kind === 'context' ? 'PLATFORM' : 'PARTICIPANT',
            }
          : {
              ...state,
              actor: { ...actor, role: kind === 'checker' ? 'viewer' : 'operator' },
              approvals: [principalApproval(kind === 'checker' ? 'REQUESTED' : 'APPROVED')],
            },
      ),
    );
    const view = render(<PrincipalWorkflow />);
    fireEvent.click(
      await screen.findByRole('button', {
        name:
          kind === 'maker'
            ? 'Commit approved principal change'
            : kind === 'checker'
              ? 'Approve Private draft principal'
              : 'Enter workspace',
      }),
    );
    await waitFor(() => expect(held.entered).toHaveBeenCalledOnce());
    const completed = expect(held.completion()).rejects.toMatchObject({ name: 'AbortError' });
    view.unmount();
    expect(held.lifecycle().signal?.aborted).toBe(true);
    await act(async () => {
      held.release();
      await completed;
    });
    expect(fetcher.mock.calls.some(([, init]) => init?.method === 'POST')).toBe(false);
    // Platform context intentionally does not restore a Participant-bound draft.
    if (kind !== 'context')
      expect(localStorage.getItem('openpc:principal-workflow:v1')).toBe(original);
  },
);
it.each([
  { field: 'sessionId', value: '018f0000-0000-7000-8000-000000000118' },
  { field: 'principalId', value: '018f0000-0000-7000-8000-000000000113' },
  { field: 'participantId', value: '018f0000-0000-7000-8000-000000000102' },
  { field: 'privacyDomainId', value: '018f0000-0000-7000-8000-000000000202' },
  { field: 'contextEpoch', value: '3' },
] as const)(
  'stops the principal command after an independent read observes changed $field during proof',
  async (change) => {
    localStorage.setItem(
      'openpc:principal-workflow:v1',
      JSON.stringify({
        actor,
        value: { ...savedReview(), approvalRequestId: principalApprovalId },
      }),
    );
    const held = holdStepUp();
    let current = actor;
    const fetcher = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) =>
      Response.json(
        String(input) === '/api/v1/ui/local-session'
          ? { ...current, authenticated: true, contextMode: 'PARTICIPANT' }
          : {
              actor: { ...current, role: 'operator' },
              approvals: current === actor ? [principalApproval('APPROVED')] : [],
              nextCursor: null,
            },
      ),
    );
    render(<PrincipalWorkflow />);
    fireEvent.click(
      await screen.findByRole('button', { name: 'Commit approved principal change' }),
    );
    await waitFor(() => expect(held.entered).toHaveBeenCalledOnce());
    current = { ...actor, [change.field]: change.value };
    fireEvent.click(screen.getByRole('button', { name: 'Open first principal' }));
    await waitFor(() => expect(held.lifecycle().signal?.aborted).toBe(true));
    const completed = expect(held.completion()).rejects.toMatchObject({ name: 'AbortError' });
    await act(async () => {
      held.release();
      await completed;
    });
    await waitFor(() =>
      expect(screen.getByRole('button', { name: 'Refresh principal approvals' })).toBeEnabled(),
    );
    expect(fetcher.mock.calls.some(([, init]) => init?.method === 'POST')).toBe(false);
    expect(screen.queryByText('Private draft principal')).not.toBeInTheDocument();
    expect(screen.queryByLabelText('Principal change review')).not.toBeInTheDocument();
  },
);
it('stops a held checker proof after an independent owner read replaces its approval binding', async () => {
  const held = holdStepUp();
  let changed = false;
  const fetcher = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) =>
    Response.json(
      String(input) === '/api/v1/ui/local-session'
        ? session
        : {
            ...state,
            actor: { ...actor, role: 'viewer' },
            approvals: [
              changed
                ? {
                    ...principalApproval('REQUESTED'),
                    candidateDigest: 'sha256:changed',
                    stepUp: {
                      ...principalApproval('REQUESTED').stepUp,
                      resourceDigest: 'sha256:changed',
                    },
                  }
                : principalApproval('REQUESTED'),
            ],
            nextCursor: null,
            ...(String(input).includes('principalId=')
              ? { effect: selectedState(principalId, 'Current principal').effect }
              : {}),
          },
    ),
  );
  render(<PrincipalWorkflow />);
  fireEvent.click(await screen.findByRole('button', { name: 'Approve Private draft principal' }));
  await waitFor(() => expect(held.entered).toHaveBeenCalledOnce());
  changed = true;
  fireEvent.click(screen.getByRole('button', { name: 'Open first principal' }));
  await screen.findByText('Current principal');
  expect(held.lifecycle().isCurrent?.()).toBe(false);
  const completed = expect(held.completion()).rejects.toMatchObject({ name: 'AbortError' });
  await act(async () => {
    held.release();
    await completed;
  });
  await waitFor(() =>
    expect(screen.getByRole('button', { name: 'Refresh principal approvals' })).toBeEnabled(),
  );
  expect(fetcher.mock.calls.some(([, init]) => init?.method === 'POST')).toBe(false);
});
it.each(['maker', 'checker', 'context'] as const)(
  'keeps independent reads available while sending one exact principal %s command',
  async (kind) => {
    const value = { ...savedReview(), approvalRequestId: principalApprovalId };
    localStorage.setItem('openpc:principal-workflow:v1', JSON.stringify({ actor, value }));
    const held = holdStepUp(),
      posts: { url: string; body: unknown }[] = [];
    let participantContext = kind !== 'context';
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const url = String(input);
      if (init?.method === 'POST') {
        posts.push({ url, body: JSON.parse(String(init.body)) });
        participantContext = true;
        return Response.json({ truthState: 'SUCCESS' });
      }
      if (url === '/api/v1/ui/local-session')
        return Response.json({
          ...session,
          contextMode: participantContext ? 'PARTICIPANT' : 'PLATFORM',
        });
      return Response.json({
        ...selectedState(principalId, 'Current principal'),
        actor: { ...actor, role: kind === 'checker' ? 'viewer' : 'operator' },
        approvals: [principalApproval(kind === 'checker' ? 'REQUESTED' : 'APPROVED')],
      });
    });
    render(<PrincipalWorkflow />);
    const button = await screen.findByRole('button', {
      name:
        kind === 'maker'
          ? 'Commit approved principal change'
          : kind === 'checker'
            ? 'Approve Private draft principal'
            : 'Enter workspace',
    });
    act(() => {
      fireEvent.click(button);
      fireEvent.click(button);
    });
    await waitFor(() => expect(held.entered).toHaveBeenCalledOnce());
    if (kind !== 'context') {
      fireEvent.click(screen.getByRole('button', { name: 'Open first principal' }));
      await screen.findByText('Current principal');
      expect(held.lifecycle().isCurrent?.()).toBe(true);
    }
    await act(async () => {
      held.release();
      await held.completion();
    });
    await waitFor(() =>
      expect(screen.getByRole('button', { name: 'Refresh principal approvals' })).toBeEnabled(),
    );
    expect(posts).toEqual([
      kind === 'context'
        ? {
            url: '/api/v1/ui/session/context',
            body: {
              participantId: actor.participantId,
              privacyDomainId: actor.privacyDomainId,
              expectedSessionId: actor.sessionId,
            },
          }
        : {
            url: '/api/v1/ui/principal-workbench',
            body:
              kind === 'maker'
                ? {
                    command: 'COMMIT',
                    reviewToken: value.reviewToken,
                    approvalRequestId: principalApprovalId,
                  }
                : {
                    command: 'APPROVE',
                    approvalRequestId: principalApprovalId,
                    candidateDigest: value.review.candidateDigest,
                  },
          },
    ]);
    expect(held.entered).toHaveBeenCalledOnce();
  },
);

it.each(['success', 'interruption'] as const)(
  'preserves issued principal original custody after late %s without starting post-unmount reads',
  async (outcome) => {
    const original = JSON.stringify({
      actor,
      value: { ...savedReview(), approvalRequestId: principalApprovalId },
    });
    localStorage.setItem('openpc:principal-workflow:v1', original);
    const mutation = deferredResponse();
    const fetcher = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      if (init?.method === 'POST') return mutation.promise;
      return Response.json(
        String(input) === '/api/v1/ui/local-session'
          ? session
          : { ...state, approvals: [principalApproval('APPROVED')] },
      );
    });
    const view = render(<PrincipalWorkflow />);
    fireEvent.click(
      await screen.findByRole('button', { name: 'Commit approved principal change' }),
    );
    await waitFor(() =>
      expect(fetcher.mock.calls.filter(([, init]) => init?.method === 'POST')).toHaveLength(1),
    );
    const issuedCalls = fetcher.mock.calls.length;
    view.unmount();
    await act(async () => {
      if (outcome === 'success') mutation.resolve(Response.json({ truthState: 'SUCCESS' }));
      else mutation.reject(new Error('PRIVATE_LOST_MUTATION_RESPONSE'));
      await mutation.promise.catch(() => undefined);
    });
    expect(fetcher.mock.calls).toHaveLength(issuedCalls);
    expect(localStorage.getItem('openpc:principal-workflow:v1')).toBe(original);
    expect(performWebAuthnStepUp).toHaveBeenCalledOnce();
  },
);

function principalContextDeferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((accept) => {
    resolve = accept;
  });
  return { promise, resolve };
}
it.each([
  { participantId: actor.participantId, privacyDomainId: actor.privacyDomainId },
  {
    participantId: '018f0000-0000-7000-8000-000000000102',
    privacyDomainId: '018f0000-0000-7000-8000-000000007201',
  },
])('selects the server principal context and captures its source session: %o', async (context) => {
  const sourceSessionId = '018f0000-0000-7000-8000-000000000118';
  let selected = false;
  const currentActor = { ...actor, ...context, sessionId: sourceSessionId };
  const fetcher = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
    if (init?.method === 'POST') {
      expect(String(input)).toBe('/api/v1/ui/session/context');
      selected = true;
      return Response.json({ accepted: true });
    }
    return Response.json(
      String(input).endsWith('/local-session')
        ? {
            ...session,
            sessionId: sourceSessionId,
            ...(selected ? context : { privacyDomainId: undefined }),
            contextMode: selected ? 'PARTICIPANT' : 'PLATFORM',
            availableContexts: [{ ...context, displayLabel: 'Server context' }, ...fixtureContexts],
          }
        : { ...state, actor: { ...currentActor, role: 'operator' } },
    );
  });
  render(<PrincipalWorkflow />);
  fireEvent.click(await screen.findByRole('button', { name: 'Enter workspace' }));
  await screen.findByRole('heading', { name: 'Principal governance' });
  expect(performWebAuthnStepUp).toHaveBeenCalledWith(
    expect.objectContaining({ actionIntentId: 'ACT-IDENTITY_CREATE_SESSION-V1' }),
    {
      actionIntentId: 'ACT-IDENTITY_CREATE_SESSION-V1',
      actionIntentDigest: 'sha256:dbc8290dd60814d5bb4248fefc9550f43d0dc97d6333ac232c8ab8a98c3354d2',
      resourceId: context.participantId,
      resourceDigest: `sha256:${createHash('sha256').update(JSON.stringify(context)).digest('hex')}`,
    },
    expect.objectContaining({ signal: expect.any(AbortSignal), isCurrent: expect.any(Function) }),
  );
  const posts = fetcher.mock.calls.filter(([, init]) => init?.method === 'POST');
  expect(posts).toHaveLength(1);
  expect(JSON.parse(String(posts[0]![1]?.body))).toEqual({
    ...context,
    expectedSessionId: sourceSessionId,
  });
});
it.each([
  { name: 'missing contexts', override: { availableContexts: undefined } },
  { name: 'empty contexts', override: { availableContexts: [] } },
  {
    name: 'missing privacy',
    override: { availableContexts: [{ participantId: actor.participantId }] },
  },
  {
    name: 'malformed Participant',
    override: {
      availableContexts: [{ participantId: 'invalid', privacyDomainId: actor.privacyDomainId }],
    },
  },
  { name: 'malformed session', override: { sessionId: 'invalid' } },
  { name: 'missing session', override: { sessionId: undefined } },
])(
  'rejects principal context selection with $name before any proof or POST',
  async ({ override }) => {
    const fetcher = vi
      .spyOn(globalThis, 'fetch')
      .mockResolvedValue(Response.json({ ...session, contextMode: 'PLATFORM', ...override }));
    render(<PrincipalWorkflow />);
    if ('sessionId' in override && override.sessionId === undefined)
      await screen.findByText(
        'Authenticated context could not be confirmed. Refresh before continuing.',
      );
    else {
      fireEvent.click(await screen.findByRole('button', { name: 'Enter workspace' }));
      await screen.findByText(
        'Authenticated context could not be confirmed. Refresh before continuing.',
      );
    }
    expect(performWebAuthnStepUp).not.toHaveBeenCalled();
    expect(fetcher.mock.calls.some(([, init]) => init?.method === 'POST')).toBe(false);
  },
);
it('stops an unmounted principal context digest before ceremony and preserves original custody', async () => {
  const held = principalContextDeferred<ArrayBuffer>();
  const digest = vi.spyOn(crypto.subtle, 'digest').mockReturnValueOnce(held.promise);
  const fetcher = vi
    .spyOn(globalThis, 'fetch')
    .mockResolvedValue(Response.json({ ...session, contextMode: 'PLATFORM' }));
  const view = render(<PrincipalWorkflow />);
  const control = await screen.findByRole('button', { name: 'Enter workspace' });
  const original = JSON.stringify({ actor, value: savedReview() });
  localStorage.setItem('openpc:principal-workflow:v1', original);
  fireEvent.click(control);
  await waitFor(() => expect(digest).toHaveBeenCalledOnce());
  const calls = fetcher.mock.calls.length;
  view.unmount();
  await act(async () => held.resolve(new ArrayBuffer(32)));
  expect(fetcher.mock.calls).toHaveLength(calls);
  expect(performWebAuthnStepUp).not.toHaveBeenCalled();
  expect(localStorage.getItem('openpc:principal-workflow:v1')).toBe(original);
});
it.each([
  ['digest', 'session'],
  ['digest', 'selection'],
  ['proof', 'session'],
  ['proof', 'selection'],
] as const)('fences principal context %s after the source %s changes', async (phase, changed) => {
  let source = { ...session, contextMode: 'PLATFORM' };
  const heldDigest = principalContextDeferred<ArrayBuffer>();
  const digest =
    phase === 'digest'
      ? vi.spyOn(crypto.subtle, 'digest').mockReturnValueOnce(heldDigest.promise)
      : undefined;
  const proof = phase === 'proof' ? holdStepUp() : undefined;
  const fetcher = vi
    .spyOn(globalThis, 'fetch')
    .mockImplementation(async () => Response.json(source));
  render(<PrincipalWorkflow />);
  const control = await screen.findByRole('button', { name: 'Enter workspace' });
  const original = JSON.stringify({ actor, value: savedReview() });
  localStorage.setItem('openpc:principal-workflow:v1', original);
  fireEvent.click(control);
  if (digest) await waitFor(() => expect(digest).toHaveBeenCalledOnce());
  else await waitFor(() => expect(proof!.entered).toHaveBeenCalledOnce());
  source =
    changed === 'session'
      ? { ...source, sessionId: '018f0000-0000-7000-8000-000000000118' }
      : {
          ...source,
          availableContexts: [
            {
              ...fixtureContexts[0]!,
              privacyDomainId: '018f0000-0000-7000-8000-000000007201',
            },
          ],
        };
  await act(async () => {
    if (digest) heldDigest.resolve(new ArrayBuffer(32));
    else {
      proof!.release();
      await proof!.completion();
    }
  });
  await screen.findByText(
    'The working context changed. Refresh the principal page before continuing.',
  );
  expect(performWebAuthnStepUp).toHaveBeenCalledTimes(phase === 'digest' ? 0 : 1);
  expect(fetcher.mock.calls.some(([, init]) => init?.method === 'POST')).toBe(false);
  expect(localStorage.getItem('openpc:principal-workflow:v1')).toBe(original);
});

const principalCommitted = 'Principal change committed and its durable effect read back.';
it.each([
  { name: 'unknown state', result: { truthState: 'UNKNOWN' } },
  { name: 'pending state', result: { truthState: 'PENDING', detail: unsafePrincipalMarker } },
  { name: 'missing state', result: {} },
  { name: 'null result', result: null },
  { name: 'non-string state', result: { truthState: true } },
  { name: 'success without effect', result: { truthState: 'SUCCESS' } },
  { name: 'ambiguity without target', result: { truthState: 'WRITE_AMBIGUITY' } },
  { name: 'reauthentication without target', result: { truthState: 'REAUTH_REQUIRED' } },
])('keeps the original principal unconfirmed after $name', async ({ result }) => {
  const fixture = principalCommitCase();
  const fetcher = mockPrincipalCommit(fixture, result);
  render(<PrincipalWorkflow />);
  fireEvent.click(await screen.findByRole('button', { name: 'Commit approved principal change' }));
  await screen.findByText(principalUnavailable);
  expect(screen.queryByText(principalCommitted)).not.toBeInTheDocument();
  expect(screen.queryByText(/Membership removal committed/u)).not.toBeInTheDocument();
  expect(document.body.textContent).not.toContain(unsafePrincipalMarker);
  expect(fetcher.mock.calls.some(([url]) => String(url).includes('principalId='))).toBe(false);
  expectOriginalPrincipalCommit(fetcher, fixture);
});
it.each(['PROVISION', 'ACTIVATE', 'SUSPEND'] as const)(
  'confirms the reviewed %s only after matching acknowledged and current operation readback',
  async (mutation) => {
    const fixture = principalCommitCase(mutation);
    const fetcher = mockPrincipalCommit(fixture, { ...fixture.readback, truthState: 'SUCCESS' });
    render(<PrincipalWorkflow />);
    fireEvent.click(
      await screen.findByRole('button', { name: 'Commit approved principal change' }),
    );
    await screen.findByText(principalCommitted);
    expect(screen.getByText(`Operation: ${fixture.readback.operationId}`)).toBeVisible();
    expect(
      screen.getByText(
        `${fixture.readback.effect.state} · revision ${fixture.readback.effect.revision}`,
      ),
    ).toBeVisible();
    expect(
      fetcher.mock.calls.filter(([url]) => String(url).includes(`principalId=${principalId}`)),
    ).toHaveLength(1);
    expectOriginalPrincipalCommit(fetcher, fixture);
  },
);
it('confirms coherent human subject and membership readback', async () => {
  const fixture = principalCommitCase('ACTIVATE');
  const outcome = humanPrincipalOutcome(fixture.readback);
  const fetcher = mockPrincipalCommit(fixture, { ...outcome, truthState: 'SUCCESS' }, outcome);
  render(<PrincipalWorkflow />);
  fireEvent.click(await screen.findByRole('button', { name: 'Commit approved principal change' }));
  await screen.findByText(principalCommitted);
  expect(screen.getByText(outcome.humanIdentity.identitySubjectId)).toBeVisible();
  expectOriginalPrincipalCommit(fetcher, fixture);
});
it('confirms a workload principal without requiring a human projection', async () => {
  const fixture = principalCommitCase();
  fixture.value.review.proposedPrincipal.kind = 'WORKLOAD';
  fixture.readback.effect.kind = 'WORKLOAD';
  fixture.stored = JSON.stringify({ actor, value: fixture.value });
  localStorage.setItem('openpc:principal-workflow:v1', fixture.stored);
  const fetcher = mockPrincipalCommit(fixture, { ...fixture.readback, truthState: 'SUCCESS' });
  render(<PrincipalWorkflow />);
  fireEvent.click(await screen.findByRole('button', { name: 'Commit approved principal change' }));
  await screen.findByText(principalCommitted);
  expect(
    screen.queryByRole('heading', { name: 'Human identity and membership' }),
  ).not.toBeInTheDocument();
  expectOriginalPrincipalCommit(fetcher, fixture);
});
it.each(
  ['acknowledgement', 'current readback'].flatMap((boundary) =>
    [
      'other principal',
      'other Participant',
      'other name',
      'other kind',
      'wrong state',
      'unchanged revision',
      'older revision',
      'malformed revision',
      'missing operation',
      'malformed operation',
      'missing epoch',
      'partial human identity',
      'foreign membership',
    ].map((defect) => ({ boundary, defect })),
  ),
)('rejects $defect at principal $boundary', async ({ boundary, defect }) => {
  const fixture = principalCommitCase('SUSPEND');
  const { readback } = fixture;
  const changes = {
    'other principal': { ...readback, effect: { ...readback.effect, principalId: secondId } },
    'other Participant': {
      ...readback,
      effect: { ...readback.effect, participantId: '018f0000-0000-7000-8000-000000000102' },
    },
    'other name': {
      ...readback,
      effect: { ...readback.effect, displayLabel: unsafePrincipalMarker },
    },
    'other kind': { ...readback, effect: { ...readback.effect, kind: 'WORKLOAD' } },
    'wrong state': { ...readback, effect: { ...readback.effect, state: 'ACTIVE' } },
    'unchanged revision': {
      ...readback,
      effect: { ...readback.effect, revision: fixture.value.review.expectedRevision },
    },
    'older revision': { ...readback, effect: { ...readback.effect, revision: '9007199254740992' } },
    'malformed revision': { ...readback, effect: { ...readback.effect, revision: '01' } },
    'missing operation': { ...readback, operationId: null },
    'malformed operation': { ...readback, operationId: 'not-an-operation' },
    'missing epoch': { ...readback, effect: { ...readback.effect, identityEpoch: undefined } },
    'partial human identity': {
      ...readback,
      effect: { ...readback.effect, identitySubjectId: secondId },
    },
    'foreign membership': {
      ...readback,
      effect: { ...readback.effect, identitySubjectId: secondId, membershipId: secondId },
    },
  };
  const invalid = changes[defect as keyof typeof changes];
  const fetcher = mockPrincipalCommit(
    fixture,
    { ...(boundary === 'acknowledgement' ? invalid : readback), truthState: 'SUCCESS' },
    boundary === 'current readback' ? invalid : readback,
  );
  render(<PrincipalWorkflow />);
  fireEvent.click(await screen.findByRole('button', { name: 'Commit approved principal change' }));
  await screen.findByText(
    /Principal (state changed|request could not be confirmed|readback belongs)/u,
  );
  expect(screen.queryByText(principalCommitted)).not.toBeInTheDocument();
  expect(screen.queryByText(`Operation: ${readback.operationId}`)).not.toBeInTheDocument();
  expect(document.body.textContent).not.toContain(unsafePrincipalMarker);
  expect(fetcher.mock.calls.filter(([url]) => String(url).includes('principalId='))).toHaveLength(
    boundary === 'acknowledgement' ? 0 : 1,
  );
  expectOriginalPrincipalCommit(fetcher, fixture);
});
it.each(['operation', 'revision', 'epoch', 'human identity'] as const)(
  'rejects current %s drift even when the principal still has the reviewed target state',
  async (changed) => {
    const fixture = principalCommitCase('SUSPEND');
    const outcome = humanPrincipalOutcome(fixture.readback);
    const current = structuredClone(outcome);
    if (changed === 'operation') current.operationId = '018f0000-0000-7000-8000-000000000852';
    else if (changed === 'revision') {
      current.effect.revision = '9007199254740996';
      current.humanIdentity.revision = current.effect.revision;
    } else if (changed === 'epoch') {
      current.effect.identityEpoch = '5';
      current.humanIdentity.membershipEpoch = '5';
    } else {
      current.effect.identitySubjectId = '018f0000-0000-7000-8000-000000000882';
      current.humanIdentity.identitySubjectId = current.effect.identitySubjectId;
    }
    const fetcher = mockPrincipalCommit(fixture, { ...outcome, truthState: 'SUCCESS' }, current);
    render(<PrincipalWorkflow />);
    fireEvent.click(
      await screen.findByRole('button', { name: 'Commit approved principal change' }),
    );
    await screen.findByText(
      'Principal state changed. Refresh or read the original operation before retrying.',
    );
    expect(screen.queryByText(principalCommitted)).not.toBeInTheDocument();
    expect(screen.queryByText(current.humanIdentity.identitySubjectId)).not.toBeInTheDocument();
    expectOriginalPrincipalCommit(fetcher, fixture);
  },
);
it.each(
  ['acknowledgement', 'current readback'].flatMap((boundary) =>
    ['subject', 'membership', 'Participant', 'state', 'revision', 'epoch'].map((defect) => ({
      boundary,
      defect,
    })),
  ),
)('rejects a conflicting human $defect at principal $boundary', async ({ boundary, defect }) => {
  const fixture = principalCommitCase('ACTIVATE');
  const outcome = humanPrincipalOutcome(fixture.readback);
  const invalid = structuredClone(outcome);
  const identity = invalid.humanIdentity;
  if (defect === 'subject') identity.identitySubjectId = secondId;
  else if (defect === 'membership') identity.membershipId = secondId;
  else if (defect === 'Participant') identity.participantId = secondId;
  else if (defect === 'state') identity.state = 'SUSPENDED';
  else if (defect === 'revision') identity.revision = '9007199254740994';
  else identity.membershipEpoch = '3';
  const fetcher = mockPrincipalCommit(
    fixture,
    { ...(boundary === 'acknowledgement' ? invalid : outcome), truthState: 'SUCCESS' },
    boundary === 'current readback' ? invalid : outcome,
  );
  render(<PrincipalWorkflow />);
  fireEvent.click(await screen.findByRole('button', { name: 'Commit approved principal change' }));
  await screen.findByText(
    'Principal state changed. Refresh or read the original operation before retrying.',
  );
  expect(screen.queryByText(principalCommitted)).not.toBeInTheDocument();
  expect(screen.queryByText(`Operation: ${outcome.operationId}`)).not.toBeInTheDocument();
  expectOriginalPrincipalCommit(fetcher, fixture);
});
it.each(['WRITE_AMBIGUITY', 'PENDING'])(
  'retains original custody after %s and uses only GET for the requested authoritative read',
  async (truthState) => {
    const fixture = principalCommitCase();
    const fetcher = mockPrincipalCommit(
      fixture,
      { truthState, principalId, reconciliation: 'READ_AUTHORITATIVE_EFFECT' },
      { ...fixture.readback, operationId: null },
    );
    render(<PrincipalWorkflow />);
    fireEvent.click(
      await screen.findByRole('button', { name: 'Commit approved principal change' }),
    );
    await screen.findByText(
      truthState === 'WRITE_AMBIGUITY'
        ? 'The response was lost. Read the principal before retrying.'
        : principalUnavailable,
    );
    expect(fetcher.mock.calls.some(([url]) => String(url).includes('principalId='))).toBe(false);
    fireEvent.click(screen.getByRole('button', { name: 'Find principal' }));
    await screen.findByText('PROVISIONED · revision 1');
    expect(screen.queryByText(principalCommitted)).not.toBeInTheDocument();
    expect(fetcher.mock.calls.filter(([url]) => String(url).includes('principalId='))).toHaveLength(
      1,
    );
    expectOriginalPrincipalCommit(fetcher, fixture);
  },
);
it.each(['wrong target', 'wrong reconciliation', 'not removal', 'wrong removal state'])(
  'does not retire the current principal context for reauthentication with %s',
  async (defect) => {
    const fixture = principalCommitCase(defect === 'not removal' ? 'SUSPEND' : 'REMOVE');
    if (defect === 'wrong removal state') {
      fixture.value.review.proposedPrincipal.state = 'SUSPENDED';
      fixture.stored = JSON.stringify({ actor, value: fixture.value });
      localStorage.setItem('openpc:principal-workflow:v1', fixture.stored);
    }
    const fetcher = mockPrincipalCommit(fixture, {
      truthState: 'REAUTH_REQUIRED',
      principalId: defect === 'wrong target' ? secondId : principalId,
      reconciliation:
        defect === 'wrong reconciliation' ? 'RETRY' : 'SIGN_IN_THEN_READ_AUTHORITATIVE_EFFECT',
    });
    render(<PrincipalWorkflow />);
    fireEvent.click(
      await screen.findByRole('button', { name: 'Commit approved principal change' }),
    );
    await screen.findByText(/Principal (state changed|request could not be confirmed)/u);
    expect(screen.getByRole('heading', { name: 'Principal governance' })).toBeVisible();
    expect(screen.queryByText(/Membership removal committed/u)).not.toBeInTheDocument();
    expect(fetcher.mock.calls.some(([url]) => String(url).includes('principalId='))).toBe(false);
    expectOriginalPrincipalCommit(fetcher, fixture);
  },
);
it.each(['wrong target', 'wrong reconciliation'])(
  'does not accept principal ambiguity with %s as the original operation result',
  async (defect) => {
    const fixture = principalCommitCase();
    const fetcher = mockPrincipalCommit(fixture, {
      truthState: 'WRITE_AMBIGUITY',
      principalId: defect === 'wrong target' ? secondId : principalId,
      reconciliation: defect === 'wrong reconciliation' ? 'RETRY' : 'READ_AUTHORITATIVE_EFFECT',
    });
    render(<PrincipalWorkflow />);
    fireEvent.click(
      await screen.findByRole('button', { name: 'Commit approved principal change' }),
    );
    await screen.findByText(/Principal (state changed|request could not be confirmed)/u);
    expect(
      screen.queryByText('The response was lost. Read the principal before retrying.'),
    ).not.toBeInTheDocument();
    expectOriginalPrincipalCommit(fetcher, fixture);
  },
);
it.each(['acknowledgement', 'readback'] as const)(
  'preserves a newer principal selection when the old commit %s arrives',
  async (phase) => {
    const fixture = principalCommitCase();
    const held = deferredResponse();
    const fetcher = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      if (init?.method === 'POST')
        return phase === 'acknowledgement'
          ? held.promise
          : Response.json({ ...fixture.readback, truthState: 'SUCCESS' });
      const url = String(input);
      if (url === '/api/v1/ui/local-session') return Response.json(session);
      if (url.includes(`principalId=${secondId}`))
        return Response.json(selectedState(secondId, 'Newer selection'));
      if (url.includes(`principalId=${principalId}`)) return held.promise;
      return Response.json(fixture.approved);
    });
    render(<PrincipalWorkflow />);
    fireEvent.click(
      await screen.findByRole('button', { name: 'Commit approved principal change' }),
    );
    await waitFor(() =>
      expect(
        fetcher.mock.calls.some(([url, init]) =>
          phase === 'acknowledgement'
            ? init?.method === 'POST'
            : String(url).includes(`principalId=${principalId}`),
        ),
      ).toBe(true),
    );
    fireEvent.click(screen.getByRole('button', { name: 'Open second principal' }));
    await screen.findByText('Newer selection');
    const count = fetcher.mock.calls.length;
    await act(async () =>
      held.resolve(
        Response.json(
          phase === 'acknowledgement'
            ? { ...fixture.readback, truthState: 'SUCCESS' }
            : { ...fixture.approved, effect: fixture.readback },
        ),
      ),
    );
    expect(fetcher.mock.calls).toHaveLength(count);
    expect(screen.getByText('Newer selection')).toBeVisible();
    expect(screen.queryByText(principalCommitted)).not.toBeInTheDocument();
    expectOriginalPrincipalCommit(fetcher, fixture);
  },
);
it.each(['SUCCESS', 'REAUTH_REQUIRED'] as const)(
  'does not apply a late principal %s to another authenticated actor',
  async (truthState) => {
    const fixture = principalCommitCase(truthState === 'REAUTH_REQUIRED' ? 'REMOVE' : 'PROVISION');
    const held = deferredResponse();
    let currentSession = session;
    const fetcher = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      if (init?.method === 'POST') return held.promise;
      if (String(input) === '/api/v1/ui/local-session') return Response.json(currentSession);
      return Response.json({
        ...fixture.approved,
        approvals: currentSession === session ? fixture.approved.approvals : [],
        actor: { ...currentSession, role: 'operator' },
      });
    });
    render(<PrincipalWorkflow />);
    fireEvent.click(
      await screen.findByRole('button', { name: 'Commit approved principal change' }),
    );
    await waitFor(() =>
      expect(fetcher.mock.calls.some(([, init]) => init?.method === 'POST')).toBe(true),
    );
    currentSession = {
      ...session,
      sessionId: '018f0000-0000-7000-8000-000000000118',
      principalId: '018f0000-0000-7000-8000-000000000112',
    };
    fireEvent.click(screen.getByRole('button', { name: 'Open second principal' }));
    await waitFor(() =>
      expect(screen.queryByText('Private draft principal')).not.toBeInTheDocument(),
    );
    const count = fetcher.mock.calls.length;
    await act(async () =>
      held.resolve(
        Response.json(
          truthState === 'SUCCESS'
            ? { ...fixture.readback, truthState }
            : { truthState, principalId, reconciliation: 'SIGN_IN_THEN_READ_AUTHORITATIVE_EFFECT' },
        ),
      ),
    );
    expect(fetcher.mock.calls).toHaveLength(count);
    expect(screen.getByRole('heading', { name: 'Principal governance' })).toBeVisible();
    expect(screen.queryByText(principalCommitted)).not.toBeInTheDocument();
    expect(screen.queryByText(/Membership removal committed/u)).not.toBeInTheDocument();
    expect(fetcher.mock.calls.filter(([, init]) => init?.method === 'POST')).toHaveLength(1);
    expect(localStorage.getItem('openpc:principal-workflow:v1')).toBeNull();
  },
);

it('restores mismatched original custody for refresh and read without another POST', async () => {
  const fixture = principalCommitCase('SUSPEND');
  let selectedReads = 0;
  const fetcher = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
    if (init?.method === 'POST')
      return Response.json({ ...fixture.readback, truthState: 'SUCCESS' });
    if (String(input) === '/api/v1/ui/local-session') return Response.json(session);
    if (String(input).includes('principalId=')) {
      selectedReads += 1;
      return Response.json({
        ...fixture.approved,
        effect: {
          ...fixture.readback,
          effect: {
            ...fixture.readback.effect,
            state: selectedReads === 1 ? 'ACTIVE' : 'SUSPENDED',
          },
        },
      });
    }
    return Response.json(fixture.approved);
  });
  render(<PrincipalWorkflow />);
  fireEvent.click(await screen.findByRole('button', { name: 'Commit approved principal change' }));
  await screen.findByText(
    'Principal state changed. Refresh or read the original operation before retrying.',
  );
  expect(screen.queryByText(principalCommitted)).not.toBeInTheDocument();
  expectOriginalPrincipalCommit(fetcher, fixture);
  fireEvent.click(screen.getByRole('button', { name: 'Refresh principal approvals' }));
  await screen.findByRole('heading', { name: 'Principal governance' });
  expect(screen.getByLabelText('Principal ID')).toHaveValue(principalId);
  fireEvent.click(screen.getByRole('button', { name: 'Find principal' }));
  await screen.findByText('SUSPENDED · revision 9007199254740995');
  expect(screen.queryByText(principalCommitted)).not.toBeInTheDocument();
  expect(selectedReads).toBe(2);
  expectOriginalPrincipalCommit(fetcher, fixture);
});

it('restores an executed principal request without offering another commit or granting a fresh effect', async () => {
  const fixture = principalCommitCase('ACTIVATE');
  const consumed = {
    ...fixture.approved,
    approvals: fixture.approved.approvals.map((item) => ({
      ...item,
      proposal: { ...item.proposal, state: 'CONSUMED' },
    })),
  };
  const fetcher = vi
    .spyOn(globalThis, 'fetch')
    .mockImplementation(async (input) =>
      Response.json(String(input) === '/api/v1/ui/local-session' ? session : consumed),
    );
  render(<PrincipalWorkflow />);
  await screen.findByRole('heading', { name: 'Executed request' });
  expect(screen.getByText(/This request has been executed/u)).toBeVisible();
  expect(
    screen.queryByRole('button', { name: 'Commit approved principal change' }),
  ).not.toBeInTheDocument();
  expect(screen.queryByText(principalCommitted)).not.toBeInTheDocument();
  expect(screen.queryByText(`Operation: ${fixture.readback.operationId}`)).not.toBeInTheDocument();
  expect(performWebAuthnStepUp).not.toHaveBeenCalled();
  expect(fetcher.mock.calls.some(([, init]) => init?.method === 'POST')).toBe(false);
  expect(localStorage.getItem('openpc:principal-workflow:v1')).toBe(fixture.stored);
});

it.each(['approval', 'digest', 'mutation', 'revision', 'principal'] as const)(
  'does not label a saved principal request executed from a mismatched %s',
  async (field) => {
    const fixture = principalCommitCase('ACTIVATE');
    const item = fixture.approved.approvals[0]!;
    const consumed = {
      ...item,
      ...(field === 'approval'
        ? { approvalRequestId: '018f0000-0000-7000-8000-000000000802' }
        : {}),
      ...(field === 'digest' ? { candidateDigest: 'sha256:another-candidate' } : {}),
      proposal: {
        ...item.proposal,
        state: 'CONSUMED',
        ...(field === 'mutation' ? { mutation: 'SUSPEND' } : {}),
        ...(field === 'revision' ? { expectedRevision: '9007199254740994' } : {}),
        proposedPrincipal: {
          ...item.proposal.proposedPrincipal,
          ...(field === 'principal' ? { principalId: secondId } : {}),
        },
      },
    };
    const fetcher = vi
      .spyOn(globalThis, 'fetch')
      .mockImplementation(async (input) =>
        Response.json(
          String(input) === '/api/v1/ui/local-session'
            ? session
            : { ...fixture.approved, approvals: [consumed] },
        ),
      );
    render(<PrincipalWorkflow />);
    await screen.findByRole('heading', { name: 'Principal governance' });
    expect(screen.queryByRole('heading', { name: 'Executed request' })).not.toBeInTheDocument();
    expect(
      screen.queryByRole('button', { name: 'Commit approved principal change' }),
    ).not.toBeInTheDocument();
    expect(fetcher.mock.calls.some(([, init]) => init?.method === 'POST')).toBe(false);
    expect(localStorage.getItem('openpc:principal-workflow:v1')).toBe(fixture.stored);
  },
);

it('cancels a held principal commit ceremony when native refresh confirms the original request was consumed', async () => {
  const fixture = principalCommitCase();
  let consumed = false;
  const held = holdStepUp();
  const fetcher = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) =>
    Response.json(
      String(input) === '/api/v1/ui/local-session'
        ? session
        : {
            ...fixture.approved,
            approvals: fixture.approved.approvals.map((item) => ({
              ...item,
              proposal: { ...item.proposal, state: consumed ? 'CONSUMED' : 'APPROVED' },
            })),
            ...(String(input).includes('principalId=') ? { effect: fixture.readback } : {}),
          },
    ),
  );
  render(<PrincipalWorkflow />);
  fireEvent.click(await screen.findByRole('button', { name: 'Commit approved principal change' }));
  await waitFor(() => expect(held.entered).toHaveBeenCalledOnce());
  const completion = expect(held.completion()).rejects.toMatchObject({ name: 'AbortError' });
  consumed = true;
  fireEvent.click(screen.getByRole('button', { name: 'Open first principal' }));
  await screen.findByRole('heading', { name: 'Executed request' });
  expect(held.lifecycle().signal?.aborted).toBe(true);
  await act(async () => {
    held.release();
    await completion;
  });
  expect(fetcher.mock.calls.some(([, init]) => init?.method === 'POST')).toBe(false);
  expect(localStorage.getItem('openpc:principal-workflow:v1')).toBe(fixture.stored);
});

it.each(['operator', 'viewer'])(
  'shows a native consumed request in the %s history without needing its old browser draft',
  async (role) => {
    const item = principalApproval('APPROVED');
    const fetcher = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) =>
      Response.json(
        String(input) === '/api/v1/ui/local-session'
          ? session
          : {
              ...state,
              actor: { ...actor, role },
              approvals: [{ ...item, proposal: { ...item.proposal, state: 'CONSUMED' } }],
            },
      ),
    );
    render(<PrincipalWorkflow />);
    await screen.findByRole('heading', { name: 'Provision principal · Executed' });
    expect(
      screen.queryByRole('button', { name: 'Commit approved principal change' }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole('button', { name: 'Approve Private draft principal' }),
    ).not.toBeInTheDocument();
    expect(performWebAuthnStepUp).not.toHaveBeenCalled();
    expect(fetcher.mock.calls.some(([, init]) => init?.method === 'POST')).toBe(false);
    expect(localStorage.getItem('openpc:principal-workflow:v1')).toBeNull();
  },
);
