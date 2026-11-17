import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, expect, it, vi } from 'vitest';
import { performWebAuthnStepUp } from '@openpc/ui-shell';
import { AccessReviewWorkflow } from './access-review-workflow';
vi.mock('@openpc/ui-shell', () => ({ performWebAuthnStepUp: vi.fn() }));
vi.mock('./local-session', () => ({ LocalSessionSurface: () => <p>Sign in</p> }));
const id = (n: number) => `018f0000-0000-7000-8000-${String(n).padStart(12, '0')}`;
const actor = {
  sessionId: id(1),
  principalId: id(2),
  participantId: id(3),
  privacyDomainId: id(4),
  contextEpoch: '1',
};
const page = {
  authoritative: false,
  participantId: id(3),
  privacyDomainId: id(4),
  subject: { id: id(5), kind: 'USER', state: 'ACTIVE', authorityEpoch: '1' },
  participantEpoch: '1',
  observedAt: new Date().toISOString(),
  items: [],
  nextCursor: null,
  completeness: 'COMPLETE',
  authorizedEmpty: true,
  decisionBoundary: 'CURRENT_GRANT_INTERSECTION_REQUIRES_LIVE_REQUEST_AUTHORIZATION',
};
afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  vi.clearAllMocks();
});
it.each([false, true])(
  'reads current access and conceals it when context changes: %s',
  async (changed) => {
    let fetched = false;
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (url) => {
      if (String(url).includes('/access-review?')) {
        fetched = true;
        return Response.json({ actor, page });
      }
      return Response.json({
        ...actor,
        ...(changed && fetched ? { contextEpoch: '2' } : {}),
        authenticated: true,
        contextMode: 'PARTICIPANT',
      });
    });
    render(<AccessReviewWorkflow />);
    const user = userEvent.setup();
    await user.type(await screen.findByLabelText('Principal ID to review'), id(5));
    await user.click(screen.getByRole('button', { name: 'Review current access' }));
    if (changed) {
      await screen.findByText('The context changed. Refresh the review.');
      expect(screen.queryByText(/No assignments or delegation paths/u)).not.toBeInTheDocument();
    } else {
      await waitFor(() =>
        expect(screen.getByText(/No assignments or delegation paths/u)).toBeVisible(),
      );
      await user.clear(screen.getByLabelText('Principal ID to review'));
      expect(screen.queryByText(/No assignments or delegation paths/u)).not.toBeInTheDocument();
    }
  },
);

function deferred<T = Response>() {
  let resolve!: (value: T) => void;
  let reject!: (cause: unknown) => void;
  const promise = new Promise<T>((yes, no) => {
    resolve = yes;
    reject = no;
  });
  return { promise, resolve, reject };
}
const sessionValue = (value = actor) => ({
  ...value,
  authenticated: true,
  contextMode: 'PARTICIPANT',
});
const emptyPage = (subject = id(5), value = actor) => ({
  ...page,
  participantId: value.participantId,
  privacyDomainId: value.privacyDomainId,
  subject: { ...page.subject, id: subject },
});
async function focus() {
  await act(async () => {
    window.dispatchEvent(new Event('focus'));
  });
}
async function chooseSubject(subject = id(5)) {
  fireEvent.change(await screen.findByLabelText('Principal ID to review'), {
    target: { value: subject },
  });
  await userEvent.setup().click(screen.getByRole('button', { name: 'Review current access' }));
}
function grantPage() {
  const scope = {
    privacyDomainIds: [actor.privacyDomainId],
    actionIntentIds: ['ACT-IDENTITY_CREATE_SESSION-V1'],
    capabilityIds: ['CALL_RESULT_DISCLOSURE'],
    resourceIds: ['urn:openpc:resource:example'],
    riskClasses: ['LOW'],
    validFrom: '2026-01-01T00:00:00.000Z',
    validUntil: null,
    makerCheckerRequired: true,
    stepUpRequired: true,
    onwardDelegationDepth: 1,
  };
  const common = {
    ...scope,
    participantId: actor.participantId,
    scopeDigest: `sha256:${'a'.repeat(64)}`,
    delegationEpoch: '1',
    state: 'ACTIVE',
  };
  const assignment = { ...common, id: id(10), principalId: id(5), authorityEnvelopeId: id(12) };
  const delegation = {
    ...common,
    id: id(11),
    parentId: id(10),
    grantorId: id(6),
    granteeId: id(5),
  };
  const ancestry = [{ id: id(10), kind: 'assignment', revision: '1', state: 'ACTIVE' }];
  const item = {
    assignmentId: id(10),
    envelopeId: id(12),
    envelopeEpoch: '1',
    constraints: {
      ...scope,
      participantId: actor.participantId,
    },
    current: true,
    reasons: [],
  };
  return {
    ...emptyPage(),
    authorizedEmpty: false,
    items: [
      {
        ...item,
        grant: { effect: assignment, revision: '1', operationId: id(20) },
        ancestry,
        remediation: { id: id(10), kind: 'assignment', revision: '1' },
      },
      {
        ...item,
        grant: { effect: delegation, revision: '2', operationId: id(21) },
        ancestry: [...ancestry, { id: id(11), kind: 'delegation', revision: '2', state: 'ACTIVE' }],
        current: false,
        reasons: ['DELEGATION_NOT_CURRENT'],
        remediation: { id: id(11), kind: 'delegation', revision: '2' },
      },
    ],
  };
}
it('renders assignments and delegations as explanation with supported remediation and live authorization', async () => {
  const fetcher = vi
    .spyOn(globalThis, 'fetch')
    .mockImplementation(async (url) =>
      Response.json(
        String(url).includes('/access-review?') ? { actor, page: grantPage() } : sessionValue(),
      ),
    );
  render(<AccessReviewWorkflow />);
  await chooseSubject();
  expect(await screen.findByRole('heading', { name: `Assignment ${id(10)}` })).toBeVisible();
  expect(screen.getByRole('heading', { name: `Delegation ${id(11)}` })).toBeVisible();
  expect(screen.getByText('The delegation no longer fits its parent authority.')).toBeVisible();
  expect(screen.getByText(/Every action still requires a live platform/u)).toBeVisible();
  const assignmentCard = screen
    .getByRole('heading', { name: `Assignment ${id(10)}` })
    .closest('article')!;
  const inspect = within(assignmentCard).getByRole('button', {
    name: 'Administrative actions, resources and authority path',
  });
  const callsBeforeInspection = fetcher.mock.calls.length;
  fireEvent.click(inspect);
  const details = await screen.findByRole('dialog', {
    name: 'Administrative actions, resources and authority path',
  });
  expect(within(details).getByText(/ACT-IDENTITY_CREATE_SESSION-V1/u)).toBeVisible();
  fireEvent.click(
    within(details).getByRole('button', {
      name: 'Close Administrative actions, resources and authority path',
    }),
  );
  await waitFor(() => expect(inspect).toHaveFocus());
  expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  expect(fetcher.mock.calls).toHaveLength(callsBeforeInspection);
  expect(
    screen.getByRole('link', { name: 'Review revocation of this delegation' }),
  ).toHaveAttribute('href', `/govern/memberships?view=grants&grantId=${id(11)}&kind=delegation`);
  expect(fetcher.mock.calls.every(([, init]) => !init?.method || init.method === 'GET')).toBe(true);
});
it.each(['success', 'failure'] as const)(
  'does not let an obsolete first session %s issue a subject read or replace newer results',
  async (outcome) => {
    const old = deferred();
    let sessions = 0;
    const fetcher = vi.spyOn(globalThis, 'fetch').mockImplementation(async (url) => {
      if (String(url).includes('/access-review?')) {
        const target = new URL(String(url), 'http://localhost').searchParams.get('subjectId')!;
        return Response.json({ actor, page: emptyPage(target) });
      }
      return ++sessions === 2 ? old.promise : Response.json(sessionValue());
    });
    render(<AccessReviewWorkflow />);
    await chooseSubject();
    fireEvent.change(screen.getByLabelText('Principal ID to review'), { target: { value: id(6) } });
    await userEvent.setup().click(screen.getByRole('button', { name: 'Review current access' }));
    await screen.findByText(id(6), { selector: 'dd' });
    await act(async () => {
      if (outcome === 'success') old.resolve(Response.json(sessionValue()));
      else old.reject(new Error('obsolete session failure'));
    });
    expect(
      fetcher.mock.calls
        .filter(([url]) => String(url).includes('/access-review?'))
        .map(([url]) => new URL(String(url), 'http://localhost').searchParams.get('subjectId')),
    ).toEqual([id(6)]);
    expect(screen.getByText(id(6), { selector: 'dd' })).toBeVisible();
    expect(screen.getByRole('status')).not.toHaveTextContent('obsolete');
  },
);
it.each(['success', 'failure'] as const)(
  'does not let an obsolete access %s issue the after-session read or clear newer busy state',
  async (outcome) => {
    const old = deferred(),
      latest = deferred();
    let sessions = 0;
    let reads = 0;
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (url) => {
      if (String(url).includes('/access-review?'))
        return ++reads === 1 ? old.promise : latest.promise;
      sessions++;
      return Response.json(sessionValue());
    });
    render(<AccessReviewWorkflow />);
    await chooseSubject();
    await waitFor(() => expect(reads).toBe(1));
    fireEvent.change(screen.getByLabelText('Principal ID to review'), { target: { value: id(6) } });
    await userEvent.setup().click(screen.getByRole('button', { name: 'Review current access' }));
    await waitFor(() => expect(reads).toBe(2));
    const before = sessions;
    await act(async () => {
      if (outcome === 'success') old.resolve(Response.json({ actor, page }));
      else old.reject(new Error('obsolete access failure'));
    });
    expect(sessions).toBe(before);
    expect(screen.getByRole('button', { name: 'Review current access' })).toBeDisabled();
    expect(screen.getByRole('status')).not.toHaveTextContent('obsolete');
    await act(async () => latest.resolve(Response.json({ actor, page: emptyPage(id(6)) })));
    expect(await screen.findByText(id(6), { selector: 'dd' })).toBeVisible();
  },
);
it('fences a delayed JSON body before the next session phase', async () => {
  const body = deferred<unknown>();
  let sessions = 0;
  const response = Response.json({});
  vi.spyOn(response, 'json').mockReturnValue(body.promise);
  vi.spyOn(globalThis, 'fetch').mockImplementation(async (url) => {
    if (String(url).includes('/access-review?')) return response;
    sessions++;
    return Response.json(sessionValue());
  });
  render(<AccessReviewWorkflow />);
  await chooseSubject();
  await waitFor(() => expect(response.json).toHaveBeenCalled());
  fireEvent.change(screen.getByLabelText('Principal ID to review'), { target: { value: id(6) } });
  await act(async () => body.resolve({ actor, page }));
  expect(sessions).toBe(2);
  expect(screen.queryByText(/No assignments or delegation paths/u)).not.toBeInTheDocument();
});
it('keeps the newer actor and projection when an obsolete after-session read settles', async () => {
  const old = deferred();
  let sessions = 0;
  const nextActor = { ...actor, privacyDomainId: id(40), contextEpoch: '2' };
  vi.spyOn(globalThis, 'fetch').mockImplementation(async (url) => {
    if (String(url).includes('/access-review?'))
      return Response.json({
        actor: sessions < 3 ? actor : nextActor,
        page: emptyPage(
          new URL(String(url), 'http://localhost').searchParams.get('subjectId')!,
          sessions < 3 ? actor : nextActor,
        ),
      });
    sessions++;
    return sessions === 3
      ? old.promise
      : Response.json(sessionValue(sessions > 3 ? nextActor : actor));
  });
  render(<AccessReviewWorkflow />);
  await chooseSubject();
  await waitFor(() => expect(sessions).toBe(3));
  await focus();
  await screen.findByText(id(40), { selector: 'dd' });
  await chooseSubject(id(6));
  await screen.findByText(id(6), { selector: 'dd' });
  await act(async () => old.resolve(Response.json(sessionValue())));
  expect(screen.getByText(id(40), { selector: 'dd' })).toBeVisible();
  expect(screen.getByText(id(6), { selector: 'dd' })).toBeVisible();
});
it.each(['denial', 'malformed', 'unreadable', 'transport'] as const)(
  'purges current private projection on %s session failure and uses a GET retry',
  async (mode) => {
    let failed = false;
    const fetcher = vi.spyOn(globalThis, 'fetch').mockImplementation(async (url) => {
      if (String(url).includes('/access-review?')) return Response.json({ actor, page });
      if (failed) {
        if (mode === 'denial') return Response.json({ title: 'Read denied' }, { status: 403 });
        if (mode === 'malformed')
          return Response.json({ ...sessionValue(), contextEpoch: 'private-invalid-epoch' });
        if (mode === 'unreadable') return new Response('not-json', { status: 200 });
        throw new Error('Session read unavailable');
      }
      return Response.json(sessionValue());
    });
    render(<AccessReviewWorkflow />);
    await chooseSubject();
    await screen.findByText(/No assignments or delegation paths/u);
    failed = true;
    await focus();
    await screen.findByRole('button', { name: 'Refresh review session' });
    expect(screen.queryByText(/No assignments or delegation paths/u)).not.toBeInTheDocument();
    expect(screen.queryByLabelText('Principal ID to review')).not.toBeInTheDocument();
    expect(screen.queryByText('Sign in')).not.toBeInTheDocument();
    expect(screen.getByRole('status')).not.toHaveTextContent('private-invalid-epoch');
    failed = false;
    await userEvent.setup().click(screen.getByRole('button', { name: 'Refresh review session' }));
    expect(await screen.findByLabelText('Principal ID to review')).toBeVisible();
    expect(fetcher.mock.calls.every(([, init]) => !init?.method || init.method === 'GET')).toBe(
      true,
    );
  },
);
it.each([
  { subject: { ...page.subject, id: id(99) } },
  { participantId: id(99) },
  { privacyDomainId: id(99) },
  { authorizedEmpty: false },
  { completeness: 'MORE' },
  { nextCursor: `assignment:${id(10)}` },
  { items: [{ privateInvalidGrant: 'must not leak' }] },
])('rejects a schema-invalid or context-inconsistent access page: %o', async (change) => {
  vi.spyOn(globalThis, 'fetch').mockImplementation(async (url) =>
    Response.json(
      String(url).includes('/access-review?')
        ? { actor, page: { ...page, ...change } }
        : sessionValue(),
    ),
  );
  render(<AccessReviewWorkflow />);
  await chooseSubject();
  await waitFor(() =>
    expect(screen.getByRole('status')).toHaveTextContent(/invalid|does not match/u),
  );
  expect(screen.queryByText(/No assignments or delegation paths/u)).not.toBeInTheDocument();
  expect(screen.queryByRole('button', { name: 'Next authority paths' })).not.toBeInTheDocument();
  expect(screen.getByRole('status')).not.toHaveTextContent('must not leak');
});
it('does not reuse a cursor after the authoritative before-session actor changes', async () => {
  let changed = false;
  let reads = 0;
  vi.spyOn(globalThis, 'fetch').mockImplementation(async (url) => {
    if (String(url).includes('/access-review?')) {
      reads++;
      return Response.json({
        actor,
        page: { ...grantPage(), completeness: 'MORE', nextCursor: `assignment:${id(10)}` },
      });
    }
    return Response.json(sessionValue(changed ? { ...actor, contextEpoch: '2' } : actor));
  });
  render(<AccessReviewWorkflow />);
  await chooseSubject();
  await screen.findByRole('button', { name: 'Next authority paths' });
  changed = true;
  await userEvent.setup().click(screen.getByRole('button', { name: 'Next authority paths' }));
  await screen.findByText('The context changed. Refresh the review.');
  expect(reads).toBe(1);
  expect(screen.queryByRole('button', { name: 'Next authority paths' })).not.toBeInTheDocument();
});
it('reads a compatible next page and starts a different subject without that cursor', async () => {
  const queries: URLSearchParams[] = [];
  vi.spyOn(globalThis, 'fetch').mockImplementation(async (url) => {
    if (!String(url).includes('/access-review?')) return Response.json(sessionValue());
    const query = new URL(String(url), 'http://localhost').searchParams;
    queries.push(query);
    return Response.json({
      actor,
      page:
        queries.length === 1
          ? {
              ...grantPage(),
              completeness: 'MORE',
              nextCursor: `assignment:${id(10)}`,
            }
          : emptyPage(query.get('subjectId')!),
    });
  });
  render(<AccessReviewWorkflow />);
  await chooseSubject();
  await userEvent
    .setup()
    .click(await screen.findByRole('button', { name: 'Next authority paths' }));
  await screen.findByText(/No assignments or delegation paths/u);
  await chooseSubject(id(6));
  await screen.findByText(id(6), { selector: 'dd' });
  expect(queries.map((query) => [query.get('subjectId'), query.get('after')])).toEqual([
    [id(5), null],
    [id(5), `assignment:${id(10)}`],
    [id(6), null],
  ]);
});
it.each(['success', 'failure'] as const)(
  'ignores an obsolete focus session %s after a newer success',
  async (outcome) => {
    const old = deferred();
    let sessions = 0;
    const nextActor = { ...actor, privacyDomainId: id(40), contextEpoch: '2' };
    vi.spyOn(globalThis, 'fetch').mockImplementation(async () => {
      sessions++;
      return sessions === 2
        ? old.promise
        : Response.json(sessionValue(sessions > 2 ? nextActor : actor));
    });
    render(<AccessReviewWorkflow />);
    await screen.findByLabelText('Principal ID to review');
    await focus();
    await focus();
    await screen.findByText(id(40), { selector: 'dd' });
    await act(async () => {
      if (outcome === 'success') old.resolve(Response.json(sessionValue()));
      else old.reject(new Error('obsolete focus failure'));
    });
    expect(screen.getByText(id(40), { selector: 'dd' })).toBeVisible();
    expect(screen.getByRole('status')).not.toHaveTextContent('obsolete');
  },
);
it('does not allow an old focus success to restore a current denied session', async () => {
  const old = deferred();
  let sessions = 0;
  vi.spyOn(globalThis, 'fetch').mockImplementation(async () => {
    sessions++;
    return sessions === 2
      ? old.promise
      : sessions === 3
        ? Response.json({ title: 'Current denial' }, { status: 403 })
        : Response.json(sessionValue());
  });
  render(<AccessReviewWorkflow />);
  await screen.findByLabelText('Principal ID to review');
  await focus();
  await focus();
  await screen.findByText('Current denial');
  await act(async () => old.resolve(Response.json(sessionValue())));
  expect(screen.queryByLabelText('Principal ID to review')).not.toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Refresh review session' })).toBeVisible();
});
it('aborts an unmounted access reader and never starts its dependent session phase', async () => {
  const pending = deferred();
  let signal: AbortSignal | null | undefined;
  let sessions = 0;
  vi.spyOn(globalThis, 'fetch').mockImplementation(async (url, init) => {
    if (String(url).includes('/access-review?')) {
      signal = init?.signal;
      return pending.promise;
    }
    sessions++;
    return Response.json(sessionValue());
  });
  const view = render(<AccessReviewWorkflow />);
  await chooseSubject();
  await waitFor(() => expect(signal).toBeDefined());
  view.unmount();
  expect(signal?.aborted).toBe(true);
  await act(async () => pending.resolve(Response.json({ actor, page })));
  expect(sessions).toBe(2);
});
it.each([false, true])(
  'keeps genuine anonymous and authenticated global-context controls: %s',
  async (authenticated) => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      Response.json({ authenticated, contextMode: 'GLOBAL' }),
    );
    render(<AccessReviewWorkflow />);
    if (authenticated)
      expect(await screen.findByRole('button', { name: 'Enter workspace' })).toBeVisible();
    else expect(await screen.findByText('Sign in')).toBeVisible();
    expect(screen.queryByLabelText('Principal ID to review')).not.toBeInTheDocument();
  },
);

it.each(['sessionId', 'principalId', 'participantId', 'privacyDomainId', 'contextEpoch'] as const)(
  'rejects a foreign response actor binding in %s even when both local-session reads agree',
  async (field) => {
    let sessions = 0;
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (url) => {
      if (String(url).includes('/access-review?'))
        return Response.json({
          actor: {
            ...actor,
            [field]: field === 'contextEpoch' ? '2' : id(99),
          },
          page,
        });
      sessions++;
      return Response.json(sessionValue());
    });
    render(<AccessReviewWorkflow />);
    await chooseSubject();
    await screen.findByText('The context changed. Refresh the review.');
    expect(sessions).toBe(3);
    expect(screen.queryByText(/No assignments or delegation paths/u)).not.toBeInTheDocument();
  },
);
it('keeps a current access denial distinct from an empty success and allows a fresh public read', async () => {
  let denied = false;
  vi.spyOn(globalThis, 'fetch').mockImplementation(async (url) => {
    if (String(url).includes('/access-review?'))
      return denied
        ? Response.json({ title: 'Access review denied' }, { status: 403 })
        : Response.json({ actor, page });
    return Response.json(sessionValue());
  });
  render(<AccessReviewWorkflow />);
  await chooseSubject();
  await screen.findByText(/No assignments or delegation paths/u);
  denied = true;
  await userEvent.setup().click(screen.getByRole('button', { name: 'Review current access' }));
  await screen.findByText('Access review denied');
  expect(screen.queryByText(/No assignments or delegation paths/u)).not.toBeInTheDocument();
  denied = false;
  await userEvent.setup().click(screen.getByRole('button', { name: 'Review current access' }));
  expect(await screen.findByText(/No assignments or delegation paths/u)).toBeVisible();
});

it('preserves the existing context-selection command and step-up while coalescing its focus refresh', async () => {
  const pending = deferred();
  let selected = false;
  let sessions = 0;
  const posts: { url: string; body: unknown }[] = [];
  const selectedActor = { ...actor, participantId: id(101), privacyDomainId: id(201) };
  vi.spyOn(globalThis, 'fetch').mockImplementation(async (url, init) => {
    if (init?.method === 'POST') {
      posts.push({ url: String(url), body: JSON.parse(String(init.body)) as unknown });
      return pending.promise;
    }
    sessions++;
    return Response.json(
      selected ? sessionValue(selectedActor) : { authenticated: true, contextMode: 'GLOBAL' },
    );
  });
  render(<AccessReviewWorkflow />);
  await userEvent.setup().click(await screen.findByRole('button', { name: 'Enter workspace' }));
  await waitFor(() => expect(posts).toHaveLength(1));
  await focus();
  await focus();
  expect(sessions).toBe(1);
  selected = true;
  await act(async () => pending.resolve(Response.json({ success: true })));
  expect(await screen.findByLabelText('Principal ID to review')).toBeVisible();
  await waitFor(() => expect(sessions).toBe(3));
  expect(posts).toEqual([
    {
      url: '/api/v1/ui/session/context',
      body: {
        participantId: id(101),
        privacyDomainId: id(201),
      },
    },
  ]);
  const action = {
    actionIntentId: 'ACT-IDENTITY_CREATE_SESSION-V1',
    actionIntentDigest: 'sha256:dbc8290dd60814d5bb4248fefc9550f43d0dc97d6333ac232c8ab8a98c3354d2',
    resourceId: id(101),
    resourceDigest: 'sha256:21e6f6ef3dfec5acda58eebd0e07fca2e1394a9777f13157e3e514d611248700',
  };
  expect(performWebAuthnStepUp).toHaveBeenCalledTimes(1);
  expect(performWebAuthnStepUp).toHaveBeenCalledWith(
    { ...action, stepUp: 'FRESH_WEBAUTHN_MAX_5M' },
    action,
  );
});
