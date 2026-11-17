import { act, cleanup, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, expect, it, vi } from 'vitest';
import { performWebAuthnStepUp } from '@openpc/ui-shell';
import { PrincipalRoleAssignments } from './principal-role-assignments';
vi.mock('@openpc/ui-shell', () => ({ performWebAuthnStepUp: vi.fn() }));

afterEach(() => {
  try {
    expect(performWebAuthnStepUp).not.toHaveBeenCalled();
    if (vi.isMockFunction(globalThis.fetch))
      expect(
        vi
          .mocked(globalThis.fetch)
          .mock.calls.some(([, init]) =>
            ['POST', 'PUT', 'PATCH', 'DELETE'].includes(init?.method ?? ''),
          ),
      ).toBe(false);
  } finally {
    cleanup();
    vi.restoreAllMocks();
    vi.clearAllMocks();
  }
});

const actor = {
  sessionId: 'session-one',
  principalId: '018f0000-0000-7000-8000-000000000001',
  participantId: '018f0000-0000-7000-8000-000000000101',
  privacyDomainId: '018f0000-0000-7000-8000-000000000201',
  contextEpoch: '2',
};
const subjectId = '018f0000-0000-7000-8000-000000000301';
const assignmentId = '018f0000-0000-7000-8000-000000000401';
const roleId = '018f0000-0000-7000-8000-000000000501';
const roleReference = `urn:openpc:role:${roleId}`;

function assignment(id = assignmentId) {
  return {
    grant: {
      effect: {
        id,
        participantId: actor.participantId,
        principalId: subjectId,
        authorityEnvelopeId: '018f0000-0000-7000-8000-000000000601',
        roleId: roleReference,
        privacyDomainIds: [actor.privacyDomainId],
        actionIntentIds: [],
        capabilityIds: [],
        resourceIds: ['*'],
        riskClasses: ['LOW'],
        validFrom: '2026-09-29T00:00:00.000Z',
        validUntil: '2026-09-30T00:00:00.000Z',
        makerCheckerRequired: true,
        stepUpRequired: true,
        onwardDelegationDepth: 0,
        scopeDigest: `sha256:${'0'.repeat(64)}`,
        delegationEpoch: '0',
        state: 'ACTIVE',
      },
      revision: '3',
      operationId: null,
    },
  };
}

function delegation() {
  const common = Object.fromEntries(
    Object.entries(assignment().grant.effect).filter(
      ([key]) => !['principalId', 'authorityEnvelopeId', 'roleId'].includes(key),
    ),
  );
  return {
    grant: {
      effect: {
        ...common,
        id: '018f0000-0000-7000-8000-000000000402',
        parentId: assignmentId,
        grantorId: actor.principalId,
        granteeId: subjectId,
        participantId: actor.participantId,
        roleId: roleReference,
        state: 'ACTIVE',
      },
      revision: '1',
      operationId: null,
    },
  };
}

function page<T>(items: T[], nextCursor: string | null = null) {
  return {
    actor,
    page: {
      participantId: actor.participantId,
      privacyDomainId: actor.privacyDomainId,
      subject: { id: subjectId, kind: 'USER', state: 'ACTIVE', authorityEpoch: '2' },
      items,
      nextCursor,
      completeness: nextCursor ? 'MORE' : 'COMPLETE',
      authorizedEmpty: items.length === 0,
    },
  };
}

function roleWorkbench(overrides: Record<string, unknown> = {}) {
  return {
    actor,
    effect: {
      effect: {
        id: roleId,
        roleId: roleReference,
        displayName: 'Debtor',
        state: 'ACTIVE',
        revision: '1',
        origin: 'GOVERNED',
        ...overrides,
      },
    },
  };
}
function deferredResponse() {
  let resolve!: (value: Response) => void;
  let reject!: (cause: Error) => void;
  const promise = new Promise<Response>((accept, fail) => {
    resolve = accept;
    reject = fail;
  });
  return { promise, resolve, reject };
}

it('shows a direct Debtor assignment and excludes delegated authority from role membership', async () => {
  const fetch = vi
    .spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(Response.json(page([assignment(), delegation()])))
    .mockResolvedValueOnce(Response.json(roleWorkbench()));

  render(<PrincipalRoleAssignments actor={actor} principalId={subjectId} />);

  expect(await screen.findByRole('heading', { name: 'Debtor' })).toBeVisible();
  expect(screen.getByText(`Role ID: ${roleId}`)).toBeVisible();
  expect(screen.getByText(`Role reference: ${roleReference}`)).toBeVisible();
  expect(screen.getByText('Assignment ACTIVE · revision 3')).toBeVisible();
  expect(screen.getByText(`Assignment ID: ${assignmentId}`)).toBeVisible();
  expect(fetch).toHaveBeenCalledTimes(2);
  expect(String(fetch.mock.calls[1]?.[0])).toContain(`roleId=${roleId}`);
});

it('distinguishes no assigned roles from an authorization or service failure', async () => {
  vi.spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(Response.json(page([])))
    .mockResolvedValueOnce(
      Response.json(
        { title: 'Role assignments forbidden', code: 'PC-AUTHZ-4030' },
        { status: 403 },
      ),
    );
  const { rerender } = render(<PrincipalRoleAssignments actor={actor} principalId={subjectId} />);

  expect(await screen.findByRole('status')).toHaveTextContent(
    'No roles are assigned to this principal in the current privacy context.',
  );
  rerender(
    <PrincipalRoleAssignments actor={{ ...actor, contextEpoch: '3' }} principalId={subjectId} />,
  );
  expect(await screen.findByRole('status')).toHaveTextContent(
    'Role assignments could not be confirmed. Reopen the principal to retry.',
  );
});

it('preserves the principal while advancing access-review cursor pages', async () => {
  const cursor = 'delegation:018f0000-0000-7000-8000-000000000402';
  const fetch = vi
    .spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(Response.json(page([delegation()], cursor)))
    .mockResolvedValueOnce(Response.json(page([assignment()])))
    .mockResolvedValueOnce(Response.json(roleWorkbench()));
  render(<PrincipalRoleAssignments actor={actor} principalId={subjectId} />);
  const user = userEvent.setup();

  expect(await screen.findByRole('status')).toHaveTextContent(
    'No direct role assignments appear on this authority page.',
  );
  await user.click(screen.getByRole('button', { name: 'Next role assignment page' }));
  expect(await screen.findByRole('heading', { name: 'Debtor' })).toBeVisible();
  const url = String(fetch.mock.calls[1]?.[0]);
  expect(url).toContain(`subjectId=${subjectId}`);
  expect(url).toContain(`after=${encodeURIComponent(cursor)}`);
});

it('clears stale role data when the principal or authenticated context changes', async () => {
  let resolveNext!: (response: Response) => void;
  vi.spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(Response.json(page([assignment()])))
    .mockResolvedValueOnce(Response.json(roleWorkbench()))
    .mockImplementationOnce(() => new Promise((resolve) => (resolveNext = resolve)));
  const { rerender } = render(<PrincipalRoleAssignments actor={actor} principalId={subjectId} />);
  expect(await screen.findByRole('heading', { name: 'Debtor' })).toBeVisible();

  const nextPrincipal = '018f0000-0000-7000-8000-000000000302';
  rerender(
    <PrincipalRoleAssignments
      actor={{ ...actor, sessionId: 'session-two', contextEpoch: '3' }}
      principalId={nextPrincipal}
    />,
  );
  await waitFor(() => expect(screen.queryByRole('heading', { name: 'Debtor' })).toBeNull());
  resolveNext(
    Response.json({
      actor: { ...actor, sessionId: 'session-two', contextEpoch: '3' },
      page: { ...page([]).page, subject: { id: nextPrincipal } },
    }),
  );
  expect(await screen.findByRole('status')).toHaveTextContent(
    'No roles are assigned to this principal in the current privacy context.',
  );
});
it.each([
  ['items object', { ...page([]), page: { ...page([]).page, items: {} } }],
  ['item boolean', { ...page([]), page: { ...page([]).page, items: [false] } }],
  ['grant effect array', page([{ grant: { ...assignment().grant, effect: [] } }])],
  ['assignment revision object', page([{ grant: { ...assignment().grant, revision: {} } }])],
  [
    'assignment state boolean',
    page([
      { grant: { ...assignment().grant, effect: { ...assignment().grant.effect, state: false } } },
    ]),
  ],
  [
    'assignment validity object',
    page([
      { grant: { ...assignment().grant, effect: { ...assignment().grant.effect, validFrom: {} } } },
    ]),
  ],
  [
    'missing grant discriminant',
    page([
      {
        grant: {
          ...assignment().grant,
          effect: { ...assignment().grant.effect, principalId: undefined },
        },
      },
    ]),
  ],
  [
    'ambiguous delegation discriminant',
    page([
      {
        grant: {
          ...delegation().grant,
          effect: { ...delegation().grant.effect, principalId: subjectId },
        },
      },
    ]),
  ],
  [
    'malformed delegated record',
    page([
      { grant: { ...delegation().grant, effect: { ...delegation().grant.effect, granteeId: {} } } },
    ]),
  ],
  ['cursor object', { ...page([]), page: { ...page([]).page, nextCursor: {} } }],
  [
    'missing authorized empty proof',
    { ...page([]), page: { ...page([]).page, authorizedEmpty: undefined } },
  ],
  [
    'contradictory empty proof',
    { ...page([assignment()]), page: { ...page([assignment()]).page, authorizedEmpty: true } },
  ],
])('rejects matching-actor malformed access-review %s before any role lookup', async (_, value) => {
  const fetch = vi.spyOn(globalThis, 'fetch').mockResolvedValue(Response.json(value));
  render(<PrincipalRoleAssignments actor={actor} principalId={subjectId} />);
  await screen.findByText(
    'Role assignments could not be confirmed. Reopen the principal to retry.',
  );
  expect(screen.queryByRole('heading', { name: 'Debtor' })).not.toBeInTheDocument();
  expect(
    screen.queryByText(/No roles are assigned|No direct role assignments/u),
  ).not.toBeInTheDocument();
  expect(
    screen.queryByRole('button', { name: 'Next role assignment page' }),
  ).not.toBeInTheDocument();
  expect(fetch).toHaveBeenCalledTimes(1);
  expect(fetch.mock.calls.some(([, init]) => init?.method === 'POST')).toBe(false);
});
it.each([
  { label: 'display name object', override: { displayName: {} } },
  { label: 'empty display name', override: { displayName: '' } },
  { label: 'overlong display name', override: { displayName: 'x'.repeat(161) } },
  { label: 'state boolean', override: { state: false } },
  { label: 'unsupported state', override: { state: 'PENDING' } },
  { label: 'revision array', override: { revision: [] } },
  { label: 'nondecimal revision', override: { revision: 'not-a-revision' } },
  { label: 'noncanonical revision', override: { revision: '01' } },
  { label: 'origin object', override: { origin: {} } },
  { label: 'unsupported origin', override: { origin: 'UNTRUSTED' } },
])(
  'rejects a matching role ID with malformed $label rather than inferring role membership',
  async ({ override }) => {
    const fetch = vi
      .spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(Response.json(page([assignment()])))
      .mockResolvedValueOnce(Response.json(roleWorkbench(override)));
    render(<PrincipalRoleAssignments actor={actor} principalId={subjectId} />);
    await screen.findByText(
      'An assigned role could not be confirmed. Reopen the principal to retry.',
    );
    expect(screen.queryByRole('heading', { name: 'Debtor' })).not.toBeInTheDocument();
    expect(screen.queryByText(/No roles are assigned/u)).not.toBeInTheDocument();
    expect(fetch).toHaveBeenCalledTimes(2);
    expect(fetch.mock.calls[1]?.[1]?.signal?.aborted).toBe(true);
    expect(fetch.mock.calls.some(([, init]) => init?.method === 'POST')).toBe(false);
  },
);
it.each(
  ['ACTIVE', 'ARCHIVED'].flatMap((state) =>
    ['GOVERNED', 'MIGRATED_ASSIGNMENT', 'BOOTSTRAP'].map((origin) => ({ state, origin })),
  ),
)(
  'accepts current $state $origin role boundaries and harmless extras',
  async ({ state, origin }) => {
    const name = 'R'.repeat(160);
    const revision = state === 'ARCHIVED' ? '0' : '19';
    const fetch = vi
      .spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(Response.json(page([assignment()])))
      .mockResolvedValueOnce(
        Response.json(roleWorkbench({ state, origin, revision, displayName: name, hint: {} })),
      );
    render(<PrincipalRoleAssignments actor={actor} principalId={subjectId} />);
    expect(await screen.findByRole('heading', { name })).toBeVisible();
    expect(screen.getByText(`Role ${state} · revision ${revision} · ${origin}`)).toBeVisible();
    expect(screen.getByText(`Assignment ID: ${assignmentId}`)).toBeVisible();
    expect(fetch).toHaveBeenCalledTimes(2);
  },
);

it.each(['access', 'role'])(
  'redacts unreadable %s JSON without reporting empty or loaded roles',
  async (phase) => {
    const fetch = vi.spyOn(globalThis, 'fetch');
    if (phase === 'role') fetch.mockResolvedValueOnce(Response.json(page([assignment()])));
    fetch.mockResolvedValueOnce(new Response('SECRET upstream JSON'));
    render(<PrincipalRoleAssignments actor={actor} principalId={subjectId} />);
    await screen.findByText(
      phase === 'role'
        ? 'An assigned role could not be confirmed. Reopen the principal to retry.'
        : 'Role assignments could not be confirmed. Reopen the principal to retry.',
    );
    expect(screen.queryByText(/SECRET|No roles are assigned|loaded from current/u)).toBeNull();
    expect(screen.queryByRole('heading', { name: 'Debtor' })).toBeNull();
    expect(screen.queryByRole('button', { name: 'Next role assignment page' })).toBeNull();
    expect(fetch).toHaveBeenCalledTimes(phase === 'role' ? 2 : 1);
  },
);
it.each([
  'page Participant',
  'page privacy',
  'subject',
  'assignment Participant',
  'assignment privacy',
  'assignment principal',
  'actor epoch',
])('rejects an unbound %s before any chained role lookup', async (field) => {
  const otherId = '018f0000-0000-7000-8000-000000000999';
  const item = assignment();
  if (field === 'assignment Participant') item.grant.effect.participantId = otherId;
  if (field === 'assignment privacy') item.grant.effect.privacyDomainIds = [otherId];
  if (field === 'assignment principal') item.grant.effect.principalId = otherId;
  const response = page([item]);
  if (field === 'page Participant') response.page.participantId = otherId;
  if (field === 'page privacy') response.page.privacyDomainId = otherId;
  if (field === 'subject') response.page.subject.id = otherId;
  if (field === 'actor epoch') response.actor = { ...actor, contextEpoch: '3' };
  const fetch = vi.spyOn(globalThis, 'fetch').mockResolvedValue(Response.json(response));
  render(<PrincipalRoleAssignments actor={actor} principalId={subjectId} />);
  await screen.findByText('The working context changed. Reopen the principal before continuing.');
  expect(fetch).toHaveBeenCalledTimes(1);
  expect(screen.queryByRole('heading', { name: 'Debtor' })).not.toBeInTheDocument();
});
it.each(['actor', 'ID', 'reference'])(
  'rejects a current role with a foreign %s binding',
  async (field) => {
    const response = roleWorkbench();
    if (field === 'actor') response.actor = { ...actor, contextEpoch: '3' };
    if (field === 'ID') response.effect.effect.id = '018f0000-0000-7000-8000-000000000502';
    if (field === 'reference')
      response.effect.effect.roleId = 'urn:openpc:role:018f0000-0000-7000-8000-000000000502';
    const fetch = vi
      .spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(Response.json(page([assignment()])))
      .mockResolvedValueOnce(Response.json(response));
    render(<PrincipalRoleAssignments actor={actor} principalId={subjectId} />);
    await screen.findByText('An assigned role could not be reconciled with its current record.');
    expect(screen.queryByRole('heading', { name: 'Debtor' })).not.toBeInTheDocument();
    expect(fetch.mock.calls.some(([, init]) => init?.method === 'POST')).toBe(false);
  },
);
it('accepts harmless access and role fields while excluding delegated role hints from membership', async () => {
  const response = page([assignment(), delegation()]);
  vi.spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(
      Response.json({
        ...response,
        hint: {},
        page: {
          ...response.page,
          hint: [],
          items: response.page.items.map((item) => ({
            ...item,
            hint: {},
            grant: { ...item.grant, hint: false, effect: { ...item.grant.effect, hint: [] } },
          })),
        },
      }),
    )
    .mockResolvedValueOnce(
      Response.json({
        ...roleWorkbench(),
        hint: false,
        effect: {
          ...roleWorkbench().effect,
          hint: {},
          effect: { ...roleWorkbench().effect.effect, hint: {} },
        },
      }),
    );
  render(<PrincipalRoleAssignments actor={actor} principalId={subjectId} />);
  await screen.findByRole('heading', { name: 'Debtor' });
  expect(screen.getAllByText(/Assignment ID:/u)).toHaveLength(1);
});
it.each([
  ['access', 'denial'],
  ['access', 'unavailable'],
  ['role', 'denial'],
  ['role', 'unavailable'],
])('removes previously displayed roles on current %s %s', async (phase, failure) => {
  const fetch = vi
    .spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(Response.json(page([assignment()])))
    .mockResolvedValueOnce(Response.json(roleWorkbench()));
  const view = render(<PrincipalRoleAssignments actor={actor} principalId={subjectId} />);
  await screen.findByRole('heading', { name: 'Debtor' });
  if (phase === 'role') fetch.mockResolvedValueOnce(Response.json(page([assignment()])));
  if (failure === 'denial')
    fetch.mockResolvedValueOnce(
      Response.json(
        { title: 'SECRET upstream role title', code: 'SECRET upstream role code' },
        { status: 403 },
      ),
    );
  else fetch.mockRejectedValueOnce(new Error('SECRET upstream role exception'));
  view.rerender(<PrincipalRoleAssignments actor={{ ...actor }} principalId={subjectId} />);
  await screen.findByText(
    phase === 'role' && failure === 'denial'
      ? 'An assigned role could not be confirmed. Reopen the principal to retry.'
      : 'Role assignments could not be confirmed. Reopen the principal to retry.',
  );
  expect(screen.queryByRole('heading', { name: 'Debtor' })).not.toBeInTheDocument();
  expect(screen.queryByText(/No roles are assigned/u)).not.toBeInTheDocument();
  expect(fetch).toHaveBeenCalledTimes(phase === 'role' ? 4 : 3);
  expect(screen.queryByText(/SECRET/u)).not.toBeInTheDocument();
});
it.each([
  ['access', 'success'],
  ['access', 'failure'],
  ['role', 'success'],
  ['role', 'failure'],
])(
  'aborts an obsolete %s read after principal/context change and ignores late %s',
  async (phase, result) => {
    const old = deferredResponse(),
      next = deferredResponse();
    const nextPrincipal = '018f0000-0000-7000-8000-000000000302';
    const nextActor = { ...actor, sessionId: 'session-two', contextEpoch: '3' };
    const fetch = vi.spyOn(globalThis, 'fetch');
    if (phase === 'role') fetch.mockResolvedValueOnce(Response.json(page([assignment()])));
    fetch.mockReturnValueOnce(old.promise).mockReturnValueOnce(next.promise);
    const view = render(<PrincipalRoleAssignments actor={actor} principalId={subjectId} />);
    await waitFor(() => expect(fetch).toHaveBeenCalledTimes(phase === 'role' ? 2 : 1));
    const signal = fetch.mock.calls.at(-1)?.[1]?.signal;
    view.rerender(<PrincipalRoleAssignments actor={nextActor} principalId={nextPrincipal} />);
    expect(signal?.aborted).toBe(true);
    await act(async () =>
      result === 'success'
        ? old.resolve(Response.json(phase === 'role' ? roleWorkbench() : page([assignment()])))
        : old.reject(new Error('Obsolete role read failed.')),
    );
    expect(screen.queryByRole('heading', { name: 'Debtor' })).not.toBeInTheDocument();
    expect(screen.queryByText('Obsolete role read failed.')).not.toBeInTheDocument();
    expect(fetch.mock.calls.filter(([url]) => String(url).includes('role-workbench'))).toHaveLength(
      phase === 'role' ? 1 : 0,
    );
    expect(screen.getByRole('status')).toHaveTextContent('Reading governed role assignments.');
    await act(async () =>
      next.resolve(
        Response.json({
          actor: nextActor,
          page: { ...page([]).page, subject: { id: nextPrincipal } },
        }),
      ),
    );
    await screen.findByText(
      'No roles are assigned to this principal in the current privacy context.',
    );
    expect(String(fetch.mock.calls.at(-1)?.[0])).toContain(`subjectId=${nextPrincipal}`);
    expect(fetch.mock.calls.some(([, init]) => init?.method === 'POST')).toBe(false);
  },
);
it.each(['access', 'role'])(
  'aborts an unmounted %s read without chained unrelated lookups',
  async (phase) => {
    const pending = deferredResponse();
    const fetch = vi.spyOn(globalThis, 'fetch');
    if (phase === 'role') fetch.mockResolvedValueOnce(Response.json(page([assignment()])));
    fetch.mockReturnValueOnce(pending.promise);
    const view = render(<PrincipalRoleAssignments actor={actor} principalId={subjectId} />);
    await waitFor(() => expect(fetch).toHaveBeenCalledTimes(phase === 'role' ? 2 : 1));
    const signal = fetch.mock.calls.at(-1)?.[1]?.signal;
    view.unmount();
    expect(signal?.aborted).toBe(true);
    await act(async () =>
      pending.resolve(Response.json(phase === 'role' ? roleWorkbench() : page([assignment()]))),
    );
    expect(fetch).toHaveBeenCalledTimes(phase === 'role' ? 2 : 1);
  },
);
it('aborts pending sibling role reads when a current role record cannot be confirmed', async () => {
  const sibling = deferredResponse();
  const second = assignment('018f0000-0000-7000-8000-000000000403');
  second.grant.effect.roleId = 'urn:openpc:role:018f0000-0000-7000-8000-000000000502';
  const fetch = vi
    .spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(Response.json(page([assignment(), second])))
    .mockResolvedValueOnce(Response.json(roleWorkbench({ displayName: {} })))
    .mockReturnValueOnce(sibling.promise);
  render(<PrincipalRoleAssignments actor={actor} principalId={subjectId} />);
  await screen.findByText(
    'An assigned role could not be confirmed. Reopen the principal to retry.',
  );
  expect(fetch.mock.calls[2]?.[1]?.signal?.aborted).toBe(true);
  await act(async () => sibling.resolve(Response.json(roleWorkbench())));
  expect(screen.queryByRole('heading', { name: 'Debtor' })).not.toBeInTheDocument();
  expect(
    screen.getByText('An assigned role could not be confirmed. Reopen the principal to retry.'),
  ).toBeVisible();
});
it.each(['success', 'failure'])(
  'discards a late role assignment cursor %s after selection change without fetching unrelated roles',
  async (result) => {
    const cursor = 'delegation:018f0000-0000-7000-8000-000000000402';
    const nextPrincipal = '018f0000-0000-7000-8000-000000000302';
    const old = deferredResponse();
    const fetch = vi
      .spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(Response.json(page([delegation()], cursor)))
      .mockReturnValueOnce(old.promise)
      .mockResolvedValueOnce(
        Response.json({ ...page([]), page: { ...page([]).page, subject: { id: nextPrincipal } } }),
      );
    const view = render(<PrincipalRoleAssignments actor={actor} principalId={subjectId} />);
    await userEvent
      .setup()
      .click(await screen.findByRole('button', { name: 'Next role assignment page' }));
    const signal = fetch.mock.calls[1]?.[1]?.signal;
    view.rerender(<PrincipalRoleAssignments actor={actor} principalId={nextPrincipal} />);
    await screen.findByText(
      'No roles are assigned to this principal in the current privacy context.',
    );
    expect(signal?.aborted).toBe(true);
    expect(String(fetch.mock.calls[2]?.[0])).toContain(`subjectId=${nextPrincipal}`);
    expect(String(fetch.mock.calls[2]?.[0])).not.toContain('after=');
    await act(async () =>
      result === 'success'
        ? old.resolve(Response.json(page([assignment()])))
        : old.reject(new Error('Obsolete assignment cursor failed.')),
    );
    expect(fetch).toHaveBeenCalledTimes(3);
    expect(fetch.mock.calls.some(([url]) => String(url).includes('role-workbench'))).toBe(false);
    expect(screen.queryByRole('heading', { name: 'Debtor' })).not.toBeInTheDocument();
    expect(screen.queryByText('Obsolete assignment cursor failed.')).not.toBeInTheDocument();
    expect(
      screen.getByText('No roles are assigned to this principal in the current privacy context.'),
    ).toBeVisible();
  },
);
