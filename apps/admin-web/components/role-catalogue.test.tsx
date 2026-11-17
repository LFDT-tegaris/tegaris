import { act, cleanup, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, expect, it, vi } from 'vitest';
import { RoleCatalogue } from './role-catalogue';
import { performWebAuthnStepUp } from '@openpc/ui-shell';
vi.mock('@openpc/ui-shell', () => ({ performWebAuthnStepUp: vi.fn() }));

afterEach(() => {
  try {
    expect(performWebAuthnStepUp).not.toHaveBeenCalled();
    if (vi.isMockFunction(globalThis.fetch))
      expect(
        vi.mocked(globalThis.fetch).mock.calls.some(([, init]) => init?.method === 'POST'),
      ).toBe(false);
  } finally {
    cleanup();
    vi.restoreAllMocks();
    vi.clearAllMocks();
  }
});
const id = (value: number) => `018f0000-0000-7000-8000-${String(value).padStart(12, '0')}`;
const actor = {
  sessionId: id(701),
  principalId: id(111),
  participantId: id(101),
  privacyDomainId: id(201),
  contextEpoch: '2',
  role: 'operator',
};
const role = {
  effect: {
    id: id(801),
    participantId: actor.participantId,
    roleId: `urn:openpc:role:${id(901)}`,
    displayName: 'Audit readers',
    state: 'ACTIVE',
    revision: '1',
    actionIntentIds: [],
  },
};
function page(overrides: Record<string, unknown> = {}) {
  return {
    actor,
    items: [role],
    nextCursor: null,
    observedAt: '2026-09-14T00:00:00Z',
    authorizedEmpty: false,
    ...overrides,
  };
}
function fullPage() {
  const items = Array.from({ length: 25 }, (_, index) => ({
    effect: {
      ...role.effect,
      id: id(801 + index),
      displayName: index === 0 ? role.effect.displayName : `Audit readers ${index}`,
    },
  }));
  return page({ items, nextCursor: id(825) });
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

it('loads active roles automatically and preserves filters for cursor pagination', async () => {
  const fetch = vi
    .spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(Response.json(fullPage()))
    .mockResolvedValueOnce(Response.json(page({ items: [], authorizedEmpty: true })));
  const open = vi.fn();
  render(<RoleCatalogue actor={actor} onOpen={open} />);
  const user = userEvent.setup();

  expect(
    await screen.findByRole('button', { name: 'View details for Audit readers' }),
  ).toBeVisible();
  expect(screen.getByRole('combobox', { name: 'Role state' })).toHaveValue('ACTIVE');
  expect(String(fetch.mock.calls[0]?.[0])).toContain('state=ACTIVE');
  expect(String(fetch.mock.calls[0]?.[0])).toContain('limit=25');
  await user.click(screen.getByRole('button', { name: 'View details for Audit readers' }));
  expect(open).toHaveBeenCalledWith(role.effect.id);
  await user.click(screen.getByRole('button', { name: 'Next role page' }));
  expect(String(fetch.mock.calls[1]?.[0])).toContain('state=ACTIVE');
  expect(String(fetch.mock.calls[1]?.[0])).toContain(`after=${id(825)}`);
});

it('distinguishes an authorized empty catalogue from a service failure', async () => {
  vi.spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(Response.json(page({ items: [], authorizedEmpty: true })))
    .mockResolvedValueOnce(
      Response.json(
        { title: 'Role service unavailable', code: 'PC-INTEGRATION-5001' },
        { status: 503 },
      ),
    );
  render(<RoleCatalogue actor={actor} onOpen={vi.fn()} />);
  const user = userEvent.setup();

  expect(await screen.findByRole('status')).toHaveTextContent(
    'No active roles exist in this Participant.',
  );
  await user.click(screen.getByRole('button', { name: 'Search roles' }));
  expect(await screen.findByRole('status')).toHaveTextContent(
    'Role catalogue unavailable. Search again.',
  );
});

it('clears prior results as soon as the authenticated context changes', async () => {
  let resolveNext!: (value: Response) => void;
  vi.spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(Response.json(page()))
    .mockImplementationOnce(() => new Promise((resolve) => (resolveNext = resolve)));
  const { rerender } = render(<RoleCatalogue actor={actor} onOpen={vi.fn()} />);
  expect(await screen.findByText('Audit readers')).toBeVisible();

  const changed = { ...actor, contextEpoch: '3' };
  rerender(<RoleCatalogue actor={changed} onOpen={vi.fn()} />);
  await waitFor(() => expect(screen.queryByText('Audit readers')).not.toBeInTheDocument());
  resolveNext(Response.json(page({ actor: changed, items: [], authorizedEmpty: true })));
  expect(await screen.findByRole('status')).toHaveTextContent(
    'No active roles exist in this Participant.',
  );
});
it.each([
  ['items object', page({ items: {} })],
  ['effect boolean', page({ items: [{ effect: false }] })],
  ['display object', page({ items: [{ effect: { ...role.effect, displayName: {} } }] })],
  ['empty display', page({ items: [{ effect: { ...role.effect, displayName: '' } }] })],
  ['actions object', page({ items: [{ effect: { ...role.effect, actionIntentIds: {} } }] })],
  ['action object', page({ items: [{ effect: { ...role.effect, actionIntentIds: [{}] } }] })],
  ['cursor boolean', page({ nextCursor: false })],
  ['observation unavailable', page({ observedAt: 'unknown' })],
  ['empty proof missing', page({ items: [], authorizedEmpty: undefined })],
  ['empty proof contradictory', page({ authorizedEmpty: true })],
])(
  'rejects matching-actor malformed %s without a role or authorized-empty projection',
  async (_, value) => {
    const open = vi.fn();
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(Response.json(value));
    render(<RoleCatalogue actor={actor} onOpen={open} />);
    await screen.findByText('Role catalogue could not be confirmed. Search again.');
    expect(screen.queryByText('Audit readers')).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Next role page' })).not.toBeInTheDocument();
    expect(screen.queryByText(/No active roles|No authorized roles/u)).not.toBeInTheDocument();
    expect(open).not.toHaveBeenCalled();
  },
);
it('accepts harmless extra fields and displays legitimate role actions', async () => {
  const action = 'ACT-PARTICIPANTS_READ_RESOURCE-V1';
  vi.spyOn(globalThis, 'fetch').mockResolvedValue(
    Response.json(
      page({
        hint: {},
        actor: { ...actor, hint: [] },
        items: [{ hint: false, effect: { ...role.effect, actionIntentIds: [action], hint: {} } }],
      }),
    ),
  );
  const open = vi.fn();
  render(<RoleCatalogue actor={actor} onOpen={open} />);
  await screen.findByText('Administrative actions (1)');
  await userEvent.setup().click(screen.getByText('Administrative actions (1)'));
  expect(screen.getByText(action)).toBeVisible();
  await userEvent
    .setup()
    .click(screen.getByRole('button', { name: 'View details for Audit readers' }));
  expect(open).toHaveBeenCalledWith(role.effect.id);
});
it('reports unreadable role responses with safe retry guidance', async () => {
  vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response('<html>Unavailable</html>'));
  render(<RoleCatalogue actor={actor} onOpen={vi.fn()} />);
  await screen.findByText('Role catalogue could not be confirmed. Search again.');
});
it.each(['denial', 'unavailable'])(
  'removes prior role selection and cursor controls on current %s',
  async (failure) => {
    const fetch = vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(Response.json(fullPage()));
    const open = vi.fn();
    render(<RoleCatalogue actor={actor} onOpen={open} />);
    await screen.findByText('Audit readers');
    if (failure === 'denial')
      fetch.mockResolvedValueOnce(
        Response.json({ title: 'Current roles denied', code: 'PC-AUTH-0005' }, { status: 403 }),
      );
    else fetch.mockRejectedValueOnce(new Error('Current roles unavailable.'));
    await userEvent.setup().click(screen.getByRole('button', { name: 'Search roles' }));
    await screen.findByText('Role catalogue unavailable. Search again.');
    expect(screen.queryByText('Audit readers')).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Next role page' })).not.toBeInTheDocument();
    expect(open).not.toHaveBeenCalled();
  },
);
it.each(['success', 'failure'])(
  'aborts an older role read on actor change and ignores late %s while the current read is busy',
  async (result) => {
    const old = deferredResponse(),
      next = deferredResponse();
    const nextActor = { ...actor, sessionId: id(702), contextEpoch: '3' };
    const fetch = vi
      .spyOn(globalThis, 'fetch')
      .mockReturnValueOnce(old.promise)
      .mockReturnValueOnce(next.promise);
    const view = render(<RoleCatalogue actor={actor} onOpen={vi.fn()} />);
    const signal = fetch.mock.calls[0]?.[1]?.signal;
    view.rerender(<RoleCatalogue actor={nextActor} onOpen={vi.fn()} />);
    expect(signal?.aborted).toBe(true);
    await act(async () =>
      result === 'success'
        ? old.resolve(Response.json(page()))
        : old.reject(new Error('Obsolete catalogue failed.')),
    );
    expect(screen.getByRole('button', { name: 'Search roles' })).toBeDisabled();
    expect(screen.queryByText('Audit readers')).not.toBeInTheDocument();
    expect(screen.queryByText('Obsolete catalogue failed.')).not.toBeInTheDocument();
    await act(async () => next.resolve(Response.json(page({ actor: nextActor }))));
    await screen.findByText('Audit readers');
  },
);
it.each(['success', 'failure'])(
  'ignores a late role cursor %s after privacy change and resets the bound cursor',
  async (result) => {
    const old = deferredResponse();
    const nextActor = { ...actor, privacyDomainId: id(202), contextEpoch: '3' };
    const fetch = vi
      .spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(Response.json(fullPage()))
      .mockReturnValueOnce(old.promise)
      .mockResolvedValueOnce(
        Response.json(page({ actor: nextActor, items: [], authorizedEmpty: true })),
      );
    const view = render(<RoleCatalogue actor={actor} onOpen={vi.fn()} />);
    await userEvent.setup().click(await screen.findByRole('button', { name: 'Next role page' }));
    const signal = fetch.mock.calls[1]?.[1]?.signal;
    view.rerender(<RoleCatalogue actor={nextActor} onOpen={vi.fn()} />);
    await screen.findByText('No active roles exist in this Participant.');
    expect(signal?.aborted).toBe(true);
    expect(String(fetch.mock.calls[2]?.[0])).not.toContain('after=');
    await act(async () =>
      result === 'success'
        ? old.resolve(Response.json(page()))
        : old.reject(new Error('Old role cursor failed.')),
    );
    expect(screen.queryByText('Audit readers')).not.toBeInTheDocument();
    expect(screen.queryByText('Old role cursor failed.')).not.toBeInTheDocument();
  },
);
it.each(['success', 'failure'])(
  'aborts unmounted catalogue reads and ignores late %s',
  async (result) => {
    const old = deferredResponse();
    const fetch = vi.spyOn(globalThis, 'fetch').mockReturnValue(old.promise);
    const view = render(<RoleCatalogue actor={actor} onOpen={vi.fn()} />);
    const signal = fetch.mock.calls[0]?.[1]?.signal;
    view.unmount();
    expect(signal?.aborted).toBe(true);
    await act(async () =>
      result === 'success'
        ? old.resolve(Response.json(page()))
        : old.reject(new Error('Unmounted catalogue failed.')),
    );
    expect(fetch).toHaveBeenCalledTimes(1);
  },
);

it.each([201, 202, 206, 403, 503])(
  'rejects HTTP %s with fixed safe guidance and a GET-only retry',
  async (status) => {
    const fetch = vi
      .spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(
        Response.json(
          { ...page(), title: 'private-owner-detail', code: 'private-owner-detail' },
          { status },
        ),
      )
      .mockResolvedValueOnce(Response.json(page()));
    const open = vi.fn();
    render(<RoleCatalogue actor={actor} onOpen={open} />);
    await screen.findByText('Role catalogue unavailable. Search again.');
    expect(screen.queryByText('Audit readers')).not.toBeInTheDocument();
    expect(screen.queryByText('private-owner-detail')).not.toBeInTheDocument();
    expect(screen.queryByText(/No active roles|No authorized roles/u)).not.toBeInTheDocument();
    await userEvent.setup().click(screen.getByRole('button', { name: 'Search roles' }));
    await screen.findByText('Audit readers');
    expect(fetch).toHaveBeenCalledTimes(2);
    expect(fetch.mock.calls.every(([, init]) => init?.method === undefined)).toBe(true);
    expect(open).not.toHaveBeenCalled();
  },
);
it('redacts a private transport exception and supports the same GET retry', async () => {
  const fetch = vi
    .spyOn(globalThis, 'fetch')
    .mockRejectedValueOnce(new Error('private-owner-detail'))
    .mockResolvedValueOnce(Response.json(page()));
  const open = vi.fn();
  render(<RoleCatalogue actor={actor} onOpen={open} />);
  await screen.findByText('Role catalogue unavailable. Search again.');
  expect(screen.queryByText('private-owner-detail')).not.toBeInTheDocument();
  await userEvent.setup().click(screen.getByRole('button', { name: 'Search roles' }));
  await screen.findByText('Audit readers');
  expect(fetch).toHaveBeenCalledTimes(2);
  expect(open).not.toHaveBeenCalled();
});
it.each([
  [
    'foreign Participant',
    { ...page(), items: [{ effect: { ...role.effect, participantId: id(102) } }] },
  ],
  ['inactive row', { ...page(), items: [{ effect: { ...role.effect, state: 'ARCHIVED' } }] }],
  ['non-UUID ID', { ...page(), items: [{ effect: { ...role.effect, id: 'invalid-id' } }] }],
  ['duplicate IDs', { ...page(), items: [role, role] }],
  ['descending IDs', { ...page(), items: [{ effect: { ...role.effect, id: id(826) } }, role] }],
  [
    'more than 25 rows',
    {
      ...fullPage(),
      items: [...fullPage().items, { effect: { ...role.effect, id: id(826) } }],
      nextCursor: null,
    },
  ],
  ['partial cursor page', { ...page(), nextCursor: role.effect.id }],
  ['wrong last cursor', { ...fullPage(), nextCursor: id(826) }],
  ['empty cursor', { ...page(), items: [], authorizedEmpty: true, nextCursor: role.effect.id }],
])('rejects current %s without a selection, cursor or empty assertion', async (_, body) => {
  vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(Response.json(body));
  const open = vi.fn();
  render(<RoleCatalogue actor={actor} onOpen={open} />);
  await screen.findByText('Role catalogue could not be confirmed. Search again.');
  expect(screen.queryByText('Audit readers')).not.toBeInTheDocument();
  expect(screen.queryByRole('button', { name: 'Next role page' })).not.toBeInTheDocument();
  expect(screen.queryByText(/No active roles|No authorized roles/u)).not.toBeInTheDocument();
  expect(open).not.toHaveBeenCalled();
});
it('rejects a cursor page at or before the requested UUID without retaining old rows', async () => {
  const fetch = vi
    .spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(Response.json(fullPage()))
    .mockResolvedValueOnce(Response.json(page()));
  const open = vi.fn();
  render(<RoleCatalogue actor={actor} onOpen={open} />);
  await userEvent.setup().click(await screen.findByRole('button', { name: 'Next role page' }));
  await screen.findByText('Role catalogue could not be confirmed. Search again.');
  expect(String(fetch.mock.calls[1]?.[0])).toContain(`after=${id(825)}`);
  expect(screen.queryByText('Audit readers')).not.toBeInTheDocument();
  expect(open).not.toHaveBeenCalled();
});
it('requires displayed rows to match the actual submitted trimmed search filter', async () => {
  vi.spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(Response.json(page()))
    .mockResolvedValueOnce(Response.json(page()));
  const open = vi.fn();
  render(<RoleCatalogue actor={actor} onOpen={open} />);
  await screen.findByText('Audit readers');
  const user = userEvent.setup();
  await user.type(screen.getByRole('textbox', { name: 'Search role names' }), ' absent ');
  await user.click(screen.getByRole('button', { name: 'Search roles' }));
  await screen.findByText('Role catalogue could not be confirmed. Search again.');
  expect(screen.queryByText('Audit readers')).not.toBeInTheDocument();
  expect(open).not.toHaveBeenCalled();
});
it.each(['sessionId', 'principalId', 'participantId', 'privacyDomainId', 'contextEpoch'] as const)(
  'rejects a response bound to a different %s without a row',
  async (key) => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(
      Response.json({
        ...page(),
        actor: { ...actor, [key]: key === 'contextEpoch' ? '9' : id(102) },
      }),
    );
    const open = vi.fn();
    render(<RoleCatalogue actor={actor} onOpen={open} />);
    await screen.findByText(
      'The working context changed. Refresh the role workflow before continuing.',
    );
    expect(screen.queryByText('Audit readers')).not.toBeInTheDocument();
    expect(open).not.toHaveBeenCalled();
  },
);

it('ignores an obsolete JSON body after actor invalidation while the replacement GET is busy', async () => {
  let resolveBody!: (value: unknown) => void;
  const response = Response.json({});
  const json = vi.spyOn(response, 'json').mockReturnValueOnce(
    new Promise((resolve) => {
      resolveBody = resolve;
    }),
  );
  const next = deferredResponse();
  const fetch = vi
    .spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(response)
    .mockReturnValueOnce(next.promise);
  const open = vi.fn();
  const view = render(<RoleCatalogue actor={actor} onOpen={open} />);
  await waitFor(() => expect(json).toHaveBeenCalledTimes(1));
  const nextActor = { ...actor, contextEpoch: '3' };
  const signal = fetch.mock.calls[0]?.[1]?.signal;
  view.rerender(<RoleCatalogue actor={nextActor} onOpen={open} />);
  expect(signal?.aborted).toBe(true);
  await act(async () => resolveBody(page()));
  expect(screen.getByRole('button', { name: 'Search roles' })).toBeDisabled();
  expect(screen.queryByText('Audit readers')).not.toBeInTheDocument();
  await act(async () => next.resolve(Response.json({ ...page(), actor: nextActor })));
  await screen.findByText('Audit readers');
  expect(screen.getByRole('button', { name: 'Search roles' })).toBeEnabled();
  expect(open).not.toHaveBeenCalled();
});
