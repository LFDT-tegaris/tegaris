import { act, cleanup, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, expect, it, vi } from 'vitest';
import { performWebAuthnStepUp } from '@openpc/ui-shell';
import { GroupCatalogue } from './group-catalogue';
vi.mock('@openpc/ui-shell', () => ({ performWebAuthnStepUp: vi.fn() }));

const id = (value: string) => `018f0000-0000-7000-8000-${value.padStart(12, '0')}`;
const actor = {
  sessionId: id('701'),
  principalId: id('111'),
  participantId: id('101'),
  privacyDomainId: id('201'),
  contextEpoch: '2',
};
const group = {
  effect: {
    groupId: id('801'),
    participantId: actor.participantId,
    groupName: 'Settlement operators',
    state: 'ACTIVE',
    revision: '1',
    createdAt: '2026-09-29T12:00:00.000Z',
    updatedAt: '2026-09-29T12:00:00.000Z',
    operationId: id('901'),
  },
};
const page = {
  actor,
  items: [group],
  nextCursor: null,
  observedAt: '2026-09-29T12:00:00.000Z',
  authorizedEmpty: false,
};
function fullPage() {
  const items = Array.from({ length: 25 }, (_, index) => ({
    effect: {
      ...group.effect,
      groupId: id(String(801 + index)),
      groupName: index === 0 ? group.effect.groupName : `Settlement operators ${index}`,
    },
  }));
  return { ...page, items, nextCursor: id('825') };
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

it('loads active groups automatically and preserves filters on the next cursor page', async () => {
  const fetch = vi
    .spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(Response.json(fullPage()))
    .mockResolvedValueOnce(
      Response.json({ ...page, items: [{ effect: { ...group.effect, groupId: id('826') } }] }),
    );
  const open = vi.fn();
  render(<GroupCatalogue actor={actor} refreshEpoch={0} onOpen={open} />);
  await screen.findByText('Settlement operators');
  expect(String(fetch.mock.calls[0]?.[0])).toContain('search=&state=ACTIVE&limit=25');
  await userEvent.setup().click(screen.getByRole('button', { name: 'Next group page' }));
  await waitFor(() => expect(fetch).toHaveBeenCalledTimes(2));
  expect(String(fetch.mock.calls[1]?.[0])).toContain(
    `search=&state=ACTIVE&limit=25&after=${id('825')}`,
  );
  await userEvent
    .setup()
    .click(await screen.findByRole('button', { name: 'View details for Settlement operators' }));
  expect(open).toHaveBeenCalledWith(id('826'));
});

it('distinguishes authorized empty results from failures and clears stale groups on context change', async () => {
  vi.spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(Response.json(page))
    .mockResolvedValueOnce(
      Response.json({
        ...page,
        actor: { ...actor, sessionId: id('702') },
        items: [],
        nextCursor: null,
        authorizedEmpty: true,
      }),
    )
    .mockResolvedValueOnce(
      Response.json(
        { title: 'The requested process is unavailable.', code: 'PC-AUTH-0005' },
        { status: 403 },
      ),
    );
  const view = render(<GroupCatalogue actor={actor} refreshEpoch={0} onOpen={() => undefined} />);
  await screen.findByText('Settlement operators');
  view.rerender(
    <GroupCatalogue
      actor={{ ...actor, sessionId: id('702') }}
      refreshEpoch={0}
      onOpen={() => undefined}
    />,
  );
  await screen.findByText('No active groups exist in this Participant.');
  expect(screen.queryByText('Settlement operators')).not.toBeInTheDocument();
  await userEvent
    .setup()
    .selectOptions(screen.getByRole('combobox', { name: 'Group state' }), 'ALL');
  await userEvent.setup().type(screen.getByRole('textbox', { name: 'Search group names' }), 'ops');
  await userEvent.setup().click(screen.getByRole('button', { name: 'Search groups' }));
  await screen.findByText('Group catalogue unavailable. Search again.');
  expect(screen.queryByText('No active groups exist in this Participant.')).not.toBeInTheDocument();
});
it.each([
  ['items object', { ...page, items: {} }],
  ['item boolean', { ...page, items: [false] }],
  ['effect array', { ...page, items: [{ effect: [] }] }],
  ['name object', { ...page, items: [{ effect: { ...group.effect, groupName: {} } }] }],
  ['empty name', { ...page, items: [{ effect: { ...group.effect, groupName: '' } }] }],
  ['state boolean', { ...page, items: [{ effect: { ...group.effect, state: true } }] }],
  ['revision array', { ...page, items: [{ effect: { ...group.effect, revision: [] } }] }],
  ['cursor object', { ...page, nextCursor: {} }],
  ['invalid observation', { ...page, observedAt: 'unavailable' }],
  ['empty flag string', { ...page, authorizedEmpty: 'false' }],
  ['missing empty proof', { ...page, items: [], authorizedEmpty: undefined }],
  ['contradictory empty proof', { ...page, authorizedEmpty: true }],
])(
  'rejects matching-actor malformed %s without rendering or claiming authorized empty',
  async (_, value) => {
    const fetch = vi.spyOn(globalThis, 'fetch').mockResolvedValue(Response.json(value));
    const open = vi.fn();
    render(<GroupCatalogue actor={actor} refreshEpoch={0} onOpen={open} />);
    await screen.findByText('Group catalogue could not be confirmed. Search again.');
    expect(screen.queryByText('Settlement operators')).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Next group page' })).not.toBeInTheDocument();
    expect(screen.queryByText(/No active groups|No authorized groups/u)).not.toBeInTheDocument();
    expect(open).not.toHaveBeenCalled();
    expect(fetch.mock.calls.some(([, init]) => init?.method === 'POST')).toBe(false);
  },
);
it('accepts harmless response fields while keeping the displayed group and selection bound', async () => {
  vi.spyOn(globalThis, 'fetch').mockResolvedValue(
    Response.json({
      ...page,
      hint: {},
      actor: { ...actor, hint: [] },
      items: [{ ...group, hint: false, effect: { ...group.effect, hint: {} } }],
    }),
  );
  const open = vi.fn();
  render(<GroupCatalogue actor={actor} refreshEpoch={0} onOpen={open} />);
  await userEvent
    .setup()
    .click(await screen.findByRole('button', { name: 'View details for Settlement operators' }));
  expect(open).toHaveBeenCalledWith(group.effect.groupId);
});
it('reports an unreadable group response with safe retry guidance', async () => {
  vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response('<html>Unavailable</html>'));
  render(<GroupCatalogue actor={actor} refreshEpoch={0} onOpen={vi.fn()} />);
  await screen.findByText('Group catalogue could not be confirmed. Search again.');
  expect(screen.queryByText(/No active groups|No authorized groups/u)).not.toBeInTheDocument();
});
it.each(['denial', 'unavailable'])(
  'removes a previously displayed group on current %s',
  async (failure) => {
    const fetch = vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(Response.json(page));
    const open = vi.fn();
    render(<GroupCatalogue actor={actor} refreshEpoch={0} onOpen={open} />);
    await screen.findByText('Settlement operators');
    if (failure === 'denial')
      fetch.mockResolvedValueOnce(
        Response.json({ title: 'Current groups denied', code: 'PC-AUTH-0005' }, { status: 403 }),
      );
    else fetch.mockRejectedValueOnce(new Error('Current groups unavailable.'));
    await userEvent.setup().click(screen.getByRole('button', { name: 'Search groups' }));
    await screen.findByText('Group catalogue unavailable. Search again.');
    expect(screen.queryByText('Settlement operators')).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Next group page' })).not.toBeInTheDocument();
    expect(open).not.toHaveBeenCalled();
  },
);
it.each(['success', 'failure'])(
  'aborts an older group read on refresh and ignores late %s while the current read is busy',
  async (result) => {
    const old = deferredResponse(),
      next = deferredResponse();
    const fetch = vi
      .spyOn(globalThis, 'fetch')
      .mockReturnValueOnce(old.promise)
      .mockReturnValueOnce(next.promise);
    const view = render(<GroupCatalogue actor={actor} refreshEpoch={0} onOpen={vi.fn()} />);
    const signal = fetch.mock.calls[0]?.[1]?.signal;
    view.rerender(<GroupCatalogue actor={actor} refreshEpoch={1} onOpen={vi.fn()} />);
    expect(signal?.aborted).toBe(true);
    await act(async () =>
      result === 'success'
        ? old.resolve(Response.json(page))
        : old.reject(new Error('Obsolete groups failed.')),
    );
    expect(screen.getByRole('button', { name: 'Search groups' })).toBeDisabled();
    expect(screen.queryByText('Settlement operators')).not.toBeInTheDocument();
    expect(screen.queryByText('Obsolete groups failed.')).not.toBeInTheDocument();
    await act(async () => next.resolve(Response.json({ ...page, nextCursor: null })));
    await screen.findByText('Settlement operators');
    expect(screen.getByRole('button', { name: 'Search groups' })).toBeEnabled();
  },
);
it.each(['success', 'failure'])(
  'discards a late group cursor %s after actor change and resets the actor-bound cursor',
  async (result) => {
    const old = deferredResponse();
    const nextActor = { ...actor, privacyDomainId: id('202'), contextEpoch: '3' };
    const fetch = vi
      .spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(Response.json(fullPage()))
      .mockReturnValueOnce(old.promise)
      .mockResolvedValueOnce(
        Response.json({
          ...page,
          actor: nextActor,
          items: [],
          nextCursor: null,
          authorizedEmpty: true,
        }),
      );
    const open = vi.fn();
    const view = render(<GroupCatalogue actor={actor} refreshEpoch={0} onOpen={open} />);
    await userEvent.setup().click(await screen.findByRole('button', { name: 'Next group page' }));
    const signal = fetch.mock.calls[1]?.[1]?.signal;
    view.rerender(<GroupCatalogue actor={nextActor} refreshEpoch={0} onOpen={open} />);
    await screen.findByText('No active groups exist in this Participant.');
    expect(signal?.aborted).toBe(true);
    expect(String(fetch.mock.calls[2]?.[0])).not.toContain('after=');
    await act(async () =>
      result === 'success'
        ? old.resolve(Response.json(page))
        : old.reject(new Error('Old cursor failed.')),
    );
    expect(screen.queryByText('Settlement operators')).not.toBeInTheDocument();
    expect(screen.queryByText('Old cursor failed.')).not.toBeInTheDocument();
    expect(screen.getByText('No active groups exist in this Participant.')).toBeVisible();
    expect(open).not.toHaveBeenCalled();
  },
);
it.each(['success', 'failure'])(
  'aborts an unmounted group read and ignores its late %s',
  async (result) => {
    const pending = deferredResponse();
    const fetch = vi.spyOn(globalThis, 'fetch').mockReturnValue(pending.promise);
    const open = vi.fn();
    const view = render(<GroupCatalogue actor={actor} refreshEpoch={0} onOpen={open} />);
    const signal = fetch.mock.calls[0]?.[1]?.signal;
    view.unmount();
    expect(signal?.aborted).toBe(true);
    await act(async () =>
      result === 'success'
        ? pending.resolve(Response.json(page))
        : pending.reject(new Error('Unmounted read failed.')),
    );
    expect(fetch).toHaveBeenCalledTimes(1);
    expect(open).not.toHaveBeenCalled();
  },
);

it.each([201, 202, 206, 403, 503])(
  'rejects HTTP %s with fixed safe guidance and a GET-only retry',
  async (status) => {
    const fetch = vi
      .spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(
        Response.json(
          { ...page, title: 'private-owner-detail', code: 'private-owner-detail' },
          { status },
        ),
      )
      .mockResolvedValueOnce(Response.json(page));
    const open = vi.fn();
    render(<GroupCatalogue actor={actor} refreshEpoch={0} onOpen={open} />);
    await screen.findByText('Group catalogue unavailable. Search again.');
    expect(screen.queryByText('Settlement operators')).not.toBeInTheDocument();
    expect(screen.queryByText('private-owner-detail')).not.toBeInTheDocument();
    expect(screen.queryByText(/No active groups|No authorized groups/u)).not.toBeInTheDocument();
    await userEvent.setup().click(screen.getByRole('button', { name: 'Search groups' }));
    await screen.findByText('Settlement operators');
    expect(fetch).toHaveBeenCalledTimes(2);
    expect(fetch.mock.calls.every(([, init]) => init?.method === undefined)).toBe(true);
    expect(open).not.toHaveBeenCalled();
  },
);
it('redacts a private transport exception and supports the same GET retry', async () => {
  const fetch = vi
    .spyOn(globalThis, 'fetch')
    .mockRejectedValueOnce(new Error('private-owner-detail'))
    .mockResolvedValueOnce(Response.json(page));
  const open = vi.fn();
  render(<GroupCatalogue actor={actor} refreshEpoch={0} onOpen={open} />);
  await screen.findByText('Group catalogue unavailable. Search again.');
  expect(screen.queryByText('private-owner-detail')).not.toBeInTheDocument();
  await userEvent.setup().click(screen.getByRole('button', { name: 'Search groups' }));
  await screen.findByText('Settlement operators');
  expect(fetch).toHaveBeenCalledTimes(2);
  expect(open).not.toHaveBeenCalled();
});
it.each([
  [
    'foreign Participant',
    { ...page, items: [{ effect: { ...group.effect, participantId: id('102') } }] },
  ],
  ['inactive row', { ...page, items: [{ effect: { ...group.effect, state: 'RETIRED' } }] }],
  ['non-UUID ID', { ...page, items: [{ effect: { ...group.effect, groupId: 'invalid-id' } }] }],
  ['duplicate IDs', { ...page, items: [group, group] }],
  [
    'descending IDs',
    { ...page, items: [{ effect: { ...group.effect, groupId: id('826') } }, group] },
  ],
  [
    'more than 25 rows',
    {
      ...fullPage(),
      items: [...fullPage().items, { effect: { ...group.effect, groupId: id('826') } }],
      nextCursor: null,
    },
  ],
  ['partial cursor page', { ...page, nextCursor: group.effect.groupId }],
  ['wrong last cursor', { ...fullPage(), nextCursor: id('826') }],
  ['empty cursor', { ...page, items: [], authorizedEmpty: true, nextCursor: group.effect.groupId }],
])('rejects current %s without a selection, cursor or empty assertion', async (_, body) => {
  vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(Response.json(body));
  const open = vi.fn();
  render(<GroupCatalogue actor={actor} refreshEpoch={0} onOpen={open} />);
  await screen.findByText('Group catalogue could not be confirmed. Search again.');
  expect(screen.queryByText('Settlement operators')).not.toBeInTheDocument();
  expect(screen.queryByRole('button', { name: 'Next group page' })).not.toBeInTheDocument();
  expect(screen.queryByText(/No active groups|No authorized groups/u)).not.toBeInTheDocument();
  expect(open).not.toHaveBeenCalled();
});
it('rejects a cursor page at or before the requested UUID without retaining old rows', async () => {
  const fetch = vi
    .spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(Response.json(fullPage()))
    .mockResolvedValueOnce(Response.json(page));
  const open = vi.fn();
  render(<GroupCatalogue actor={actor} refreshEpoch={0} onOpen={open} />);
  await userEvent.setup().click(await screen.findByRole('button', { name: 'Next group page' }));
  await screen.findByText('Group catalogue could not be confirmed. Search again.');
  expect(String(fetch.mock.calls[1]?.[0])).toContain(`after=${id('825')}`);
  expect(screen.queryByText('Settlement operators')).not.toBeInTheDocument();
  expect(open).not.toHaveBeenCalled();
});
it('requires displayed rows to match the actual submitted trimmed search filter', async () => {
  vi.spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(Response.json(page))
    .mockResolvedValueOnce(Response.json(page));
  const open = vi.fn();
  render(<GroupCatalogue actor={actor} refreshEpoch={0} onOpen={open} />);
  await screen.findByText('Settlement operators');
  const user = userEvent.setup();
  await user.type(screen.getByRole('textbox', { name: 'Search group names' }), ' absent ');
  await user.click(screen.getByRole('button', { name: 'Search groups' }));
  await screen.findByText('Group catalogue could not be confirmed. Search again.');
  expect(screen.queryByText('Settlement operators')).not.toBeInTheDocument();
  expect(open).not.toHaveBeenCalled();
});
it.each(['sessionId', 'principalId', 'participantId', 'privacyDomainId', 'contextEpoch'] as const)(
  'rejects a response bound to a different %s without a row',
  async (key) => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(
      Response.json({
        ...page,
        actor: { ...actor, [key]: key === 'contextEpoch' ? '9' : id('102') },
      }),
    );
    const open = vi.fn();
    render(<GroupCatalogue actor={actor} refreshEpoch={0} onOpen={open} />);
    await screen.findByText(
      'The working context changed. Refresh the group workflow before continuing.',
    );
    expect(screen.queryByText('Settlement operators')).not.toBeInTheDocument();
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
  const view = render(<GroupCatalogue actor={actor} refreshEpoch={0} onOpen={open} />);
  await waitFor(() => expect(json).toHaveBeenCalledTimes(1));
  const nextActor = { ...actor, contextEpoch: '3' };
  const signal = fetch.mock.calls[0]?.[1]?.signal;
  view.rerender(<GroupCatalogue actor={nextActor} refreshEpoch={0} onOpen={open} />);
  expect(signal?.aborted).toBe(true);
  await act(async () => resolveBody(page));
  expect(screen.getByRole('button', { name: 'Search groups' })).toBeDisabled();
  expect(screen.queryByText('Settlement operators')).not.toBeInTheDocument();
  await act(async () => next.resolve(Response.json({ ...page, actor: nextActor })));
  await screen.findByText('Settlement operators');
  expect(screen.getByRole('button', { name: 'Search groups' })).toBeEnabled();
  expect(open).not.toHaveBeenCalled();
});
