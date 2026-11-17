import { act, render, screen, waitFor, cleanup } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, expect, it, vi } from 'vitest';
import { performWebAuthnStepUp } from '@openpc/ui-shell';
import { PrincipalCatalogue } from './principal-catalogue';
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
const actor = {
  sessionId: 'session',
  principalId: 'principal',
  participantId: 'participant',
  privacyDomainId: 'privacy',
  contextEpoch: '2',
  role: 'operator',
};
const principal = {
  effect: {
    principalId: 'principal-result',
    displayLabel: 'Current reader',
    kind: 'USER',
    state: 'ACTIVE',
    revision: '1',
  },
};
const catalogue = {
  actor,
  items: [principal],
  nextCursor: 'principal-result',
  observedAt: '2026-09-14T00:00:00Z',
  authorizedEmpty: false,
};
function deferredResponse() {
  let resolve!: (value: Response) => void;
  let reject!: (cause: Error) => void;
  const promise = new Promise<Response>((accept, fail) => {
    resolve = accept;
    reject = fail;
  });
  return { promise, resolve, reject };
}

it('loads active users automatically, offers assignment and clears results on context mismatch', async () => {
  const page = {
    actor,
    items: [
      {
        effect: {
          principalId: 'principal-result',
          displayLabel: 'Audit reader',
          kind: 'USER',
          state: 'ACTIVE',
          revision: '1',
        },
      },
    ],
    nextCursor: null,
    observedAt: '2026-09-14T00:00:00Z',
    authorizedEmpty: false,
  };
  const fetch = vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(Response.json(page));
  const open = vi.fn();
  render(<PrincipalCatalogue actor={actor} onOpen={open} />);
  const user = userEvent.setup();
  expect(screen.getByRole('combobox', { name: 'Principal state' })).toHaveValue('ACTIVE');
  expect(screen.getByRole('combobox', { name: 'Principal type' })).toHaveValue('USER');
  await user.click(await screen.findByRole('button', { name: 'Open Audit reader' }));
  expect(open).toHaveBeenCalledWith('principal-result');
  expect(screen.getByRole('link', { name: 'Assign role to Audit reader' })).toHaveAttribute(
    'href',
    '/govern/memberships?view=grants&principalId=principal-result',
  );
  expect(String(fetch.mock.calls[0]![0])).toContain('state=ACTIVE&kind=USER&limit=25');
  fetch.mockResolvedValueOnce(Response.json({ ...page, actor: { ...actor, contextEpoch: '3' } }));
  await user.click(screen.getByRole('button', { name: 'Search principals' }));
  await waitFor(() =>
    expect(screen.getByRole('status').textContent).toContain('working context changed'),
  );
  expect(screen.queryByRole('button', { name: 'Open Audit reader' })).toBeNull();
});

it('preserves search filters while advancing the cursor', async () => {
  const first = {
    actor,
    items: [
      {
        effect: {
          principalId: 'workload-one',
          displayLabel: 'Workload one',
          kind: 'WORKLOAD',
          state: 'ACTIVE',
          revision: '1',
        },
      },
    ],
    nextCursor: 'workload-one',
    observedAt: '2026-09-14T00:00:00Z',
    authorizedEmpty: false,
  };
  const second = {
    ...first,
    items: [
      {
        effect: {
          ...first.items[0]!.effect,
          principalId: 'workload-two',
          displayLabel: 'Workload two',
        },
      },
    ],
    nextCursor: null,
  };
  const fetch = vi
    .spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(
      Response.json({ ...first, items: [], nextCursor: null, authorizedEmpty: true }),
    )
    .mockResolvedValueOnce(Response.json(first))
    .mockResolvedValueOnce(Response.json(second));
  render(<PrincipalCatalogue actor={actor} onOpen={vi.fn()} />);
  const user = userEvent.setup();
  await screen.findByText('No authorized principals match this search.');
  await user.type(screen.getByRole('textbox', { name: 'Search principal names' }), 'Workload');
  await user.selectOptions(screen.getByRole('combobox', { name: 'Principal state' }), 'ACTIVE');
  await user.selectOptions(screen.getByRole('combobox', { name: 'Principal type' }), 'WORKLOAD');
  await user.click(screen.getByRole('button', { name: 'Search principals' }));
  await user.click(await screen.findByRole('button', { name: 'Next principal page' }));
  await screen.findByText('Workload two');
  expect(String(fetch.mock.calls[2]![0])).toContain(
    'search=Workload&state=ACTIVE&kind=WORKLOAD&limit=25&after=workload-one',
  );
});
it.each([
  ['items object', { ...catalogue, items: {} }],
  ['effect boolean', { ...catalogue, items: [{ effect: false }] }],
  [
    'empty display label',
    { ...catalogue, items: [{ effect: { ...principal.effect, displayLabel: '' } }] },
  ],
  [
    'display label object',
    { ...catalogue, items: [{ effect: { ...principal.effect, displayLabel: {} } }] },
  ],
  ['kind array', { ...catalogue, items: [{ effect: { ...principal.effect, kind: [] } }] }],
  ['state object', { ...catalogue, items: [{ effect: { ...principal.effect, state: {} } }] }],
  [
    'revision boolean',
    { ...catalogue, items: [{ effect: { ...principal.effect, revision: false } }] },
  ],
  ['cursor boolean', { ...catalogue, nextCursor: true }],
  ['invalid observation', { ...catalogue, observedAt: 'unknown' }],
  ['missing empty proof', { ...catalogue, items: [], authorizedEmpty: undefined }],
  ['contradictory empty proof', { ...catalogue, authorizedEmpty: true }],
])(
  'rejects matching-actor malformed %s without an open or role assignment projection',
  async (_, value) => {
    const fetch = vi.spyOn(globalThis, 'fetch').mockResolvedValue(Response.json(value));
    const open = vi.fn();
    render(<PrincipalCatalogue actor={actor} onOpen={open} />);
    await screen.findByText('Principal catalogue could not be confirmed. Search again.');
    expect(screen.queryByText('Current reader')).not.toBeInTheDocument();
    expect(screen.queryByRole('link', { name: /Assign role/u })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Next principal page' })).not.toBeInTheDocument();
    expect(
      screen.queryByText('No authorized principals match this search.'),
    ).not.toBeInTheDocument();
    expect(open).not.toHaveBeenCalled();
    expect(fetch.mock.calls.some(([, init]) => init?.method === 'POST')).toBe(false);
  },
);
it('reports an unreadable principal response with safe retry guidance', async () => {
  vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response('<html>Unavailable</html>'));
  render(<PrincipalCatalogue actor={actor} onOpen={vi.fn()} />);
  await screen.findByText('Principal catalogue could not be confirmed. Search again.');
  expect(screen.queryByText('No authorized principals match this search.')).not.toBeInTheDocument();
});
it('accepts harmless response fields without losing principal selection or the governed assignment link', async () => {
  vi.spyOn(globalThis, 'fetch').mockResolvedValue(
    Response.json({
      ...catalogue,
      hint: {},
      actor: { ...actor, hint: [] },
      items: [{ ...principal, hint: false, effect: { ...principal.effect, hint: {} } }],
    }),
  );
  const open = vi.fn();
  render(<PrincipalCatalogue actor={actor} onOpen={open} />);
  await userEvent.setup().click(await screen.findByRole('button', { name: 'Open Current reader' }));
  expect(open).toHaveBeenCalledWith(principal.effect.principalId);
  expect(screen.getByRole('link', { name: 'Assign role to Current reader' })).toHaveAttribute(
    'href',
    '/govern/memberships?view=grants&principalId=principal-result',
  );
});
it.each(['denial', 'unavailable'])(
  'removes principal selection and assignment links on current %s',
  async (failure) => {
    const fetch = vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(Response.json(catalogue));
    const open = vi.fn();
    render(<PrincipalCatalogue actor={actor} onOpen={open} />);
    await screen.findByText('Current reader');
    if (failure === 'denial')
      fetch.mockResolvedValueOnce(
        Response.json(
          { title: 'Current principals denied', code: 'PC-AUTH-0005' },
          { status: 403 },
        ),
      );
    else fetch.mockRejectedValueOnce(new Error('Current principals unavailable.'));
    await userEvent.setup().click(screen.getByRole('button', { name: 'Search principals' }));
    await screen.findByText(
      failure === 'denial'
        ? 'Current principals denied (PC-AUTH-0005)'
        : 'Current principals unavailable.',
    );
    expect(screen.queryByText('Current reader')).not.toBeInTheDocument();
    expect(screen.queryByRole('link', { name: /Assign role/u })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Next principal page' })).not.toBeInTheDocument();
    expect(
      screen.queryByText('No authorized principals match this search.'),
    ).not.toBeInTheDocument();
    expect(open).not.toHaveBeenCalled();
  },
);
it.each(['success', 'failure'])(
  'aborts an older principal read on actor change and ignores late %s while current inventory is busy',
  async (result) => {
    const old = deferredResponse(),
      next = deferredResponse();
    const nextActor = { ...actor, sessionId: 'next-session', contextEpoch: '3' };
    const fetch = vi
      .spyOn(globalThis, 'fetch')
      .mockReturnValueOnce(old.promise)
      .mockReturnValueOnce(next.promise);
    const view = render(<PrincipalCatalogue actor={actor} onOpen={vi.fn()} />);
    const signal = fetch.mock.calls[0]?.[1]?.signal;
    view.rerender(<PrincipalCatalogue actor={nextActor} onOpen={vi.fn()} />);
    expect(signal?.aborted).toBe(true);
    await act(async () =>
      result === 'success'
        ? old.resolve(Response.json(catalogue))
        : old.reject(new Error('Obsolete principals failed.')),
    );
    expect(screen.getByRole('button', { name: 'Search principals' })).toBeDisabled();
    expect(screen.queryByText('Current reader')).not.toBeInTheDocument();
    expect(screen.queryByText('Obsolete principals failed.')).not.toBeInTheDocument();
    await act(async () => next.resolve(Response.json({ ...catalogue, actor: nextActor })));
    await screen.findByText('Current reader');
    expect(screen.getByRole('button', { name: 'Search principals' })).toBeEnabled();
  },
);
it.each(['success', 'failure'])(
  'ignores a late principal cursor %s after privacy change and starts a fresh cursor-free search',
  async (result) => {
    const old = deferredResponse();
    const nextActor = { ...actor, privacyDomainId: 'next-privacy', contextEpoch: '3' };
    const fetch = vi
      .spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(Response.json(catalogue))
      .mockReturnValueOnce(old.promise)
      .mockResolvedValueOnce(
        Response.json({
          ...catalogue,
          actor: nextActor,
          items: [],
          nextCursor: null,
          authorizedEmpty: true,
        }),
      );
    const open = vi.fn();
    const view = render(<PrincipalCatalogue actor={actor} onOpen={open} />);
    await userEvent
      .setup()
      .click(await screen.findByRole('button', { name: 'Next principal page' }));
    const signal = fetch.mock.calls[1]?.[1]?.signal;
    view.rerender(<PrincipalCatalogue actor={nextActor} onOpen={open} />);
    await screen.findByText('No authorized principals match this search.');
    expect(signal?.aborted).toBe(true);
    expect(String(fetch.mock.calls[2]?.[0])).not.toContain('after=');
    await act(async () =>
      result === 'success'
        ? old.resolve(Response.json(catalogue))
        : old.reject(new Error('Old principal cursor failed.')),
    );
    expect(screen.queryByText('Current reader')).not.toBeInTheDocument();
    expect(screen.queryByText('Old principal cursor failed.')).not.toBeInTheDocument();
    expect(screen.getByText('No authorized principals match this search.')).toBeVisible();
    expect(open).not.toHaveBeenCalled();
  },
);
it.each(['success', 'failure'])(
  'aborts an unmounted principal catalogue and ignores its late %s',
  async (result) => {
    const pending = deferredResponse();
    const fetch = vi.spyOn(globalThis, 'fetch').mockReturnValue(pending.promise);
    const open = vi.fn();
    const view = render(<PrincipalCatalogue actor={actor} onOpen={open} />);
    const signal = fetch.mock.calls[0]?.[1]?.signal;
    view.unmount();
    expect(signal?.aborted).toBe(true);
    await act(async () =>
      result === 'success'
        ? pending.resolve(Response.json(catalogue))
        : pending.reject(new Error('Unmounted principal read failed.')),
    );
    expect(fetch).toHaveBeenCalledTimes(1);
    expect(open).not.toHaveBeenCalled();
  },
);

const selectionActor = {
  ...actor,
  sessionId: '018f0000-0000-7000-8000-000000000701',
  principalId: '018f0000-0000-7000-8000-000000000111',
  participantId: '018f0000-0000-7000-8000-000000000102',
  privacyDomainId: '018f0000-0000-7000-8000-000000000202',
};
const choiceId = '018f0000-0000-7000-8000-000000000190';
function choicePage(kind = 'WORKLOAD') {
  return {
    ...catalogue,
    actor: selectionActor,
    items: [
      {
        effect: {
          ...principal.effect,
          principalId: choiceId,
          participantId: selectionActor.participantId,
          identityEpoch: '1',
          displayLabel: 'Named current choice',
          kind,
        },
        operationId: null,
      },
    ],
    nextCursor: null,
    completeness: 'COMPLETE',
  };
}
function fullChoicePage(start = 190) {
  const items = Array.from({ length: 25 }, (_, index) => ({
    effect: {
      ...choicePage().items[0]!.effect,
      principalId: `018f0000-0000-7000-8000-${String(start + index).padStart(12, '0')}`,
      displayLabel: index === 0 ? 'Named current choice' : `Named current choice ${index + 1}`,
    },
    operationId: null,
  }));
  return { ...choicePage(), items, nextCursor: items.at(-1)!.effect.principalId };
}
it('shows named choices with exact identity and revision in a native disclosure', async () => {
  vi.spyOn(globalThis, 'fetch').mockResolvedValue(Response.json(choicePage('USER')));
  render(
    <PrincipalCatalogue actor={selectionActor} selection={{ kind: 'USER', onSelect: vi.fn() }} />,
  );
  await screen.findByRole('button', { name: 'Select Named current choice' });
  expect(screen.getByText(choiceId)).not.toBeVisible();
  expect(screen.getByText('Revision 1')).not.toBeVisible();
  const summary = screen.getByText('Principal details', { selector: 'summary' });
  const user = userEvent.setup();
  summary.focus();
  await user.click(summary);
  expect(screen.getByText(choiceId)).toBeVisible();
  expect(screen.getByText('Revision 1')).toBeVisible();
  await user.click(summary);
  expect(screen.getByText(choiceId)).not.toBeVisible();
});
it.each(['USER', 'WORKLOAD'] as const)(
  'selects real ACTIVE %s choices without role assignment or approval',
  async (kind) => {
    const fetch = vi.spyOn(globalThis, 'fetch').mockResolvedValue(Response.json(choicePage(kind)));
    const select = vi.fn();
    render(<PrincipalCatalogue actor={selectionActor} selection={{ kind, onSelect: select }} />);
    await userEvent
      .setup()
      .click(await screen.findByRole('button', { name: 'Select Named current choice' }));
    expect(select).toHaveBeenCalledWith(choiceId, 'Named current choice');
    expect(String(fetch.mock.calls[0]?.[0])).toContain(`state=ACTIVE&kind=${kind}&limit=25`);
    expect(screen.queryByRole('link')).not.toBeInTheDocument();
    expect(screen.queryByRole('combobox')).not.toBeInTheDocument();
    expect(screen.getByText(/Selection does not approve or authorize/)).toBeVisible();
  },
);
it('excludes the maker from checker choices while retaining truthful nonempty metadata', async () => {
  vi.spyOn(globalThis, 'fetch').mockResolvedValue(
    Response.json({
      ...choicePage('USER'),
      items: [
        {
          effect: {
            ...choicePage('USER').items[0]!.effect,
            principalId: selectionActor.principalId,
          },
        },
      ],
    }),
  );
  const select = vi.fn();
  render(
    <PrincipalCatalogue
      actor={selectionActor}
      selection={{
        kind: 'USER',
        excludedPrincipalId: selectionActor.principalId,
        onSelect: select,
      }}
    />,
  );
  expect(await screen.findByText('The current maker cannot check their own change.')).toBeVisible();
  expect(
    screen.queryByRole('button', { name: 'Select Named current choice' }),
  ).not.toBeInTheDocument();
  expect(screen.queryByText('No authorized principals match this search.')).not.toBeInTheDocument();
  expect(select).not.toHaveBeenCalled();
});
it.each([
  { kind: 'USER' },
  { state: 'REVOKED' },
  { state: 'PROVISIONED' },
  { principalId: 'fabricated-id' },
  { revision: 'noncanonical' },
])('rejects a current selection page with a wrong kind/state/identity %j', async (patch) => {
  vi.spyOn(globalThis, 'fetch').mockResolvedValue(
    Response.json({
      ...choicePage(),
      items: [{ effect: { ...choicePage().items[0]!.effect, ...patch } }],
    }),
  );
  const select = vi.fn();
  render(
    <PrincipalCatalogue
      actor={selectionActor}
      selection={{ kind: 'WORKLOAD', onSelect: select }}
    />,
  );
  await screen.findByText('Principal choices are unavailable. Search again.');
  expect(screen.queryByText('Named current choice')).not.toBeInTheDocument();
  expect(select).not.toHaveBeenCalled();
});
it.each([201, 401, 403, 404, 503])(
  'conceals stale choices and private non200 details for selection GET %s and supports GET-only retry',
  async (status) => {
    const fetch = vi
      .spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(Response.json(choicePage()))
      .mockResolvedValueOnce(
        Response.json(
          { ...choicePage(), title: 'private-choice-secret', code: 'private-code' },
          { status },
        ),
      )
      .mockResolvedValueOnce(Response.json(choicePage()));
    render(
      <PrincipalCatalogue
        actor={selectionActor}
        selection={{ kind: 'WORKLOAD', onSelect: vi.fn() }}
      />,
    );
    await screen.findByRole('button', { name: 'Select Named current choice' });
    const user = userEvent.setup();
    await user.click(screen.getByRole('button', { name: 'Search principals' }));
    await screen.findByText('Principal choices are unavailable. Search again.');
    expect(screen.queryByText(/private-choice-secret/)).not.toBeInTheDocument();
    expect(
      screen.queryByRole('button', { name: 'Select Named current choice' }),
    ).not.toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Search principals' }));
    await screen.findByRole('button', { name: 'Select Named current choice' });
    expect(fetch).toHaveBeenCalledTimes(3);
  },
);
it.each(['empty', 'malformed', 'unreadable', 'transport'])(
  'keeps %s selection state truthful and private',
  async (outcome) => {
    const fetch = vi.spyOn(globalThis, 'fetch');
    if (outcome === 'transport') fetch.mockRejectedValue(new Error('private-choice-secret'));
    else if (outcome === 'unreadable')
      fetch.mockResolvedValue(
        new Response('private-choice-secret', { headers: { 'content-type': 'application/json' } }),
      );
    else
      fetch.mockResolvedValue(
        Response.json(
          outcome === 'empty'
            ? { ...choicePage(), items: [], authorizedEmpty: true }
            : {
                ...choicePage(),
                items: [
                  {
                    effect: {
                      principalId: choiceId,
                      displayLabel: { secret: 'private-choice-secret' },
                    },
                  },
                ],
              },
        ),
      );
    render(
      <PrincipalCatalogue
        actor={selectionActor}
        selection={{ kind: 'WORKLOAD', onSelect: vi.fn() }}
      />,
    );
    await screen.findByText(
      outcome === 'empty'
        ? 'No authorized principals match this search.'
        : 'Principal choices are unavailable. Search again.',
    );
    expect(screen.queryByRole('button', { name: /^Select / })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Next principal page' })).not.toBeInTheDocument();
    expect(screen.queryByText(/private-choice-secret/)).not.toBeInTheDocument();
    if (outcome !== 'empty')
      expect(
        screen.queryByText('No authorized principals match this search.'),
      ).not.toBeInTheDocument();
  },
);
it.each(['success', 'failure'])(
  'invalidates a selected-context cursor and ignores its late %s after a privacy change',
  async (outcome) => {
    const old = deferredResponse();
    const nextActor = {
      ...selectionActor,
      privacyDomainId: '018f0000-0000-7000-8000-000000000203',
      contextEpoch: '3',
    };
    const fetch = vi
      .spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(Response.json(fullChoicePage()))
      .mockReturnValueOnce(old.promise)
      .mockResolvedValueOnce(
        Response.json({ ...choicePage(), actor: nextActor, items: [], authorizedEmpty: true }),
      );
    const select = vi.fn();
    const view = render(
      <PrincipalCatalogue
        actor={selectionActor}
        selection={{ kind: 'WORKLOAD', onSelect: select }}
      />,
    );
    await userEvent
      .setup()
      .click(await screen.findByRole('button', { name: 'Next principal page' }));
    const signal = fetch.mock.calls[1]?.[1]?.signal;
    view.rerender(
      <PrincipalCatalogue actor={nextActor} selection={{ kind: 'WORKLOAD', onSelect: select }} />,
    );
    await screen.findByText('No authorized principals match this search.');
    expect(signal?.aborted).toBe(true);
    expect(String(fetch.mock.calls[2]?.[0])).not.toContain('after=');
    await act(async () =>
      outcome === 'success'
        ? old.resolve(Response.json(fullChoicePage(215)))
        : old.reject(new Error('private-old-choice')),
    );
    expect(screen.queryByRole('button', { name: /^Select / })).not.toBeInTheDocument();
    expect(screen.queryByText(/private-old-choice/)).not.toBeInTheDocument();
    expect(select).not.toHaveBeenCalled();
  },
);
it('keeps fixed ACTIVE/kind selection filters through a name search and cursor', async () => {
  const fetch = vi
    .spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(Response.json(fullChoicePage()))
    .mockResolvedValueOnce(Response.json(fullChoicePage()))
    .mockResolvedValueOnce(Response.json(fullChoicePage(215)));
  render(
    <PrincipalCatalogue
      actor={selectionActor}
      selection={{ kind: 'WORKLOAD', onSelect: vi.fn() }}
    />,
  );
  await screen.findByRole('button', { name: 'Select Named current choice' });
  const user = userEvent.setup();
  await user.type(screen.getByRole('textbox', { name: 'Search principal names' }), 'Named');
  await user.click(screen.getByRole('button', { name: 'Search principals' }));
  await user.click(await screen.findByRole('button', { name: 'Next principal page' }));
  expect(String(fetch.mock.calls[1]?.[0])).toContain('search=Named&state=ACTIVE&kind=WORKLOAD');
  expect(String(fetch.mock.calls[2]?.[0])).toContain(
    `search=Named&state=ACTIVE&kind=WORKLOAD&limit=25&after=${fullChoicePage().nextCursor}`,
  );
});
it.each(['partial cursor', 'foreign cursor', 'duplicate identity', 'unordered rows'])(
  'rejects a %s selection page before displaying choices',
  async (kind) => {
    const page = fullChoicePage();
    const invalid =
      kind === 'partial cursor'
        ? { ...choicePage(), nextCursor: choiceId }
        : kind === 'foreign cursor'
          ? { ...page, nextCursor: choiceId }
          : {
              ...page,
              items:
                kind === 'duplicate identity'
                  ? [page.items[0]!, page.items[0]!]
                  : [...page.items].reverse(),
              nextCursor: null,
            };
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(Response.json(invalid));
    render(
      <PrincipalCatalogue
        actor={selectionActor}
        selection={{ kind: 'WORKLOAD', onSelect: vi.fn() }}
      />,
    );
    await screen.findByText('Principal choices are unavailable. Search again.');
    expect(screen.queryByRole('button', { name: /^Select / })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Next principal page' })).not.toBeInTheDocument();
  },
);
