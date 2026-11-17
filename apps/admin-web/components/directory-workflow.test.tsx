import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { performWebAuthnStepUp } from '@openpc/ui-shell';
import { DirectoryWorkflow } from './directory-workflow';
import { writeBoundPolicyState } from './policy-workflow-storage';
vi.mock('@openpc/ui-shell', () => ({ performWebAuthnStepUp: vi.fn(async () => undefined) }));
vi.mock('./local-session', () => ({
  LocalSessionSurface: () => <p>Authenticated session controls</p>,
}));
const id = (value: string) => `018f0000-0000-7000-8000-${value.padStart(12, '0')}`;
const actor = {
  sessionId: id('701'),
  principalId: id('111'),
  participantId: id('101'),
  privacyDomainId: id('201'),
  contextEpoch: '2',
};
const candidate = {
  change: { mutation: 'SUSPEND', connectorId: id('192') },
  expectedRevision: '3',
  profileDigest: `sha256:${'c'.repeat(64)}`,
};
const review = {
  reviewToken: 'r'.repeat(100),
  approvalRequestId: id('801'),
  review: {
    candidate,
    resourceId: id('192'),
    expectedRevision: '3',
    candidateDigest: `sha256:${'a'.repeat(64)}`,
    checkerPrincipalId: id('112'),
    reason: 'Suspend this registered directory connector.',
    expiresAt: new Date(Date.now() + 300000).toISOString(),
    stepUp: {
      actionIntentId: 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
      actionIntentDigest: `sha256:${'b'.repeat(64)}`,
      resourceId: id('192'),
      resourceDigest: `sha256:${'a'.repeat(64)}`,
    },
  },
};
const state = {
  actor,
  profiles: [{ profileId: id('141'), label: 'Corporate directory' }],
  approvals: [],
  nextCursor: null,
};
const localSession = (currentActor = actor) => ({
  authenticated: true,
  contextMode: 'PARTICIPANT',
  ...currentActor,
});
function withSession(
  owner: (url: RequestInfo | URL, options?: RequestInit) => Promise<Response>,
  currentActor = actor,
) {
  return vi
    .spyOn(globalThis, 'fetch')
    .mockImplementation((url, options) =>
      String(url) === '/api/v1/ui/local-session'
        ? Promise.resolve(Response.json(localSession(currentActor)))
        : owner(url, options),
    );
}
beforeEach(() => {
  localStorage.clear();
  vi.clearAllMocks();
});
afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});
it('retains a confirmed commit and directs reauthentication without overwriting it with a stale-session read', async () => {
  writeBoundPolicyState('openpc:directory-workflow:v1', actor, review);
  const fetch = withSession(async (_url, options) =>
    options?.method === 'POST'
      ? Response.json({
          truthState: 'SUCCESS',
          operationId: id('850'),
          requiresReauthentication: true,
        })
      : Response.json(state),
  );
  render(<DirectoryWorkflow />);
  await waitFor(() => expect(screen.getByLabelText('Directory change review')).toBeVisible());
  await userEvent
    .setup()
    .click(screen.getByRole('button', { name: 'Verify and commit directory change' }));
  await expect(screen.findByRole('status')).resolves.toHaveTextContent(
    `Directory change committed. Operation: ${id('850')} Sign in again`,
  );
  expect(
    fetch.mock.calls.filter(([url]) => String(url) !== '/api/v1/ui/local-session'),
  ).toHaveLength(3);
  expect(performWebAuthnStepUp).toHaveBeenCalledOnce();
});
it('preserves a business denial rather than presenting it as a lost response', async () => {
  writeBoundPolicyState('openpc:directory-workflow:v1', actor, review);
  withSession(async (_url, options) =>
    options?.method === 'POST'
      ? Response.json(
          { title: 'The reviewed provider observation is stale.', code: 'PC-DATA-6007' },
          { status: 409 },
        )
      : Response.json(state),
  );
  render(<DirectoryWorkflow />);
  await waitFor(() => expect(screen.getByLabelText('Directory change review')).toBeVisible());
  await userEvent
    .setup()
    .click(screen.getByRole('button', { name: 'Verify and commit directory change' }));
  await expect(screen.findByRole('alert')).resolves.toHaveTextContent(
    'provider observation is stale',
  );
  expect(screen.queryByRole('status')).not.toBeInTheDocument();
});
it('does not restore a review after the session or privacy context changes', async () => {
  writeBoundPolicyState('openpc:directory-workflow:v1', actor, review);
  const currentActor = { ...actor, sessionId: id('702') };
  withSession(async () => Response.json({ ...state, actor: currentActor }), currentActor);
  render(<DirectoryWorkflow />);
  await waitFor(() =>
    expect(screen.getByRole('button', { name: 'Prepare directory change' })).toBeEnabled(),
  );
  expect(screen.queryByLabelText('Directory change review')).not.toBeInTheDocument();
});
it('requires exact provider and local identity inputs for reconciliation without exposing provider secrets', async () => {
  withSession(async () => Response.json(state));
  render(<DirectoryWorkflow />);
  await waitFor(() =>
    expect(screen.getByRole('button', { name: 'Prepare directory change' })).toBeEnabled(),
  );
  await userEvent
    .setup()
    .selectOptions(screen.getByRole('combobox', { name: 'Change' }), 'RECONCILE');
  expect(screen.getByRole('textbox', { name: 'Exact provider user ID' })).toBeRequired();
  expect(screen.getByRole('textbox', { name: 'Local member principal ID' })).toBeRequired();
  expect(
    screen.queryByRole('combobox', { name: 'Registered directory profile' }),
  ).not.toBeInTheDocument();
  expect(screen.queryByLabelText(/private key|provider token/iu)).not.toBeInTheDocument();
});

type Reader = 'list' | 'connector' | 'group' | 'member';
const readers: Reader[] = ['list', 'connector', 'group', 'member'];
const now = '2026-10-04T12:00:00.000Z';
const connector = {
  effect: {
    connectorId: id('192'),
    participantId: actor.participantId,
    profileId: id('141'),
    profileDigest: `sha256:${'c'.repeat(64)}`,
    displayName: 'Corporate directory',
    massChangeThreshold: 5,
    externalGroupFreshnessSeconds: 900,
    state: 'ACTIVE',
    revision: '5',
    operationId: id('850'),
    createdAt: now,
    updatedAt: now,
  },
};
const group = {
  group: {
    effect: {
      groupId: id('193'),
      participantId: actor.participantId,
      groupName: 'Local directory group',
      state: 'ACTIVE',
      revision: '5',
      createdAt: now,
      updatedAt: now,
      operationId: id('851'),
    },
    members: [
      {
        memberId: id('901'),
        principalId: id('142'),
        displayName: 'Directory colleague',
        state: 'ACTIVE',
        current: true,
        joinedAt: now,
        validUntil: null,
        revokedAt: null,
      },
    ],
    nextCursor: null,
  },
  mapping: {
    connectorId: id('192'),
    externalGroupId: 'external-group',
    profileDigest: `sha256:${'c'.repeat(64)}`,
    providerVersion: 'W/"2"',
    providerModifiedAt: now,
    observedAt: now,
    freshUntil: '2026-10-04T12:15:00.000Z',
    fresh: true,
    revision: '3',
    operationId: id('851'),
  },
};
const member = {
  binding: {
    participantId: actor.participantId,
    connectorId: id('192'),
    externalId: 'provider-A',
    principalId: id('142'),
    state: 'LINKED',
    providerVersion: 'W/"2"',
    providerModifiedAt: now,
    observedAt: now,
    revision: '2',
    operationId: id('852'),
  },
  membership: {
    principalId: id('142'),
    displayLabel: 'Directory colleague',
    state: 'ACTIVE',
    revision: '2',
  },
};
const values = { list: state, connector, group, member };
const labels = {
  connector: 'Directory result',
  group: 'Directory group result',
  member: 'Directory member result',
};
const unavailable = 'The directory read is unavailable. Retry the same read.';
const contextUnavailable =
  'The directory context is unavailable or changed. Refresh directory approvals.';
function pendingResponse() {
  let resolve!: (value: Response) => void;
  let reject!: (cause: Error) => void;
  const promise = new Promise<Response>((yes, no) => {
    resolve = yes;
    reject = no;
  });
  return { promise, resolve, reject };
}
function harness() {
  const counts: Record<Reader, number> = { list: 0, connector: 0, group: 0, member: 0 };
  const handlers: Record<Reader, () => Promise<Response>> = {
    list: async () => Response.json(state),
    connector: async () => Response.json(connector),
    group: async () => Response.json(group),
    member: async () => Response.json(member),
  };
  const session = { read: async () => Response.json(localSession()) };
  const mutation = {
    write: async (_body: unknown): Promise<Response> => {
      throw new Error('Unexpected POST');
    },
  };
  const fetcher = vi.spyOn(globalThis, 'fetch').mockImplementation(async (url, init) => {
    if (String(url) === '/api/v1/ui/local-session') return session.read();
    if (init?.method === 'POST') return mutation.write(JSON.parse(String(init.body)));
    const query = new URL(String(url), 'http://localhost').searchParams;
    const reader: Reader = query.has('groupId')
      ? 'group'
      : query.has('externalId')
        ? 'member'
        : query.has('connectorId')
          ? 'connector'
          : 'list';
    counts[reader] += 1;
    return handlers[reader]();
  });
  return { handlers, session, mutation, fetcher, counts };
}
async function ready() {
  const view = render(<DirectoryWorkflow />);
  await waitFor(() =>
    expect(screen.getByRole('button', { name: 'Prepare directory change' })).toBeEnabled(),
  );
  return view;
}
function clickRead(reader: Reader) {
  if (reader === 'list')
    fireEvent.click(screen.getByRole('button', { name: 'Refresh directory approvals' }));
  else {
    if (reader === 'group')
      fireEvent.change(screen.getByLabelText('Saved local group ID'), {
        target: { value: id('193') },
      });
    else
      fireEvent.change(screen.getByLabelText('Saved connector ID'), {
        target: { value: id('192') },
      });
    if (reader === 'member')
      fireEvent.change(screen.getByLabelText('Saved provider user ID'), {
        target: { value: 'provider-A' },
      });
    fireEvent.click(
      screen.getByRole('button', {
        name:
          reader === 'connector'
            ? 'Read connector'
            : reader === 'group'
              ? 'Read directory group'
              : 'Read directory member',
      }),
    );
  }
}
async function expectProjection(reader: Reader) {
  if (reader === 'list') await screen.findByText('No directory approvals on this page.');
  else await screen.findByLabelText(labels[reader]);
}
function expectNoProjection(reader: Reader) {
  if (reader === 'list') {
    expect(screen.queryByText('No directory approvals on this page.')).not.toBeInTheDocument();
    expect(
      screen.queryByRole('combobox', { name: 'Registered directory profile' }),
    ).not.toBeInTheDocument();
  } else expect(screen.queryByLabelText(labels[reader])).not.toBeInTheDocument();
}
function expectNoWrites(fetcher: ReturnType<typeof harness>['fetcher']) {
  expect(fetcher.mock.calls.every(([, init]) => init?.method !== 'POST')).toBe(true);
}

it.each(readers)(
  'reads the current %s projection through public session checks with no mutation',
  async (reader) => {
    const h = harness();
    await ready();
    clickRead(reader);
    await expectProjection(reader);
    expectNoWrites(h.fetcher);
    const gets = h.fetcher.mock.calls.filter(([url]) => String(url) !== '/api/v1/ui/local-session');
    expect(
      gets.every(([, init]) => init?.cache === 'no-store' && init.signal instanceof AbortSignal),
    ).toBe(true);
    expect(
      h.fetcher.mock.calls.filter(([url]) => String(url) === '/api/v1/ui/local-session').length,
    ).toBeGreaterThanOrEqual(4);
  },
);

it.each(
  readers.flatMap((reader) => [201, 202, 206, 503].map((status) => [reader, status] as const)),
)(
  'hides the old %s projection when a valid-shaped owner response has HTTP %s',
  async (reader, status) => {
    const h = harness();
    await ready();
    clickRead(reader);
    await expectProjection(reader);
    h.handlers[reader] = async () => Response.json(values[reader], { status });
    clickRead(reader);
    const alert = await screen.findByRole('alert');
    expect(alert).toHaveTextContent(unavailable);
    await waitFor(() => expect(alert).toHaveFocus());
    expectNoProjection(reader);
    expectNoWrites(h.fetcher);
  },
);

it.each(readers)(
  'clears a previous %s projection on private malformed JSON, then retries only GET',
  async (reader) => {
    const h = harness();
    await ready();
    clickRead(reader);
    await expectProjection(reader);
    h.handlers[reader] = async () =>
      new Response('{private-sentinel', { headers: { 'Content-Type': 'application/json' } });
    clickRead(reader);
    expect(await screen.findByRole('alert')).toHaveTextContent(unavailable);
    expectNoProjection(reader);
    expect(document.body).not.toHaveTextContent('private-sentinel');
    h.handlers[reader] = async () => Response.json(values[reader]);
    if (reader !== 'list') {
      fireEvent.click(screen.getByRole('button', { name: 'Refresh directory approvals' }));
      await waitFor(() =>
        expect(screen.getByRole('button', { name: 'Prepare directory change' })).toBeEnabled(),
      );
    }
    clickRead(reader);
    await expectProjection(reader);
    expectNoWrites(h.fetcher);
  },
);

it.each(readers.flatMap((reader) => [401, 403, 404].map((status) => [reader, status] as const)))(
  'conceals previous private %s output on current HTTP %s owner denial',
  async (reader, status) => {
    const h = harness();
    await ready();
    clickRead(reader);
    await expectProjection(reader);
    h.handlers[reader] = async () => Response.json({ title: 'private-sentinel' }, { status });
    clickRead(reader);
    expect(await screen.findByRole('alert')).toHaveTextContent(contextUnavailable);
    for (const kind of readers) expectNoProjection(kind);
    expect(screen.queryByLabelText('Directory change review')).not.toBeInTheDocument();
    expect(document.body).not.toHaveTextContent('private-sentinel');
    expectNoWrites(h.fetcher);
  },
);

it.each(readers)(
  'hides %s output while a superseding read is pending and on transport failure',
  async (reader) => {
    const h = harness();
    await ready();
    clickRead(reader);
    await expectProjection(reader);
    const pending = pendingResponse();
    h.handlers[reader] = () => pending.promise;
    const previous = h.counts[reader];
    clickRead(reader);
    await waitFor(() => expect(h.counts[reader]).toBeGreaterThan(previous));
    await waitFor(() => expectNoProjection(reader));
    await act(async () => pending.reject(new Error('private-sentinel')));
    expect(await screen.findByRole('alert')).toHaveTextContent(unavailable);
    expectNoProjection(reader);
    expect(document.body).not.toHaveTextContent('private-sentinel');
    expectNoWrites(h.fetcher);
  },
);

it.each(['sessionId', 'principalId', 'participantId', 'privacyDomainId', 'contextEpoch'] as const)(
  'rejects a list whose final public session %s changes',
  async (field) => {
    const h = harness();
    await ready();
    h.handlers.list = async () => {
      h.session.read = async () =>
        Response.json(
          localSession({ ...actor, [field]: field === 'contextEpoch' ? '3' : id('999') }),
        );
      return Response.json(state);
    };
    clickRead('list');
    expect(await screen.findByRole('alert')).toHaveTextContent(contextUnavailable);
    expectNoProjection('list');
    expectNoWrites(h.fetcher);
  },
);

it.each(['connector', 'group', 'member'] as const)(
  'rejects %s data if the final session privacy context changes',
  async (reader) => {
    const h = harness();
    await ready();
    h.handlers[reader] = async () => {
      h.session.read = async () =>
        Response.json(localSession({ ...actor, privacyDomainId: id('999') }));
      return Response.json(values[reader]);
    };
    clickRead(reader);
    expect(await screen.findByRole('alert')).toHaveTextContent(contextUnavailable);
    for (const kind of readers) expectNoProjection(kind);
    expectNoWrites(h.fetcher);
  },
);

it.each([
  ['unauthenticated', { authenticated: false }],
  ['Platform context', { ...localSession(), contextMode: 'PLATFORM' }],
  ['missing actor', { authenticated: true, contextMode: 'PARTICIPANT' }],
  ['invalid session', null],
] as const)(
  'does not fetch private directory data for %s session readback',
  async (_label, body) => {
    const h = harness();
    h.session.read = async () => Response.json(body);
    render(<DirectoryWorkflow />);
    expect(await screen.findByRole('alert')).toHaveTextContent(contextUnavailable);
    expect(h.fetcher.mock.calls.every(([url]) => String(url) === '/api/v1/ui/local-session')).toBe(
      true,
    );
    expectNoProjection('list');
  },
);

it.each(['connector', 'group', 'member'] as const)(
  'rejects selected-resource substitution in the %s projection',
  async (reader) => {
    const h = harness();
    await ready();
    h.handlers[reader] = async () =>
      Response.json(
        reader === 'connector'
          ? { effect: { ...connector.effect, connectorId: id('999') } }
          : reader === 'group'
            ? {
                ...group,
                group: { ...group.group, effect: { ...group.group.effect, groupId: id('999') } },
              }
            : { ...member, binding: { ...member.binding, externalId: 'foreign-provider' } },
      );
    clickRead(reader);
    expect(await screen.findByRole('alert')).toHaveTextContent(unavailable);
    expectNoProjection(reader);
    expect(document.body).not.toHaveTextContent('foreign-provider');
    expectNoWrites(h.fetcher);
  },
);

it('rejects a member binding whose principal differs from the membership projection', async () => {
  const h = harness();
  await ready();
  h.handlers.member = async () =>
    Response.json({ ...member, membership: { ...member.membership, principalId: id('999') } });
  clickRead('member');
  expect(await screen.findByRole('alert')).toHaveTextContent(unavailable);
  expectNoProjection('member');
  expectNoWrites(h.fetcher);
});

it('retains membership field filtering from the existing decoder', async () => {
  const h = harness();
  await ready();
  h.handlers.member = async () =>
    Response.json({
      ...member,
      membership: { ...member.membership, privateToken: 'private-sentinel' },
    });
  clickRead('member');
  await expectProjection('member');
  expect(document.body).not.toHaveTextContent('private-sentinel');
  expectNoWrites(h.fetcher);
});

it.each(readers)('does not render private fields from a malformed %s schema', async (reader) => {
  const h = harness();
  await ready();
  h.handlers[reader] = async () => Response.json({ privateToken: 'private-sentinel' });
  clickRead(reader);
  expect(await screen.findByRole('alert')).toHaveTextContent(unavailable);
  expectNoProjection(reader);
  expect(document.body).not.toHaveTextContent('private-sentinel');
  expectNoWrites(h.fetcher);
});

it('rejects a list for a foreign actor even when the public session remains current', async () => {
  const h = harness();
  await ready();
  h.handlers.list = async () =>
    Response.json({ ...state, actor: { ...actor, privacyDomainId: id('999') } });
  clickRead('list');
  expect(await screen.findByRole('alert')).toHaveTextContent(contextUnavailable);
  expectNoProjection('list');
  expectNoWrites(h.fetcher);
});

it.each(['connector', 'group', 'member'] as const)(
  'refuses a foreign Participant %s projection',
  async (reader) => {
    const h = harness();
    await ready();
    h.handlers[reader] = async () =>
      Response.json(
        reader === 'connector'
          ? { effect: { ...connector.effect, participantId: id('999') } }
          : reader === 'group'
            ? {
                ...group,
                group: {
                  ...group.group,
                  effect: { ...group.group.effect, participantId: id('999') },
                },
              }
            : { ...member, binding: { ...member.binding, participantId: id('999') } },
      );
    clickRead(reader);
    expect(await screen.findByRole('alert')).toHaveTextContent(unavailable);
    expectNoProjection(reader);
    expectNoWrites(h.fetcher);
  },
);

it('rejects an approval row assigned to a different checker without displaying its candidate', async () => {
  const h = harness();
  await ready();
  h.handlers.list = async () =>
    Response.json({
      ...state,
      approvals: [
        {
          approvalRequestId: `urn:openpc:resource:${id('801')}`,
          candidateDigest: review.review.candidateDigest,
          makerSubjectRef: `urn:openpc:resource:${id('112')}`,
          checkerSubjectRef: `urn:openpc:resource:${id('999')}`,
          revision: '2',
          state: 'REQUESTED',
          stepUp: review.review.stepUp,
          proposal: {
            candidateDigest: review.review.candidateDigest,
            resourceId: id('192'),
            makerPrincipalId: id('112'),
            catalogOperationId: 'ID-OP-DIRECTORY-CONNECTOR-SUSPEND',
            expectedRevision: '3',
            state: 'PROPOSED',
            operationId: null,
            expiresAt: review.review.expiresAt,
            candidate,
            approval: { approvalRequestId: id('801'), reason: 'Private foreign review reason' },
          },
        },
      ],
    });
  clickRead('list');
  expect(await screen.findByRole('alert')).toHaveTextContent(unavailable);
  expect(document.body).not.toHaveTextContent('Private foreign review reason');
  expectNoProjection('list');
  expectNoWrites(h.fetcher);
});

it('preserves the owner-projected stale directory-group state and its authority-denial text', async () => {
  const h = harness();
  await ready();
  h.handlers.group = async () =>
    Response.json({ ...group, mapping: { ...group.mapping, fresh: false } });
  clickRead('group');
  await expectProjection('group');
  expect(screen.getByLabelText('Directory group result')).toHaveTextContent(
    'Stale — group authority denied',
  );
  expectNoWrites(h.fetcher);
});

it.each(['receipt', 'failure'] as const)(
  'does not let an older initial list %s replace a newer manual lane read',
  async (outcome) => {
    const h = harness();
    const pending = pendingResponse();
    let lists = 0;
    h.handlers.list = () =>
      ++lists === 1 ? pending.promise : Promise.resolve(Response.json(state));
    render(<DirectoryWorkflow />);
    await waitFor(() => expect(lists).toBe(1));
    fireEvent.change(screen.getByRole('combobox', { name: 'Approval lane' }), {
      target: { value: 'maker' },
    });
    await waitFor(() =>
      expect(screen.getByRole('button', { name: 'Prepare directory change' })).toBeEnabled(),
    );
    await act(async () => {
      if (outcome === 'receipt')
        pending.resolve(
          Response.json({
            ...state,
            profiles: [{ profileId: id('999'), label: 'Old private profile' }],
          }),
        );
      else pending.reject(new Error('private-sentinel'));
    });
    expect(screen.getByRole('combobox', { name: 'Approval lane' })).toHaveValue('maker');
    expect(screen.queryByRole('option', { name: 'Old private profile' })).not.toBeInTheDocument();
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    expectNoWrites(h.fetcher);
  },
);

it.each(['connector', 'group', 'member'] as const)(
  'cancels a deferred %s read after its selector changes, without blocking a fresh read',
  async (reader) => {
    const h = harness();
    await ready();
    const pending = pendingResponse();
    h.handlers[reader] = () => pending.promise;
    clickRead(reader);
    await waitFor(() =>
      expect(
        h.fetcher.mock.calls.some(([url]) =>
          new URL(String(url), 'http://localhost').searchParams.has(
            reader === 'group' ? 'groupId' : reader === 'member' ? 'externalId' : 'connectorId',
          ),
        ),
      ).toBe(true),
    );
    const label =
      reader === 'group'
        ? 'Saved local group ID'
        : reader === 'member'
          ? 'Saved provider user ID'
          : 'Saved connector ID';
    fireEvent.change(screen.getByLabelText(label), {
      target: { value: reader === 'member' ? 'provider-B' : id('999') },
    });
    h.handlers[reader] = async () => Response.json(values[reader]);
    clickRead(reader);
    await expectProjection(reader);
    await act(async () =>
      pending.resolve(
        Response.json(
          reader === 'connector'
            ? { effect: { ...connector.effect, displayName: 'Old private display' } }
            : reader === 'group'
              ? {
                  ...group,
                  group: {
                    ...group.group,
                    effect: { ...group.group.effect, groupName: 'Old private display' },
                  },
                }
              : {
                  ...member,
                  membership: { ...member.membership, displayLabel: 'Old private display' },
                },
        ),
      ),
    );
    expect(document.body).not.toHaveTextContent('Old private display');
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    expectNoWrites(h.fetcher);
  },
);

it.each(readers)(
  'rejects a late %s response after blur, then permits an explicit matching-context refresh',
  async (reader) => {
    const h = harness();
    await ready();
    const pending = pendingResponse();
    h.handlers[reader] = () => pending.promise;
    clickRead(reader);
    await waitFor(() =>
      expect(
        h.fetcher.mock.calls.filter(([url]) => String(url) !== '/api/v1/ui/local-session').length,
      ).toBeGreaterThan(reader === 'list' ? 1 : 2),
    );
    fireEvent(window, new Event('blur'));
    await act(async () => pending.resolve(Response.json(values[reader])));
    for (const kind of readers) expectNoProjection(kind);
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    h.handlers[reader] = async () => Response.json(values[reader]);
    clickRead('list');
    await expectProjection('list');
    expectNoWrites(h.fetcher);
  },
);

it('passes the existing UUID group membership cursor unchanged and hides the old page during failure', async () => {
  const h = harness();
  await ready();
  h.handlers.group = async () =>
    Response.json({ ...group, group: { ...group.group, nextCursor: id('991') } });
  clickRead('group');
  await expectProjection('group');
  h.handlers.group = async () => Response.json({ title: 'private-sentinel' }, { status: 503 });
  fireEvent.click(screen.getByRole('button', { name: 'Next group membership page' }));
  expect(await screen.findByRole('alert')).toHaveTextContent(unavailable);
  expectNoProjection('group');
  expect(
    h.fetcher.mock.calls.some(([url]) =>
      String(url).includes(`groupId=${id('193')}&cursor=${id('991')}`),
    ),
  ).toBe(true);
  expect(
    screen.queryByRole('button', { name: 'Next group membership page' }),
  ).not.toBeInTheDocument();
  expectNoWrites(h.fetcher);
});

it.each(readers)(
  'ignores an unfinished %s reader after unmount while a separate reader stays current',
  async (reader) => {
    const h = harness();
    const previous = await ready();
    const pending = pendingResponse();
    h.handlers[reader] = () => pending.promise;
    const count = h.counts[reader];
    clickRead(reader);
    await waitFor(() => expect(h.counts[reader]).toBeGreaterThan(count));
    previous.unmount();
    h.handlers[reader] = async () => Response.json(values[reader]);
    await ready();
    await act(async () => pending.resolve(Response.json(values[reader])));
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Prepare directory change' })).toBeEnabled();
    if (reader !== 'list') expectNoProjection(reader);
    expectNoWrites(h.fetcher);
  },
);

it.each(readers)(
  'rejects deferred %s JSON decoding after blur and a newer current read',
  async (reader) => {
    const h = harness();
    await ready();
    let resolve!: (value: unknown) => void;
    const decoded = new Promise<unknown>((yes) => {
      resolve = yes;
    });
    const response = Response.json(values[reader]);
    const decode = vi.spyOn(response, 'json').mockReturnValueOnce(decoded);
    h.handlers[reader] = async () => response;
    clickRead(reader);
    await waitFor(() => expect(decode).toHaveBeenCalledTimes(1));
    fireEvent(window, new Event('blur'));
    h.handlers[reader] = async () => Response.json(values[reader]);
    clickRead('list');
    await expectProjection('list');
    await act(async () => resolve(values[reader]));
    if (reader !== 'list') expectNoProjection(reader);
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    expectNoWrites(h.fetcher);
  },
);

it('preserves the opaque approval cursor and lane, then removes a failed old page', async () => {
  const h = harness();
  await ready();
  h.handlers.list = async () => Response.json({ ...state, nextCursor: 'existing-opaque-cursor' });
  clickRead('list');
  await screen.findByRole('button', { name: 'Next approvals' });
  h.handlers.list = async () => Response.json({ title: 'private-sentinel' }, { status: 503 });
  fireEvent.click(screen.getByRole('button', { name: 'Next approvals' }));
  expect(await screen.findByRole('alert')).toHaveTextContent(unavailable);
  expectNoProjection('list');
  expect(
    h.fetcher.mock.calls.some(([url]) =>
      String(url).endsWith('lane=checker&cursor=existing-opaque-cursor'),
    ),
  ).toBe(true);
  expectNoWrites(h.fetcher);
});

it.each(['SUCCESS', 'WRITE_AMBIGUITY'] as const)(
  'retains the original %s mutation status/custody across read outage and concealed context, without a second POST',
  async (truthState) => {
    writeBoundPolicyState('openpc:directory-workflow:v1', actor, review);
    const original = localStorage.getItem('openpc:directory-workflow:v1');
    const h = harness();
    h.mutation.write = async () =>
      Response.json(
        {
          truthState,
          ...(truthState === 'SUCCESS'
            ? { operationId: id('850'), readback: connector, requiresReauthentication: true }
            : {}),
        },
        { status: truthState === 'SUCCESS' ? 200 : 202 },
      );
    await ready();
    fireEvent.click(screen.getByRole('button', { name: 'Verify and commit directory change' }));
    const status =
      truthState === 'SUCCESS'
        ? `Directory change committed. Operation: ${id('850')} Sign in again`
        : 'The commit outcome is uncertain.';
    await waitFor(() => expect(screen.getByRole('status')).toHaveTextContent(status));
    h.handlers.list = async () => Response.json({ title: 'private-sentinel' }, { status: 503 });
    clickRead('list');
    expect(await screen.findByRole('alert')).toHaveTextContent(unavailable);
    expect(screen.getByRole('status')).toHaveTextContent(status);
    h.handlers.list = async () => Response.json({ title: 'private-sentinel' }, { status: 401 });
    clickRead('list');
    expect(await screen.findByRole('alert')).toHaveTextContent(contextUnavailable);
    expect(screen.queryByRole('status')).not.toBeInTheDocument();
    h.handlers.list = async () => Response.json(state);
    clickRead('list');
    await expectProjection('list');
    await waitFor(() => expect(screen.getByRole('status')).toHaveTextContent(status));
    expect(localStorage.getItem('openpc:directory-workflow:v1')).toBe(original);
    const writes = h.fetcher.mock.calls.filter(([, init]) => init?.method === 'POST');
    expect(writes).toHaveLength(1);
    expect(JSON.parse(String(writes[0]![1]?.body))).toEqual({
      command: 'COMMIT',
      reviewToken: review.reviewToken,
      approvalRequestId: review.approvalRequestId,
    });
  },
);

it('retains the original successful receipt and warning when its immediate authority refresh fails', async () => {
  writeBoundPolicyState('openpc:directory-workflow:v1', actor, review);
  const original = localStorage.getItem('openpc:directory-workflow:v1');
  const h = harness();
  h.mutation.write = async () => {
    h.handlers.list = async () => Response.json({ title: 'private-sentinel' }, { status: 503 });
    return Response.json({
      truthState: 'SUCCESS',
      operationId: id('850'),
      readback: connector,
      requiresReauthentication: false,
    });
  };
  await ready();
  fireEvent.click(screen.getByRole('button', { name: 'Verify and commit directory change' }));
  expect(await screen.findByRole('alert')).toHaveTextContent(
    'The operation result above is retained. Sign in again to refresh current authority.',
  );
  expect(screen.getByRole('status')).toHaveTextContent(
    `Directory change committed. Operation: ${id('850')}`,
  );
  expect(document.body).not.toHaveTextContent('private-sentinel');
  h.handlers.list = async () => Response.json(state);
  clickRead('list');
  await expectProjection('list');
  expectNoProjection('connector');
  fireEvent.click(screen.getByRole('button', { name: 'Read saved connector' }));
  expect(await screen.findByLabelText('Directory result')).toHaveTextContent('Corporate directory');
  await waitFor(() =>
    expect(screen.getByRole('status')).toHaveTextContent(
      `Directory change committed. Operation: ${id('850')}`,
    ),
  );
  expect(localStorage.getItem('openpc:directory-workflow:v1')).toBe(original);
  expect(h.fetcher.mock.calls.filter(([, init]) => init?.method === 'POST')).toHaveLength(1);
});

it('does not expose the old operation receipt when a different current actor has a list outage', async () => {
  writeBoundPolicyState('openpc:directory-workflow:v1', actor, review);
  const original = localStorage.getItem('openpc:directory-workflow:v1');
  const h = harness();
  h.mutation.write = async () =>
    Response.json({
      truthState: 'SUCCESS',
      operationId: id('850'),
      requiresReauthentication: true,
    });
  await ready();
  fireEvent.click(screen.getByRole('button', { name: 'Verify and commit directory change' }));
  await waitFor(() => expect(screen.getByRole('status')).toHaveTextContent(id('850')));
  h.session.read = async () => Response.json(localSession({ ...actor, principalId: id('999') }));
  h.handlers.list = async () => Response.json({ title: 'private-sentinel' }, { status: 503 });
  clickRead('list');
  expect(await screen.findByRole('alert')).toHaveTextContent(contextUnavailable);
  expect(document.body).not.toHaveTextContent(id('850'));
  expect(screen.queryByLabelText('Directory change review')).not.toBeInTheDocument();
  expect(localStorage.getItem('openpc:directory-workflow:v1')).toBe(original);
  h.session.read = async () => Response.json(localSession());
  h.handlers.list = async () => Response.json(state);
  clickRead('list');
  await expectProjection('list');
  await waitFor(() => expect(screen.getByRole('status')).toHaveTextContent(id('850')));
  expect(h.fetcher.mock.calls.filter(([, init]) => init?.method === 'POST')).toHaveLength(1);
});

it('does not resurrect a previous manual connector read when a failed list is refreshed', async () => {
  const h = harness();
  await ready();
  clickRead('connector');
  await expectProjection('connector');
  h.handlers.list = async () => Response.json({}, { status: 503 });
  clickRead('list');
  expect(await screen.findByRole('alert')).toHaveTextContent(unavailable);
  h.handlers.list = async () => Response.json(state);
  clickRead('list');
  await expectProjection('list');
  expectNoProjection('connector');
  expectNoWrites(h.fetcher);
});
