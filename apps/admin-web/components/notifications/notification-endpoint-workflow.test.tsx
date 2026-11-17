import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { UiRuntimeProvider } from '@openpc/ui-shell';
import { NotificationEndpointWorkflow } from './notification-endpoint-workflow';
import {
  endpointCommand,
  endpointMutation,
  endpointCreateAction,
  endpointUpdateAction,
  type EndpointMutation,
  type EndpointVerifyCommand,
} from '../../lib/notification-endpoint-workflow';

const stepUp = vi.hoisted(() => vi.fn());
vi.mock('@openpc/ui-shell', async (original) => ({
  ...(await original<Record<string, unknown>>()),
  performWebAuthnStepUp: stepUp,
}));

// Component contracts with a BFF response fixture. Real API, identity, persistence,
// browser reflow and accessibility acceptance belong to the integrated journey.
const id = (n: number) => `018f0000-0000-7000-8000-${String(n).padStart(12, '0')}`;
const ref = `urn:openpc:resource:${id(4)}`;
const actorKey = `sha256:${'a'.repeat(64)}`;
const binding = { actorKey, actor: { participantId: id(3), privacyDomainId: id(5) } };
const etag = `"sha256:${'b'.repeat(64)}"`;
const time = '2026-09-24T00:00:00.123456Z';
const item = {
  notificationEndpointId: ref,
  participantId: `urn:openpc:participant:${id(3)}`,
  channel: 'WEBHOOK' as const,
  state: 'DISABLED' as 'DISABLED' | 'ACTIVE' | 'QUARANTINED' | 'RETIRED',
  destinationRef: `urn:openpc:resource:${id(8)}`,
  arbitraryEgress: false,
  revision: '1',
  createdAt: time,
  updatedAt: time,
};
const choice = {
  channel: item.channel,
  destinationRef: item.destinationRef,
  replacementDigest: `sha256:${'d'.repeat(64)}`,
};
const replacements = () => ({
  ...binding,
  kind: 'REPLACEMENTS',
  choices: {
    notificationEndpointId: ref,
    revision: item.revision,
    authority: 'NONE',
    items: [choice],
  },
});
const page = () => ({
  kind: 'LIST',
  ...binding,
  page: {
    items: [item],
    total: '1',
    nextCursor: null,
    completeness: 'COMPLETE',
    authorizedEmpty: false,
    snapshotRevision: '1',
  },
});
const operation = (command: EndpointMutation) => ({
  operationId: id(7),
  resourceRef: ref,
  actionIntentId:
    command.command === 'CREATE'
      ? endpointCreateAction.id
      : command.command === 'UPDATE'
        ? endpointUpdateAction.id
        : 'ACT-NOTIFICATION_UPDATE_VERIFY-V1',
  intentDigest: `sha256:${'c'.repeat(64)}`,
  idempotencyKey: `workbench-notification-endpoint-${command.requestKey}`,
  state: 'SUCCEEDED',
  truthState: 'SUCCESS',
  revision: command.command === 'CREATE' ? '1' : String(BigInt(command.expectedRevision) + 1n),
  createdAt: time,
  updatedAt: time,
});
let handle: (url: URL, init?: RequestInit) => Promise<Response>;
let latest: ReturnType<typeof operation> | undefined;
const commands: EndpointMutation[] = [];
const reads: URL[] = [];
function mount() {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  const view = render(
    <QueryClientProvider client={client}>
      <NotificationEndpointWorkflow />
    </QueryClientProvider>,
  );
  return { client, ...view };
}
beforeEach(() => {
  sessionStorage.clear();
  stepUp.mockReset().mockResolvedValue(undefined);
  commands.length = 0;
  reads.length = 0;
  latest = undefined;
  item.state = 'DISABLED';
  item.revision = '1';
  handle = async (url, init) => {
    if (url.pathname.endsWith('/local-session')) return Response.json({ enabled: false });
    if (init?.method === 'POST') {
      const input = endpointCommand.parse(JSON.parse(String(init.body)));
      if (input.command === 'REVIEW_CREATE')
        return Response.json({
          ...binding,
          kind: 'CREATE_REVIEW',
          request: { ...input, command: 'CREATE', candidateDigest: actorKey },
          stepUp: {
            actionIntentId: endpointCreateAction.id,
            actionIntentDigest: endpointCreateAction.digest,
            resourceId: input.requestKey,
            resourceDigest: actorKey,
          },
        });
      if (input.command === 'REVIEW_UPDATE')
        return Response.json({
          ...binding,
          kind: 'UPDATE_REVIEW',
          request: { ...input, command: 'UPDATE', candidateDigest: actorKey },
          choice,
          stepUp: {
            actionIntentId: endpointUpdateAction.id,
            actionIntentDigest: endpointUpdateAction.digest,
            resourceId: ref.slice(-36),
            resourceDigest: actorKey,
          },
        });
      const command = endpointMutation.parse(input);
      commands.push(command);
      latest = operation(command);
      if (command.command === 'CREATE') {
        item.state = 'DISABLED';
        item.revision = '1';
      }
      if (command.command === 'UPDATE') {
        item.state = item.state === 'QUARANTINED' ? 'QUARANTINED' : 'DISABLED';
        item.revision = latest.revision;
      }
      if (command.command === 'VERIFY') {
        item.state = 'ACTIVE';
        item.revision = latest.revision;
      }
      return Response.json({ ...binding, kind: 'OPERATION', operation: latest }, { status: 202 });
    }
    reads.push(url);
    if (url.searchParams.get('view') === 'REPLACEMENTS') return Response.json(replacements());
    if (url.searchParams.get('view') === 'DETAIL')
      return Response.json({ ...binding, kind: 'DETAIL', endpoint: item, etag });
    if (url.searchParams.get('view') === 'OPERATION')
      return Response.json({ ...binding, kind: 'OPERATION', operation: latest });
    return Response.json(page());
  };
  vi.stubGlobal(
    'fetch',
    vi.fn((input: string | URL | Request, init?: RequestInit) =>
      handle(new URL(String(input), 'http://localhost'), init),
    ),
  );
});
afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  sessionStorage.clear();
});

const storageKey = 'openpc:notification-endpoint-request:v1';
const problem = (status: number, code: string, truthState: string) => ({
  type:
    status === 412 ? 'https://errors.openpc.local/stale' : 'https://errors.openpc.local/conflict',
  title: 'Safe failure',
  status,
  code,
  truthState,
  retryable: false,
  traceId: id(9),
});
async function inspect() {
  const user = userEvent.setup();
  await user.click(await screen.findByRole('button', { name: `Inspect ${ref}` }));
  await screen.findByRole('heading', { name: 'Endpoint details' });
  return user;
}
async function verify() {
  const user = await inspect();
  await user.type(screen.getByLabelText('Verification reason'), 'Verify the admitted endpoint.');
  await user.click(screen.getByRole('button', { name: 'Verify endpoint' }));
  return user;
}
it('inspects without egress, then binds explicit verification and requires authoritative effect readback', async () => {
  mount();
  const user = await inspect();
  expect(screen.getByRole('heading', { name: 'Endpoint details' })).toHaveFocus();
  expect(commands).toHaveLength(0);
  expect(screen.getByRole('button', { name: 'Review endpoint creation' })).toBeEnabled();
  expect(screen.getByRole('button', { name: 'Load replacement choices' })).toBeEnabled();
  await user.type(screen.getByLabelText('Verification reason'), 'Verify the admitted endpoint.');
  await user.click(screen.getByRole('button', { name: 'Verify endpoint' }));
  await screen.findByRole('region', { name: 'Endpoint operation' });
  expect(commands).toHaveLength(1);
  expect(commands[0]).toMatchObject({
    command: 'VERIFY',
    actorKey,
    endpointRef: ref,
    expectedRevision: '1',
    etag,
  });
  expect(screen.getByRole('button', { name: 'Verify endpoint' })).toBeDisabled();
  expect(screen.getByRole('region', { name: 'Endpoint details' })).toHaveTextContent('DISABLED');
  await user.click(screen.getByRole('button', { name: 'Read operation endpoint' }));
  await waitFor(() =>
    expect(screen.getByRole('region', { name: 'Endpoint details' })).toHaveTextContent('ACTIVE'),
  );
  expect(
    screen.queryByRole('region', { name: 'Original endpoint request recovery' }),
  ).not.toBeInTheDocument();
  expect(commands).toHaveLength(1);
});
it.each(['QUARANTINED', 'RETIRED'] as const)(
  'keeps %s state read-only for verification without an invented state mutation',
  async (state) => {
    item.state = state;
    mount();
    await inspect();
    expect(screen.queryByRole('button', { name: 'Verify endpoint' })).not.toBeInTheDocument();
    expect(
      screen.queryByRole('button', { name: /disable|reactivate|unquarantine/i }),
    ).not.toBeInTheDocument();
    expect(commands).toHaveLength(0);
  },
);
it('preserves UNKNOWN across remount and only an explicit action repeats the exact original request', async () => {
  const normal = handle;
  handle = async (url, init) => {
    if (init?.method === 'POST') {
      commands.push(endpointCommand.options[0].parse(JSON.parse(String(init.body))));
      return Response.json(problem(409, 'PC-FACT-4001', 'UNKNOWN'), { status: 409 });
    }
    return normal(url, init);
  };
  const view = mount();
  await verify();
  expect(await screen.findByRole('alert')).toHaveTextContent('outcome is unknown');
  expect(screen.getByRole('alert')).toHaveFocus();
  expect(
    screen.queryByRole('button', { name: 'Dismiss rejected request and refresh' }),
  ).not.toBeInTheDocument();
  const original = commands[0];
  expect(JSON.parse(sessionStorage.getItem(storageKey)!)).toMatchObject({
    request: original,
    uncertain: true,
  });
  view.unmount();
  mount();
  const user = userEvent.setup();
  await screen.findByRole('region', { name: 'Original endpoint request recovery' });
  expect(commands).toHaveLength(1);
  await user.click(screen.getByRole('button', { name: 'Recover original verification' }));
  await screen.findByRole('alert');
  expect(commands).toEqual([original, original]);
  expect(
    screen.queryByRole('button', { name: 'Dismiss rejected request and refresh' }),
  ).not.toBeInTheDocument();
});
it('retains transport ambiguity and recovers a lost response without a new key or operation guess', async () => {
  const normal = handle;
  let lost = true;
  handle = async (url, init) => {
    if (init?.method === 'POST' && lost) {
      commands.push(endpointCommand.options[0].parse(JSON.parse(String(init.body))));
      throw new Error('response lost');
    }
    return normal(url, init);
  };
  const view = mount();
  await verify();
  await screen.findByRole('alert');
  const original = commands[0];
  view.unmount();
  lost = false;
  mount();
  const user = userEvent.setup();
  await user.click(await screen.findByRole('button', { name: 'Recover original verification' }));
  await screen.findByRole('region', { name: 'Endpoint operation' });
  expect(commands).toEqual([original, original]);
  await user.click(screen.getByRole('button', { name: 'Recover original verification' }));
  await waitFor(() =>
    expect(reads.some((url) => url.searchParams.get('view') === 'OPERATION')).toBe(true),
  );
  expect(commands).toHaveLength(2);
});
it('a later stale response cannot erase an already uncertain original', async () => {
  const request: EndpointVerifyCommand = {
    command: 'VERIFY',
    actorKey,
    requestKey: id(6),
    endpointRef: ref,
    expectedRevision: '1',
    etag,
    reason: 'Original verification',
  };
  sessionStorage.setItem(storageKey, JSON.stringify({ request, uncertain: true }));
  const normal = handle;
  handle = async (url, init) =>
    init?.method === 'POST'
      ? Response.json(problem(412, 'PC-DATA-6007', 'STALE'), { status: 412 })
      : normal(url, init);
  mount();
  const user = userEvent.setup();
  await user.click(await screen.findByRole('button', { name: 'Recover original verification' }));
  await screen.findByRole('alert');
  expect(JSON.parse(sessionStorage.getItem(storageKey)!)).toEqual({ request, uncertain: true });
  expect(
    screen.queryByRole('button', { name: 'Dismiss rejected request and refresh' }),
  ).not.toBeInTheDocument();
});
it('permits explicit dismissal only for a first definite stale rejection', async () => {
  const normal = handle;
  handle = async (url, init) =>
    init?.method === 'POST'
      ? Response.json(problem(412, 'PC-DATA-6007', 'STALE'), { status: 412 })
      : normal(url, init);
  mount();
  const user = await verify();
  await user.click(
    await screen.findByRole('button', { name: 'Dismiss rejected request and refresh' }),
  );
  await screen.findByRole('list', { name: 'Endpoint results' });
  expect(sessionStorage.getItem(storageKey)).toBeNull();
});
it('blocks a mismatched operation and does not settle an original from endpoint state alone', async () => {
  const normal = handle;
  handle = async (url, init) => {
    if (init?.method === 'POST') {
      const response = await normal(url, init);
      const body = await response.json();
      return Response.json(
        { ...body, operation: { ...body.operation, idempotencyKey: 'different-original-key' } },
        { status: 202 },
      );
    }
    return normal(url, init);
  };
  mount();
  const user = await verify();
  await screen.findByRole('alert');
  await user.click(screen.getByRole('button', { name: `Inspect ${ref}` }));
  await waitFor(() =>
    expect(screen.getByRole('region', { name: 'Endpoint details' })).toHaveTextContent('ACTIVE'),
  );
  expect(screen.getByRole('region', { name: 'Original endpoint request recovery' })).toBeVisible();
});
it('clears protected context and ignores late responses after shared context invalidation', async () => {
  let complete!: (response: Response) => void;
  const normal = handle;
  handle = async (url, init) =>
    url.searchParams.get('view') === 'DETAIL'
      ? new Promise((resolve) => {
          complete = resolve;
        })
      : normal(url, init);
  const view = mount(),
    user = userEvent.setup();
  await user.click(await screen.findByRole('button', { name: `Inspect ${ref}` }));
  act(() => view.client.clear());
  await act(async () =>
    complete(Response.json({ ...binding, kind: 'DETAIL', endpoint: item, etag })),
  );
  expect(screen.queryByRole('heading', { name: 'Endpoint details' })).not.toBeInTheDocument();
  expect(screen.queryByRole('list', { name: 'Endpoint results' })).not.toBeInTheDocument();
  expect(sessionStorage.getItem(storageKey)).toBeNull();
});
it('purges foreign recovery hints and rejects a changed actor in detail readback', async () => {
  const request = {
    command: 'VERIFY',
    actorKey: `sha256:${'b'.repeat(64)}`,
    requestKey: id(6),
    endpointRef: ref,
    expectedRevision: '1',
    etag,
    reason: 'Foreign context',
  };
  sessionStorage.setItem(storageKey, JSON.stringify({ request, uncertain: true }));
  const normal = handle;
  handle = async (url, init) =>
    url.searchParams.get('view') === 'DETAIL'
      ? Response.json({
          ...binding,
          actorKey: request.actorKey,
          kind: 'DETAIL',
          endpoint: item,
          etag,
        })
      : normal(url, init);
  mount();
  const user = userEvent.setup();
  await user.click(await screen.findByRole('button', { name: `Inspect ${ref}` }));
  await screen.findByRole('alert');
  expect(sessionStorage.getItem(storageKey)).toBeNull();
  expect(screen.queryByRole('heading', { name: 'Endpoint details' })).not.toBeInTheDocument();
});
it('supports labelled keyboard filters and distinguishes authorized empty from unavailable', async () => {
  const normal = handle;
  handle = async (url, init) =>
    url.pathname.endsWith('/local-session')
      ? normal(url, init)
      : Response.json({
          ...page(),
          page: { ...page().page, items: [], total: '0', authorizedEmpty: true },
        });
  const view = mount(),
    user = userEvent.setup();
  await screen.findAllByText('No authorized endpoints match this filter.');
  await user.tab();
  expect(screen.getByLabelText('Filter field')).toHaveFocus();
  await user.selectOptions(screen.getByLabelText('Filter field'), 'state');
  await user.type(screen.getByLabelText('Filter value'), 'DISABLED');
  await user.click(screen.getByRole('button', { name: 'Refresh endpoints' }));
  await waitFor(() =>
    expect(
      vi
        .mocked(fetch)
        .mock.calls.some(([url]) => String(url).includes('filter=state%3Aeq%3ADISABLED')),
    ).toBe(true),
  );
  expect(screen.getByRole('button', { name: 'Next page' })).toBeDisabled();
  view.unmount();
  handle = async (url, init) =>
    url.pathname.endsWith('/local-session')
      ? normal(url, init)
      : Response.json({}, { status: 404 });
  mount();
  await screen.findByRole('alert');
  expect(screen.queryByText('0 matching endpoints')).not.toBeInTheDocument();
});
it('hides current endpoint and free text when focus leaves the window', async () => {
  mount();
  const user = await inspect();
  await user.type(screen.getByLabelText('Verification reason'), 'Private context');
  fireEvent.blur(window);
  expect(screen.queryByRole('heading', { name: 'Endpoint details' })).not.toBeInTheDocument();
  expect(screen.queryByText('Private context')).not.toBeInTheDocument();
});

async function createReview() {
  const user = userEvent.setup();
  await screen.findByRole('button', { name: `Inspect ${ref}` });
  await user.type(screen.getByLabelText('Endpoint destination reference'), item.destinationRef);
  await user.type(screen.getByLabelText('Creation reason'), 'Register the installed endpoint.');
  await user.click(screen.getByRole('button', { name: 'Review endpoint creation' }));
  await screen.findByRole('region', { name: 'Endpoint creation review' });
  return user;
}
it('reviews an exact CREATE candidate, authenticates once and reads its disabled result before verification', async () => {
  mount();
  const user = await createReview();
  expect(commands).toHaveLength(0);
  expect(stepUp).not.toHaveBeenCalled();
  await user.click(screen.getByRole('button', { name: 'Authenticate and create endpoint' }));
  await screen.findByRole('region', { name: 'Endpoint operation' });
  expect(commands).toHaveLength(1);
  const request = commands[0]!;
  expect(request.command).toBe('CREATE');
  expect(stepUp).toHaveBeenCalledExactlyOnceWith(
    {
      actionIntentId: endpointCreateAction.id,
      actionIntentDigest: endpointCreateAction.digest,
      resourceId: request.requestKey,
      resourceDigest: actorKey,
      stepUp: 'FRESH_WEBAUTHN_MAX_5M',
    },
    {
      actionIntentId: endpointCreateAction.id,
      actionIntentDigest: endpointCreateAction.digest,
      resourceId: request.requestKey,
      resourceDigest: actorKey,
    },
  );
  expect(screen.queryByRole('button', { name: 'Verify endpoint' })).not.toBeInTheDocument();
  await user.click(screen.getByRole('button', { name: 'Read operation endpoint' }));
  await waitFor(() =>
    expect(screen.getByRole('region', { name: 'Endpoint details' })).toHaveTextContent('DISABLED'),
  );
  expect(screen.getByRole('button', { name: 'Verify endpoint' })).toBeEnabled();
  expect(sessionStorage.getItem(storageKey)).toBeNull();
});
it('invalidates the reviewed candidate when any input changes and leaves cancelled authentication without a mutation', async () => {
  mount();
  const user = await createReview();
  await user.type(screen.getByLabelText('Creation reason'), ' Changed.');
  expect(
    screen.queryByRole('region', { name: 'Endpoint creation review' }),
  ).not.toBeInTheDocument();
  await user.click(screen.getByRole('button', { name: 'Review endpoint creation' }));
  stepUp.mockRejectedValueOnce(new Error('private authenticator diagnostic'));
  await user.click(await screen.findByRole('button', { name: 'Authenticate and create endpoint' }));
  expect(await screen.findByRole('alert')).toHaveTextContent(
    'No endpoint mutation request was sent',
  );
  expect(screen.getByRole('alert')).not.toHaveTextContent('private');
  expect(commands).toHaveLength(0);
  expect(sessionStorage.getItem(storageKey)).toBeNull();
});
it('suppresses late WebAuthn completion after context invalidation without posting CREATE', async () => {
  let finish!: () => void;
  stepUp.mockImplementationOnce(
    () =>
      new Promise<void>((resolve) => {
        finish = resolve;
      }),
  );
  const view = mount(),
    user = await createReview();
  await user.click(screen.getByRole('button', { name: 'Authenticate and create endpoint' }));
  act(() => view.client.clear());
  await act(async () => finish());
  expect(commands).toHaveLength(0);
  expect(
    screen.queryByRole('region', { name: 'Endpoint creation review' }),
  ).not.toBeInTheDocument();
});
it('recovers lost CREATE only by its original request without repeating WebAuthn or changing the candidate', async () => {
  const normal = handle;
  let lose = true;
  handle = async (url, init) => {
    const input = init?.body ? JSON.parse(String(init.body)) : undefined;
    const reply = await normal(url, init);
    if (input?.command === 'CREATE' && lose) throw new Error('lost response');
    return reply;
  };
  const view = mount(),
    user = await createReview();
  await user.click(screen.getByRole('button', { name: 'Authenticate and create endpoint' }));
  await screen.findByRole('alert');
  const original = commands[0];
  view.unmount();
  lose = false;
  mount();
  await user.click(await screen.findByRole('button', { name: 'Recover original creation' }));
  await screen.findByRole('region', { name: 'Endpoint operation' });
  expect(commands).toEqual([original, original]);
  expect(stepUp).toHaveBeenCalledTimes(1);
});

it('settles an uncertain CREATE through a known matching operation without replaying the request', async () => {
  const normal = handle;
  handle = async (url, init) => {
    const response = await normal(url, init);
    if (init?.body && JSON.parse(String(init.body)).command === 'CREATE')
      throw new Error('lost browser reply');
    return response;
  };
  mount();
  const user = await createReview();
  await user.click(screen.getByRole('button', { name: 'Authenticate and create endpoint' }));
  await screen.findByRole('alert');
  await user.type(screen.getByLabelText('Existing endpoint operation ID'), id(7));
  await user.click(screen.getByRole('button', { name: 'Read endpoint operation' }));
  await screen.findByRole('region', { name: 'Endpoint operation' });
  await user.click(screen.getByRole('button', { name: 'Read operation endpoint' }));
  await waitFor(() =>
    expect(
      screen.queryByRole('region', { name: 'Original endpoint request recovery' }),
    ).not.toBeInTheDocument(),
  );
  expect(commands).toHaveLength(1);
  expect(stepUp).toHaveBeenCalledTimes(1);
});

async function replacementReview() {
  const user = await inspect();
  await user.click(screen.getByRole('button', { name: 'Load replacement choices' }));
  await user.selectOptions(
    await screen.findByLabelText('Endpoint replacement'),
    choice.replacementDigest,
  );
  await user.type(
    screen.getByLabelText('Replacement reason'),
    'Replace the installed credential binding.',
  );
  await user.click(screen.getByRole('button', { name: 'Review endpoint replacement' }));
  await screen.findByRole('region', { name: 'Endpoint replacement review' });
  return user;
}
it.each(['ACTIVE', 'QUARANTINED'] as const)(
  'replaces %s through selected choices and step-up, then reads the actual disabled/quarantined state',
  async (state) => {
    item.state = state;
    mount();
    const user = await replacementReview();
    expect(commands).toHaveLength(0);
    await user.click(screen.getByRole('button', { name: 'Authenticate and replace endpoint' }));
    await screen.findByRole('region', { name: 'Endpoint operation' });
    expect(commands[0]).toMatchObject({
      command: 'UPDATE',
      endpointRef: ref,
      expectedRevision: '1',
      etag,
      replacementDigest: choice.replacementDigest,
      candidateDigest: actorKey,
    });
    expect(stepUp).toHaveBeenCalledWith(
      expect.objectContaining({ actionIntentId: endpointUpdateAction.id }),
      expect.objectContaining({ resourceId: ref.slice(-36), resourceDigest: actorKey }),
    );
    expect(screen.getByRole('region', { name: 'Endpoint details' })).toHaveTextContent(state);
    await user.click(screen.getByRole('button', { name: 'Read operation endpoint' }));
    await waitFor(() =>
      expect(
        screen.queryByRole('region', { name: 'Original endpoint request recovery' }),
      ).not.toBeInTheDocument(),
    );
    expect(screen.getByRole('region', { name: 'Endpoint details' })).toHaveTextContent(
      state === 'QUARANTINED' ? 'QUARANTINED' : 'DISABLED',
    );
    if (state === 'ACTIVE') {
      await user.type(
        screen.getByLabelText('Verification reason'),
        'Verify the replacement binding.',
      );
      await user.click(screen.getByRole('button', { name: 'Verify endpoint' }));
      await waitFor(() => expect(commands).toHaveLength(2));
      expect(commands[1]).toMatchObject({
        command: 'VERIFY',
        endpointRef: ref,
        expectedRevision: '2',
      });
    } else
      expect(screen.queryByRole('button', { name: 'Verify endpoint' })).not.toBeInTheDocument();
  },
);
it('keeps retired endpoints without replacement controls', async () => {
  item.state = 'RETIRED';
  mount();
  await inspect();
  expect(
    screen.queryByRole('button', { name: 'Load replacement choices' }),
  ).not.toBeInTheDocument();
});
it('rejects stale choices and clears reviewed replacement on input or context changes', async () => {
  const normal = handle;
  handle = async (url, init) =>
    url.searchParams.get('view') === 'REPLACEMENTS'
      ? Response.json({ ...replacements(), choices: { ...replacements().choices, revision: '2' } })
      : normal(url, init);
  const view = mount(),
    user = await inspect();
  await user.click(screen.getByRole('button', { name: 'Load replacement choices' }));
  expect(await screen.findByRole('alert')).toHaveTextContent('stale');
  expect(screen.queryByLabelText('Endpoint replacement')).not.toBeInTheDocument();
  handle = normal;
  await user.click(screen.getByRole('button', { name: 'Load replacement choices' }));
  await user.selectOptions(
    await screen.findByLabelText('Endpoint replacement'),
    choice.replacementDigest,
  );
  await user.type(screen.getByLabelText('Replacement reason'), 'Replace installed binding.');
  await user.click(screen.getByRole('button', { name: 'Review endpoint replacement' }));
  await screen.findByRole('region', { name: 'Endpoint replacement review' });
  await user.type(screen.getByLabelText('Replacement reason'), ' Changed.');
  expect(
    screen.queryByRole('region', { name: 'Endpoint replacement review' }),
  ).not.toBeInTheDocument();
  act(() => view.client.clear());
  expect(screen.queryByLabelText('Endpoint replacement')).not.toBeInTheDocument();
  expect(commands).toHaveLength(0);
});
it('retains UNKNOWN replacement across remount, preserves exact replay and does not repeat WebAuthn', async () => {
  const normal = handle;
  handle = async (url, init) => {
    const input = init?.body ? JSON.parse(String(init.body)) : undefined;
    if (input?.command === 'UPDATE') {
      commands.push(endpointMutation.parse(input));
      return Response.json(problem(409, 'PC-FACT-4001', 'UNKNOWN'), { status: 409 });
    }
    return normal(url, init);
  };
  const view = mount(),
    user = await replacementReview();
  await user.click(screen.getByRole('button', { name: 'Authenticate and replace endpoint' }));
  await screen.findByRole('alert');
  const original = commands[0];
  view.unmount();
  mount();
  await user.click(await screen.findByRole('button', { name: 'Recover original replacement' }));
  await screen.findByRole('alert');
  expect(commands).toEqual([original, original]);
  expect(stepUp).toHaveBeenCalledTimes(1);
  expect(
    screen.queryByRole('button', { name: 'Dismiss rejected request and refresh' }),
  ).not.toBeInTheDocument();
});

const candidateCases = [
  { command: 'CREATE', review: createReview, button: 'Authenticate and create endpoint' },
  { command: 'UPDATE', review: replacementReview, button: 'Authenticate and replace endpoint' },
] as const;
it.each(candidateCases)(
  'discards late $command success after protected-context invalidation',
  async ({ command, review, button }) => {
    let complete!: () => void;
    const normal = handle;
    handle = async (url, init) => {
      if (init?.body && JSON.parse(String(init.body)).command === command) {
        const accepted = await normal(url, init);
        return new Promise<Response>((resolve) => {
          complete = () => resolve(accepted);
        });
      }
      return normal(url, init);
    };
    const view = mount(),
      user = await review();
    await user.click(screen.getByRole('button', { name: button }));
    await waitFor(() => expect(commands).toHaveLength(1));
    expect(JSON.parse(sessionStorage.getItem(storageKey)!)).toMatchObject({
      uncertain: true,
      request: commands[0],
    });
    act(() => view.client.clear());
    await act(async () => complete());
    expect(screen.queryByRole('region', { name: 'Endpoint operation' })).not.toBeInTheDocument();
    expect(
      screen.queryByRole('region', { name: 'Original endpoint request recovery' }),
    ).not.toBeInTheDocument();
    expect(screen.queryByRole('region', { name: 'Endpoint details' })).not.toBeInTheDocument();
    expect(sessionStorage.getItem(storageKey)).toBeNull();
    expect(commands).toHaveLength(1);
  },
);
it.each(candidateCases)(
  'does not restore a late $command failure after context changes',
  async ({ command, review, button }) => {
    let reject!: (cause: Error) => void;
    const normal = handle;
    handle = async (url, init) => {
      if (init?.body && JSON.parse(String(init.body)).command === command)
        return new Promise<Response>((_resolve, failure) => {
          reject = failure;
        });
      return normal(url, init);
    };
    const view = mount(),
      user = await review();
    await user.click(screen.getByRole('button', { name: button }));
    await waitFor(() => expect(reject).toBeTypeOf('function'));
    act(() => view.client.clear());
    await act(async () => reject(new Error('private provider detail must not render')));
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    expect(screen.queryByText(/private provider/)).not.toBeInTheDocument();
    expect(sessionStorage.getItem(storageKey)).toBeNull();
    expect(commands).toHaveLength(0);
  },
);
it.each(candidateCases)(
  'allows only one $command submission while WebAuthn or its reply is pending',
  async ({ command, review, button }) => {
    const auth = Promise.withResolvers<void>();
    const reply = Promise.withResolvers<Response>();
    stepUp.mockReturnValueOnce(auth.promise);
    const normal = handle;
    handle = async (url, init) => {
      if (init?.body && JSON.parse(String(init.body)).command === command) {
        const accepted = await normal(url, init);
        await reply.promise;
        return accepted;
      }
      return normal(url, init);
    };
    mount();
    const user = await review();
    const authenticate = screen.getByRole('button', { name: button });
    await user.dblClick(authenticate);
    expect(stepUp).toHaveBeenCalledTimes(1);
    expect(authenticate).toBeDisabled();
    expect(commands).toHaveLength(0);
    await act(async () => auth.resolve());
    await waitFor(() => expect(commands).toHaveLength(1));
    const recovery = screen.getByRole('button', {
      name: command === 'CREATE' ? 'Recover original creation' : 'Recover original replacement',
    });
    expect(recovery).toBeDisabled();
    await user.click(recovery);
    expect(commands).toHaveLength(1);
    await act(async () => reply.resolve(Response.json({})));
    await screen.findByRole('region', { name: 'Endpoint operation' });
    expect(commands).toHaveLength(1);
  },
);
it('does not submit UPDATE when WebAuthn completes after its context was removed', async () => {
  const auth = Promise.withResolvers<void>();
  stepUp.mockReturnValueOnce(auth.promise);
  const view = mount(),
    user = await replacementReview();
  await user.click(screen.getByRole('button', { name: 'Authenticate and replace endpoint' }));
  act(() => view.client.clear());
  await act(async () => auth.resolve());
  expect(commands).toHaveLength(0);
  expect(sessionStorage.getItem(storageKey)).toBeNull();
});
it.each(candidateCases)(
  'renders a safe focused $command rejection without claiming an effect',
  async ({ command, review, button }) => {
    const normal = handle;
    handle = async (url, init) => {
      if (init?.body && JSON.parse(String(init.body)).command === command)
        return Response.json(
          { ...problem(404, 'PC-AUTH-0005', 'DENIED'), title: 'private credential material' },
          { status: 404 },
        );
      return normal(url, init);
    };
    mount();
    const user = await review();
    await user.click(screen.getByRole('button', { name: button }));
    const alert = await screen.findByRole('alert');
    expect(alert).toHaveTextContent('unavailable in this context');
    expect(alert).toHaveFocus();
    expect(screen.queryByText(/private credential material/)).not.toBeInTheDocument();
    expect(screen.queryByRole('region', { name: 'Endpoint operation' })).not.toBeInTheDocument();
    expect(commands).toHaveLength(0);
  },
);
it('reads the known original UPDATE operation after a lost response without resending', async () => {
  const normal = handle;
  handle = async (url, init) => {
    const response = await normal(url, init);
    if (init?.body && JSON.parse(String(init.body)).command === 'UPDATE')
      throw new Error('lost reply');
    return response;
  };
  mount();
  const user = await replacementReview();
  await user.click(screen.getByRole('button', { name: 'Authenticate and replace endpoint' }));
  await screen.findByRole('alert');
  await user.type(screen.getByLabelText('Existing endpoint operation ID'), id(7));
  await user.click(screen.getByRole('button', { name: 'Read endpoint operation' }));
  await screen.findByRole('region', { name: 'Endpoint operation' });
  await user.click(screen.getByRole('button', { name: 'Read operation endpoint' }));
  await waitFor(() =>
    expect(
      screen.queryByRole('region', { name: 'Original endpoint request recovery' }),
    ).not.toBeInTheDocument(),
  );
  expect(commands).toHaveLength(1);
  expect(stepUp).toHaveBeenCalledTimes(1);
});

it.each(candidateCases)(
  'rejects a $command reply with unchanged key but a foreign scope projection',
  async ({ command, review, button }) => {
    const normal = handle;
    handle = async (url, init) => {
      const response = await normal(url, init);
      if (init?.body && JSON.parse(String(init.body)).command === command) {
        const body = await response.json();
        return Response.json(
          { ...body, actor: { ...binding.actor, privacyDomainId: id(99) } },
          { status: 202 },
        );
      }
      return response;
    };
    mount();
    const user = await review();
    await user.click(screen.getByRole('button', { name: button }));
    expect(await screen.findByRole('alert')).toHaveTextContent('Context changed');
    expect(screen.queryByRole('region', { name: 'Endpoint operation' })).not.toBeInTheDocument();
    expect(sessionStorage.getItem(storageKey)).toBeNull();
  },
);

// Exercise the actual shared runtime event consumer while retaining this mounted
// component. This is a component contract, not proof that the live event route
// publishes Identity changes (the browser driver must establish that separately).
it.each(
  candidateCases.flatMap((candidate) => [
    { ...candidate, reply: 'success' },
    { ...candidate, reply: 'failure' },
  ]),
)(
  'discards the first $command $reply through shared runtime context invalidation without remount',
  async ({ command, review, button, reply }) => {
    const sources: { onmessage?: (event: MessageEvent) => void; close: () => void }[] = [];
    vi.stubGlobal(
      'EventSource',
      class {
        onmessage?: (event: MessageEvent) => void;
        constructor() {
          sources.push(this);
        }
        close() {}
      },
    );
    const responseGate = Promise.withResolvers<Response>();
    const normal = handle;
    let committed!: Response;
    handle = async (url, init) => {
      if (init?.body && JSON.parse(String(init.body)).command === command) {
        committed = await normal(url, init);
        return responseGate.promise;
      }
      return normal(url, init);
    };
    try {
      render(
        <UiRuntimeProvider>
          <NotificationEndpointWorkflow />
        </UiRuntimeProvider>,
      );
      const user = await review();
      const mounted = screen.getByRole('region', { name: 'Notification endpoints' });
      await user.click(screen.getByRole('button', { name: button }));
      await waitFor(() => expect(commands).toHaveLength(1));
      expect(JSON.parse(sessionStorage.getItem(storageKey)!)).toMatchObject({
        uncertain: true,
        request: commands[0],
      });
      act(() =>
        sources[0]?.onmessage?.(
          new MessageEvent('message', { data: JSON.stringify({ type: 'context-changed' }) }),
        ),
      );
      expect(screen.getByRole('region', { name: 'Notification endpoints' })).toBe(mounted);
      expect(sessionStorage.getItem(storageKey)).toBeNull();
      expect(
        screen.queryByRole('region', { name: 'Original endpoint request recovery' }),
      ).not.toBeInTheDocument();
      await act(async () =>
        responseGate.resolve(
          reply === 'success'
            ? committed
            : Response.json(problem(404, 'PC-AUTH-0005', 'DENIED'), { status: 404 }),
        ),
      );
      expect(screen.getByRole('region', { name: 'Notification endpoints' })).toBe(mounted);
      expect(screen.queryByRole('region', { name: 'Endpoint operation' })).not.toBeInTheDocument();
      expect(screen.queryByRole('region', { name: 'Endpoint details' })).not.toBeInTheDocument();
      expect(screen.queryByRole('alert')).not.toBeInTheDocument();
      expect(screen.queryByRole('list', { name: 'Endpoint results' })).not.toBeInTheDocument();
      expect(commands).toHaveLength(1);
      expect(sessionStorage.getItem(storageKey)).toBeNull();
    } finally {
      cleanup();
      vi.unstubAllGlobals();
    }
  },
);

it.each(candidateCases)(
  'recovers the original $command by GET after a returned context without another mutation or authentication',
  async ({ command, review, button }) => {
    const normal = handle;
    let returned = false;
    const currentActorKey = `sha256:${'e'.repeat(64)}`;
    handle = async (url, init) => {
      const response = await normal(url, init);
      if (init?.body && JSON.parse(String(init.body)).command === command)
        throw new Error('first reply lost');
      if (returned && !url.pathname.endsWith('/local-session')) {
        const body = await response.json();
        return Response.json({ ...body, actorKey: currentActorKey }, { status: response.status });
      }
      return response;
    };
    const view = mount(),
      user = await review();
    await user.click(screen.getByRole('button', { name: button }));
    await screen.findByRole('alert');
    const original = structuredClone(commands[0]);
    act(() => view.client.clear());
    returned = true;
    await user.click(screen.getByRole('button', { name: 'Refresh endpoints' }));
    await screen.findByRole('list', { name: 'Endpoint results' });
    await user.type(screen.getByLabelText('Existing endpoint operation ID'), id(7));
    await user.click(screen.getByRole('button', { name: 'Read endpoint operation' }));
    await screen.findByRole('region', { name: 'Endpoint operation' });
    await user.click(screen.getByRole('button', { name: 'Read operation endpoint' }));
    await screen.findByRole('region', { name: 'Endpoint details' });
    expect(commands).toEqual([original]);
    expect(stepUp).toHaveBeenCalledTimes(1);
    expect(
      reads
        .filter((url) => url.searchParams.get('view') === 'OPERATION')
        .at(-1)
        ?.searchParams.get('actorKey'),
    ).toBe(currentActorKey);
    expect(sessionStorage.getItem(storageKey)).toBeNull();
  },
);

// Reader projections are disposable; known original request/receipt custody is not.
async function readExistingOperation(
  withOriginal = true,
  command: 'VERIFY' | 'CREATE' | 'UPDATE' = 'VERIFY',
) {
  const request = endpointMutation.parse(
    command === 'CREATE'
      ? {
          command,
          actorKey,
          requestKey: id(6),
          channel: item.channel,
          destinationRef: item.destinationRef,
          arbitraryEgress: false,
          reason: 'Original endpoint creation',
          candidateDigest: actorKey,
        }
      : command === 'UPDATE'
        ? {
            command,
            actorKey,
            requestKey: id(6),
            endpointRef: ref,
            expectedRevision: '1',
            etag,
            replacementDigest: choice.replacementDigest,
            reason: 'Original endpoint replacement',
            candidateDigest: actorKey,
          }
        : {
            command,
            actorKey,
            requestKey: id(6),
            endpointRef: ref,
            expectedRevision: '1',
            etag,
            reason: 'Original endpoint verification',
          },
  );
  const recoverName =
    request.command === 'CREATE'
      ? 'Recover original creation'
      : request.command === 'UPDATE'
        ? 'Recover original replacement'
        : 'Recover original verification';
  latest = operation(request);
  item.revision = latest.revision;
  item.state = command === 'VERIFY' ? 'ACTIVE' : 'DISABLED';
  if (withOriginal)
    sessionStorage.setItem(
      storageKey,
      JSON.stringify({ request, operationId: latest.operationId, uncertain: true }),
    );
  const view = mount(),
    user = userEvent.setup();
  await screen.findByRole('list', { name: 'Endpoint results' });
  if (withOriginal) await user.click(screen.getByRole('button', { name: recoverName }));
  else {
    await user.type(screen.getByLabelText('Existing endpoint operation ID'), latest.operationId);
    await user.click(screen.getByRole('button', { name: 'Read endpoint operation' }));
  }
  await screen.findByRole('region', { name: 'Endpoint operation' });
  return { view, user, request, recoverName, saved: sessionStorage.getItem(storageKey) };
}
function failedReader(kind: string, phase = 'OPERATION'): Promise<Response> {
  if (kind === 'transport') return Promise.reject(new Error('response lost'));
  if (kind === 'unavailable') return Promise.resolve(Response.json({}, { status: 503 }));
  if (kind === 'stale')
    return Promise.resolve(Response.json({ code: 'PC-DATA-6007' }, { status: 412 }));
  if (kind === 'invalid JSON')
    return Promise.resolve(new Response('{', { headers: { 'Content-Type': 'application/json' } }));
  if (kind === 'wrong kind')
    return Promise.resolve(
      Response.json(
        phase === 'OPERATION' ? page() : { ...binding, kind: 'OPERATION', operation: latest },
      ),
    );
  return Promise.resolve(
    Response.json({
      ...binding,
      kind: 'OPERATION',
      operation: {
        ...latest,
        ...(kind === 'wrong operation' ? { operationId: id(9) } : { privateDiagnostic: 'hidden' }),
      },
    }),
  );
}
it.each([
  'transport',
  'unavailable',
  'invalid JSON',
  'malformed',
  'wrong kind',
  'wrong operation',
  'stale',
])(
  'hides the previous operation after a current %s read, retaining exact original custody',
  async (kind) => {
    const { user, request, recoverName, saved } = await readExistingOperation();
    const normal = handle;
    handle = (url, init) =>
      url.searchParams.get('view') === 'OPERATION' ? failedReader(kind) : normal(url, init);
    await user.click(screen.getByRole('button', { name: recoverName }));
    expect(await screen.findByRole('alert')).toHaveFocus();
    expect(screen.queryByRole('region', { name: 'Endpoint operation' })).not.toBeInTheDocument();
    expect(
      screen.queryByRole('button', { name: 'Read operation endpoint' }),
    ).not.toBeInTheDocument();
    expect(
      screen.getByText('Endpoint operation unavailable. Retry the same operation read.'),
    ).toBeVisible();
    expect(sessionStorage.getItem(storageKey)).toBe(saved);
    expect(screen.getByRole('button', { name: 'Review endpoint creation' })).toBeDisabled();
    expect(
      screen.queryByRole('button', { name: 'Dismiss rejected request and refresh' }),
    ).not.toBeInTheDocument();
    expect(commands).toHaveLength(0);
    expect(stepUp).not.toHaveBeenCalled();
    handle = normal;
    await user.click(screen.getByRole('button', { name: recoverName }));
    expect(await screen.findByRole('region', { name: 'Endpoint operation' })).toHaveTextContent(
      id(7),
    );
    expect(sessionStorage.getItem(storageKey)).toBe(saved);
    expect(
      reads
        .filter((url) => url.searchParams.get('view') === 'OPERATION')
        .every((url) => url.searchParams.get('operationId') === id(7)),
    ).toBe(true);
    expect(JSON.parse(saved!).request).toEqual(request);
    expect(commands).toHaveLength(0);
    expect(stepUp).not.toHaveBeenCalled();
  },
);
it.each(['transport', 'unavailable', 'invalid JSON', 'wrong kind'])(
  'clears the prior operation when list revalidation is %s without losing the original',
  async (kind) => {
    const { user, recoverName, saved } = await readExistingOperation();
    const normal = handle;
    handle = (url, init) =>
      url.searchParams.get('view') === 'LIST' ? failedReader(kind, 'LIST') : normal(url, init);
    await user.click(screen.getByRole('button', { name: 'Refresh endpoints' }));
    await screen.findByRole('alert');
    expect(screen.queryByRole('region', { name: 'Endpoint operation' })).not.toBeInTheDocument();
    expect(screen.queryByRole('list', { name: 'Endpoint results' })).not.toBeInTheDocument();
    expect(screen.getByText('Endpoint list unavailable.')).toBeVisible();
    expect(sessionStorage.getItem(storageKey)).toBe(saved);
    expect(screen.getByRole('button', { name: 'Review endpoint creation' })).toBeDisabled();
    expect(commands).toHaveLength(0);
    expect(stepUp).not.toHaveBeenCalled();
    handle = normal;
    await user.click(screen.getByRole('button', { name: 'Refresh endpoints' }));
    await screen.findByRole('list', { name: 'Endpoint results' });
    expect(screen.queryByRole('region', { name: 'Endpoint operation' })).not.toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: recoverName }));
    await screen.findByRole('region', { name: 'Endpoint operation' });
    await user.click(screen.getByRole('button', { name: 'Read operation endpoint' }));
    await screen.findByRole('heading', { name: 'Endpoint details' });
    await waitFor(() =>
      expect(
        screen.queryByRole('region', { name: 'Original endpoint request recovery' }),
      ).not.toBeInTheDocument(),
    );
    expect(sessionStorage.getItem(storageKey)).toBeNull();
    expect(commands).toHaveLength(0);
    expect(stepUp).not.toHaveBeenCalled();
  },
);
it.each(['OPERATION', 'LIST'])(
  'invalidates the previous display at %s admission and adopts only its completed read',
  async (phase) => {
    const { user, recoverName, saved } = await readExistingOperation();
    let complete!: (response: Response) => void;
    const normal = handle;
    handle = (url, init) =>
      url.searchParams.get('view') === phase
        ? new Promise<Response>((resolve) => {
            complete = resolve;
          })
        : normal(url, init);
    await user.click(
      screen.getByRole('button', {
        name: phase === 'LIST' ? 'Refresh endpoints' : recoverName,
      }),
    );
    expect(complete).toBeTypeOf('function');
    expect(screen.queryByRole('region', { name: 'Endpoint operation' })).not.toBeInTheDocument();
    expect(
      screen.queryByRole('button', { name: 'Read operation endpoint' }),
    ).not.toBeInTheDocument();
    expect(
      screen.getByText(
        phase === 'LIST' ? 'Loading notification endpoints.' : 'Reading endpoint operation.',
      ),
    ).toBeVisible();
    expect(sessionStorage.getItem(storageKey)).toBe(saved);
    expect(commands).toHaveLength(0);
    await act(async () =>
      complete(
        Response.json(
          phase === 'LIST' ? page() : { ...binding, kind: 'OPERATION', operation: latest },
        ),
      ),
    );
    if (phase === 'LIST') {
      expect(screen.getByRole('list', { name: 'Endpoint results' })).toBeVisible();
      expect(screen.queryByRole('region', { name: 'Endpoint operation' })).not.toBeInTheDocument();
    } else
      expect(screen.getByRole('region', { name: 'Endpoint operation' })).toHaveTextContent(id(7));
    expect(sessionStorage.getItem(storageKey)).toBe(saved);
    expect(commands).toHaveLength(0);
    expect(stepUp).not.toHaveBeenCalled();
  },
);
it.each(['blur', 'context reset'])(
  'rejects a late operation completion after %s and clears its retained receipt authority',
  async (boundary) => {
    const { view, user, recoverName, saved } = await readExistingOperation();
    const receipt = latest;
    let complete!: (response: Response) => void;
    const normal = handle;
    handle = (url, init) =>
      url.searchParams.get('view') === 'OPERATION'
        ? new Promise<Response>((resolve) => {
            complete = resolve;
          })
        : normal(url, init);
    await user.click(screen.getByRole('button', { name: recoverName }));
    expect(complete).toBeTypeOf('function');
    if (boundary === 'blur') fireEvent.blur(window);
    else act(() => view.client.clear());
    await act(async () =>
      complete(Response.json({ ...binding, kind: 'OPERATION', operation: receipt })),
    );
    expect(screen.queryByRole('region', { name: 'Endpoint operation' })).not.toBeInTheDocument();
    expect(screen.queryByRole('list', { name: 'Endpoint results' })).not.toBeInTheDocument();
    expect(sessionStorage.getItem(storageKey)).toBe(boundary === 'blur' ? saved : null);
    expect(commands).toHaveLength(0);
    expect(stepUp).not.toHaveBeenCalled();
    if (boundary === 'blur') {
      handle = normal;
      fireEvent.focus(window);
      await screen.findByRole('list', { name: 'Endpoint results' });
      await user.click(screen.getByRole('button', { name: `Inspect ${ref}` }));
      await screen.findByRole('heading', { name: 'Endpoint details' });
      // Reauthorizing the list alone cannot restore the cleared operation proof.
      expect(
        screen.getByRole('region', { name: 'Original endpoint request recovery' }),
      ).toBeVisible();
      expect(sessionStorage.getItem(storageKey)).toBe(saved);
      expect(commands).toHaveLength(0);
    }
  },
);
it('does not display an earlier operation when a different manual selector fails', async () => {
  const { user } = await readExistingOperation(false);
  const normal = handle;
  handle = (url, init) =>
    url.searchParams.get('view') === 'OPERATION' ? failedReader('unavailable') : normal(url, init);
  await user.clear(screen.getByLabelText('Existing endpoint operation ID'));
  await user.type(screen.getByLabelText('Existing endpoint operation ID'), id(9));
  await user.click(screen.getByRole('button', { name: 'Read endpoint operation' }));
  await screen.findByRole('alert');
  expect(screen.queryByRole('region', { name: 'Endpoint operation' })).not.toBeInTheDocument();
  expect(sessionStorage.getItem(storageKey)).toBeNull();
  handle = (url, init) =>
    url.searchParams.get('view') === 'OPERATION'
      ? Promise.resolve(
          Response.json({
            ...binding,
            kind: 'OPERATION',
            operation: { ...latest, operationId: id(9) },
          }),
        )
      : normal(url, init);
  await user.click(screen.getByRole('button', { name: 'Read endpoint operation' }));
  expect(await screen.findByRole('region', { name: 'Endpoint operation' })).toHaveTextContent(
    id(9),
  );
  expect(commands).toHaveLength(0);
  expect(stepUp).not.toHaveBeenCalled();
});
it.each(['RUNNING', 'WRITE_AMBIGUITY'])(
  'keeps an unresolved %s original after refresh and current resource readback',
  async (state) => {
    const { user, recoverName } = await readExistingOperation();
    latest = { ...latest!, state, truthState: 'UNKNOWN' };
    await user.click(screen.getByRole('button', { name: recoverName }));
    await screen.findByRole('region', { name: 'Endpoint operation' });
    const saved = sessionStorage.getItem(storageKey);
    await user.click(screen.getByRole('button', { name: 'Refresh endpoints' }));
    await screen.findByRole('list', { name: 'Endpoint results' });
    await user.click(screen.getByRole('button', { name: `Inspect ${ref}` }));
    await screen.findByRole('heading', { name: 'Endpoint details' });
    expect(
      screen.getByRole('region', { name: 'Original endpoint request recovery' }),
    ).toBeVisible();
    expect(sessionStorage.getItem(storageKey)).toBe(saved);
    expect(screen.getByRole('button', { name: 'Review endpoint creation' })).toBeDisabled();
    expect(
      screen.queryByRole('button', { name: 'Dismiss rejected request and refresh' }),
    ).not.toBeInTheDocument();
    expect(commands).toHaveLength(0);
    expect(stepUp).not.toHaveBeenCalled();
  },
);
it.each([401, 403, 404])(
  'preserves the existing privacy boundary on an operation %s denial',
  async (status) => {
    const { user, recoverName, saved } = await readExistingOperation();
    const normal = handle;
    handle = (url, init) =>
      url.searchParams.get('view') === 'OPERATION'
        ? Promise.resolve(Response.json({ code: 'PC-AUTH-0005' }, { status }))
        : normal(url, init);
    await user.click(screen.getByRole('button', { name: recoverName }));
    await screen.findByRole('alert');
    expect(screen.queryByRole('region', { name: 'Endpoint operation' })).not.toBeInTheDocument();
    expect(screen.queryByRole('list', { name: 'Endpoint results' })).not.toBeInTheDocument();
    expect(
      screen.queryByRole('region', { name: 'Original endpoint request recovery' }),
    ).not.toBeInTheDocument();
    expect(sessionStorage.getItem(storageKey)).toBe(saved);
    expect(commands).toHaveLength(0);
    expect(stepUp).not.toHaveBeenCalled();
  },
);

it.each(['CREATE', 'UPDATE'] as const)(
  'retains the original %s verification-reset guard through list projection invalidation',
  async (command) => {
    const { user, saved } = await readExistingOperation(true, command);
    await user.click(screen.getByRole('button', { name: 'Refresh endpoints' }));
    await screen.findByRole('list', { name: 'Endpoint results' });
    expect(screen.queryByRole('region', { name: 'Endpoint operation' })).not.toBeInTheDocument();
    item.state = 'ACTIVE';
    await user.click(screen.getByRole('button', { name: `Inspect ${ref}` }));
    await screen.findByRole('alert');
    expect(screen.queryByRole('heading', { name: 'Endpoint details' })).not.toBeInTheDocument();
    expect(sessionStorage.getItem(storageKey)).toBe(saved);
    item.state = 'DISABLED';
    await user.click(screen.getByRole('button', { name: `Inspect ${ref}` }));
    await screen.findByRole('heading', { name: 'Endpoint details' });
    await waitFor(() =>
      expect(
        screen.queryByRole('region', { name: 'Original endpoint request recovery' }),
      ).not.toBeInTheDocument(),
    );
    expect(sessionStorage.getItem(storageKey)).toBeNull();
    expect(commands).toHaveLength(0);
    expect(stepUp).not.toHaveBeenCalled();
  },
);
it('settles the unchanged original through retained receipt and current detail after a failed operation read', async () => {
  const { user, recoverName, saved } = await readExistingOperation();
  const normal = handle;
  handle = (url, init) =>
    url.searchParams.get('view') === 'OPERATION' ? failedReader('unavailable') : normal(url, init);
  await user.click(screen.getByRole('button', { name: recoverName }));
  await screen.findByRole('alert');
  expect(sessionStorage.getItem(storageKey)).toBe(saved);
  await user.click(screen.getByRole('button', { name: `Inspect ${ref}` }));
  await screen.findByRole('heading', { name: 'Endpoint details' });
  await waitFor(() =>
    expect(
      screen.queryByRole('region', { name: 'Original endpoint request recovery' }),
    ).not.toBeInTheDocument(),
  );
  expect(sessionStorage.getItem(storageKey)).toBeNull();
  expect(commands).toHaveLength(0);
  expect(stepUp).not.toHaveBeenCalled();
});
