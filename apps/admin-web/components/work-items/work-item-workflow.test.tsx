import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { WorkItemWorkflow } from './work-item-workflow';
import {
  workItemActions,
  workItemCommand,
  type WorkItemCommand,
} from '../../lib/work-item-workflow';

// Component contracts with a BFF response fixture. Real API, identity, persistence,
// browser reflow and accessibility acceptance belong to the integrated journey.
const id = (n: number) => `018f0000-0000-7000-8000-${String(n).padStart(12, '0')}`;
const ref = `urn:openpc:resource:${id(4)}`;
const actorKey = `sha256:${'a'.repeat(64)}`;
const binding = {
  actorKey,
  actor: {
    participantId: id(3),
    privacyDomainId: id(5),
    principalRef: `urn:openpc:resource:${id(2)}`,
  },
};
const etag = `"sha256:${'b'.repeat(64)}"`;
const time = '2026-09-24T00:00:00.123456Z';
const item = {
  workItemId: ref,
  participantId: `urn:openpc:participant:${id(3)}`,
  kind: 'REMEDIATION' as 'REMEDIATION' | 'FLEET_FAILURE',
  assigneeRef: null as string | null,
  state: 'OPEN' as 'OPEN' | 'CLAIMED' | 'COMPLETED',
  resourceRef: ref,
  revision: '1',
  createdAt: time,
  updatedAt: time,
};
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
const operation = (command: WorkItemCommand) => ({
  operationId: id(7),
  resourceRef: ref,
  actionIntentId: workItemActions[command.command],
  intentDigest: `sha256:${'c'.repeat(64)}`,
  idempotencyKey: `workbench-work-item-${command.requestKey}`,
  state: 'SUCCEEDED',
  truthState: 'SUCCESS',
  revision: command.command === 'CREATE' ? '1' : String(BigInt(command.expectedRevision) + 1n),
  createdAt: time,
  updatedAt: time,
});
let handle: (url: URL, init?: RequestInit) => Promise<Response>;
let latest: ReturnType<typeof operation> | undefined;
const commands: WorkItemCommand[] = [];
const reads: URL[] = [];
function mount() {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  const view = render(
    <QueryClientProvider client={client}>
      <WorkItemWorkflow />
    </QueryClientProvider>,
  );
  return { client, ...view };
}
beforeEach(() => {
  sessionStorage.clear();
  commands.length = 0;
  reads.length = 0;
  latest = undefined;
  item.kind = 'REMEDIATION';
  item.state = 'OPEN';
  item.assigneeRef = null;
  item.revision = '1';
  handle = async (url, init) => {
    if (url.pathname.endsWith('/local-session')) return Response.json({ enabled: false });
    if (init?.method === 'POST') {
      const command = workItemCommand.parse(JSON.parse(String(init.body)));
      commands.push(command);
      latest = operation(command);
      item.revision = latest.revision;
      if (command.command === 'CLAIM') {
        item.state = 'CLAIMED';
        item.assigneeRef = binding.actor.principalRef;
      }
      if (command.command === 'COMPLETE') item.state = 'COMPLETED';
      return Response.json({ ...binding, kind: 'OPERATION', operation: latest }, { status: 202 });
    }
    reads.push(url);
    if (url.searchParams.get('view') === 'DETAIL')
      return Response.json({ ...binding, kind: 'DETAIL', workItem: item, etag });
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

it('keeps native Fleet handling distinct from source recovery through claim and completion readback', async () => {
  item.kind = 'FLEET_FAILURE';
  const user = userEvent.setup();
  mount();
  await user.click(await screen.findByRole('button', { name: `Inspect ${ref}` }));
  const notice =
    /does not release quarantine, acknowledge Fact delivery or recover the source failure/u;
  expect(await screen.findByRole('note')).toHaveTextContent(notice);
  for (const [command, label, revision] of [
    ['CLAIM', 'Claim work item', '1'],
    ['COMPLETE', 'Complete work item', '2'],
  ] as const) {
    await user.type(
      screen.getByLabelText('Transition reason'),
      'Record handling without source recovery.',
    );
    await user.click(screen.getByRole('button', { name: label }));
    await waitFor(() =>
      expect(screen.getByRole('button', { name: 'Read operation work item' })).toBeEnabled(),
    );
    expect(commands.at(-1)).toMatchObject({
      command,
      expectedRevision: revision,
      workItemRef: ref,
      actorKey,
      etag,
    });
    await user.click(screen.getByRole('button', { name: 'Read operation work item' }));
    await waitFor(() =>
      expect(
        screen.queryByRole('region', { name: 'Original request recovery' }),
      ).not.toBeInTheDocument(),
    );
    expect(screen.getByRole('note')).toHaveTextContent(notice);
  }
  expect(commands.map((command) => command.command)).toEqual(['CLAIM', 'COMPLETE']);
  expect(await screen.findByText('Current work-item state: COMPLETED.')).toBeVisible();
  expect(screen.queryByRole('button', { name: 'Complete work item' })).not.toBeInTheDocument();
});

it('keeps Fleet completion unavailable to a different assignee', async () => {
  item.kind = 'FLEET_FAILURE';
  item.state = 'CLAIMED';
  item.revision = '2';
  item.assigneeRef = `urn:openpc:resource:${id(90)}`;
  mount();
  fireEvent.click(await screen.findByRole('button', { name: `Inspect ${ref}` }));
  expect(await screen.findByRole('button', { name: 'Complete work item' })).toBeDisabled();
  fireEvent.change(screen.getByLabelText('Transition reason'), {
    target: { value: 'A non-claimant must remain unable to complete this work item.' },
  });
  expect(screen.getByRole('button', { name: 'Complete work item' })).toBeDisabled();
  expect(screen.getByRole('note')).toHaveTextContent('does not release quarantine');
  expect(commands).toHaveLength(0);
});

it('creates, updates, claims and completes using revisions with separate original operation and item readback', async () => {
  const user = userEvent.setup();
  mount();
  await screen.findByRole('list', { name: 'Work-item results' });
  await user.selectOptions(screen.getByLabelText('Kind'), 'REMEDIATION');
  await user.type(screen.getByLabelText('Resource reference'), ref);
  await user.type(
    screen.getByLabelText('Assignee reference (optional)'),
    binding.actor.principalRef,
  );
  await user.type(screen.getByLabelText('Reason'), 'Investigate the referenced issue.');
  await user.click(screen.getByRole('button', { name: 'Create work item' }));
  await screen.findByRole('region', { name: 'Work-item operation' });
  expect(commands[0]).toMatchObject({
    command: 'CREATE',
    kind: 'REMEDIATION',
    resourceRef: ref,
    assigneeRef: binding.actor.principalRef,
    reason: 'Investigate the referenced issue.',
  });
  expect(screen.queryByRole('heading', { name: 'Work-item details' })).not.toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Create work item' })).toBeDisabled();
  await user.click(screen.getByRole('button', { name: 'Recover original result' }));
  await waitFor(() =>
    expect(reads.some((url) => url.searchParams.get('operationId') === id(7))).toBe(true),
  );
  expect(commands).toHaveLength(1);
  await user.click(screen.getByRole('button', { name: 'Read operation work item' }));
  expect(await screen.findByRole('heading', { name: 'Work-item details' })).toHaveFocus();
  await waitFor(() =>
    expect(
      screen.queryByRole('region', { name: 'Original request recovery' }),
    ).not.toBeInTheDocument(),
  );
  for (const [command, button, revision] of [
    ['UPDATE', 'Update work item', '1'],
    ['CLAIM', 'Claim work item', '2'],
    ['COMPLETE', 'Complete work item', '3'],
  ] as const) {
    await user.type(screen.getByLabelText('Transition reason'), `${command} the work item.`);
    if (command === 'UPDATE')
      await user.type(
        screen.getByLabelText('Replacement payload digest'),
        `sha256:${'d'.repeat(64)}`,
      );
    await user.click(screen.getByRole('button', { name: button }));
    await screen.findByRole('region', { name: 'Original request recovery' });
    await waitFor(() =>
      expect(screen.getByRole('button', { name: 'Read operation work item' })).toBeEnabled(),
    );
    expect(commands.at(-1)).toMatchObject({
      command,
      actorKey,
      workItemRef: ref,
      expectedRevision: revision,
      etag,
    });
    await user.click(screen.getByRole('button', { name: 'Read operation work item' }));
    await waitFor(() =>
      expect(
        screen.queryByRole('region', { name: 'Original request recovery' }),
      ).not.toBeInTheDocument(),
    );
  }
  expect(await screen.findByText('Current work-item state: COMPLETED.')).toBeVisible();
  expect(commands).toHaveLength(4);
  expect(screen.queryByRole('button', { name: 'Update work item' })).not.toBeInTheDocument();
  expect(
    screen.getByText(/Completion does not prove the linked business issue is resolved/),
  ).toBeVisible();
});
it('inspects without mutation and prevents claiming an item assigned to another principal', async () => {
  item.assigneeRef = `urn:openpc:resource:${id(9)}`;
  const user = userEvent.setup();
  mount();
  await user.click(await screen.findByRole('button', { name: `Inspect ${ref}` }));
  expect(await screen.findByRole('heading', { name: 'Work-item details' })).toHaveFocus();
  await user.type(screen.getByLabelText('Transition reason'), 'Attempt claim.');
  expect(screen.getByRole('button', { name: 'Claim work item' })).toBeDisabled();
  expect(commands).toHaveLength(0);
});
it('preserves an ambiguous original request across remount and never retries automatically', async () => {
  const user = userEvent.setup();
  const normal = handle;
  let lost = true;
  handle = async (url, init) => {
    if (lost && init?.method === 'POST') {
      commands.push(workItemCommand.parse(JSON.parse(String(init.body))));
      throw new Error('connection lost');
    }
    return normal(url, init);
  };
  const view = mount();
  await screen.findByRole('list', { name: 'Work-item results' });
  await user.type(screen.getByLabelText('Resource reference'), ref);
  await user.type(screen.getByLabelText('Reason'), 'Inform operator.');
  await user.click(screen.getByRole('button', { name: 'Create work item' }));
  await screen.findByRole('alert');
  expect(commands).toHaveLength(1);
  const original = commands[0];
  view.unmount();
  lost = false;
  mount();
  await screen.findByRole('region', { name: 'Original request recovery' });
  expect(screen.getByRole('button', { name: 'Create work item' })).toBeDisabled();
  await user.click(screen.getByRole('button', { name: 'Recover original result' }));
  await screen.findByRole('region', { name: 'Work-item operation' });
  expect(commands).toHaveLength(2);
  expect(commands[1]).toEqual(original);
});
it('does not discard an uncertain request merely because later recovery is denied or stale', async () => {
  const saved = {
    request: {
      command: 'CREATE',
      actorKey,
      requestKey: id(6),
      kind: 'REMEDIATION',
      assigneeRef: null,
      resourceRef: ref,
      reason: 'Original intent',
    },
    uncertain: true,
  };
  sessionStorage.setItem('openpc:work-item-request:v1', JSON.stringify(saved));
  const normal = handle;
  handle = async (url, init) =>
    init?.method === 'POST'
      ? Response.json({ code: 'PC-DATA-6007' }, { status: 412 })
      : normal(url, init);
  const user = userEvent.setup();
  mount();
  await user.click(await screen.findByRole('button', { name: 'Recover original result' }));
  await screen.findByRole('alert');
  expect(
    screen.queryByRole('button', { name: 'Dismiss rejected request and refresh' }),
  ).not.toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Create work item' })).toBeDisabled();
});
it('clears protected state on shared context reset and ignores late detail responses', async () => {
  let complete: ((response: Response) => void) | undefined;
  const normal = handle;
  handle = async (url, init) =>
    url.searchParams.get('view') === 'DETAIL'
      ? new Promise<Response>((resolve) => {
          complete = resolve;
        })
      : normal(url, init);
  const user = userEvent.setup();
  const view = mount();
  await user.click(await screen.findByRole('button', { name: `Inspect ${ref}` }));
  act(() => view.client.clear());
  await act(async () =>
    complete?.(Response.json({ ...binding, kind: 'DETAIL', workItem: item, etag })),
  );
  expect(screen.queryByRole('heading', { name: 'Work-item details' })).not.toBeInTheDocument();
  expect(screen.queryByRole('list', { name: 'Work-item results' })).not.toBeInTheDocument();
  expect(sessionStorage.getItem('openpc:work-item-request:v1')).toBeNull();
});
it('rejects a changed actor in delayed data and purges stored recovery hints from another context', async () => {
  sessionStorage.setItem(
    'openpc:work-item-request:v1',
    JSON.stringify({
      request: {
        command: 'CREATE',
        actorKey: `sha256:${'d'.repeat(64)}`,
        requestKey: id(6),
        kind: 'REMEDIATION',
        assigneeRef: null,
        resourceRef: ref,
        reason: 'Foreign',
      },
      uncertain: true,
    }),
  );
  const normal = handle;
  handle = async (url, init) =>
    url.searchParams.get('view') === 'DETAIL'
      ? Response.json({
          ...binding,
          actorKey: `sha256:${'d'.repeat(64)}`,
          kind: 'DETAIL',
          workItem: item,
          etag,
        })
      : normal(url, init);
  const user = userEvent.setup();
  mount();
  await user.click(await screen.findByRole('button', { name: `Inspect ${ref}` }));
  await screen.findByRole('alert');
  expect(screen.queryByRole('heading', { name: 'Work-item details' })).not.toBeInTheDocument();
  expect(sessionStorage.getItem('openpc:work-item-request:v1')).toBeNull();
});
it('keeps authorized empty distinct from unavailable and provides keyboard-labelled filters', async () => {
  const normal = handle;
  handle = async (url, init) =>
    url.pathname.endsWith('/local-session')
      ? normal(url, init)
      : Response.json({
          ...page(),
          page: { ...page().page, items: [], total: '0', authorizedEmpty: true },
        });
  const user = userEvent.setup();
  const view = mount();
  await screen.findAllByText('No authorized work items match this filter.');
  await user.tab();
  expect(screen.getByLabelText('Filter field')).toHaveFocus();
  await user.selectOptions(screen.getByLabelText('Filter field'), 'state');
  await user.type(screen.getByLabelText('Filter value'), 'OPEN');
  await user.click(screen.getByRole('button', { name: 'Refresh work items' }));
  await waitFor(() =>
    expect(
      vi.mocked(fetch).mock.calls.some(([url]) => String(url).includes('filter=state%3Aeq%3AOPEN')),
    ).toBe(true),
  );
  expect(screen.getByRole('button', { name: 'Next page' })).toBeDisabled();
  view.unmount();
  handle = async (url, init) =>
    url.pathname.endsWith('/local-session')
      ? normal(url, init)
      : Response.json({ code: 'PC-AUTH-0005' }, { status: 403 });
  mount();
  await screen.findByRole('alert');
  expect(screen.queryByText('0 matching work items')).not.toBeInTheDocument();
});
it('clears displayed private inputs when focus leaves the window', async () => {
  const user = userEvent.setup();
  mount();
  await screen.findByRole('list', { name: 'Work-item results' });
  await user.type(screen.getByLabelText('Reason'), 'Private operator context');
  fireEvent.blur(window);
  expect(screen.getByLabelText('Reason')).toHaveValue('');
  expect(screen.queryByRole('list', { name: 'Work-item results' })).not.toBeInTheDocument();
});

it('keeps an ambiguous original blocked when operation recovery returns another action', async () => {
  const request = {
    command: 'CLAIM',
    actorKey,
    requestKey: id(6),
    workItemRef: ref,
    expectedRevision: '1',
    etag,
    reason: 'Claim original.',
  } as const;
  sessionStorage.setItem(
    'openpc:work-item-request:v1',
    JSON.stringify({ request, operationId: id(7), uncertain: true }),
  );
  const normal = handle;
  handle = async (url, init) =>
    url.searchParams.get('view') === 'OPERATION'
      ? Response.json({
          ...binding,
          kind: 'OPERATION',
          operation: { ...operation(request), actionIntentId: workItemActions.COMPLETE },
        })
      : normal(url, init);
  const user = userEvent.setup();
  mount();
  await user.click(await screen.findByRole('button', { name: 'Recover original result' }));
  await screen.findByRole('alert');
  expect(screen.getByRole('button', { name: 'Create work item' })).toBeDisabled();
  expect(commands).toHaveLength(0);
});
it('makes a definite stale first request refreshable without treating it as a successful claim', async () => {
  const normal = handle;
  handle = async (url, init) =>
    init?.method === 'POST'
      ? Response.json({ code: 'PC-DATA-6007' }, { status: 412 })
      : normal(url, init);
  const user = userEvent.setup();
  mount();
  await user.click(await screen.findByRole('button', { name: `Inspect ${ref}` }));
  await user.type(screen.getByLabelText('Transition reason'), 'Competing claim.');
  await user.click(screen.getByRole('button', { name: 'Claim work item' }));
  await screen.findByRole('alert');
  expect(screen.queryByRole('region', { name: 'Work-item operation' })).not.toBeInTheDocument();
  await user.click(screen.getByRole('button', { name: 'Dismiss rejected request and refresh' }));
  await screen.findByRole('list', { name: 'Work-item results' });
  expect(
    screen.queryByRole('region', { name: 'Original request recovery' }),
  ).not.toBeInTheDocument();
});

// Reader display is disposable; accepted original operation evidence is not.
async function readExistingOperation(
  withOriginal = true,
  command: WorkItemCommand['command'] = 'CREATE',
) {
  const request = workItemCommand.parse(
    command === 'CREATE'
      ? {
          command,
          actorKey,
          requestKey: id(6),
          kind: 'REMEDIATION',
          resourceRef: ref,
          assigneeRef: null,
          reason: 'Original work item',
        }
      : {
          command,
          actorKey,
          requestKey: id(6),
          workItemRef: ref,
          expectedRevision: '1',
          etag,
          reason: 'Original work-item transition',
          ...(command === 'UPDATE' ? { replacementDigest: `sha256:${'d'.repeat(64)}` } : {}),
        },
  );
  latest = operation(request);
  item.revision = latest.revision;
  item.state = command === 'COMPLETE' ? 'COMPLETED' : command === 'CLAIM' ? 'CLAIMED' : 'OPEN';
  item.assigneeRef =
    command === 'CLAIM' || command === 'COMPLETE' ? binding.actor.principalRef : null;
  if (withOriginal)
    sessionStorage.setItem(
      'openpc:work-item-request:v1',
      JSON.stringify({ request, operationId: latest.operationId, uncertain: true }),
    );
  const view = mount(),
    user = userEvent.setup();
  await screen.findByRole('list', { name: 'Work-item results' });
  if (withOriginal)
    await user.click(screen.getByRole('button', { name: 'Recover original result' }));
  else {
    await user.type(screen.getByLabelText('Existing operation ID'), latest.operationId);
    await user.click(screen.getByRole('button', { name: 'Read operation' }));
  }
  await screen.findByRole('region', { name: 'Work-item operation' });
  return { view, user, request, saved: sessionStorage.getItem('openpc:work-item-request:v1') };
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
        ...(kind === 'wrong operation'
          ? { operationId: id(9) }
          : kind === 'wrong action'
            ? { actionIntentId: workItemActions.COMPLETE }
            : kind === 'wrong key'
              ? { idempotencyKey: `workbench-work-item-${id(9)}` }
              : { privateDiagnostic: 'hidden' }),
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
  'wrong action',
  'wrong key',
  'stale',
])(
  'hides the previous operation after a current %s read, retaining exact original custody',
  async (kind) => {
    const { user, request, saved } = await readExistingOperation();
    const normal = handle;
    handle = (url, init) =>
      url.searchParams.get('view') === 'OPERATION' ? failedReader(kind) : normal(url, init);
    await user.click(screen.getByRole('button', { name: 'Recover original result' }));
    expect(await screen.findByRole('alert')).toHaveFocus();
    expect(screen.queryByRole('region', { name: 'Work-item operation' })).not.toBeInTheDocument();
    expect(
      screen.queryByRole('button', { name: 'Read operation work item' }),
    ).not.toBeInTheDocument();
    expect(
      screen.getByText('Work-item operation unavailable. Retry the same operation read.'),
    ).toBeVisible();
    expect(sessionStorage.getItem('openpc:work-item-request:v1')).toBe(saved);
    expect(screen.getByRole('button', { name: 'Create work item' })).toBeDisabled();
    expect(
      screen.queryByRole('button', { name: 'Dismiss rejected request and refresh' }),
    ).not.toBeInTheDocument();
    expect(commands).toHaveLength(0);

    handle = normal;
    await user.click(screen.getByRole('button', { name: 'Recover original result' }));
    expect(await screen.findByRole('region', { name: 'Work-item operation' })).toHaveTextContent(
      id(7),
    );
    expect(sessionStorage.getItem('openpc:work-item-request:v1')).toBe(saved);
    expect(
      reads
        .filter((url) => url.searchParams.get('view') === 'OPERATION')
        .every((url) => url.searchParams.get('operationId') === id(7)),
    ).toBe(true);
    expect(JSON.parse(saved!).request).toEqual(request);
    expect(commands).toHaveLength(0);
  },
);
it.each(['transport', 'unavailable', 'invalid JSON', 'wrong kind'])(
  'clears the prior operation when list revalidation is %s without losing the original',
  async (kind) => {
    const { user, saved } = await readExistingOperation();
    const normal = handle;
    handle = (url, init) =>
      url.searchParams.get('view') === 'LIST' ? failedReader(kind, 'LIST') : normal(url, init);
    await user.click(screen.getByRole('button', { name: 'Refresh work items' }));
    await screen.findByRole('alert');
    expect(screen.queryByRole('region', { name: 'Work-item operation' })).not.toBeInTheDocument();
    expect(screen.queryByRole('list', { name: 'Work-item results' })).not.toBeInTheDocument();
    expect(screen.getByText('Work-item list unavailable.')).toBeVisible();
    expect(sessionStorage.getItem('openpc:work-item-request:v1')).toBe(saved);
    expect(screen.getByRole('button', { name: 'Create work item' })).toBeDisabled();
    expect(commands).toHaveLength(0);

    handle = normal;
    await user.click(screen.getByRole('button', { name: 'Refresh work items' }));
    await screen.findByRole('list', { name: 'Work-item results' });
    expect(screen.queryByRole('region', { name: 'Work-item operation' })).not.toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Recover original result' }));
    await screen.findByRole('region', { name: 'Work-item operation' });
    await user.click(screen.getByRole('button', { name: 'Read operation work item' }));
    await screen.findByRole('heading', { name: 'Work-item details' });
    await waitFor(() =>
      expect(
        screen.queryByRole('region', { name: 'Original request recovery' }),
      ).not.toBeInTheDocument(),
    );
    expect(sessionStorage.getItem('openpc:work-item-request:v1')).toBeNull();
    expect(commands).toHaveLength(0);
  },
);
it.each(['OPERATION', 'LIST'])(
  'invalidates the previous display at %s admission and adopts only its completed read',
  async (phase) => {
    const { user, saved } = await readExistingOperation();
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
        name: phase === 'LIST' ? 'Refresh work items' : 'Recover original result',
      }),
    );
    expect(complete).toBeTypeOf('function');
    expect(screen.queryByRole('region', { name: 'Work-item operation' })).not.toBeInTheDocument();
    expect(
      screen.queryByRole('button', { name: 'Read operation work item' }),
    ).not.toBeInTheDocument();
    expect(
      screen.getByText(phase === 'LIST' ? 'Loading work items.' : 'Reading work-item operation.'),
    ).toBeVisible();
    expect(sessionStorage.getItem('openpc:work-item-request:v1')).toBe(saved);
    expect(commands).toHaveLength(0);
    await act(async () =>
      complete(
        Response.json(
          phase === 'LIST' ? page() : { ...binding, kind: 'OPERATION', operation: latest },
        ),
      ),
    );
    if (phase === 'LIST') {
      expect(screen.getByRole('list', { name: 'Work-item results' })).toBeVisible();
      expect(screen.queryByRole('region', { name: 'Work-item operation' })).not.toBeInTheDocument();
    } else
      expect(screen.getByRole('region', { name: 'Work-item operation' })).toHaveTextContent(id(7));
    expect(sessionStorage.getItem('openpc:work-item-request:v1')).toBe(saved);
    expect(commands).toHaveLength(0);
  },
);
it.each(['blur', 'context reset'])(
  'rejects a late operation completion after %s and clears its retained receipt authority',
  async (boundary) => {
    const { view, user, saved } = await readExistingOperation();
    const receipt = latest;
    let complete!: (response: Response) => void;
    const normal = handle;
    handle = (url, init) =>
      url.searchParams.get('view') === 'OPERATION'
        ? new Promise<Response>((resolve) => {
            complete = resolve;
          })
        : normal(url, init);
    await user.click(screen.getByRole('button', { name: 'Recover original result' }));
    expect(complete).toBeTypeOf('function');
    if (boundary === 'blur') fireEvent.blur(window);
    else act(() => view.client.clear());
    await act(async () =>
      complete(Response.json({ ...binding, kind: 'OPERATION', operation: receipt })),
    );
    expect(screen.queryByRole('region', { name: 'Work-item operation' })).not.toBeInTheDocument();
    expect(screen.queryByRole('list', { name: 'Work-item results' })).not.toBeInTheDocument();
    expect(sessionStorage.getItem('openpc:work-item-request:v1')).toBe(
      boundary === 'blur' ? saved : null,
    );
    expect(commands).toHaveLength(0);

    if (boundary === 'blur') {
      handle = normal;
      fireEvent.focus(window);
      await screen.findByRole('list', { name: 'Work-item results' });
      await user.click(screen.getByRole('button', { name: `Inspect ${ref}` }));
      await screen.findByRole('heading', { name: 'Work-item details' });
      // Reauthorizing the list alone cannot restore the cleared operation proof.
      expect(screen.getByRole('region', { name: 'Original request recovery' })).toBeVisible();
      expect(sessionStorage.getItem('openpc:work-item-request:v1')).toBe(saved);
      expect(commands).toHaveLength(0);
    }
  },
);
it('does not display an earlier operation when a different manual selector fails', async () => {
  const { user } = await readExistingOperation(false);
  const normal = handle;
  handle = (url, init) =>
    url.searchParams.get('view') === 'OPERATION' ? failedReader('unavailable') : normal(url, init);
  await user.clear(screen.getByLabelText('Existing operation ID'));
  await user.type(screen.getByLabelText('Existing operation ID'), id(9));
  await user.click(screen.getByRole('button', { name: 'Read operation' }));
  await screen.findByRole('alert');
  expect(screen.queryByRole('region', { name: 'Work-item operation' })).not.toBeInTheDocument();
  expect(sessionStorage.getItem('openpc:work-item-request:v1')).toBeNull();
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
  await user.click(screen.getByRole('button', { name: 'Read operation' }));
  expect(await screen.findByRole('region', { name: 'Work-item operation' })).toHaveTextContent(
    id(9),
  );
  expect(commands).toHaveLength(0);
});
it.each(['RUNNING', 'WRITE_AMBIGUITY'])(
  'keeps an unresolved %s original after refresh and current resource readback',
  async (state) => {
    const { user } = await readExistingOperation();
    latest = { ...latest!, state, truthState: 'UNKNOWN' };
    await user.click(screen.getByRole('button', { name: 'Recover original result' }));
    await screen.findByRole('region', { name: 'Work-item operation' });
    const saved = sessionStorage.getItem('openpc:work-item-request:v1');
    await user.click(screen.getByRole('button', { name: 'Refresh work items' }));
    await screen.findByRole('list', { name: 'Work-item results' });
    await user.click(screen.getByRole('button', { name: `Inspect ${ref}` }));
    await screen.findByRole('heading', { name: 'Work-item details' });
    expect(screen.getByRole('region', { name: 'Original request recovery' })).toBeVisible();
    expect(sessionStorage.getItem('openpc:work-item-request:v1')).toBe(saved);
    expect(screen.getByRole('button', { name: 'Create work item' })).toBeDisabled();
    expect(
      screen.queryByRole('button', { name: 'Dismiss rejected request and refresh' }),
    ).not.toBeInTheDocument();
    expect(commands).toHaveLength(0);
  },
);
it.each([401, 403, 404])(
  'preserves the existing privacy boundary on an operation %s denial',
  async (status) => {
    const { user, saved } = await readExistingOperation();
    const normal = handle;
    handle = (url, init) =>
      url.searchParams.get('view') === 'OPERATION'
        ? Promise.resolve(Response.json({ code: 'PC-AUTH-0005' }, { status }))
        : normal(url, init);
    await user.click(screen.getByRole('button', { name: 'Recover original result' }));
    await screen.findByRole('alert');
    expect(screen.queryByRole('region', { name: 'Work-item operation' })).not.toBeInTheDocument();
    expect(screen.queryByRole('list', { name: 'Work-item results' })).not.toBeInTheDocument();
    expect(
      screen.queryByRole('region', { name: 'Original request recovery' }),
    ).not.toBeInTheDocument();
    expect(sessionStorage.getItem('openpc:work-item-request:v1')).toBe(saved);
    expect(commands).toHaveLength(0);
  },
);

it.each(['CREATE', 'UPDATE', 'CLAIM', 'COMPLETE'] as const)(
  'preserves original %s receipt and terminal-state requirements through list refresh',
  async (command) => {
    const { user, saved } = await readExistingOperation(true, command);
    await user.click(screen.getByRole('button', { name: 'Refresh work items' }));
    await screen.findByRole('list', { name: 'Work-item results' });
    expect(screen.queryByRole('region', { name: 'Work-item operation' })).not.toBeInTheDocument();
    if (command === 'CLAIM' || command === 'COMPLETE') {
      item.state = command === 'CLAIM' ? 'OPEN' : 'CLAIMED';
      await user.click(screen.getByRole('button', { name: `Inspect ${ref}` }));
      await screen.findByRole('heading', { name: 'Work-item details' });
      expect(screen.getByRole('region', { name: 'Original request recovery' })).toBeVisible();
      expect(sessionStorage.getItem('openpc:work-item-request:v1')).toBe(saved);
      expect(screen.getByRole('button', { name: 'Create work item' })).toBeDisabled();
      item.state = command === 'CLAIM' ? 'CLAIMED' : 'COMPLETED';
    }
    await user.click(screen.getByRole('button', { name: `Inspect ${ref}` }));
    await screen.findByRole('heading', { name: 'Work-item details' });
    await waitFor(() =>
      expect(
        screen.queryByRole('region', { name: 'Original request recovery' }),
      ).not.toBeInTheDocument(),
    );
    expect(sessionStorage.getItem('openpc:work-item-request:v1')).toBeNull();
    expect(commands).toHaveLength(0);
  },
);
it('settles only the unchanged original through its retained receipt and current detail after a failed operation read', async () => {
  const { user, saved } = await readExistingOperation();
  const normal = handle;
  handle = (url, init) =>
    url.searchParams.get('view') === 'OPERATION' ? failedReader('unavailable') : normal(url, init);
  await user.click(screen.getByRole('button', { name: 'Recover original result' }));
  await screen.findByRole('alert');
  expect(sessionStorage.getItem('openpc:work-item-request:v1')).toBe(saved);
  await user.click(screen.getByRole('button', { name: `Inspect ${ref}` }));
  await screen.findByRole('heading', { name: 'Work-item details' });
  await waitFor(() =>
    expect(
      screen.queryByRole('region', { name: 'Original request recovery' }),
    ).not.toBeInTheDocument(),
  );
  expect(sessionStorage.getItem('openpc:work-item-request:v1')).toBeNull();
  expect(commands).toHaveLength(0);
});
it.each(['CLAIM', 'COMPLETE'] as const)(
  'rejects a foreign resource during known original %s operation recovery without settling or reminting',
  async (command) => {
    const { user, saved } = await readExistingOperation(true, command);
    const normal = handle;
    handle = (url, init) =>
      url.searchParams.get('view') === 'OPERATION'
        ? Promise.resolve(
            Response.json({
              ...binding,
              kind: 'OPERATION',
              operation: { ...latest, resourceRef: `urn:openpc:resource:${id(9)}` },
            }),
          )
        : normal(url, init);
    await user.click(screen.getByRole('button', { name: 'Recover original result' }));
    await screen.findByRole('alert');
    expect(screen.queryByRole('region', { name: 'Work-item operation' })).not.toBeInTheDocument();
    expect(screen.getByRole('region', { name: 'Original request recovery' })).toBeVisible();
    expect(sessionStorage.getItem('openpc:work-item-request:v1')).toBe(saved);
    expect(screen.getByRole('button', { name: 'Create work item' })).toBeDisabled();
    expect(commands).toHaveLength(0);
  },
);
