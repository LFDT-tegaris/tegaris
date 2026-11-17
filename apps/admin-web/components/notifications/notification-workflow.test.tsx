import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { NotificationWorkflow } from './notification-workflow';
import { notificationCommand, type NotificationCommand } from '../../lib/notification-workflow';

// Component contracts with a BFF response fixture. Real API, identity, persistence,
// browser reflow and accessibility acceptance belong to the integrated journey.
const id = (n: number) => `018f0000-0000-7000-8000-${String(n).padStart(12, '0')}`;
const ref = `urn:openpc:resource:${id(4)}`;
const actorKey = `sha256:${'a'.repeat(64)}`;
const binding = { actorKey, actor: { participantId: id(3), privacyDomainId: id(5) } };
const etag = `"sha256:${'b'.repeat(64)}"`;
const time = '2026-09-24T00:00:00.123456Z';
const item = {
  notificationId: ref,
  participantId: `urn:openpc:participant:${id(3)}`,
  severity: 'WARNING' as const,
  state: 'UNREAD' as 'UNREAD' | 'ACKNOWLEDGED',
  messageKey: 'evidence.export.completed',
  resourceRef: null,
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
const operation = (command: NotificationCommand) => ({
  operationId: id(7),
  resourceRef: ref,
  actionIntentId:
    command.command === 'CREATE'
      ? 'ACT-NOTIFICATIONS_CREATE_RESOURCE-V1'
      : 'ACT-NOTIFICATION_UPDATE_ACKNOWLEDGE-V1',
  intentDigest: `sha256:${'c'.repeat(64)}`,
  idempotencyKey: `workbench-notification-${command.requestKey}`,
  state: 'SUCCEEDED',
  truthState: 'SUCCESS',
  revision: command.command === 'CREATE' ? '1' : '2',
  createdAt: time,
  updatedAt: time,
});
let handle: (url: URL, init?: RequestInit) => Promise<Response>;
let latest: ReturnType<typeof operation> | undefined;
const commands: NotificationCommand[] = [];
const reads: URL[] = [];
function mount() {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  const view = render(
    <QueryClientProvider client={client}>
      <NotificationWorkflow />
    </QueryClientProvider>,
  );
  return { client, ...view };
}
beforeEach(() => {
  sessionStorage.clear();
  commands.length = 0;
  reads.length = 0;
  latest = undefined;
  item.state = 'UNREAD';
  item.revision = '1';
  handle = async (url, init) => {
    if (url.pathname.endsWith('/local-session')) return Response.json({ enabled: false });
    if (init?.method === 'POST') {
      const command = notificationCommand.parse(JSON.parse(String(init.body)));
      commands.push(command);
      latest = operation(command);
      if (command.command === 'ACKNOWLEDGE') {
        item.state = 'ACKNOWLEDGED';
        item.revision = '2';
      }
      return Response.json({ ...binding, kind: 'OPERATION', operation: latest }, { status: 202 });
    }
    reads.push(url);
    if (url.searchParams.get('view') === 'DETAIL')
      return Response.json({ ...binding, kind: 'DETAIL', notification: item, etag });
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

it('reads detail without marking read or acknowledging; explicit ACK retains revision and ETag', async () => {
  const user = userEvent.setup();
  mount();
  await user.click(
    await screen.findByRole('button', { name: 'Inspect evidence.export.completed' }),
  );
  expect(await screen.findByRole('heading', { name: 'Notification details' })).toHaveFocus();
  expect(commands).toHaveLength(0);
  expect(
    screen.getByText('Viewing does not mark this notification read or acknowledged.'),
  ).toBeVisible();
  await user.type(screen.getByLabelText('Acknowledgement reason'), 'Reviewed operational notice.');
  await user.click(screen.getByRole('button', { name: 'Acknowledge notification' }));
  await screen.findByRole('region', { name: 'Notification operation' });
  expect(commands).toHaveLength(1);
  expect(commands[0]).toMatchObject({
    command: 'ACKNOWLEDGE',
    actorKey,
    notificationRef: ref,
    expectedRevision: '1',
    etag,
  });
  expect(screen.getByRole('button', { name: 'Create notification' })).toBeDisabled();
  await user.click(screen.getByRole('button', { name: 'Read operation notification' }));
  await screen.findByText('Current metadata state: ACKNOWLEDGED.');
  expect(
    screen.queryByRole('region', { name: 'Original request recovery' }),
  ).not.toBeInTheDocument();
  expect(commands).toHaveLength(1);
});
it('creates from meaningful fields and separates the operation result from effect readback', async () => {
  const user = userEvent.setup();
  mount();
  await screen.findByRole('list', { name: 'Notification results' });
  await user.selectOptions(screen.getByLabelText('Severity'), 'WARNING');
  await user.type(screen.getByLabelText('Message key'), 'evidence.export.completed');
  await user.type(screen.getByLabelText('Reason'), 'Inform operator.');
  await user.click(screen.getByRole('button', { name: 'Create notification' }));
  await screen.findByRole('region', { name: 'Notification operation' });
  expect(commands[0]).toMatchObject({
    command: 'CREATE',
    severity: 'WARNING',
    messageKey: 'evidence.export.completed',
    resourceRef: null,
    reason: 'Inform operator.',
  });
  expect(
    screen.getByText(
      'This status describes the metadata operation. It does not establish delivery.',
    ),
  ).toBeVisible();
  expect(screen.queryByRole('heading', { name: 'Notification details' })).not.toBeInTheDocument();
  await user.click(screen.getByRole('button', { name: 'Recover original result' }));
  await waitFor(() =>
    expect(reads.some((url) => url.searchParams.get('operationId') === id(7))).toBe(true),
  );
  expect(commands).toHaveLength(1);
});
it('preserves an ambiguous original request across remount and never retries automatically', async () => {
  const user = userEvent.setup();
  const normal = handle;
  let lost = true;
  handle = async (url, init) => {
    if (lost && init?.method === 'POST') {
      commands.push(notificationCommand.parse(JSON.parse(String(init.body))));
      throw new Error('connection lost');
    }
    return normal(url, init);
  };
  const view = mount();
  await screen.findByRole('list', { name: 'Notification results' });
  await user.type(screen.getByLabelText('Message key'), 'evidence.export.completed');
  await user.type(screen.getByLabelText('Reason'), 'Inform operator.');
  await user.click(screen.getByRole('button', { name: 'Create notification' }));
  await screen.findByRole('alert');
  expect(commands).toHaveLength(1);
  const original = commands[0];
  view.unmount();
  lost = false;
  mount();
  await screen.findByRole('region', { name: 'Original request recovery' });
  expect(screen.getByRole('button', { name: 'Create notification' })).toBeDisabled();
  await user.click(screen.getByRole('button', { name: 'Recover original result' }));
  await screen.findByRole('region', { name: 'Notification operation' });
  expect(commands).toHaveLength(2);
  expect(commands[1]).toEqual(original);
});
it('does not discard an uncertain request merely because later recovery is denied or stale', async () => {
  const saved = {
    request: {
      command: 'CREATE',
      actorKey,
      requestKey: id(6),
      severity: 'INFO',
      messageKey: 'notice.test',
      resourceRef: null,
      reason: 'Original intent',
    },
    uncertain: true,
  };
  sessionStorage.setItem('openpc:notification-request:v1', JSON.stringify(saved));
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
  expect(screen.getByRole('button', { name: 'Create notification' })).toBeDisabled();
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
  await user.click(
    await screen.findByRole('button', { name: 'Inspect evidence.export.completed' }),
  );
  act(() => view.client.clear());
  await act(async () =>
    complete?.(Response.json({ ...binding, kind: 'DETAIL', notification: item, etag })),
  );
  expect(screen.queryByRole('heading', { name: 'Notification details' })).not.toBeInTheDocument();
  expect(screen.queryByRole('list', { name: 'Notification results' })).not.toBeInTheDocument();
  expect(sessionStorage.getItem('openpc:notification-request:v1')).toBeNull();
});
it('rejects a changed actor in delayed data and purges stored recovery hints from another context', async () => {
  sessionStorage.setItem(
    'openpc:notification-request:v1',
    JSON.stringify({
      request: {
        command: 'CREATE',
        actorKey: `sha256:${'d'.repeat(64)}`,
        requestKey: id(6),
        severity: 'INFO',
        messageKey: 'notice.test',
        resourceRef: null,
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
          notification: item,
          etag,
        })
      : normal(url, init);
  const user = userEvent.setup();
  mount();
  await user.click(
    await screen.findByRole('button', { name: 'Inspect evidence.export.completed' }),
  );
  await screen.findByRole('alert');
  expect(screen.queryByRole('heading', { name: 'Notification details' })).not.toBeInTheDocument();
  expect(sessionStorage.getItem('openpc:notification-request:v1')).toBeNull();
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
  await screen.findAllByText('No authorized notifications match this filter.');
  await user.tab();
  expect(screen.getByLabelText('Filter field')).toHaveFocus();
  await user.selectOptions(screen.getByLabelText('Filter field'), 'state');
  await user.type(screen.getByLabelText('Filter value'), 'UNREAD');
  await user.click(screen.getByRole('button', { name: 'Refresh notifications' }));
  await waitFor(() =>
    expect(
      vi
        .mocked(fetch)
        .mock.calls.some(([url]) => String(url).includes('filter=state%3Aeq%3AUNREAD')),
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
  expect(screen.queryByText('0 matching notifications')).not.toBeInTheDocument();
});
it('clears displayed private inputs when focus leaves the window', async () => {
  const user = userEvent.setup();
  mount();
  await screen.findByRole('list', { name: 'Notification results' });
  await user.type(screen.getByLabelText('Reason'), 'Private operator context');
  fireEvent.blur(window);
  expect(screen.getByLabelText('Reason')).toHaveValue('');
  expect(screen.queryByRole('list', { name: 'Notification results' })).not.toBeInTheDocument();
});

// Reader projections are disposable; known original request/receipt custody is not.
async function readExistingOperation(
  withOriginal = true,
  command: 'CREATE' | 'ACKNOWLEDGE' = 'CREATE',
) {
  const request = notificationCommand.parse(
    command === 'CREATE'
      ? {
          command,
          actorKey,
          requestKey: id(6),
          severity: 'WARNING',
          messageKey: item.messageKey,
          resourceRef: null,
          reason: 'Original notification',
        }
      : {
          command,
          actorKey,
          requestKey: id(6),
          notificationRef: ref,
          expectedRevision: '1',
          etag,
          reason: 'Original acknowledgement',
        },
  );
  latest = operation(request);
  item.revision = latest.revision;
  item.state = command === 'ACKNOWLEDGE' ? 'ACKNOWLEDGED' : 'UNREAD';
  if (withOriginal)
    sessionStorage.setItem(
      'openpc:notification-request:v1',
      JSON.stringify({ request, operationId: latest.operationId, uncertain: true }),
    );
  const view = mount(),
    user = userEvent.setup();
  await screen.findByRole('list', { name: 'Notification results' });
  if (withOriginal)
    await user.click(screen.getByRole('button', { name: 'Recover original result' }));
  else {
    await user.type(screen.getByLabelText('Existing operation ID'), latest.operationId);
    await user.click(screen.getByRole('button', { name: 'Read operation' }));
  }
  await screen.findByRole('region', { name: 'Notification operation' });
  return { view, user, request, saved: sessionStorage.getItem('openpc:notification-request:v1') };
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
    const { user, request, saved } = await readExistingOperation();
    const normal = handle;
    handle = (url, init) =>
      url.searchParams.get('view') === 'OPERATION' ? failedReader(kind) : normal(url, init);
    await user.click(screen.getByRole('button', { name: 'Recover original result' }));
    expect(await screen.findByRole('alert')).toHaveFocus();
    expect(
      screen.queryByRole('region', { name: 'Notification operation' }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole('button', { name: 'Read operation notification' }),
    ).not.toBeInTheDocument();
    expect(
      screen.getByText('Notification operation unavailable. Retry the same operation read.'),
    ).toBeVisible();
    expect(sessionStorage.getItem('openpc:notification-request:v1')).toBe(saved);
    expect(screen.getByRole('button', { name: 'Create notification' })).toBeDisabled();
    expect(
      screen.queryByRole('button', { name: 'Dismiss rejected request and refresh' }),
    ).not.toBeInTheDocument();
    expect(commands).toHaveLength(0);

    handle = normal;
    await user.click(screen.getByRole('button', { name: 'Recover original result' }));
    expect(await screen.findByRole('region', { name: 'Notification operation' })).toHaveTextContent(
      id(7),
    );
    expect(sessionStorage.getItem('openpc:notification-request:v1')).toBe(saved);
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
    await user.click(screen.getByRole('button', { name: 'Refresh notifications' }));
    await screen.findByRole('alert');
    expect(
      screen.queryByRole('region', { name: 'Notification operation' }),
    ).not.toBeInTheDocument();
    expect(screen.queryByRole('list', { name: 'Notification results' })).not.toBeInTheDocument();
    expect(screen.getByText('Notification list unavailable.')).toBeVisible();
    expect(sessionStorage.getItem('openpc:notification-request:v1')).toBe(saved);
    expect(screen.getByRole('button', { name: 'Create notification' })).toBeDisabled();
    expect(commands).toHaveLength(0);

    handle = normal;
    await user.click(screen.getByRole('button', { name: 'Refresh notifications' }));
    await screen.findByRole('list', { name: 'Notification results' });
    expect(
      screen.queryByRole('region', { name: 'Notification operation' }),
    ).not.toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Recover original result' }));
    await screen.findByRole('region', { name: 'Notification operation' });
    await user.click(screen.getByRole('button', { name: 'Read operation notification' }));
    await screen.findByRole('heading', { name: 'Notification details' });
    await waitFor(() =>
      expect(
        screen.queryByRole('region', { name: 'Original request recovery' }),
      ).not.toBeInTheDocument(),
    );
    expect(sessionStorage.getItem('openpc:notification-request:v1')).toBeNull();
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
        name: phase === 'LIST' ? 'Refresh notifications' : 'Recover original result',
      }),
    );
    expect(complete).toBeTypeOf('function');
    expect(
      screen.queryByRole('region', { name: 'Notification operation' }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole('button', { name: 'Read operation notification' }),
    ).not.toBeInTheDocument();
    expect(
      screen.getByText(
        phase === 'LIST' ? 'Loading notifications.' : 'Reading notification operation.',
      ),
    ).toBeVisible();
    expect(sessionStorage.getItem('openpc:notification-request:v1')).toBe(saved);
    expect(commands).toHaveLength(0);
    await act(async () =>
      complete(
        Response.json(
          phase === 'LIST' ? page() : { ...binding, kind: 'OPERATION', operation: latest },
        ),
      ),
    );
    if (phase === 'LIST') {
      expect(screen.getByRole('list', { name: 'Notification results' })).toBeVisible();
      expect(
        screen.queryByRole('region', { name: 'Notification operation' }),
      ).not.toBeInTheDocument();
    } else
      expect(screen.getByRole('region', { name: 'Notification operation' })).toHaveTextContent(
        id(7),
      );
    expect(sessionStorage.getItem('openpc:notification-request:v1')).toBe(saved);
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
    expect(
      screen.queryByRole('region', { name: 'Notification operation' }),
    ).not.toBeInTheDocument();
    expect(screen.queryByRole('list', { name: 'Notification results' })).not.toBeInTheDocument();
    expect(sessionStorage.getItem('openpc:notification-request:v1')).toBe(
      boundary === 'blur' ? saved : null,
    );
    expect(commands).toHaveLength(0);

    if (boundary === 'blur') {
      handle = normal;
      fireEvent.focus(window);
      await screen.findByRole('list', { name: 'Notification results' });
      await user.click(screen.getByRole('button', { name: 'Inspect evidence.export.completed' }));
      await screen.findByRole('heading', { name: 'Notification details' });
      // Reauthorizing the list alone cannot restore the cleared operation proof.
      expect(screen.getByRole('region', { name: 'Original request recovery' })).toBeVisible();
      expect(sessionStorage.getItem('openpc:notification-request:v1')).toBe(saved);
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
  expect(screen.queryByRole('region', { name: 'Notification operation' })).not.toBeInTheDocument();
  expect(sessionStorage.getItem('openpc:notification-request:v1')).toBeNull();
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
  expect(await screen.findByRole('region', { name: 'Notification operation' })).toHaveTextContent(
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
    await screen.findByRole('region', { name: 'Notification operation' });
    const saved = sessionStorage.getItem('openpc:notification-request:v1');
    await user.click(screen.getByRole('button', { name: 'Refresh notifications' }));
    await screen.findByRole('list', { name: 'Notification results' });
    await user.click(screen.getByRole('button', { name: 'Inspect evidence.export.completed' }));
    await screen.findByRole('heading', { name: 'Notification details' });
    expect(screen.getByRole('region', { name: 'Original request recovery' })).toBeVisible();
    expect(sessionStorage.getItem('openpc:notification-request:v1')).toBe(saved);
    expect(screen.getByRole('button', { name: 'Create notification' })).toBeDisabled();
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
    expect(
      screen.queryByRole('region', { name: 'Notification operation' }),
    ).not.toBeInTheDocument();
    expect(screen.queryByRole('list', { name: 'Notification results' })).not.toBeInTheDocument();
    expect(
      screen.queryByRole('region', { name: 'Original request recovery' }),
    ).not.toBeInTheDocument();
    expect(sessionStorage.getItem('openpc:notification-request:v1')).toBe(saved);
    expect(commands).toHaveLength(0);
  },
);

it.each(['CREATE', 'ACKNOWLEDGE'] as const)(
  'retains the original %s receipt for current detail reconciliation after list refresh',
  async (command) => {
    const { user, saved } = await readExistingOperation(true, command);
    await user.click(screen.getByRole('button', { name: 'Refresh notifications' }));
    await screen.findByRole('list', { name: 'Notification results' });
    expect(
      screen.queryByRole('region', { name: 'Notification operation' }),
    ).not.toBeInTheDocument();
    if (command === 'ACKNOWLEDGE') {
      item.state = 'UNREAD';
      await user.click(screen.getByRole('button', { name: 'Inspect evidence.export.completed' }));
      await screen.findByRole('heading', { name: 'Notification details' });
      expect(screen.getByRole('region', { name: 'Original request recovery' })).toBeVisible();
      expect(sessionStorage.getItem('openpc:notification-request:v1')).toBe(saved);
      item.state = 'ACKNOWLEDGED';
    }
    await user.click(screen.getByRole('button', { name: 'Inspect evidence.export.completed' }));
    await screen.findByRole('heading', { name: 'Notification details' });
    await waitFor(() =>
      expect(
        screen.queryByRole('region', { name: 'Original request recovery' }),
      ).not.toBeInTheDocument(),
    );
    expect(sessionStorage.getItem('openpc:notification-request:v1')).toBeNull();
    expect(commands).toHaveLength(0);
  },
);
it('settles the unchanged original through retained receipt and current detail after a failed operation read', async () => {
  const { user, saved } = await readExistingOperation();
  const normal = handle;
  handle = (url, init) =>
    url.searchParams.get('view') === 'OPERATION' ? failedReader('unavailable') : normal(url, init);
  await user.click(screen.getByRole('button', { name: 'Recover original result' }));
  await screen.findByRole('alert');
  expect(sessionStorage.getItem('openpc:notification-request:v1')).toBe(saved);
  await user.click(screen.getByRole('button', { name: 'Inspect evidence.export.completed' }));
  await screen.findByRole('heading', { name: 'Notification details' });
  await waitFor(() =>
    expect(
      screen.queryByRole('region', { name: 'Original request recovery' }),
    ).not.toBeInTheDocument(),
  );
  expect(sessionStorage.getItem('openpc:notification-request:v1')).toBeNull();
  expect(commands).toHaveLength(0);
});
