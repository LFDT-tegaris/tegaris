import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import { SetupWorkflow } from './setup-workflow';
import { sessionTransitionEvent, sessionTransitionStorageKey } from './session-transition';
vi.mock('./local-session', () => ({ LocalSessionSurface: () => <p>Session controls</p> }));
vi.mock('./transaction-workflow', () => ({ TransactionWorkflow: () => <p>Provider controls</p> }));
const actor = {
  sessionId: '018f0000-0000-7000-8000-000000000111',
  principalId: '018f0000-0000-7000-8000-000000000112',
  participantId: '018f0000-0000-7000-8000-000000000101',
  privacyDomainId: '018f0000-0000-7000-8000-000000000201',
  contextEpoch: '2',
};
afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  localStorage.clear();
});
it.each([
  ['COMPLETE', true, 'No providers are available to your account in this workspace.'],
  ['UNKNOWN', false, 'No records returned; coverage is incomplete.'],
] as const)(
  'keeps provider emptiness distinct from %s coverage in the product view',
  async (completeness, authorizedEmpty, message) => {
    const fetcher = vi
      .spyOn(globalThis, 'fetch')
      .mockImplementation(async (input) =>
        Response.json(
          String(input).includes('?')
            ? { actor, result: { items: [], nextCursor: null, completeness, authorizedEmpty } }
            : { actor },
        ),
      );
    render(<SetupWorkflow kind="providers" evaluationUi showSessionControls={false} />);
    expect(await screen.findByText(message)).toBeVisible();
    expect(screen.queryByText('Session controls')).toBeNull();
    expect(fetcher.mock.calls.every(([, init]) => init?.method !== 'POST')).toBe(true);
  },
);

it('selects an actual provider record without typing a reference or issuing a command', async () => {
  const reference = 'urn:openpc:resource:018f0000-0000-7000-8000-000000000321';
  const provider = {
    providerProfileId: reference,
    chainId: '92870',
    state: 'QUALIFIED',
    admissionScope: 'BOUNDED_QA',
    historicalReorgConformance: 'NOT_TESTED',
    endpointSecretRef: 'urn:openpc:secret:provider-fixture',
  };
  const fetcher = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
    const query = new URL(String(input), 'http://localhost').searchParams;
    return Response.json(
      query.has('kind')
        ? {
            actor,
            result: query.has('resourceId')
              ? provider
              : {
                  items: [provider],
                  nextCursor: null,
                  completeness: 'COMPLETE',
                  authorizedEmpty: false,
                },
          }
        : { actor },
    );
  });
  render(<SetupWorkflow kind="providers" />);
  await screen.findByRole('heading', { name: 'Chain 92870' });
  expect(screen.getByText('Bounded evaluation')).toBeVisible();
  expect(screen.getByText('Not verified')).toBeVisible();
  expect(screen.getByText('Qualified')).toBeVisible();
  const details = screen
    .getByRole('button', { name: 'Technical details', hidden: true })
    .parentElement!.querySelector('dialog')!;
  expect(details.open).toBe(false);
  const raw = screen.getByLabelText('Technical details for provider 1');
  expect(raw).not.toBeVisible();
  expect(screen.getByLabelText('Provider reference to read')).not.toBeVisible();
  fireEvent.click(screen.getByRole('button', { name: 'View provider 1 for chain 92870' }));
  await waitFor(() =>
    expect(
      fetcher.mock.calls.some(([input]) =>
        String(input).includes(`resourceId=${reference.slice(-36)}`),
      ),
    ).toBe(true),
  );
  await screen.findByRole('heading', { name: 'Chain 92870' });
  expect(fetcher.mock.calls.every(([, init]) => !init?.method)).toBe(true);
  fireEvent.click(screen.getByRole('button', { name: 'Technical details', hidden: true }));
  const currentDetails = screen.getByLabelText('Technical details for provider 1');
  expect(currentDetails.tabIndex).toBe(0);
  expect(currentDetails).toHaveTextContent(reference);
});

it('shows actual denial without fabricating an empty collection or readiness', async () => {
  const fetcher = vi
    .spyOn(globalThis, 'fetch')
    .mockImplementation(async (input) =>
      String(input).includes('?')
        ? Response.json(
            { title: 'Not found or not authorized', code: 'PC-AUTH-0005' },
            { status: 404 },
          )
        : Response.json({ actor }),
    );
  render(<SetupWorkflow kind="runtime" />);
  await screen.findByText(
    'Setup request was not authorized. Refresh the authenticated context before continuing.',
  );
  expect(screen.queryByText('No authorized records.')).not.toBeInTheDocument();
  expect(screen.getByText(/Discovery records an unready target/)).toBeInTheDocument();
  expect(fetcher.mock.calls.every(([, init]) => !init?.method)).toBe(true);
});

it('restores the original ambiguous discovery without replay, and clears data when context changes', async () => {
  localStorage.setItem(
    'openpc:setup:runtime:v1',
    JSON.stringify({
      actor,
      value: {
        reviewToken: 'original',
        preview: { reason: 'private original request' },
        uncertain: true,
      },
    }),
  );
  let current = actor;
  const fetcher = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) =>
    Response.json(
      String(input).includes('?')
        ? {
            actor: current,
            result: {
              items: [],
              nextCursor: null,
              completeness: 'COMPLETE',
              authorizedEmpty: true,
            },
          }
        : { actor: current },
    ),
  );
  render(<SetupWorkflow kind="runtime" />);
  await screen.findByText(/private original request/);
  expect(screen.getByRole('button', { name: 'Record discovered target' })).toBeDisabled();
  current = { ...actor, sessionId: actor.privacyDomainId, principalId: actor.privacyDomainId };
  fireEvent.click(screen.getByRole('button', { name: 'Refresh runtime targets' }));
  await waitFor(() =>
    expect(screen.queryByText(/private original request/)).not.toBeInTheDocument(),
  );
  expect(localStorage.getItem('openpc:setup:runtime:v1')).toBeNull();
  expect(fetcher.mock.calls.every(([, init]) => !init?.method)).toBe(true);
});

it.each(['same-tab', 'cross-tab'] as const)(
  'clears setup data during a %s session transition without replaying the original request',
  async (channel) => {
    const stored = JSON.stringify({
      actor,
      value: {
        reviewToken: 'original',
        preview: { reason: 'private original request' },
        uncertain: true,
      },
    });
    localStorage.setItem('openpc:setup:runtime:v1', stored);
    let current = actor;
    const fetcher = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) =>
      Response.json(
        String(input).includes('?')
          ? {
              actor: current,
              result: {
                items: [{ targetId: 'private-runtime-record' }],
                nextCursor: null,
                completeness: 'COMPLETE',
                authorizedEmpty: false,
              },
            }
          : { actor: current },
      ),
    );
    const transition = (phase: 'changing' | 'settled') =>
      channel === 'same-tab'
        ? fireEvent(window, new CustomEvent(sessionTransitionEvent, { detail: { phase } }))
        : fireEvent(
            window,
            new StorageEvent('storage', {
              key: sessionTransitionStorageKey,
              newValue: JSON.stringify({ phase, nonce: 'public-notification' }),
            }),
          );
    render(<SetupWorkflow kind="runtime" />);
    await screen.findByText(/private-runtime-record/);
    await screen.findByText(/private original request/);
    fireEvent.change(screen.getByLabelText('Runtime target reference to read'), {
      target: { value: 'private-resource-reference' },
    });
    const reads = fetcher.mock.calls.length;
    transition('changing');
    expect(screen.queryByText(/private-runtime-record/)).not.toBeInTheDocument();
    expect(screen.queryByText(/private original request/)).not.toBeInTheDocument();
    expect(screen.queryByText(/Participant:/)).not.toBeInTheDocument();
    expect(screen.getByLabelText('Runtime target reference to read')).toHaveValue('');
    expect(localStorage.getItem('openpc:setup:runtime:v1')).toBe(stored);
    fireEvent.focus(window);
    expect(fetcher.mock.calls).toHaveLength(reads);
    current = { ...actor, contextEpoch: '3' };
    transition('settled');
    await screen.findByText(/Participant:/);
    expect(screen.queryByText(/private original request/)).not.toBeInTheDocument();
    expect(fetcher.mock.calls.every(([, init]) => !init?.method)).toBe(true);
  },
);

it('ignores an old successful list after sign-out starts', async () => {
  let release!: (response: Response) => void;
  const delayed = new Promise<Response>((resolve) => (release = resolve));
  let signedOut = false;
  const fetcher = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
    if (signedOut) return Response.json({ code: 'PC-AUTH-0005' }, { status: 404 });
    return String(input).includes('?') ? delayed : Response.json({ actor });
  });
  render(<SetupWorkflow kind="providers" />);
  await waitFor(() =>
    expect(fetcher.mock.calls.some(([input]) => String(input).includes('?'))).toBe(true),
  );
  fireEvent(window, new CustomEvent(sessionTransitionEvent, { detail: { phase: 'changing' } }));
  signedOut = true;
  fireEvent(window, new CustomEvent(sessionTransitionEvent, { detail: { phase: 'settled' } }));
  await screen.findByText(setupAuthorization);
  await act(async () =>
    release(
      Response.json({
        actor,
        result: {
          items: [{ chainId: 'PRIVATE_OLD_PROVIDER' }],
          completeness: 'COMPLETE',
          authorizedEmpty: false,
        },
      }),
    ),
  );
  expect(screen.queryByText(/PRIVATE_OLD_PROVIDER/)).not.toBeInTheDocument();
  expect(screen.queryByText(/Participant:/)).not.toBeInTheDocument();
  expect(fetcher.mock.calls.every(([, init]) => !init?.method)).toBe(true);
});

it('hides records during focus revalidation and conceals them if the session is gone', async () => {
  let release!: (response: Response) => void;
  let rechecking = false;
  const delayed = new Promise<Response>((resolve) => (release = resolve));
  vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
    if (rechecking) return delayed;
    return Response.json(
      String(input).includes('?')
        ? {
            actor,
            result: {
              items: [{ chainId: 'PRIVATE_FOCUSED_PROVIDER' }],
              completeness: 'COMPLETE',
              authorizedEmpty: false,
            },
          }
        : { actor },
    );
  });
  render(<SetupWorkflow kind="providers" />);
  await screen.findByRole('heading', { name: 'Chain PRIVATE_FOCUSED_PROVIDER' });
  rechecking = true;
  fireEvent.focus(window);
  expect(screen.queryAllByText(/PRIVATE_FOCUSED_PROVIDER/)).toHaveLength(0);
  expect(screen.queryByText(/Participant:/)).not.toBeInTheDocument();
  await act(async () => release(Response.json({ code: 'PC-AUTH-0005' }, { status: 404 })));
  await screen.findByText(setupAuthorization);
  expect(screen.queryAllByText(/PRIVATE_FOCUSED_PROVIDER/)).toHaveLength(0);
});

it('keeps an unsubmitted setup draft after the same actor passes focus revalidation', async () => {
  vi.spyOn(globalThis, 'fetch').mockImplementation(async () => Response.json({ actor }));
  render(<SetupWorkflow kind="indexers" />);
  await screen.findByText(/Participant:/);
  fireEvent.change(screen.getByLabelText('Reader engine version'), { target: { value: '1.2.3' } });
  fireEvent.change(screen.getByLabelText('Setup reason'), {
    target: { value: 'Prepare the reader' },
  });
  fireEvent.focus(window);
  await screen.findByText(/Participant:/);
  expect(screen.getByLabelText('Reader engine version')).toHaveValue('1.2.3');
  expect(screen.getByLabelText('Setup reason')).toHaveValue('Prepare the reader');
});

it('preserves the current workspace after the previous actor command rejects', async () => {
  const original = { reviewToken: 'actor-a-review', preview: { reason: 'ACTOR_A_PRIVATE_REVIEW' } };
  localStorage.setItem('openpc:setup:runtime:v1', JSON.stringify({ actor, value: original }));
  let current = actor;
  let items: { targetId: string }[] = [];
  let release!: (response: Response) => void;
  const delayed = new Promise<Response>((resolve) => (release = resolve));
  const fetcher = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
    if (init?.method === 'POST') return delayed;
    return Response.json(
      String(input).includes('?')
        ? {
            actor: current,
            result: {
              items,
              nextCursor: null,
              completeness: 'COMPLETE',
              authorizedEmpty: items.length === 0,
            },
          }
        : { actor: current },
    );
  });
  render(<SetupWorkflow kind="runtime" />);
  await screen.findByText(/ACTOR_A_PRIVATE_REVIEW/);
  fireEvent.click(screen.getByRole('button', { name: 'Record discovered target' }));
  await waitFor(() =>
    expect(fetcher.mock.calls.filter(([, init]) => init?.method === 'POST')).toHaveLength(1),
  );
  fireEvent(window, new CustomEvent(sessionTransitionEvent, { detail: { phase: 'changing' } }));
  current = { ...actor, sessionId: actor.privacyDomainId, principalId: actor.privacyDomainId };
  items = [{ targetId: 'ACTOR_B_CURRENT_RESOURCE' }];
  const retainedB = JSON.stringify({
    actor: current,
    value: {
      reviewToken: 'actor-b-review',
      preview: { reason: 'ACTOR_B_PRIVATE_REVIEW' },
      uncertain: true,
    },
  });
  localStorage.setItem('openpc:setup:runtime:v1', retainedB);
  fireEvent(window, new CustomEvent(sessionTransitionEvent, { detail: { phase: 'settled' } }));
  await screen.findByText(/ACTOR_B_PRIVATE_REVIEW/);
  await screen.findByText(/ACTOR_B_CURRENT_RESOURCE/);
  await act(async () => release(Response.json({ code: 'PC-AUTH-0005' }, { status: 403 })));
  expect(screen.queryByText(setupAuthorization)).not.toBeInTheDocument();
  expect(screen.getByText(/ACTOR_B_CURRENT_RESOURCE/)).toBeInTheDocument();
  expect(screen.queryByText(/ACTOR_A_PRIVATE_REVIEW/)).not.toBeInTheDocument();
  expect(screen.getByText(/ACTOR_B_PRIVATE_REVIEW/)).toBeInTheDocument();
  expect(localStorage.getItem('openpc:setup:runtime:v1')).toBe(retainedB);
  expect(fetcher.mock.calls.filter(([, init]) => init?.method === 'POST')).toHaveLength(1);
});

it.each(['owner read', 'final context'] as const)(
  'conceals retained review and fields when the %s denies after a successful base read',
  async (boundary) => {
    const stored = JSON.stringify({
      actor,
      value: {
        reviewToken: 'original',
        preview: { reason: 'PRIVATE_RETAINED_SETUP' },
        uncertain: true,
      },
    });
    localStorage.setItem('openpc:setup:runtime:v1', stored);
    let failing = false;
    let baseReads = 0;
    let release!: (response: Response) => void;
    const delayed = new Promise<Response>((resolve) => (release = resolve));
    const fetcher = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      const collection = String(input).includes('?');
      if (failing) {
        if (!collection) baseReads++;
        if (
          (boundary === 'owner read' && collection) ||
          (boundary === 'final context' && !collection && baseReads === 2)
        )
          return delayed;
      }
      return setupRead(input);
    });
    render(<SetupWorkflow kind="runtime" />);
    await screen.findByText(/PRIVATE_RETAINED_SETUP/);
    fireEvent.change(screen.getByLabelText('Runtime target reference to read'), {
      target: { value: 'PRIVATE_REFERENCE' },
    });
    failing = true;
    const before = fetcher.mock.calls.length;
    fireEvent.click(screen.getByRole('button', { name: 'Refresh runtime targets' }));
    await waitFor(() =>
      expect(fetcher.mock.calls.length).toBe(before + (boundary === 'owner read' ? 2 : 3)),
    );
    expect(screen.queryByText(/PRIVATE_RETAINED_SETUP/)).not.toBeInTheDocument();
    expect(screen.queryByText(/Participant:/)).not.toBeInTheDocument();
    expect(screen.getByLabelText('Runtime target reference to read')).toHaveValue('');
    await act(async () => release(Response.json({ code: 'PC-AUTH-0005' }, { status: 401 })));
    await screen.findByText(setupAuthorization);
    expect(screen.queryByText(/PRIVATE_RETAINED_SETUP/)).not.toBeInTheDocument();
    expect(screen.queryByText(/Participant:/)).not.toBeInTheDocument();
    expect(
      screen.queryByRole('button', { name: 'Record discovered target' }),
    ).not.toBeInTheDocument();
    expect(localStorage.getItem('openpc:setup:runtime:v1')).toBe(stored);
    expect(fetcher.mock.calls.every(([, init]) => !init?.method)).toBe(true);
  },
);

it.each([404, 503])(
  'preserves the original discovery on HTTP %s and blocks uncertain replay',
  async (status) => {
    localStorage.setItem(
      'openpc:setup:runtime:v1',
      JSON.stringify({
        actor,
        value: { reviewToken: 'original', preview: { reason: 'original discovery' } },
      }),
    );
    const fetcher = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      if (init?.method === 'POST') return Response.json({ title: 'Request rejected' }, { status });
      return Response.json(
        String(input).includes('?')
          ? {
              actor,
              result: {
                items: [],
                nextCursor: null,
                completeness: 'COMPLETE',
                authorizedEmpty: true,
              },
            }
          : { actor },
      );
    });
    render(<SetupWorkflow kind="runtime" />);
    const submit = await screen.findByRole('button', { name: 'Record discovered target' });
    await screen.findByText('No authorized records.');
    fireEvent.click(submit);
    await screen.findByText(
      status === 404
        ? 'Setup request was not authorized. Refresh the authenticated context before continuing.'
        : 'Setup could not be confirmed. Refresh or read the original operation before retrying.',
    );
    await waitFor(() => expect(submit).toHaveProperty('disabled', status === 503));
    const retained = JSON.parse(localStorage.getItem('openpc:setup:runtime:v1')!);
    expect(retained.value).toMatchObject({ reviewToken: 'original', uncertain: status === 503 });
    expect(fetcher.mock.calls.filter(([, init]) => init?.method === 'POST')).toHaveLength(1);
  },
);

const unsafeSetupMarker = 'PRIVATE_SETUP_TRANSPORT_OR_SERVER_DETAIL';
const setupUnavailable =
  'Setup could not be confirmed. Refresh or read the original operation before retrying.';
const setupAuthorization =
  'Setup request was not authorized. Refresh the authenticated context before continuing.';
const setupConflict =
  'Setup state changed. Refresh or read the original operation before retrying.';
const setupInput = 'Setup request was rejected. Check the inputs before continuing.';
const setupFailures = [
  { name: '400', status: 400, message: setupInput, uncertain: false },
  { name: '401', status: 401, message: setupAuthorization, uncertain: false },
  { name: '403', status: 403, message: setupAuthorization, uncertain: false },
  { name: '404', status: 404, message: setupAuthorization, uncertain: false },
  { name: '409', status: 409, message: setupConflict, uncertain: false },
  { name: '422', status: 422, message: setupInput, uncertain: false },
  { name: '428', status: 428, message: setupConflict, uncertain: false },
  // Display classification must not add 412 to the deterministic-rejection contract.
  { name: '412', status: 412, message: setupConflict, uncertain: true },
  { name: '500', status: 500, message: setupUnavailable, uncertain: true },
  { name: '503', status: 503, message: setupUnavailable, uncertain: true },
  { name: 'transport', message: setupUnavailable, uncertain: true },
  { name: 'unknown object', message: setupUnavailable, uncertain: true },
  { name: 'non-JSON success', message: setupUnavailable, uncertain: true },
  { name: 'malformed JSON success', message: setupUnavailable, uncertain: true },
] as const;
function failSetup(failure: (typeof setupFailures)[number]): Response {
  if ('status' in failure)
    return Response.json(
      { title: unsafeSetupMarker, code: unsafeSetupMarker },
      { status: failure.status },
    );
  if (failure.name === 'transport') throw new Error(unsafeSetupMarker);
  if (failure.name === 'unknown object')
    throw { message: unsafeSetupMarker, code: unsafeSetupMarker };
  return new Response(failure.name === 'non-JSON success' ? unsafeSetupMarker : '{', {
    status: 200,
  });
}
function setupRead(input: RequestInfo | URL) {
  return Response.json(
    String(input).includes('?')
      ? {
          actor,
          result: {
            items: [],
            nextCursor: 'next-page',
            completeness: 'COMPLETE',
            authorizedEmpty: true,
          },
        }
      : { actor },
  );
}
it.each(setupFailures)(
  'hides $name discovery failures while retaining the original uncertainty contract',
  async (failure) => {
    const original = {
      reviewToken: 'original-sealed-review',
      preview: { reason: 'original discovery', requestKey: 'original-intent' },
    };
    localStorage.setItem('openpc:setup:runtime:v1', JSON.stringify({ actor, value: original }));
    const fetcher = vi
      .spyOn(globalThis, 'fetch')
      .mockImplementation(async (input, init) =>
        init?.method === 'POST' ? failSetup(failure) : setupRead(input),
      );
    render(<SetupWorkflow kind="runtime" />);
    const submit = await screen.findByRole('button', { name: 'Record discovered target' });
    await screen.findByText('No authorized records.');
    fireEvent.click(submit);
    await screen.findByText(failure.message);
    await waitFor(() => expect(submit).toHaveProperty('disabled', failure.uncertain));
    expect(document.body.textContent).not.toContain(unsafeSetupMarker);
    expect(JSON.parse(localStorage.getItem('openpc:setup:runtime:v1')!)).toEqual({
      actor,
      value: { ...original, uncertain: failure.uncertain },
    });
    const posts = fetcher.mock.calls.filter(([, init]) => init?.method === 'POST');
    expect(posts).toHaveLength(1);
    expect(JSON.parse(String(posts[0]![1]!.body))).toEqual({
      command: 'CREATE_RUNTIME',
      reviewToken: original.reviewToken,
    });
    expect(
      screen.queryByRole('button', { name: 'Read original operation' }),
    ).not.toBeInTheDocument();
    expect(screen.queryByText(/The operation was recorded/)).not.toBeInTheDocument();
    expect(screen.queryByRole('alert') !== null).toBe(failure.uncertain);
  },
);
it.each([
  'initial context',
  'initial list',
  'refresh',
  'resource',
  'cursor',
  'original operation',
  'preview',
] as const)('does not display untrusted details from the %s boundary', async (boundary) => {
  const original = {
    reviewToken: 'original',
    preview: { reason: 'original discovery' },
    operationId: actor.principalId,
  };
  if (boundary === 'original operation')
    localStorage.setItem('openpc:setup:runtime:v1', JSON.stringify({ actor, value: original }));
  const stored = localStorage.getItem('openpc:setup:runtime:v1');
  let fail = boundary.startsWith('initial');
  const fetcher = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, _init) => {
    const url = String(input);
    if (fail && (boundary !== 'initial list' || url.includes('?')))
      return failSetup({ name: 'transport', message: setupUnavailable, uncertain: true });
    return setupRead(input);
  });
  render(<SetupWorkflow kind="runtime" />);
  if (!fail) {
    await screen.findByText('No authorized records.');
    fail = true;
    if (boundary === 'preview') {
      fireEvent.change(screen.getByLabelText('Reason for discovery'), {
        target: { value: 'Review this exact runtime discovery.' },
      });
      fireEvent.click(screen.getByRole('button', { name: 'Review discovery' }));
    } else if (boundary === 'resource') {
      fireEvent.change(screen.getByLabelText('Runtime target reference to read'), {
        target: { value: actor.principalId },
      });
      fireEvent.click(screen.getByRole('button', { name: 'Read current resource' }));
    } else
      fireEvent.click(
        screen.getByRole('button', {
          name:
            boundary === 'cursor'
              ? 'Read next page'
              : boundary === 'original operation'
                ? 'Read original operation'
                : 'Refresh runtime targets',
        }),
      );
  }
  await screen.findByText(setupUnavailable);
  expect(document.body.textContent).not.toContain(unsafeSetupMarker);
  expect(localStorage.getItem('openpc:setup:runtime:v1')).toBe(stored);
  expect(fetcher.mock.calls.filter(([, init]) => init?.method === 'POST')).toHaveLength(
    boundary === 'preview' ? 1 : 0,
  );
  expect(screen.queryByText(/The operation was recorded/)).not.toBeInTheDocument();
});
it('retains uncertainty when a successful discovery response belongs to another context', async () => {
  const original = { reviewToken: 'original', preview: { reason: 'original discovery' } };
  localStorage.setItem('openpc:setup:runtime:v1', JSON.stringify({ actor, value: original }));
  const fetcher = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) =>
    init?.method === 'POST'
      ? Response.json({
          actor: { ...actor, contextEpoch: '3' },
          operation: { operationId: actor.principalId },
        })
      : setupRead(input),
  );
  render(<SetupWorkflow kind="runtime" />);
  await screen.findByText('No authorized records.');
  fireEvent.click(screen.getByRole('button', { name: 'Record discovered target' }));
  await screen.findByText('The selected context changed. Refresh before continuing.');
  expect(JSON.parse(localStorage.getItem('openpc:setup:runtime:v1')!).value).toEqual({
    ...original,
    uncertain: true,
  });
  expect(fetcher.mock.calls.filter(([, init]) => init?.method === 'POST')).toHaveLength(1);
  expect(screen.getByRole('button', { name: 'Record discovered target' })).toBeDisabled();
});
it.each([200, 201])(
  'keeps a successful HTTP %s operation as an operation rather than runtime readiness',
  async (status) => {
    const original = { reviewToken: 'original', preview: { reason: 'original discovery' } };
    localStorage.setItem('openpc:setup:runtime:v1', JSON.stringify({ actor, value: original }));
    const operation = {
      operationId: actor.principalId,
      resourceRef: `urn:openpc:resource:${actor.sessionId}`,
    };
    const fetcher = vi
      .spyOn(globalThis, 'fetch')
      .mockImplementation(async (input, init) =>
        init?.method === 'POST'
          ? Response.json({ actor, operation }, { status })
          : setupRead(input),
      );
    render(<SetupWorkflow kind="runtime" />);
    await screen.findByText('No authorized records.');
    fireEvent.click(screen.getByRole('button', { name: 'Record discovered target' }));
    await screen.findByText(/The operation was recorded/);
    expect(JSON.parse(localStorage.getItem('openpc:setup:runtime:v1')!).value).toEqual({
      ...original,
      uncertain: false,
      operationId: operation.operationId,
      resourceId: actor.sessionId,
    });
    expect(screen.getByRole('button', { name: 'Record discovered target' })).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Read original operation' })).toBeEnabled();
    expect(fetcher.mock.calls.filter(([, init]) => init?.method === 'POST')).toHaveLength(1);
  },
);

it('reviews ordinary reader setup, preserves ambiguity, and clears the previous actor fields', async () => {
  let current = actor;
  const commands: Record<string, unknown>[] = [];
  vi.spyOn(globalThis, 'fetch').mockImplementation(async (_input, init) => {
    if (init?.method === 'POST') {
      const body = JSON.parse(String(init.body));
      commands.push(body);
      return Response.json(
        body.command === 'PREVIEW_INDEXER'
          ? {
              actor: current,
              reviewToken: 'reader-original',
              preview: { engine: 'CLIENT_INDEXER', reason: 'actual reader' },
            }
          : { actor: current, truthState: 'UNKNOWN' },
      );
    }
    return Response.json({ actor: current });
  });
  render(<SetupWorkflow kind="indexers" />);
  await screen.findByText(/Participant:/);
  fireEvent.change(screen.getByLabelText('Reader engine'), { target: { value: 'CLIENT_INDEXER' } });
  fireEvent.change(screen.getByLabelText('Reader engine version'), { target: { value: '1.0.0' } });
  fireEvent.change(screen.getByLabelText('Reader profile artifact digest (sha256)'), {
    target: { value: 'sha256:' + 'a'.repeat(64) },
  });
  fireEvent.change(screen.getByLabelText('Setup reason'), { target: { value: 'actual reader' } });
  fireEvent.click(screen.getByRole('button', { name: 'Review setup' }));
  await screen.findByText(/The reviewed input cannot declare/);
  expect(commands[0]).toMatchObject({
    command: 'PREVIEW_INDEXER',
    kind: 'indexers',
    fields: { engine: 'CLIENT_INDEXER', engineVersion: '1.0.0' },
  });
  fireEvent.click(screen.getByRole('button', { name: 'Submit reviewed setup' }));
  await screen.findByText(/The outcome is unknown/);
  expect(screen.getByRole('button', { name: 'Submit reviewed setup' })).toBeDisabled();
  current = { ...actor, sessionId: actor.privacyDomainId };
  fireEvent.click(screen.getByRole('button', { name: 'Refresh chain reader' }));
  await waitFor(() => expect(screen.queryByText(/actual reader/)).not.toBeInTheDocument());
  expect(screen.getByLabelText('Reader engine version')).toHaveValue('');
  expect(commands).toHaveLength(2);
});

it('reviews runtime activation without an approval form or caller-supplied generation and records readback separately', async () => {
  const commands: Record<string, unknown>[] = [];
  vi.spyOn(globalThis, 'fetch').mockImplementation(async (_input, init) => {
    if (init?.method !== 'POST') return Response.json({ actor });
    const body = JSON.parse(String(init.body));
    commands.push(body);
    return Response.json(
      body.command === 'PREVIEW_INDEXER'
        ? {
            actor,
            reviewToken: 'activation-original',
            preview: { targetRef: actor.sessionId, replacementDigest: 'sha256:' + 'a'.repeat(64) },
          }
        : {
            actor,
            operation: {
              operationId: actor.principalId,
              resourceRef: 'urn:openpc:resource:' + actor.sessionId,
              state: 'ACCEPTED',
              truthState: 'SUCCESS',
            },
          },
    );
  });
  render(<SetupWorkflow kind="runtime-activation" showSessionControls={false} />);
  expect(screen.queryByText('Session controls')).not.toBeInTheDocument();
  await screen.findByText(/Participant:/);
  fireEvent.change(screen.getByLabelText('Runtime target resource reference'), {
    target: { value: 'urn:openpc:resource:' + actor.sessionId },
  });
  fireEvent.change(screen.getByLabelText('Runtime target expected revision'), {
    target: { value: '4' },
  });
  fireEvent.change(screen.getByLabelText('Setup reason'), {
    target: { value: 'Refresh current sources' },
  });
  fireEvent.click(screen.getByRole('button', { name: 'Review setup' }));
  await screen.findByText(/This review binds the current candidate/);
  expect(commands[0]).toMatchObject({
    command: 'PREVIEW_INDEXER',
    kind: 'runtime-activation',
    fields: { targetRef: 'urn:openpc:resource:' + actor.sessionId, expectedRevision: '4' },
  });
  expect(screen.queryByLabelText(/Checker/)).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', { name: 'Submit reviewed setup' }));
  await screen.findByText(/The update was recorded/);
  expect(screen.getByRole('button', { name: 'Read original operation' })).toBeEnabled();
  expect(commands[1]).toEqual({ command: 'EXECUTE_INDEXER', reviewToken: 'activation-original' });
});

it('shows loading while a provider read is pending and lets the user return to the directory', async () => {
  const reference = 'urn:openpc:resource:018f0000-0000-7000-8000-000000000321';
  const provider = { providerProfileId: reference, chainId: '92870', state: 'REGISTERED' };
  let finish: ((response: Response) => void) | undefined;
  const fetcher = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
    const query = new URL(String(input), 'http://localhost').searchParams;
    if (query.has('resourceId'))
      return new Promise<Response>((resolve) => {
        finish = resolve;
      });
    return Response.json(
      query.has('kind')
        ? {
            actor,
            result: {
              items: [provider],
              nextCursor: null,
              completeness: 'COMPLETE',
              authorizedEmpty: false,
            },
          }
        : { actor },
    );
  });
  render(<SetupWorkflow kind="providers" />);
  await screen.findByRole('heading', { name: 'Chain 92870' });
  fireEvent.click(screen.getByRole('button', { name: 'View provider 1 for chain 92870' }));
  await screen.findByText('Loading providers…');
  expect(screen.queryByRole('heading', { name: 'Chain 92870' })).toBeNull();
  expect(screen.queryByText('No authorized records.')).toBeNull();
  expect(screen.getByRole('button', { name: 'Refresh providers' })).toBeDisabled();
  expect(screen.getByText('Read current resource', { selector: 'button' })).toBeDisabled();
  await waitFor(() => expect(finish).toBeTypeOf('function'));
  await act(async () => finish!(Response.json({ actor, result: provider })));
  await screen.findByRole('heading', { name: 'Chain 92870' });
  expect(screen.queryByText('Loading providers…')).toBeNull();
  fireEvent.click(screen.getByRole('button', { name: 'Back to all providers' }));
  await screen.findByText('1 provider on this page.');
  expect(screen.queryByRole('button', { name: 'Back to all providers' })).toBeNull();
  expect(fetcher.mock.calls.every(([, init]) => !init?.method)).toBe(true);
});

it('ends loading on an unavailable read without turning the failure into an empty directory', async () => {
  const fetcher = vi
    .spyOn(globalThis, 'fetch')
    .mockImplementation(async (input) =>
      String(input).includes('?') ? Response.json({}, { status: 503 }) : Response.json({ actor }),
    );
  render(<SetupWorkflow kind="providers" />);
  await screen.findByText(
    'Setup could not be confirmed. Refresh or read the original operation before retrying.',
  );
  expect(screen.queryByText('Loading providers…')).toBeNull();
  expect(screen.queryByText('No authorized records.')).toBeNull();
  expect(screen.getByRole('button', { name: 'Refresh providers' })).toBeEnabled();
  expect(fetcher.mock.calls.every(([, init]) => !init?.method)).toBe(true);
});

it('clears loading immediately on a context transition and discards the delayed provider reply', async () => {
  let finish: ((response: Response) => void) | undefined;
  vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) =>
    String(input).includes('?')
      ? new Promise<Response>((resolve) => {
          finish = resolve;
        })
      : Response.json({ actor }),
  );
  render(<SetupWorkflow kind="providers" />);
  await screen.findByText('Loading providers…');
  await waitFor(() => expect(finish).toBeTypeOf('function'));
  act(() => {
    window.dispatchEvent(
      new CustomEvent(sessionTransitionEvent, { detail: { phase: 'changing' } }),
    );
  });
  expect(screen.queryByText('Loading providers…')).toBeNull();
  await act(async () =>
    finish!(
      Response.json({ actor, result: { providerProfileId: 'old-provider', chainId: '92870' } }),
    ),
  );
  expect(screen.queryByRole('heading', { name: 'Chain 92870' })).toBeNull();
  expect(screen.queryByText('Loading providers…')).toBeNull();
});

it('reads a runtime target from a card using the original reference and returns to its collection', async () => {
  const target = {
    targetId: 'urn:openpc:resource:018f0000-0000-7000-8000-000000000321',
    state: 'STAGING',
    desiredGenerationDigest: `sha256:${'a'.repeat(64)}`,
    activeGenerationDigest: null,
    observedAt: '2026-11-09T13:12:00.000Z',
  };
  const fetcher = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
    const query = new URL(String(input), 'http://localhost').searchParams;
    return Response.json(
      query.has('kind')
        ? {
            actor,
            result: query.has('resourceId')
              ? target
              : {
                  items: [target],
                  nextCursor: null,
                  completeness: 'COMPLETE',
                  authorizedEmpty: false,
                },
          }
        : { actor },
    );
  });
  render(<SetupWorkflow kind="runtime" evaluationUi showSessionControls={false} />);
  await screen.findByRole('heading', { name: 'Runtime target 1' });
  expect(screen.getByText('1 runtime target on this page.')).toBeVisible();
  expect(screen.getByLabelText('Runtime target reference to read')).not.toBeVisible();
  expect(screen.getByText(/Participant:/)).not.toBeVisible();
  expect(screen.getByLabelText('Technical details for runtime target 1')).not.toBeVisible();
  fireEvent.click(screen.getByRole('button', { name: 'View runtime target 1' }));
  await screen.findByRole('button', { name: 'Back to all runtime targets' });
  expect(
    fetcher.mock.calls.some(([url]) =>
      String(url).includes(`resourceId=${target.targetId.slice(-36)}`),
    ),
  ).toBe(true);
  fireEvent.click(screen.getByRole('button', { name: 'Back to all runtime targets' }));
  await screen.findByText('1 runtime target on this page.');
  expect(fetcher.mock.calls.every(([, init]) => !init?.method)).toBe(true);
});

it.each([
  ['COMPLETE', true, 'No runtime targets are available to your account in this workspace.'],
  ['UNKNOWN', false, 'No records returned; coverage is incomplete.'],
] as const)(
  'reports runtime collection emptiness with %s coverage',
  async (completeness, authorizedEmpty, message) => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) =>
      Response.json(
        String(input).includes('?')
          ? { actor, result: { items: [], nextCursor: null, completeness, authorizedEmpty } }
          : { actor },
      ),
    );
    render(<SetupWorkflow kind="runtime" evaluationUi showSessionControls={false} />);
    expect(await screen.findByText(message)).toBeVisible();
    expect(screen.queryByRole('heading', { name: 'Runtime target 1' })).toBeNull();
  },
);

it('clears a listed runtime target when its resource read is denied and keeps private diagnostics hidden', async () => {
  const target = {
    targetId: 'urn:openpc:resource:018f0000-0000-7000-8000-000000000321',
    state: 'STAGING',
  };
  const fetcher = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
    const query = new URL(String(input), 'http://localhost').searchParams;
    if (query.has('resourceId'))
      return Response.json({ detail: 'PRIVATE_RUNTIME_RESPONSE_DETAIL' }, { status: 404 });
    return Response.json(
      query.has('kind')
        ? {
            actor,
            result: {
              items: [target],
              nextCursor: null,
              completeness: 'COMPLETE',
              authorizedEmpty: false,
            },
          }
        : { actor },
    );
  });
  render(<SetupWorkflow kind="runtime" evaluationUi showSessionControls={false} />);
  await screen.findByRole('heading', { name: 'Runtime target 1' });
  fireEvent.click(screen.getByRole('button', { name: 'View runtime target 1' }));
  await screen.findByText(
    'Setup request was not authorized. Refresh the authenticated context before continuing.',
  );
  expect(screen.queryByRole('heading', { name: 'Runtime target 1' })).toBeNull();
  expect(document.body).not.toHaveTextContent('PRIVATE_RUNTIME_RESPONSE_DETAIL');
  expect(fetcher.mock.calls.every(([, init]) => !init?.method)).toBe(true);
});
