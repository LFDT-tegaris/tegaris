import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { performWebAuthnStepUp } from '@openpc/ui-shell';
import { ParticipantEnvelopeWorkflow } from './participant-envelope-workflow';

vi.mock('@openpc/ui-shell', async () => {
  const actual = await vi.importActual<typeof import('@openpc/ui-shell')>('@openpc/ui-shell');
  return { ...actual, performWebAuthnStepUp: vi.fn().mockResolvedValue(undefined) };
});
vi.mock('./local-session', () => ({ LocalSessionSurface: () => <h2>Sign in again</h2> }));
vi.mock('./participant-envelope-recovery', () => ({
  ParticipantEnvelopeRecovery: () => <h2>Historical proposal lookup</h2>,
}));

const id = (suffix: number) => `018f0000-0000-7000-8000-${String(suffix).padStart(12, '0')}`;
const digest = `sha256:${'a'.repeat(64)}`;
const resourceDigest = `sha256:${'b'.repeat(64)}`;
const storageKey = 'openpc:participant-envelope-workflow:v1';
const session = {
  enabled: true,
  authenticated: true,
  sessionId: id(701),
  principalId: id(111),
  participantId: id(101),
  privacyDomainId: id(201),
  contextEpoch: '2',
  contextMode: 'PARTICIPANT',
  role: 'operator',
};
function workbench(role = 'operator') {
  return {
    actor: {
      role,
      principalId: role === 'viewer' ? id(112) : session.principalId,
      participantId: session.participantId,
      privacyDomainId: session.privacyDomainId,
      contextEpoch: session.contextEpoch,
    },
    approvals: [] as ReturnType<typeof approval>[],
  };
}
function approval(state = 'REQUESTED') {
  return {
    approvalRequestId: `urn:openpc:resource:${id(801)}`,
    candidateDigest: digest,
    state,
    revision: '1',
    stepUp: {
      actionIntentId: 'ACT-APPROVAL_REQUESTS_UPDATE_RESOURCE-V1',
      actionIntentDigest: resourceDigest,
      resourceId: id(801),
      resourceDigest,
    },
  };
}
function publicOperation(actionIntentId = 'ACT-APPROVAL_REQUESTS_CREATE_RESOURCE-V1') {
  return {
    operationId: id(902),
    actionIntentId,
    intentDigest: resourceDigest,
    idempotencyKey: 'workbench-request-original',
    resourceRef: `urn:openpc:resource:${id(801)}`,
    revision: '1',
    state: 'SUCCEEDED',
    truthState: 'SUCCESS',
    createdAt: '2026-10-04T00:00:00.000Z',
    updatedAt: '2026-10-04T00:00:00.000Z',
  };
}
function fullApproval(state = 'REQUESTED') {
  return {
    ...approval(state),
    actionIntentId: 'ACT-APPROVAL_REQUESTS_CREATE_RESOURCE-V1',
    makerSubjectRef: `urn:openpc:resource:${id(111)}`,
    checkerSubjectRef: `urn:openpc:resource:${id(112)}`,
    createdAt: '2026-10-04T00:00:00.000Z',
    updatedAt: '2026-10-04T00:00:00.000Z',
  };
}
function submission() {
  return {
    ...review(),
    reviewToken: 's'.repeat(100),
    operation: publicOperation(),
    approval: fullApproval(),
  };
}
function committedEffect() {
  return {
    ...effect().effect,
    authorityEpoch: '2',
    actionIntentIds: ['ACT-PARTICIPANTS_UPDATE_RESOURCE-V1'],
    resourceIds: ['*'],
    riskClasses: ['HIGH'],
    validFrom: review().review.validFrom,
    validUntil: review().review.validUntil,
    makerCheckerRequired: true,
    stepUpRequired: true,
    onwardDelegationDepth: 0,
  };
}
function committed() {
  return {
    operation: { operationId: id(902), state: 'SUCCEEDED', truthState: 'SUCCESS' },
    effect: committedEffect(),
  };
}
function review() {
  return {
    reviewToken: 'r'.repeat(100),
    review: {
      envelopeId: id(901),
      label: 'Local governance proposal',
      reason: 'Create the reviewed administration envelope.',
      candidateDigest: digest,
      validFrom: '2026-10-04T00:00:00.000Z',
      validUntil: new Date('2026-11-10T10:00').toISOString(),
      actionIntentId: 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
      riskClass: 'HIGH',
      makerCheckerRequired: true,
      stepUpRequired: true,
    },
  };
}
function effect() {
  return {
    operationId: id(902),
    effect: {
      id: id(901),
      state: 'DRAFT',
      semanticDigest: resourceDigest,
      participantId: session.participantId,
      privacyDomainIds: [session.privacyDomainId],
      authorityEpoch: '2',
      actionIntentIds: ['ACT-PARTICIPANTS_UPDATE_RESOURCE-V1'],
      resourceIds: ['*'],
      riskClasses: ['HIGH'],
      validFrom: review().review.validFrom,
      validUntil: review().review.validUntil,
      makerCheckerRequired: true,
      stepUpRequired: true,
      onwardDelegationDepth: 0,
    },
  };
}
function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((yes, no) => {
    resolve = yes;
    reject = no;
  });
  return { promise, resolve, reject };
}
function mockReads(...results: (Response | Promise<Response> | Error)[]) {
  let currentSession: unknown = session;
  const fetch = vi.spyOn(globalThis, 'fetch').mockImplementation((input) => {
    if (input === '/api/v1/ui/local-session') return Promise.resolve(Response.json(currentSession));
    const next = results.shift();
    if (!next) return Promise.reject(new Error('Unexpected workbench request'));
    return next instanceof Error ? Promise.reject(next) : Promise.resolve(next);
  });
  return {
    fetch,
    setSession: (value: unknown) => {
      currentSession = value;
    },
  };
}
function workbenchCalls(fetch: ReturnType<typeof mockReads>['fetch']) {
  return fetch.mock.calls.filter(([input]) =>
    String(input).startsWith('/api/v1/ui/participant-workbench'),
  );
}
class MockEventSource {
  static sources: MockEventSource[] = [];
  readonly listeners = new Map<string, () => void>();
  readonly close = vi.fn();
  constructor(readonly url: string) {
    MockEventSource.sources.push(this);
  }
  addEventListener(name: string, callback: () => void) {
    this.listeners.set(name, callback);
  }
  invalidate() {
    this.listeners.get('snapshot-invalidated')?.();
  }
}
let polls: (() => void)[] = [];
beforeEach(() => {
  MockEventSource.sources = [];
  polls = [];
  vi.stubGlobal('EventSource', MockEventSource);
  const browserTimers: Pick<Window, 'setInterval' | 'clearInterval'> = window;
  const original = browserTimers.setInterval.bind(window);
  const clear = browserTimers.clearInterval.bind(window);
  vi.spyOn(browserTimers, 'setInterval').mockImplementation((handler, timeout, ...args) => {
    if (timeout === 1_500 && typeof handler === 'function') {
      polls.push(() => handler(...args));
      return 1_000_000 + polls.length;
    }
    return original(handler, timeout, ...args);
  });
  vi.spyOn(browserTimers, 'clearInterval').mockImplementation((timer) => {
    if (timer === undefined || timer < 1_000_000) clear(timer);
  });
});
afterEach(() => {
  cleanup();
  localStorage.clear();
  vi.restoreAllMocks();
  vi.clearAllMocks();
  vi.mocked(performWebAuthnStepUp).mockReset().mockResolvedValue(undefined);
  vi.unstubAllGlobals();
});
async function requestPreview() {
  await screen.findByRole('heading', { name: 'Create an authority envelope' });
  fireEvent.change(screen.getByRole('textbox', { name: 'Purpose' }), {
    target: { value: review().review.label },
  });
  fireEvent.change(screen.getByLabelText('Valid until'), { target: { value: '2026-11-10T10:00' } });
  fireEvent.change(screen.getByRole('textbox', { name: 'Reason' }), {
    target: { value: review().review.reason },
  });
  await userEvent.setup().click(screen.getByRole('button', { name: 'Review immutable candidate' }));
}
async function prepare() {
  await requestPreview();
  await screen.findByRole('heading', { name: 'Immutable review' });
}

it('preserves preview, original token, distinct checker submission and exact approved commit/readback', async () => {
  const { performWebAuthnStepUp } = await import('@openpc/ui-shell');
  const { fetch } = mockReads(
    Response.json(workbench()),
    Response.json(review()),
    Response.json(submission()),
    Response.json({ ...workbench(), approvals: [approval('APPROVED')] }),
    Response.json(committed()),
    Response.json({ ...workbench(), approvals: [approval('APPROVED')], effect: effect() }),
  );
  render(<ParticipantEnvelopeWorkflow />);
  await prepare();
  const user = userEvent.setup();
  await user.click(screen.getByRole('button', { name: 'Send to checker' }));
  await screen.findByText('Approval requested from the distinct checker.');
  const submitted = { ...submission(), ...review(), approvalRequestId: id(801) };
  expect(JSON.parse(localStorage.getItem(storageKey)!)).toEqual(submitted);
  expect(screen.queryByRole('button', { name: 'Commit approved effect' })).toBeNull();
  await user.click(screen.getByRole('button', { name: 'Refresh Participant workspace' }));
  await user.click(await screen.findByRole('button', { name: 'Commit approved effect' }));
  expect(await screen.findByRole('heading', { name: 'Authoritative effect' })).toBeVisible();
  expect(
    await screen.findByText(
      'The operation succeeded and the authoritative envelope effect was read back.',
    ),
  ).toBeVisible();
  const commands = fetch.mock.calls
    .filter(([, options]) => options?.method === 'POST')
    .map(([, options]) => JSON.parse(String(options?.body)));
  expect(commands).toEqual([
    {
      command: 'PREVIEW',
      label: review().review.label,
      reason: review().review.reason,
      validUntil: new Date('2026-11-10T10:00').toISOString(),
    },
    { command: 'SUBMIT', reviewToken: review().reviewToken },
    { command: 'COMMIT', reviewToken: review().reviewToken, approvalRequestId: id(801) },
  ]);
  expect(performWebAuthnStepUp).toHaveBeenCalledWith(
    {
      actionIntentId: 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
      actionIntentDigest: 'sha256:bec5bb71e10db36e744f98a55dd6b54a0c42f9f55b73ac322a1de6e8592fd529',
      stepUp: 'FRESH_WEBAUTHN_MAX_5M',
    },
    { resourceId: id(901), resourceDigest: digest },
    { signal: expect.any(AbortSignal), isCurrent: expect.any(Function) },
  );
  expect(JSON.parse(localStorage.getItem(storageKey)!)).toEqual(submitted);
});

it('preserves the checker step-up binding and decision payload', async () => {
  const { performWebAuthnStepUp } = await import('@openpc/ui-shell');
  const { fetch, setSession } = mockReads(
    Response.json({ ...workbench('viewer'), approvals: [approval()] }),
    Response.json({ reconciled: true, approval: fullApproval('APPROVED') }),
  );
  setSession({ ...session, role: 'viewer', principalId: id(112) });
  render(<ParticipantEnvelopeWorkflow />);
  await userEvent
    .setup()
    .click(await screen.findByRole('button', { name: 'Review and approve with security key' }));
  await screen.findByText('The immutable candidate is approved.');
  expect(performWebAuthnStepUp).toHaveBeenCalledWith(
    { ...approval().stepUp, stepUp: 'FRESH_WEBAUTHN_MAX_5M' },
    { resourceId: id(801), resourceDigest },
    { signal: expect.any(AbortSignal), isCurrent: expect.any(Function) },
  );
  expect(JSON.parse(String(workbenchCalls(fetch)[1]?.[1]?.body))).toEqual({
    command: 'APPROVE',
    approvalRequestId: id(801),
  });
});

it('uses stored originals solely for exact authorized readback and never infers mutation recovery', async () => {
  const original = JSON.stringify({ ...review(), approvalRequestId: id(801) });
  localStorage.setItem(storageKey, original);
  const { fetch } = mockReads(
    Response.json({ ...workbench(), approvals: [approval('APPROVED')], effect: effect() }),
  );
  render(<ParticipantEnvelopeWorkflow />);
  expect(screen.queryByText(review().review.label)).toBeNull();
  expect(await screen.findByRole('heading', { name: 'Authoritative effect' })).toBeVisible();
  expect(String(workbenchCalls(fetch)[0]?.[0])).toBe(
    `/api/v1/ui/participant-workbench?envelopeId=${id(901)}`,
  );
  expect(
    screen.queryByRole('button', {
      name: /Send to checker|Commit approved effect|Review immutable candidate/u,
    }),
  ).toBeNull();
  expect(screen.queryByText(review().review.label)).toBeNull();
  expect(localStorage.getItem(storageKey)).toBe(original);
  expect(fetch.mock.calls.some(([, options]) => options?.method === 'POST')).toBe(false);
});

it.each(['logout', 'platform'] as const)(
  'clears the old workspace/review on %s while preserving originals',
  async (variant) => {
    const { setSession } = mockReads(Response.json(workbench()), Response.json(review()));
    render(<ParticipantEnvelopeWorkflow />);
    await prepare();
    const original = localStorage.getItem(storageKey);
    const source = MockEventSource.sources.at(-1)!;
    setSession(
      variant === 'logout'
        ? { enabled: true, authenticated: false }
        : { ...session, contextMode: 'PLATFORM' },
    );
    await act(async () => source.invalidate());
    await screen.findByRole('heading', {
      name: variant === 'logout' ? 'Sign in again' : 'Participant administration',
    });
    expect(screen.queryByRole('heading', { name: 'Immutable review' })).toBeNull();
    expect(screen.queryByRole('heading', { name: 'Participant context' })).toBeNull();
    expect(source.close).toHaveBeenCalled();
    expect(localStorage.getItem(storageKey)).toBe(original);
  },
);

it.each(['success', 'failure'] as const)(
  'ignores an obsolete owner read finishing with %s after a newer context read',
  async (outcome) => {
    const old = deferred<Response>();
    const { fetch, setSession } = mockReads(
      old.promise,
      Response.json({ ...workbench(), actor: { ...workbench().actor, contextEpoch: '3' } }),
    );
    render(<ParticipantEnvelopeWorkflow />);
    await waitFor(() => expect(workbenchCalls(fetch)).toHaveLength(1));
    setSession({ ...session, contextEpoch: '3' });
    await userEvent
      .setup()
      .click(screen.getByRole('button', { name: 'Refresh Participant workspace' }));
    await screen.findByRole('heading', { name: 'Participant context' });
    expect(workbenchCalls(fetch)[0]?.[1]?.signal?.aborted).toBe(true);
    await act(async () => {
      if (outcome === 'success') old.resolve(Response.json(workbench()));
      else old.reject(new Error('secret old transport result'));
    });
    expect(screen.getByRole('status')).toHaveTextContent(
      'The authorized Participant workspace was read back.',
    );
    expect(screen.getByText('3')).toBeVisible();
    expect(screen.queryByText(/secret/u)).toBeNull();
  },
);

it('does not accept a session rotation between owner response and display', async () => {
  const pending = deferred<Response>();
  const { fetch, setSession } = mockReads(pending.promise);
  render(<ParticipantEnvelopeWorkflow />);
  await waitFor(() => expect(workbenchCalls(fetch)).toHaveLength(1));
  setSession({ ...session, sessionId: id(702) });
  await act(async () => pending.resolve(Response.json(workbench())));
  expect(screen.getByRole('status')).toHaveTextContent('The Participant workspace is unavailable.');
  expect(screen.queryByRole('heading', { name: 'Participant context' })).toBeNull();
  expect(screen.queryByRole('button', { name: 'Review immutable candidate' })).toBeNull();
});

it.each(['http', 'transport', 'invalid-json'] as const)(
  'masks old data and safely renders a %s read failure',
  async (variant) => {
    const next =
      variant === 'http'
        ? Response.json({ title: 'secret title', code: 'SECRET-CODE' }, { status: 403 })
        : variant === 'transport'
          ? new Error('secret transport token')
          : new Response('secret invalid JSON');
    const { fetch } = mockReads(Response.json(workbench()), next);
    render(<ParticipantEnvelopeWorkflow />);
    await screen.findByRole('heading', { name: 'Participant context' });
    await userEvent
      .setup()
      .click(screen.getByRole('button', { name: 'Refresh Participant workspace' }));
    await waitFor(() =>
      expect(screen.getByRole('status')).toHaveTextContent(
        'The Participant workspace is unavailable.',
      ),
    );
    expect(screen.queryByRole('heading', { name: 'Participant context' })).toBeNull();
    expect(screen.queryByText(/secret|SECRET-CODE/u)).toBeNull();
    expect(fetch.mock.calls.some(([, options]) => options?.method === 'POST')).toBe(false);
  },
);

it.each([
  ['foreign principal', { ...workbench(), actor: { ...workbench().actor, principalId: id(113) } }],
  [
    'foreign Participant',
    { ...workbench(), actor: { ...workbench().actor, participantId: id(102) } },
  ],
  [
    'foreign privacy',
    { ...workbench(), actor: { ...workbench().actor, privacyDomainId: id(202) } },
  ],
  ['stale epoch', { ...workbench(), actor: { ...workbench().actor, contextEpoch: '1' } }],
  [
    'invalid approval',
    { ...workbench(), approvals: [{ approvalRequestId: 'invented', state: 'APPROVED' }] },
  ],
  [
    'mismatched step-up',
    {
      ...workbench(),
      approvals: [{ ...approval(), stepUp: { ...approval().stepUp, resourceId: id(802) } }],
    },
  ],
  ['unsolicited effect', { ...workbench(), effect: effect() }],
  [
    'malformed effect',
    { ...workbench(), effect: { operationId: 'secret invalid ID', effect: {} } },
  ],
] as const)('rejects %s without displaying or granting a workspace', async (_name, value) => {
  mockReads(Response.json(value));
  render(<ParticipantEnvelopeWorkflow />);
  await waitFor(() =>
    expect(screen.getByRole('status')).toHaveTextContent(
      'The Participant workspace is unavailable.',
    ),
  );
  expect(screen.queryByRole('heading', { name: 'Participant context' })).toBeNull();
  expect(screen.queryByText(/secret|invented/u)).toBeNull();
});

it('cleans up the existing polling/event callbacks and ignores stale callbacks after logout', async () => {
  localStorage.setItem(storageKey, JSON.stringify({ ...review(), approvalRequestId: id(801) }));
  const { fetch, setSession } = mockReads(
    Response.json({ ...workbench(), approvals: [approval()] }),
  );
  render(<ParticipantEnvelopeWorkflow />);
  await screen.findByRole('heading', { name: 'Participant context' });
  expect(polls).toHaveLength(1);
  const oldPoll = polls[0]!;
  const source = MockEventSource.sources.at(-1)!;
  expect(source.url).toBe(`/api/v1/ui/participant-workbench/events?approvalRequestId=${id(801)}`);
  setSession({ enabled: true, authenticated: false });
  await act(async () => oldPoll());
  await screen.findByRole('heading', { name: 'Sign in again' });
  const count = fetch.mock.calls.length;
  await act(async () => {
    oldPoll();
    source.invalidate();
  });
  expect(fetch).toHaveBeenCalledTimes(count);
  expect(source.close).toHaveBeenCalled();
  expect(window.clearInterval).toHaveBeenCalledWith(1_000_001);
  expect(localStorage.getItem(storageKey)).not.toBeNull();
});

it('stops polling when exact historical approval readback is terminal', async () => {
  localStorage.setItem(storageKey, JSON.stringify({ ...review(), approvalRequestId: id(801) }));
  mockReads(Response.json({ ...workbench(), approvals: [approval('EXPIRED')] }));
  render(<ParticipantEnvelopeWorkflow />);
  await screen.findByRole('heading', { name: 'Participant context' });
  expect(polls).toHaveLength(0);
  expect(screen.queryByRole('button', { name: 'Send to checker' })).toBeNull();
});

it.each(['success', 'failure'] as const)(
  'aborts and ignores an owner response after unmount (%s)',
  async (variant) => {
    const pending = deferred<Response>();
    const { fetch } = mockReads(pending.promise);
    const view = render(<ParticipantEnvelopeWorkflow />);
    await waitFor(() => expect(workbenchCalls(fetch)).toHaveLength(1));
    view.unmount();
    expect(workbenchCalls(fetch)[0]?.[1]?.signal?.aborted).toBe(true);
    const count = fetch.mock.calls.length;
    await act(async () => {
      if (variant === 'success') pending.resolve(Response.json(workbench()));
      else pending.reject(new Error('secret after unmount'));
    });
    expect(view.container).toBeEmptyDOMElement();
    expect(fetch).toHaveBeenCalledTimes(count);
  },
);

it('preserves malformed saved originals and blocks accidental replacement', async () => {
  const original = '{secret malformed original';
  localStorage.setItem(storageKey, original);
  mockReads(Response.json(workbench()));
  render(<ParticipantEnvelopeWorkflow />);
  await screen.findByRole('heading', { name: 'Participant context' });
  expect(localStorage.getItem(storageKey)).toBe(original);
  expect(screen.queryByRole('button', { name: 'Review immutable candidate' })).toBeNull();
  expect(screen.queryByText(/secret/u)).toBeNull();
});

it.each(['wrong-envelope', 'foreign-Participant', 'foreign-privacy'] as const)(
  'rejects %s effect readback for the exact stored selection',
  async (variant) => {
    const original = JSON.stringify(review());
    localStorage.setItem(storageKey, original);
    const readback = effect();
    if (variant === 'wrong-envelope') readback.effect.id = id(999);
    if (variant === 'foreign-Participant') readback.effect.participantId = id(102);
    if (variant === 'foreign-privacy') readback.effect.privacyDomainIds = [id(202)];
    mockReads(Response.json({ ...workbench(), effect: readback }));
    render(<ParticipantEnvelopeWorkflow />);
    await waitFor(() =>
      expect(screen.getByRole('status')).toHaveTextContent(
        'The Participant workspace is unavailable.',
      ),
    );
    expect(screen.queryByRole('heading', { name: 'Authoritative effect' })).toBeNull();
    expect(screen.queryByRole('heading', { name: 'Participant context' })).toBeNull();
    expect(localStorage.getItem(storageKey)).toBe(original);
  },
);

it('redacts a preview failure and keeps its unchanged request', async () => {
  const { fetch } = mockReads(
    Response.json(workbench()),
    Response.json({ title: 'secret command title', code: 'SECRET-CODE' }, { status: 403 }),
  );
  render(<ParticipantEnvelopeWorkflow />);
  await screen.findByRole('heading', { name: 'Create an authority envelope' });
  fireEvent.change(screen.getByRole('textbox', { name: 'Purpose' }), {
    target: { value: review().review.label },
  });
  fireEvent.change(screen.getByLabelText('Valid until'), { target: { value: '2026-11-10T10:00' } });
  fireEvent.change(screen.getByRole('textbox', { name: 'Reason' }), {
    target: { value: review().review.reason },
  });
  await userEvent.setup().click(screen.getByRole('button', { name: 'Review immutable candidate' }));
  await screen.findByText(
    'The request was not completed. Reconcile the original review before continuing.',
  );
  expect(screen.queryByText(/secret|SECRET-CODE/u)).toBeNull();
  expect(JSON.parse(String(workbenchCalls(fetch)[1]?.[1]?.body))).toMatchObject({
    command: 'PREVIEW',
    label: review().review.label,
  });
});

it.each([
  null,
  {},
  { ...review(), reviewToken: 'SECRET-TOKEN' },
  { ...review(), review: { ...review().review, actionIntentId: 'ACT-UNKNOWN-V1' } },
  { ...review(), review: { ...review().review, makerCheckerRequired: false } },
  { ...review(), review: { ...review().review, label: 'A different business request' } },
  { ...review(), review: { ...review().review, validUntil: '2026-01-01T00:00:00.000Z' } },
  { ...review(), review: { ...review().review, candidateDigest: 'SECRET-DIGEST' } },
])(
  'rejects malformed preview success before storing or rendering a review (%j)',
  async (response) => {
    const { fetch } = mockReads(Response.json(workbench()), Response.json(response));
    render(<ParticipantEnvelopeWorkflow />);
    await requestPreview();
    await screen.findByText(
      'The request was not completed. Reconcile the original review before continuing.',
    );
    expect(localStorage.getItem(storageKey)).toBeNull();
    expect(screen.queryByRole('heading', { name: 'Immutable review' })).toBeNull();
    expect(screen.queryByText(/SECRET-/u)).toBeNull();
    expect(workbenchCalls(fetch)).toHaveLength(2);
  },
);

it.each([
  {},
  { ...review(), approval: approval() },
  {
    ...submission(),
    review: { ...review().review, reason: 'A different immutable business intent.' },
  },
  { ...submission(), approval: { ...fullApproval(), candidateDigest: resourceDigest } },
  {
    ...submission(),
    approval: { ...fullApproval(), makerSubjectRef: `urn:openpc:resource:${id(113)}` },
  },
  { ...submission(), approval: { ...fullApproval(), state: 'APPROVED' } },
  {
    ...submission(),
    operation: { ...publicOperation(), resourceRef: `urn:openpc:resource:${id(802)}` },
  },
  {
    ...submission(),
    operation: { ...publicOperation(), actionIntentId: 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1' },
  },
])('preserves first raw review after mismatched SUBMIT success (%j)', async (response) => {
  const { fetch } = mockReads(
    Response.json(workbench()),
    Response.json(review()),
    Response.json(response),
  );
  render(<ParticipantEnvelopeWorkflow />);
  await prepare();
  const raw = localStorage.getItem(storageKey);
  await userEvent.setup().click(screen.getByRole('button', { name: 'Send to checker' }));
  await screen.findByText(
    'The request was not completed. Reconcile the original review before continuing.',
  );
  expect(localStorage.getItem(storageKey)).toBe(raw);
  expect(screen.queryByText('Approval requested from the distinct checker.')).toBeNull();
  expect(workbenchCalls(fetch)).toHaveLength(3);
});

it.each([
  {},
  { approval: fullApproval('APPROVED') },
  { reconciled: true, approval: { ...fullApproval('APPROVED'), candidateDigest: resourceDigest } },
  {
    reconciled: true,
    approval: { ...fullApproval('APPROVED'), approvalRequestId: `urn:openpc:resource:${id(802)}` },
  },
  { reconciled: true, approval: fullApproval('REQUESTED') },
  {
    operation: {
      ...publicOperation('ACT-POLICY_APPROVE_REQUEST-V1'),
      resourceRef: `urn:openpc:resource:${id(802)}`,
    },
    approval: fullApproval('APPROVED'),
  },
  {
    reconciled: true,
    approval: { ...fullApproval('APPROVED'), checkerSubjectRef: `urn:openpc:resource:${id(113)}` },
  },
])('does not claim a checker decision for an invalid success response (%j)', async (response) => {
  const { fetch, setSession } = mockReads(
    Response.json({ ...workbench('viewer'), approvals: [approval()] }),
    Response.json(response),
  );
  setSession({ ...session, role: 'viewer', principalId: id(112) });
  render(<ParticipantEnvelopeWorkflow />);
  await userEvent
    .setup()
    .click(await screen.findByRole('button', { name: 'Review and approve with security key' }));
  await screen.findByText(
    'The request was not completed. Reconcile the original review before continuing.',
  );
  expect(screen.queryByText('The immutable candidate is approved.')).toBeNull();
  expect(workbenchCalls(fetch)).toHaveLength(2);
});

it('accepts a full public checker decision operation distinct from envelope execution', async () => {
  const { setSession } = mockReads(
    Response.json({ ...workbench('viewer'), approvals: [approval()] }),
    Response.json({
      operation: publicOperation('ACT-POLICY_APPROVE_REQUEST-V1'),
      approval: fullApproval('APPROVED'),
    }),
  );
  setSession({ ...session, role: 'viewer', principalId: id(112) });
  render(<ParticipantEnvelopeWorkflow />);
  await userEvent
    .setup()
    .click(await screen.findByRole('button', { name: 'Review and approve with security key' }));
  expect(await screen.findByText('The immutable candidate is approved.')).toBeVisible();
  expect(screen.queryByRole('heading', { name: 'Authoritative effect' })).toBeNull();
});

it.each([
  {},
  { operationId: id(902) },
  { ...committed(), operation: { ...committed().operation, state: 'ACCEPTED' } },
  { ...committed(), effect: { ...committedEffect(), id: id(999) } },
  { ...committed(), effect: { ...committedEffect(), privacyDomainIds: [id(202)] } },
  { ...committed(), effect: { ...committedEffect(), validUntil: '2026-11-11T10:00:00.000Z' } },
  {
    truthState: 'WRITE_AMBIGUITY',
    envelopeId: id(999),
    reconciliation: 'READ_AUTHORITATIVE_EFFECT',
  },
])(
  'preserves custody and suppresses success/readback after malformed COMMIT response (%j)',
  async (response) => {
    const { fetch } = mockReads(
      Response.json(workbench()),
      Response.json(review()),
      Response.json(submission()),
      Response.json({ ...workbench(), approvals: [approval('APPROVED')] }),
      Response.json(response),
      Response.json({ ...workbench(), approvals: [approval('APPROVED')] }),
    );
    render(<ParticipantEnvelopeWorkflow />);
    await prepare();
    const user = userEvent.setup();
    await user.click(screen.getByRole('button', { name: 'Send to checker' }));
    await screen.findByText('Approval requested from the distinct checker.');
    await user.click(screen.getByRole('button', { name: 'Refresh Participant workspace' }));
    const commitButton = await screen.findByRole('button', { name: 'Commit approved effect' });
    const raw = localStorage.getItem(storageKey);
    await user.click(commitButton);
    await screen.findByText(
      'The request was not completed. Reconcile the original review before continuing.',
    );
    expect(localStorage.getItem(storageKey)).toBe(raw);
    expect(screen.queryByRole('heading', { name: 'Authoritative effect' })).toBeNull();
    expect(workbenchCalls(fetch)).toHaveLength(5);
    expect(fetch.mock.calls.filter(([, options]) => options?.method === 'POST')).toHaveLength(3);
    expect(screen.queryByRole('button', { name: 'Commit approved effect' })).toBeNull();
    fireEvent.click(commitButton);
    await user.click(screen.getByRole('button', { name: 'Read original envelope outcome' }));
    await screen.findByText(
      'The effect is unresolved; refresh authoritative readback before continuing.',
    );
    expect(
      screen.queryByRole('button', {
        name: /Commit approved effect|Review immutable candidate|Send to checker/u,
      }),
    ).toBeNull();
    expect(fetch.mock.calls.filter(([, options]) => options?.method === 'POST')).toHaveLength(3);
    expect(localStorage.getItem(storageKey)).toBe(raw);
  },
);

it('reads the legacy WRITE_AMBIGUITY effect without claiming operation correlation or replaying POST', async () => {
  const { fetch } = mockReads(
    Response.json(workbench()),
    Response.json(review()),
    Response.json(submission()),
    Response.json({ ...workbench(), approvals: [approval('APPROVED')] }),
    Response.json({
      truthState: 'WRITE_AMBIGUITY',
      envelopeId: id(901),
      reconciliation: 'READ_AUTHORITATIVE_EFFECT',
    }),
    Response.json({ ...workbench(), approvals: [approval('APPROVED')], effect: effect() }),
  );
  render(<ParticipantEnvelopeWorkflow />);
  await prepare();
  const user = userEvent.setup();
  await user.click(screen.getByRole('button', { name: 'Send to checker' }));
  await screen.findByText('Approval requested from the distinct checker.');
  await user.click(screen.getByRole('button', { name: 'Refresh Participant workspace' }));
  await user.click(await screen.findByRole('button', { name: 'Commit approved effect' }));
  expect(await screen.findByRole('heading', { name: 'Authoritative effect' })).toBeVisible();
  await screen.findByText(
    'The effect is unresolved; refresh authoritative readback before continuing.',
  );
  expect(
    screen.queryByText(
      'The operation succeeded and the authoritative envelope effect was read back.',
    ),
  ).toBeNull();
  expect(screen.queryByRole('button', { name: 'Commit approved effect' })).toBeNull();
  expect(fetch.mock.calls.filter(([, options]) => options?.method === 'POST')).toHaveLength(3);
  expect(workbenchCalls(fetch).at(-1)?.[0]).toBe(
    `/api/v1/ui/participant-workbench?envelopeId=${id(901)}`,
  );
  expect(JSON.parse(localStorage.getItem(storageKey)!)).toMatchObject({
    reviewToken: review().reviewToken,
    approvalRequestId: id(801),
  });
});

it.each(['missing-fields', 'different-validity', 'different-operation'] as const)(
  'keeps commit unresolved when authoritative follow-up has %s',
  async (variant) => {
    const readback =
      variant === 'missing-fields'
        ? {
            operationId: id(902),
            effect: {
              id: id(901),
              state: 'DRAFT',
              semanticDigest: resourceDigest,
              participantId: session.participantId,
              privacyDomainIds: [session.privacyDomainId],
            },
          }
        : variant === 'different-validity'
          ? { ...effect(), effect: { ...effect().effect, validUntil: '2026-11-11T10:00:00.000Z' } }
          : { ...effect(), operationId: id(903) };
    const { fetch } = mockReads(
      Response.json(workbench()),
      Response.json(review()),
      Response.json(submission()),
      Response.json({ ...workbench(), approvals: [approval('APPROVED')] }),
      Response.json(committed()),
      Response.json({ ...workbench(), approvals: [approval('APPROVED')], effect: readback }),
    );
    render(<ParticipantEnvelopeWorkflow />);
    await prepare();
    const user = userEvent.setup();
    await user.click(screen.getByRole('button', { name: 'Send to checker' }));
    await screen.findByText('Approval requested from the distinct checker.');
    await user.click(screen.getByRole('button', { name: 'Refresh Participant workspace' }));
    await user.click(await screen.findByRole('button', { name: 'Commit approved effect' }));
    expect(
      await screen.findByText(
        'The Participant workspace is unavailable. Refresh to check current access.',
      ),
    ).toBeVisible();
    expect(localStorage.getItem(storageKey)).not.toBeNull();
    expect(fetch.mock.calls.filter(([, options]) => options?.method === 'POST')).toHaveLength(3);
  },
);

function envelopeLifecycleFetch(
  options: {
    post?: (body: { command: string }) => Response | Promise<Response>;
    session?: () => typeof session;
    read?: (selected: boolean) => unknown;
  } = {},
) {
  let sent = false;
  return vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
    const url = String(input);
    if (url === '/api/v1/ui/local-session') return Response.json(options.session?.() ?? session);
    if (init?.method === 'POST') {
      const body = JSON.parse(String(init.body)) as { command: string };
      if (body.command === 'COMMIT') sent = true;
      if (options.post) return options.post(body);
      return Response.json(
        body.command === 'PREVIEW'
          ? review()
          : body.command === 'SUBMIT'
            ? submission()
            : committed(),
      );
    }
    const result = (await options.read?.(sent && url.includes('envelopeId='))) ?? {
      ...workbench(),
      approvals: [approval('APPROVED')],
      ...(sent && url.includes('envelopeId=') ? { effect: effect() } : {}),
    };
    return result instanceof Response ? result : Response.json(result);
  });
}
function envelopePosts(fetch: ReturnType<typeof envelopeLifecycleFetch>) {
  return fetch.mock.calls.filter(
    ([url, init]) => String(url) === '/api/v1/ui/participant-workbench' && init?.method === 'POST',
  );
}
async function prepareApprovedEnvelope() {
  await prepare();
  fireEvent.click(screen.getByRole('button', { name: 'Send to checker' }));
  await screen.findByText('Approval requested from the distinct checker.');
  fireEvent.click(screen.getByRole('button', { name: 'Refresh Participant workspace' }));
  return screen.findByRole('button', { name: 'Commit approved effect' });
}

const unresolved = 'The effect is unresolved; refresh authoritative readback before continuing.';
const originalSucceeded =
  'The operation succeeded and the authoritative envelope effect was read back.';
function assertOriginalEnvelopePosts(fetch: ReturnType<typeof envelopeLifecycleFetch>) {
  const posts = envelopePosts(fetch);
  expect(posts).toHaveLength(3);
  expect(JSON.parse(String(posts[2]![1]!.body))).toEqual({
    command: 'COMMIT',
    reviewToken: review().reviewToken,
    approvalRequestId: id(801),
  });
}

it.each(['lost', 'malformed', 'ambiguity'] as const)(
  'fences the settled original envelope %s through repeated reads of APPROVED without an effect',
  async (failure) => {
    const fetch = envelopeLifecycleFetch({
      post: (body) => {
        if (body.command !== 'COMMIT')
          return Response.json(body.command === 'PREVIEW' ? review() : submission());
        if (failure === 'lost') throw new TypeError('PRIVATE lost original response');
        return Response.json(
          failure === 'malformed'
            ? {}
            : {
                truthState: 'WRITE_AMBIGUITY',
                envelopeId: id(901),
                reconciliation: 'READ_AUTHORITATIVE_EFFECT',
              },
        );
      },
      read: () => ({ ...workbench(), approvals: [approval('APPROVED')] }),
    });
    render(<ParticipantEnvelopeWorkflow />);
    const commit = await prepareApprovedEnvelope();
    const stored = localStorage.getItem(storageKey);
    await userEvent.setup().click(commit);
    await waitFor(() =>
      expect(screen.getByRole('button', { name: 'Read original envelope outcome' })).toBeEnabled(),
    );
    fireEvent.click(commit);
    for (const name of ['Refresh Participant workspace', 'Read original envelope outcome']) {
      await userEvent.setup().click(screen.getByRole('button', { name }));
      await screen.findByText(unresolved);
      expect(
        screen.queryByRole('button', {
          name: /Commit approved effect|Review immutable candidate|Send to checker/u,
        }),
      ).toBeNull();
    }
    assertOriginalEnvelopePosts(fetch);
    expect(performWebAuthnStepUp).toHaveBeenCalledOnce();
    expect(localStorage.getItem(storageKey)).toBe(stored);
    expect(screen.queryByText(originalSucceeded)).toBeNull();
    expect(document.body.textContent).not.toContain('PRIVATE');
    const gets = workbenchCalls(fetch).filter(([, init]) => init?.method !== 'POST');
    expect(gets.slice(1).every(([url]) => String(url).endsWith(`envelopeId=${id(901)}`))).toBe(
      true,
    );
  },
);

it.each([
  'absent',
  '404',
  '503',
  'malformed',
  'foreign envelope',
  'privacy',
  'validity',
  'operation',
  'semantic digest',
  'authority epoch',
  'session race',
  'context race',
] as const)(
  'keeps known original envelope custody after %s readback, even after another explicit GET',
  async (defect) => {
    let observed = false;
    const fetch = envelopeLifecycleFetch({
      session: () =>
        observed && ['session race', 'context race'].includes(defect)
          ? {
              ...session,
              ...(defect === 'session race' ? { sessionId: id(702) } : { contextEpoch: '3' }),
            }
          : session,
      read: (selected) => {
        if (!selected) return { ...workbench(), approvals: [approval('APPROVED')] };
        observed = true;
        if (defect === '404' || defect === '503')
          return Response.json({}, { status: Number(defect) });
        if (defect === 'malformed') return {};
        if (defect === 'absent') return { ...workbench(), approvals: [approval('APPROVED')] };
        const readback = effect();
        if (defect === 'foreign envelope') readback.effect.id = id(999);
        if (defect === 'privacy') readback.effect.privacyDomainIds = [id(202)];
        if (defect === 'validity') readback.effect.validUntil = '2026-11-11T10:00:00.000Z';
        if (defect === 'operation') readback.operationId = id(903);
        if (defect === 'semantic digest') readback.effect.semanticDigest = digest;
        if (defect === 'authority epoch') readback.effect.authorityEpoch = '3';
        return { ...workbench(), approvals: [approval('APPROVED')], effect: readback };
      },
    });
    render(<ParticipantEnvelopeWorkflow />);
    fireEvent.click(await prepareApprovedEnvelope());
    await waitFor(() =>
      expect(screen.getByRole('button', { name: 'Read original envelope outcome' })).toBeEnabled(),
    );
    const stored = localStorage.getItem(storageKey);
    expect(screen.queryByText(originalSucceeded)).toBeNull();
    const before = workbenchCalls(fetch).length;
    await userEvent
      .setup()
      .click(screen.getByRole('button', { name: 'Read original envelope outcome' }));
    await waitFor(() => expect(workbenchCalls(fetch).length).toBeGreaterThan(before));
    await screen.findByText(
      defect === 'absent' || defect === 'session race'
        ? unresolved
        : 'The Participant workspace is unavailable. Refresh to check current access.',
    );
    if (defect !== 'session race')
      expect(screen.queryByRole('heading', { name: 'Authoritative effect' })).toBeNull();
    expect(
      screen.queryByRole('button', {
        name: /Commit approved effect|Review immutable candidate|Send to checker/u,
      }),
    ).toBeNull();
    expect(screen.queryByText(originalSucceeded)).toBeNull();
    assertOriginalEnvelopePosts(fetch);
    expect(localStorage.getItem(storageKey)).toBe(stored);
    expect(performWebAuthnStepUp).toHaveBeenCalledOnce();
  },
);

it('retains known accepted-operation success through matching reads and never rearms after the effect disappears', async () => {
  let present = true;
  const fetch = envelopeLifecycleFetch({
    read: (selected) => ({
      ...workbench(),
      approvals: [approval('APPROVED')],
      ...(selected && present ? { effect: effect() } : {}),
    }),
  });
  render(<ParticipantEnvelopeWorkflow />);
  fireEvent.click(await prepareApprovedEnvelope());
  await screen.findByText(originalSucceeded);
  const stored = localStorage.getItem(storageKey);
  await waitFor(() =>
    expect(screen.getByRole('button', { name: 'Read original envelope outcome' })).toBeEnabled(),
  );
  await userEvent
    .setup()
    .click(screen.getByRole('button', { name: 'Read original envelope outcome' }));
  await screen.findByText(originalSucceeded);
  expect(screen.getByRole('heading', { name: 'Authoritative effect' })).toBeVisible();
  present = false;
  await userEvent
    .setup()
    .click(screen.getByRole('button', { name: 'Refresh Participant workspace' }));
  await screen.findByText(unresolved);
  expect(screen.queryByRole('heading', { name: 'Authoritative effect' })).toBeNull();
  expect(
    screen.queryByRole('button', {
      name: /Commit approved effect|Review immutable candidate|Send to checker/u,
    }),
  ).toBeNull();
  expect(screen.queryByText(originalSucceeded)).toBeNull();
  assertOriginalEnvelopePosts(fetch);
  expect(performWebAuthnStepUp).toHaveBeenCalledOnce();
  expect(localStorage.getItem(storageKey)).toBe(stored);
});

it.each(['lost', 'ambiguity'] as const)(
  'shows the separately authorized original envelope after %s without claiming an unknown original operation succeeded',
  async (failure) => {
    const fetch = envelopeLifecycleFetch({
      post: (body) => {
        if (body.command !== 'COMMIT')
          return Response.json(body.command === 'PREVIEW' ? review() : submission());
        if (failure === 'lost') throw new TypeError('PRIVATE response lost');
        return Response.json({
          truthState: 'WRITE_AMBIGUITY',
          envelopeId: id(901),
          reconciliation: 'READ_AUTHORITATIVE_EFFECT',
        });
      },
    });
    render(<ParticipantEnvelopeWorkflow />);
    fireEvent.click(await prepareApprovedEnvelope());
    await waitFor(() =>
      expect(screen.getByRole('button', { name: 'Read original envelope outcome' })).toBeEnabled(),
    );
    await userEvent
      .setup()
      .click(screen.getByRole('button', { name: 'Read original envelope outcome' }));
    await screen.findByRole('heading', { name: 'Authoritative effect' });
    await screen.findByText(unresolved);
    expect(screen.queryByText(originalSucceeded)).toBeNull();
    expect(screen.queryByRole('button', { name: 'Commit approved effect' })).toBeNull();
    assertOriginalEnvelopePosts(fetch);
    expect(performWebAuthnStepUp).toHaveBeenCalledOnce();
  },
);

it.each(['lost', 'malformed', 'ambiguity', 'success'] as const)(
  'keeps saved original envelope %s read-only after reload without reconstructing operation correlation',
  async (failure) => {
    const fetch = envelopeLifecycleFetch({
      post: (body) => {
        if (body.command !== 'COMMIT')
          return Response.json(body.command === 'PREVIEW' ? review() : submission());
        if (failure === 'lost') throw new TypeError('PRIVATE response lost');
        return Response.json(
          failure === 'success'
            ? committed()
            : failure === 'malformed'
              ? {}
              : {
                  truthState: 'WRITE_AMBIGUITY',
                  envelopeId: id(901),
                  reconciliation: 'READ_AUTHORITATIVE_EFFECT',
                },
        );
      },
    });
    const view = render(<ParticipantEnvelopeWorkflow />);
    fireEvent.click(await prepareApprovedEnvelope());
    await waitFor(() =>
      expect(screen.getByRole('button', { name: 'Read original envelope outcome' })).toBeEnabled(),
    );
    const stored = localStorage.getItem(storageKey);
    view.unmount();
    render(<ParticipantEnvelopeWorkflow />);
    await screen.findByRole('heading', { name: 'Authoritative effect' });
    await screen.findByText(unresolved);
    await userEvent
      .setup()
      .click(screen.getByRole('button', { name: 'Read original envelope outcome' }));
    await screen.findByText(unresolved);
    expect(
      screen.queryByRole('button', {
        name: /Commit approved effect|Review immutable candidate|Send to checker/u,
      }),
    ).toBeNull();
    expect(screen.queryByText(originalSucceeded)).toBeNull();
    expect(localStorage.getItem(storageKey)).toBe(stored);
    assertOriginalEnvelopePosts(fetch);
    expect(performWebAuthnStepUp).toHaveBeenCalledOnce();
  },
);

it.each(['newer read', 'session rotation', 'unmount'] as const)(
  'ignores a held original envelope GET after %s without releasing sent custody',
  async (retirement) => {
    const pending = deferred<Response>();
    let selectedReads = 0;
    let changed = false;
    const fetch = envelopeLifecycleFetch({
      session: () => (changed ? { ...session, sessionId: id(702) } : session),
      post: (body) => {
        if (body.command === 'COMMIT') throw new TypeError('PRIVATE response lost');
        return Response.json(body.command === 'PREVIEW' ? review() : submission());
      },
      read: (selected) =>
        selected && ++selectedReads === 1
          ? pending.promise
          : { ...workbench(), approvals: [approval('APPROVED')] },
    });
    const view = render(<ParticipantEnvelopeWorkflow />);
    fireEvent.click(await prepareApprovedEnvelope());
    await waitFor(() =>
      expect(screen.getByRole('button', { name: 'Read original envelope outcome' })).toBeEnabled(),
    );
    const stored = localStorage.getItem(storageKey);
    fireEvent.click(screen.getByRole('button', { name: 'Read original envelope outcome' }));
    await waitFor(() => expect(selectedReads).toBe(1));
    const signal = workbenchCalls(fetch).at(-1)?.[1]?.signal;
    if (retirement === 'unmount') view.unmount();
    else if (retirement === 'session rotation') changed = true;
    else {
      await userEvent
        .setup()
        .click(screen.getByRole('button', { name: 'Read original envelope outcome' }));
      await screen.findByText(unresolved);
    }
    if (retirement !== 'session rotation') expect(signal?.aborted).toBe(true);
    await act(async () =>
      pending.resolve(
        Response.json({
          ...workbench(),
          approvals: [approval('APPROVED')],
          effect: effect(),
        }),
      ),
    );
    if (retirement === 'session rotation')
      await screen.findByText(
        'The Participant workspace is unavailable. Refresh to check current access.',
      );
    expect(screen.queryByText(originalSucceeded)).toBeNull();
    expect(screen.queryByRole('heading', { name: 'Authoritative effect' })).toBeNull();
    expect(screen.queryByRole('button', { name: 'Commit approved effect' })).toBeNull();
    assertOriginalEnvelopePosts(fetch);
    expect(localStorage.getItem(storageKey)).toBe(stored);
    expect(performWebAuthnStepUp).toHaveBeenCalledOnce();
  },
);

it('keeps the in-memory sent original fenced when optional storage writes fail', async () => {
  const storage = vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => {
    throw new DOMException('PRIVATE quota', 'QuotaExceededError');
  });
  const fetch = envelopeLifecycleFetch({
    post: (body) => {
      if (body.command === 'COMMIT') throw new TypeError('PRIVATE original loss');
      return Response.json(body.command === 'PREVIEW' ? review() : submission());
    },
    read: () => ({ ...workbench(), approvals: [approval('APPROVED')] }),
  });
  render(<ParticipantEnvelopeWorkflow />);
  fireEvent.click(await prepareApprovedEnvelope());
  await waitFor(() =>
    expect(screen.getByRole('button', { name: 'Read original envelope outcome' })).toBeEnabled(),
  );
  const writes = storage.mock.calls.length;
  await userEvent
    .setup()
    .click(screen.getByRole('button', { name: 'Read original envelope outcome' }));
  await screen.findByText(unresolved);
  expect(storage).toHaveBeenCalledTimes(writes);
  expect(
    screen.queryByRole('button', {
      name: /Commit approved effect|Review immutable candidate|Send to checker/u,
    }),
  ).toBeNull();
  assertOriginalEnvelopePosts(fetch);
  expect(performWebAuthnStepUp).toHaveBeenCalledOnce();
  expect(document.body.textContent).not.toContain('PRIVATE');
});

it('keeps unreadable saved original custody fail-closed without creating a replacement review', async () => {
  const stored = JSON.stringify({ ...review(), approvalRequestId: id(801) });
  localStorage.setItem(storageKey, stored);
  const readStored = Storage.prototype.getItem;
  vi.spyOn(Storage.prototype, 'getItem').mockImplementation(() => {
    throw new DOMException('PRIVATE unavailable storage', 'SecurityError');
  });
  const writes = vi.spyOn(Storage.prototype, 'setItem');
  const fetch = envelopeLifecycleFetch();
  render(<ParticipantEnvelopeWorkflow />);
  await screen.findByText(
    'Saved original custody could not be confirmed. Recover the original review before creating another request.',
  );
  await userEvent
    .setup()
    .click(screen.getByRole('button', { name: 'Refresh Participant workspace' }));
  await screen.findByText(
    'Saved original custody could not be confirmed. Recover the original review before creating another request.',
  );
  expect(
    screen.queryByRole('button', {
      name: /Commit approved effect|Review immutable candidate|Send to checker/u,
    }),
  ).toBeNull();
  expect(envelopePosts(fetch)).toHaveLength(0);
  expect(writes).not.toHaveBeenCalled();
  expect(readStored.call(localStorage, storageKey)).toBe(stored);
  expect(performWebAuthnStepUp).not.toHaveBeenCalled();
  expect(document.body.textContent).not.toContain('PRIVATE');
});

it('excludes same-turn envelope COMMIT entries and retains the original token and approval body', async () => {
  const pending = deferred<void>();
  vi.mocked(performWebAuthnStepUp).mockImplementationOnce(() => pending.promise);
  const fetch = envelopeLifecycleFetch();
  render(<ParticipantEnvelopeWorkflow />);
  const commit = await prepareApprovedEnvelope();
  act(() => {
    fireEvent.click(commit);
    fireEvent.click(commit);
  });
  await waitFor(() => expect(performWebAuthnStepUp).toHaveBeenCalledTimes(1));
  expect(envelopePosts(fetch)).toHaveLength(2);
  await act(async () => pending.resolve());
  await screen.findByText(
    'The operation succeeded and the authoritative envelope effect was read back.',
  );
  expect(envelopePosts(fetch).map(([, init]) => JSON.parse(String(init!.body)))).toEqual([
    {
      command: 'PREVIEW',
      label: review().review.label,
      reason: review().review.reason,
      validUntil: review().review.validUntil,
    },
    { command: 'SUBMIT', reviewToken: review().reviewToken },
    { command: 'COMMIT', reviewToken: review().reviewToken, approvalRequestId: id(801) },
  ]);
});
it.each([
  'sessionId',
  'principalId',
  'participantId',
  'privacyDomainId',
  'contextEpoch',
  'contextMode',
  'role',
] as const)(
  'retires a pending envelope ceremony after an authorized invalidation changes %s',
  async (field) => {
    const pending = deferred<void>();
    vi.mocked(performWebAuthnStepUp).mockImplementationOnce(() => pending.promise);
    let changed = false;
    const next = {
      ...session,
      [field]:
        field === 'role'
          ? 'viewer'
          : field === 'contextMode'
            ? 'PLATFORM'
            : field === 'contextEpoch'
              ? '3'
              : id(702),
    };
    const fetch = envelopeLifecycleFetch({
      session: () => (changed ? next : session),
      read: () =>
        changed
          ? { ...workbench(), actor: { ...workbench().actor, ...next }, approvals: [] }
          : { ...workbench(), approvals: [approval('APPROVED')] },
    });
    render(<ParticipantEnvelopeWorkflow />);
    const commit = await prepareApprovedEnvelope();
    const source = MockEventSource.sources.at(-1)!;
    act(() => {
      fireEvent.click(commit);
      changed = true;
      source.invalidate();
    });
    await waitFor(() => expect(performWebAuthnStepUp).toHaveBeenCalledTimes(1));
    const controls = vi.mocked(performWebAuthnStepUp).mock.calls[0]![2]!;
    await waitFor(() => expect(controls.signal!.aborted).toBe(true));
    await waitFor(() =>
      expect(screen.queryByRole('heading', { name: 'Immutable review' })).not.toBeInTheDocument(),
    );
    const stored = localStorage.getItem(storageKey);
    await act(async () => pending.resolve());
    expect(envelopePosts(fetch)).toHaveLength(2);
    expect(controls.isCurrent!()).toBe(false);
    expect(localStorage.getItem(storageKey)).toBe(stored);
    expect(
      screen.queryByText(
        'The operation succeeded and the authoritative envelope effect was read back.',
      ),
    ).not.toBeInTheDocument();
  },
);
it('cancels an obsolete checker binding before approval POST and lets its public read finish', async () => {
  const pending = deferred<void>();
  vi.mocked(performWebAuthnStepUp).mockImplementationOnce(() => pending.promise);
  let changed = false;
  const checker = { ...session, principalId: id(112), role: 'viewer' };
  const fetch = envelopeLifecycleFetch({
    session: () => checker,
    read: () => ({
      ...workbench('viewer'),
      approvals: changed
        ? [{ ...approval(), revision: '2', candidateDigest: resourceDigest }]
        : [approval()],
    }),
  });
  render(<ParticipantEnvelopeWorkflow />);
  const approve = await screen.findByRole('button', {
    name: 'Review and approve with security key',
  });
  await waitFor(() => expect(MockEventSource.sources.length).toBeGreaterThan(0));
  const source = MockEventSource.sources.at(-1)!;
  act(() => {
    fireEvent.click(approve);
    changed = true;
    source.invalidate();
  });
  await waitFor(() => expect(screen.getByText(resourceDigest)).toBeVisible());
  const controls = vi.mocked(performWebAuthnStepUp).mock.calls[0]![2]!;
  expect(controls.signal!.aborted).toBe(true);
  await act(async () => pending.resolve());
  expect(envelopePosts(fetch)).toHaveLength(0);
  expect(screen.queryByText('The immutable candidate is approved.')).not.toBeInTheDocument();
});
it.each(['sessionId', 'principalId', 'participantId', 'privacyDomainId'] as const)(
  'preserves the already-sent envelope original through changed %s and explicit readback',
  async (field) => {
    const pending = deferred<Response>();
    let changed = false;
    const next = { ...session, [field]: id(702) };
    const fetch = envelopeLifecycleFetch({
      session: () => (changed ? next : session),
      post: (body) =>
        body.command === 'COMMIT'
          ? pending.promise
          : Response.json(body.command === 'PREVIEW' ? review() : submission()),
      read: (selected) => ({
        ...workbench(),
        actor: { ...workbench().actor, ...(changed ? next : {}) },
        approvals: [approval('APPROVED')],
        ...(selected ? { effect: effect() } : {}),
      }),
    });
    render(<ParticipantEnvelopeWorkflow />);
    fireEvent.click(await prepareApprovedEnvelope());
    await waitFor(() => expect(envelopePosts(fetch)).toHaveLength(3));
    const stored = localStorage.getItem(storageKey);
    changed = true;
    await act(async () =>
      pending.resolve(
        Response.json(
          {
            envelopeId: id(901),
            truthState: 'WRITE_AMBIGUITY',
            reconciliation: 'READ_AUTHORITATIVE_EFFECT',
          },
          { status: 202 },
        ),
      ),
    );
    if (field === 'sessionId') await screen.findByRole('heading', { name: 'Authoritative effect' });
    else
      await screen.findByText(
        'The Participant workspace is unavailable. Refresh to check current access.',
      );
    const before = fetch.mock.calls.length;
    fireEvent.click(screen.getByRole('button', { name: 'Refresh Participant workspace' }));
    if (field === 'sessionId')
      await waitFor(() =>
        expect(
          fetch.mock.calls
            .slice(before)
            .some(([url]) => String(url).includes(`envelopeId=${id(901)}`)),
        ).toBe(true),
      );
    else await waitFor(() => expect(fetch.mock.calls.length).toBeGreaterThan(before));
    expect(
      fetch.mock.calls.slice(before).some(([url]) => String(url).includes('envelopeId=')),
    ).toBe(field === 'sessionId');
    expect(localStorage.getItem(storageKey)).toBe(stored);
    expect(screen.queryByRole('heading', { name: 'Immutable review' })).not.toBeInTheDocument();
    expect(envelopePosts(fetch)).toHaveLength(3);
  },
);
it('adopts the accepted submission in memory when optional storage is unavailable', async () => {
  const fetch = envelopeLifecycleFetch();
  render(<ParticipantEnvelopeWorkflow />);
  await prepare();
  const stored = localStorage.getItem(storageKey);
  vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => {
    throw new DOMException('private quota detail', 'QuotaExceededError');
  });
  fireEvent.click(screen.getByRole('button', { name: 'Send to checker' }));
  await screen.findByText('Approval requested from the distinct checker.');
  expect(screen.getByText('Approval state:')).toHaveTextContent('REQUESTED');
  fireEvent.click(screen.getByRole('button', { name: 'Refresh Participant workspace' }));
  expect(await screen.findByRole('button', { name: 'Commit approved effect' })).toBeVisible();
  expect(localStorage.getItem(storageKey)).toBe(stored);
  expect(document.body.textContent).not.toContain('private quota detail');
  expect(envelopePosts(fetch)).toHaveLength(2);
});
it.each(['success', 'failure'] as const)(
  'suppresses late envelope PREVIEW %s after local fields change',
  async (outcome) => {
    const pending = deferred<Response>();
    const fetch = envelopeLifecycleFetch({ post: () => pending.promise });
    render(<ParticipantEnvelopeWorkflow />);
    await screen.findByRole('heading', { name: 'Create an authority envelope' });
    fireEvent.change(screen.getByRole('textbox', { name: 'Purpose' }), {
      target: { value: review().review.label },
    });
    fireEvent.change(screen.getByLabelText('Valid until'), {
      target: { value: '2026-11-10T10:00' },
    });
    fireEvent.change(screen.getByRole('textbox', { name: 'Reason' }), {
      target: { value: review().review.reason },
    });
    const form = screen
      .getByRole('button', { name: 'Review immutable candidate' })
      .closest('form')!;
    act(() => {
      fireEvent.submit(form);
      fireEvent.submit(form);
    });
    await waitFor(() => expect(envelopePosts(fetch)).toHaveLength(1));
    fireEvent.change(screen.getByRole('textbox', { name: 'Purpose' }), {
      target: { value: 'A different purpose' },
    });
    await act(async () =>
      pending.resolve(
        outcome === 'success'
          ? Response.json(review())
          : Response.json({ title: 'private provider trace' }, { status: 503 }),
      ),
    );
    expect(screen.queryByRole('heading', { name: 'Immutable review' })).not.toBeInTheDocument();
    expect(localStorage.getItem(storageKey)).toBeNull();
    expect(document.body.textContent).not.toContain('private provider trace');
  },
);
it.each(['challenge', 'navigator', 'verification'] as const)(
  'composes the actual envelope helper and suppresses post-unmount effects at held %s',
  async (phase) => {
    const actual = await vi.importActual<typeof import('@openpc/ui-shell')>('@openpc/ui-shell');
    vi.mocked(performWebAuthnStepUp).mockImplementation(actual.performWebAuthnStepUp);
    const bytes = (value: string) => new TextEncoder().encode(value).buffer;
    class Credential {
      rawId = bytes('credential');
      response = {
        authenticatorData: bytes('authenticator'),
        clientDataJSON: bytes('client'),
        signature: bytes('signature'),
      };
    }
    const challenge = {
      publicKey: {
        challenge: 'Y2hhbGxlbmdl',
        rpId: 'localhost',
        allowCredentials: [{ id: 'Y3JlZGVudGlhbA', type: 'public-key' }],
        timeout: 300000,
        userVerification: 'required',
      },
      expiresAt: new Date(Date.now() + 300_000).toISOString().replace('Z', '000Z'),
    };
    const verified = { status: 'verified', stepUpVerifiedAt: '2026-10-05T00:00:01.000000Z' };
    const pending = deferred<Response | Credential>();
    const get = vi.fn(async () => (phase === 'navigator' ? pending.promise : new Credential()));
    vi.stubGlobal('PublicKeyCredential', Credential);
    vi.stubGlobal('navigator', { credentials: { get } });
    const ordinary = envelopeLifecycleFetch();
    const implementation = ordinary.getMockImplementation()!;
    ordinary.mockImplementation(async (input, init) => {
      const url = String(input);
      if (url.endsWith('/assertion/challenge'))
        return phase === 'challenge'
          ? (pending.promise as Promise<Response>)
          : Response.json(challenge);
      if (url.endsWith('/assertion/verify'))
        return phase === 'verification'
          ? (pending.promise as Promise<Response>)
          : Response.json(verified);
      return implementation(input, init);
    });
    const view = render(<ParticipantEnvelopeWorkflow />);
    fireEvent.click(await prepareApprovedEnvelope());
    await waitFor(() => {
      if (phase === 'navigator') expect(get).toHaveBeenCalledTimes(1);
      else
        expect(
          ordinary.mock.calls.some(([url]) =>
            String(url).endsWith(
              phase === 'challenge' ? '/assertion/challenge' : '/assertion/verify',
            ),
          ),
        ).toBe(true);
    });
    const stored = localStorage.getItem(storageKey);
    const controls = vi.mocked(performWebAuthnStepUp).mock.calls[0]![2]!;
    view.unmount();
    expect(controls.signal!.aborted).toBe(true);
    await act(async () =>
      pending.resolve(
        phase === 'navigator'
          ? new Credential()
          : Response.json(phase === 'challenge' ? challenge : verified),
      ),
    );
    expect(envelopePosts(ordinary)).toHaveLength(2);
    expect(get).toHaveBeenCalledTimes(phase === 'challenge' ? 0 : 1);
    expect(
      ordinary.mock.calls.filter(([url]) => String(url).endsWith('/assertion/verify')),
    ).toHaveLength(phase === 'verification' ? 1 : 0);
    expect(localStorage.getItem(storageKey)).toBe(stored);
  },
);

it.each(['success', 'failure'] as const)(
  'excludes duplicate envelope SUBMIT and preserves original custody after unmount with %s',
  async (outcome) => {
    const pending = deferred<Response>();
    const fetch = envelopeLifecycleFetch({
      post: (body) => (body.command === 'PREVIEW' ? Response.json(review()) : pending.promise),
    });
    const view = render(<ParticipantEnvelopeWorkflow />);
    await prepare();
    const stored = localStorage.getItem(storageKey);
    const submit = screen.getByRole('button', { name: 'Send to checker' });
    act(() => {
      fireEvent.click(submit);
      fireEvent.click(submit);
    });
    await waitFor(() => expect(envelopePosts(fetch)).toHaveLength(2));
    expect(JSON.parse(String(envelopePosts(fetch)[1]![1]!.body))).toEqual({
      command: 'SUBMIT',
      reviewToken: review().reviewToken,
    });
    view.unmount();
    await act(async () =>
      pending.resolve(
        outcome === 'success'
          ? Response.json(submission())
          : Response.json({ title: 'private submission trace' }, { status: 503 }),
      ),
    );
    expect(localStorage.getItem(storageKey)).toBe(stored);
    expect(envelopePosts(fetch)).toHaveLength(2);
    expect(document.body.textContent).not.toContain('private submission trace');
  },
);

it.each(['navigator', 'verification'] as const)(
  'composes the actual envelope helper and checks the actual session after held %s without a UI invalidation',
  async (phase) => {
    const actual = await vi.importActual<typeof import('@openpc/ui-shell')>('@openpc/ui-shell');
    vi.mocked(performWebAuthnStepUp).mockImplementation(actual.performWebAuthnStepUp);
    const bytes = (value: string) => new TextEncoder().encode(value).buffer;
    class Credential {
      rawId = bytes('credential');
      response = {
        authenticatorData: bytes('authenticator'),
        clientDataJSON: bytes('client'),
        signature: bytes('signature'),
      };
    }
    const challenge = {
      publicKey: {
        challenge: 'Y2hhbGxlbmdl',
        rpId: 'localhost',
        allowCredentials: [{ id: 'Y3JlZGVudGlhbA', type: 'public-key' }],
        timeout: 300000,
        userVerification: 'required',
      },
      expiresAt: new Date(Date.now() + 300_000).toISOString().replace('Z', '000Z'),
    };
    const verified = { status: 'verified', stepUpVerifiedAt: '2026-10-05T00:00:01.000000Z' };
    let changedSession = false;
    const pending = deferred<Response | Credential>();
    const get = vi.fn(async () => (phase === 'navigator' ? pending.promise : new Credential()));
    vi.stubGlobal('PublicKeyCredential', Credential);
    vi.stubGlobal('navigator', { credentials: { get } });
    const ordinary = envelopeLifecycleFetch({
      session: () => (changedSession ? { ...session, principalId: id(702) } : session),
    });
    const implementation = ordinary.getMockImplementation()!;
    ordinary.mockImplementation(async (input, init) => {
      const url = String(input);
      if (url.endsWith('/assertion/challenge')) return Response.json(challenge);
      if (url.endsWith('/assertion/verify'))
        return phase === 'verification'
          ? (pending.promise as Promise<Response>)
          : Response.json(verified);
      return implementation(input, init);
    });
    render(<ParticipantEnvelopeWorkflow />);
    fireEvent.click(await prepareApprovedEnvelope());
    await waitFor(() => {
      if (phase === 'navigator') expect(get).toHaveBeenCalledTimes(1);
      else
        expect(ordinary.mock.calls.some(([url]) => String(url).endsWith('/assertion/verify'))).toBe(
          true,
        );
    });
    const stored = localStorage.getItem(storageKey);
    const controls = vi.mocked(performWebAuthnStepUp).mock.calls[0]![2]!;
    changedSession = true;
    await act(async () =>
      pending.resolve(phase === 'navigator' ? new Credential() : Response.json(verified)),
    );
    await waitFor(() => expect(controls.signal!.aborted).toBe(true));
    expect(screen.queryByRole('heading', { name: 'Immutable review' })).not.toBeInTheDocument();
    expect(envelopePosts(ordinary)).toHaveLength(2);
    expect(get).toHaveBeenCalledTimes(1);
    expect(
      ordinary.mock.calls.filter(([url]) => String(url).endsWith('/assertion/verify')),
    ).toHaveLength(1);
    expect(localStorage.getItem(storageKey)).toBe(stored);
  },
);

it.each([
  'sessionId',
  'principalId',
  'participantId',
  'privacyDomainId',
  'contextEpoch',
  'contextMode',
  'role',
] as const)(
  'qualifies the actual envelope session after held step-up when %s changes without a UI read',
  async (field) => {
    const pending = deferred<void>();
    vi.mocked(performWebAuthnStepUp).mockImplementationOnce(() => pending.promise);
    let changed = false;
    const next = {
      ...session,
      [field]:
        field === 'role'
          ? 'viewer'
          : field === 'contextMode'
            ? 'PLATFORM'
            : field === 'contextEpoch'
              ? '3'
              : id(702),
    };
    const fetch = envelopeLifecycleFetch({ session: () => (changed ? next : session) });
    render(<ParticipantEnvelopeWorkflow />);
    fireEvent.click(await prepareApprovedEnvelope());
    await waitFor(() => expect(performWebAuthnStepUp).toHaveBeenCalledTimes(1));
    const before = fetch.mock.calls.filter(
      ([url]) => String(url) === '/api/v1/ui/local-session',
    ).length;
    const stored = localStorage.getItem(storageKey);
    changed = true;
    await act(async () => pending.resolve());
    await screen.findByText(
      'The Participant workspace is unavailable. Refresh to check current access.',
    );
    expect(
      fetch.mock.calls.filter(([url]) => String(url) === '/api/v1/ui/local-session'),
    ).toHaveLength(before + 1);
    expect(envelopePosts(fetch)).toHaveLength(2);
    expect(screen.queryByRole('heading', { name: 'Immutable review' })).not.toBeInTheDocument();
    expect(localStorage.getItem(storageKey)).toBe(stored);
  },
);

it('retires a held actual envelope session qualification on unmount before business POST', async () => {
  const ordinary = envelopeLifecycleFetch();
  const implementation = ordinary.getMockImplementation()!;
  const pending = deferred<Response>();
  let holdSession = false;
  ordinary.mockImplementation(async (input, init) =>
    String(input) === '/api/v1/ui/local-session' && holdSession
      ? pending.promise
      : implementation(input, init),
  );
  const view = render(<ParticipantEnvelopeWorkflow />);
  const commit = await prepareApprovedEnvelope();
  const before = ordinary.mock.calls.filter(
    ([url]) => String(url) === '/api/v1/ui/local-session',
  ).length;
  holdSession = true;
  fireEvent.click(commit);
  await waitFor(() =>
    expect(
      ordinary.mock.calls.filter(([url]) => String(url) === '/api/v1/ui/local-session'),
    ).toHaveLength(before + 1),
  );
  const stored = localStorage.getItem(storageKey);
  const controls = vi.mocked(performWebAuthnStepUp).mock.calls[0]![2]!;
  view.unmount();
  expect(controls.signal!.aborted).toBe(true);
  await act(async () => pending.resolve(Response.json(session)));
  expect(envelopePosts(ordinary)).toHaveLength(2);
  expect(localStorage.getItem(storageKey)).toBe(stored);
});

it('retains one notification connection across same-account invalidation reads', async () => {
  const { fetch } = mockReads(
    Response.json(workbench()),
    Response.json(workbench()),
    Response.json(workbench()),
  );
  render(<ParticipantEnvelopeWorkflow />);
  await screen.findByRole('heading', { name: 'Participant context' });
  await waitFor(() => expect(MockEventSource.sources).toHaveLength(1));
  const source = MockEventSource.sources[0]!;
  await act(async () => source.invalidate());
  await waitFor(() => expect(workbenchCalls(fetch)).toHaveLength(2));
  await screen.findByRole('heading', { name: 'Participant context' });
  expect(MockEventSource.sources).toHaveLength(1);
  expect(source.close).not.toHaveBeenCalled();
  await act(async () => source.invalidate());
  await waitFor(() => expect(workbenchCalls(fetch)).toHaveLength(3));
  await screen.findByRole('heading', { name: 'Participant context' });
  expect(MockEventSource.sources).toHaveLength(1);
  expect(fetch.mock.calls.some(([, options]) => options?.method === 'POST')).toBe(false);
});

it('closes the notification connection when an authenticated refresh cannot be verified', async () => {
  const { fetch } = mockReads(Response.json(workbench()), new Error('unavailable'));
  render(<ParticipantEnvelopeWorkflow />);
  await screen.findByRole('heading', { name: 'Participant context' });
  await waitFor(() => expect(MockEventSource.sources).toHaveLength(1));
  const source = MockEventSource.sources[0]!;
  await act(async () => source.invalidate());
  await screen.findByText(
    'The Participant workspace is unavailable. Refresh to check current access.',
  );
  expect(screen.queryByRole('heading', { name: 'Participant context' })).toBeNull();
  expect(source.close).toHaveBeenCalledTimes(1);
  await act(async () => source.invalidate());
  expect(workbenchCalls(fetch)).toHaveLength(2);
  expect(fetch.mock.calls.some(([, options]) => options?.method === 'POST')).toBe(false);
});

it('arms notifications only after the full workspace read is verified', async () => {
  const pending = deferred<Response>();
  const fetch = vi
    .spyOn(globalThis, 'fetch')
    .mockImplementation(async (input) =>
      input === '/api/v1/ui/local-session' ? Response.json(session) : pending.promise,
    );
  render(<ParticipantEnvelopeWorkflow evaluationUi />);
  await screen.findByRole('heading', { name: 'Loading organization authority' });
  expect(MockEventSource.sources).toHaveLength(0);
  await act(async () => pending.resolve(Response.json(workbench())));
  await screen.findByRole('heading', { name: 'Organization authority' });
  await waitFor(() => expect(MockEventSource.sources).toHaveLength(1));
  expect(fetch.mock.calls.some(([, options]) => options?.method === 'POST')).toBe(false);
});

it('keeps the authority draft and focus when inspecting workspace references', async () => {
  const { fetch } = mockReads(Response.json(workbench()));
  const user = userEvent.setup();
  render(<ParticipantEnvelopeWorkflow evaluationUi />);
  await screen.findByRole('heading', { name: 'Organization authority' });
  const purpose = screen.getByRole('textbox', { name: 'Purpose' });
  await user.type(purpose, 'Quarterly service access');
  expect(screen.getByRole('button', { name: 'Review request' })).toBeVisible();
  expect(screen.getByText(session.participantId)).not.toBeVisible();
  const references = screen.getByRole('button', { name: 'Workspace details' });
  await user.click(references);
  expect(screen.getByRole('dialog', { name: 'Workspace details' })).toBeVisible();
  expect(screen.getByText(session.participantId)).toBeVisible();
  await user.click(screen.getByRole('button', { name: 'Close Workspace details' }));
  await waitFor(() =>
    expect(screen.queryByRole('dialog', { name: 'Workspace details' })).toBeNull(),
  );
  expect(references).toHaveFocus();
  expect(purpose).toHaveValue('Quarterly service access');
  expect(fetch.mock.calls.some(([, options]) => options?.method === 'POST')).toBe(false);
});
