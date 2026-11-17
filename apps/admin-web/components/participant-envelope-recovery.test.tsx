import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import { ParticipantEnvelopeRecovery } from './participant-envelope-recovery';

const storageKey = 'openpc:participant-envelope-recovery:v1';
const selection = {
  envelopeId: '018f0000-0000-7000-8000-000000000701',
  targetParticipantId: '018f0000-0000-7000-8000-000000000702',
  issuerPrivacyDomainId: '018f0000-0000-7000-8000-000000000201',
  creationApprovalRequestId: '018f0000-0000-7000-8000-000000000301',
};
const session = {
  enabled: true,
  authenticated: true,
  sessionId: '018f0000-0000-7000-8000-000000000711',
  principalId: '018f0000-0000-7000-8000-000000000111',
  participantId: '018f0000-0000-7000-8000-000000000101',
  privacyDomainId: selection.issuerPrivacyDomainId,
  contextEpoch: '2',
  contextMode: 'PLATFORM',
  role: 'operator',
};
const readFailure =
  'The proposal is unavailable. Check current access and the saved identifiers before refreshing.';
function mockReads(...results: (Response | Promise<Response> | Error)[]) {
  return vi.spyOn(globalThis, 'fetch').mockImplementation((input) => {
    if (input === '/api/v1/ui/local-session') return Promise.resolve(Response.json(session));
    const next = results.shift();
    if (!next) return Promise.reject(new Error('Unexpected proposal read'));
    return next instanceof Error ? Promise.reject(next) : Promise.resolve(next);
  });
}
function ownerCalls(fetcher: ReturnType<typeof mockReads>) {
  return fetcher.mock.calls.filter(([input]) =>
    String(input).startsWith('/api/v1/ui/participant-workbench?'),
  );
}
function recovered() {
  const scope = {
    administration: {
      participantIds: [selection.targetParticipantId],
      privacyDomainIds: ['018f0000-0000-7000-8000-000000000703'],
      resourceIds: [selection.envelopeId],
      actionIntentIds: ['ACT-PARTICIPANTS_UPDATE_RESOURCE-V1'],
      dataClasses: [],
      targetProfileIds: [],
      riskClasses: ['HIGH'],
    },
    runtime: {
      participantIds: [],
      privacyDomainIds: [],
      resourceIds: [],
      capabilityIds: [],
      dataClasses: [],
      targetProfileIds: [],
      riskClasses: [],
    },
    validFromNs: '1788220800000000000',
    validUntilNs: '1798761600000000000',
    makerCheckerRequired: true,
    stepUpRequired: true,
    onwardDelegationDepth: 0,
  };
  return {
    selection,
    actor: {
      principalId: session.principalId,
      participantId: session.participantId,
      contextEpoch: session.contextEpoch,
    },
    state: 'DRAFT',
    semanticDigest: `sha256:${'a'.repeat(64)}`,
    creationOperationId: '018f0000-0000-7000-8000-000000000501',
    lastOperationId: '018f0000-0000-7000-8000-000000000501',
    disclosurePrivacyDomainIds: [],
    usable: scope,
    grantable: scope,
    runtimePermission: 'NONE',
  };
}
afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  localStorage.clear();
});

it('restores identifiers only and displays scope only after authoritative recovery', async () => {
  localStorage.setItem(
    storageKey,
    JSON.stringify({ ...selection, usable: { secret: 'cached authority' } }),
  );
  let resolve!: (value: Response) => void;
  const fetcher = mockReads(
    new Promise<Response>((done) => {
      resolve = done;
    }),
  );
  render(<ParticipantEnvelopeRecovery />);
  expect(screen.queryByRole('heading', { name: 'Proposal DRAFT' })).not.toBeInTheDocument();
  expect(screen.queryByText('cached authority')).not.toBeInTheDocument();
  expect(JSON.parse(localStorage.getItem(storageKey)!)).toEqual(selection);
  await waitFor(() => expect(ownerCalls(fetcher)).toHaveLength(1));
  expect(ownerCalls(fetcher)[0]?.[0]).toBe(
    `/api/v1/ui/participant-workbench?${new URLSearchParams(selection)}`,
  );
  await act(async () => resolve(Response.json(recovered())));
  expect(await screen.findByRole('heading', { name: 'Proposal DRAFT' })).toBeInTheDocument();
  expect(screen.getByText('None in the selected issuer privacy domain')).toBeInTheDocument();
  expect(screen.getByText('This proposal does not authorize runtime work.')).toBeInTheDocument();
  expect(JSON.parse(localStorage.getItem(storageKey)!)).toEqual(selection);
});

it('removes disclosed state before refresh and keeps it removed after an authorization failure', async () => {
  localStorage.setItem(storageKey, JSON.stringify(selection));
  let resolve!: (value: Response) => void;
  mockReads(
    Response.json(recovered()),
    new Promise<Response>((done) => {
      resolve = done;
    }),
  );
  render(<ParticipantEnvelopeRecovery />);
  await screen.findByRole('heading', { name: 'Proposal DRAFT' });
  fireEvent.click(screen.getByRole('button', { name: 'Refresh from server' }));
  expect(screen.queryByRole('heading', { name: 'Proposal DRAFT' })).not.toBeInTheDocument();
  expect(screen.queryByText(recovered().semanticDigest)).not.toBeInTheDocument();
  await act(async () =>
    resolve(Response.json({ title: 'Access is no longer available.' }, { status: 403 })),
  );
  expect(await screen.findByText(readFailure)).toBeInTheDocument();
  expect(screen.queryByText('Grantable scope')).not.toBeInTheDocument();
});

it('clears scope on identifier edits before native validation and stops refreshing the old selection', async () => {
  localStorage.setItem(storageKey, JSON.stringify(selection));
  const fetcher = mockReads(Response.json(recovered()));
  render(<ParticipantEnvelopeRecovery />);
  await screen.findByRole('heading', { name: 'Proposal DRAFT' });
  fireEvent.change(screen.getByLabelText('Envelope ID'), { target: { value: 'invalid' } });
  expect(screen.queryByText('Usable scope')).not.toBeInTheDocument();
  expect(screen.queryByText(recovered().semanticDigest)).not.toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Refresh from server' })).toBeDisabled();
  const count = fetcher.mock.calls.length;
  fireEvent(window, new Event('focus'));
  fireEvent(window, new Event('pageshow'));
  expect(fetcher).toHaveBeenCalledTimes(count);
  expect(JSON.parse(localStorage.getItem(storageKey)!)).toEqual(selection);
});

it('ignores an older successful response after a newer context read was denied', async () => {
  localStorage.setItem(storageKey, JSON.stringify(selection));
  let first!: (value: Response) => void;
  let second!: (value: Response) => void;
  const fetcher = mockReads(
    new Promise<Response>((done) => {
      first = done;
    }),
    new Promise<Response>((done) => {
      second = done;
    }),
  );
  render(<ParticipantEnvelopeRecovery />);
  await waitFor(() => expect(ownerCalls(fetcher)).toHaveLength(1));
  fireEvent.focus(window);
  await waitFor(() => expect(ownerCalls(fetcher)).toHaveLength(2));
  await act(async () => second(Response.json({ title: 'Context changed.' }, { status: 403 })));
  await screen.findByText(readFailure);
  await act(async () => first(Response.json(recovered())));
  expect(screen.queryByRole('heading', { name: 'Proposal DRAFT' })).not.toBeInTheDocument();
  expect(screen.getByText(readFailure)).toBeInTheDocument();
});

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((yes, no) => {
    resolve = yes;
    reject = no;
  });
  return { promise, resolve, reject };
}

it.each([
  ['missing scope', (body: ReturnType<typeof recovered>) => ({ ...body, usable: undefined })],
  [
    'invalid dimension array',
    (body: ReturnType<typeof recovered>) => ({
      ...body,
      usable: {
        ...body.usable,
        administration: { ...body.usable.administration, resourceIds: 'secret invalid array' },
      },
    }),
  ],
  [
    'invalid capability',
    (body: ReturnType<typeof recovered>) => ({
      ...body,
      usable: {
        ...body.usable,
        runtime: { ...body.usable.runtime, capabilityIds: ['INVENTED_PERMISSION'] },
      },
    }),
  ],
  [
    'invalid risk',
    (body: ReturnType<typeof recovered>) => ({
      ...body,
      grantable: {
        ...body.grantable,
        administration: { ...body.grantable.administration, riskClasses: ['invented'] },
      },
    }),
  ],
  [
    'missing boolean',
    (body: ReturnType<typeof recovered>) => ({
      ...body,
      usable: { ...body.usable, stepUpRequired: undefined },
    }),
  ],
  [
    'invalid depth',
    (body: ReturnType<typeof recovered>) => ({
      ...body,
      grantable: { ...body.grantable, onwardDelegationDepth: 33 },
    }),
  ],
  [
    'duplicate scope values',
    (body: ReturnType<typeof recovered>) => ({
      ...body,
      usable: {
        ...body.usable,
        administration: {
          ...body.usable.administration,
          participantIds: [selection.targetParticipantId, selection.targetParticipantId],
        },
      },
    }),
  ],
  [
    'wildcard resources',
    (body: ReturnType<typeof recovered>) => ({
      ...body,
      usable: {
        ...body.usable,
        administration: { ...body.usable.administration, resourceIds: ['*'] },
      },
    }),
  ],
  [
    'invalid disclosure array',
    (body: ReturnType<typeof recovered>) => ({
      ...body,
      disclosurePrivacyDomainIds: 'secret domains',
    }),
  ],
  [
    'foreign disclosure',
    (body: ReturnType<typeof recovered>) => ({
      ...body,
      disclosurePrivacyDomainIds: ['018f0000-0000-7000-8000-000000000202'],
    }),
  ],
  [
    'invalid digest',
    (body: ReturnType<typeof recovered>) => ({ ...body, semanticDigest: 'secret invalid digest' }),
  ],
  [
    'invented operation',
    (body: ReturnType<typeof recovered>) => ({
      ...body,
      creationOperationId: 'invented operation',
    }),
  ],
  ['active state', (body: ReturnType<typeof recovered>) => ({ ...body, state: 'ACTIVE' })],
  [
    'runtime permission',
    (body: ReturnType<typeof recovered>) => ({ ...body, runtimePermission: 'GRANTED' }),
  ],
  [
    'wrong selected ID',
    (body: ReturnType<typeof recovered>) => ({
      ...body,
      selection: { ...selection, envelopeId: '018f0000-0000-7000-8000-000000000799' },
    }),
  ],
  ['missing actor', (body: ReturnType<typeof recovered>) => ({ ...body, actor: undefined })],
  [
    'foreign actor',
    (body: ReturnType<typeof recovered>) => ({
      ...body,
      actor: { ...body.actor, principalId: '018f0000-0000-7000-8000-000000000112' },
    }),
  ],
  [
    'stale context',
    (body: ReturnType<typeof recovered>) => ({
      ...body,
      actor: { ...body.actor, contextEpoch: '1' },
    }),
  ],
] as const)(
  'rejects %s without scope disclosure or an invented runtime grant',
  async (_name, malformed) => {
    localStorage.setItem(storageKey, JSON.stringify(selection));
    mockReads(Response.json(malformed(recovered())));
    render(<ParticipantEnvelopeRecovery />);
    await screen.findByText(readFailure);
    expect(
      screen.queryByRole('heading', { name: /Proposal (DRAFT|SUBMITTED|APPROVED|ACTIVE)/u }),
    ).toBeNull();
    expect(screen.queryByText('Usable scope')).toBeNull();
    expect(screen.queryByText('Grantable scope')).toBeNull();
    expect(screen.queryByText(/secret|invented|INVENTED/u)).toBeNull();
    expect(JSON.parse(localStorage.getItem(storageKey)!)).toEqual(selection);
  },
);

it.each([
  'not-a-number',
  '-1',
  '1.5',
  '0001000',
  '18446744073709551616000',
  '18446744073709551615',
  '1788220800000000001',
])('rejects malformed or unbounded nanosecond time %s before rendering', async (value) => {
  localStorage.setItem(storageKey, JSON.stringify(selection));
  const body = recovered();
  mockReads(Response.json({ ...body, usable: { ...body.usable, validFromNs: value } }));
  render(<ParticipantEnvelopeRecovery />);
  await screen.findByText(readFailure);
  expect(screen.queryByText('Usable scope')).toBeNull();
  expect(screen.queryByText('Invalid Date')).toBeNull();
});

it.each(['equal', 'reversed'] as const)(
  'rejects %s lifetime endpoints before display',
  async (variant) => {
    localStorage.setItem(storageKey, JSON.stringify(selection));
    const body = recovered();
    mockReads(
      Response.json({
        ...body,
        grantable: {
          ...body.grantable,
          validUntilNs: variant === 'equal' ? body.grantable.validFromNs : '1000',
        },
      }),
    );
    render(<ParticipantEnvelopeRecovery />);
    await screen.findByText(readFailure);
    expect(screen.queryByText('Grantable scope')).toBeNull();
  },
);

it.each(['http', 'transport', 'invalid-json'] as const)(
  'redacts malicious %s diagnostics',
  async (variant) => {
    localStorage.setItem(storageKey, JSON.stringify(selection));
    mockReads(
      variant === 'http'
        ? Response.json(
            { title: 'secret owner title', code: 'SECRET-CODE', body: 'secret raw body' },
            { status: 403 },
          )
        : variant === 'transport'
          ? new Error('secret transport credentials')
          : new Response('secret malformed JSON'),
    );
    render(<ParticipantEnvelopeRecovery />);
    await screen.findByText(readFailure);
    expect(screen.queryByText(/secret|SECRET-CODE/u)).toBeNull();
    expect(screen.queryByText('Usable scope')).toBeNull();
  },
);

it.each(['logout', 'rotation', 'foreign-privacy'] as const)(
  'masks an old view when session readback reports %s',
  async (variant) => {
    localStorage.setItem(storageKey, JSON.stringify(selection));
    let sessionReads = 0;
    vi.spyOn(globalThis, 'fetch').mockImplementation((input) => {
      if (input !== '/api/v1/ui/local-session') return Promise.resolve(Response.json(recovered()));
      sessionReads++;
      return Promise.resolve(
        Response.json(
          sessionReads === 1
            ? session
            : variant === 'logout'
              ? { enabled: true, authenticated: false }
              : variant === 'rotation'
                ? { ...session, sessionId: '018f0000-0000-7000-8000-000000000712' }
                : { ...session, privacyDomainId: '018f0000-0000-7000-8000-000000000202' },
        ),
      );
    });
    render(<ParticipantEnvelopeRecovery />);
    await screen.findByText(readFailure);
    expect(screen.queryByRole('heading', { name: 'Proposal DRAFT' })).toBeNull();
    expect(localStorage.getItem(storageKey)).toBe(JSON.stringify(selection));
  },
);

it('does not fetch or expose proposal data when the current session is unauthenticated', async () => {
  localStorage.setItem(storageKey, JSON.stringify(selection));
  const fetcher = vi
    .spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(Response.json({ enabled: true, authenticated: false }));
  render(<ParticipantEnvelopeRecovery />);
  await screen.findByText(readFailure);
  expect(fetcher).toHaveBeenCalledTimes(1);
  expect(fetcher.mock.calls[0]?.[0]).toBe('/api/v1/ui/local-session');
  expect(screen.queryByText('Usable scope')).toBeNull();
});

it.each(['success', 'failure'] as const)(
  'ignores a late old %s after lookup IDs changed and newer recovery succeeded',
  async (variant) => {
    localStorage.setItem(storageKey, JSON.stringify(selection));
    const old = deferred<Response>();
    const nextSelection = { ...selection, envelopeId: '018f0000-0000-7000-8000-000000000799' };
    const fetcher = mockReads(
      old.promise,
      Response.json({ ...recovered(), selection: nextSelection, state: 'APPROVED' }),
    );
    render(<ParticipantEnvelopeRecovery />);
    await waitFor(() => expect(ownerCalls(fetcher)).toHaveLength(1));
    fireEvent.change(screen.getByLabelText('Envelope ID'), {
      target: { value: nextSelection.envelopeId },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Recover proposal' }));
    await screen.findByRole('heading', { name: 'Proposal APPROVED' });
    expect(ownerCalls(fetcher)[0]?.[1]?.signal?.aborted).toBe(true);
    await act(async () => {
      if (variant === 'success') old.resolve(Response.json(recovered()));
      else old.reject(new Error('secret obsolete lookup failure'));
    });
    expect(screen.getByRole('heading', { name: 'Proposal APPROVED' })).toBeVisible();
    expect(screen.queryByRole('heading', { name: 'Proposal DRAFT' })).toBeNull();
    expect(screen.queryByText(/secret/u)).toBeNull();
    expect(JSON.parse(localStorage.getItem(storageKey)!)).toEqual(nextSelection);
  },
);

it('ignores obsolete JSON parsing after a newer denial', async () => {
  localStorage.setItem(storageKey, JSON.stringify(selection));
  const body = deferred<unknown>();
  const old = Response.json({});
  vi.spyOn(old, 'json').mockReturnValue(body.promise);
  mockReads(old, Response.json({ title: 'secret newer denial' }, { status: 403 }));
  render(<ParticipantEnvelopeRecovery />);
  await waitFor(() => expect(old.json).toHaveBeenCalled());
  fireEvent.focus(window);
  await screen.findByText(readFailure);
  await act(async () => body.resolve(recovered()));
  expect(screen.getByText(readFailure)).toBeVisible();
  expect(screen.queryByText('Usable scope')).toBeNull();
});

it.each(['success', 'failure'] as const)(
  'aborts on unmount and ignores late %s without another session request',
  async (variant) => {
    localStorage.setItem(storageKey, JSON.stringify(selection));
    const pending = deferred<Response>();
    const fetcher = mockReads(pending.promise);
    const view = render(<ParticipantEnvelopeRecovery />);
    await waitFor(() => expect(ownerCalls(fetcher)).toHaveLength(1));
    view.unmount();
    expect(ownerCalls(fetcher)[0]?.[1]?.signal?.aborted).toBe(true);
    const count = fetcher.mock.calls.length;
    await act(async () => {
      if (variant === 'success') pending.resolve(Response.json(recovered()));
      else pending.reject(new Error('secret after unmount'));
    });
    expect(view.container).toBeEmptyDOMElement();
    expect(fetcher).toHaveBeenCalledTimes(count);
    fireEvent.focus(window);
    fireEvent(window, new Event('pageshow'));
    expect(fetcher).toHaveBeenCalledTimes(count);
  },
);
