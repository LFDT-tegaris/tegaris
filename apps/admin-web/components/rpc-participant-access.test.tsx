import { performWebAuthnStepUp } from '@openpc/ui-shell';
import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';

import { RpcParticipantAccess } from './rpc-participant-access';

vi.mock('@openpc/ui-shell', () => ({
  performWebAuthnStepUp: vi.fn().mockResolvedValue(undefined),
}));
vi.mock('next/link', () => ({
  default: ({ children, ...props }: React.ComponentProps<'a'>) => <a {...props}>{children}</a>,
}));

const id = (suffix: number) => `018f0000-0000-7000-8000-${String(suffix).padStart(12, '0')}`;
const digest = `sha256:${'a'.repeat(64)}`;
const actor = {
  sessionId: id(701),
  principalId: id(111),
  participantId: id(101),
  privacyDomainId: id(201),
  contextMode: 'PARTICIPANT' as const,
  contextEpoch: '2',
  role: 'operator' as const,
};
const workload = (suffix: number) => `urn:openpc:workload:${id(suffix)}`;
const policy = (suffix: number) => `urn:openpc:policy-set:${id(suffix)}`;
const moduleIds = [
  'pc.config.assets',
  'pc.evidence',
  'pc.fact-bridge',
  'pc.foundation.kernel',
  'pc.identity',
  'pc.module.framework',
  'pc.multi-rpc',
  'pc.participant.governance',
  'pc.policy.argument-guard',
  'pc.policy.compiler-distributor',
  'pc.policy.contract-method',
  'pc.policy.invocation-capability',
  'pc.policy.lifecycle',
  'pc.policy.rpc-surface',
  'pc.policy.runtime-guard',
  'pc.policy.state-read',
  'pc.runtime',
  'pc.transaction.delivery',
];
function catalogue(suffix = 301) {
  return {
    actor,
    workloads: [
      {
        effect: {
          principalId: id(suffix),
          displayLabel: `Workload ${suffix}`,
          kind: 'WORKLOAD',
          state: 'ACTIVE',
        },
      },
    ],
    roles: [
      {
        effect: {
          id: id(501),
          roleId: `urn:openpc:role:${id(501)}`,
          displayName: 'RPC Read/Write Caller',
          state: 'ACTIVE',
        },
      },
    ],
    envelopes: [
      {
        effect: {
          id: id(601),
          state: 'ACTIVE',
          capabilityIds: ['CALL_RESULT_DISCLOSURE'],
          resourceIds: [id(602)],
          semanticDigest: digest,
          validFrom: '2020-01-01T00:00:00.000Z',
          validUntil: '2035-01-01T00:00:00.000Z',
        },
        operationId: id(603),
      },
    ],
    modules: {
      moduleBindings: moduleIds.map((moduleId) => ({
        moduleId,
        semanticVersion: '1.0.0',
        manifestDigest: digest,
        configurationDigest: digest,
        installationId: id(801),
        revision: '1',
      })),
      simulationAuthorities: [],
      simulationWorkloads: [{ principalId: id(suffix), workloadId: workload(suffix) }],
      authorizedEmpty: false,
    },
    policySets: [{ policySetId: policy(suffix), name: `Policy ${suffix}` }],
  };
}
function preview(suffix = 301) {
  return {
    authoritative: false,
    workloadId: workload(suffix),
    credentialCurrent: true,
    policyGenerationId: id(901),
    policyGeneration: '4',
    policyVersionId: id(902),
    methods: [
      {
        method: 'eth_call',
        capabilityId: 'CALL_RESULT_DISCLOSURE',
        truthState: 'SUCCESS',
        reasons: [],
        assignments: [],
      },
    ],
  };
}
const stepUp = {
  actionIntentId: 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
  actionIntentDigest: digest,
  resourceId: actor.participantId,
  resourceDigest: digest,
};
function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((yes, no) => {
    resolve = yes;
    reject = no;
  });
  return { promise, resolve, reject };
}
function policyOperation(
  actionIntentId: string,
  idempotencyKey: string,
  resourceRef: string,
  state: string,
) {
  return {
    operationId: id(998),
    actionIntentId,
    idempotencyKey,
    resourceRef,
    state,
    intentDigest: digest,
    revision: '1',
    truthState: 'SUCCESS',
    createdAt: '2026-10-04T00:00:00.000000Z',
    updatedAt: '2026-10-04T00:00:00.000000Z',
  };
}
function versionResponse(options?: RequestInit) {
  return policyOperation(
    'ACT-POLICY_VERSIONS_CREATE_RESOURCE-V1',
    String((options?.headers as Record<string, string>)?.['Idempotency-Key']),
    `urn:openpc:policy-version:${id(999)}`,
    'ACCEPTED',
  );
}
function setResponse(options?: RequestInit) {
  const body = JSON.parse(String(options?.body)) as { requestKey: string };
  return {
    operation: policyOperation(
      'ACT-POLICY_SETS_CREATE_RESOURCE-V1',
      `policy-set-${body.requestKey}`,
      `urn:openpc:policy-set:${id(999)}`,
      'SUCCEEDED',
    ),
  };
}
let currentSession: Record<string, unknown> = { ...actor };
let sessionRequests = vi.fn<typeof globalThis.fetch>();
function mockRequests() {
  const requests = vi.fn<typeof globalThis.fetch>();
  sessionRequests = vi.fn<typeof globalThis.fetch>(async () =>
    Response.json({ enabled: true, authenticated: true, ...currentSession }),
  );
  vi.spyOn(globalThis, 'fetch').mockImplementation((input, options) =>
    String(input) === '/api/v1/ui/local-session'
      ? sessionRequests(input, options)
      : requests(input, options),
  );
  return requests;
}
beforeEach(() => {
  vi.mocked(performWebAuthnStepUp).mockReset().mockResolvedValue(undefined);
  currentSession = { ...actor };
});

afterEach(() => {
  cleanup();
  vi.useRealTimers();
  vi.restoreAllMocks();
  vi.clearAllMocks();
});

it('uses producer URNs and module bindings and preserves the policy command', async () => {
  const fetch = mockRequests()
    .mockResolvedValueOnce(Response.json(catalogue()))
    .mockResolvedValueOnce(
      Response.json({
        actionIntentDigest: digest,
        csrfToken: 'csrf',
        path: '/api/v1/ui/process-domains/policy-author-compose-simulate/actions/create-version',
      }),
    )
    .mockImplementationOnce(async (_, options) => Response.json(versionResponse(options)));
  render(<RpcParticipantAccess />);
  const user = userEvent.setup();
  expect(await screen.findByRole('heading', { name: 'RPC access by workload' })).toBeVisible();
  expect(screen.getByRole('combobox', { name: 'Workload' })).toHaveValue(workload(301));
  expect(screen.getByText('Enabled module bindings: 18/18.')).toBeVisible();
  await user.type(screen.getByRole('textbox', { name: 'Read contract-method policy ID' }), id(701));
  await user.type(
    screen.getByRole('textbox', { name: 'Write contract-method policy ID' }),
    id(702),
  );
  await user.click(screen.getByRole('button', { name: 'Create immutable RPC policy version' }));
  expect(await screen.findByText(/Created version:/u)).toHaveTextContent(id(999));
  expect(fetch.mock.calls[2]?.[0]).toBe(
    '/api/v1/ui/process-domains/policy-author-compose-simulate/actions/create-version',
  );
  const request = fetch.mock.calls[2]?.[1];
  expect(request?.method).toBe('POST');
  expect(request?.headers).toMatchObject({
    'OpenPC-Action-Intent-Digest': digest,
    'X-CSRF-Token': 'csrf',
  });
  expect(JSON.parse(String(request?.body))).toMatchObject({
    policySetId: policy(301),
    semanticVersion: '1.0.0',
    semanticDocument: {
      participantId: actor.participantId,
      privacyDomainId: actor.privacyDomainId,
      rpcPolicies: [
        {
          rules: [
            { method: 'eth_call', effect: 'ALLOW', requiredRoles: [`urn:openpc:role:${id(501)}`] },
            {
              method: 'eth_sendRawTransaction',
              effect: 'ALLOW',
              requiredRoles: [`urn:openpc:role:${id(501)}`],
            },
          ],
        },
      ],
    },
  });
});

it.each([
  ['eth_call', 'eth_sendRawTransaction', 'Read', 'Write', 701],
  ['eth_sendRawTransaction', 'eth_call', 'Write', 'Read', 702],
] as const)(
  'creates a %s policy without fields for the unselected method',
  async (method, other, selected, omitted, reference) => {
    const requests = mockRequests()
      .mockResolvedValueOnce(Response.json(catalogue()))
      .mockImplementationOnce(async () => rpcVersionBootstrap())
      .mockImplementationOnce(async (_, options) => Response.json(versionResponse(options)));
    render(<RpcParticipantAccess />);
    const user = userEvent.setup();
    await screen.findByRole('heading', { name: 'RPC access by workload' });
    await user.click(screen.getByRole('checkbox', { name: other }));
    expect(screen.getByLabelText(`${omitted} contract-method policy ID`)).toBeDisabled();
    expect(screen.getByLabelText(`${omitted} contract-method policy ID`)).not.toBeRequired();
    expect(screen.getByLabelText(`${omitted} contract-method policy ID`)).not.toBeVisible();
    await user.type(
      screen.getByRole('textbox', { name: `${selected} contract-method policy ID` }),
      id(reference),
    );
    const action = screen.getByRole('button', { name: 'Create immutable RPC policy version' });
    expect(action.closest('form')!.checkValidity()).toBe(true);
    await user.click(action);
    await screen.findByText(/Created version:/u);
    const body = JSON.parse(String(requests.mock.calls[2]?.[1]?.body));
    expect(
      body.semanticDocument.rpcPolicies[0].rules.map((rule: { method: string }) => rule.method),
    ).toEqual(['eth_call', 'eth_sendRawTransaction']);
    expect(
      body.semanticDocument.rpcPolicies[0].rules.find(
        (rule: { method: string }) => rule.method === method,
      ),
    ).toMatchObject({ requiredRoles: [`urn:openpc:role:${id(501)}`] });
    expect(body.semanticDocument.contractPolicies).toEqual([
      { contractMethodPolicyId: id(reference), revision: '1' },
    ]);
  },
);

it('rejects an empty method selection before any version request', async () => {
  const requests = mockRequests().mockResolvedValueOnce(Response.json(catalogue()));
  render(<RpcParticipantAccess />);
  const user = userEvent.setup();
  await screen.findByRole('heading', { name: 'RPC access by workload' });
  await user.click(screen.getByRole('checkbox', { name: 'eth_call' }));
  await user.click(screen.getByRole('checkbox', { name: 'eth_sendRawTransaction' }));
  const action = screen.getByRole('button', { name: 'Create immutable RPC policy version' });
  expect(action).toBeDisabled();
  fireEvent.submit(action.closest('form')!);
  await screen.findByText('Choose at least one RPC method.');
  expect(requests.mock.calls.filter(([, options]) => options?.method === 'POST')).toHaveLength(0);
  expect(requests).toHaveBeenCalledTimes(1);
});

it('uses distinct RPC roles while including only the selected read contract', async () => {
  const initial = catalogue();
  initial.roles[0]!.effect.displayName = 'Creditor';
  initial.roles.push({
    effect: {
      ...initial.roles[0]!.effect,
      id: id(502),
      roleId: `urn:openpc:role:${id(502)}`,
      displayName: 'Debtor',
    },
  });
  const requests = mockRequests()
    .mockResolvedValueOnce(Response.json(initial))
    .mockImplementationOnce(async () => rpcVersionBootstrap())
    .mockImplementationOnce(async (_, options) => Response.json(versionResponse(options)));
  render(<RpcParticipantAccess />);
  const user = userEvent.setup();
  await screen.findByRole('heading', { name: 'RPC access by workload' });
  expect(screen.getByRole('combobox', { name: 'Read RPC role' })).toHaveValue('');
  expect(screen.getByRole('combobox', { name: 'Write RPC role' })).toHaveValue('');
  await user.selectOptions(
    screen.getByRole('combobox', { name: 'Read RPC role' }),
    `urn:openpc:role:${id(501)}`,
  );
  await user.selectOptions(
    screen.getByRole('combobox', { name: 'Write RPC role' }),
    `urn:openpc:role:${id(502)}`,
  );
  await user.click(screen.getByRole('checkbox', { name: 'eth_sendRawTransaction' }));
  await user.type(screen.getByRole('textbox', { name: 'Read contract-method policy ID' }), id(701));
  await user.click(screen.getByRole('button', { name: 'Create immutable RPC policy version' }));
  await screen.findByText(/Created version:/u);
  const body = JSON.parse(String(requests.mock.calls[2]?.[1]?.body));
  expect(body.semanticDocument.rpcPolicies[0].rules).toEqual([
    { method: 'eth_call', effect: 'ALLOW', requiredRoles: [`urn:openpc:role:${id(501)}`] },
    {
      method: 'eth_sendRawTransaction',
      effect: 'ALLOW',
      requiredRoles: [`urn:openpc:role:${id(502)}`],
    },
  ]);
  expect(body.semanticDocument.contractPolicies).toEqual([
    { contractMethodPolicyId: id(701), revision: '1' },
  ]);
});

it('requires explicit RPC role choices when several roles are available', async () => {
  const initial = catalogue();
  initial.roles.push({
    effect: {
      ...initial.roles[0]!.effect,
      id: id(502),
      roleId: `urn:openpc:role:${id(502)}`,
      displayName: 'Another role',
    },
  });
  const requests = mockRequests().mockResolvedValueOnce(Response.json(initial));
  render(<RpcParticipantAccess />);
  const user = userEvent.setup();
  await screen.findByRole('heading', { name: 'RPC access by workload' });
  await user.type(screen.getByRole('textbox', { name: 'Read contract-method policy ID' }), id(701));
  await user.type(
    screen.getByRole('textbox', { name: 'Write contract-method policy ID' }),
    id(702),
  );
  const action = screen.getByRole('button', { name: 'Create immutable RPC policy version' });
  expect(action.closest('form')!.checkValidity()).toBe(false);
  fireEvent.submit(action.closest('form')!);
  await screen.findByText('Choose a role for RPC reads and writes.');
  expect(requests.mock.calls.filter(([, options]) => options?.method === 'POST')).toHaveLength(0);
});

it('prepares an assignment for an explicitly selected catalogue role', async () => {
  const initial = catalogue();
  initial.roles[0]!.effect.displayName = 'Example Creditor';
  mockRequests().mockResolvedValueOnce(Response.json(initial));
  render(<RpcParticipantAccess />);
  const user = userEvent.setup();
  await screen.findByRole('heading', { name: 'RPC access by workload' });
  expect(screen.queryByRole('link', { name: 'Assign RPC role' })).toBeNull();
  await user.selectOptions(
    screen.getByRole('combobox', { name: 'Role to assign' }),
    `urn:openpc:role:${id(501)}`,
  );
  const link = screen.getByRole('link', { name: 'Assign RPC role' });
  const params = new URL(link.getAttribute('href')!, 'https://demo.example.org').searchParams;
  expect(params.get('principalId')).toBe(id(301));
  expect(params.get('roleId')).toBe(`urn:openpc:role:${id(501)}`);
  expect(params.get('authorityEnvelopeId')).toBe(id(601));
  expect(params.get('capabilityIds')).toBe('CALL_RESULT_DISCLOSURE');
  expect(params.get('resourceIds')).toBe(id(602));
});

it.each([
  ['Expired', '2020-01-01T00:00:00.000Z', '2021-01-01T00:00:00.000Z'],
  ['Scheduled', '2034-01-01T00:00:00.000Z', '2035-01-01T00:00:00.000Z'],
])(
  'does not offer an assignment through a %s RPC envelope',
  async (status, validFrom, validUntil) => {
    const initial = catalogue();
    Object.assign(initial.envelopes[0]!.effect, { validFrom, validUntil });
    const requests = mockRequests().mockResolvedValueOnce(Response.json(initial));
    render(<RpcParticipantAccess />);
    await screen.findByRole('heading', { name: 'RPC access by workload' });
    await userEvent
      .setup()
      .selectOptions(
        screen.getByRole('combobox', { name: 'Role to assign' }),
        initial.roles[0]!.effect.roleId,
      );
    expect(screen.getByText(status, { exact: true })).toBeVisible();
    expect(screen.queryByRole('link', { name: 'Assign RPC role' })).toBeNull();
    expect(
      screen.getByText(
        'An active, unexpired read envelope is required before assigning this role.',
      ),
    ).toBeVisible();
    expect(requests.mock.calls.filter(([, options]) => options?.method === 'POST')).toHaveLength(0);
  },
);

it('selects a live read envelope while retaining an expired envelope in history', async () => {
  const initial = catalogue();
  const live = structuredClone(initial.envelopes[0]!);
  live.effect.id = id(604);
  initial.envelopes[0]!.effect.validUntil = '2021-01-01T00:00:00.000Z';
  initial.envelopes.push(live);
  mockRequests().mockResolvedValueOnce(Response.json(initial));
  render(<RpcParticipantAccess />);
  await screen.findByRole('heading', { name: 'RPC access by workload' });
  await userEvent
    .setup()
    .selectOptions(
      screen.getByRole('combobox', { name: 'Role to assign' }),
      initial.roles[0]!.effect.roleId,
    );
  const link = screen.getByRole('link', { name: 'Assign RPC role' });
  expect(
    new URL(link.getAttribute('href')!, 'https://demo.example.org').searchParams.get(
      'authorityEnvelopeId',
    ),
  ).toBe(id(604));
  expect(screen.getByText('Expired', { exact: true })).toBeVisible();
  expect(screen.getByText(id(601), { exact: true })).toBeVisible();
});

it('removes the assignment shortcut when the envelope expires without a refresh', async () => {
  vi.useFakeTimers();
  vi.setSystemTime(new Date('2030-01-01T00:00:00.000Z'));
  const initial = catalogue();
  initial.envelopes[0]!.effect.validUntil = '2030-01-01T00:00:01.000Z';
  mockRequests().mockResolvedValueOnce(Response.json(initial));
  await act(async () => {
    render(<RpcParticipantAccess />);
  });
  fireEvent.change(screen.getByRole('combobox', { name: 'Role to assign' }), {
    target: { value: initial.roles[0]!.effect.roleId },
  });
  expect(screen.getByRole('link', { name: 'Assign RPC role' })).toBeVisible();
  await act(async () => {
    await vi.advanceTimersByTimeAsync(1001);
  });
  expect(screen.queryByRole('link', { name: 'Assign RPC role' })).toBeNull();
  expect(screen.getByText('Expired', { exact: true })).toBeVisible();
});

it('rejects an RPC envelope whose validity window is missing', async () => {
  const initial = catalogue();
  const effect = { ...initial.envelopes[0]!.effect } as Partial<
    (typeof initial.envelopes)[number]['effect']
  >;
  delete effect.validUntil;
  mockRequests().mockResolvedValueOnce(
    Response.json({ ...initial, envelopes: [{ ...initial.envelopes[0], effect }] }),
  );
  render(<RpcParticipantAccess />);
  await screen.findByText('Participant RPC access is unavailable. Refresh to try again.');
  expect(screen.queryByRole('combobox', { name: 'Role to assign' })).toBeNull();
});

it('reads the exact selection and masks the preview when a selector changes', async () => {
  const initial = catalogue();
  initial.policySets.push({ policySetId: policy(302), name: 'Policy 302' });
  const fetch = mockRequests()
    .mockResolvedValueOnce(Response.json(initial))
    .mockResolvedValueOnce(Response.json({ ...initial, preview: preview() }));
  render(<RpcParticipantAccess />);
  const user = userEvent.setup();
  await user.click(await screen.findByRole('button', { name: 'Read current RPC access' }));
  expect(await screen.findByRole('table')).toHaveTextContent('SUCCESS');
  const query = new URL(String(fetch.mock.calls[1]?.[0]), 'https://example.test').searchParams;
  expect(query.get('workloadId')).toBe(workload(301));
  expect(query.get('policySetId')).toBe(policy(301));
  await user.selectOptions(
    screen.getAllByRole('combobox', { name: 'Policy set' })[0]!,
    policy(302),
  );
  expect(screen.queryByRole('table')).toBeNull();
});

it.each(['success', 'failure'] as const)(
  'keeps a newer read when the old read finishes with %s',
  async (outcome) => {
    const old = deferred<Response>();
    const fetch = mockRequests()
      .mockReturnValueOnce(old.promise)
      .mockResolvedValueOnce(Response.json(catalogue(302)));
    render(<RpcParticipantAccess />);
    const user = userEvent.setup();
    await waitFor(() => expect(fetch).toHaveBeenCalledTimes(1));
    await user.click(screen.getByRole('button', { name: 'Refresh Participant RPC access' }));
    expect(await screen.findByRole('combobox', { name: 'Workload' })).toHaveValue(workload(302));
    expect(fetch.mock.calls[0]?.[1]?.signal?.aborted).toBe(true);
    await act(async () => {
      if (outcome === 'success') old.resolve(Response.json(catalogue()));
      else old.reject(new Error('secret stale transport diagnostic'));
    });
    expect(screen.getByRole('combobox', { name: 'Workload' })).toHaveValue(workload(302));
    expect(screen.getByRole('status')).toHaveTextContent('Participant RPC configuration loaded.');
    expect(screen.queryByText(/secret stale/u)).toBeNull();
  },
);

it('recovers from a failed refresh using only newly returned selections', async () => {
  const pending = deferred<Response>();
  mockRequests()
    .mockResolvedValueOnce(Response.json(catalogue()))
    .mockReturnValueOnce(pending.promise)
    .mockResolvedValueOnce(Response.json(catalogue(302)));
  render(<RpcParticipantAccess />);
  const user = userEvent.setup();
  await screen.findByRole('combobox', { name: 'Workload' });
  await user.click(screen.getByRole('button', { name: 'Refresh Participant RPC access' }));
  await act(async () => pending.reject(new Error('private transport details')));
  expect(screen.queryByRole('combobox')).toBeNull();
  await user.click(screen.getByRole('button', { name: 'Refresh Participant RPC access' }));
  expect(await screen.findByRole('combobox', { name: 'Workload' })).toHaveValue(workload(302));
  expect(screen.getAllByRole('combobox', { name: 'Policy set' })[0]).toHaveValue(policy(302));
});

it.each(['http', 'transport', 'invalid-json'] as const)(
  'removes previous data and redacts a %s failure',
  async (kind) => {
    const pending = deferred<Response>();
    mockRequests()
      .mockResolvedValueOnce(Response.json(catalogue()))
      .mockReturnValueOnce(pending.promise);
    render(<RpcParticipantAccess />);
    await screen.findByRole('combobox', { name: 'Workload' });
    await userEvent
      .setup()
      .click(screen.getByRole('button', { name: 'Refresh Participant RPC access' }));
    expect(screen.queryByRole('combobox', { name: 'Workload' })).toBeNull();
    expect(screen.queryByRole('link', { name: 'Assign RPC role' })).toBeNull();
    await act(async () => {
      if (kind === 'transport') pending.reject(new Error('secret transport token'));
      else if (kind === 'http')
        pending.resolve(
          Response.json({ title: 'secret title', code: 'SECRET-CODE' }, { status: 403 }),
        );
      else pending.resolve(new Response('secret malformed body', { status: 200 }));
    });
    expect(screen.getByRole('status')).toHaveTextContent(
      'Participant RPC access is unavailable. Refresh to try again.',
    );
    expect(screen.queryByText(/secret|SECRET-CODE/u)).toBeNull();
    expect(
      screen.queryByRole('button', { name: 'Create immutable RPC policy version' }),
    ).toBeNull();
  },
);

it.each(['removed', 'changed-actor', 'empty', 'step-up'] as const)(
  'revalidates selectors after %s readback',
  async (variant) => {
    const next = catalogue(302);
    if (variant === 'changed-actor')
      next.actor = { ...actor, contextEpoch: '3', participantId: id(102) };
    if (variant === 'empty' || variant === 'step-up') {
      next.modules.simulationWorkloads = [];
      next.modules.authorizedEmpty = true;
      next.policySets = [];
    }
    mockRequests()
      .mockResolvedValueOnce(Response.json(catalogue()))
      .mockResolvedValueOnce(
        Response.json({ ...next, ...(variant === 'step-up' ? { requiresStepUp: stepUp } : {}) }),
      );
    render(<RpcParticipantAccess />);
    await screen.findByRole('combobox', { name: 'Workload' });
    if (variant === 'changed-actor') currentSession = { ...next.actor };
    await userEvent
      .setup()
      .click(screen.getByRole('button', { name: 'Refresh Participant RPC access' }));
    if (variant === 'step-up') {
      expect(
        await screen.findByRole('button', {
          name: 'Verify Participant authenticator and load RPC access',
        }),
      ).toBeVisible();
      expect(screen.queryByRole('combobox', { name: 'Workload' })).toBeNull();
    } else {
      const selector = await screen.findByRole('combobox', { name: 'Workload' });
      const policySelector = screen.getAllByRole('combobox', { name: 'Policy set' })[0]!;
      if (variant === 'empty') {
        for (const empty of [selector, policySelector]) {
          expect(empty).toHaveProperty('value', '');
          expect(empty.querySelectorAll('option')).toHaveLength(0);
        }
      } else {
        expect(selector).toHaveValue(workload(302));
        expect(policySelector).toHaveValue(policy(302));
      }
      expect(within(selector).queryByRole('option', { name: 'Workload 301' })).toBeNull();
      if (variant === 'empty')
        expect(screen.getByRole('button', { name: 'Read current RPC access' })).toBeDisabled();
    }
  },
);

it('keeps the exact WebAuthn step-up binding and loads fresh configuration', async () => {
  const { performWebAuthnStepUp } = await import('@openpc/ui-shell');
  mockRequests()
    .mockResolvedValueOnce(Response.json({ ...catalogue(), requiresStepUp: stepUp }))
    .mockResolvedValueOnce(Response.json(catalogue()));
  render(<RpcParticipantAccess />);
  await userEvent.setup().click(
    await screen.findByRole('button', {
      name: 'Verify Participant authenticator and load RPC access',
    }),
  );
  expect(await screen.findByRole('combobox', { name: 'Workload' })).toHaveValue(workload(301));
  expect(performWebAuthnStepUp).toHaveBeenCalledWith(
    { ...stepUp, stepUp: 'FRESH_WEBAUTHN_MAX_5M' },
    { resourceId: stepUp.resourceId, resourceDigest: stepUp.resourceDigest },
    expect.objectContaining({ signal: expect.any(AbortSignal), isCurrent: expect.any(Function) }),
  );
});

it.each([
  ['missing actor', (value: ReturnType<typeof catalogue>) => ({ ...value, actor: undefined })],
  [
    'wrong context',
    (value: ReturnType<typeof catalogue>) => ({
      ...value,
      actor: { ...actor, contextMode: 'PLATFORM' },
    }),
  ],
  [
    'invalid modules',
    (value: ReturnType<typeof catalogue>) => ({
      ...value,
      modules: { ...value.modules, simulationWorkloads: [{}] },
    }),
  ],
  [
    'invalid roles',
    (value: ReturnType<typeof catalogue>) => ({
      ...value,
      roles: [{ effect: { id: 'invented' } }],
    }),
  ],
  [
    'invalid envelopes',
    (value: ReturnType<typeof catalogue>) => ({
      ...value,
      envelopes: [{ effect: {}, operationId: null }],
    }),
  ],
  [
    'invalid policy set',
    (value: ReturnType<typeof catalogue>) => ({
      ...value,
      policySets: [{ policySetId: id(301), name: 'invalid identifier' }],
    }),
  ],
  [
    'invented preview',
    (value: ReturnType<typeof catalogue>) => ({
      ...value,
      preview: { ...preview(), authoritative: true },
    }),
  ],
] as const)('rejects %s without inventing actionable data', async (_name, malformed) => {
  mockRequests().mockResolvedValue(Response.json(malformed(catalogue())));
  render(<RpcParticipantAccess />);
  await waitFor(() =>
    expect(screen.getByRole('status')).toHaveTextContent('Participant RPC access is unavailable.'),
  );
  expect(screen.queryByRole('combobox')).toBeNull();
});

it('rejects a preview for a different workload instead of relabelling it', async () => {
  mockRequests()
    .mockResolvedValueOnce(Response.json(catalogue()))
    .mockResolvedValueOnce(Response.json({ ...catalogue(), preview: preview(302) }));
  render(<RpcParticipantAccess />);
  await userEvent
    .setup()
    .click(await screen.findByRole('button', { name: 'Read current RPC access' }));
  await waitFor(() =>
    expect(screen.getByRole('status')).toHaveTextContent('Participant RPC access is unavailable.'),
  );
  expect(screen.queryByRole('table')).toBeNull();
});

it('drops a formerly valid preview when the response removes its selection', async () => {
  mockRequests()
    .mockResolvedValueOnce(Response.json(catalogue()))
    .mockResolvedValueOnce(Response.json({ ...catalogue(302), preview: preview() }));
  render(<RpcParticipantAccess />);
  await userEvent
    .setup()
    .click(await screen.findByRole('button', { name: 'Read current RPC access' }));
  expect(await screen.findByRole('combobox', { name: 'Workload' })).toHaveValue(workload(302));
  expect(screen.queryByRole('table')).toBeNull();
});

it('does not carry a prior actor selection even when it appears in the new actor catalogue', async () => {
  const initial = catalogue();
  initial.modules.simulationWorkloads.push({ principalId: id(302), workloadId: workload(302) });
  initial.policySets.push({ policySetId: policy(302), name: 'Policy 302' });
  mockRequests()
    .mockResolvedValueOnce(Response.json(initial))
    .mockResolvedValueOnce(Response.json({ ...initial, actor: { ...actor, sessionId: id(702) } }));
  render(<RpcParticipantAccess />);
  const user = userEvent.setup();
  await user.selectOptions(
    await screen.findByRole('combobox', { name: 'Workload' }),
    workload(302),
  );
  await user.selectOptions(
    screen.getAllByRole('combobox', { name: 'Policy set' })[0]!,
    policy(302),
  );
  await user.selectOptions(
    screen.getByRole('combobox', { name: 'Role to assign' }),
    `urn:openpc:role:${id(501)}`,
  );
  await user.click(screen.getByRole('checkbox', { name: 'eth_sendRawTransaction' }));
  currentSession = { ...actor, sessionId: id(702) };
  await user.click(screen.getByRole('button', { name: 'Refresh Participant RPC access' }));
  expect(await screen.findByRole('combobox', { name: 'Workload' })).toHaveValue(workload(301));
  expect(screen.getAllByRole('combobox', { name: 'Policy set' })[0]).toHaveValue(policy(301));
  expect(screen.getByRole('combobox', { name: 'Role to assign' })).toHaveValue('');
  expect(screen.queryByRole('link', { name: 'Assign RPC role' })).toBeNull();
  expect(screen.getByRole('checkbox', { name: 'eth_call' })).toBeChecked();
  expect(screen.getByRole('checkbox', { name: 'eth_sendRawTransaction' })).toBeChecked();
});

it('ignores an obsolete JSON continuation after a newer read', async () => {
  const body = deferred<unknown>();
  const old = Response.json({});
  vi.spyOn(old, 'json').mockReturnValue(body.promise);
  mockRequests()
    .mockResolvedValueOnce(old)
    .mockResolvedValueOnce(Response.json(catalogue(302)));
  render(<RpcParticipantAccess />);
  await waitFor(() => expect(old.json).toHaveBeenCalled());
  await userEvent
    .setup()
    .click(screen.getByRole('button', { name: 'Refresh Participant RPC access' }));
  expect(await screen.findByRole('combobox', { name: 'Workload' })).toHaveValue(workload(302));
  await act(async () => body.resolve({ actor: 'secret malformed old body' }));
  expect(screen.getByRole('status')).toHaveTextContent('Participant RPC configuration loaded.');
  expect(screen.getByRole('combobox', { name: 'Workload' })).toHaveValue(workload(302));
});

it.each(['success', 'failure'] as const)(
  'aborts on unmount and ignores later %s',
  async (outcome) => {
    const pending = deferred<Response>();
    const fetch = mockRequests().mockReturnValueOnce(pending.promise);
    const view = render(<RpcParticipantAccess />);
    await waitFor(() => expect(fetch).toHaveBeenCalledTimes(1));
    view.unmount();
    expect(fetch.mock.calls[0]?.[1]?.signal?.aborted).toBe(true);
    await act(async () => {
      if (outcome === 'success') pending.resolve(Response.json(catalogue()));
      else pending.reject(new Error('secret after unmount'));
    });
    expect(view.container).toBeEmptyDOMElement();
  },
);

it('redacts command errors while retaining the current configuration', async () => {
  mockRequests()
    .mockResolvedValueOnce(Response.json(catalogue()))
    .mockResolvedValueOnce(
      Response.json({ title: 'secret mutation title', code: 'SECRET-CODE' }, { status: 403 }),
    );
  render(<RpcParticipantAccess />);
  await userEvent.setup().click(await screen.findByRole('button', { name: 'Create policy set' }));
  await waitFor(() =>
    expect(screen.getByRole('status')).toHaveTextContent('The request was not completed.'),
  );
  expect(screen.queryByText(/secret|SECRET-CODE/u)).toBeNull();
  expect(screen.getByRole('combobox', { name: 'Workload' })).toHaveValue(workload(301));
});

it.each(['fetch', 'body', 'error'] as const)(
  'checks the actual session after a delayed RPC %s without a second component load',
  async (continuation) => {
    const pending = deferred<Response>();
    const body = deferred<unknown>();
    const response = Response.json({});
    vi.spyOn(response, 'json').mockReturnValue(body.promise);
    const requests = mockRequests().mockReturnValueOnce(
      continuation === 'body' ? Promise.resolve(response) : pending.promise,
    );
    render(<RpcParticipantAccess />);
    await waitFor(() => expect(requests).toHaveBeenCalledTimes(1));
    if (continuation === 'body') await waitFor(() => expect(response.json).toHaveBeenCalled());
    currentSession = { enabled: true, authenticated: false };
    await act(async () => {
      if (continuation === 'body') body.resolve(catalogue());
      else if (continuation === 'fetch') pending.resolve(Response.json(catalogue()));
      else pending.reject(new Error('private stale error'));
    });
    await waitFor(() =>
      expect(screen.getByRole('status')).toHaveTextContent(
        'Participant RPC access is unavailable.',
      ),
    );
    expect(sessionRequests).toHaveBeenCalledTimes(2);
    expect(requests).toHaveBeenCalledTimes(1);
    expect(screen.queryByRole('combobox')).toBeNull();
    expect(screen.queryByRole('button', { name: 'Create policy set' })).toBeNull();
    expect(screen.queryByText(/private stale/u)).toBeNull();
    expect(sessionRequests.mock.calls[0]?.[1]).toMatchObject({
      cache: 'no-store',
      credentials: 'same-origin',
    });
  },
);

it.each([
  { sessionId: id(702) },
  { principalId: id(112) },
  { participantId: id(102) },
  { privacyDomainId: id(202) },
  { contextEpoch: '3' },
  { contextMode: 'PLATFORM' },
  { role: 'viewer' },
  { enabled: false },
])('does not display an old catalogue after session binding changes to %s', async (change) => {
  const pending = deferred<Response>();
  const requests = mockRequests().mockReturnValueOnce(pending.promise);
  render(<RpcParticipantAccess />);
  await waitFor(() => expect(requests).toHaveBeenCalledTimes(1));
  currentSession = { ...actor, ...change };
  await act(async () => pending.resolve(Response.json(catalogue())));
  await waitFor(() =>
    expect(screen.getByRole('status')).toHaveTextContent('Participant RPC access is unavailable.'),
  );
  expect(screen.queryByRole('combobox')).toBeNull();
  expect(requests).toHaveBeenCalledTimes(1);
});

it.each([
  { sessionId: id(702) },
  { principalId: id(112) },
  { participantId: id(102) },
  { privacyDomainId: id(202) },
  { contextEpoch: '3' },
  { role: 'viewer' as const },
])(
  'rejects a catalogue actor that differs from the stable actual session by %s',
  async (change) => {
    mockRequests().mockResolvedValueOnce(
      Response.json({ ...catalogue(), actor: { ...actor, ...change } }),
    );
    render(<RpcParticipantAccess />);
    await waitFor(() =>
      expect(screen.getByRole('status')).toHaveTextContent(
        'Participant RPC access is unavailable.',
      ),
    );
    expect(sessionRequests).toHaveBeenCalledTimes(2);
    expect(screen.queryByRole('combobox')).toBeNull();
  },
);

it.each([{ enabled: false }, { authenticated: false }, { contextMode: 'PLATFORM' }])(
  'does not start the RPC read without a current Participant session (%s)',
  async (change) => {
    currentSession = { ...actor, ...change };
    const requests = mockRequests();
    render(<RpcParticipantAccess />);
    await waitFor(() =>
      expect(screen.getByRole('status')).toHaveTextContent(
        'Participant RPC access is unavailable.',
      ),
    );
    expect(requests).not.toHaveBeenCalled();
    expect(sessionRequests).toHaveBeenCalledTimes(1);
  },
);

it('does not restore a late policy version result after the initiating policy selection changes', async () => {
  const initial = catalogue();
  initial.policySets.push({ policySetId: policy(302), name: 'Policy 302' });
  const pending = deferred<Response>();
  const requests = mockRequests()
    .mockResolvedValueOnce(Response.json(initial))
    .mockResolvedValueOnce(
      Response.json({
        actionIntentDigest: digest,
        csrfToken: 'csrf',
        path: '/api/v1/ui/process-domains/policy-author-compose-simulate/actions/create-version',
      }),
    )
    .mockReturnValueOnce(pending.promise);
  render(<RpcParticipantAccess />);
  const user = userEvent.setup();
  await user.type(
    await screen.findByRole('textbox', { name: 'Read contract-method policy ID' }),
    id(701),
  );
  await user.type(
    screen.getByRole('textbox', { name: 'Write contract-method policy ID' }),
    id(702),
  );
  await user.click(screen.getByRole('button', { name: 'Create immutable RPC policy version' }));
  await waitFor(() => expect(requests).toHaveBeenCalledTimes(3));
  const originalRequest = String(requests.mock.calls[2]?.[1]?.body);
  await user.selectOptions(
    screen.getAllByRole('combobox', { name: 'Policy set' })[0]!,
    policy(302),
  );
  await act(async () =>
    pending.resolve(Response.json(versionResponse(requests.mock.calls[2]?.[1]))),
  );
  await waitFor(() =>
    expect(
      screen.getByRole('button', { name: 'Create immutable RPC policy version' }),
    ).toBeEnabled(),
  );
  expect(screen.queryByText(/Created version:/u)).toBeNull();
  expect(screen.getByRole('status')).not.toHaveTextContent('was accepted');
  expect(screen.getAllByRole('combobox', { name: 'Policy set' })[0]).toHaveValue(policy(302));
  expect(String(requests.mock.calls[2]?.[1]?.body)).toBe(originalRequest);
  expect(JSON.parse(originalRequest)).toMatchObject({ policySetId: policy(301) });
  expect(requests).toHaveBeenCalledTimes(3);
});

it.each(['success', 'failure'] as const)(
  'does not refresh or restore a late policy-set %s after a same-actor selector edit',
  async (outcome) => {
    const initial = catalogue();
    initial.modules.simulationWorkloads.push({ principalId: id(302), workloadId: workload(302) });
    const pending = deferred<Response>();
    const requests = mockRequests()
      .mockResolvedValueOnce(Response.json(initial))
      .mockReturnValueOnce(pending.promise);
    render(<RpcParticipantAccess />);
    const user = userEvent.setup();
    await user.click(await screen.findByRole('button', { name: 'Create policy set' }));
    await waitFor(() => expect(requests).toHaveBeenCalledTimes(2));
    await user.selectOptions(screen.getByRole('combobox', { name: 'Workload' }), workload(302));
    await act(async () => {
      if (outcome === 'success')
        pending.resolve(Response.json(setResponse(requests.mock.calls[1]?.[1])));
      else pending.reject(new Error('private stale command error'));
    });
    await waitFor(() =>
      expect(screen.getByRole('button', { name: 'Create policy set' })).toBeEnabled(),
    );
    expect(screen.getByRole('combobox', { name: 'Workload' })).toHaveValue(workload(302));
    expect(screen.getByRole('status')).toHaveTextContent('Participant RPC configuration loaded.');
    expect(requests).toHaveBeenCalledTimes(2);
  },
);

it('retains a current policy-set completion and its session-checked refresh', async () => {
  const requests = mockRequests()
    .mockResolvedValueOnce(Response.json(catalogue()))
    .mockImplementationOnce(async (_, options) => Response.json(setResponse(options)))
    .mockResolvedValueOnce(Response.json(catalogue()));
  render(<RpcParticipantAccess />);
  await userEvent.setup().click(await screen.findByRole('button', { name: 'Create policy set' }));
  expect(await screen.findByText('The RPC policy set was created.')).toBeVisible();
  expect(requests).toHaveBeenCalledTimes(3);
  expect(sessionRequests).toHaveBeenCalledTimes(5);
});

it.each(['missing', 'wrong-action', 'failed', 'wrong-key', 'non-json'] as const)(
  'does not refresh or claim policy-set success for %s response',
  async (variant) => {
    const requests = mockRequests()
      .mockResolvedValueOnce(Response.json(catalogue()))
      .mockImplementationOnce(async (_, options) => {
        const next = setResponse(options);
        if (variant === 'missing') return Response.json({});
        if (variant === 'non-json') return new Response('SECRET-MUTATION-BODY', { status: 201 });
        if (variant === 'wrong-action')
          next.operation.actionIntentId = 'ACT-POLICY_VERSIONS_CREATE_RESOURCE-V1';
        if (variant === 'failed') next.operation.state = 'FAILED';
        if (variant === 'wrong-key') next.operation.idempotencyKey = 'policy-set-unrelated';
        return Response.json(next);
      });
    render(<RpcParticipantAccess />);
    await userEvent.setup().click(await screen.findByRole('button', { name: 'Create policy set' }));
    await waitFor(() =>
      expect(screen.getByRole('status')).toHaveTextContent('The request was not completed.'),
    );
    expect(requests).toHaveBeenCalledTimes(2);
    expect(sessionRequests).toHaveBeenCalledTimes(3);
    expect(screen.queryByText(/SECRET-MUTATION-BODY|The RPC policy set was created/u)).toBeNull();
  },
);

it.each(['missing', 'wrong-ref', 'wrong-digest', 'wrong-key', 'wrong-state', 'non-json'] as const)(
  'does not display a created policy version for %s response',
  async (variant) => {
    const requests = mockRequests()
      .mockResolvedValueOnce(Response.json(catalogue()))
      .mockResolvedValueOnce(
        Response.json({
          actionIntentDigest: digest,
          csrfToken: 'csrf',
          path: '/api/v1/ui/process-domains/policy-author-compose-simulate/actions/create-version',
        }),
      )
      .mockImplementationOnce(async (_, options) => {
        const next = versionResponse(options);
        if (variant === 'missing') return Response.json({ resourceRef: next.resourceRef });
        if (variant === 'non-json') return new Response('SECRET-MUTATION-BODY', { status: 202 });
        if (variant === 'wrong-ref') next.resourceRef = `urn:openpc:resource:${id(999)}`;
        if (variant === 'wrong-digest') next.intentDigest = `sha256:${'b'.repeat(64)}`;
        if (variant === 'wrong-key') next.idempotencyKey = 'policy-create-version-unrelated';
        if (variant === 'wrong-state') next.state = 'SUCCEEDED';
        return Response.json(next);
      });
    render(<RpcParticipantAccess />);
    const user = userEvent.setup();
    await user.type(
      await screen.findByRole('textbox', { name: 'Read contract-method policy ID' }),
      id(701),
    );
    await user.type(
      screen.getByRole('textbox', { name: 'Write contract-method policy ID' }),
      id(702),
    );
    await user.click(screen.getByRole('button', { name: 'Create immutable RPC policy version' }));
    await waitFor(() =>
      expect(screen.getByRole('status')).toHaveTextContent('The request was not completed.'),
    );
    expect(requests).toHaveBeenCalledTimes(3);
    expect(screen.queryByText(/Created version:|SECRET-MUTATION-BODY/u)).toBeNull();
  },
);

it.each([
  {},
  {
    actionIntentDigest: digest,
    csrfToken: '',
    path: '/api/v1/ui/process-domains/policy-author-compose-simulate/actions/create-version',
  },
  { actionIntentDigest: digest, csrfToken: 'csrf', path: 'https://unrelated.example/mutation' },
])('rejects malformed policy bootstrap before forwarding a mutation (%j)', async (bootstrap) => {
  const requests = mockRequests()
    .mockResolvedValueOnce(Response.json(catalogue()))
    .mockResolvedValueOnce(Response.json(bootstrap));
  render(<RpcParticipantAccess />);
  const user = userEvent.setup();
  await user.type(
    await screen.findByRole('textbox', { name: 'Read contract-method policy ID' }),
    id(701),
  );
  await user.type(
    screen.getByRole('textbox', { name: 'Write contract-method policy ID' }),
    id(702),
  );
  await user.click(screen.getByRole('button', { name: 'Create immutable RPC policy version' }));
  await waitFor(() =>
    expect(screen.getByRole('status')).toHaveTextContent('The request was not completed.'),
  );
  expect(requests).toHaveBeenCalledTimes(2);
  expect(requests.mock.calls.every(([, options]) => options?.method !== 'POST')).toBe(true);
});

it('takes the Participant proof reservation synchronously and forwards the original helper binding', async () => {
  const held = deferred<void>();
  vi.mocked(performWebAuthnStepUp).mockReturnValueOnce(held.promise);
  const requests = mockRequests().mockImplementation(async () =>
    Response.json({ ...catalogue(), requiresStepUp: stepUp }),
  );
  render(<RpcParticipantAccess />);
  const button = await screen.findByRole('button', {
    name: 'Verify Participant authenticator and load RPC access',
  });
  act(() => {
    button.click();
    button.click();
  });
  expect(performWebAuthnStepUp).toHaveBeenCalledTimes(1);
  const [action, binding, lifecycle] = vi.mocked(performWebAuthnStepUp).mock.calls[0]!;
  expect(action).toEqual({ ...stepUp, stepUp: 'FRESH_WEBAUTHN_MAX_5M' });
  expect(binding).toEqual({ resourceId: stepUp.resourceId, resourceDigest: stepUp.resourceDigest });
  expect(lifecycle?.signal?.aborted).toBe(false);
  expect(lifecycle?.isCurrent?.()).toBe(true);
  await act(async () => held.resolve());
  await waitFor(() => expect(requests).toHaveBeenCalledTimes(2));
  expect(sessionRequests).toHaveBeenCalledTimes(5);
});

it.each([
  { sessionId: id(702) },
  { principalId: id(112) },
  { participantId: id(102) },
  { privacyDomainId: id(202) },
  { contextEpoch: '3' },
  { role: 'viewer' },
  { contextMode: 'PLATFORM' },
  { authenticated: false },
])(
  'does not refresh private Participant context after a held proof and actual session drift %s',
  async (change) => {
    const held = deferred<void>();
    vi.mocked(performWebAuthnStepUp).mockReturnValueOnce(held.promise);
    const requests = mockRequests().mockImplementation(async () =>
      Response.json({ ...catalogue(), requiresStepUp: stepUp }),
    );
    render(<RpcParticipantAccess />);
    await userEvent.setup().click(
      await screen.findByRole('button', {
        name: 'Verify Participant authenticator and load RPC access',
      }),
    );
    currentSession = { ...actor, ...change };
    await act(async () => held.resolve());
    await waitFor(() =>
      expect(screen.getByRole('status')).toHaveTextContent(
        'Participant RPC access is unavailable.',
      ),
    );
    expect(requests).toHaveBeenCalledTimes(1);
    expect(requests.mock.calls.filter(([, options]) => options?.method === 'POST')).toHaveLength(0);
    expect(screen.queryByRole('combobox')).toBeNull();
    expect(screen.queryByText('Workload 301')).toBeNull();
  },
);

it('retires the held Participant helper on unmount even if the mock resolves afterwards', async () => {
  const held = deferred<void>();
  vi.mocked(performWebAuthnStepUp).mockReturnValueOnce(held.promise);
  const requests = mockRequests().mockImplementation(async () =>
    Response.json({ ...catalogue(), requiresStepUp: stepUp }),
  );
  const view = render(<RpcParticipantAccess />);
  await userEvent.setup().click(
    await screen.findByRole('button', {
      name: 'Verify Participant authenticator and load RPC access',
    }),
  );
  const lifecycle = vi.mocked(performWebAuthnStepUp).mock.calls[0]![2]!;
  view.unmount();
  expect(lifecycle.signal?.aborted).toBe(true);
  expect(lifecycle.isCurrent?.()).toBe(false);
  await act(async () => held.resolve());
  expect(requests).toHaveBeenCalledTimes(1);
  expect(sessionRequests).toHaveBeenCalledTimes(2);
});

async function fillRpcVersionForm() {
  const user = userEvent.setup();
  await screen.findByRole('combobox', { name: 'Read RPC role' });
  await user.selectOptions(
    screen.getByRole('combobox', { name: 'Read RPC role' }),
    `urn:openpc:role:${id(501)}`,
  );
  await user.selectOptions(
    screen.getByRole('combobox', { name: 'Write RPC role' }),
    `urn:openpc:role:${id(501)}`,
  );
  await user.type(
    await screen.findByRole('textbox', { name: 'Read contract-method policy ID' }),
    id(701),
  );
  await user.type(
    screen.getByRole('textbox', { name: 'Write contract-method policy ID' }),
    id(702),
  );
  return user;
}
const rpcVersionBootstrap = () =>
  Response.json({
    actionIntentDigest: digest,
    csrfToken: 'csrf',
    path: '/api/v1/ui/process-domains/policy-author-compose-simulate/actions/create-version',
  });

it.each(['bootstrap', 'session qualification'] as const)(
  'does not publish a retired Participant preparation failure after an uncontrolled edit at %s',
  async (phase) => {
    const held = deferred<Response>();
    const requests = mockRequests().mockImplementation(async () => Response.json(catalogue()));
    render(<RpcParticipantAccess />);
    const user = await fillRpcVersionForm();
    const status = screen.getByRole('status').textContent;
    if (phase === 'bootstrap') requests.mockReturnValueOnce(held.promise);
    else sessionRequests.mockReturnValueOnce(held.promise);
    await user.click(
      screen.getByRole('button', {
        name: phase === 'bootstrap' ? 'Create immutable RPC policy version' : 'Create policy set',
      }),
    );
    if (phase === 'bootstrap') await waitFor(() => expect(requests).toHaveBeenCalledTimes(2));
    else await waitFor(() => expect(sessionRequests).toHaveBeenCalledTimes(3));
    await user.type(screen.getByRole('textbox', { name: 'Name' }), ' changed locally');
    await act(async () => held.reject(new Error('PRIVATE-RETIRED-PREPARATION')));
    await waitFor(() =>
      expect(screen.getByRole('button', { name: 'Create policy set' })).toBeEnabled(),
    );
    expect(screen.getByRole('status').textContent).toBe(status);
    expect(
      screen.queryByText(/PRIVATE-RETIRED|request was not completed|Created version:/u),
    ).toBeNull();
    expect(requests.mock.calls.filter(([, options]) => options?.method === 'POST')).toHaveLength(0);
    expect(sessionRequests).toHaveBeenCalledTimes(phase === 'bootstrap' ? 2 : 3);
  },
);

it.each(['Read RPC role', 'Read policy revision', 'eth_call'] as const)(
  'fences the captured RPC policy version before POST after a held bootstrap and %s edit',
  async (label) => {
    const initial = catalogue();
    initial.roles.push({
      effect: {
        id: id(502),
        roleId: `urn:openpc:role:${id(502)}`,
        displayName: 'Other role',
        state: 'ACTIVE',
      },
    });
    const held = deferred<Response>();
    const requests = mockRequests()
      .mockImplementationOnce(async () => Response.json(initial))
      .mockReturnValueOnce(held.promise);
    render(<RpcParticipantAccess />);
    const user = await fillRpcVersionForm();
    await user.click(screen.getByRole('button', { name: 'Create immutable RPC policy version' }));
    await waitFor(() => expect(requests).toHaveBeenCalledTimes(2));
    if (label === 'Read RPC role')
      await user.selectOptions(
        screen.getByRole('combobox', { name: 'Read RPC role' }),
        `urn:openpc:role:${id(502)}`,
      );
    else if (label === 'eth_call')
      await user.click(screen.getByRole('checkbox', { name: 'eth_call' }));
    else await user.type(screen.getByRole('textbox', { name: label }), '2');
    expect(requests.mock.calls[1]?.[1]?.signal?.aborted).toBe(true);
    await act(async () => held.resolve(rpcVersionBootstrap()));
    await waitFor(() =>
      expect(
        screen.getByRole('button', { name: 'Create immutable RPC policy version' }),
      ).toBeEnabled(),
    );
    expect(requests).toHaveBeenCalledTimes(2);
    expect(requests.mock.calls.filter(([, options]) => options?.method === 'POST')).toHaveLength(0);
    expect(screen.queryByText(/Created version:/u)).toBeNull();
  },
);

it('captures one complete original policy-set body under same-turn form submission', async () => {
  const held = deferred<Response>();
  const requests = mockRequests()
    .mockImplementationOnce(async () => Response.json(catalogue()))
    .mockReturnValueOnce(held.promise)
    .mockImplementationOnce(async () => Response.json(catalogue()));
  render(<RpcParticipantAccess />);
  const button = await screen.findByRole('button', { name: 'Create policy set' });
  const form = button.closest('form')!;
  act(() => {
    expect(fireEvent.submit(form)).toBe(false);
    expect(fireEvent.submit(form)).toBe(false);
  });
  await waitFor(() => expect(requests).toHaveBeenCalledTimes(2));
  const original = JSON.parse(String(requests.mock.calls[1]?.[1]?.body));
  expect(original).toEqual({
    requestKey: expect.stringMatching(/^[0-9a-f-]{36}$/u),
    name: 'RPC access policy',
    reason: 'Create a policy set for governed RPC access.',
  });
  expect(requests.mock.calls.filter(([, options]) => options?.method === 'POST')).toHaveLength(1);
  await act(async () => held.resolve(Response.json(setResponse(requests.mock.calls[1]?.[1]))));
  expect(await screen.findByText('The RPC policy set was created.')).toBeVisible();
  expect(String(requests.mock.calls[1]?.[1]?.body)).toBe(JSON.stringify(original));
  expect(requests.mock.calls.filter(([, options]) => options?.method === 'POST')).toHaveLength(1);
});

it.each(['lost', 'malformed success'] as const)(
  'preserves a %s original policy version intent and prevents a newly keyed business replay',
  async (failure) => {
    const held = deferred<Response>();
    const requests = mockRequests()
      .mockImplementationOnce(async () => Response.json(catalogue()))
      .mockImplementationOnce(async () => rpcVersionBootstrap())
      .mockReturnValueOnce(held.promise);
    render(<RpcParticipantAccess />);
    const user = await fillRpcVersionForm();
    await user.click(screen.getByRole('button', { name: 'Create immutable RPC policy version' }));
    await waitFor(() => expect(requests).toHaveBeenCalledTimes(3));
    const request = requests.mock.calls[2]![1]!;
    const originalBody = String(request.body);
    const originalKey = (request.headers as Record<string, string>)['Idempotency-Key'];
    await act(async () => {
      if (failure === 'lost') held.reject(new Error('PRIVATE-OWNER-CREDENTIAL-ERROR'));
      else held.resolve(Response.json({ detail: 'PRIVATE-OWNER-CREDENTIAL-ERROR' }));
    });
    await waitFor(() =>
      expect(screen.getByRole('status')).toHaveTextContent(
        'original RPC policy request requires authoritative readback',
      ),
    );
    await user.click(screen.getByRole('button', { name: 'Create immutable RPC policy version' }));
    expect(requests).toHaveBeenCalledTimes(3);
    expect(requests.mock.calls.filter(([, options]) => options?.method === 'POST')).toHaveLength(1);
    expect(String(request.body)).toBe(originalBody);
    expect((request.headers as Record<string, string>)['Idempotency-Key']).toBe(originalKey);
    expect(JSON.parse(originalBody)).toMatchObject({
      policySetId: policy(301),
      semanticVersion: '1.0.0',
    });
    expect(screen.queryByText(/PRIVATE-OWNER/u)).toBeNull();
    expect(screen.queryByText(/Created version:/u)).toBeNull();
  },
);
