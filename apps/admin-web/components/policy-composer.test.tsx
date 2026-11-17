import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';

import type { AuthorizedAction } from '@openpc/ui-shell';

import { PolicyComposer } from './policy-composer';
import {
  clearPolicyWorkflowStorage,
  policyAuthorStorageKey,
  transactionWorkflowPrivacyEvent,
} from './policy-workflow-storage';
import { notifySessionTransition } from './session-transition';

beforeEach(() => localStorage.clear());
afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

const createAction: AuthorizedAction = {
  actionIntentId: 'ACT-POLICY_VERSIONS_CREATE_RESOURCE-V1',
  actionIntentDigest: 'sha256:0698f0799814d66949037c7f205545b7ef81419ddf2ac5e5ccc0c15af509e5bb',
  operationId: 'createPolicyVersion',
  method: 'POST',
  path: '/api/v1/ui/process-domains/policy-author-compose-simulate/actions/create-version',
  riskClass: 'STANDARD',
  stepUp: 'NONE',
  idempotency: 'KEY_UNTIL_TERMINAL',
  etagRequired: false,
};
const simulateAction: AuthorizedAction = {
  actionIntentId: 'ACT-POLICY_CREATE_SIMULATION-V1',
  actionIntentDigest: 'sha256:4ffd4eb52cb455fc9f5cfb78f10c0c601da101b3ad37a8c9ae30a7242da743fd',
  operationId: 'simulatePolicyVersion',
  method: 'POST',
  path: '/api/v1/ui/process-domains/policy-author-compose-simulate/actions/simulate',
  riskClass: 'STANDARD',
  stepUp: 'NONE',
  idempotency: 'KEY_UNTIL_TERMINAL',
  etagRequired: false,
};

const session = {
  authenticated: true,
  role: 'operator',
  contextMode: 'PARTICIPANT',
  contextEpoch: '2',
  sessionId: '018f0000-0000-7000-8000-000000000117',
  principalId: '018f0000-0000-7000-8000-000000000111',
  participantId: '018f0000-0000-7000-8000-000000000101',
  privacyDomainId: '018f0000-0000-7000-8000-000000000201',
};
const policySet = {
  policySetId: 'urn:openpc:policy-set:018f0000-0000-7000-8000-000000000920',
  participantId: `urn:openpc:participant:${session.participantId}`,
  name: 'Current policy',
  state: 'DRAFT',
  activeVersionDigest: null,
  revision: '1',
  createdAt: '2026-09-22T00:00:00.000000Z',
  updatedAt: '2026-09-22T00:00:00.000000Z',
};
const page = (items: (typeof policySet)[] = [policySet]) => ({
  items,
  nextCursor: null,
  total: String(items.length),
  completeness: 'COMPLETE',
  authorizedEmpty: items.length === 0,
  snapshotRevision: '1',
});
const bootstrap = (action: AuthorizedAction) =>
  Response.json({
    actionIntentDigest: action.actionIntentDigest,
    csrfToken: 'a'.repeat(43),
    path: action.path,
  });
const versionId = '018f0000-0000-7000-8000-000000000921';
const receipt = (key: string) => ({
  operationId: '018f0000-0000-7000-8000-000000000922',
  actionIntentId: createAction.actionIntentId,
  intentDigest: createAction.actionIntentDigest,
  idempotencyKey: key,
  resourceRef: `urn:openpc:policy-version:${versionId}`,
  revision: '1',
  state: 'ACCEPTED',
  truthState: 'SUCCESS',
  createdAt: '2026-09-22T00:00:00.000000Z',
  updatedAt: '2026-09-22T00:00:00.000000Z',
});
const simulationAuthority = {
  assignmentId: '018f0000-0000-7000-8000-000000000932',
  envelopeId: '018f0000-0000-7000-8000-000000000933',
  principalId: '018f0000-0000-7000-8000-000000000934',
  roleId: '018f0000-0000-7000-8000-000000000935',
  workloadId: 'urn:openpc:workload:018f0000-0000-7000-8000-000000000936',
};
const props = {
  actions: [createAction, simulateAction],
  authorityContextKey: 'current-context',
  participantRef: `urn:openpc:participant:${session.participantId}`,
};
function defaultRead(url: string): Response {
  if (url === '/api/v1/ui/local-session') return Response.json(session);
  if (url.startsWith('/api/v1/ui/rpc-access-workbench'))
    return Response.json({
      actor: session,
      modules: {
        simulationAuthorities: [simulationAuthority],
        simulationWorkloads: [
          {
            principalId: simulationAuthority.principalId,
            workloadId: simulationAuthority.workloadId,
          },
        ],
      },
      workloads: [
        {
          effect: {
            principalId: simulationAuthority.principalId,
            displayLabel: 'Current workload',
          },
        },
      ],
    });
  if (url.startsWith('/api/v1/ui/policy-versions?')) {
    const query = new URL(url, 'http://localhost').searchParams;
    const actor = Object.fromEntries(
      ['sessionId', 'principalId', 'participantId', 'privacyDomainId', 'contextEpoch'].map(
        (field) => [field, session[field as keyof typeof session]],
      ),
    );
    const version = {
      policyVersionId: query.get('policyVersionId') ?? `urn:openpc:policy-version:${versionId}`,
      policySetId: query.get('policySetId'),
      semanticVersion: '3.0.0',
      normalizedPolicyDigest: `sha256:${'a1'.repeat(32)}`,
      dependencyClosureDigest: `sha256:${'b2'.repeat(32)}`,
      state: 'DRAFT',
      revision: '1',
      createdAt: policySet.createdAt,
      updatedAt: policySet.updatedAt,
    };
    return Response.json(
      query.has('policyVersionId')
        ? { actor, version }
        : {
            actor,
            policySetId: version.policySetId,
            items: [version],
            nextCursor: null,
            total: '1',
            authorizedEmpty: false,
            completeness: 'COMPLETE',
            snapshotRevision: '1',
          },
    );
  }
  if (url === '/api/v1/ui/policy-sets') return Response.json(page());
  if (url.startsWith('/api/v1/ui/policy-sets?policySetId=')) return Response.json(policySet);
  if (url.includes('policy-session'))
    return bootstrap(url.includes('create-version') ? createAction : simulateAction);
  throw new Error(`Unexpected test read: ${url}`);
}
async function prepareCreate() {
  const user = userEvent.setup();
  await screen.findByRole('option', { name: 'Current policy · DRAFT' });
  await user.selectOptions(
    screen.getByLabelText('Policy set for this version'),
    policySet.policySetId,
  );
  fireEvent.change(screen.getByLabelText('Semantic version'), { target: { value: '3.0.0' } });
  await user.selectOptions(screen.getByLabelText('Policy source'), 'ADMITTED');
  expect(screen.getByRole('group', { name: 'Artifact references' })).toBeVisible();
  expect(screen.getByLabelText('Normalized policy digest')).toBeVisible();
  expect(screen.getByLabelText('Dependency closure digest')).toBeVisible();
  fireEvent.change(screen.getByLabelText('Normalized policy digest'), {
    target: { value: `sha256:${'a1'.repeat(32)}` },
  });
  fireEvent.change(screen.getByLabelText('Dependency closure digest'), {
    target: { value: `sha256:${'b2'.repeat(32)}` },
  });
  return user;
}

type SimulationKind = 'CONTRACT' | 'VISIBILITY' | 'SOURCE';
const simulationInputs = (kind: SimulationKind): [string, string][] =>
  kind === 'CONTRACT'
    ? [
        ['Contract method policy ID', '018f0000-0000-7000-8000-000000000951'],
        ['Encoded call data', '0x70a08231' + '1'.repeat(64)],
      ]
    : kind === 'VISIBILITY'
      ? [
          ['Visibility policy ID', '018f0000-0000-7000-8000-000000000951'],
          ['Purpose', 'PRIVATE_AUDIT_PURPOSE'],
          ['Fields (comma-separated; empty for whole receipts)', 'privateCustomerReference'],
        ]
      : [
          ['Indexer profile ID', '018f0000-0000-7000-8000-000000000941'],
          ['Projection plan ID', '018f0000-0000-7000-8000-000000000942'],
          ['First block', '10'],
          ['Last block', '10'],
          ['Maximum response bytes', '10000'],
        ];

async function openSimulationInputs(
  user: ReturnType<typeof userEvent.setup>,
  kind: SimulationKind,
) {
  await screen.findByRole('option', { name: 'Current policy · DRAFT' });
  await user.selectOptions(
    screen.getByLabelText('Policy set for this version'),
    policySet.policySetId,
  );
  await user.click(await screen.findByRole('button', { name: /Review version 3[.]0[.]0/ }));
  await screen.findByText('Version 3.0.0 selected');
  await user.selectOptions(screen.getByLabelText('Policy family'), kind);
}

async function simulationRead(input: unknown, actor = session) {
  const url = String(input);
  if (url === '/api/v1/ui/local-session') return Response.json(actor);
  const response = defaultRead(url);
  if (url.startsWith('/api/v1/ui/policy-versions?')) {
    const body = await response.json();
    return Response.json({
      ...body,
      actor: Object.fromEntries(
        ['sessionId', 'principalId', 'participantId', 'privacyDomainId', 'contextEpoch'].map(
          (field) => [field, actor[field as keyof typeof actor]],
        ),
      ),
    });
  }
  return response;
}

const simulationKinds: SimulationKind[] = ['CONTRACT', 'VISIBILITY', 'SOURCE'];
it.each(simulationKinds)(
  'conceals %s inputs until the exact native workspace is revalidated',
  async (kind) => {
    let held = false;
    let resume!: (response: Response) => void;
    const read = new Promise<Response>((resolve) => {
      resume = resolve;
    });
    const fetchMock = vi
      .spyOn(globalThis, 'fetch')
      .mockImplementation(async (input) =>
        held && String(input) === '/api/v1/ui/local-session' ? read : simulationRead(input),
      );
    const user = userEvent.setup();
    render(<PolicyComposer {...props} view="simulation" />);
    await openSimulationInputs(user, kind);
    for (const [label, value] of simulationInputs(kind))
      fireEvent.change(screen.getByLabelText(label), { target: { value } });
    held = true;
    fireEvent(window, new Event('blur'));
    fireEvent(window, new Event('focus'));
    for (const [label] of simulationInputs(kind))
      expect(screen.queryByLabelText(label)).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Run simulation' })).toBeDisabled();
    await act(async () => resume(Response.json(session)));
    for (const [label, value] of simulationInputs(kind))
      await waitFor(() => expect(screen.getByLabelText(label)).toHaveValue(value));
    expect(fetchMock.mock.calls.some(([url]) => url === simulateAction.path)).toBe(false);
  },
);

const actorChanges = ['sessionId', 'principalId', 'privacyDomainId', 'contextEpoch'] as const;
it.each(simulationKinds.flatMap((kind) => actorChanges.map((field) => ({ kind, field }))))(
  'does not transfer $kind draft inputs after a native $field change',
  async ({ kind, field }) => {
    let current = session;
    const fetchMock = vi
      .spyOn(globalThis, 'fetch')
      .mockImplementation((input) => simulationRead(input, current));
    const user = userEvent.setup();
    render(<PolicyComposer {...props} view="simulation" />);
    await openSimulationInputs(user, kind);
    for (const [label, value] of simulationInputs(kind))
      fireEvent.change(screen.getByLabelText(label), { target: { value } });
    current = {
      ...session,
      [field]: field === 'contextEpoch' ? '3' : '018f0000-0000-7000-8000-000000000199',
    };
    fireEvent(window, new Event('blur'));
    fireEvent(window, new Event('focus'));
    await openSimulationInputs(user, kind);
    for (const [label, value] of simulationInputs(kind))
      expect(screen.getByLabelText(label)).not.toHaveValue(value);
    expect(fetchMock.mock.calls.some(([url]) => url === simulateAction.path)).toBe(false);
  },
);

it.each(simulationKinds)('discards %s inputs on explicit privacy cleanup', async (kind) => {
  const fetchMock = vi
    .spyOn(globalThis, 'fetch')
    .mockImplementation((input) => simulationRead(input));
  const user = userEvent.setup();
  render(<PolicyComposer {...props} view="simulation" />);
  await openSimulationInputs(user, kind);
  for (const [label, value] of simulationInputs(kind))
    fireEvent.change(screen.getByLabelText(label), { target: { value } });
  act(() => {
    clearPolicyWorkflowStorage();
    window.dispatchEvent(new Event(transactionWorkflowPrivacyEvent));
  });
  await openSimulationInputs(user, kind);
  for (const [label, value] of simulationInputs(kind))
    expect(screen.getByLabelText(label)).not.toHaveValue(value);
  expect(fetchMock.mock.calls.some(([url]) => url === simulateAction.path)).toBe(false);
});

it.each(['blur', 'privacy', 'context', 'input'] as const)(
  'does not dispatch a simulation whose bootstrap is held across %s invalidation',
  async (change) => {
    let release!: (response: Response) => void;
    const held = new Promise<Response>((resolve) => {
      release = resolve;
    });
    const fetchMock = vi
      .spyOn(globalThis, 'fetch')
      .mockImplementation((input) =>
        String(input).startsWith('/api/v1/ui/policy-session') ? held : simulationRead(input),
      );
    const user = userEvent.setup();
    const view = render(<PolicyComposer {...props} view="simulation" />);
    await openSimulationInputs(user, 'SOURCE');
    for (const [label, value] of simulationInputs('SOURCE'))
      fireEvent.change(screen.getByLabelText(label), { target: { value } });
    await user.click(screen.getByRole('button', { name: 'Run simulation' }));
    await waitFor(() =>
      expect(
        fetchMock.mock.calls.some(([url]) => String(url).startsWith('/api/v1/ui/policy-session')),
      ).toBe(true),
    );
    if (change === 'blur') fireEvent(window, new Event('blur'));
    else if (change === 'privacy')
      act(() => {
        clearPolicyWorkflowStorage();
        window.dispatchEvent(new Event(transactionWorkflowPrivacyEvent));
      });
    else if (change === 'context')
      view.rerender(
        <PolicyComposer {...props} authorityContextKey="other-workspace" view="simulation" />,
      );
    else fireEvent.change(screen.getByLabelText('First block'), { target: { value: '12' } });
    await act(async () => release(bootstrap(simulateAction)));
    expect(fetchMock.mock.calls.some(([url]) => url === simulateAction.path)).toBe(false);
    expect(screen.queryByRole('region', { name: 'Simulation result' })).not.toBeInTheDocument();
  },
);

it.each(['foreign', 'unavailable', 'network', 'malformed'] as const)(
  'requires a fresh native session before dispatch and conceals inputs after %s verification',
  async (failure) => {
    let verifying = false;
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      const url = String(input);
      if (url.startsWith('/api/v1/ui/policy-session')) {
        verifying = true;
        return bootstrap(simulateAction);
      }
      if (verifying && url === '/api/v1/ui/local-session') {
        if (failure === 'network') throw new Error('Session transport unavailable');
        if (failure === 'unavailable') return new Response(null, { status: 503 });
        if (failure === 'malformed') return new Response('{', { status: 200 });
        return Response.json({ ...session, principalId: '018f0000-0000-7000-8000-000000000199' });
      }
      return simulationRead(input);
    });
    const user = userEvent.setup();
    render(<PolicyComposer {...props} view="simulation" />);
    await openSimulationInputs(user, 'SOURCE');
    for (const [label, value] of simulationInputs('SOURCE'))
      fireEvent.change(screen.getByLabelText(label), { target: { value } });
    await user.click(screen.getByRole('button', { name: 'Run simulation' }));
    await waitFor(() =>
      expect(screen.queryByLabelText('Indexer profile ID')).not.toBeInTheDocument(),
    );
    expect(fetchMock.mock.calls.some(([url]) => url === simulateAction.path)).toBe(false);
    expect(screen.queryByRole('region', { name: 'Simulation result' })).not.toBeInTheDocument();
  },
);

it('reveals contract simulation inputs only after an owner-verified version and clears them on blur', async () => {
  const fetchMock = vi
    .spyOn(globalThis, 'fetch')
    .mockImplementation(async (input) => defaultRead(String(input)));
  const user = userEvent.setup();
  render(<PolicyComposer {...props} view="simulation" />);
  await screen.findByRole('option', { name: 'Current policy · DRAFT' });
  await user.selectOptions(
    screen.getByLabelText('Policy set for this version'),
    policySet.policySetId,
  );
  await screen.findByRole('button', { name: /Review version 3[.]0[.]0/ });
  expect(screen.queryByRole('textbox', { name: 'Encoded call data' })).not.toBeInTheDocument();
  expect(
    screen.queryByRole('textbox', { name: 'Contract method policy ID' }),
  ).not.toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Run simulation' })).toBeDisabled();
  await user.click(screen.getByRole('button', { name: /Review version 3[.]0[.]0/ }));
  await screen.findByText('Version 3.0.0 selected');
  expect(screen.getByRole('textbox', { name: 'Encoded call data' })).toBeVisible();
  expect(screen.getByRole('textbox', { name: 'Contract method policy ID' })).toBeVisible();
  fireEvent(window, new Event('blur'));
  await waitFor(() =>
    expect(screen.queryByRole('textbox', { name: 'Encoded call data' })).not.toBeInTheDocument(),
  );
  expect(screen.getByRole('button', { name: 'Run simulation' })).toBeDisabled();
  expect(fetchMock.mock.calls.some(([url]) => String(url) === simulateAction.path)).toBe(false);
});

it('restores an imported document and reconciles the exact original body and key after response loss', async () => {
  const document = {
    schemaVersion: '1.0.0',
    participantId: session.participantId,
    privacyDomainId: session.privacyDomainId,
    moduleBindings: [],
    rpcPolicies: [],
    contractPolicies: [],
    requiredFacts: [],
  };
  const text = JSON.stringify(document, null, 2),
    sends: RequestInit[] = [];
  vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
    if (String(input) === createAction.path) {
      sends.push(init!);
      if (sends.length === 1) throw Error('response lost');
      return Response.json(
        receipt(String((init!.headers as Record<string, string>)['Idempotency-Key'])),
        { status: 202 },
      );
    }
    return defaultRead(String(input));
  });
  const user = userEvent.setup(),
    view = render(<PolicyComposer {...props} view="author" />);
  await screen.findByRole('option', { name: 'Current policy · DRAFT' });
  await user.selectOptions(
    screen.getByLabelText('Policy set for this version'),
    policySet.policySetId,
  );
  expect(screen.getByLabelText('Semantic version')).toHaveValue('');
  await user.type(screen.getByLabelText('Semantic version'), '3.0.0');
  await user.upload(
    screen.getByLabelText('Policy file'),
    new File([text], 'rules.json', { type: 'application/json' }),
  );
  await screen.findByRole('region', { name: 'Policy draft review' });
  await user.click(screen.getByRole('button', { name: 'Create immutable version' }));
  await screen.findByText(/original version result is unknown/);
  view.unmount();
  render(<PolicyComposer {...props} view="author" />);
  await waitFor(() =>
    expect(screen.getByRole('button', { name: 'Reconcile original version' })).toBeEnabled(),
  );
  expect(screen.getByLabelText('Typed policy document (JSON)')).toHaveValue(text);
  await user.click(screen.getByRole('button', { name: 'Reconcile original version' }));
  await screen.findByText('Immutable version 3.0.0 was accepted. It is not active.');
  expect(sends).toHaveLength(2);
  expect(sends[1]!.body).toBe(sends[0]!.body);
  expect(JSON.parse(String(sends[0]!.body)).semanticDocument).toEqual(document);
  expect((sends[1]!.headers as Record<string, string>)['Idempotency-Key']).toBe(
    (sends[0]!.headers as Record<string, string>)['Idempotency-Key'],
  );
});

it('does not mint a new request or send a foreign policy document through programmatic form submission', async () => {
  const fetchMock = vi
      .spyOn(globalThis, 'fetch')
      .mockImplementation(async (input) => defaultRead(String(input))),
    user = userEvent.setup();
  render(<PolicyComposer {...props} view="author" />);
  await screen.findByRole('option', { name: 'Current policy · DRAFT' });
  await user.selectOptions(
    screen.getByLabelText('Policy set for this version'),
    policySet.policySetId,
  );
  await user.type(screen.getByLabelText('Semantic version'), '1.0.0');
  await user.click(screen.getByText('Edit policy JSON', { selector: 'summary' }));
  fireEvent.change(screen.getByLabelText('Typed policy document (JSON)'), {
    target: {
      value: JSON.stringify({
        schemaVersion: '1.0.0',
        participantId: session.participantId,
        privacyDomainId: 'foreign',
        moduleBindings: [],
        rpcPolicies: [],
        contractPolicies: [],
        requiredFacts: [],
      }),
    },
  });
  const create = screen.getByRole('button', { name: 'Create immutable version' });
  expect(create).toBeDisabled();
  fireEvent.submit(create.closest('form')!);
  expect(fetchMock.mock.calls.some(([url]) => String(url) === createAction.path)).toBe(false);
  expect(localStorage.getItem(policyAuthorStorageKey)).toBeNull();
});

it.each(['ADMITTED', 'DOCUMENT', 'CATALOGUE'] as const)(
  'collects meaningful %s policy input and labels simulation as non-authoritative',
  async (sourceMode) => {
    const versionId = '018f0000-0000-7000-8000-000000000921';
    const methodId = '018f0000-0000-7000-8000-000000000931';
    const fetchMock = vi.spyOn(globalThis, 'fetch');
    fetchMock.mockImplementation(async (input, init) => {
      const url = String(input);
      if (sourceMode === 'CATALOGUE' && url.startsWith('/api/v1/ui/contract-catalogue?'))
        return Response.json({
          kind: 'methods',
          actor: Object.fromEntries(
            ['sessionId', 'principalId', 'participantId', 'privacyDomainId', 'contextEpoch'].map(
              (field) => [field, session[field as keyof typeof session]],
            ),
          ),
          items: [
            {
              id: `urn:openpc:resource:${methodId}`,
              label: 'balanceOf(address)',
              revision: '1',
              createdAt: policySet.createdAt,
              runtimeBindingId: 'urn:openpc:resource:018f0000-0000-7000-8000-000000000941',
              abiArtifactId: 'urn:openpc:resource:018f0000-0000-7000-8000-000000000942',
              selector: '0x70a08231',
              effect: 'READ',
              state: 'ACTIVE',
              approvalRequirement: 'NONE',
              mfaRequirement: 'NONE',
            },
          ],
          nextCursor: null,
          total: '1',
          completeness: 'COMPLETE',
          authorizedEmpty: false,
          snapshotRevision: '1',
        });
      if (url === createAction.path)
        return Response.json(
          receipt(String((init?.headers as Record<string, string>)['Idempotency-Key'])),
          { status: 202 },
        );
      if (url === simulateAction.path)
        return Response.json(
          {
            simulationId: '018f0000-0000-7000-8000-000000000923',
            authorityLabel: 'SIMULATION_ONLY',
            evaluation: { truthState: 'DENIED', permissions: [] },
          },
          { status: 201 },
        );
      return defaultRead(url);
    });
    const user = userEvent.setup();
    render(
      <PolicyComposer
        actions={[createAction, simulateAction]}
        authorityContextKey={`sha256:${'c3'.repeat(32)}:2`}
        participantRef="urn:openpc:participant:018f0000-0000-7000-8000-000000000101"
      />,
    );
    await screen.findByRole('option', { name: 'Current policy · DRAFT' });
    await user.selectOptions(
      screen.getByLabelText('Policy set for this version'),
      'urn:openpc:policy-set:018f0000-0000-7000-8000-000000000920',
    );
    fireEvent.change(screen.getByLabelText('Semantic version'), { target: { value: '3.0.0' } });

    if (sourceMode === 'DOCUMENT') {
      await user.selectOptions(screen.getByLabelText('Policy source'), 'DOCUMENT');
      await user.click(screen.getByText('Edit policy JSON', { selector: 'summary' }));
      await user.click(screen.getByLabelText('Typed policy document (JSON)'));
      await user.paste(
        JSON.stringify({
          schemaVersion: '1.0.0',
          participantId: session.participantId,
          privacyDomainId: session.privacyDomainId,
          moduleBindings: [],
          rpcPolicies: [],
          contractPolicies: [],
          requiredFacts: [],
          visibilityPolicies: [],
        }),
      );
    } else {
      await user.selectOptions(screen.getByLabelText('Policy source'), 'ADMITTED');
      await user.clear(screen.getByLabelText('Normalized policy digest'));
      await user.type(
        screen.getByLabelText('Normalized policy digest'),
        `sha256:${'a1'.repeat(32)}`,
      );
      await user.clear(screen.getByLabelText('Dependency closure digest'));
      await user.type(
        screen.getByLabelText('Dependency closure digest'),
        `sha256:${'b2'.repeat(32)}`,
      );
    }
    await waitFor(() =>
      expect(screen.getByRole('button', { name: 'Create immutable version' })).toBeEnabled(),
    );
    await user.click(screen.getByRole('button', { name: 'Create immutable version' }));
    await screen.findByText('Immutable version 3.0.0 was accepted. It is not active.');
    await screen.findByText('Version 3.0.0 selected');
    expect(screen.queryByRole('textbox', { name: 'Policy version ID' })).not.toBeInTheDocument();

    if (sourceMode === 'DOCUMENT') {
      expect(
        JSON.parse(
          String(fetchMock.mock.calls.find(([url]) => url === createAction.path)![1]?.body),
        ),
      ).toMatchObject({
        semanticDocument: { schemaVersion: '1.0.0', visibilityPolicies: [] },
      });
      await user.selectOptions(screen.getByLabelText('Policy family'), 'VISIBILITY');
      await user.type(screen.getByLabelText('Visibility policy ID'), methodId);
      await user.type(
        screen.getByLabelText('Fields (comma-separated; empty for whole receipts)'),
        'PEF-AMOUNT',
      );
    } else {
      await user.selectOptions(screen.getByRole('combobox', { name: 'RPC method' }), 'eth_call');
      if (sourceMode === 'CATALOGUE') {
        const chooser = screen.getByRole('button', { name: 'Choose a contract method' });
        expect(
          screen.queryByRole('dialog', { name: 'Choose a contract method' }),
        ).not.toBeInTheDocument();
        await user.click(chooser);
        const library = await screen.findByRole('dialog', { name: 'Choose a contract method' });
        expect(library).toBeVisible();
        await user.click(await screen.findByRole('button', { name: 'Select balanceOf(address)' }));
        expect(screen.getByLabelText('Contract method policy ID')).toHaveValue(methodId);
        await waitFor(() => expect(library).not.toBeVisible());
        expect(chooser).toHaveFocus();
      } else
        await user.type(
          screen.getByRole('textbox', { name: 'Contract method policy ID' }),
          methodId,
        );
      await user.type(
        screen.getByRole('textbox', { name: 'Encoded call data' }),
        '0x70a08231' + '0'.repeat(64),
      );
    }
    await user.click(screen.getByRole('button', { name: 'Run simulation' }));

    await screen.findByRole('region', { name: 'Simulation result' });
    expect(screen.getByText('Policy preview')).toBeInTheDocument();
    expect(screen.getByText('Denied')).toBeInTheDocument();
    expect(screen.getByText('Preview only. Live access is unchanged.')).toBeInTheDocument();
    const simulationBody = JSON.parse(
      String(fetchMock.mock.calls.find(([url]) => url === simulateAction.path)![1]?.body),
    );
    expect(simulationBody).toEqual({
      policyVersionId: versionId,
      ...(sourceMode === 'DOCUMENT'
        ? {
            visibilityPolicyId: methodId,
            purpose: 'AUDIT',
            dimensions: ['EXISTENCE', 'PAYLOAD'],
            fields: ['PEF-AMOUNT'],
          }
        : {
            contractMethodPolicyId: methodId,
            workloadId: simulationAuthority.workloadId,
            assignmentId: simulationAuthority.assignmentId,
            method: 'eth_call',
            calldata: '0x70a08231' + '0'.repeat(64),
          }),
    });
    const changedLabel = sourceMode === 'DOCUMENT' ? 'Purpose' : 'Encoded call data';
    const changedValue = sourceMode === 'DOCUMENT' ? 'MARKETING' : '0x70a08231' + '1'.repeat(64);
    await user.clear(screen.getByLabelText(changedLabel));
    await user.type(screen.getByLabelText(changedLabel), changedValue);
    expect(screen.getByLabelText(changedLabel)).toHaveValue(changedValue);
    expect(screen.queryByRole('region', { name: 'Simulation result' })).not.toBeInTheDocument();
    if (sourceMode === 'DOCUMENT') {
      const preview = {
        authoritative: false,
        authorityGeneration: `sha256:${'a1'.repeat(32)}`,
        truthState: 'SUCCESS',
        effects: ['ALLOW'],
      };
      fetchMock.mockResolvedValueOnce(Response.json(preview));
      await user.click(screen.getByRole('button', { name: 'Check current effective access' }));
      await screen.findByRole('region', { name: 'Current effective access' });
      expect(screen.getByText('Current effective access — preview only')).toBeInTheDocument();
      let deliver: (response: Response) => void = () => {
        throw new Error('request not started');
      };
      fetchMock.mockImplementationOnce(
        () =>
          new Promise<Response>((resolve) => {
            deliver = resolve;
          }),
      );
      await user.click(screen.getByRole('button', { name: 'Check current effective access' }));
      await user.type(screen.getByLabelText('Purpose', { exact: true }), '_CHANGED');
      await act(async () => {
        deliver(Response.json(preview));
      });
      expect(
        screen.queryByRole('region', { name: 'Current effective access' }),
      ).not.toBeInTheDocument();
    }
  },
);

it('simulates a bounded source request and clears its result when the input or context changes', async () => {
  const user = userEvent.setup();
  const participantId = '018f0000-0000-7000-8000-000000000101';
  const versionId = '018f0000-0000-7000-8000-000000000921';
  const indexerProfileId = '018f0000-0000-7000-8000-000000000941';
  const projectionPlanId = '018f0000-0000-7000-8000-000000000942';
  const fetchMock = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
    const url = String(input);
    if (url === '/api/v1/ui/local-session') return Response.json({ ...session, role: 'viewer' });
    if (url === simulateAction.path)
      return Response.json({
        authorityLabel: 'SIMULATION_ONLY',
        evaluation: { truthState: 'SUCCESS' },
      });
    return defaultRead(url);
  });
  const props = {
    actions: [simulateAction],
    authorityContextKey: 'source-context',
    participantRef: `urn:openpc:participant:${participantId}`,
  };
  const view = render(<PolicyComposer {...props} />);
  await screen.findByRole('option', { name: 'Current policy · DRAFT' });
  await user.selectOptions(
    screen.getByLabelText('Policy set for this version'),
    policySet.policySetId,
  );
  await user.click(await screen.findByRole('button', { name: /Review version 3[.]0[.]0/ }));
  await screen.findByText('Version 3.0.0 selected');
  await user.selectOptions(screen.getByLabelText('Policy family'), 'SOURCE');
  for (const [label, value] of [
    ['Indexer profile ID', indexerProfileId],
    ['Projection plan ID', projectionPlanId],
    ['First block', '10'],
    ['Last block', '10'],
    ['Maximum response bytes', '10000'],
  ] as const)
    await user.type(screen.getByLabelText(label), value);
  await user.click(screen.getByRole('button', { name: 'Run simulation' }));
  await screen.findByRole('region', { name: 'Simulation result' });
  expect(
    JSON.parse(
      String(fetchMock.mock.calls.find(([url]) => url === simulateAction.path)?.[1]?.body),
    ),
  ).toEqual({
    policyVersionId: versionId,
    indexerProfileId,
    projectionPlanId,
    dataClass: 'STATE_CALL',
    rangeStart: '10',
    rangeEnd: '10',
    maximumResponseBytes: 10000,
  });
  await user.selectOptions(screen.getByLabelText('Source data class'), 'FULL_BLOCK_TRANSACTIONS');
  expect(screen.queryByRole('region', { name: 'Simulation result' })).not.toBeInTheDocument();
  fetchMock.mockResolvedValueOnce(Response.json({ authenticated: false }));
  view.rerender(<PolicyComposer {...props} authorityContextKey="changed-context" />);
  await waitFor(() =>
    expect(screen.queryByText(/Version [0-9.]+ selected/)).not.toBeInTheDocument(),
  );
  expect(screen.getByLabelText('Policy family')).toBeDisabled();
  expect(screen.queryByLabelText('Indexer profile ID')).not.toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Run simulation' })).toBeDisabled();
});

function deferredResponse() {
  let resolve!: (response: Response) => void;
  const promise = new Promise<Response>((done) => {
    resolve = done;
  });
  return { promise, resolve };
}
it('preserves the exact original key and input through loss, edits, selection changes and reload', async () => {
  const second = {
    ...policySet,
    policySetId: policySet.policySetId.replace('920', '924'),
    name: 'Other policy',
  };
  const sends: RequestInit[] = [];
  const fetchMock = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
    if (String(input) === createAction.path) {
      sends.push(init!);
      if (sends.length === 1) throw new Error('response lost');
      return Response.json(
        receipt(String((init?.headers as Record<string, string>)['Idempotency-Key'])),
        { status: 202 },
      );
    }
    if (String(input) === '/api/v1/ui/policy-sets') return Response.json(page([policySet, second]));
    return defaultRead(String(input));
  });
  const view = render(<PolicyComposer {...props} />);
  const user = await prepareCreate();
  await user.click(screen.getByRole('button', { name: 'Create immutable version' }));
  await screen.findByText(/original version result is unknown/u);
  const retained = localStorage.getItem(policyAuthorStorageKey);
  await user.selectOptions(
    screen.getByLabelText('Policy set for this version'),
    second.policySetId,
  );
  expect(screen.getByRole('button', { name: 'Reconcile original version' })).toBeDisabled();
  expect(localStorage.getItem(policyAuthorStorageKey)).toBe(retained);
  await user.selectOptions(
    screen.getByLabelText('Policy set for this version'),
    policySet.policySetId,
  );
  fireEvent.change(screen.getByLabelText('Semantic version'), { target: { value: '3.0.1' } });
  expect(screen.getByRole('button', { name: 'Reconcile original version' })).toBeDisabled();
  expect(sends).toHaveLength(1);
  expect(localStorage.getItem(policyAuthorStorageKey)).toBe(retained);
  view.unmount();
  render(<PolicyComposer {...props} />);
  await waitFor(() =>
    expect(screen.getByRole('button', { name: 'Reconcile original version' })).toBeEnabled(),
  );
  expect(screen.getByLabelText('Semantic version')).toHaveValue('3.0.0');
  await user.click(screen.getByRole('button', { name: 'Reconcile original version' }));
  await screen.findByText('Immutable version 3.0.0 was accepted. It is not active.');
  expect(sends).toHaveLength(2);
  expect(sends[1]?.body).toBe(sends[0]?.body);
  expect((sends[1]?.headers as Record<string, string>)['Idempotency-Key']).toBe(
    (sends[0]?.headers as Record<string, string>)['Idempotency-Key'],
  );
  const commands = fetchMock.mock.calls.flatMap(([url], index) =>
    String(url) === createAction.path ? [index] : [],
  );
  expect(commands).toHaveLength(2);
  expect(
    fetchMock.mock.calls.slice(0, commands[0]).some(([url]) => url === '/api/v1/ui/local-session'),
  ).toBe(true);
  expect(
    fetchMock.mock.calls
      .slice(commands[0]! + 1, commands[1])
      .some(([url]) => url === '/api/v1/ui/local-session'),
  ).toBe(true);
});
it.each(['selection', 'input', 'source'] as const)(
  'keeps a late success bound to its original %s projection and prevents duplicate submission',
  async (change) => {
    const pending = deferredResponse();
    const second = {
      ...policySet,
      policySetId: policySet.policySetId.replace('920', '924'),
      name: 'Other policy',
    };
    let sent: RequestInit | undefined;
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      if (String(input) === createAction.path) {
        sent = init;
        return pending.promise;
      }
      if (String(input) === '/api/v1/ui/policy-sets')
        return Response.json(page([policySet, second]));
      return defaultRead(String(input));
    });
    render(<PolicyComposer {...props} />);
    const user = await prepareCreate();
    const form = screen.getByRole('button', { name: 'Create immutable version' }).closest('form')!;
    fireEvent.submit(form);
    fireEvent.submit(form);
    await waitFor(() => expect(sent).toBeDefined());
    if (change === 'selection')
      await user.selectOptions(
        screen.getByLabelText('Policy set for this version'),
        second.policySetId,
      );
    else if (change === 'source')
      await user.selectOptions(screen.getByLabelText('Policy source'), 'DOCUMENT');
    else
      fireEvent.change(screen.getByLabelText('Semantic version'), { target: { value: '3.0.1' } });
    await act(async () =>
      pending.resolve(
        Response.json(
          receipt(String((sent!.headers as Record<string, string>)['Idempotency-Key'])),
          { status: 202 },
        ),
      ),
    );
    expect(screen.queryByText(/Version [0-9.]+ selected/)).not.toBeInTheDocument();
    expect(fetchMock.mock.calls.filter(([url]) => url === createAction.path)).toHaveLength(1);
    const saved = JSON.parse(localStorage.getItem(policyAuthorStorageKey)!);
    expect(saved.value).toMatchObject({
      policySetId: policySet.policySetId,
      semanticVersion: '3.0.0',
      policyVersionId: versionId,
    });
  },
);
it.each(['logout', 'actor'] as const)(
  'does not restore original private state after %s and a late completion',
  async (change) => {
    const pending = deferredResponse();
    let currentSession = session;
    let sent: RequestInit | undefined;
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      if (String(input) === createAction.path) {
        sent = init;
        return pending.promise;
      }
      if (String(input) === '/api/v1/ui/local-session') return Response.json(currentSession);
      return defaultRead(String(input));
    });
    const view = render(<PolicyComposer {...props} />);
    const user = await prepareCreate();
    await user.click(screen.getByRole('button', { name: 'Create immutable version' }));
    await waitFor(() => expect(sent).toBeDefined());
    if (change === 'logout') clearPolicyWorkflowStorage();
    else {
      currentSession = { ...session, principalId: '018f0000-0000-7000-8000-000000000112' };
      view.rerender(<PolicyComposer {...props} authorityContextKey="new-actor" />);
      await waitFor(() =>
        expect(screen.queryByLabelText('Normalized policy digest')).not.toBeInTheDocument(),
      );
    }
    await act(async () =>
      pending.resolve(
        Response.json(
          receipt(String((sent!.headers as Record<string, string>)['Idempotency-Key'])),
          { status: 202 },
        ),
      ),
    );
    expect(localStorage.getItem(policyAuthorStorageKey)).toBeNull();
    expect(screen.queryByText(/Version [0-9.]+ selected/)).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Reconcile original version' })).toBeDisabled();
  },
);
it.each(['changed', 'denied'] as const)(
  'does not post an old intent when the fresh actor read is %s',
  async (mode) => {
    let reads = 0;
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      if (String(input) === '/api/v1/ui/local-session') {
        reads += 1;
        if (reads > 1)
          return mode === 'denied'
            ? new Response(null, { status: 403 })
            : Response.json({ ...session, contextEpoch: '3' });
      }
      return defaultRead(String(input));
    });
    render(<PolicyComposer {...props} />);
    const user = await prepareCreate();
    await user.click(screen.getByRole('button', { name: 'Create immutable version' }));
    await screen.findByText(/original version result is unknown/u);
    expect(fetchMock.mock.calls.filter(([url]) => url === createAction.path)).toHaveLength(0);
    expect(
      JSON.parse(localStorage.getItem(policyAuthorStorageKey)!).value.createIdempotencyKey,
    ).toMatch(/^policy-create-version-/u);
  },
);
it('keeps a restored unresolved request after the actual PolicySets collection read fails', async () => {
  const key = 'policy-create-version-018f0000-0000-7000-8000-000000000925';
  const bound = JSON.stringify({
    actor: session,
    value: {
      policySetId: policySet.policySetId,
      semanticVersion: '3.0.0',
      normalizedPolicyDigest: `sha256:${'a1'.repeat(32)}`,
      dependencyClosureDigest: `sha256:${'b2'.repeat(32)}`,
      policyVersionId: '',
      createIdempotencyKey: key,
    },
  });
  localStorage.setItem(policyAuthorStorageKey, bound);
  vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) =>
    String(input) === '/api/v1/ui/policy-sets'
      ? new Response(null, { status: 403 })
      : defaultRead(String(input)),
  );
  render(<PolicyComposer {...props} />);
  await screen.findByText('Policy sets could not be read in this context.');
  expect(localStorage.getItem(policyAuthorStorageKey)).toBe(bound);
  expect(screen.getByRole('button', { name: 'Reconcile original version' })).toBeDisabled();
});

const effectiveGeneration = `sha256:${'a1'.repeat(32)}`;
const effectiveReply = (truthState = 'SUCCESS') => ({
  authoritative: false,
  authorityGeneration: effectiveGeneration,
  truthState,
  subjectRef: `urn:openpc:resource:${session.principalId}`,
  resourceRef: `urn:openpc:resource:${policySet.policySetId.slice(-36)}`,
  explanationRefs: ['current-preview'],
  effects: truthState === 'SUCCESS' ? ['ALLOW'] : ['DENY'],
});
const effectiveUrl = (input: unknown) => String(input).startsWith('/api/v1/ui/effective-access?');
async function prepareEffectiveAccess() {
  await screen.findByRole('option', { name: 'Current policy · DRAFT' });
  const user = userEvent.setup();
  await user.selectOptions(
    screen.getByLabelText('Policy set for this version'),
    policySet.policySetId,
  );
  await user.selectOptions(screen.getByLabelText('Policy family'), 'VISIBILITY');
  fireEvent.change(screen.getByLabelText('Visibility policy ID'), {
    target: { value: '018f0000-0000-7000-8000-000000000951' },
  });
  await waitFor(() =>
    expect(screen.getByRole('button', { name: 'Check current effective access' })).toBeEnabled(),
  );
  return user;
}
function deferredEffectiveBody() {
  let resolve!: (body: unknown) => void;
  let reject!: (reason: unknown) => void;
  const promise = new Promise<unknown>((done, fail) => {
    resolve = done;
    reject = fail;
  });
  const response = new Response(null, { status: 200 });
  const json = vi.fn(() => promise);
  response.json = json;
  return { response, json, resolve, reject };
}

it.each(['SUCCESS', 'DENIED', 'UNKNOWN'] as const)(
  'renders valid %s effective access as a preview with the original GET inputs',
  async (truthState) => {
    const fetch = vi
      .spyOn(globalThis, 'fetch')
      .mockImplementation(async (input) =>
        effectiveUrl(input)
          ? Response.json(effectiveReply(truthState))
          : defaultRead(String(input)),
      );
    render(<PolicyComposer {...props} />);
    const user = await prepareEffectiveAccess();
    await user.click(screen.getByRole('button', { name: 'Check current effective access' }));
    const region = await screen.findByRole('region', { name: 'Current effective access' });
    expect(within(region).getByText(truthState)).toBeInTheDocument();
    expect(within(region).getByText(effectiveGeneration)).toBeInTheDocument();
    expect(within(region).getByText('Current effective access — preview only')).toBeInTheDocument();
    expect(
      screen.getByText(
        'Current effective access was read. Protected requests are authorized separately.',
      ),
    ).toBeInTheDocument();
    const call = fetch.mock.calls.find(([url]) => effectiveUrl(url))!;
    const query = new URL(String(call[0]), 'http://localhost').searchParams;
    expect(Object.fromEntries(query)).toEqual({
      policySetId: policySet.policySetId,
      visibilityPolicyId: '018f0000-0000-7000-8000-000000000951',
      purpose: 'AUDIT',
      dimensions: 'EXISTENCE,PAYLOAD',
      fields: '',
    });
    expect(call[1]).toEqual({
      cache: 'no-store',
      credentials: 'same-origin',
      signal: expect.any(AbortSignal),
    });
    expect(fetch.mock.calls.filter(([, init]) => init?.method === 'POST')).toHaveLength(0);
  },
);

it('requires a current selected parent before enabling the effective preview', async () => {
  const fetcher = vi
    .spyOn(globalThis, 'fetch')
    .mockImplementation(async (input) => defaultRead(String(input)));
  render(<PolicyComposer {...props} />);
  const user = userEvent.setup();
  await screen.findByRole('option', { name: 'Current policy · DRAFT' });
  await user.selectOptions(screen.getByLabelText('Policy family'), 'VISIBILITY');
  fireEvent.change(screen.getByLabelText('Visibility policy ID'), {
    target: { value: '018f0000-0000-7000-8000-000000000951' },
  });
  const preview = screen.getByRole('button', { name: 'Check current effective access' });
  expect(preview).toBeDisabled();
  fireEvent.click(preview);
  expect(fetcher.mock.calls.some(([input]) => effectiveUrl(input))).toBe(false);
  await user.selectOptions(
    screen.getByLabelText('Policy set for this version'),
    policySet.policySetId,
  );
  await waitFor(() => expect(preview).toBeEnabled());
  await user.selectOptions(screen.getByLabelText('Policy set for this version'), '');
  expect(preview).toBeDisabled();
  expect(fetcher.mock.calls.some(([input]) => effectiveUrl(input))).toBe(false);
});

it.each(['parent changes', 'unmounts'] as const)(
  'cancels a preview and ignores its JSON when the selected owner %s',
  async (boundary) => {
    const second = {
      ...policySet,
      policySetId: policySet.policySetId.replace('920', '924'),
      name: 'Second policy',
    };
    const old = deferredEffectiveBody();
    let previewReads = 0;
    const fetcher = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      const url = String(input);
      if (effectiveUrl(input)) {
        previewReads += 1;
        return previewReads === 1
          ? old.response
          : Response.json({ ...effectiveReply('DENIED'), resourceRef: second.policySetId });
      }
      if (url === '/api/v1/ui/policy-sets') return Response.json(page([policySet, second]));
      return defaultRead(url);
    });
    const view = render(<PolicyComposer {...props} />);
    const user = await prepareEffectiveAccess();
    await user.click(screen.getByRole('button', { name: 'Check current effective access' }));
    await waitFor(() => expect(old.json).toHaveBeenCalledOnce());
    const previewCall = fetcher.mock.calls.find(([input]) => effectiveUrl(input))!;
    const signal = previewCall[1]?.signal;
    expect(signal?.aborted).toBe(false);
    expect(
      new URL(String(previewCall[0]), 'http://localhost').searchParams.get('policySetId'),
    ).toBe(policySet.policySetId);
    if (boundary === 'unmounts') view.unmount();
    else
      await user.selectOptions(
        screen.getByLabelText('Policy set for this version'),
        second.policySetId,
      );
    expect(signal?.aborted).toBe(true);
    await act(async () => old.resolve(effectiveReply()));
    expect(
      screen.queryByRole('region', { name: 'Current effective access' }),
    ).not.toBeInTheDocument();
    if (boundary === 'parent changes') {
      await user.click(screen.getByRole('button', { name: 'Check current effective access' }));
      const region = await screen.findByRole('region', { name: 'Current effective access' });
      expect(within(region).getByText('DENIED')).toBeInTheDocument();
      const calls = fetcher.mock.calls.filter(([input]) => effectiveUrl(input));
      expect(calls).toHaveLength(2);
      expect(
        new URL(String(calls[1]![0]), 'http://localhost').searchParams.get('policySetId'),
      ).toBe(second.policySetId);
    }
  },
);

it('accepts only consumed effective fields with harmless unconsumed additions', async () => {
  vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) =>
    effectiveUrl(input)
      ? Response.json({
          authoritative: false,
          authorityGeneration: effectiveGeneration,
          truthState: 'UNKNOWN',
          futureMetadata: { revision: '2' },
        })
      : defaultRead(String(input)),
  );
  render(<PolicyComposer {...props} />);
  const user = await prepareEffectiveAccess();
  await user.click(screen.getByRole('button', { name: 'Check current effective access' }));
  const region = await screen.findByRole('region', { name: 'Current effective access' });
  expect(within(region).getByText('UNKNOWN')).toBeInTheDocument();
  expect(within(region).getByText(effectiveGeneration)).toBeInTheDocument();
  expect(within(region).queryByText('futureMetadata')).not.toBeInTheDocument();
});

it.each([
  ['null', null],
  ['array', []],
  ['string', 'malformed'],
  ['number', 42],
  ['boolean', false],
  ['empty-object', {}],
  ['missing-authoritative', { authorityGeneration: effectiveGeneration, truthState: 'SUCCESS' }],
  ['authoritative-true', { ...effectiveReply(), authoritative: true }],
  ['authoritative-string', { ...effectiveReply(), authoritative: 'false' }],
  ['missing-generation', { authoritative: false, truthState: 'SUCCESS' }],
  ['empty-generation', { ...effectiveReply(), authorityGeneration: '' }],
  ['invalid-generation', { ...effectiveReply(), authorityGeneration: 'not-a-digest' }],
  ['short-generation', { ...effectiveReply(), authorityGeneration: 'sha256:a1' }],
  ['nonhex-generation', { ...effectiveReply(), authorityGeneration: `sha256:${'g'.repeat(64)}` }],
  [
    'uppercase-generation',
    { ...effectiveReply(), authorityGeneration: `sha256:${'AB'.repeat(32)}` },
  ],
  [
    'object-generation',
    { ...effectiveReply(), authorityGeneration: { digest: effectiveGeneration } },
  ],
  ['missing-truth', { authoritative: false, authorityGeneration: effectiveGeneration }],
  ['invented-truth', { ...effectiveReply(), truthState: 'ALLOW_FOREVER' }],
  ['lowercase-truth', { ...effectiveReply(), truthState: 'success' }],
  ['object-truth', { ...effectiveReply(), truthState: { state: 'SUCCESS' } }],
] as const)(
  'rejects current malformed effective access %s without retaining an earlier projection',
  async (_name, value) => {
    let reads = 0;
    const fetch = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      if (!effectiveUrl(input)) return defaultRead(String(input));
      reads += 1;
      return Response.json(reads === 1 ? effectiveReply() : value);
    });
    render(<PolicyComposer {...props} />);
    const user = await prepareEffectiveAccess();
    const button = screen.getByRole('button', { name: 'Check current effective access' });
    await user.click(button);
    await screen.findByRole('region', { name: 'Current effective access' });
    await user.click(button);
    await screen.findByText('Current effective access could not be read safely.');
    expect(
      screen.queryByRole('region', { name: 'Current effective access' }),
    ).not.toBeInTheDocument();
    expect(fetch.mock.calls.filter(([, init]) => init?.method === 'POST')).toHaveLength(0);
  },
);

it.each(['denied', 'transport', 'unreadable', '404'] as const)(
  'clears a prior effective projection on current %s and preserves the existing safe status',
  async (mode) => {
    let reads = 0;
    const unavailable = new Response(null, {
      status: mode === '404' ? 404 : mode === 'denied' ? 403 : 200,
    });
    const json = vi.fn().mockRejectedValue(new SyntaxError('Unreadable effective response'));
    unavailable.json = json;
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      if (!effectiveUrl(input)) return defaultRead(String(input));
      reads += 1;
      if (reads === 1) return Response.json(effectiveReply());
      if (mode === 'transport') throw new TypeError('Effective transport failed');
      return unavailable;
    });
    render(<PolicyComposer {...props} />);
    const user = await prepareEffectiveAccess();
    const button = screen.getByRole('button', { name: 'Check current effective access' });
    await user.click(button);
    await screen.findByRole('region', { name: 'Current effective access' });
    await user.click(button);
    await screen.findByText(
      mode === '404'
        ? 'No active policy is available for this visibility request.'
        : 'Current effective access could not be read safely.',
    );
    expect(
      screen.queryByRole('region', { name: 'Current effective access' }),
    ).not.toBeInTheDocument();
    if (mode === 'denied' || mode === '404') expect(json).not.toHaveBeenCalled();
  },
);

it.each(['success', 'denied', '404'] as const)(
  'ignores an obsolete effective HTTP %s before decoding when a newer preview succeeds',
  async (mode) => {
    const old = deferredResponse();
    let reads = 0;
    const fetch = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      if (!effectiveUrl(input)) return defaultRead(String(input));
      reads += 1;
      return reads === 1 ? old.promise : Response.json(effectiveReply('DENIED'));
    });
    render(<PolicyComposer {...props} />);
    const user = await prepareEffectiveAccess();
    const button = screen.getByRole('button', { name: 'Check current effective access' });
    await user.click(button);
    await waitFor(() =>
      expect(fetch.mock.calls.filter(([url]) => effectiveUrl(url))).toHaveLength(1),
    );
    await user.click(button);
    const region = await screen.findByRole('region', { name: 'Current effective access' });
    const reply = new Response(null, {
      status: mode === '404' ? 404 : mode === 'denied' ? 403 : 200,
    });
    const json = vi.fn().mockResolvedValue(effectiveReply('SUCCESS'));
    reply.json = json;
    await act(async () => old.resolve(reply));
    expect(json).not.toHaveBeenCalled();
    expect(within(region).getByText('DENIED')).toBeInTheDocument();
    expect(
      screen.getByText(
        'Current effective access was read. Protected requests are authorized separately.',
      ),
    ).toBeInTheDocument();
  },
);

it.each(['valid', 'malformed', 'unreadable'] as const)(
  'ignores obsolete effective JSON %s after a newer successful preview',
  async (mode) => {
    const old = deferredEffectiveBody();
    let reads = 0;
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      if (!effectiveUrl(input)) return defaultRead(String(input));
      reads += 1;
      return reads === 1 ? old.response : Response.json(effectiveReply('DENIED'));
    });
    render(<PolicyComposer {...props} />);
    const user = await prepareEffectiveAccess();
    const button = screen.getByRole('button', { name: 'Check current effective access' });
    await user.click(button);
    await waitFor(() => expect(old.json).toHaveBeenCalledOnce());
    await user.click(button);
    const region = await screen.findByRole('region', { name: 'Current effective access' });
    await act(async () => {
      if (mode === 'unreadable') old.reject(new SyntaxError('Obsolete JSON failed'));
      else old.resolve(mode === 'malformed' ? { authoritative: true } : effectiveReply('SUCCESS'));
    });
    expect(within(region).getByText('DENIED')).toBeInTheDocument();
    expect(
      screen.getByText(
        'Current effective access was read. Protected requests are authorized separately.',
      ),
    ).toBeInTheDocument();
  },
);

it.each([
  ['Visibility policy ID', '018f0000-0000-7000-8000-000000000952'],
  ['Purpose', 'STATE_READ'],
  ['Dimensions (comma-separated)', 'METADATA'],
  ['Fields (comma-separated; empty for whole receipts)', 'receiptId'],
] as const)(
  'keeps the effective preview cleared when %s changes during JSON read',
  async (label, value) => {
    const old = deferredEffectiveBody();
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) =>
      effectiveUrl(input) ? old.response : defaultRead(String(input)),
    );
    render(<PolicyComposer {...props} />);
    const user = await prepareEffectiveAccess();
    await user.click(screen.getByRole('button', { name: 'Check current effective access' }));
    await waitFor(() => expect(old.json).toHaveBeenCalledOnce());
    fireEvent.change(screen.getByLabelText(label), { target: { value } });
    await act(async () => old.resolve(effectiveReply()));
    expect(
      screen.queryByRole('region', { name: 'Current effective access' }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByText(
        'Current effective access was read. Protected requests are authorized separately.',
      ),
    ).not.toBeInTheDocument();
  },
);

it('does not adopt original-actor effective JSON after a local-session actor reload', async () => {
  const old = deferredEffectiveBody();
  let currentSession = session;
  const sessionReads: string[] = [];
  vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
    if (effectiveUrl(input)) return old.response;
    if (String(input) === '/api/v1/ui/local-session') {
      sessionReads.push(currentSession.principalId);
      return Response.json(currentSession);
    }
    return defaultRead(String(input));
  });
  const view = render(<PolicyComposer {...props} />);
  const user = await prepareEffectiveAccess();
  await user.click(screen.getByRole('button', { name: 'Check current effective access' }));
  await waitFor(() => expect(old.json).toHaveBeenCalledOnce());
  currentSession = {
    ...session,
    principalId: '018f0000-0000-7000-8000-000000000199',
    contextEpoch: '3',
  };
  view.rerender(<PolicyComposer {...props} authorityContextKey="new-actor-context" />);
  await waitFor(() => expect(screen.getByLabelText('Policy family')).toHaveValue('CONTRACT'));
  await waitFor(() => expect(sessionReads).toContain(currentSession.principalId));
  await screen.findByText(
    'Choose a policy set and review a version to configure a contract simulation.',
  );
  await act(async () => old.resolve(effectiveReply()));
  expect(
    screen.queryByRole('region', { name: 'Current effective access' }),
  ).not.toBeInTheDocument();
  expect(
    screen.queryByText(
      'Current effective access was read. Protected requests are authorized separately.',
    ),
  ).not.toBeInTheDocument();
});

it.each(['denied', '404'] as const)(
  'does not restore an obsolete successful effective JSON after the current read is %s',
  async (mode) => {
    const old = deferredEffectiveBody();
    let reads = 0;
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      if (!effectiveUrl(input)) return defaultRead(String(input));
      reads += 1;
      return reads === 1
        ? old.response
        : new Response(null, { status: mode === '404' ? 404 : 403 });
    });
    render(<PolicyComposer {...props} />);
    const user = await prepareEffectiveAccess();
    const button = screen.getByRole('button', { name: 'Check current effective access' });
    await user.click(button);
    await waitFor(() => expect(old.json).toHaveBeenCalledOnce());
    await user.click(button);
    const status =
      mode === '404'
        ? 'No active policy is available for this visibility request.'
        : 'Current effective access could not be read safely.';
    await screen.findByText(status);
    await act(async () => old.resolve(effectiveReply()));
    expect(screen.getByText(status)).toBeInTheDocument();
    expect(
      screen.queryByRole('region', { name: 'Current effective access' }),
    ).not.toBeInTheDocument();
  },
);

it('keeps the accepted version across evaluation views without replaying creation', async () => {
  const fetchMock = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
    const url = String(input);
    if (url === createAction.path) {
      return Response.json(
        receipt(String((init?.headers as Record<string, string>)['Idempotency-Key'])),
        { status: 202 },
      );
    }
    return defaultRead(url);
  });
  const { rerender } = render(<PolicyComposer {...props} view="author" />);
  const user = await prepareCreate();
  expect(screen.queryByRole('button', { name: 'Run simulation' })).not.toBeInTheDocument();
  await user.click(screen.getByRole('button', { name: 'Create immutable version' }));
  await screen.findByText('Immutable version 3.0.0 was accepted. It is not active.');
  const writeClipboard = vi.spyOn(navigator.clipboard, 'writeText').mockResolvedValue(undefined);
  const requestsBeforeCopy = fetchMock.mock.calls.length;
  const copy = screen.getByRole('button', { name: 'Copy Policy version reference' });
  expect(copy.closest('details')).toBeNull();
  await user.click(copy);
  expect(writeClipboard).toHaveBeenCalledWith(versionId);
  expect(await screen.findByText('Policy version reference copied.')).toHaveAttribute(
    'role',
    'status',
  );
  expect(fetchMock.mock.calls).toHaveLength(requestsBeforeCopy);
  expect(screen.getByRole('link', { name: 'Continue to simulation' })).toHaveAttribute(
    'href',
    '/configure/policies?view=simulation',
  );
  rerender(<PolicyComposer {...props} view="simulation" />);
  expect(
    screen.queryByRole('button', { name: 'Create immutable version' }),
  ).not.toBeInTheDocument();
  await screen.findByText('Version 3.0.0 selected');
  expect(fetchMock.mock.calls.filter(([url]) => url === createAction.path)).toHaveLength(1);
  expect(fetchMock.mock.calls.filter(([url]) => url === simulateAction.path)).toHaveLength(0);
});

it('does not enable simulation in a new evaluation session without an accepted version', async () => {
  vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => defaultRead(String(input)));
  render(<PolicyComposer {...props} view="simulation" />);
  await screen.findByRole('option', { name: 'Current policy · DRAFT' });
  expect(screen.getByRole('button', { name: 'Run simulation' })).toBeDisabled();
  expect(screen.getByRole('heading', { name: 'Choose a policy version' })).toBeInTheDocument();
});

it.each(['success', 'denied', 'privacy-cleared'] as const)(
  'revalidates a saved version after remount: %s',
  async (outcome) => {
    let remounted = false;
    let resolvePage!: (response: Response) => void;
    const pendingPage = new Promise<Response>((resolve) => {
      resolvePage = resolve;
    });
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const url = String(input);
      if (url === createAction.path)
        return Response.json(
          receipt(String((init?.headers as Record<string, string>)['Idempotency-Key'])),
          { status: 202 },
        );
      if (remounted && url === '/api/v1/ui/policy-sets') return pendingPage;
      return defaultRead(url);
    });
    const author = render(<PolicyComposer {...props} view="author" />);
    const user = await prepareCreate();
    await user.click(screen.getByRole('button', { name: 'Create immutable version' }));
    await screen.findByText('Immutable version 3.0.0 was accepted. It is not active.');
    author.unmount();
    remounted = true;
    render(<PolicyComposer {...props} view="simulation" />);
    await screen.findByText('Loading policy sets.');
    expect(screen.queryByText(/Version [0-9.]+ selected/)).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Run simulation' })).toBeDisabled();
    if (outcome === 'privacy-cleared') clearPolicyWorkflowStorage();
    await act(async () =>
      resolvePage(
        outcome === 'denied' ? new Response(null, { status: 403 }) : Response.json(page()),
      ),
    );
    if (outcome === 'denied')
      await screen.findByText('Policy sets could not be read in this context.');
    else if (outcome === 'privacy-cleared')
      expect(
        screen.queryByRole('option', { name: 'Current policy · DRAFT' }),
      ).not.toBeInTheDocument();
    else await screen.findByRole('option', { name: 'Current policy · DRAFT' });
    if (outcome === 'success') await screen.findByText('Version 3.0.0 selected');
    else expect(screen.queryByText('Version 3.0.0 selected')).not.toBeInTheDocument();
    expect(fetchMock.mock.calls.filter(([url]) => url === createAction.path)).toHaveLength(1);
    expect(fetchMock.mock.calls.filter(([url]) => url === simulateAction.path)).toHaveLength(0);
  },
);

it.each(['privacy-cleanup', 'session-mismatch'] as const)(
  'source switching cannot restore concealed policy content after %s',
  async (change) => {
    let changed = false;
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      if (changed && String(input) === '/api/v1/ui/local-session' && change === 'session-mismatch')
        return Response.json({ ...session, principalId: '018f0000-0000-7000-8000-000000000199' });
      return defaultRead(String(input));
    });
    const user = userEvent.setup();
    render(<PolicyComposer {...props} view="author" />);
    await screen.findByRole('option', { name: 'Current policy · DRAFT' });
    const document = {
      schemaVersion: '1.0.0',
      participantId: session.participantId,
      privacyDomainId: session.privacyDomainId,
      moduleBindings: [],
      rpcPolicies: [],
      contractPolicies: [],
      requiredFacts: [],
    };
    await user.upload(
      screen.getByLabelText('Policy file'),
      new File([JSON.stringify(document)], 'rules.json', { type: 'application/json' }),
    );
    await screen.findByRole('region', { name: 'Policy draft review' });
    changed = true;
    act(() => {
      if (change === 'privacy-cleanup') {
        clearPolicyWorkflowStorage();
        window.dispatchEvent(new Event(transactionWorkflowPrivacyEvent));
      } else {
        const nonce = notifySessionTransition('changing');
        notifySessionTransition('settled', nonce);
      }
    });
    await waitFor(() =>
      expect(screen.getByLabelText('Typed policy document (JSON)')).toHaveValue(''),
    );
    await user.selectOptions(screen.getByLabelText('Policy source'), 'ADMITTED');
    await user.selectOptions(screen.getByLabelText('Policy source'), 'DOCUMENT');
    expect(screen.getByLabelText('Typed policy document (JSON)')).toHaveValue('');
    expect(screen.queryByRole('region', { name: 'Policy draft review' })).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Create immutable version' })).toBeDisabled();
    expect(fetchMock.mock.calls.filter(([url]) => url === createAction.path)).toHaveLength(0);
  },
);

it('keeps an unsent document concealed until the same native actor is revalidated on focus', async () => {
  let pending = false;
  let resume!: (response: Response) => void;
  const read = new Promise<Response>((resolve) => {
    resume = resolve;
  });
  const fetchMock = vi
    .spyOn(globalThis, 'fetch')
    .mockImplementation(async (input) =>
      pending && String(input) === '/api/v1/ui/local-session' ? read : defaultRead(String(input)),
    );
  const user = userEvent.setup();
  render(<PolicyComposer {...props} view="author" />);
  await screen.findByRole('option', { name: 'Current policy · DRAFT' });
  await user.selectOptions(
    screen.getByLabelText('Policy set for this version'),
    policySet.policySetId,
  );
  await user.type(screen.getByLabelText('Semantic version'), '1.2.3');
  const text = JSON.stringify({
    schemaVersion: '1.0.0',
    participantId: session.participantId,
    privacyDomainId: session.privacyDomainId,
    moduleBindings: [],
    rpcPolicies: [],
    contractPolicies: [],
    requiredFacts: [],
  });
  await user.upload(
    screen.getByLabelText('Policy file'),
    new File([text], 'rules.json', { type: 'application/json' }),
  );
  await screen.findByRole('region', { name: 'Policy draft review' });
  pending = true;
  fireEvent(window, new Event('blur'));
  fireEvent(window, new Event('focus'));
  expect(screen.getByLabelText('Typed policy document (JSON)')).toHaveValue('');
  expect(screen.getByLabelText('Semantic version')).toHaveValue('');
  expect(screen.getByRole('button', { name: 'Create immutable version' })).toBeDisabled();
  await act(async () => resume(Response.json(session)));
  await waitFor(() =>
    expect(screen.getByLabelText('Typed policy document (JSON)')).toHaveValue(text),
  );
  expect(screen.getByLabelText('Semantic version')).toHaveValue('1.2.3');
  await waitFor(() =>
    expect(screen.getByRole('button', { name: 'Create immutable version' })).toBeEnabled(),
  );
  expect(screen.getByLabelText('Policy set for this version')).toHaveValue(policySet.policySetId);
  expect(fetchMock.mock.calls.filter(([url]) => url === createAction.path)).toHaveLength(0);
});

it.each([false, true])(
  'recovers the original unknown request after focus without browser storage, following privacy cleanup: %s',
  async (privacyCleared) => {
    const sends: RequestInit[] = [];
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      if (String(input) === createAction.path) {
        sends.push(init!);
        if (sends.length === 1) throw Error('response lost');
        return Response.json(
          receipt(String((init!.headers as Record<string, string>)['Idempotency-Key'])),
          { status: 202 },
        );
      }
      return defaultRead(String(input));
    });
    render(<PolicyComposer {...props} view="author" />);
    await screen.findByRole('option', { name: 'Current policy · DRAFT' });
    if (privacyCleared) {
      act(() => {
        clearPolicyWorkflowStorage();
        window.dispatchEvent(new Event(transactionWorkflowPrivacyEvent));
      });
      await screen.findByRole('option', { name: 'Current policy · DRAFT' });
    }
    vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => {
      throw Error('storage unavailable');
    });
    vi.spyOn(Storage.prototype, 'getItem').mockImplementation(() => {
      throw Error('storage unavailable');
    });
    const user = await prepareCreate();
    await user.click(screen.getByRole('button', { name: 'Create immutable version' }));
    await screen.findByText(/original version result is unknown/u);
    fireEvent(window, new Event('blur'));
    expect(screen.getByRole('button', { name: 'Reconcile original version' })).toBeDisabled();
    fireEvent(window, new Event('focus'));
    await waitFor(() =>
      expect(screen.getByRole('button', { name: 'Reconcile original version' })).toBeEnabled(),
    );
    expect(screen.getByLabelText('Semantic version')).toHaveValue('3.0.0');
    await user.click(screen.getByRole('button', { name: 'Reconcile original version' }));
    await screen.findByText('Immutable version 3.0.0 was accepted. It is not active.');
    expect(sends).toHaveLength(2);
    expect(sends[1]!.body).toBe(sends[0]!.body);
    expect((sends[1]!.headers as Record<string, string>)['Idempotency-Key']).toBe(
      (sends[0]!.headers as Record<string, string>)['Idempotency-Key'],
    );
  },
);

const disclosureDraft = {
  schemaVersion: '1.0.0',
  participantId: session.participantId,
  privacyDomainId: session.privacyDomainId,
  moduleBindings: [],
  rpcPolicies: [],
  contractPolicies: [],
  requiredFacts: [],
  visibilityPolicies: [
    {
      policyId: '018f0000-0000-7000-8000-000000000901',
      selector: {
        kind: 'TRANSACTION',
        runtimeBindingId: '018f0000-0000-7000-8000-000000000902',
        bindingRevision: '1',
      },
      mode: 'STATIC',
      effect: 'ALLOW',
      subject: { kind: 'PRINCIPAL', principalId: session.principalId },
      purpose: 'AUDIT',
      requiredRoles: ['reader'],
      dimensions: ['EXISTENCE', 'METADATA', 'PAYLOAD'],
      fields: ['from', 'to', 'value'],
      conditions: [],
    },
  ],
};
it.each([false, true])(
  'retains imported disclosure choices after verified focus recovery, advanced source: %s',
  async (advanced) => {
    const fetchMock = vi
        .spyOn(globalThis, 'fetch')
        .mockImplementation(async (url) => defaultRead(String(url))),
      user = userEvent.setup();
    render(<PolicyComposer {...props} view="author" />);
    await screen.findByRole('option', { name: 'Current policy · DRAFT' });
    await user.upload(
      screen.getByLabelText('Policy file'),
      new File([JSON.stringify(disclosureDraft)], 'rules.json', { type: 'application/json' }),
    );
    await screen.findByRole('region', { name: 'Disclosure permissions' });
    await user.click(screen.getByLabelText('from'));
    expect(screen.getByLabelText('from')).not.toBeChecked();
    if (advanced) await user.selectOptions(screen.getByLabelText('Policy source'), 'ADMITTED');
    fireEvent(window, new Event('blur'));
    expect(
      screen.queryByRole('region', { name: 'Disclosure permissions' }),
    ).not.toBeInTheDocument();
    fireEvent(window, new Event('focus'));
    await waitFor(() =>
      expect(screen.getByLabelText('Policy source')).toHaveValue(
        advanced ? 'ADMITTED' : 'DOCUMENT',
      ),
    );
    await screen.findByRole('option', { name: 'Current policy · DRAFT' });
    if (advanced) await user.selectOptions(screen.getByLabelText('Policy source'), 'DOCUMENT');
    await screen.findByRole('region', { name: 'Disclosure permissions' });
    expect(screen.getByLabelText('from')).not.toBeChecked();
    await user.click(screen.getByLabelText('from'));
    expect(screen.getByLabelText('from')).toBeChecked();
    expect(fetchMock.mock.calls.filter(([, init]) => init?.method === 'POST')).toHaveLength(0);
  },
);
it.each(['privacy', 'actor'] as const)(
  'does not restore imported disclosure choices after %s changes',
  async (kind) => {
    let current = session;
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (url) =>
      String(url) === '/api/v1/ui/local-session'
        ? Response.json(current)
        : defaultRead(String(url)),
    );
    const user = userEvent.setup();
    render(<PolicyComposer {...props} view="author" />);
    await screen.findByRole('option', { name: 'Current policy · DRAFT' });
    await user.upload(
      screen.getByLabelText('Policy file'),
      new File([JSON.stringify(disclosureDraft)], 'rules.json', { type: 'application/json' }),
    );
    await screen.findByRole('region', { name: 'Disclosure permissions' });
    await user.click(screen.getByLabelText('from'));
    act(() => {
      if (kind === 'privacy') {
        clearPolicyWorkflowStorage();
        window.dispatchEvent(new Event(transactionWorkflowPrivacyEvent));
      } else {
        current = { ...session, contextEpoch: '3' };
        window.dispatchEvent(new Event('blur'));
        window.dispatchEvent(new Event('focus'));
      }
    });
    await waitFor(() => expect(screen.getByLabelText('Policy file')).toBeEnabled());
    expect(
      screen.queryByRole('region', { name: 'Disclosure permissions' }),
    ).not.toBeInTheDocument();
    expect(screen.getByLabelText('Typed policy document (JSON)')).toHaveValue('');
  },
);
