import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { performWebAuthnStepUp } from '@openpc/ui-shell';
import { WorkloadWorkflow } from './workload-workflow';
import {
  DiscoveryCertificateRecoveryWorkflow,
  type DiscoveryRecoveryView,
} from './discovery-certificate-recovery-workflow';
import { trustFixture as discoveryFixture } from '../../../services/identity-service/src/domain/discovery-certificate-recovery.test-fixture';
import { writeBoundPolicyState } from './policy-workflow-storage';
vi.mock('@openpc/ui-shell', () => ({ performWebAuthnStepUp: vi.fn() }));

type StepUpLifecycle = { readonly signal?: AbortSignal; readonly isCurrent?: () => boolean };
function assertStepUpCurrent(lifecycle?: StepUpLifecycle) {
  if (!lifecycle || lifecycle.signal?.aborted || lifecycle.isCurrent?.() !== true)
    throw new DOMException('The operation was cancelled.', 'AbortError');
}
beforeEach(() => {
  vi.mocked(performWebAuthnStepUp)
    .mockReset()
    .mockImplementation(async (_action, _binding, lifecycle?: StepUpLifecycle) => {
      assertStepUpCurrent(lifecycle);
    });
});
function holdStepUp() {
  let release!: () => void;
  let lifecycle!: StepUpLifecycle;
  const entered = vi.fn();
  vi.mocked(performWebAuthnStepUp).mockImplementation(
    (_action, _binding, control?: StepUpLifecycle) => {
      assertStepUpCurrent(control);
      lifecycle = control!;
      entered();
      return new Promise<void>((resolve) => {
        release = resolve;
      }).then(() => assertStepUpCurrent(control));
    },
  );
  return {
    entered,
    release: () => release(),
    lifecycle: () => lifecycle,
    completion: () => vi.mocked(performWebAuthnStepUp).mock.results[0]!.value as Promise<void>,
  };
}

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
const state = { actor, approvals: [], nextCursor: null };
const candidate = {
  credentialId: id('192'),
  participantId: actor.participantId,
  principalId: id('190'),
  workloadId: `urn:openpc:workload:${id('191')}`,
  publicKeySpkiDer: 'cHVibGljLWtleQ==',
};
const review = {
  reviewToken: 'r'.repeat(100),
  approvalRequestId: id('801'),
  review: {
    mutation: 'ISSUE',
    candidate,
    resourceId: candidate.credentialId,
    expectedRevision: '0',
    candidateDigest: `sha256:${'a'.repeat(64)}`,
    checkerPrincipalId: id('112'),
    reason: 'Authorize this workload certificate.',
    expiresAt: new Date(Date.now() + 300000).toISOString(),
    stepUp: {
      actionIntentId: 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
      actionIntentDigest: `sha256:${'b'.repeat(64)}`,
      resourceId: candidate.credentialId,
      resourceDigest: `sha256:${'a'.repeat(64)}`,
    },
  },
};
const certificate = {
  credentialId: candidate.credentialId,
  participantId: actor.participantId,
  principalId: candidate.principalId,
  workloadId: candidate.workloadId,
  state: 'ACTIVE',
  workloadEpoch: '1',
  revision: '1',
  certificateDer: 'Y2VydGlmaWNhdGU=',
  keyId: `sha256:${'c'.repeat(64)}`,
  certificateFingerprint: `sha256:${'d'.repeat(64)}`,
  uriSan: candidate.workloadId,
  issuer: 'openpc-local-issuer',
  notBefore: '2026-10-04T00:00:00.000Z',
  notAfter: '2026-10-05T00:00:00.000Z',
  rotateAt: '2026-10-04T20:00:00.000Z',
  replacedCredentialId: null,
};
const consumed = {
  ...state,
  approvals: [
    {
      approvalRequestId: `urn:openpc:resource:${id('801')}`,
      candidateDigest: review.review.candidateDigest,
      makerSubjectRef: `urn:openpc:resource:${actor.principalId}`,
      checkerSubjectRef: `urn:openpc:resource:${id('112')}`,
      revision: '2',
      state: 'APPROVED',
      proposal: {
        candidateDigest: review.review.candidateDigest,
        resourceId: candidate.credentialId,
        makerPrincipalId: actor.principalId,
        catalogOperationId: 'ID-OP-WORKLOAD-ISSUE',
        expectedRevision: '0',
        state: 'CONSUMED',
        operationId: id('850'),
        expiresAt: review.review.expiresAt,
        candidate,
      },
      stepUp: review.review.stepUp,
    },
  ],
};
const originalPendingKey = `openpc:workload-workflow:v1:original:${actor.principalId}:${actor.participantId}:${actor.privacyDomainId}`;
function retainWorkloadCommand(command: 'SUBMIT' | 'COMMIT' | 'APPROVE' = 'COMMIT') {
  writeBoundPolicyState(originalPendingKey, actor, {
    command,
    candidateDigest: review.review.candidateDigest,
    expectedRevision: review.review.expectedRevision,
    ...(command === 'SUBMIT' ? {} : { approvalRequestId: review.approvalRequestId }),
  });
}
function deferredResponse() {
  let resolve!: (response: Response) => void;
  let reject!: (cause: Error) => void;
  const promise = new Promise<Response>((accept, fail) => {
    resolve = accept;
    reject = fail;
  });
  return { promise, resolve, reject };
}
beforeEach(() => {
  localStorage.clear();
  vi.clearAllMocks();
});
afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});
function selectWorkflowView(view: 'Certificates' | 'Changes' | 'Approvals' | 'Recovery') {
  const button = within(
    screen.getByRole('navigation', { name: 'Certificate workflow views' }),
  ).getByRole('button', { name: view });
  if (button.getAttribute('aria-current') !== 'page') fireEvent.click(button);
}

function navigateToWorkloadControl(role: string, name: unknown) {
  if (role === 'textbox') {
    if (name === 'Saved credential ID') selectWorkflowView('Certificates');
    else if (name === 'Original workload approval ID') selectWorkflowView('Recovery');
    else selectWorkflowView('Changes');
  } else if (role === 'combobox') {
    selectWorkflowView(name === 'Approval lane' ? 'Approvals' : 'Changes');
  } else if (role === 'button' && typeof name === 'string') {
    if (
      [
        'Refresh workload approvals',
        'Verify and approve workload change',
        'Next workload approvals',
        'View saved certificate',
      ].includes(name)
    )
      selectWorkflowView('Approvals');
    else if (name === 'Read workload certificate') selectWorkflowView('Certificates');
    else if (name === 'Read original workload operation') selectWorkflowView('Recovery');
    else if (
      [
        'Prepare workload change',
        'Request workload approval',
        'Verify and commit workload change',
        'Read saved workload',
        'Read saved workload operation',
        'Choose workload principal',
        'Choose checker',
      ].includes(name)
    )
      selectWorkflowView('Changes');
  }
}
function workloadControl(
  role: Parameters<typeof screen.getByRole>[0],
  options?: Parameters<typeof screen.getByRole>[1],
) {
  navigateToWorkloadControl(role, options?.name);
  return screen.getByRole(role, options);
}
function findWorkloadControl(
  role: Parameters<typeof screen.findByRole>[0],
  options?: Parameters<typeof screen.findByRole>[1],
) {
  navigateToWorkloadControl(role, options?.name);
  return screen.findByRole(role, options);
}
function renderExpandedWorkload() {
  const view = render(<WorkloadWorkflow />);
  fireEvent.click(screen.getByText('Session details', { exact: true }));
  selectWorkflowView('Changes');
  return view;
}

it('opens with certificate lookup and keeps inactive workflow controls out of navigation', async () => {
  const fetcher = vi.spyOn(globalThis, 'fetch').mockResolvedValue(Response.json(state));
  render(<WorkloadWorkflow />);
  await screen.findByText(
    'No certificate selected. Enter the credential reference from your approved request.',
  );
  expect(screen.getByRole('textbox', { name: 'Saved credential ID' })).toBeVisible();
  expect(screen.getByText('Prepare a workload change')).not.toBeVisible();
  expect(screen.getByText('Find an original workload operation')).not.toBeVisible();
  await waitFor(() =>
    expect(screen.getByText(`Signed-in principal: ${actor.principalId}`)).not.toBeVisible(),
  );
  expect(screen.queryByRole('button', { name: 'Prepare workload change' })).toBeNull();
  expect(screen.queryByRole('button', { name: 'Verify and approve workload change' })).toBeNull();
  expect(fetcher.mock.calls.some(([, init]) => init?.method === 'POST')).toBe(false);
});

it('admits lookup input only after the initial native context loads', async () => {
  const loading = deferredResponse();
  const fetcher = vi.spyOn(globalThis, 'fetch').mockImplementationOnce(() => loading.promise);
  const user = userEvent.setup();
  render(<WorkloadWorkflow />);
  const lookup = screen.getByRole('textbox', { name: 'Saved credential ID' });
  expect(lookup).toBeDisabled();
  await user.type(lookup, candidate.credentialId);
  expect(lookup).toHaveValue('');
  await act(async () => loading.resolve(Response.json(state)));
  expect(lookup).toBeEnabled();
  await user.type(lookup, candidate.credentialId);
  expect(lookup).toHaveValue(candidate.credentialId);
  expect(fetcher).toHaveBeenCalledOnce();
  expect(fetcher.mock.calls.some(([, init]) => init?.method === 'POST')).toBe(false);
});

it('opens an executed certificate request from the records view and confirms the owner readback', async () => {
  const fetcher = vi
    .spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(Response.json(consumed))
    .mockResolvedValueOnce(Response.json(consumed))
    .mockResolvedValueOnce(Response.json(certificate));
  const user = userEvent.setup();
  render(<WorkloadWorkflow />);
  const records = await screen.findByRole('table', { name: 'Assigned certificate requests' });
  expect(within(records).getByText('Executed')).toBeVisible();
  expect(screen.queryByLabelText('Workload certificate result')).toBeNull();
  await user.click(
    within(records).getByRole('button', {
      name: `Open certificate #${certificate.credentialId.slice(-8)}`,
    }),
  );
  expect(
    await screen.findByRole('heading', {
      name: `Certificate #${certificate.credentialId.slice(-8)}`,
    }),
  ).toHaveFocus();
  expect(String(fetcher.mock.calls.at(-1)![0])).toContain(
    `credentialId=${certificate.credentialId}`,
  );
  expect(fetcher.mock.calls.some(([, init]) => init?.method === 'POST')).toBe(false);
});

it('shows authoritative certificate dates and download without expanding changes or cryptographic details', async () => {
  const fetcher = vi
    .spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(Response.json(state))
    .mockResolvedValueOnce(Response.json(state))
    .mockResolvedValueOnce(Response.json(certificate));
  const user = userEvent.setup();
  render(<WorkloadWorkflow />);
  await waitFor(() => expect(fetcher).toHaveBeenCalledOnce());
  await user.type(
    screen.getByRole('textbox', { name: 'Saved credential ID' }),
    certificate.credentialId,
  );
  await user.click(screen.getByRole('button', { name: 'Read workload certificate' }));
  await screen.findByLabelText('Workload certificate result');
  expect(
    screen.getByRole('heading', { name: `Certificate #${certificate.credentialId.slice(-8)}` }),
  ).toBeVisible();
  expect(screen.getByText('05 Oct 2026, 00:00 UTC')).toBeVisible();
  expect(screen.getByRole('link', { name: 'Download public certificate (.der)' })).toHaveAttribute(
    'href',
    `data:application/pkix-cert;base64,${certificate.certificateDer}`,
  );
  expect(
    screen.getByText(`Certificate fingerprint: ${certificate.certificateFingerprint}`),
  ).not.toBeVisible();
  expect(screen.getByText('Prepare a workload change')).not.toBeVisible();
  await user.click(screen.getByText('Certificate technical details', { exact: true }));
  expect(
    screen.getByText(`Certificate fingerprint: ${certificate.certificateFingerprint}`),
  ).toBeVisible();
  expect(fetcher.mock.calls.some(([, init]) => init?.method === 'POST')).toBe(false);
});

it('keeps original custody and draft inputs while moving between workflow views', async () => {
  retainWorkloadCommand();
  const original = localStorage.getItem(originalPendingKey);
  const fetcher = vi.spyOn(globalThis, 'fetch').mockResolvedValue(Response.json(state));
  const user = userEvent.setup();
  render(<WorkloadWorkflow />);
  await screen.findByRole('button', { name: 'Read original workload outcome' });
  await user.click(screen.getByRole('button', { name: 'Changes' }));
  await user.type(
    screen.getByRole('textbox', { name: 'New credential ID' }),
    candidate.credentialId,
  );
  expect(screen.getByRole('button', { name: 'Prepare workload change' })).toBeDisabled();
  await user.click(screen.getByRole('button', { name: 'Certificates' }));
  expect(screen.getByText(/Further workload changes are blocked/u)).toBeVisible();
  expect(screen.getByRole('button', { name: 'Read original workload outcome' })).toBeVisible();
  await user.click(screen.getByRole('button', { name: 'Changes' }));
  expect(screen.getByRole('textbox', { name: 'New credential ID' })).toHaveValue(
    candidate.credentialId,
  );
  expect(localStorage.getItem(originalPendingKey)).toBe(original);
  expect(fetcher.mock.calls.some(([, init]) => init?.method === 'POST')).toBe(false);
});

it.each(['APPROVED', 'CONSUMED'] as const)(
  'distinguishes a %s request from confirmed certificate readback',
  async (proposalState) => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      Response.json(
        proposalState === 'CONSUMED'
          ? consumed
          : { ...state, approvals: [requestedWorkloadApproval('APPROVED')] },
      ),
    );
    const user = userEvent.setup();
    render(<WorkloadWorkflow />);
    await user.click(screen.getByRole('button', { name: 'Approvals' }));
    expect(
      await screen.findByRole('heading', {
        name:
          proposalState === 'CONSUMED'
            ? 'Issue certificate · Executed'
            : 'Issue certificate · Approved — awaiting execution',
      }),
    ).toBeVisible();
    expect(
      screen.getByText(
        proposalState === 'CONSUMED'
          ? `Operation: ${id('850')}`
          : 'Operation: Effect not confirmed',
      ),
    ).toBeVisible();
    expect(screen.queryByLabelText('Workload certificate result')).not.toBeInTheDocument();
    expect(
      screen.getByText(`Candidate digest: ${review.review.candidateDigest}`),
    ).not.toBeVisible();
  },
);

it('reads the selected executed request certificate through the current owner without copying an identifier', async () => {
  const fetcher = vi
    .spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(Response.json(consumed))
    .mockResolvedValueOnce(Response.json(consumed))
    .mockResolvedValueOnce(Response.json(certificate));
  const user = userEvent.setup();
  render(<WorkloadWorkflow />);
  await user.click(screen.getByRole('button', { name: 'Approvals' }));
  await user.click(await screen.findByRole('button', { name: 'View saved certificate' }));
  const title = await screen.findByRole('heading', {
    name: `Certificate #${certificate.credentialId.slice(-8)}`,
  });
  expect(title).toHaveFocus();
  expect(String(fetcher.mock.calls.at(-1)![0])).toBe(
    `/api/v1/ui/workload-workbench?credentialId=${certificate.credentialId}`,
  );
  expect(fetcher.mock.calls.some(([, init]) => init?.method === 'POST')).toBe(false);
});

it('does not read a selected executed request certificate after the current actor changes', async () => {
  const fetcher = vi
    .spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(Response.json(consumed))
    .mockResolvedValueOnce(
      Response.json({ ...consumed, actor: { ...actor, sessionId: id('702') } }),
    );
  const user = userEvent.setup();
  render(<WorkloadWorkflow />);
  await user.click(screen.getByRole('button', { name: 'Approvals' }));
  await user.click(await screen.findByRole('button', { name: 'View saved certificate' }));
  expect(screen.queryByLabelText('Workload certificate result')).not.toBeInTheDocument();
  expect(fetcher.mock.calls.some(([url]) => String(url).includes('credentialId='))).toBe(false);
  expect(fetcher.mock.calls.some(([, init]) => init?.method === 'POST')).toBe(false);
});

it('shows only the inputs meaningful to the selected workload change', async () => {
  vi.spyOn(globalThis, 'fetch').mockResolvedValue(Response.json(state));
  renderExpandedWorkload();
  await waitFor(() =>
    expect(workloadControl('button', { name: 'Prepare workload change' })).toBeEnabled(),
  );
  expect(workloadControl('textbox', { name: 'Workload public key' })).toBeVisible();
  expect(workloadControl('textbox', { name: 'Workload principal ID' })).toBeVisible();
  await userEvent
    .setup()
    .selectOptions(workloadControl('combobox', { name: /^Change/u }), 'REVOKE');
  expect(workloadControl('textbox', { name: 'Credential ID to revoke' })).toBeVisible();
  expect(screen.queryByRole('textbox', { name: 'Workload public key' })).not.toBeInTheDocument();
  expect(screen.queryByRole('textbox', { name: 'Workload principal ID' })).not.toBeInTheDocument();
});
it('restores the actor-bound review and prevents a second write after the owner consumed it', async () => {
  writeBoundPolicyState('openpc:workload-workflow:v1', actor, review);
  const fetch = vi.spyOn(globalThis, 'fetch').mockResolvedValue(Response.json(consumed));
  renderExpandedWorkload();
  await waitFor(() => expect(screen.getByLabelText('Workload change review')).toBeVisible());
  expect(workloadControl('button', { name: 'Verify and commit workload change' })).toBeDisabled();
  expect(performWebAuthnStepUp).not.toHaveBeenCalled();
  expect(fetch.mock.calls.some(([, options]) => options?.method === 'POST')).toBe(false);
});
it('does not restore another session’s review', async () => {
  writeBoundPolicyState('openpc:workload-workflow:v1', actor, review);
  vi.spyOn(globalThis, 'fetch').mockResolvedValue(
    Response.json({ ...state, actor: { ...actor, sessionId: id('702') } }),
  );
  renderExpandedWorkload();
  await waitFor(() =>
    expect(workloadControl('button', { name: 'Prepare workload change' })).toBeEnabled(),
  );
  expect(screen.queryByLabelText('Workload change review')).not.toBeInTheDocument();
});
it.each(['success', 'failure'])(
  'discards a delayed initial inventory %s after a newer lane and actor read',
  async (outcome) => {
    const initial = deferredResponse();
    const currentActor = { ...actor, sessionId: id('702'), principalId: id('113') };
    writeBoundPolicyState('openpc:workload-workflow:v1', currentActor, review);
    const fetch = vi
      .spyOn(globalThis, 'fetch')
      // Ignore abort to exercise ordering even if the old response is already arriving.
      .mockImplementationOnce(() => initial.promise)
      .mockResolvedValueOnce(Response.json({ ...consumed, actor: currentActor }));
    const user = userEvent.setup();
    renderExpandedWorkload();
    const lane = workloadControl('combobox', { name: 'Approval lane' });
    await user.selectOptions(lane, 'maker');
    await screen.findByText(`Signed-in principal: ${currentActor.principalId}`);
    expect(fetch.mock.calls[0]?.[1]?.signal?.aborted).toBe(true);
    await act(async () => {
      if (outcome === 'success') initial.resolve(Response.json(state));
      else initial.reject(new Error('The old inventory failed.'));
    });
    expect(lane).toHaveValue('maker');
    expect(screen.getByText(`Signed-in principal: ${currentActor.principalId}`)).toBeVisible();
    expect(screen.queryByText(`Signed-in principal: ${actor.principalId}`)).not.toBeInTheDocument();
    selectWorkflowView('Changes');
    expect(screen.getByLabelText('Workload change review')).toBeVisible();
    selectWorkflowView('Approvals');
    expect(screen.getByText(`Operation: ${id('850')}`)).toBeVisible();
    expect(workloadControl('button', { name: 'Verify and commit workload change' })).toBeDisabled();
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    expect(performWebAuthnStepUp).not.toHaveBeenCalled();
    expect(fetch.mock.calls.some(([, options]) => options?.method === 'POST')).toBe(false);
  },
);
it.each([
  { change: 'session', nextActor: { ...actor, sessionId: id('702') } },
  { change: 'principal', nextActor: { ...actor, principalId: id('113') } },
  { change: 'Participant', nextActor: { ...actor, participantId: id('102') } },
  { change: 'privacy domain', nextActor: { ...actor, privacyDomainId: id('202') } },
  { change: 'context epoch', nextActor: { ...actor, contextEpoch: '3' } },
])(
  'drops a saved certificate read and displayed result after a $change switch',
  async ({ nextActor }) => {
    writeBoundPolicyState('openpc:workload-workflow:v1', actor, review);
    const fetch = vi
      .spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(Response.json(state))
      .mockResolvedValueOnce(Response.json(state))
      .mockResolvedValueOnce(Response.json(certificate))
      .mockResolvedValueOnce(Response.json({ ...state, actor: nextActor }));
    const user = userEvent.setup();
    renderExpandedWorkload();
    await screen.findByLabelText('Workload change review');
    await user.click(workloadControl('button', { name: 'Read saved workload' }));
    await screen.findByLabelText('Workload certificate result');
    expect(workloadControl('link', { name: 'Download public certificate (.der)' })).toBeVisible();
    await user.click(workloadControl('button', { name: 'Read saved workload' }));
    expect(screen.queryByLabelText('Workload certificate result')).not.toBeInTheDocument();
    expect(
      screen.queryByRole('link', { name: 'Download public certificate (.der)' }),
    ).not.toBeInTheDocument();
    expect(screen.queryByLabelText('Workload change review')).not.toBeInTheDocument();
    expect(fetch.mock.calls.filter(([url]) => String(url).includes('credentialId='))).toHaveLength(
      1,
    );
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    expect(fetch.mock.calls.some(([, options]) => options?.method === 'POST')).toBe(false);
  },
);
it('keeps the originally requested certificate ID when the lookup input changes during readback', async () => {
  const pending = deferredResponse();
  const fetch = vi
    .spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(Response.json(state))
    .mockResolvedValueOnce(Response.json(state))
    .mockImplementationOnce(() => pending.promise);
  const user = userEvent.setup();
  renderExpandedWorkload();
  await waitFor(() =>
    expect(workloadControl('button', { name: 'Prepare workload change' })).toBeEnabled(),
  );
  const lookup = workloadControl('textbox', { name: 'Saved credential ID' });
  await user.type(lookup, candidate.credentialId);
  await user.click(workloadControl('button', { name: 'Read workload certificate' }));
  await waitFor(() => expect(fetch).toHaveBeenCalledTimes(3));
  await user.clear(lookup);
  await user.type(lookup, id('193'));
  await act(async () => pending.resolve(Response.json(certificate)));
  expect(screen.getByText(`Credential: ${candidate.credentialId}`)).toBeVisible();
  expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  expect(String(fetch.mock.calls[2]?.[0])).toContain(`credentialId=${candidate.credentialId}`);
});
it('stops an old saved commit before assertion or write when its inventory refresh changes actor', async () => {
  writeBoundPolicyState('openpc:workload-workflow:v1', actor, review);
  const fetch = vi
    .spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(Response.json(state))
    .mockResolvedValueOnce(Response.json({ ...state, actor: { ...actor, sessionId: id('702') } }));
  const user = userEvent.setup();
  renderExpandedWorkload();
  const commit = await findWorkloadControl('button', { name: 'Verify and commit workload change' });
  await user.click(commit);
  expect(screen.queryByLabelText('Workload change review')).not.toBeInTheDocument();
  expect(performWebAuthnStepUp).not.toHaveBeenCalled();
  expect(fetch.mock.calls.some(([, options]) => options?.method === 'POST')).toBe(false);
  expect(screen.queryByRole('alert')).not.toBeInTheDocument();
});
it.each(['credential', 'Participant'])(
  'rejects a current certificate read with a foreign %s binding',
  async (field) => {
    const fetch = vi
      .spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(Response.json(state))
      .mockResolvedValueOnce(Response.json(state))
      .mockResolvedValueOnce(
        Response.json({
          ...certificate,
          ...(field === 'credential' ? { credentialId: id('193') } : { participantId: id('102') }),
        }),
      );
    const user = userEvent.setup();
    renderExpandedWorkload();
    await waitFor(() =>
      expect(workloadControl('button', { name: 'Prepare workload change' })).toBeEnabled(),
    );
    await user.type(
      workloadControl('textbox', { name: 'Saved credential ID' }),
      candidate.credentialId,
    );
    await user.click(workloadControl('button', { name: 'Read workload certificate' }));
    expect(await findWorkloadControl('alert')).toHaveTextContent(
      'Certificate readback belongs to a different context.',
    );
    expect(screen.queryByLabelText('Workload certificate result')).not.toBeInTheDocument();
    expect(fetch.mock.calls.some(([, options]) => options?.method === 'POST')).toBe(false);
  },
);
it.each([
  { kind: 'inventory', outcome: 'success' },
  { kind: 'inventory', outcome: 'failure' },
  { kind: 'certificate', outcome: 'success' },
  { kind: 'certificate', outcome: 'failure' },
])(
  'cancels a pending $kind read on unmount and discards its late $outcome after a context remount',
  async ({ kind, outcome }) => {
    const pending = deferredResponse();
    const fetch = vi.spyOn(globalThis, 'fetch');
    if (kind === 'inventory') fetch.mockImplementationOnce(() => pending.promise);
    else
      fetch
        .mockResolvedValueOnce(Response.json(state))
        .mockResolvedValueOnce(Response.json(state))
        .mockImplementationOnce(() => pending.promise);
    const user = userEvent.setup();
    const view = renderExpandedWorkload();
    if (kind === 'certificate') {
      await waitFor(() =>
        expect(workloadControl('button', { name: 'Prepare workload change' })).toBeEnabled(),
      );
      await user.type(
        workloadControl('textbox', { name: 'Saved credential ID' }),
        candidate.credentialId,
      );
      await user.click(workloadControl('button', { name: 'Read workload certificate' }));
      await waitFor(() => expect(fetch).toHaveBeenCalledTimes(3));
    }
    const signal = fetch.mock.calls.at(-1)?.[1]?.signal;
    expect(signal?.aborted).toBe(false);
    view.unmount();
    expect(signal?.aborted).toBe(true);
    const currentActor = { ...actor, principalId: id('113'), sessionId: id('702') };
    fetch.mockResolvedValueOnce(Response.json({ ...state, actor: currentActor }));
    renderExpandedWorkload();
    await screen.findByText(`Signed-in principal: ${currentActor.principalId}`);
    await act(async () => {
      if (outcome === 'success')
        pending.resolve(Response.json(kind === 'inventory' ? state : certificate));
      else pending.reject(new Error('The obsolete read failed.'));
    });
    expect(screen.getByText(`Signed-in principal: ${currentActor.principalId}`)).toBeVisible();
    expect(screen.queryByLabelText('Workload certificate result')).not.toBeInTheDocument();
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    expect(fetch.mock.calls.some(([, options]) => options?.method === 'POST')).toBe(false);
  },
);

function principalChoices(kind: 'USER' | 'WORKLOAD', currentActor = actor) {
  const effect = {
    principalId: kind === 'WORKLOAD' ? candidate.principalId : review.review.checkerPrincipalId,
    displayLabel: kind === 'WORKLOAD' ? 'Operations workload' : 'Independent reviewer',
    participantId: currentActor.participantId,
    identityEpoch: '1',
    kind,
    state: 'ACTIVE',
    revision: '1',
  };
  return {
    actor: currentActor,
    items:
      kind === 'USER'
        ? [
            {
              effect: {
                ...effect,
                principalId: currentActor.principalId,
                displayLabel: 'Current maker',
              },
              operationId: null,
            },
            { effect, operationId: null },
          ]
        : [{ effect, operationId: null }],
    nextCursor: null,
    completeness: 'COMPLETE',
    authorizedEmpty: false,
    observedAt: '2026-10-04T00:00:00.000Z',
  };
}
async function selectDraftPrincipals(user: ReturnType<typeof userEvent.setup>) {
  await user.click(await findWorkloadControl('button', { name: 'Choose workload principal' }));
  await user.click(await findWorkloadControl('button', { name: 'Select Operations workload' }));
  expect(workloadControl('button', { name: 'Choose workload principal' })).toHaveFocus();
  await user.click(workloadControl('button', { name: 'Choose checker' }));
  await findWorkloadControl('button', { name: 'Select Independent reviewer' });
  expect(
    screen.queryByRole('button', { name: 'Select Current maker', hidden: true }),
  ).not.toBeInTheDocument();
  await user.click(workloadControl('button', { name: 'Select Independent reviewer' }));
  expect(workloadControl('button', { name: 'Choose checker' })).toHaveFocus();
}
it('prepares the original command with real labelled workload/checker IDs and no client approval', async () => {
  const posts: unknown[] = [];
  const fetch = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
    const url = String(input);
    if (url.startsWith('/api/v1/ui/principal-catalogue'))
      return Response.json(principalChoices(url.includes('kind=WORKLOAD') ? 'WORKLOAD' : 'USER'));
    if (init?.method === 'POST') {
      posts.push(JSON.parse(init.body as string));
      return Response.json({ reviewToken: review.reviewToken, review: review.review });
    }
    return Response.json(state);
  });
  renderExpandedWorkload();
  await screen.findByText(`Signed-in principal: ${actor.principalId}`);
  const user = userEvent.setup();
  await selectDraftPrincipals(user);
  expect(workloadControl('textbox', { name: 'Workload principal ID' })).toHaveValue(
    candidate.principalId,
  );
  expect(workloadControl('textbox', { name: 'Checker principal ID' })).toHaveValue(
    review.review.checkerPrincipalId,
  );
  expect(workloadControl('textbox', { name: 'Workload principal ID' })).toHaveAttribute('readonly');
  expect(screen.getByText('Selected workload principal: Operations workload')).toBeVisible();
  expect(screen.getByText('Selected checker: Independent reviewer')).toBeVisible();
  expect(posts).toEqual([]);
  await user.type(
    workloadControl('textbox', { name: 'New credential ID' }),
    candidate.credentialId,
  );
  await user.type(workloadControl('textbox', { name: 'Workload ID' }), candidate.workloadId);
  await user.type(
    workloadControl('textbox', { name: 'Workload public key' }),
    candidate.publicKeySpkiDer,
  );
  await user.type(
    workloadControl('textbox', { name: 'Reason for workload change' }),
    review.review.reason,
  );
  await user.click(workloadControl('button', { name: 'Prepare workload change' }));
  await screen.findByLabelText('Workload change review');
  expect(posts).toEqual([
    {
      command: 'PREPARE',
      input: {
        mutation: 'ISSUE',
        credentialId: candidate.credentialId,
        principalId: candidate.principalId,
        workloadId: candidate.workloadId,
        publicKeySpkiDer: candidate.publicKeySpkiDer,
      },
      checkerPrincipalId: review.review.checkerPrincipalId,
      reason: review.review.reason,
      expectedSessionId: actor.sessionId,
    },
  ]);
  expect(performWebAuthnStepUp).not.toHaveBeenCalled();
  expect(fetch.mock.calls.filter(([, init]) => init?.method === 'POST')).toHaveLength(1);
});
it('requires real draft selections before preparing and never sends empty or fabricated choices', async () => {
  const fetch = vi.spyOn(globalThis, 'fetch').mockResolvedValue(Response.json(state));
  renderExpandedWorkload();
  await screen.findByText(`Signed-in principal: ${actor.principalId}`);
  const user = userEvent.setup();
  await user.type(
    workloadControl('textbox', { name: 'New credential ID' }),
    candidate.credentialId,
  );
  await user.type(workloadControl('textbox', { name: 'Workload ID' }), candidate.workloadId);
  await user.type(
    workloadControl('textbox', { name: 'Workload public key' }),
    candidate.publicKeySpkiDer,
  );
  await user.type(
    workloadControl('textbox', { name: 'Reason for workload change' }),
    review.review.reason,
  );
  await user.click(workloadControl('button', { name: 'Prepare workload change' }));
  expect(await findWorkloadControl('alert')).toHaveTextContent(
    'Choose the current workload principal and an independent checker first.',
  );
  expect(fetch).toHaveBeenCalledTimes(1);
  expect(performWebAuthnStepUp).not.toHaveBeenCalled();
});
it('changing draft choices preserves the exact saved consumed review and never repeats its business write', async () => {
  writeBoundPolicyState('openpc:workload-workflow:v1', actor, review);
  const fetch = vi
    .spyOn(globalThis, 'fetch')
    .mockImplementation(async (input) =>
      String(input).startsWith('/api/v1/ui/principal-catalogue')
        ? Response.json(
            principalChoices(String(input).includes('kind=WORKLOAD') ? 'WORKLOAD' : 'USER'),
          )
        : Response.json(consumed),
    );
  renderExpandedWorkload();
  await screen.findByLabelText('Workload change review');
  const saved = localStorage.getItem('openpc:workload-workflow:v1');
  expect(saved).not.toBeNull();
  await selectDraftPrincipals(userEvent.setup());
  expect(localStorage.getItem('openpc:workload-workflow:v1')).toBe(saved);
  await userEvent.setup().click(screen.getByText('Change technical details', { exact: true }));
  expect(
    within(screen.getByLabelText('Workload change review')).getByText(
      `Candidate digest: ${review.review.candidateDigest}`,
    ),
  ).toBeVisible();
  expect(workloadControl('button', { name: 'Verify and commit workload change' })).toBeDisabled();
  expect(fetch.mock.calls.some(([, init]) => init?.method === 'POST')).toBe(false);
  expect(performWebAuthnStepUp).not.toHaveBeenCalled();
});
it.each([
  { change: 'session', next: { ...actor, sessionId: id('702') } },
  { change: 'principal', next: { ...actor, principalId: id('113') } },
  { change: 'Participant', next: { ...actor, participantId: id('102') } },
  { change: 'privacy', next: { ...actor, privacyDomainId: id('202') } },
  { change: 'epoch', next: { ...actor, contextEpoch: '3' } },
])(
  'clears only new draft selections when the current $change binding changes',
  async ({ next }) => {
    let currentActor = actor;
    const fetch = vi
      .spyOn(globalThis, 'fetch')
      .mockImplementation(async (input) =>
        String(input).startsWith('/api/v1/ui/principal-catalogue')
          ? Response.json(
              principalChoices(
                String(input).includes('kind=WORKLOAD') ? 'WORKLOAD' : 'USER',
                currentActor,
              ),
            )
          : Response.json({ ...state, actor: currentActor }),
      );
    renderExpandedWorkload();
    await screen.findByText(`Signed-in principal: ${actor.principalId}`);
    const user = userEvent.setup();
    await selectDraftPrincipals(user);
    currentActor = next;
    await user.selectOptions(workloadControl('combobox', { name: 'Approval lane' }), 'maker');
    await waitFor(() =>
      expect(workloadControl('textbox', { name: 'Checker principal ID' })).toHaveValue(''),
    );
    expect(workloadControl('textbox', { name: 'Workload principal ID' })).toHaveValue('');
    expect(screen.queryByText('Selected checker: Independent reviewer')).not.toBeInTheDocument();
    expect(
      screen.queryByText('Selected workload principal: Operations workload'),
    ).not.toBeInTheDocument();
    expect(fetch.mock.calls.some(([, init]) => init?.method === 'POST')).toBe(false);
  },
);
it.each(['success', 'failure'])(
  'closes a draft picker on context change and ignores its late cursor %s',
  async (outcome) => {
    const old = deferredResponse();
    let currentActor = actor;
    let catalogueReads = 0;
    const fetch = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      if (String(input).startsWith('/api/v1/ui/principal-catalogue')) {
        catalogueReads++;
        if (catalogueReads === 2) return old.promise;
        const items = Array.from({ length: 25 }, (_, index) => ({
          effect: {
            ...principalChoices('WORKLOAD', currentActor).items[0]!.effect,
            principalId: id(String(190 + index)),
            displayLabel: index === 0 ? 'Operations workload' : `Operations workload ${index + 1}`,
          },
          operationId: null,
        }));
        return Response.json({
          ...principalChoices('WORKLOAD', currentActor),
          items,
          nextCursor: items.at(-1)!.effect.principalId,
        });
      }
      return Response.json({ ...state, actor: currentActor });
    });
    renderExpandedWorkload();
    await screen.findByText(`Signed-in principal: ${actor.principalId}`);
    const user = userEvent.setup();
    await user.click(workloadControl('button', { name: 'Choose workload principal' }));
    await user.click(await findWorkloadControl('button', { name: 'Next principal page' }));
    const signal = fetch.mock.calls.find(([input]) => String(input).includes('after='))?.[1]
      ?.signal;
    currentActor = { ...actor, privacyDomainId: id('202'), contextEpoch: '3' };
    await user.selectOptions(workloadControl('combobox', { name: 'Approval lane' }), 'maker');
    await waitFor(() =>
      expect(
        screen.queryByRole('region', { name: 'Choose a workload principal', hidden: true }),
      ).not.toBeInTheDocument(),
    );
    expect(signal?.aborted).toBe(true);
    await act(async () =>
      outcome === 'success'
        ? old.resolve(Response.json(principalChoices('WORKLOAD')))
        : old.reject(new Error('private-old-picker')),
    );
    expect(workloadControl('textbox', { name: 'Workload principal ID' })).toHaveValue('');
    expect(
      screen.queryByRole('button', { name: 'Select Operations workload', hidden: true }),
    ).not.toBeInTheDocument();
    expect(screen.queryByText(/private-old-picker/)).not.toBeInTheDocument();
    expect(fetch.mock.calls.some(([, init]) => init?.method === 'POST')).toBe(false);
  },
);

function requestedWorkloadApproval(approvalState: 'REQUESTED' | 'APPROVED' = 'REQUESTED') {
  const original = consumed.approvals[0]!;
  return {
    ...original,
    state: approvalState,
    proposal: { ...original.proposal, state: approvalState, operationId: null },
  };
}
it.each(['maker', 'checker'] as const)(
  'cancels held workload %s proof on unmount without changing original custody',
  async (kind) => {
    writeBoundPolicyState('openpc:workload-workflow:v1', actor, review);
    const original = localStorage.getItem('openpc:workload-workflow:v1'),
      held = holdStepUp();
    const fetcher = vi.spyOn(globalThis, 'fetch').mockImplementation(async () =>
      Response.json({
        ...state,
        approvals: [requestedWorkloadApproval(kind === 'maker' ? 'APPROVED' : 'REQUESTED')],
      }),
    );
    const view = renderExpandedWorkload();
    fireEvent.click(
      await findWorkloadControl('button', {
        name:
          kind === 'maker'
            ? 'Verify and commit workload change'
            : 'Verify and approve workload change',
      }),
    );
    await waitFor(() => expect(held.entered).toHaveBeenCalledOnce());
    const completed = expect(held.completion()).rejects.toMatchObject({ name: 'AbortError' });
    view.unmount();
    expect(held.lifecycle().signal?.aborted).toBe(true);
    await act(async () => {
      held.release();
      await completed;
    });
    expect(fetcher.mock.calls.some(([, init]) => init?.method === 'POST')).toBe(false);
    expect(localStorage.getItem('openpc:workload-workflow:v1')).toBe(original);
  },
);
it.each(['maker', 'checker'] as const)(
  'sends one exact current workload %s command after held proof despite duplicate clicks',
  async (kind) => {
    writeBoundPolicyState('openpc:workload-workflow:v1', actor, review);
    const held = holdStepUp(),
      posts: unknown[] = [];
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (_input, init) => {
      if (init?.method === 'POST') {
        posts.push(JSON.parse(String(init.body)));
        return Response.json({
          truthState: 'SUCCESS',
          operationId: id('850'),
          readback: certificate,
        });
      }
      return Response.json(
        posts.length
          ? consumed
          : {
              ...state,
              approvals: [requestedWorkloadApproval(kind === 'maker' ? 'APPROVED' : 'REQUESTED')],
            },
      );
    });
    renderExpandedWorkload();
    const button = await findWorkloadControl('button', {
      name:
        kind === 'maker'
          ? 'Verify and commit workload change'
          : 'Verify and approve workload change',
    });
    act(() => {
      fireEvent.click(button);
      fireEvent.click(button);
    });
    await waitFor(() => expect(held.entered).toHaveBeenCalledOnce());
    await act(async () => {
      held.release();
      await held.completion();
    });
    await waitFor(() =>
      expect(workloadControl('button', { name: 'Refresh workload approvals' })).toBeEnabled(),
    );
    expect(posts).toEqual([
      kind === 'maker'
        ? {
            command: 'COMMIT',
            reviewToken: review.reviewToken,
            approvalRequestId: review.approvalRequestId,
          }
        : {
            command: 'APPROVE',
            approvalRequestId: review.approvalRequestId,
            candidateDigest: review.review.candidateDigest,
            expectedRevision: '2',
          },
    ]);
    expect(performWebAuthnStepUp).toHaveBeenCalledWith(
      { ...review.review.stepUp, stepUp: 'FRESH_WEBAUTHN_MAX_5M' },
      review.review.stepUp,
      expect.objectContaining({ signal: expect.anything(), isCurrent: expect.any(Function) }),
    );
  },
);
it.each(['maker', 'checker'] as const)(
  'redacts private authenticator exceptions and emits no workload %s command',
  async (kind) => {
    writeBoundPolicyState('openpc:workload-workflow:v1', actor, review);
    const original = localStorage.getItem('openpc:workload-workflow:v1');
    vi.mocked(performWebAuthnStepUp).mockRejectedValueOnce(
      new Error('PRIVATE_AUTHENTICATOR_DETAIL'),
    );
    const fetcher = vi.spyOn(globalThis, 'fetch').mockImplementation(async () =>
      Response.json({
        ...state,
        approvals: [requestedWorkloadApproval(kind === 'maker' ? 'APPROVED' : 'REQUESTED')],
      }),
    );
    renderExpandedWorkload();
    fireEvent.click(
      await findWorkloadControl('button', {
        name:
          kind === 'maker'
            ? 'Verify and commit workload change'
            : 'Verify and approve workload change',
      }),
    );
    await screen.findByText(
      'Workload request could not be confirmed. Read the saved operation before retrying.',
    );
    expect(performWebAuthnStepUp).toHaveBeenCalledOnce();
    expect(performWebAuthnStepUp).toHaveBeenCalledWith(
      { ...review.review.stepUp, stepUp: 'FRESH_WEBAUTHN_MAX_5M' },
      review.review.stepUp,
      expect.objectContaining({ signal: expect.anything(), isCurrent: expect.any(Function) }),
    );
    await waitFor(() =>
      expect(workloadControl('button', { name: 'Refresh workload approvals' })).toBeEnabled(),
    );
    expect(document.body.textContent).not.toContain('PRIVATE_AUTHENTICATOR_DETAIL');
    expect(fetcher.mock.calls.some(([, init]) => init?.method === 'POST')).toBe(false);
    expect(localStorage.getItem('openpc:workload-workflow:v1')).toBe(original);
  },
);
it.each(['credential', 'Participant'] as const)(
  'rejects a committed workload readback for another %s without publishing it',
  async (field) => {
    writeBoundPolicyState('openpc:workload-workflow:v1', actor, review);
    const fetcher = vi.spyOn(globalThis, 'fetch').mockImplementation(async (_input, init) =>
      Response.json(
        init?.method === 'POST'
          ? {
              truthState: 'SUCCESS',
              operationId: id('850'),
              readback: {
                ...certificate,
                ...(field === 'credential'
                  ? { credentialId: id('999') }
                  : { participantId: id('102') }),
              },
            }
          : { ...state, approvals: [requestedWorkloadApproval('APPROVED')] },
      ),
    );
    renderExpandedWorkload();
    fireEvent.click(
      await findWorkloadControl('button', { name: 'Verify and commit workload change' }),
    );
    await screen.findByText('Certificate readback belongs to a different context.');
    await waitFor(() =>
      expect(workloadControl('button', { name: 'Refresh workload approvals' })).toBeEnabled(),
    );
    expect(screen.queryByLabelText('Workload certificate result')).not.toBeInTheDocument();
    expect(fetcher.mock.calls.filter(([, init]) => init?.method === 'POST')).toHaveLength(1);
    expect(localStorage.getItem('openpc:workload-workflow:v1')).not.toBeNull();
  },
);
it('keeps an accepted workload submission and original readback available when browser persistence throws', async () => {
  writeBoundPolicyState('openpc:workload-workflow:v1', actor, {
    reviewToken: review.reviewToken,
    review: review.review,
  });
  const original = localStorage.getItem('openpc:workload-workflow:v1');
  const posts: unknown[] = [];
  vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
    if (init?.method === 'POST') {
      posts.push(JSON.parse(String(init.body)));
      return Response.json({
        ...review,
        approval: { approvalRequestId: review.approvalRequestId },
      });
    }
    return Response.json(String(input).includes('credentialId=') ? certificate : state);
  });
  renderExpandedWorkload();
  const button = await findWorkloadControl('button', { name: 'Request workload approval' });
  vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => {
    throw new Error('PRIVATE_STORAGE_DETAIL');
  });
  fireEvent.click(button);
  await screen.findByText(
    'Approval requested. The assigned checker must review it in their own session.',
  );
  await waitFor(() =>
    expect(workloadControl('button', { name: 'Read saved workload' })).toBeEnabled(),
  );
  expect(posts).toEqual([{ command: 'SUBMIT', reviewToken: review.reviewToken }]);
  expect(localStorage.getItem('openpc:workload-workflow:v1')).toBe(original);
  expect(document.body.textContent).not.toContain('PRIVATE_STORAGE_DETAIL');
  fireEvent.click(workloadControl('button', { name: 'Read saved workload' }));
  await screen.findByLabelText('Workload certificate result');
  expect(posts).toHaveLength(1);
});

it.each(['success', 'interruption'] as const)(
  'preserves issued workload original custody after late %s without starting post-unmount reads',
  async (outcome) => {
    writeBoundPolicyState('openpc:workload-workflow:v1', actor, review);
    const original = localStorage.getItem('openpc:workload-workflow:v1');
    let resolve!: (value: Response) => void, reject!: (cause: Error) => void;
    const pending = new Promise<Response>((yes, no) => {
      resolve = yes;
      reject = no;
    });
    const fetcher = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      if (init?.method === 'POST') return pending;
      return Response.json({ ...state, approvals: [requestedWorkloadApproval('APPROVED')] });
    });
    const view = renderExpandedWorkload();
    fireEvent.click(
      await findWorkloadControl('button', { name: 'Verify and commit workload change' }),
    );
    await waitFor(() =>
      expect(fetcher.mock.calls.filter(([, init]) => init?.method === 'POST')).toHaveLength(1),
    );
    const issuedCalls = fetcher.mock.calls.length;
    view.unmount();
    await act(async () => {
      if (outcome === 'success') resolve(Response.json({ truthState: 'SUCCESS' }));
      else reject(new Error('PRIVATE_LOST_MUTATION_RESPONSE'));
      await pending.catch(() => undefined);
    });
    expect(fetcher.mock.calls).toHaveLength(issuedCalls);
    expect(localStorage.getItem('openpc:workload-workflow:v1')).toBe(original);
    expect(performWebAuthnStepUp).toHaveBeenCalledOnce();
  },
);

function discoveryCaller(lane: 'maker' | 'checker' = 'maker') {
  const fixture = discoveryFixture();
  const enrollment = fixture.source.enrollment;
  const intent = {
    ...fixture.intent,
    validFrom: new Date(Date.now() - 60000).toISOString(),
    validUntil: new Date(Date.now() + 900000).toISOString(),
  };
  const actor = {
    sessionId: id('701'),
    principalId: intent.administrators[lane === 'maker' ? 0 : 1].principalId,
    participantId: enrollment.participantId,
    contextEpoch: '2',
  };
  const binding = intent.certificateRecovery;
  const originalReview = {
    reviewToken: 'r'.repeat(100),
    review: {
      ...review.review,
      mutation: 'ROTATE' as const,
      candidate: {
        replacedCredentialId: binding.predecessorCredentialId,
        credentialId: binding.successorCredentialId,
        publicKeySpkiDer: binding.successorPublicKeySpkiDer,
      },
      resourceId: binding.predecessorCredentialId,
      expectedRevision: binding.predecessorRevision,
      checkerPrincipalId: intent.administrators[1].principalId,
      expiresAt: new Date(Date.now() + 300000).toISOString(),
      stepUp: {
        ...review.review.stepUp,
        resourceId: binding.predecessorCredentialId,
      },
    },
  };
  const view: DiscoveryRecoveryView = {
    recoveryId: intent.recoveryId,
    enrollmentId: intent.enrollmentId,
    intent,
    intentDigest: 'sha256:' + 'a'.repeat(64),
    state: 'ACTIVE',
    revision: '5',
    authority: 'DISCOVERY_CERTIFICATE_REPLACEMENT_ONLY',
    assurance: enrollment.assurance,
    actors: {
      executorPrincipalId: enrollment.recoveryPrincipal.principalId,
      custodianPrincipalIds: [
        enrollment.custodians[0].principalId,
        enrollment.custodians[1].principalId,
      ],
      administratorPrincipalIds: enrollment.administratorPrincipalIds,
    },
    proofs: [],
  };
  const onStatus = vi.fn();
  const props = {
    view,
    actor,
    enrollmentId: intent.enrollmentId,
    privacyDomainId: enrollment.privacyDomainId,
    recoveryId: intent.recoveryId,
    busy: false,
    now: Date.now(),
    post: vi.fn(async () => view),
    assertion: vi.fn(async () => 'assertion'),
    run: async (work: () => Promise<void>) => {
      try {
        await work();
      } catch {
        onStatus('Original command unavailable; read the original case.');
      }
    },
    onView: vi.fn(),
    onCase: vi.fn(),
    onStatus,
  };
  const storageKey =
    'openpc:discovery-certificate-review:' +
    JSON.stringify([props.enrollmentId, props.privacyDomainId, props.recoveryId, actor]);
  return { props, originalReview, storageKey, binding, intent };
}

it.each([false, true])(
  'Discovery caller preserves the original admitted URN through COMMIT with storage failure=%s',
  async (unavailableStorage) => {
    const f = discoveryCaller();
    localStorage.setItem(f.storageKey, JSON.stringify(f.originalReview));
    const approvalRequestId = id('801');
    const fetch = vi
      .spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(
        Response.json({
          ...f.originalReview,
          approval: { approvalRequestId: 'urn:openpc:resource:' + approvalRequestId },
        }),
      )
      .mockResolvedValueOnce(Response.json({ truthState: 'SUCCESS' }))
      .mockResolvedValueOnce(
        Response.json({
          truthState: 'SUCCESS',
          readback: {
            ...certificate,
            credentialId: f.binding.successorCredentialId,
            participantId: f.props.actor.participantId,
            principalId: f.binding.workloadPrincipalId,
            workloadId: 'urn:openpc:workload:' + f.binding.targetId,
            replacedCredentialId: f.binding.predecessorCredentialId,
          },
        }),
      );
    render(<DiscoveryCertificateRecoveryWorkflow {...f.props} />);
    const submit = await screen.findByRole('button', {
      name: 'Verify and submit certificate rotation',
    });
    if (unavailableStorage)
      vi.spyOn(Storage.prototype, 'setItem').mockImplementationOnce(() => {
        throw new Error('Storage unavailable');
      });
    await userEvent.setup().click(submit);
    const commit = screen.getByRole('button', { name: 'Verify and commit certificate rotation' });
    await waitFor(() => expect(commit).toBeEnabled());
    if (unavailableStorage)
      expect(screen.getByRole('alert')).toHaveTextContent('retained in this session');
    else
      expect(JSON.parse(localStorage.getItem(f.storageKey)!).approvalRequestId).toBe(
        approvalRequestId,
      );
    expect(submit).toBeDisabled();
    await userEvent.setup().click(commit);
    await waitFor(() => expect(fetch).toHaveBeenCalledTimes(3));
    const commands = fetch.mock.calls
      .filter(([, init]) => init?.method === 'POST')
      .map(([, init]) => JSON.parse(String(init!.body)));
    expect(commands.map((v) => v.command)).toEqual(['SUBMIT', 'COMMIT']);
    expect(commands[1]).toEqual({
      command: 'COMMIT',
      reviewToken: f.originalReview.reviewToken,
      approvalRequestId,
      discoveryRecovery: {
        enrollmentId: f.props.enrollmentId,
        recoveryId: f.props.recoveryId,
        privacyDomainId: f.props.privacyDomainId,
      },
    });
    expect(f.props.onStatus).not.toHaveBeenCalledWith(
      'Original command unavailable; read the original case.',
    );
  },
);

it('Discovery caller normalizes the actual original checker READ URN without changing its candidate or revision', async () => {
  const f = discoveryCaller('checker');
  const approvalRequestId = id('801');
  const state = {
    actor: { ...f.props.actor, privacyDomainId: f.props.privacyDomainId },
    approvals: [
      {
        approvalRequestId: 'urn:openpc:resource:' + approvalRequestId,
        candidateDigest: f.originalReview.review.candidateDigest,
        makerSubjectRef: 'urn:openpc:resource:' + f.intent.administrators[0].principalId,
        checkerSubjectRef: 'urn:openpc:resource:' + f.props.actor.principalId,
        revision: '3',
        state: 'REQUESTED',
        proposal: {
          candidateDigest: f.originalReview.review.candidateDigest,
          resourceId: f.binding.predecessorCredentialId,
          makerPrincipalId: f.intent.administrators[0].principalId,
          catalogOperationId: 'ID-OP-WORKLOAD-ROTATE',
          expectedRevision: f.binding.predecessorRevision,
          state: 'APPROVED',
          operationId: null,
          expiresAt: f.originalReview.review.expiresAt,
          candidate: f.originalReview.review.candidate,
          approval: { approvalRequestId, reason: null },
        },
        stepUp: f.originalReview.review.stepUp,
      },
    ],
    nextCursor: null,
  };
  const fetch = vi
    .spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(Response.json(state))
    .mockResolvedValueOnce(Response.json({ truthState: 'PENDING' }))
    .mockResolvedValueOnce(Response.json({ ...state, approvals: [] }));
  render(<DiscoveryCertificateRecoveryWorkflow {...f.props} />);
  await userEvent
    .setup()
    .click(screen.getByRole('button', { name: 'Read original certificate rotation' }));
  await userEvent.setup().click(
    await screen.findByRole('button', {
      name: 'Verify and approve certificate candidate urn:openpc:resource:' + approvalRequestId,
    }),
  );
  await waitFor(() => expect(fetch).toHaveBeenCalledTimes(3));
  const command = JSON.parse(String(fetch.mock.calls[1]![1]!.body));
  expect(command).toEqual({
    command: 'APPROVE',
    approvalRequestId,
    candidateDigest: f.originalReview.review.candidateDigest,
    expectedRevision: '3',
    discoveryRecovery: {
      enrollmentId: f.props.enrollmentId,
      recoveryId: f.props.recoveryId,
      privacyDomainId: f.props.privacyDomainId,
    },
  });
  expect(f.props.onStatus).not.toHaveBeenCalledWith(
    'Original command unavailable; read the original case.',
  );
});

it.each(['multiple', 'malformed', 'unreadable', 'missing retained'])(
  'Discovery preparation stays blocked for %s custody',
  async (failure) => {
    const f = discoveryCaller();
    if (failure === 'malformed') localStorage.setItem(f.storageKey, '{bad');
    if (failure === 'multiple') {
      for (const n of ['910', '911'])
        localStorage.setItem(
          'openpc:discovery-certificate-review:' +
            JSON.stringify([f.props.enrollmentId, f.props.privacyDomainId, id(n), f.props.actor]),
          JSON.stringify(f.originalReview),
        );
    }
    if (failure === 'unreadable')
      vi.spyOn(Storage.prototype, 'getItem').mockImplementation(() => {
        throw new Error('private storage');
      });
    const fetch = vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      Response.json({
        actor: { ...f.props.actor, privacyDomainId: f.props.privacyDomainId },
        approvals: [],
        nextCursor: null,
        preapprovalState: 'PRESENT',
      }),
    );
    render(<DiscoveryCertificateRecoveryWorkflow {...f.props} />);
    await userEvent
      .setup()
      .type(
        screen.getByLabelText('Certificate rotation reason'),
        'Retain the exact original rotation request.',
      );
    const prepare = screen.getByRole('button', { name: 'Prepare enrolled certificate rotation' });
    expect(prepare).toBeDisabled();
    await userEvent
      .setup()
      .click(screen.getByRole('button', { name: 'Read original certificate rotation' }));
    await waitFor(() => expect(fetch).toHaveBeenCalledTimes(1));
    expect(prepare).toBeDisabled();
    expect(fetch.mock.calls.some(([, init]) => init?.method === 'POST')).toBe(false);
  },
);
it('Discovery preparation requires an authenticated explicit ABSENT read', async () => {
  const f = discoveryCaller();
  const fetch = vi.spyOn(globalThis, 'fetch').mockResolvedValue(
    Response.json({
      actor: { ...f.props.actor, privacyDomainId: f.props.privacyDomainId },
      approvals: [],
      nextCursor: null,
      preapprovalState: 'ABSENT',
    }),
  );
  render(<DiscoveryCertificateRecoveryWorkflow {...f.props} />);
  await userEvent
    .setup()
    .type(
      screen.getByLabelText('Certificate rotation reason'),
      'Create only the exact enrolled rotation.',
    );
  const prepare = screen.getByRole('button', { name: 'Prepare enrolled certificate rotation' });
  expect(prepare).toBeDisabled();
  await userEvent
    .setup()
    .click(screen.getByRole('button', { name: 'Read original certificate rotation' }));
  await waitFor(() => expect(prepare).toBeEnabled());
  expect(fetch).toHaveBeenCalledTimes(1);
});

it.each(['http denial', 'invalid body', 'actor mismatch'])(
  'Discovery removes stale absence after %s read',
  async (failure) => {
    const f = discoveryCaller(),
      actor = { ...f.props.actor, privacyDomainId: f.props.privacyDomainId };
    const fetch = vi
      .spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(
        Response.json({ actor, approvals: [], nextCursor: null, preapprovalState: 'ABSENT' }),
      );
    if (failure === 'http denial')
      fetch.mockResolvedValueOnce(Response.json({ code: 'PC-AUTH-0005' }, { status: 404 }));
    if (failure === 'invalid body')
      fetch.mockResolvedValueOnce(Response.json({ incomplete: true }));
    if (failure === 'actor mismatch')
      fetch.mockResolvedValueOnce(
        Response.json({
          actor: { ...actor, sessionId: id('998') },
          approvals: [],
          nextCursor: null,
          preapprovalState: 'ABSENT',
        }),
      );
    render(<DiscoveryCertificateRecoveryWorkflow {...f.props} />);
    await userEvent
      .setup()
      .type(
        screen.getByLabelText('Certificate rotation reason'),
        'Preserve the exact enrolled original target.',
      );
    const prepare = screen.getByRole('button', { name: 'Prepare enrolled certificate rotation' }),
      read = screen.getByRole('button', { name: 'Read original certificate rotation' });
    await userEvent.setup().click(read);
    await waitFor(() => expect(prepare).toBeEnabled());
    await userEvent.setup().click(read);
    await waitFor(() =>
      expect(f.props.onStatus).toHaveBeenCalledWith(
        'Original command unavailable; read the original case.',
      ),
    );
    expect(prepare).toBeDisabled();
    expect(fetch.mock.calls.some(([, init]) => init?.method === 'POST')).toBe(false);
  },
);

it.each([false, true])(
  'Discovery approved resume preserves metadata custody with ambiguous response=%s',
  async (ambiguous) => {
    const f = discoveryCaller();
    f.intent.schemaVersion = 2;
    const originalApproval = id('801'),
      nextApproval = id('802');
    const draft = {
      ...f.originalReview,
      review: {
        ...f.originalReview.review,
        resumeDraft: { approvalRequestId: originalApproval, expectedAttempt: '2' },
        stepUp: {
          ...f.originalReview.review.stepUp,
          actionIntentId: 'ACT-APPROVAL_REQUESTS_UPDATE_RESOURCE-V1',
          resourceId: originalApproval,
          resourceDigest: 'sha256:' + 'd'.repeat(64),
        },
      },
    };
    localStorage.setItem(f.storageKey, JSON.stringify(draft));
    const fetch = vi.spyOn(globalThis, 'fetch').mockImplementationOnce(async () => {
      expect(JSON.parse(localStorage.getItem(f.storageKey)!).resumeSent).toBe(true);
      return ambiguous
        ? Response.json({ code: 'PC-INTEGRATION-5001' }, { status: 503 })
        : Response.json(
            {
              ...f.originalReview,
              approval: { approvalRequestId: 'urn:openpc:resource:' + nextApproval },
            },
            { status: 202 },
          );
    });
    render(<DiscoveryCertificateRecoveryWorkflow {...f.props} />);
    const resume = await screen.findByRole('button', {
      name: 'Verify and resume original approval',
    });
    await userEvent.setup().click(resume);
    await waitFor(() => expect(fetch).toHaveBeenCalledTimes(1));
    expect(JSON.parse(String(fetch.mock.calls[0]![1]!.body))).toMatchObject({
      command: 'RESUME',
      reviewToken: draft.reviewToken,
    });
    expect(vi.mocked(performWebAuthnStepUp).mock.calls[0]![1]).toMatchObject({
      actionIntentId: 'ACT-APPROVAL_REQUESTS_UPDATE_RESOURCE-V1',
      resourceId: originalApproval,
      resourceDigest: 'sha256:' + 'd'.repeat(64),
    });
    if (ambiguous) {
      await waitFor(() => expect(resume).toBeDisabled());
      expect(
        screen.getByRole('button', { name: 'Verify and commit certificate rotation' }),
      ).toBeDisabled();
      expect(
        JSON.parse(localStorage.getItem(f.storageKey)!).review.resumeDraft.approvalRequestId,
      ).toBe(originalApproval);
      expect(screen.getByRole('status')).toHaveTextContent(
        'Read the original certificate rotation',
      );
    } else {
      await waitFor(() =>
        expect(JSON.parse(localStorage.getItem(f.storageKey)!).approvalRequestId).toBe(
          nextApproval,
        ),
      );
      expect(JSON.parse(localStorage.getItem(f.storageKey)!).review.resumeDraft).toBeUndefined();
      expect(JSON.parse(localStorage.getItem(f.storageKey)!).review.stepUp.actionIntentId).toBe(
        'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
      );
    }
  },
);

it('finds an original after re-login with keyboard submission and no replacement mutation authority', async () => {
  const renewed = { ...actor, sessionId: id('702') };
  writeBoundPolicyState('openpc:workload-workflow:v1', actor, review);
  const fetcher = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) =>
    Response.json({
      ...(String(input).includes('originalApprovalRequestId=') ? consumed : state),
      actor: renewed,
    }),
  );
  renderExpandedWorkload();
  await screen.findByText(`Signed-in principal: ${actor.principalId}`);
  const user = userEvent.setup();
  await user.type(
    workloadControl('textbox', { name: 'Original workload approval ID' }),
    `${review.approvalRequestId}{Enter}`,
  );
  await screen.findByText(
    `Original workload operation committed: ${id('850')}. Certificate readback is available separately.`,
  );
  expect(screen.queryByLabelText('Workload change review')).not.toBeInTheDocument();
  expect(fetcher.mock.calls.at(-1)![0]).toBe(
    `/api/v1/ui/workload-workbench?originalApprovalRequestId=${review.approvalRequestId}`,
  );
  expect(fetcher.mock.calls.some(([, init]) => init?.method === 'POST')).toBe(false);
  expect(performWebAuthnStepUp).not.toHaveBeenCalled();
});

it.each(['response loss', 'pending 202', 'malformed success'])(
  'retains the exact sent commit through %s and remount until a positive original read',
  async (failure) => {
    writeBoundPolicyState('openpc:workload-workflow:v1', actor, review);
    let committed = false;
    const posts: unknown[] = [];
    const fetcher = vi.spyOn(globalThis, 'fetch').mockImplementation(async (_input, init) => {
      if (init?.method === 'POST') {
        posts.push(JSON.parse(String(init.body)));
        if (failure === 'response loss') throw new Error('PRIVATE_LOST_RESPONSE');
        return Response.json(
          failure === 'pending 202' ? { truthState: 'WRITE_AMBIGUITY' } : { truthState: 'SUCCESS' },
          { status: 202 },
        );
      }
      return Response.json(
        committed ? consumed : { ...state, approvals: [requestedWorkloadApproval('APPROVED')] },
      );
    });
    const view = renderExpandedWorkload();
    fireEvent.click(
      await findWorkloadControl('button', { name: 'Verify and commit workload change' }),
    );
    await waitFor(() => expect(posts).toHaveLength(1));
    await waitFor(() =>
      expect(workloadControl('button', { name: 'Refresh workload approvals' })).toBeEnabled(),
    );
    expect(workloadControl('button', { name: 'Verify and commit workload change' })).toBeDisabled();
    expect(workloadControl('button', { name: 'Prepare workload change' })).toBeDisabled();
    expect(JSON.parse(localStorage.getItem(originalPendingKey)!).value).toMatchObject({
      command: 'COMMIT',
      approvalRequestId: review.approvalRequestId,
    });
    expect(localStorage.getItem(originalPendingKey)).not.toContain(review.reviewToken);
    view.unmount();
    renderExpandedWorkload();
    await findWorkloadControl('button', { name: 'Read original workload outcome' });
    expect(workloadControl('button', { name: 'Verify and commit workload change' })).toBeDisabled();
    committed = true;
    fireEvent.click(workloadControl('button', { name: 'Read original workload outcome' }));
    await screen.findByText(
      `Original workload operation committed: ${id('850')}. Certificate readback is available separately.`,
    );
    expect(
      screen.queryByRole('button', { name: 'Read original workload outcome' }),
    ).not.toBeInTheDocument();
    expect(workloadControl('button', { name: 'Verify and commit workload change' })).toBeDisabled();
    expect(fetcher.mock.calls.at(-1)![0]).toBe(
      `/api/v1/ui/workload-workbench?originalApprovalRequestId=${review.approvalRequestId}`,
    );
    expect(posts).toEqual([
      {
        command: 'COMMIT',
        reviewToken: review.reviewToken,
        approvalRequestId: review.approvalRequestId,
      },
    ]);
    expect(document.body.textContent).not.toContain('PRIVATE_LOST_RESPONSE');
  },
);

it.each([
  'missing',
  'wrong approval',
  'wrong digest',
  'wrong candidate',
  'wrong revision',
  'pending',
])(
  'keeps sent custody when original readback is %s and ignores changed-ID attempts',
  async (defect) => {
    writeBoundPolicyState('openpc:workload-workflow:v1', actor, review);
    retainWorkloadCommand();
    const observed = structuredClone(consumed);
    const item = observed.approvals[0]!;
    if (defect === 'missing') observed.approvals = [];
    if (defect === 'wrong approval') item.approvalRequestId = `urn:openpc:resource:${id('999')}`;
    if (defect === 'wrong digest') item.candidateDigest = `sha256:${'f'.repeat(64)}`;
    if (defect === 'wrong candidate') item.proposal.candidate.credentialId = id('999');
    if (defect === 'wrong revision') item.proposal.expectedRevision = '1';
    if (defect === 'pending') {
      item.proposal.state = 'APPROVED';
      item.proposal.operationId = null as unknown as string;
    }
    const fetcher = vi
      .spyOn(globalThis, 'fetch')
      .mockImplementation(async (input) =>
        Response.json(String(input).includes('originalApprovalRequestId=') ? observed : state),
      );
    renderExpandedWorkload();
    fireEvent.click(
      await findWorkloadControl('button', { name: 'Read original workload outcome' }),
    );
    await waitFor(() =>
      expect(workloadControl('button', { name: 'Refresh workload approvals' })).toBeEnabled(),
    );
    expect(workloadControl('button', { name: 'Read original workload outcome' })).toBeVisible();
    expect(workloadControl('button', { name: 'Prepare workload change' })).toBeDisabled();
    expect(workloadControl('textbox', { name: 'Original workload approval ID' })).toBeDisabled();
    fireEvent.click(workloadControl('button', { name: 'Verify and commit workload change' }));
    expect(fetcher.mock.calls.some(([, init]) => init?.method === 'POST')).toBe(false);
    expect(JSON.parse(localStorage.getItem(originalPendingKey)!).value.command).toBe('COMMIT');
  },
);

it.each([403, 404, 503])(
  'preserves unresolved custody across exact read denial %s',
  async (status) => {
    writeBoundPolicyState('openpc:workload-workflow:v1', actor, review);
    retainWorkloadCommand();
    const original = localStorage.getItem(originalPendingKey);
    const fetcher = vi
      .spyOn(globalThis, 'fetch')
      .mockImplementation(async (input) =>
        String(input).includes('originalApprovalRequestId=')
          ? new Response('PRIVATE_DENIAL', { status })
          : Response.json(state),
      );
    renderExpandedWorkload();
    fireEvent.click(
      await findWorkloadControl('button', { name: 'Read original workload outcome' }),
    );
    const alert = await findWorkloadControl('alert');
    expect(alert).toHaveFocus();
    expect(localStorage.getItem(originalPendingKey)).toBe(original);
    expect(workloadControl('button', { name: 'Prepare workload change' })).toBeDisabled();
    if (status !== 503)
      expect(screen.queryByLabelText('Workload change review')).not.toBeInTheDocument();
    expect(document.body.textContent).not.toContain('PRIVATE_DENIAL');
    expect(fetcher.mock.calls.some(([, init]) => init?.method === 'POST')).toBe(false);
  },
);

it('reconciles a lost submit by exact digest/revision without sending a second proposal', async () => {
  const unsent = { reviewToken: review.reviewToken, review: review.review };
  writeBoundPolicyState('openpc:workload-workflow:v1', actor, unsent);
  const posts: unknown[] = [];
  const fetcher = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
    if (init?.method === 'POST') {
      posts.push(JSON.parse(String(init.body)));
      throw new Error('lost');
    }
    return Response.json(
      String(input).includes('candidateDigest=')
        ? { ...state, approvals: [requestedWorkloadApproval()] }
        : state,
    );
  });
  renderExpandedWorkload();
  fireEvent.click(await findWorkloadControl('button', { name: 'Request workload approval' }));
  await screen.findByText(
    'Original workload approval: REQUESTED. The workload effect is not confirmed.',
  );
  expect(workloadControl('button', { name: 'Request workload approval' })).toBeDisabled();
  expect(JSON.parse(localStorage.getItem('openpc:workload-workflow:v1')!).value).toEqual(review);
  const selector = new URL(String(fetcher.mock.calls.at(-1)![0]), 'http://localhost').searchParams;
  expect(selector.get('candidateDigest')).toBe(review.review.candidateDigest);
  expect(selector.get('expectedRevision')).toBe('0');
  expect(posts).toEqual([{ command: 'SUBMIT', reviewToken: review.reviewToken }]);
});

it.each(['session', 'privacy', 'principal', 'Participant', 'epoch'])(
  'purges all visible original data on a %s switch while preserving unresolved custody',
  async (change) => {
    writeBoundPolicyState('openpc:workload-workflow:v1', actor, review);
    retainWorkloadCommand();
    const original = localStorage.getItem(originalPendingKey);
    const nextActor = {
      ...actor,
      ...(change === 'session' ? { sessionId: id('702') } : {}),
      ...(change === 'privacy' ? { privacyDomainId: id('202') } : {}),
      ...(change === 'principal' ? { principalId: id('113') } : {}),
      ...(change === 'Participant' ? { participantId: id('102') } : {}),
      ...(change === 'epoch' ? { contextEpoch: '3' } : {}),
    };
    vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(Response.json(state))
      .mockResolvedValueOnce(Response.json({ ...state, actor: nextActor }));
    renderExpandedWorkload();
    await findWorkloadControl('button', { name: 'Read original workload outcome' });
    fireEvent.change(workloadControl('textbox', { name: 'New credential ID' }), {
      target: { value: candidate.credentialId },
    });
    fireEvent.click(workloadControl('button', { name: 'Refresh workload approvals' }));
    await waitFor(() =>
      expect(screen.queryByLabelText('Workload change review')).not.toBeInTheDocument(),
    );
    expect(workloadControl('textbox', { name: 'New credential ID' })).toHaveValue('');
    expect(document.body.textContent).not.toContain(review.review.candidateDigest);
    expect(localStorage.getItem(originalPendingKey)).toBe(original);
  },
);

it('does not publish a late original outcome after unmount and a different context restart', async () => {
  writeBoundPolicyState('openpc:workload-workflow:v1', actor, review);
  retainWorkloadCommand();
  const delayed = deferredResponse();
  const fetcher = vi
    .spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(Response.json(state))
    .mockImplementationOnce(() => delayed.promise);
  const view = renderExpandedWorkload();
  fireEvent.click(await findWorkloadControl('button', { name: 'Read original workload outcome' }));
  await waitFor(() => expect(fetcher).toHaveBeenCalledTimes(2));
  view.unmount();
  expect(fetcher.mock.calls[1]![1]?.signal?.aborted).toBe(true);
  fetcher.mockResolvedValueOnce(
    Response.json({ ...state, actor: { ...actor, principalId: id('113'), sessionId: id('702') } }),
  );
  renderExpandedWorkload();
  await screen.findByText(`Signed-in principal: ${id('113')}`);
  await act(async () => delayed.resolve(Response.json(consumed)));
  expect(document.body.textContent).not.toContain(id('850'));
  expect(
    screen.queryByRole('button', { name: 'Read original workload outcome' }),
  ).not.toBeInTheDocument();
  expect(fetcher.mock.calls.some(([, init]) => init?.method === 'POST')).toBe(false);
});

it('stops a cold commit at exact consumed readback even when the catalogue page omitted it', async () => {
  writeBoundPolicyState('openpc:workload-workflow:v1', actor, review);
  const fetcher = vi
    .spyOn(globalThis, 'fetch')
    .mockImplementation(async (input) =>
      Response.json(String(input).includes('originalApprovalRequestId=') ? consumed : state),
    );
  renderExpandedWorkload();
  fireEvent.click(
    await findWorkloadControl('button', { name: 'Verify and commit workload change' }),
  );
  await screen.findByText(
    `Original workload operation committed: ${id('850')}. Certificate readback is available separately.`,
  );
  expect(fetcher.mock.calls.some(([, init]) => init?.method === 'POST')).toBe(false);
  expect(performWebAuthnStepUp).not.toHaveBeenCalled();
});

it('reconciles a lost checker response from the original approval without repeating the decision', async () => {
  const checkerActor = { ...actor, principalId: id('112'), sessionId: id('702') };
  let approved = false;
  const posts: unknown[] = [];
  const fetcher = vi.spyOn(globalThis, 'fetch').mockImplementation(async (_input, init) => {
    if (init?.method === 'POST') {
      posts.push(JSON.parse(String(init.body)));
      approved = true;
      throw new Error('lost decision');
    }
    return Response.json({
      ...state,
      actor: checkerActor,
      approvals: [requestedWorkloadApproval(approved ? 'APPROVED' : 'REQUESTED')],
    });
  });
  renderExpandedWorkload();
  fireEvent.click(
    await findWorkloadControl('button', { name: 'Verify and approve workload change' }),
  );
  await screen.findByText(
    'Original workload approval: APPROVED. The workload effect is not confirmed.',
  );
  expect(
    screen.queryByRole('button', { name: 'Read original workload outcome' }),
  ).not.toBeInTheDocument();
  expect(fetcher.mock.calls.at(-1)![0]).toBe(
    `/api/v1/ui/workload-workbench?originalApprovalRequestId=${review.approvalRequestId}`,
  );
  expect(posts).toHaveLength(1);
});

it('retains unresolved original selection across re-login while discarding the old review authority', async () => {
  writeBoundPolicyState('openpc:workload-workflow:v1', actor, review);
  retainWorkloadCommand();
  const renewed = { ...actor, sessionId: id('702'), contextEpoch: '3' };
  const fetcher = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) =>
    Response.json({
      ...(String(input).includes('originalApprovalRequestId=') ? consumed : state),
      actor: renewed,
    }),
  );
  renderExpandedWorkload();
  const read = await findWorkloadControl('button', { name: 'Read original workload outcome' });
  expect(workloadControl('button', { name: 'Prepare workload change' })).toBeDisabled();
  expect(screen.queryByLabelText('Workload change review')).not.toBeInTheDocument();
  expect(document.body.textContent).not.toContain(review.review.candidateDigest);
  fireEvent.click(read);
  await screen.findByText(
    `Original workload operation committed: ${id('850')}. Certificate readback is available separately.`,
  );
  expect(fetcher.mock.calls.at(-1)![0]).toBe(
    `/api/v1/ui/workload-workbench?originalApprovalRequestId=${review.approvalRequestId}`,
  );
  expect(fetcher.mock.calls.some(([, init]) => init?.method === 'POST')).toBe(false);
  expect(performWebAuthnStepUp).not.toHaveBeenCalled();
});

it.each(['PLATFORM_OPERATOR', 'USER', 'WORKLOAD'])(
  'checks the selected Platform operator catalogue before choosing a checker (%s)',
  async (returnedKind) => {
    const fetch = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      if (!String(input).startsWith('/api/v1/ui/principal-catalogue')) return Response.json(state);
      const page = principalChoices('USER');
      return Response.json({
        ...page,
        items: page.items.map((item) => ({
          ...item,
          effect: { ...item.effect, kind: returnedKind },
        })),
      });
    });
    renderExpandedWorkload();
    await screen.findByText(`Signed-in principal: ${actor.principalId}`);
    const user = userEvent.setup();
    await user.selectOptions(
      workloadControl('combobox', { name: 'Checker principal type' }),
      'PLATFORM_OPERATOR',
    );
    await user.click(workloadControl('button', { name: 'Choose checker' }));
    await waitFor(() =>
      expect(fetch.mock.calls.some(([url]) => String(url).includes('kind=PLATFORM_OPERATOR'))).toBe(
        true,
      ),
    );
    if (returnedKind === 'PLATFORM_OPERATOR') {
      await user.click(
        await findWorkloadControl('button', { name: 'Select Independent reviewer' }),
      );
      expect(workloadControl('textbox', { name: 'Checker principal ID' })).toHaveValue(
        review.review.checkerPrincipalId,
      );
      await user.selectOptions(
        workloadControl('combobox', { name: 'Checker principal type' }),
        'USER',
      );
      expect(workloadControl('textbox', { name: 'Checker principal ID' })).toHaveValue('');
    } else {
      await screen.findByText('Principal choices are unavailable. Search again.');
      expect(
        screen.queryByRole('button', { name: 'Select Independent reviewer', hidden: true }),
      ).not.toBeInTheDocument();
      expect(workloadControl('textbox', { name: 'Checker principal ID' })).toHaveValue('');
    }
    expect(
      screen.queryByRole('button', { name: 'Select Current maker', hidden: true }),
    ).not.toBeInTheDocument();
    expect(fetch.mock.calls.some(([, init]) => init?.method === 'POST')).toBe(false);
    expect(performWebAuthnStepUp).not.toHaveBeenCalled();
  },
);
