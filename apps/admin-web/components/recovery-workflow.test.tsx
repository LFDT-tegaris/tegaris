import { render, screen, waitFor, within, cleanup, act } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { performWebAuthnStepUp } from '@openpc/ui-shell';
import { RecoveryWorkflow } from './recovery-workflow';
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
  recoveryId: id('801'),
  participantId: actor.participantId,
  subjectId: id('114'),
  recoveryPrincipalId: id('113'),
  custodianPrincipalIds: [id('111'), id('112')],
  purposeDigest: `sha256:${'a'.repeat(64)}`,
  actionIntentId: 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
};
const review = {
  reviewToken: 'r'.repeat(100),
  review: {
    mutation: 'BEGIN',
    resourceId: candidate.recoveryId,
    candidate,
    candidateDigest: `sha256:${'b'.repeat(64)}`,
    expectedRevision: '0',
    reason: 'Recover this account after authenticator loss.',
    checkerPrincipalId: id('112'),
    stepUp: {
      actionIntentId: candidate.actionIntentId,
      actionIntentDigest: `sha256:${'c'.repeat(64)}`,
      resourceId: candidate.recoveryId,
      resourceDigest: `sha256:${'b'.repeat(64)}`,
    },
  },
};
const state = { actor, approvals: [], nextCursor: null, completeness: 'COMPLETE' };
beforeEach(() => {
  localStorage.clear();
  vi.mocked(performWebAuthnStepUp).mockReset().mockResolvedValue(undefined);
});
afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});
it('exposes exact accessible names for all recovery transition and approval selectors', async () => {
  vi.spyOn(globalThis, 'fetch').mockResolvedValue(Response.json(state));
  const user = userEvent.setup();
  render(<RecoveryWorkflow />);
  await waitFor(() =>
    expect(screen.getByRole('button', { name: 'Review transition' })).toBeEnabled(),
  );
  const transition = screen.getByLabelText('Transition', { exact: true });
  for (const [value, field] of [
    ['QUALIFY', 'Hardware authenticator credential ID'],
    ['REVOKE', 'Recovery executor principal ID'],
    ['BEGIN', 'Account to recover'],
    ['CUSTODY', 'Recovery case ID'],
    ['COMPLETE', 'Recovery case ID'],
    ['POST_REVIEW', 'Post-recovery findings and resolution'],
  ]) {
    await user.selectOptions(transition, value!);
    expect(screen.getByLabelText(field!, { exact: true })).toBeVisible();
  }
  await user.selectOptions(screen.getByLabelText('Requests to show', { exact: true }), 'maker');
  expect(screen.getByLabelText('Requests to show', { exact: true })).toHaveValue('maker');
});
it('renders exact signer review purpose and terminal state without showing account replacement or active authority', async () => {
  const recovery = {
    effect: {
      purpose: 'IDENTITY_ENVELOPE_SIGNER_REPAIR_ONLY',
      recoveryId: id('801'),
      participantId: actor.participantId,
      privacyDomainId: actor.privacyDomainId,
      enrollmentId: id('800'),
      issuerPrincipalId: id('194'),
      executorPrincipalId: id('113'),
      custodianPrincipalIds: [id('115'), id('116')],
      rotationId: id('802'),
      creationOperationId: id('803'),
      activationOperationId: id('804'),
      intentDigest: 'sha256:' + '11'.repeat(32),
      state: 'REVOKED',
      revision: '4',
      issuedAt: '2026-10-03T06:00:00.000Z',
      expiresAt: '2026-10-03T06:15:00.000Z',
      leaseExpired: true,
      authority: 'NONE',
      postReviewRequired: true,
      postReviewStatus: 'REQUIRED',
      reviewedAt: null,
      reviewedByPrincipalId: null,
      reviewNoteDigest: null,
    },
    operationId: null,
  };
  vi.spyOn(globalThis, 'fetch').mockResolvedValue(Response.json({ ...state, recovery }));
  render(<RecoveryWorkflow />);
  expect(await screen.findByText('Signer recovery state: REVOKED')).toBeInTheDocument();
  expect(screen.getByText(/Authority: NONE/)).toBeInTheDocument();
  expect(screen.queryByText(/Replacement authenticator:/)).not.toBeInTheDocument();
});
it('prepares meaningful inputs and preserves a saved request across reload after submission response loss', async () => {
  const user = userEvent.setup();
  const fetch = vi
    .spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(Response.json(state))
    .mockResolvedValueOnce(Response.json(review))
    .mockRejectedValueOnce(new Error('Submission response lost'));
  const rendered = render(<RecoveryWorkflow />);
  await waitFor(() =>
    expect(screen.getByRole('button', { name: 'Review transition' })).toBeEnabled(),
  );
  for (const [name, value] of [
    ['Account to recover', id('114')],
    ['Qualified recovery executor', id('113')],
    ['First custodian', id('111')],
    ['Second custodian', id('112')],
    ['Distinct checker principal ID', id('112')],
    ['Recovery purpose', review.review.reason],
  ])
    await user.type(screen.getByLabelText(name!), value!);
  await user.click(screen.getByRole('button', { name: 'Review transition' }));
  await screen.findByLabelText('Saved recovery transition');
  expect(JSON.parse(String(fetch.mock.calls[1]![1]?.body))).toMatchObject({
    command: 'PREVIEW',
    input: {
      subjectId: id('114'),
      recoveryPrincipalId: id('113'),
      custodianPrincipalIds: [id('111'), id('112')],
      reason: review.review.reason,
    },
  });
  await user.click(screen.getByRole('button', { name: 'Request checker approval' }));
  await expect(screen.findByRole('alert')).resolves.toHaveTextContent('Submission response lost');
  expect(fetch).toHaveBeenCalledTimes(3);
  expect(performWebAuthnStepUp).not.toHaveBeenCalled();
  rendered.unmount();
  fetch.mockResolvedValueOnce(Response.json(state));
  render(<RecoveryWorkflow />);
  const saved = await screen.findByLabelText('Saved recovery transition');
  expect(within(saved).getByText(review.review.reason)).toBeVisible();
  expect(within(saved).getByRole('button', { name: 'Request checker approval' })).toBeVisible();
});
it('rejects saved review restoration for a different authenticated principal', async () => {
  localStorage.setItem('openpc:recovery-workflow:v1', JSON.stringify({ actor, value: review }));
  vi.spyOn(globalThis, 'fetch').mockResolvedValue(
    Response.json({ ...state, actor: { ...actor, principalId: id('112') } }),
  );
  render(<RecoveryWorkflow />);
  await waitFor(() =>
    expect(screen.getByRole('button', { name: 'Review transition' })).toBeEnabled(),
  );
  expect(screen.queryByLabelText('Saved recovery transition')).toBeNull();
});
it('keeps a consumed approval distinct from execution and offers authoritative readback', async () => {
  localStorage.setItem(
    'openpc:recovery-workflow:v1',
    JSON.stringify({ actor, value: { ...review, approvalRequestId: id('301') } }),
  );
  vi.spyOn(globalThis, 'fetch').mockResolvedValue(
    Response.json({
      ...state,
      approvals: [
        {
          approvalRequestId: `urn:openpc:resource:${id('301')}`,
          candidateDigest: review.review.candidateDigest,
          state: 'APPROVED',
          revision: '2',
          makerSubjectRef: `urn:openpc:resource:${actor.principalId}`,
          checkerSubjectRef: `urn:openpc:resource:${id('112')}`,
          proposal: {
            mutation: 'BEGIN',
            resourceId: candidate.recoveryId,
            expectedRevision: '0',
            state: 'CONSUMED',
            expiresAt: new Date().toISOString(),
            candidate,
            approval: { reason: review.review.reason },
          },
          stepUp: review.review.stepUp,
        },
      ],
    }),
  );
  render(<RecoveryWorkflow />);
  await screen.findByText('This approved request has already executed.');
  expect(
    screen.getByRole('button', { name: 'Verify authenticator and execute approved transition' }),
  ).toBeDisabled();
  expect(screen.getByRole('button', { name: 'Read saved transition result' })).toBeEnabled();
});

const saved = { ...review, approvalRequestId: id('301') };
const checkerApproval = {
  approvalRequestId: `urn:openpc:resource:${id('301')}`,
  candidateDigest: review.review.candidateDigest,
  state: 'REQUESTED',
  revision: '2',
  makerSubjectRef: `urn:openpc:resource:${id('112')}`,
  checkerSubjectRef: `urn:openpc:resource:${actor.principalId}`,
  proposal: {
    mutation: 'BEGIN',
    resourceId: candidate.recoveryId,
    expectedRevision: '0',
    state: 'PENDING',
    expiresAt: '2099-01-01T00:00:00.000Z',
    candidate,
    approval: { reason: review.review.reason },
  },
  stepUp: review.review.stepUp,
};
const ceremonyButton = (lane: 'maker' | 'checker') =>
  lane === 'maker'
    ? 'Verify authenticator and execute approved transition'
    : 'Verify authenticator and approve this transition';
const stateFor = (lane: 'maker' | 'checker') => ({
  ...state,
  approvals: lane === 'checker' ? [checkerApproval] : [],
});
function restoreMaker(lane: 'maker' | 'checker') {
  if (lane === 'maker')
    localStorage.setItem('openpc:recovery-workflow:v1', JSON.stringify({ actor, value: saved }));
}
function holdCeremony() {
  let release!: () => void;
  const held = new Promise<void>((resolve) => {
    release = resolve;
  });
  vi.mocked(performWebAuthnStepUp).mockImplementationOnce(() => held);
  return async () => {
    await act(async () => {
      release();
      await held;
    });
  };
}
const businessCalls = (fetcher: { mock: { calls: [unknown, RequestInit?][] } }) =>
  fetcher.mock.calls.filter(([, init]) => init?.method === 'POST');

it.each(['maker', 'checker'] as const)(
  'binds the %s held ceremony to lifecycle and rejects selection drift before owner read or POST',
  async (lane) => {
    restoreMaker(lane);
    const release = holdCeremony();
    const fetcher = vi.spyOn(globalThis, 'fetch').mockResolvedValue(Response.json(stateFor(lane)));
    const user = userEvent.setup();
    render(<RecoveryWorkflow />);
    await user.click(await screen.findByRole('button', { name: ceremonyButton(lane) }));
    await waitFor(() => expect(performWebAuthnStepUp).toHaveBeenCalledOnce());
    const lifecycle = vi.mocked(performWebAuthnStepUp).mock.calls[0]![2]!;
    expect(lifecycle.isCurrent?.()).toBe(true);
    await user.type(screen.getByLabelText('Recovery purpose'), 'Changed selection during ceremony');
    expect(lifecycle.signal?.aborted).toBe(true);
    expect(lifecycle.isCurrent?.()).toBe(false);
    await release();
    await screen.findByRole('alert');
    expect(fetcher).toHaveBeenCalledOnce();
    expect(businessCalls(fetcher)).toHaveLength(0);
  },
);

it.each(['maker', 'checker'] as const)(
  'cancels the %s held ceremony on unmount without reading or dispatching',
  async (lane) => {
    restoreMaker(lane);
    const release = holdCeremony();
    const fetcher = vi.spyOn(globalThis, 'fetch').mockResolvedValue(Response.json(stateFor(lane)));
    const user = userEvent.setup();
    const rendered = render(<RecoveryWorkflow />);
    await user.click(await screen.findByRole('button', { name: ceremonyButton(lane) }));
    const lifecycle = vi.mocked(performWebAuthnStepUp).mock.calls[0]![2]!;
    rendered.unmount();
    expect(lifecycle.signal?.aborted).toBe(true);
    expect(lifecycle.isCurrent?.()).toBe(false);
    await release();
    expect(fetcher).toHaveBeenCalledOnce();
    expect(businessCalls(fetcher)).toHaveLength(0);
  },
);

it.each(['sessionId', 'principalId', 'participantId', 'privacyDomainId', 'contextEpoch'] as const)(
  'rejects authoritative %s drift after held ceremony and preserves the original saved request',
  async (field) => {
    restoreMaker('maker');
    const release = holdCeremony();
    const fetcher = vi
      .spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(Response.json(state))
      .mockResolvedValueOnce(
        Response.json({
          ...state,
          actor: { ...actor, [field]: field === 'contextEpoch' ? '3' : id('999') },
        }),
      );
    const user = userEvent.setup();
    render(<RecoveryWorkflow />);
    await user.click(await screen.findByRole('button', { name: ceremonyButton('maker') }));
    await release();
    await screen.findByRole('alert');
    expect(fetcher).toHaveBeenCalledTimes(2);
    expect(businessCalls(fetcher)).toHaveLength(0);
    expect(screen.queryByLabelText('Saved recovery transition')).toBeNull();
    expect(JSON.parse(localStorage.getItem('openpc:recovery-workflow:v1')!)).toEqual({
      actor,
      value: saved,
    });
  },
);

it('rejects a changed checker approval after authoritative readback without POST', async () => {
  const fetcher = vi
    .spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(Response.json(stateFor('checker')))
    .mockResolvedValueOnce(
      Response.json({ ...state, approvals: [{ ...checkerApproval, revision: '3' }] }),
    );
  const user = userEvent.setup();
  render(<RecoveryWorkflow />);
  await user.click(await screen.findByRole('button', { name: ceremonyButton('checker') }));
  await screen.findByRole('alert');
  expect(businessCalls(fetcher)).toHaveLength(0);
});

it('rechecks the selection after a held actor read before sending the original maker POST', async () => {
  restoreMaker('maker');
  let release!: (response: Response) => void;
  const read = new Promise<Response>((resolve) => {
    release = resolve;
  });
  const fetcher = vi
    .spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(Response.json(state))
    .mockImplementationOnce(() => read);
  const user = userEvent.setup();
  render(<RecoveryWorkflow />);
  await user.click(await screen.findByRole('button', { name: ceremonyButton('maker') }));
  await waitFor(() => expect(fetcher).toHaveBeenCalledTimes(2));
  await user.type(screen.getByLabelText('Recovery purpose'), 'Changed during actor read');
  await act(async () => {
    release(Response.json(state));
    await read;
  });
  await screen.findByRole('alert');
  expect(businessCalls(fetcher)).toHaveLength(0);
});

it.each(['maker', 'checker'] as const)(
  'does not send the %s command when the authenticator aborts',
  async (lane) => {
    restoreMaker(lane);
    vi.mocked(performWebAuthnStepUp).mockRejectedValueOnce(
      new DOMException('Authenticator cancelled', 'AbortError'),
    );
    const fetcher = vi.spyOn(globalThis, 'fetch').mockResolvedValue(Response.json(stateFor(lane)));
    const user = userEvent.setup();
    render(<RecoveryWorkflow />);
    await user.click(await screen.findByRole('button', { name: ceremonyButton(lane) }));
    await screen.findByRole('alert');
    expect(fetcher).toHaveBeenCalledOnce();
    expect(businessCalls(fetcher)).toHaveLength(0);
  },
);

it.each(['maker', 'checker'] as const)(
  'reads the same authoritative actor immediately before the exact %s business command',
  async (lane) => {
    restoreMaker(lane);
    const currentState = stateFor(lane);
    const fetcher = vi
      .spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(Response.json(currentState))
      .mockResolvedValueOnce(Response.json(currentState))
      .mockResolvedValueOnce(
        Response.json({ truthState: 'SUCCESS', resourceId: candidate.recoveryId }),
      )
      .mockResolvedValueOnce(Response.json(currentState));
    const user = userEvent.setup();
    render(<RecoveryWorkflow />);
    await user.click(await screen.findByRole('button', { name: ceremonyButton(lane) }));
    await waitFor(() => expect(fetcher).toHaveBeenCalledTimes(4));
    expect(String(fetcher.mock.calls[1]![0])).toContain(
      `lane=${lane}&approvalRequestId=${id('301')}`,
    );
    expect(fetcher.mock.calls[1]![1]?.signal).toBe(
      vi.mocked(performWebAuthnStepUp).mock.calls[0]![2]?.signal,
    );
    expect(JSON.parse(String(businessCalls(fetcher)[0]![1]?.body))).toEqual(
      lane === 'maker'
        ? {
            command: 'COMMIT',
            reviewToken: saved.reviewToken,
            approvalRequestId: saved.approvalRequestId,
          }
        : {
            command: 'APPROVE',
            approvalRequestId: id('301'),
            candidateDigest: checkerApproval.candidateDigest,
            expectedRevision: checkerApproval.revision,
          },
    );
  },
);

it('retains the original maker key and authoritative readback after a sent response is lost', async () => {
  restoreMaker('maker');
  const fetcher = vi
    .spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(Response.json(state))
    .mockResolvedValueOnce(Response.json(state))
    .mockRejectedValueOnce(new Error('Original execution response lost'))
    .mockResolvedValueOnce(Response.json(state));
  const user = userEvent.setup();
  render(<RecoveryWorkflow />);
  await user.click(await screen.findByRole('button', { name: ceremonyButton('maker') }));
  await expect(screen.findByRole('alert')).resolves.toHaveTextContent(
    'Original execution response lost',
  );
  expect(fetcher).toHaveBeenCalledTimes(4);
  expect(String(fetcher.mock.calls[3]![0])).toContain(
    `approvalRequestId=${saved.approvalRequestId}`,
  );
  expect(JSON.parse(localStorage.getItem('openpc:recovery-workflow:v1')!)).toEqual({
    actor,
    value: saved,
  });
  expect(businessCalls(fetcher)).toHaveLength(1);
});

it('ignores a late initial read after unmount and preserves saved custody', async () => {
  restoreMaker('maker');
  let release!: (response: Response) => void;
  const read = new Promise<Response>((resolve) => {
    release = resolve;
  });
  const fetcher = vi.spyOn(globalThis, 'fetch').mockImplementationOnce(() => read);
  const rendered = render(<RecoveryWorkflow />);
  rendered.unmount();
  expect(fetcher.mock.calls[0]![1]?.signal?.aborted).toBe(true);
  await act(async () => {
    release(Response.json({ ...state, actor: { ...actor, principalId: id('999') } }));
    await read;
  });
  expect(JSON.parse(localStorage.getItem('openpc:recovery-workflow:v1')!)).toEqual({
    actor,
    value: saved,
  });
});

it('rejects a foreign checker session before sending the approval', async () => {
  const fetcher = vi
    .spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(Response.json(stateFor('checker')))
    .mockResolvedValueOnce(
      Response.json({ ...stateFor('checker'), actor: { ...actor, sessionId: id('999') } }),
    );
  const user = userEvent.setup();
  render(<RecoveryWorkflow />);
  await user.click(await screen.findByRole('button', { name: ceremonyButton('checker') }));
  await screen.findByRole('alert');
  expect(businessCalls(fetcher)).toHaveLength(0);
});

it('reads the original checker approval after a sent response is lost without replaying it', async () => {
  const currentState = stateFor('checker');
  const fetcher = vi
    .spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(Response.json(currentState))
    .mockResolvedValueOnce(Response.json(currentState))
    .mockRejectedValueOnce(new Error('Original approval response lost'))
    .mockResolvedValueOnce(Response.json(currentState));
  const user = userEvent.setup();
  render(<RecoveryWorkflow />);
  await user.click(await screen.findByRole('button', { name: ceremonyButton('checker') }));
  await expect(screen.findByRole('alert')).resolves.toHaveTextContent(
    'Original approval response lost',
  );
  expect(String(fetcher.mock.calls[3]![0])).toContain(`approvalRequestId=${id('301')}`);
  expect(businessCalls(fetcher)).toHaveLength(1);
});

it('preserves the first sent execution failure when authoritative readback also fails', async () => {
  restoreMaker('maker');
  const fetcher = vi
    .spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(Response.json(state))
    .mockResolvedValueOnce(Response.json(state))
    .mockRejectedValueOnce(new Error('First execution failure'))
    .mockRejectedValueOnce(new Error('Later readback failure'));
  const user = userEvent.setup();
  render(<RecoveryWorkflow />);
  await user.click(await screen.findByRole('button', { name: ceremonyButton('maker') }));
  await expect(screen.findByRole('alert')).resolves.toHaveTextContent('First execution failure');
  expect(screen.getByRole('status')).toHaveTextContent(
    'response and its readback could not be confirmed',
  );
  expect(businessCalls(fetcher)).toHaveLength(1);
  expect(JSON.parse(localStorage.getItem('openpc:recovery-workflow:v1')!)).toEqual({
    actor,
    value: saved,
  });
});

it('does not abort or replay a sent maker command on unmount and retains original custody', async () => {
  restoreMaker('maker');
  let release!: (response: Response) => void;
  const sent = new Promise<Response>((resolve) => {
    release = resolve;
  });
  const fetcher = vi
    .spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(Response.json(state))
    .mockResolvedValueOnce(Response.json(state))
    .mockImplementationOnce(() => sent);
  const user = userEvent.setup();
  const rendered = render(<RecoveryWorkflow />);
  await user.click(await screen.findByRole('button', { name: ceremonyButton('maker') }));
  await waitFor(() => expect(businessCalls(fetcher)).toHaveLength(1));
  expect(businessCalls(fetcher)[0]![1]?.signal).toBeUndefined();
  rendered.unmount();
  await act(async () => {
    release(Response.json({ truthState: 'WRITE_AMBIGUITY', resourceId: candidate.recoveryId }));
    await sent;
  });
  expect(fetcher).toHaveBeenCalledTimes(3);
  expect(JSON.parse(localStorage.getItem('openpc:recovery-workflow:v1')!)).toEqual({
    actor,
    value: saved,
  });
});

it('removes stale actor presentation but retains sent original custody when readback changes account', async () => {
  restoreMaker('maker');
  const fetcher = vi
    .spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(Response.json(state))
    .mockResolvedValueOnce(Response.json(state))
    .mockRejectedValueOnce(new Error('Original response lost'))
    .mockResolvedValueOnce(Response.json({ ...state, actor: { ...actor, sessionId: id('999') } }));
  const user = userEvent.setup();
  render(<RecoveryWorkflow />);
  await user.click(await screen.findByRole('button', { name: ceremonyButton('maker') }));
  await expect(screen.findByRole('alert')).resolves.toHaveTextContent('Original response lost');
  expect(screen.queryByLabelText('Saved recovery transition')).toBeNull();
  expect(businessCalls(fetcher)).toHaveLength(1);
  expect(JSON.parse(localStorage.getItem('openpc:recovery-workflow:v1')!)).toEqual({
    actor,
    value: saved,
  });
});
