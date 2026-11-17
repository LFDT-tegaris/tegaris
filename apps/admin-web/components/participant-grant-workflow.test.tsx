import { createHash, webcrypto } from 'node:crypto';
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { performWebAuthnStepUp } from '@openpc/ui-shell';
import { ParticipantGrantWorkflow } from './participant-grant-workflow';

vi.mock('@openpc/ui-shell', () => ({ performWebAuthnStepUp: vi.fn(async () => undefined) }));
vi.mock('./local-session', () => ({
  LocalSessionSurface: () => <p>Authenticated session controls</p>,
}));

const actor = {
  sessionId: '018f0000-0000-7000-8000-000000000117',
  principalId: '018f0000-0000-7000-8000-000000000111',
  participantId: '018f0000-0000-7000-8000-000000000101',
  privacyDomainId: '018f0000-0000-7000-8000-000000000201',
  contextEpoch: '2',
};
const principalId = '018f0000-0000-7000-8000-000000000891';
function savedReview() {
  return {
    reviewToken: 'sealed-review',
    review: {
      kind: 'assignment',
      mutation: 'CREATE',
      resourceId: principalId,
      expectedRevision: '0',
      candidateDigest: `sha256:${'a'.repeat(64)}`,
      reason: 'Private maker-only proposal.',
      proposedGrant: {
        id: principalId,
        participantId: actor.participantId,
        principalId: actor.principalId,
        authorityEnvelopeId: '018f0000-0000-7000-8000-000000000121',
        groupId: '018f0000-0000-7000-8000-000000000777',
        state: 'ACTIVE',
        privacyDomainIds: [actor.privacyDomainId],
        actionIntentIds: [],
        capabilityIds: [],
        resourceIds: ['private-resource'],
        riskClasses: ['LOW'],
        validFrom: '2026-09-14T00:00:00.000Z',
        validUntil: '2030-01-01T00:00:00.000Z',
        makerCheckerRequired: true,
        stepUpRequired: true,
        onwardDelegationDepth: 0,
        delegationEpoch: '0',
        scopeDigest: `sha256:${'b'.repeat(64)}`,
      },
      stepUp: {
        actionIntentId: 'test-action',
        actionIntentDigest: 'sha256:action',
        resourceId: principalId,
        resourceDigest: 'sha256:review',
      },
    },
  };
}
beforeEach(() => {
  vi.stubGlobal('crypto', webcrypto);
});
afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  vi.clearAllMocks();
  localStorage.clear();
  vi.unstubAllGlobals();
});

it('uses owner-bound Platform privacy for declared assignments without switching context', async () => {
  const fetch = vi
    .spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(
      Response.json({
        ...actor,
        privacyDomainId: undefined,
        authenticated: true,
        contextMode: 'PLATFORM',
      }),
    )
    .mockResolvedValueOnce(
      Response.json({ actor: { ...actor, role: 'operator' }, approvals: [], nextCursor: null }),
    );
  render(<ParticipantGrantWorkflow platformHandoff />);
  expect(await screen.findByText('Platform administration assignments')).toBeVisible();
  expect(fetch.mock.calls[1]?.[0]).toBe('/api/v1/ui/grant-workbench?mode=platform-handoff');
  expect(screen.queryByRole('button', { name: 'Enter workspace' })).toBeNull();
  expect(screen.queryByRole('button', { name: 'Review grant creation' })).toBeNull();
  expect(
    screen.getByRole('button', { name: 'Review declared administration assignment' }),
  ).toBeVisible();
});

it('clears another actor’s persisted proposal before displaying an authenticated grant page', async () => {
  localStorage.setItem('openpc:grant-workflow:v1', JSON.stringify({ actor, value: savedReview() }));
  const checker = {
    ...actor,
    principalId: '018f0000-0000-7000-8000-000000000112',
    sessionId: '018f0000-0000-7000-8000-000000000118',
  };
  vi.spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(
      Response.json({ ...checker, authenticated: true, contextMode: 'PARTICIPANT' }),
    )
    .mockResolvedValueOnce(
      Response.json({ actor: { ...checker, role: 'viewer' }, approvals: [], nextCursor: null }),
    );
  render(<ParticipantGrantWorkflow />);
  await screen.findByRole('heading', { name: 'Participant grants' });
  expect(
    screen.queryByRole('region', { name: 'Prepare declared successor assignment' }),
  ).not.toBeInTheDocument();
  expect(screen.queryByText('private-resource')).not.toBeInTheDocument();
  expect(screen.getByLabelText('Grant ID')).toHaveValue('');
  expect(localStorage.getItem('openpc:grant-workflow:v1')).toBeNull();
});

it('restores a valid review only after the same actor and context are read from Identity', async () => {
  localStorage.setItem('openpc:grant-workflow:v1', JSON.stringify({ actor, value: savedReview() }));
  vi.spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(
      Response.json({ ...actor, authenticated: true, contextMode: 'PARTICIPANT' }),
    )
    .mockResolvedValueOnce(
      Response.json({ actor: { ...actor, role: 'operator' }, approvals: [], nextCursor: null }),
    );
  render(<ParticipantGrantWorkflow />);
  await waitFor(() => expect(screen.getByText('private-resource')).toBeVisible());
  expect(screen.getByLabelText('Grant ID')).toHaveValue(principalId);
  expect(screen.getByText('Group membership constraint')).toBeVisible();
  expect(screen.getByText('018f0000-0000-7000-8000-000000000777')).toBeVisible();
});

it('opens a review remediation target through an authorized read without dispatching a mutation', async () => {
  const fetcher = vi
    .spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(
      Response.json({ ...actor, authenticated: true, contextMode: 'PARTICIPANT' }),
    )
    .mockResolvedValueOnce(
      Response.json({
        actor: { ...actor, role: 'operator' },
        approvals: [],
        nextCursor: null,
        effect: { effect: savedReview().review.proposedGrant, revision: '1', operationId: null },
      }),
    );
  render(<ParticipantGrantWorkflow initialGrant={{ id: principalId, kind: 'assignment' }} />);
  await screen.findByRole('button', { name: 'Review grant revocation' });
  expect(screen.getByLabelText('Grant ID')).toHaveValue(principalId);
  expect(String(fetcher.mock.calls[1]![0])).toContain(`grantId=${principalId}&kind=assignment`);
  expect(
    fetcher.mock.calls.every(([, options]) => !options?.method || options.method === 'GET'),
  ).toBe(true);
});

it('prefills a selected principal without dispatching a mutation', async () => {
  const selected = '018f0000-0000-7000-8000-000000000892';
  const fetcher = vi
    .spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(
      Response.json({ ...actor, authenticated: true, contextMode: 'PARTICIPANT' }),
    )
    .mockResolvedValueOnce(
      Response.json({ actor: { ...actor, role: 'operator' }, approvals: [], nextCursor: null }),
    );
  render(<ParticipantGrantWorkflow initialPrincipalId={selected} />);
  expect(await screen.findByRole('textbox', { name: 'Principal ID' })).toHaveValue(selected);
  expect(
    fetcher.mock.calls.every(([, options]) => !options?.method || options.method === 'GET'),
  ).toBe(true);
});

const unsafeGrantMarker = 'PRIVATE_GRANT_SERVER_OR_TRANSPORT_DETAIL';
const grantUnavailable =
  'Grant request could not be confirmed. Refresh or read the original operation before retrying.';
const grantFailures = [
  {
    name: 'authorization',
    status: 403,
    message:
      'Grant request was not authorized. Refresh the authenticated context before continuing.',
  },
  {
    name: 'conflict',
    status: 409,
    message: 'Grant state changed. Refresh or read the original operation before retrying.',
  },
  {
    name: 'input',
    status: 422,
    message: 'Grant request was rejected. Check the inputs before continuing.',
  },
  { name: 'unknown code', status: 503, message: grantUnavailable },
  { name: 'transport', message: grantUnavailable },
  { name: 'unknown thrown object', message: grantUnavailable },
  { name: 'non-JSON success', message: grantUnavailable },
] as const;
function failGrant(failure: (typeof grantFailures)[number]): Response {
  if ('status' in failure)
    return Response.json(
      { title: unsafeGrantMarker, code: unsafeGrantMarker },
      { status: failure.status },
    );
  if (failure.name === 'transport') throw new Error(unsafeGrantMarker);
  if (failure.name === 'unknown thrown object')
    throw { message: unsafeGrantMarker, details: unsafeGrantMarker };
  return new Response(unsafeGrantMarker, { status: 200 });
}
const grantSession = {
  ...actor,
  authenticated: true,
  contextMode: 'PARTICIPANT',
  availableContexts: [
    { participantId: actor.participantId, privacyDomainId: actor.privacyDomainId },
  ],
};
const grantState = { actor: { ...actor, role: 'operator' }, approvals: [], nextCursor: null };
const grantApprovalId = '018f0000-0000-7000-8000-000000000801';
function grantApproval(approvalState: string) {
  const value = savedReview();
  return {
    approvalRequestId: `urn:openpc:resource:${grantApprovalId}`,
    candidateDigest: value.review.candidateDigest,
    state: approvalState,
    proposal: value.review,
    stepUp: value.review.stepUp,
  };
}
it.each(
  grantFailures.flatMap((failure) =>
    ['session', 'workbench', 'Platform handoff'].map((phase) => ({ ...failure, phase })),
  ),
)(
  'hides $name from the initial grant $phase reader without losing stored custody',
  async (failure) => {
    const original = JSON.stringify({ actor, value: savedReview() });
    localStorage.setItem('openpc:grant-workflow:v1', original);
    const fetcher = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) =>
      String(input) === '/api/v1/ui/local-session' && failure.phase !== 'session'
        ? Response.json({
            ...grantSession,
            ...(failure.phase === 'Platform handoff'
              ? { contextMode: 'PLATFORM', privacyDomainId: undefined }
              : {}),
          })
        : failGrant(failure),
    );
    render(<ParticipantGrantWorkflow platformHandoff={failure.phase === 'Platform handoff'} />);
    await screen.findByText(failure.message);
    expect(document.body.textContent).not.toContain(unsafeGrantMarker);
    expect(screen.queryByRole('heading', { name: 'Participant grants' })).not.toBeInTheDocument();
    expect(screen.queryByText('No visible grant approvals on this page.')).not.toBeInTheDocument();
    expect(localStorage.getItem('openpc:grant-workflow:v1')).toBe(original);
    expect(fetcher.mock.calls.some(([, init]) => init?.method === 'POST')).toBe(false);
  },
);
it.each(
  grantFailures.flatMap((failure) =>
    ['preview', 'submit', 'approve', 'commit'].map((boundary) => ({ ...failure, boundary })),
  ),
)(
  'hides $name from grant $boundary without replacing or replaying the original review',
  async (failure) => {
    const value = {
      ...savedReview(),
      ...(failure.boundary === 'commit' ? { approvalRequestId: grantApprovalId } : {}),
    };
    const original = JSON.stringify({ actor, value });
    localStorage.setItem('openpc:grant-workflow:v1', original);
    const reader = {
      ...grantState,
      actor: { ...actor, role: failure.boundary === 'approve' ? 'viewer' : 'operator' },
      approvals:
        failure.boundary === 'approve' || failure.boundary === 'commit'
          ? [grantApproval(failure.boundary === 'approve' ? 'REQUESTED' : 'APPROVED')]
          : [],
    };
    const fetcher = vi
      .spyOn(globalThis, 'fetch')
      .mockImplementation(async (input, init) =>
        init?.method === 'POST'
          ? failGrant(failure)
          : Response.json(String(input) === '/api/v1/ui/local-session' ? grantSession : reader),
      );
    render(<ParticipantGrantWorkflow />);
    await screen.findByRole('heading', { name: 'Participant grants' });
    const names = {
      preview: 'Review grant creation',
      submit: 'Send grant to checker',
      approve: `Approve ${principalId}`,
      commit: 'Commit approved grant change',
    };
    const control = screen.getByRole('button', {
      name: names[failure.boundary as keyof typeof names],
    });
    if (failure.boundary === 'preview') {
      grantCreationInputs(control.closest('form')!);
      fireEvent.submit(control.closest('form')!);
    } else fireEvent.click(control);
    await screen.findByText(failure.message);
    expect(document.body.textContent).not.toContain(unsafeGrantMarker);
    expect(localStorage.getItem('openpc:grant-workflow:v1')).toBe(original);
    expect(
      screen.queryByText('The grant change is awaiting a distinct checker.'),
    ).not.toBeInTheDocument();
    expect(screen.queryByText(/Grant change committed/)).not.toBeInTheDocument();
    const posts = fetcher.mock.calls.filter(([, init]) => init?.method === 'POST');
    expect(posts).toHaveLength(1);
    const body = JSON.parse(String(posts[0]![1]!.body));
    if (failure.boundary === 'submit')
      expect(body).toEqual({ command: 'SUBMIT', reviewToken: value.reviewToken });
    else if (failure.boundary === 'commit')
      expect(body).toEqual({
        command: 'COMMIT',
        reviewToken: value.reviewToken,
        approvalRequestId: grantApprovalId,
      });
    else if (failure.boundary === 'approve')
      expect(body).toEqual({
        command: 'APPROVE',
        approvalRequestId: grantApprovalId,
        candidateDigest: value.review.candidateDigest,
      });
    else expect(body).toMatchObject({ command: 'PREVIEW_ASSIGN' });
  },
);
it.each(['refresh', 'grant readback', 'approval cursor'] as const)(
  'hides a transport failure at the grant %s boundary without changing the stored review',
  async (boundary) => {
    const original = JSON.stringify({ actor, value: savedReview() });
    localStorage.setItem('openpc:grant-workflow:v1', original);
    let fail = false;
    const fetcher = vi
      .spyOn(globalThis, 'fetch')
      .mockImplementation(async (input) =>
        String(input) === '/api/v1/ui/local-session'
          ? Response.json(grantSession)
          : fail
            ? failGrant({ name: 'transport', message: grantUnavailable })
            : Response.json({ ...grantState, nextCursor: 'next-grant-page' }),
      );
    render(<ParticipantGrantWorkflow />);
    await screen.findByRole('heading', { name: 'Participant grants' });
    fail = true;
    fireEvent.click(
      screen.getByRole('button', {
        name:
          boundary === 'refresh'
            ? 'Refresh approvals'
            : boundary === 'grant readback'
              ? 'Find grant'
              : 'Next approval page',
      }),
    );
    await screen.findByText(grantUnavailable);
    expect(document.body.textContent).not.toContain(unsafeGrantMarker);
    expect(localStorage.getItem('openpc:grant-workflow:v1')).toBe(original);
    expect(fetcher.mock.calls.some(([, init]) => init?.method === 'POST')).toBe(false);
  },
);
it('hides a grant authenticator exception and prevents commit before step-up succeeds', async () => {
  const original = JSON.stringify({
    actor,
    value: { ...savedReview(), approvalRequestId: grantApprovalId },
  });
  localStorage.setItem('openpc:grant-workflow:v1', original);
  vi.mocked(performWebAuthnStepUp).mockRejectedValueOnce(new Error(unsafeGrantMarker));
  const fetcher = vi
    .spyOn(globalThis, 'fetch')
    .mockImplementation(async (input) =>
      Response.json(
        String(input) === '/api/v1/ui/local-session'
          ? grantSession
          : { ...grantState, approvals: [grantApproval('APPROVED')] },
      ),
    );
  render(<ParticipantGrantWorkflow />);
  fireEvent.click(await screen.findByRole('button', { name: 'Commit approved grant change' }));
  await screen.findByText(grantUnavailable);
  expect(document.body.textContent).not.toContain(unsafeGrantMarker);
  expect(localStorage.getItem('openpc:grant-workflow:v1')).toBe(original);
  expect(fetcher.mock.calls.some(([, init]) => init?.method === 'POST')).toBe(false);
});
it('hides a context selection failure without claiming activation', async () => {
  const fetcher = vi
    .spyOn(globalThis, 'fetch')
    .mockImplementation(async (_input, init) =>
      init?.method === 'POST'
        ? failGrant(grantFailures[0])
        : Response.json({ ...grantSession, contextMode: 'PLATFORM' }),
    );
  render(<ParticipantGrantWorkflow />);
  fireEvent.click(await screen.findByRole('button', { name: 'Enter workspace' }));
  await screen.findByText(grantFailures[0].message);
  expect(document.body.textContent).not.toContain(unsafeGrantMarker);
  expect(screen.queryByText('Participant privacy context is active.')).not.toBeInTheDocument();
  expect(fetcher.mock.calls.filter(([, init]) => init?.method === 'POST')).toHaveLength(1);
});
it('does not expose a local date-conversion exception or dispatch an invalid grant preview', async () => {
  const fetcher = vi
    .spyOn(globalThis, 'fetch')
    .mockImplementation(async (input) =>
      Response.json(String(input) === '/api/v1/ui/local-session' ? grantSession : grantState),
    );
  render(<ParticipantGrantWorkflow />);
  const control = await screen.findByRole('button', { name: 'Review grant creation' });
  fireEvent.change(control.closest('form')!.querySelector('[name="validFrom"]')!, {
    target: { value: '' },
  });
  fireEvent.submit(control.closest('form')!);
  await screen.findByText(grantUnavailable);
  expect(document.body.textContent).not.toContain('Invalid time value');
  expect(fetcher.mock.calls.some(([, init]) => init?.method === 'POST')).toBe(false);
  expect(localStorage.getItem('openpc:grant-workflow:v1')).toBeNull();
});
it('preserves the original grant review and blocks further commands after an ambiguous commit response', async () => {
  const original = JSON.stringify({
    actor,
    value: { ...savedReview(), approvalRequestId: grantApprovalId },
  });
  localStorage.setItem('openpc:grant-workflow:v1', original);
  const fetcher = vi
    .spyOn(globalThis, 'fetch')
    .mockImplementation(async (input, init) =>
      Response.json(
        init?.method === 'POST'
          ? { truthState: 'WRITE_AMBIGUITY' }
          : String(input) === '/api/v1/ui/local-session'
            ? grantSession
            : { ...grantState, approvals: [grantApproval('APPROVED')] },
      ),
    );
  render(<ParticipantGrantWorkflow />);
  fireEvent.click(await screen.findByRole('button', { name: 'Commit approved grant change' }));
  await screen.findByRole('button', { name: 'Read grant after signing in' });
  expect(
    screen.queryByRole('button', { name: 'Commit approved grant change' }),
  ).not.toBeInTheDocument();
  expect(localStorage.getItem('openpc:grant-workflow:v1')).toBe(original);
  expect(fetcher.mock.calls.filter(([, init]) => init?.method === 'POST')).toHaveLength(1);
});

function grantCreationInputs(form: HTMLFormElement) {
  const value = savedReview().review;
  for (const [name, input] of [
    ['principalId', value.proposedGrant.principalId],
    ['authorityEnvelopeId', value.proposedGrant.authorityEnvelopeId],
    ['resourceIds', value.proposedGrant.resourceIds.join('\n')],
    ['reason', value.reason],
  ])
    fireEvent.change(form.querySelector(`[name=${name}]`)!, { target: { value: input } });
}
it.each([200, 201])(
  'preserves a valid HTTP %s grant preview without claiming approval or commitment',
  async (status) => {
    const value = savedReview();
    const fetcher = vi
      .spyOn(globalThis, 'fetch')
      .mockImplementation(async (input, init) =>
        Response.json(
          init?.method === 'POST'
            ? value
            : String(input) === '/api/v1/ui/local-session'
              ? grantSession
              : grantState,
          { status: init?.method === 'POST' ? status : 200 },
        ),
      );
    render(<ParticipantGrantWorkflow />);
    const control = await screen.findByRole('button', { name: 'Review grant creation' });
    const form = control.closest('form')!;
    grantCreationInputs(form);
    fireEvent.submit(form);
    await screen.findByText('Review the exact grant and its limits before requesting approval.');
    expect(JSON.parse(localStorage.getItem('openpc:grant-workflow:v1')!).value).toEqual(value);
    expect(screen.getByRole('button', { name: 'Send grant to checker' })).toBeEnabled();
    expect(
      screen.queryByRole('button', { name: 'Commit approved grant change' }),
    ).not.toBeInTheDocument();
    const posts = fetcher.mock.calls.filter(([, init]) => init?.method === 'POST');
    expect(posts).toHaveLength(1);
    expect(JSON.parse(String(posts[0]![1]!.body))).toMatchObject({
      command: 'PREVIEW_ASSIGN',
      principalId: value.review.proposedGrant.principalId,
      authorityEnvelopeId: value.review.proposedGrant.authorityEnvelopeId,
      resourceIds: value.review.proposedGrant.resourceIds,
      reason: value.review.reason,
    });
  },
);

function grantDeferred<T = void>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((yes) => {
    resolve = yes;
  });
  return { promise, resolve };
}
function holdGrantCeremony(phase: 'challenge' | 'navigator' | 'VERIFY') {
  const entered = grantDeferred(),
    release = grantDeferred();
  const phases: string[] = [];
  vi.mocked(performWebAuthnStepUp).mockImplementationOnce(async (_action, _binding, lifecycle) => {
    for (const currentPhase of ['challenge', 'navigator', 'VERIFY']) {
      if (lifecycle?.signal?.aborted || !lifecycle?.isCurrent?.())
        throw new DOMException('Cancelled ceremony', 'AbortError');
      phases.push(currentPhase);
      if (currentPhase === phase) {
        entered.resolve(undefined);
        await release.promise;
      }
      if (lifecycle?.signal?.aborted || !lifecycle?.isCurrent?.())
        throw new DOMException('Cancelled ceremony', 'AbortError');
    }
  });
  return { entered, release, phases };
}
function grantCeremonyInput(boundary: 'context' | 'approve' | 'commit') {
  const value = {
    ...savedReview(),
    ...(boundary === 'commit' ? { approvalRequestId: grantApprovalId } : {}),
  };
  const original = JSON.stringify({ actor, value });
  if (boundary !== 'context') localStorage.setItem('openpc:grant-workflow:v1', original);
  const approval = grantApproval(boundary === 'approve' ? 'REQUESTED' : 'APPROVED');
  if (boundary === 'approve') {
    approval.stepUp = {
      actionIntentId: 'ACT-POLICY_APPROVE_REQUEST-V1',
      actionIntentDigest: 'sha256:460403d23ce1c8fb48362b045fb558200fb3ea7ab73469546730b067c1d63cd8',
      resourceId: grantApprovalId,
      resourceDigest: `sha256:${createHash('sha256')
        .update(
          JSON.stringify({
            actionIntentId: 'ACT-POLICY_APPROVE_REQUEST-V1',
            approvalRequestId: approval.approvalRequestId,
            candidateDigest: approval.candidateDigest,
            decision: 'APPROVE',
            expectedRevision: '1',
          }),
        )
        .digest('hex')}`,
    };
  }
  const reader = {
    ...grantState,
    actor: { ...actor, role: boundary === 'approve' ? 'viewer' : 'operator' },
    approvals: [approval],
  };
  const name =
    boundary === 'context'
      ? 'Enter workspace'
      : boundary === 'approve'
        ? `Approve ${principalId}`
        : 'Commit approved grant change';
  return { original, reader, name };
}
it.each(['context', 'approve', 'commit'] as const)(
  'cancels an unmounted grant %s ceremony before later helper phases or business dispatch',
  async (boundary) => {
    const { original, reader, name } = grantCeremonyInput(boundary);
    const held = holdGrantCeremony('navigator');
    const fetcher = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) =>
      Response.json(
        String(input).endsWith('/local-session')
          ? {
              ...grantSession,
              ...(boundary === 'context' ? { contextMode: 'PLATFORM' } : {}),
            }
          : reader,
      ),
    );
    const view = render(<ParticipantGrantWorkflow />);
    const control = await screen.findByRole('button', { name });
    act(() => {
      fireEvent.click(control);
      fireEvent.click(control);
    });
    await held.entered.promise;
    expect(held.phases).toEqual(['challenge', 'navigator']);
    expect(performWebAuthnStepUp).toHaveBeenCalledTimes(1);
    if (boundary !== 'context') {
      const expected =
        boundary === 'approve' ? reader.approvals[0]!.stepUp : savedReview().review.stepUp;
      expect(vi.mocked(performWebAuthnStepUp).mock.calls[0]!.slice(0, 2)).toEqual([
        { ...expected, stepUp: 'FRESH_WEBAUTHN_MAX_5M' },
        expected,
      ]);
      if (boundary === 'approve') expect(expected.resourceId).toBe(grantApprovalId);
    }
    const lifecycle = vi.mocked(performWebAuthnStepUp).mock.calls[0]![2]!;
    expect(lifecycle.isCurrent?.()).toBe(true);
    view.unmount();
    expect(lifecycle.signal?.aborted).toBe(true);
    expect(lifecycle.isCurrent?.()).toBe(false);
    const readsBefore = fetcher.mock.calls.length;
    await act(async () => held.release.resolve(undefined));
    expect(held.phases).not.toContain('VERIFY');
    expect(fetcher.mock.calls).toHaveLength(readsBefore);
    expect(fetcher.mock.calls.some(([, init]) => init?.method === 'POST')).toBe(false);
    if (boundary !== 'context')
      expect(localStorage.getItem('openpc:grant-workflow:v1')).toBe(original);
  },
);
it.each(['challenge', 'navigator', 'VERIFY'] as const)(
  'fences grant commit after a read-selection edit during the held %s phase',
  async (phase) => {
    const { original, reader, name } = grantCeremonyInput('commit');
    const held = holdGrantCeremony(phase);
    const fetcher = vi
      .spyOn(globalThis, 'fetch')
      .mockImplementation(async (input) =>
        Response.json(String(input).endsWith('/local-session') ? grantSession : reader),
      );
    render(<ParticipantGrantWorkflow />);
    fireEvent.click(await screen.findByRole('button', { name }));
    await held.entered.promise;
    expect(held.phases.at(-1)).toBe(phase);
    fireEvent.change(screen.getByLabelText('Grant ID'), {
      target: { value: 'different-selection' },
    });
    expect(vi.mocked(performWebAuthnStepUp).mock.calls[0]![2]!.signal?.aborted).toBe(true);
    await act(async () => held.release.resolve(undefined));
    expect(fetcher.mock.calls.some(([, init]) => init?.method === 'POST')).toBe(false);
    expect(localStorage.getItem('openpc:grant-workflow:v1')).toBe(original);
    expect(screen.queryByText('Grant created and its durable effect read back.')).toBeNull();
    expect(screen.getByRole('button', { name })).toBeEnabled();
  },
);
it('checks grant ownership again when a helper returns despite cancellation', async () => {
  const { original, reader, name } = grantCeremonyInput('approve');
  const held = grantDeferred();
  vi.mocked(performWebAuthnStepUp).mockImplementationOnce(async () => held.promise);
  const fetcher = vi
    .spyOn(globalThis, 'fetch')
    .mockImplementation(async (input) =>
      Response.json(String(input).endsWith('/local-session') ? grantSession : reader),
    );
  render(<ParticipantGrantWorkflow />);
  fireEvent.click(await screen.findByRole('button', { name }));
  await waitFor(() => expect(performWebAuthnStepUp).toHaveBeenCalledTimes(1));
  fireEvent.change(screen.getByLabelText('Grant type to read'), {
    target: { value: 'delegation' },
  });
  await act(async () => held.resolve(undefined));
  expect(fetcher.mock.calls.some(([, init]) => init?.method === 'POST')).toBe(false);
  expect(localStorage.getItem('openpc:grant-workflow:v1')).toBe(original);
});
it.each([
  { truthState: 'WRITE_AMBIGUITY' },
  { truthState: 'SUCCESS', reauthenticationRequired: true },
])(
  'retains an already-sent grant reconciliation result across a same-actor selection edit: %o',
  async (result) => {
    const { original, reader, name } = grantCeremonyInput('commit');
    const post = grantDeferred<Response>();
    const fetcher = vi
      .spyOn(globalThis, 'fetch')
      .mockImplementation(async (input, init) =>
        init?.method === 'POST'
          ? post.promise
          : Response.json(String(input).endsWith('/local-session') ? grantSession : reader),
      );
    render(<ParticipantGrantWorkflow />);
    fireEvent.click(await screen.findByRole('button', { name }));
    await waitFor(() =>
      expect(fetcher.mock.calls.filter(([, init]) => init?.method === 'POST')).toHaveLength(1),
    );
    const mutation = fetcher.mock.calls.find(([, init]) => init?.method === 'POST')!;
    expect(JSON.parse(String(mutation[1]!.body))).toEqual({
      command: 'COMMIT',
      reviewToken: 'sealed-review',
      approvalRequestId: grantApprovalId,
    });
    fireEvent.change(screen.getByLabelText('Grant ID'), { target: { value: 'another-read' } });
    await act(async () => post.resolve(Response.json(result)));
    expect(
      await screen.findByRole('button', { name: 'Read grant after signing in' }),
    ).toBeEnabled();
    expect(screen.queryByRole('button', { name })).toBeNull();
    expect(localStorage.getItem('openpc:grant-workflow:v1')).toBe(original);
    expect(fetcher.mock.calls.filter(([, init]) => init?.method === 'POST')).toHaveLength(1);
  },
);
it('ignores a late grant preview after unmount without changing original custody', async () => {
  const original = JSON.stringify({ actor, value: savedReview() });
  localStorage.setItem('openpc:grant-workflow:v1', original);
  const post = grantDeferred<Response>();
  const fetcher = vi
    .spyOn(globalThis, 'fetch')
    .mockImplementation(async (input, init) =>
      init?.method === 'POST'
        ? post.promise
        : Response.json(String(input).endsWith('/local-session') ? grantSession : grantState),
    );
  const view = render(<ParticipantGrantWorkflow />);
  const form = (await screen.findByRole('button', { name: 'Review grant creation' })).closest(
    'form',
  )!;
  grantCreationInputs(form);
  act(() => {
    fireEvent.submit(form);
    fireEvent.submit(form);
  });
  await waitFor(() =>
    expect(fetcher.mock.calls.filter(([, init]) => init?.method === 'POST')).toHaveLength(1),
  );
  view.unmount();
  const before = fetcher.mock.calls.length;
  await act(async () =>
    post.resolve(Response.json({ ...savedReview(), reviewToken: 'different-review' })),
  );
  expect(fetcher.mock.calls).toHaveLength(before);
  expect(localStorage.getItem('openpc:grant-workflow:v1')).toBe(original);
});

it.each([
  { truthState: 'WRITE_AMBIGUITY' },
  { truthState: 'SUCCESS', reauthenticationRequired: true },
])(
  'reads the original revoked grant under a new legitimate session without rebinding its sealed review: %o',
  async (result) => {
    const value = { ...savedReview(), approvalRequestId: grantApprovalId };
    value.review.mutation = 'REVOKE';
    const original = JSON.stringify({ actor, value });
    localStorage.setItem('openpc:grant-workflow:v1', original);
    const nextActor = {
      ...actor,
      sessionId: '018f0000-0000-7000-8000-000000000119',
      contextEpoch: '3',
    };
    let renewed = false;
    const queries: string[] = [],
      posts: unknown[] = [];
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (url, init) => {
      if (init?.method === 'POST') {
        posts.push(JSON.parse(String(init.body)));
        return Response.json(result, { status: 202 });
      }
      if (String(url).endsWith('/local-session'))
        return Response.json({ ...grantSession, ...(renewed ? nextActor : {}) });
      queries.push(String(url));
      return Response.json(
        renewed
          ? {
              actor: { ...nextActor, role: 'operator' },
              approvals: [],
              nextCursor: null,
              effect: {
                effect: { ...value.review.proposedGrant, state: 'REVOKED' },
                revision: '2',
                operationId: 'original-grant-operation',
              },
            }
          : { ...grantState, approvals: [grantApproval('APPROVED')] },
      );
    });
    render(<ParticipantGrantWorkflow />);
    fireEvent.click(await screen.findByRole('button', { name: 'Commit approved grant change' }));
    const read = await screen.findByRole('button', { name: 'Read grant after signing in' });
    renewed = true;
    fireEvent.click(read);
    await screen.findByText('original-grant-operation', { exact: false });
    expect(queries).toHaveLength(2);
    expect(Object.fromEntries(new URL(queries[1]!, 'http://localhost').searchParams)).toEqual({
      grantId: principalId,
      kind: 'assignment',
    });
    expect(posts).toEqual([
      { command: 'COMMIT', reviewToken: value.reviewToken, approvalRequestId: grantApprovalId },
    ]);
    expect(localStorage.getItem('openpc:grant-workflow:v1')).toBe(original);
    expect(screen.queryByRole('region', { name: 'Grant change review' })).toBeNull();
    expect(screen.queryByRole('button', { name: 'Commit approved grant change' })).toBeNull();
    expect(screen.queryByRole('button', { name: 'Send grant to checker' })).toBeNull();
    expect(screen.getByLabelText('Grant ID')).toHaveValue(principalId);
    expect(screen.getByLabelText('Grant type to read')).toHaveValue('assignment');
  },
);
it.each(['principalId', 'participantId', 'privacyDomainId'] as const)(
  'does not carry an original grant read selector into a newly authenticated foreign %s',
  async (field) => {
    const { original, reader, name } = grantCeremonyInput('commit');
    const nextActor = {
      ...actor,
      sessionId: '018f0000-0000-7000-8000-000000000119',
      [field]: '018f0000-0000-7000-8000-000000000999',
      contextEpoch: '3',
    };
    let renewed = false;
    const queries: string[] = [],
      posts: unknown[] = [];
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (url, init) => {
      if (init?.method === 'POST') {
        posts.push(JSON.parse(String(init.body)));
        return Response.json({ truthState: 'WRITE_AMBIGUITY' }, { status: 202 });
      }
      if (String(url).endsWith('/local-session'))
        return Response.json({ ...grantSession, ...(renewed ? nextActor : {}) });
      queries.push(String(url));
      return Response.json(
        renewed ? { ...grantState, actor: { ...nextActor, role: 'operator' } } : reader,
      );
    });
    render(<ParticipantGrantWorkflow />);
    fireEvent.click(await screen.findByRole('button', { name }));
    const read = await screen.findByRole('button', { name: 'Read grant after signing in' });
    renewed = true;
    fireEvent.click(read);
    await waitFor(() => expect(queries).toHaveLength(2));
    expect(new URL(queries[1]!, 'http://localhost').searchParams.has('grantId')).toBe(false);
    expect(new URL(queries[1]!, 'http://localhost').searchParams.has('kind')).toBe(false);
    await waitFor(() => expect(screen.getByLabelText('Grant ID')).toHaveValue(''));
    expect(screen.queryByRole('button', { name: 'Send grant to checker' })).toBeNull();
    expect(posts).toHaveLength(1);
    expect(localStorage.getItem('openpc:grant-workflow:v1')).toBe(original);
  },
);
it('keeps a confirmed grant preview usable when optional storage throws', async () => {
  const fetcher = vi
    .spyOn(globalThis, 'fetch')
    .mockImplementation(async (input, init) =>
      init?.method === 'POST'
        ? Response.json(savedReview())
        : Response.json(String(input).endsWith('/local-session') ? grantSession : grantState),
    );
  render(<ParticipantGrantWorkflow />);
  const form = (await screen.findByRole('button', { name: 'Review grant creation' })).closest(
    'form',
  )!;
  grantCreationInputs(form);
  vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => {
    throw new Error(unsafeGrantMarker);
  });
  fireEvent.submit(form);
  expect(await screen.findByRole('button', { name: 'Send grant to checker' })).toBeEnabled();
  expect(document.body.textContent).not.toContain(unsafeGrantMarker);
  expect(fetcher.mock.calls.filter(([, init]) => init?.method === 'POST')).toHaveLength(1);
});

it.each([
  { participantId: actor.participantId, privacyDomainId: actor.privacyDomainId },
  {
    participantId: '018f0000-0000-7000-8000-000000000102',
    privacyDomainId: '018f0000-0000-7000-8000-000000007201',
  },
])('selects the server grant context and captures its source session: %o', async (context) => {
  const sourceSessionId = '018f0000-0000-7000-8000-000000000118';
  let selected = false;
  const currentActor = { ...actor, ...context, sessionId: sourceSessionId };
  const fetcher = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
    if (init?.method === 'POST') {
      expect(String(input)).toBe('/api/v1/ui/session/context');
      selected = true;
      return Response.json({ accepted: true });
    }
    return Response.json(
      String(input).endsWith('/local-session')
        ? {
            ...grantSession,
            sessionId: sourceSessionId,
            ...(selected ? context : { privacyDomainId: undefined }),
            contextMode: selected ? 'PARTICIPANT' : 'PLATFORM',
            availableContexts: [
              { ...context, displayLabel: 'Server context' },
              ...grantSession.availableContexts,
            ],
          }
        : { ...grantState, actor: { ...currentActor, role: 'operator' } },
    );
  });
  render(<ParticipantGrantWorkflow />);
  fireEvent.click(await screen.findByRole('button', { name: 'Enter workspace' }));
  await screen.findByText('Participant privacy context is active.');
  expect(performWebAuthnStepUp).toHaveBeenCalledWith(
    expect.objectContaining({ actionIntentId: 'ACT-IDENTITY_CREATE_SESSION-V1' }),
    {
      actionIntentId: 'ACT-IDENTITY_CREATE_SESSION-V1',
      actionIntentDigest: 'sha256:dbc8290dd60814d5bb4248fefc9550f43d0dc97d6333ac232c8ab8a98c3354d2',
      resourceId: context.participantId,
      resourceDigest: `sha256:${createHash('sha256').update(JSON.stringify(context)).digest('hex')}`,
    },
    expect.objectContaining({ signal: expect.any(AbortSignal), isCurrent: expect.any(Function) }),
  );
  const posts = fetcher.mock.calls.filter(([, init]) => init?.method === 'POST');
  expect(posts).toHaveLength(1);
  expect(JSON.parse(String(posts[0]![1]?.body))).toEqual({
    ...context,
    expectedSessionId: sourceSessionId,
  });
});
it.each([
  { name: 'missing contexts', override: { availableContexts: undefined } },
  { name: 'empty contexts', override: { availableContexts: [] } },
  {
    name: 'missing privacy',
    override: { availableContexts: [{ participantId: actor.participantId }] },
  },
  {
    name: 'malformed Participant',
    override: {
      availableContexts: [{ participantId: 'invalid', privacyDomainId: actor.privacyDomainId }],
    },
  },
  { name: 'malformed session', override: { sessionId: 'invalid' } },
  { name: 'missing session', override: { sessionId: undefined } },
])('rejects grant context selection with $name before any proof or POST', async ({ override }) => {
  const fetcher = vi
    .spyOn(globalThis, 'fetch')
    .mockResolvedValue(Response.json({ ...grantSession, contextMode: 'PLATFORM', ...override }));
  render(<ParticipantGrantWorkflow />);
  fireEvent.click(await screen.findByRole('button', { name: 'Enter workspace' }));
  await screen.findByText(grantUnavailable);
  expect(performWebAuthnStepUp).not.toHaveBeenCalled();
  expect(fetcher.mock.calls.some(([, init]) => init?.method === 'POST')).toBe(false);
});
it('stops an unmounted grant context digest before ceremony and preserves original custody', async () => {
  const held = grantDeferred<ArrayBuffer>();
  const digest = vi.spyOn(crypto.subtle, 'digest').mockReturnValueOnce(held.promise);
  const fetcher = vi
    .spyOn(globalThis, 'fetch')
    .mockResolvedValue(Response.json({ ...grantSession, contextMode: 'PLATFORM' }));
  const view = render(<ParticipantGrantWorkflow />);
  const control = await screen.findByRole('button', { name: 'Enter workspace' });
  const original = JSON.stringify({ actor, value: savedReview() });
  localStorage.setItem('openpc:grant-workflow:v1', original);
  fireEvent.click(control);
  await waitFor(() => expect(digest).toHaveBeenCalledOnce());
  const calls = fetcher.mock.calls.length;
  view.unmount();
  await act(async () => held.resolve(new ArrayBuffer(32)));
  expect(fetcher.mock.calls).toHaveLength(calls);
  expect(performWebAuthnStepUp).not.toHaveBeenCalled();
  expect(localStorage.getItem('openpc:grant-workflow:v1')).toBe(original);
});
it.each([
  ['digest', 'session'],
  ['digest', 'selection'],
  ['proof', 'session'],
  ['proof', 'selection'],
] as const)('fences grant context %s after the source %s changes', async (phase, changed) => {
  let source = { ...grantSession, contextMode: 'PLATFORM' };
  const heldDigest = grantDeferred<ArrayBuffer>();
  const digest =
    phase === 'digest'
      ? vi.spyOn(crypto.subtle, 'digest').mockReturnValueOnce(heldDigest.promise)
      : undefined;
  const proof = phase === 'proof' ? holdGrantCeremony('navigator') : undefined;
  const fetcher = vi
    .spyOn(globalThis, 'fetch')
    .mockImplementation(async () => Response.json(source));
  render(<ParticipantGrantWorkflow />);
  const control = await screen.findByRole('button', { name: 'Enter workspace' });
  const original = JSON.stringify({ actor, value: savedReview() });
  localStorage.setItem('openpc:grant-workflow:v1', original);
  fireEvent.click(control);
  if (digest) await waitFor(() => expect(digest).toHaveBeenCalledOnce());
  else await proof!.entered.promise;
  source =
    changed === 'session'
      ? { ...source, sessionId: '018f0000-0000-7000-8000-000000000118' }
      : {
          ...source,
          availableContexts: [
            {
              ...grantSession.availableContexts[0]!,
              privacyDomainId: '018f0000-0000-7000-8000-000000007201',
            },
          ],
        };
  await act(async () => {
    if (digest) heldDigest.resolve(new ArrayBuffer(32));
    else proof!.release.resolve(undefined);
  });
  await screen.findByText('The authenticated handoff context changed. Refresh before continuing.');
  expect(performWebAuthnStepUp).toHaveBeenCalledTimes(phase === 'digest' ? 0 : 1);
  expect(fetcher.mock.calls.some(([, init]) => init?.method === 'POST')).toBe(false);
  expect(localStorage.getItem('openpc:grant-workflow:v1')).toBe(original);
});
