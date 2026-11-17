// Presentation-owner regressions: all HTTP responses and authenticator calls are mocked.
// These fixtures do not establish real bootstrap authority, approval or recipient acceptance.
import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { performWebAuthnStepUp } from '@openpc/ui-shell';
import { ParticipantBootstrapWorkflow } from './participant-bootstrap';
import { sessionTransitionEvent, sessionTransitionStorageKey } from './session-transition';

vi.mock('@openpc/ui-shell', () => ({ performWebAuthnStepUp: vi.fn(async () => undefined) }));
vi.mock('./local-session', () => ({
  LocalSessionSurface: () => <p>Authenticated session controls</p>,
}));

const id = (value: number) => `018f0000-0000-7000-8000-${String(value).padStart(12, '0')}`;
const digest = `sha256:${'a'.repeat(64)}`;
const storageKey = 'openpc:first-admin-review';
const actor = {
  authenticated: true,
  sessionId: id(21),
  principalId: id(10),
  participantId: id(20),
  contextMode: 'PLATFORM',
  privacyDomainId: null,
  contextEpoch: '1',
};
const session = { ...actor, privacyDomainId: undefined, enabled: true };
let sessionResponse: () => Promise<Response>;
const sessionReads = vi.fn();
beforeEach(() => {
  sessionReads.mockClear();
  sessionResponse = async () => Response.json(session);
});
function mockBootstrapFetch() {
  const commands = vi.fn<typeof fetch>();
  vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
    if (input === '/api/v1/ui/local-session') {
      expect(init).toMatchObject({ cache: 'no-store', signal: expect.any(AbortSignal) });
      sessionReads();
      return sessionResponse();
    }
    return commands(input, init);
  });
  return commands;
}
async function renderPlatform() {
  const result = render(<ParticipantBootstrapWorkflow />);
  await screen.findByRole('heading', {
    name: 'Create a Participant and invite its first administrator',
  });
  return result;
}
const approvalId = id(801);
const makerId = id(10),
  checkerId = id(11);
const candidate = {
  participantId: id(100),
  displayName: 'Original proposed Participant',
  idempotencyKey: 'original-participant-bootstrap-intent',
  firstAdministrator: {
    invitationId: id(101),
    mandateId: id(102),
    privacyDomainId: id(103),
    roleId: id(104),
    authorityEnvelopeId: id(105),
    assignmentId: id(106),
    displayName: 'Original administrator',
    recipientIssuer: 'https://identity.example.test',
    recipientSubject: 'exact-original-account',
    recipientAudience: 'original-audience',
    tokenDigest: `sha256:${'b'.repeat(64)}`,
    actionIntentIds: ['ACT-PARTICIPANTS_READ_RESOURCE-V1'],
    configuration: { 'participant.first_admin_invite_ttl': 7200000 },
  },
};
const stepUp = {
  actionIntentId: 'ACT-PARTICIPANTS_CREATE_RESOURCE-V1',
  actionIntentDigest: digest,
  resourceId: candidate.participantId,
  resourceDigest: digest,
};
const review = {
  candidate,
  candidateDigest: digest,
  reviewToken: 'original-sealed-review-'.repeat(5),
  stepUp,
};
const custody = {
  participantId: candidate.participantId,
  privacyDomainId: candidate.firstAdministrator.privacyDomainId,
  mandateId: candidate.firstAdministrator.mandateId,
  invitationId: candidate.firstAdministrator.invitationId,
  makerPrincipalId: makerId,
  checkerPrincipalId: checkerId,
  custodyGeneration: '1',
  tokenVersion: '2',
  revision: '3',
  state: 'ACTIVE',
  expiresAt: '2030-01-01T00:00:00.000Z',
  operationId: id(777),
};
function changeReview(mutation: 'ROTATE' | 'REVOKE' = 'ROTATE') {
  return {
    ...review,
    candidate: {
      participantId: custody.participantId,
      mandateId: custody.mandateId,
      invitationId: custody.invitationId,
      custodyGeneration: custody.custodyGeneration,
      tokenVersion: custody.tokenVersion,
      expectedRevision: custody.revision,
      idempotencyKey: 'original-custody-change-intent',
      change:
        mutation === 'ROTATE'
          ? { mutation, tokenDigest: `sha256:${'c'.repeat(64)}` }
          : { mutation },
    },
  };
}
function pendingRead(
  value: typeof review | ReturnType<typeof changeReview> = review,
  proposalState = 'APPROVED',
) {
  return {
    state: 'NOT_CONSUMED',
    proposalState,
    participantId: value.candidate.participantId,
    candidateDigest: value.candidateDigest,
  };
}
function checked(state = 'REQUESTED') {
  return {
    proposal: {
      candidate,
      candidateDigest: digest,
      state: 'APPROVAL_REQUESTED',
      expiresAt: custody.expiresAt,
      operationId: null,
      result: null,
    },
    approval: { approvalRequestId: `urn:openpc:resource:${approvalId}`, state, revision: '1' },
    stepUp: { ...stepUp, actionIntentId: 'ACT-POLICY_APPROVE_REQUEST-V1', resourceId: approvalId },
  };
}
function approvedResponse() {
  return {
    operation: {
      operationId: id(900),
      actionIntentId: 'ACT-POLICY_APPROVE_REQUEST-V1',
      intentDigest: digest,
      idempotencyKey: `workbench-approve-${approvalId}`,
      resourceRef: `urn:openpc:resource:${approvalId}`,
      revision: '2',
      state: 'SUCCEEDED',
      truthState: 'SUCCESS',
      createdAt: '2026-10-04T00:00:00.000Z',
      updatedAt: '2026-10-04T00:00:00.000Z',
    },
    approval: {
      ...checked('APPROVED').approval,
      candidateDigest: digest,
      makerSubjectRef: `urn:openpc:resource:${makerId}`,
      checkerSubjectRef: `urn:openpc:resource:${checkerId}`,
    },
  };
}
function seed(
  value: typeof review | ReturnType<typeof changeReview> = review,
  selectedApproval = approvalId,
  savedAt = Date.now() - 1000,
) {
  const original = JSON.stringify({ actor, review: value, approvalId: selectedApproval, savedAt });
  sessionStorage.setItem(storageKey, original);
  return original;
}
afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  vi.clearAllMocks();
  sessionStorage.clear();
  localStorage.clear();
});
const unsafeMarker = 'PRIVATE_BOOTSTRAP_SERVER_TRANSPORT_OR_VALIDATOR_DETAIL';
const unavailable =
  'Participant bootstrap could not be confirmed. Read the original approval or custody before retrying.';
const failures = [
  {
    name: 'authorization',
    status: 403,
    message:
      'Participant bootstrap was not authorized. Refresh the authenticated context before continuing.',
  },
  {
    name: 'conflict',
    status: 409,
    message:
      'Participant bootstrap state changed. Read the original approval or custody before retrying.',
  },
  {
    name: 'input',
    status: 422,
    message: 'Participant bootstrap was rejected. Check the inputs before continuing.',
  },
  { name: 'unknown code', status: 503, message: unavailable },
  { name: 'transport', message: unavailable },
  { name: 'unknown thrown object', message: unavailable },
  { name: 'non-JSON success', message: unavailable },
  { name: 'malformed JSON success', message: unavailable },
] as const;
function fail(failure: (typeof failures)[number]): Response {
  if ('status' in failure)
    return Response.json(
      {
        title: unsafeMarker,
        code: failure.name === 'unknown code' ? 'PC-AUTH-0005' : unsafeMarker,
      },
      { status: failure.status },
    );
  if (failure.name === 'transport') throw new Error(unsafeMarker);
  if (failure.name === 'unknown thrown object') throw { message: unsafeMarker, code: unsafeMarker };
  return new Response(failure.name === 'non-JSON success' ? unsafeMarker : '{', { status: 200 });
}
const controls = {
  SESSION: 'Verify Platform authenticator',
  PREPARE: 'Prepare first-administrator review',
  SUBMIT: 'Request first-administrator approval',
  COMMIT: 'Check original invitation status',
  READ_ORIGINAL: 'Read original invitation outcome',
  READ_CUSTODY: 'Read first-administrator custody',
  PREPARE_CHANGE: 'Prepare custody change',
  REVIEW: 'Load first-administrator approval',
  APPROVE: 'Approve first administration with authenticator',
} as const;
type Boundary = keyof typeof controls;
function creationInputs() {
  for (const [label, value] of [
    ['New Participant name', candidate.displayName],
    ['First administrator name', candidate.firstAdministrator.displayName],
    ['Administrator identity provider issuer', candidate.firstAdministrator.recipientIssuer],
    ['Exact administrator account subject', candidate.firstAdministrator.recipientSubject],
    ['Administrator identity provider audience', candidate.firstAdministrator.recipientAudience],
    ['Independent Platform checker ID', checkerId],
    [
      'Reason for creating this Participant',
      'Create the exact original Participant administration.',
    ],
    ['First-administrator invitation lifetime (minutes)', '120'],
  ])
    fireEvent.change(screen.getByLabelText(label!), { target: { value } });
  const fields = screen.getByRole('group', { name: 'Administrator capabilities' });
  for (const checkbox of within(fields).getAllByRole('checkbox')) {
    const selected =
      (checkbox as HTMLInputElement).value === candidate.firstAdministrator.actionIntentIds[0];
    if ((checkbox as HTMLInputElement).checked !== selected) fireEvent.click(checkbox);
  }
}
function checkerInputs() {
  for (const [label, value] of [
    ['Proposed Participant ID', candidate.participantId],
    ['First-administrator candidate digest', digest],
    ['First-administrator approval request ID', approvalId],
  ])
    fireEvent.change(screen.getByLabelText(label!), { target: { value } });
}
async function controlFor(boundary: Boundary) {
  await screen.findByRole('region', { name: 'Prepared first administration' });
  if (boundary === 'PREPARE') creationInputs();
  if (boundary === 'READ_CUSTODY' || boundary === 'PREPARE_CHANGE')
    fireEvent.change(screen.getByLabelText('Participant with outstanding first administration'), {
      target: { value: candidate.participantId },
    });
  if (boundary === 'PREPARE_CHANGE') {
    fireEvent.click(screen.getByRole('button', { name: controls.READ_CUSTODY }));
    await screen.findByText(/Custody state: ACTIVE/);
    fireEvent.change(screen.getByLabelText('Reason for changing first-administrator custody'), {
      target: { value: 'Rotate the exact original custody invitation.' },
    });
  }
  if (boundary === 'REVIEW' || boundary === 'APPROVE') checkerInputs();
  if (boundary === 'APPROVE') {
    fireEvent.click(screen.getByRole('button', { name: controls.REVIEW }));
    await screen.findByText('Approval state: REQUESTED');
  }
  if (boundary === 'COMMIT') {
    fireEvent.click(screen.getByRole('button', { name: controls.COMMIT }));
    const control = await screen.findByRole('button', {
      name: /^Verify and (issue invitation|apply custody change)$/u,
    });
    await waitFor(() => expect(control).toBeEnabled());
    return control;
  }
  return screen.getByRole('button', { name: controls[boundary] });
}
function invoke(control: HTMLElement, boundary: Boundary) {
  if (boundary === 'PREPARE' || boundary === 'PREPARE_CHANGE')
    fireEvent.submit(control.closest('form')!);
  else fireEvent.click(control);
}
function expectedBody(boundary: Boundary) {
  if (boundary === 'PREPARE')
    return {
      command: 'PREPARE',
      displayName: candidate.displayName,
      administratorName: candidate.firstAdministrator.displayName,
      recipientIssuer: candidate.firstAdministrator.recipientIssuer,
      recipientSubject: candidate.firstAdministrator.recipientSubject,
      recipientAudience: candidate.firstAdministrator.recipientAudience,
      ttlMinutes: 120,
      checkerPrincipalId: checkerId,
      reason: 'Create the exact original Participant administration.',
      actionIntentIds: candidate.firstAdministrator.actionIntentIds,
    };
  if (boundary === 'SUBMIT') return { command: 'SUBMIT', reviewToken: review.reviewToken };
  if (boundary === 'COMMIT')
    return { command: 'COMMIT', reviewToken: review.reviewToken, approvalRequestId: approvalId };
  if (boundary === 'READ_ORIGINAL')
    return { command: 'READ_ORIGINAL', reviewToken: review.reviewToken };
  if (boundary === 'READ_CUSTODY')
    return { command: 'READ_CUSTODY', participantId: candidate.participantId };
  if (boundary === 'PREPARE_CHANGE')
    return {
      command: 'PREPARE_CHANGE',
      participantId: custody.participantId,
      mutation: 'ROTATE',
      reason: 'Rotate the exact original custody invitation.',
    };
  if (boundary === 'REVIEW' || boundary === 'APPROVE')
    return {
      command: boundary,
      resourceId: candidate.participantId,
      candidateDigest: digest,
      approvalRequestId: approvalId,
    };
  return { command: 'SESSION' };
}
function commands(fetcher: { mock: { calls: Parameters<typeof globalThis.fetch>[] } }) {
  return fetcher.mock.calls.map(([input, init]) => {
    expect(input).toBe('/api/v1/ui/participant-bootstrap');
    expect(init).toMatchObject({
      method: 'POST',
      cache: 'no-store',
      headers: { 'Content-Type': 'application/json' },
    });
    return JSON.parse(String(init!.body));
  });
}
function prefix(boundary: Boundary) {
  return boundary === 'PREPARE_CHANGE'
    ? ['READ_CUSTODY']
    : boundary === 'APPROVE'
      ? ['REVIEW']
      : boundary === 'COMMIT'
        ? ['READ_ORIGINAL']
        : [];
}
it.each(
  failures.flatMap((failure) =>
    (Object.keys(controls) as Boundary[]).map((boundary) => ({ ...failure, boundary })),
  ),
)(
  'hides $name from $boundary and preserves the original review without automatic replay or success',
  async (failure) => {
    const original = seed(review, failure.boundary === 'SUBMIT' ? '' : approvalId);
    const fetcher = mockBootstrapFetch().mockImplementation(async (_input, init) => {
      const body = JSON.parse(String(init!.body));
      if (body.command === failure.boundary) return fail(failure);
      if (body.command === 'READ_ORIGINAL') return Response.json(pendingRead());
      if (body.command === 'READ_CUSTODY') return Response.json(custody);
      if (body.command === 'REVIEW') return Response.json(checked());
      throw new Error('Unexpected bootstrap command');
    });
    await renderPlatform();
    invoke(await controlFor(failure.boundary), failure.boundary);
    await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent(failure.message));
    expect(document.body.textContent).not.toContain(unsafeMarker);
    expect(document.body.textContent).not.toContain('PC-AUTH-0005');
    expect(sessionStorage.getItem(storageKey)).toBe(original);
    expect(screen.queryByLabelText('First-administrator invitation link')).not.toBeInTheDocument();
    expect(screen.queryByText('Platform authenticator verified.')).not.toBeInTheDocument();
    expect(
      screen.queryByText('Independent approval requested. No invitation has been issued yet.'),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByText('Independent approval recorded. The maker can issue the invitation.'),
    ).not.toBeInTheDocument();
    const observed = commands(fetcher);
    expect(observed.map((body) => body.command)).toEqual([
      ...prefix(failure.boundary),
      failure.boundary,
    ]);
    expect(observed.at(-1)).toEqual(expectedBody(failure.boundary));
    await waitFor(() =>
      expect(screen.getByRole('button', { name: controls.SESSION })).toBeEnabled(),
    );
    expect(commands(fetcher)).toHaveLength(observed.length);
    if (failure.boundary === 'SESSION') expect(performWebAuthnStepUp).not.toHaveBeenCalled();
  },
);
it.each([
  'SESSION',
  'PREPARE',
  'SUBMIT',
  'COMMIT',
  'READ_ORIGINAL',
  'READ_CUSTODY',
  'PREPARE_CHANGE',
  'REVIEW',
] as const)(
  'hides structured validator details from %s before replacing custody or reporting success',
  async (boundary) => {
    const original = seed(review, boundary === 'SUBMIT' ? '' : approvalId);
    const fetcher = mockBootstrapFetch().mockImplementation(async (_input, init) => {
      const body = JSON.parse(String(init!.body));
      if (body.command === 'READ_ORIGINAL' && boundary !== 'READ_ORIGINAL')
        return Response.json(pendingRead());
      return body.command === boundary
        ? Response.json({
            candidate: { displayName: unsafeMarker },
            approvalRequestId: unsafeMarker,
            participantId: unsafeMarker,
            state: unsafeMarker,
            stepUp: { resourceId: unsafeMarker },
          })
        : Response.json(custody);
    });
    await renderPlatform();
    invoke(await controlFor(boundary), boundary);
    await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent(unavailable));
    expect(document.body.textContent).not.toContain(unsafeMarker);
    expect(document.body.textContent).not.toContain('invalid_type');
    expect(sessionStorage.getItem(storageKey)).toBe(original);
    expect(screen.queryByLabelText('First-administrator invitation link')).not.toBeInTheDocument();
    expect(commands(fetcher).map((body) => body.command)).toEqual([...prefix(boundary), boundary]);
  },
);
it('does not report independent approval when the post-APPROVE authoritative review is unreadable', async () => {
  const original = seed();
  let reviews = 0;
  const fetcher = mockBootstrapFetch().mockImplementation(async (_input, init) => {
    const body = JSON.parse(String(init!.body));
    if (body.command === 'APPROVE') return Response.json(approvedResponse(), { status: 202 });
    return Response.json(++reviews === 1 ? checked() : { proposal: { candidate: unsafeMarker } });
  });
  await renderPlatform();
  fireEvent.click(await controlFor('APPROVE'));
  await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent(unavailable));
  expect(document.body.textContent).not.toContain(unsafeMarker);
  expect(
    screen.queryByText('Independent approval recorded. The maker can issue the invitation.'),
  ).not.toBeInTheDocument();
  expect(sessionStorage.getItem(storageKey)).toBe(original);
  expect(commands(fetcher).map((body) => body.command)).toEqual(['REVIEW', 'APPROVE', 'REVIEW']);
});
it.each(['SESSION', 'COMMIT', 'APPROVE'] as const)(
  'hides private authenticator failures at %s and forbids its effect before verification',
  async (boundary) => {
    const original = seed();
    vi.mocked(performWebAuthnStepUp).mockRejectedValueOnce(new Error(unsafeMarker));
    const fetcher = mockBootstrapFetch().mockImplementation(async (_input, init) =>
      Response.json(
        JSON.parse(String(init!.body)).command === 'SESSION'
          ? { stepUp }
          : JSON.parse(String(init!.body)).command === 'READ_ORIGINAL'
            ? pendingRead()
            : checked(),
      ),
    );
    await renderPlatform();
    fireEvent.click(await controlFor(boundary));
    await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent(unavailable));
    expect(document.body.textContent).not.toContain(unsafeMarker);
    expect(sessionStorage.getItem(storageKey)).toBe(original);
    expect(commands(fetcher).map((body) => body.command)).toEqual(
      boundary === 'SESSION' ? ['SESSION'] : prefix(boundary),
    );
    expect(screen.queryByLabelText('First-administrator invitation link')).not.toBeInTheDocument();
  },
);
it.each([200, 201, 202])(
  'preserves all valid HTTP %s bootstrap command families and separate owner readback',
  async (status) => {
    const original = seed(review, '');
    let approved = false;
    const invitationLink = `https://localhost/govern/memberships?view=invitation-acceptance#participantId=${candidate.participantId}&token=example-original-invitation`;
    const fetcher = mockBootstrapFetch().mockImplementation(async (_input, init) => {
      const body = JSON.parse(String(init!.body));
      if (body.command === 'APPROVE') {
        approved = true;
        return Response.json(approvedResponse(), { status });
      }
      return Response.json(
        body.command === 'SESSION'
          ? { actor: { participantId: id(20), principalId: makerId, sessionId: id(21) }, stepUp }
          : body.command === 'PREPARE'
            ? review
            : body.command === 'SUBMIT'
              ? { approvalRequestId: approvalId }
              : body.command === 'READ_CUSTODY'
                ? custody
                : body.command === 'READ_ORIGINAL'
                  ? pendingRead()
                  : body.command === 'REVIEW'
                    ? checked(approved ? 'APPROVED' : 'REQUESTED')
                    : body.command === 'PREPARE_CHANGE'
                      ? changeReview()
                      : {
                          operationId: id(900),
                          participantId: candidate.participantId,
                          state: 'PROVISIONING',
                          invitationLink,
                        },
        { status },
      );
    });
    await renderPlatform();
    fireEvent.click(await controlFor('SESSION'));
    await screen.findByText('Platform authenticator verified.');
    expect(sessionStorage.getItem(storageKey)).toBe(original);
    expect(performWebAuthnStepUp).toHaveBeenLastCalledWith(
      { ...stepUp, stepUp: 'FRESH_WEBAUTHN_MAX_5M' },
      stepUp,
    );
    invoke(await controlFor('PREPARE'), 'PREPARE');
    await screen.findByText(
      'Review the exact administrator, provider, capabilities and lifetime before requesting independent approval.',
    );
    expect(JSON.parse(sessionStorage.getItem(storageKey)!).review).toEqual(review);
    expect(JSON.parse(sessionStorage.getItem(storageKey)!).approvalId).toBe('');
    fireEvent.click(screen.getByRole('button', { name: controls.SUBMIT }));
    await screen.findByText('Independent approval requested. No invitation has been issued yet.');
    expect(JSON.parse(sessionStorage.getItem(storageKey)!).approvalId).toBe(approvalId);
    expect(screen.queryByLabelText('First-administrator invitation link')).not.toBeInTheDocument();
    fireEvent.click(await controlFor('APPROVE'));
    await screen.findByText('Independent approval recorded. The maker can issue the invitation.');
    await screen.findByText('Approval state: APPROVED');
    expect(screen.getByRole('button', { name: controls.APPROVE })).toBeDisabled();
    fireEvent.click(screen.getByRole('button', { name: controls.COMMIT }));
    expect(performWebAuthnStepUp).toHaveBeenCalledTimes(2); // SESSION and checker only.
    const continuation = await screen.findByRole('button', {
      name: /^Verify and (issue invitation|apply custody change)$/u,
    });
    await waitFor(() => expect(continuation).toBeEnabled());
    fireEvent.click(continuation);
    await screen.findByText(
      'The empty Participant and invitation are saved. Administration remains inactive until recipient acceptance.',
    );
    expect(screen.getByLabelText('First-administrator invitation link')).toHaveValue(
      invitationLink,
    );
    invoke(await controlFor('PREPARE_CHANGE'), 'PREPARE_CHANGE');
    await screen.findByText(
      'Review this custody change and request approval from the original independent checker.',
    );
    expect(JSON.parse(sessionStorage.getItem(storageKey)!).review).toEqual(changeReview());
    expect(JSON.parse(sessionStorage.getItem(storageKey)!).approvalId).toBe('');
    expect(screen.queryByLabelText('First-administrator invitation link')).not.toBeInTheDocument();
    const observed = commands(fetcher);
    expect(observed.map((body) => body.command)).toEqual([
      'SESSION',
      'PREPARE',
      'SUBMIT',
      'REVIEW',
      'APPROVE',
      'REVIEW',
      'READ_ORIGINAL',
      'COMMIT',
      'READ_CUSTODY',
      'PREPARE_CHANGE',
    ]);
    for (const body of observed) expect(body).toEqual(expectedBody(body.command as Boundary));
  },
);
it.each(['ROTATE', 'REVOKE'] as const)(
  'reads the existing %s consumed custody outcome without a new ceremony or changing the stored intent',
  async (mutation) => {
    const value = changeReview(mutation);
    const original = seed(value);
    const state = mutation === 'ROTATE' ? 'ACTIVE' : 'CANCELLED';
    const invitationLink =
      'https://localhost/govern/memberships#token=example-rotated-original-invitation';
    const fetcher = mockBootstrapFetch().mockResolvedValue(
      Response.json({
        operationId: id(900),
        participantId: custody.participantId,
        state,
        ...(mutation === 'ROTATE' ? { invitationLink } : {}),
      }),
    );
    await renderPlatform();
    fireEvent.click(
      await screen.findByRole('button', { name: 'Check original custody-change status' }),
    );
    await screen.findByText(
      mutation === 'ROTATE'
        ? 'The replacement invitation is saved with its original deadline. The old link and ceremony session are invalid.'
        : 'The first-administrator invitation is permanently revoked. No administration was activated.',
    );
    expect(sessionStorage.getItem(storageKey)).toBe(original);
    expect(commands(fetcher)).toEqual([
      { command: 'READ_ORIGINAL', reviewToken: value.reviewToken },
    ]);
    expect(performWebAuthnStepUp).not.toHaveBeenCalled();
    if (mutation === 'ROTATE')
      expect(screen.getByLabelText('First-administrator invitation link')).toHaveValue(
        invitationLink,
      );
    else
      expect(
        screen.queryByLabelText('First-administrator invitation link'),
      ).not.toBeInTheDocument();
  },
);
it.each(['ACCEPTED', 'EXPIRED', 'CANCELLED', 'RECOVERY_REQUIRED'] as const)(
  'does not stage a custody mutation from %s readback',
  async (state) => {
    const original = seed();
    const fetcher = mockBootstrapFetch().mockResolvedValue(Response.json({ ...custody, state }));
    await renderPlatform();
    fireEvent.change(screen.getByLabelText('Participant with outstanding first administration'), {
      target: { value: custody.participantId },
    });
    fireEvent.click(screen.getByRole('button', { name: controls.READ_CUSTODY }));
    await screen.findByText(new RegExp(`Custody state: ${state}`));
    expect(screen.getByRole('button', { name: controls.PREPARE_CHANGE })).toBeDisabled();
    expect(commands(fetcher)).toEqual([
      { command: 'READ_CUSTODY', participantId: custody.participantId },
    ]);
    expect(sessionStorage.getItem(storageKey)).toBe(original);
  },
);
it('restores an actor-bound original review after current-session verification without executing a bootstrap command', async () => {
  const original = seed();
  const fetcher = mockBootstrapFetch();
  const first = await renderPlatform();
  await screen.findByRole('region', { name: 'Prepared first administration' });
  first.unmount();
  await renderPlatform();
  await screen.findByRole('region', { name: 'Prepared first administration' });
  expect(sessionStorage.getItem(storageKey)).toBe(original);
  expect(fetcher).not.toHaveBeenCalled();
  expect(sessionReads).toHaveBeenCalledTimes(2);
});
it('does not restore an expired tab-local review or fabricate a new approval', async () => {
  seed(review, approvalId, Date.now() - 86400001);
  const fetcher = mockBootstrapFetch();
  await renderPlatform();
  expect(
    screen.queryByRole('region', { name: 'Prepared first administration' }),
  ).not.toBeInTheDocument();
  expect(sessionStorage.getItem(storageKey)).toBeNull();
  expect(fetcher).not.toHaveBeenCalled();
  expect(sessionReads).toHaveBeenCalledTimes(1);
});

it.each([
  {},
  null,
  [],
  { title: unsafeMarker, code: unsafeMarker },
  {
    operation: { operationId: id(900), truthState: unsafeMarker },
    approval: { state: 'APPROVED' },
  },
  { reconciled: true, approval: { state: unsafeMarker } },
])(
  'rejects malformed successful APPROVE receipt %o before another read or success message',
  async (invalid) => {
    const original = seed();
    const fetcher = mockBootstrapFetch().mockImplementation(async (_input, init) =>
      Response.json(JSON.parse(String(init!.body)).command === 'APPROVE' ? invalid : checked()),
    );
    await renderPlatform();
    fireEvent.click(await controlFor('APPROVE'));
    await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent(unavailable));
    expect(document.body.textContent).not.toContain(unsafeMarker);
    expect(
      screen.queryByText('Independent approval recorded. The maker can issue the invitation.'),
    ).not.toBeInTheDocument();
    expect(sessionStorage.getItem(storageKey)).toBe(original);
    expect(commands(fetcher).map((body) => body.command)).toEqual(['REVIEW', 'APPROVE']);
  },
);
it('preserves the producer’s already-approved reconciliation envelope and reads the original approval without changing custody', async () => {
  const original = seed();
  let approved = false;
  const fetcher = mockBootstrapFetch().mockImplementation(async (_input, init) => {
    const body = JSON.parse(String(init!.body));
    if (body.command === 'APPROVE') {
      approved = true;
      return Response.json({ reconciled: true, approval: approvedResponse().approval });
    }
    return Response.json(checked(approved ? 'APPROVED' : 'REQUESTED'));
  });
  await renderPlatform();
  fireEvent.click(await controlFor('APPROVE'));
  await screen.findByText('Independent approval recorded. The maker can issue the invitation.');
  expect(commands(fetcher).map((body) => body.command)).toEqual(['REVIEW', 'APPROVE', 'REVIEW']);
  expect(sessionStorage.getItem(storageKey)).toBe(original);
  expect(screen.getByRole('button', { name: controls.APPROVE })).toBeDisabled();
});
it.each([
  [400, 'Participant bootstrap was rejected. Check the inputs before continuing.'],
  [
    401,
    'Participant bootstrap was not authorized. Refresh the authenticated context before continuing.',
  ],
  [
    404,
    'Participant bootstrap was not authorized. Refresh the authenticated context before continuing.',
  ],
  [
    412,
    'Participant bootstrap state changed. Read the original approval or custody before retrying.',
  ],
  [
    428,
    'Participant bootstrap state changed. Read the original approval or custody before retrying.',
  ],
  [500, unavailable],
] as const)(
  'uses fixed HTTP %s failure text even when the problem body is non-JSON',
  async (status, message) => {
    const original = seed();
    const fetcher = mockBootstrapFetch().mockResolvedValue(new Response(unsafeMarker, { status }));
    await renderPlatform();
    fireEvent.click(await controlFor('SESSION'));
    await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent(message));
    expect(document.body.textContent).not.toContain(unsafeMarker);
    expect(sessionStorage.getItem(storageKey)).toBe(original);
    expect(performWebAuthnStepUp).not.toHaveBeenCalled();
    expect(commands(fetcher)).toEqual([{ command: 'SESSION' }]);
  },
);

it('preserves the upstream two-administrator denial without replacing the original proposal or manufacturing approval', async () => {
  const original = seed();
  const fetcher = mockBootstrapFetch().mockResolvedValue(
    Response.json({ title: unsafeMarker, code: 'PC-AUTH-0002' }, { status: 403 }),
  );
  await renderPlatform();
  const control = await controlFor('PREPARE');
  fireEvent.change(screen.getByLabelText('Independent Platform checker ID'), {
    target: { value: makerId },
  });
  invoke(control, 'PREPARE');
  await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent(failures[0].message));
  expect(sessionStorage.getItem(storageKey)).toBe(original);
  expect(document.body.textContent).not.toContain(unsafeMarker);
  expect(commands(fetcher)).toEqual([{ ...expectedBody('PREPARE'), checkerPrincipalId: makerId }]);
  expect(
    screen.queryByText('Independent approval requested. No invitation has been issued yet.'),
  ).not.toBeInTheDocument();
});
it.each(['ROTATE', 'REVOKE'] as const)(
  'retains the sealed %s intent and original deadline after an interrupted original read without automatic retry',
  async (mutation) => {
    const value = changeReview(mutation);
    const original = seed(value);
    const fetcher = mockBootstrapFetch().mockRejectedValue(new Error(unsafeMarker));
    await renderPlatform();
    fireEvent.click(
      await screen.findByRole('button', { name: 'Check original custody-change status' }),
    );
    await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent(unavailable));
    expect(sessionStorage.getItem(storageKey)).toBe(original);
    expect(document.body.textContent).not.toContain(unsafeMarker);
    expect(screen.queryByLabelText('First-administrator invitation link')).not.toBeInTheDocument();
    expect(screen.queryByText(/The replacement invitation is saved/)).not.toBeInTheDocument();
    expect(
      screen.queryByText(/The first-administrator invitation is permanently revoked/),
    ).not.toBeInTheDocument();
    expect(commands(fetcher)).toEqual([
      { command: 'READ_ORIGINAL', reviewToken: value.reviewToken },
    ]);
    expect(performWebAuthnStepUp).not.toHaveBeenCalled();
  },
);

it('recovers an original consumed creation without requiring an approval ID or any authenticator', async () => {
  const original = seed(review, '');
  const invitationLink = 'http://localhost/govern/memberships#token=original-consumed-token';
  const fetcher = mockBootstrapFetch().mockResolvedValue(
    Response.json({
      operationId: id(900),
      participantId: candidate.participantId,
      state: 'PROVISIONING',
      invitationLink,
    }),
  );
  await renderPlatform();
  fireEvent.click(await controlFor('READ_ORIGINAL'));
  await screen.findByText(
    'The empty Participant and invitation are saved. Administration remains inactive until recipient acceptance.',
  );
  expect(screen.getByLabelText('First-administrator invitation link')).toHaveValue(invitationLink);
  expect(
    screen.queryByRole('button', { name: /^Verify and (issue invitation|apply custody change)$/u }),
  ).not.toBeInTheDocument();
  expect(commands(fetcher)).toEqual([expectedBody('READ_ORIGINAL')]);
  expect(performWebAuthnStepUp).not.toHaveBeenCalled();
  expect(sessionStorage.getItem(storageKey)).toBe(original);
});

it.each(['PROPOSED', 'APPROVAL_REQUESTED', 'APPROVED', 'CANCELLED', 'EXPIRED'])(
  'shows unconsumed %s as a pure read and never automatically starts verification or COMMIT',
  async (state) => {
    const original = seed();
    const fetcher = mockBootstrapFetch().mockResolvedValue(
      Response.json(pendingRead(review, state)),
    );
    await renderPlatform();
    fireEvent.click(await controlFor('READ_ORIGINAL'));
    await screen.findByText(/The original intent has not been consumed/);
    expect(performWebAuthnStepUp).not.toHaveBeenCalled();
    expect(commands(fetcher)).toEqual([expectedBody('READ_ORIGINAL')]);
    expect(sessionStorage.getItem(storageKey)).toBe(original);
    expect(screen.queryByLabelText('First-administrator invitation link')).not.toBeInTheDocument();
    const continuation = screen.queryByRole('button', {
      name: /^Verify and (issue invitation|apply custody change)$/u,
    });
    if (state === 'APPROVED') expect(continuation).toBeEnabled();
    else expect(continuation).not.toBeInTheDocument();
  },
);

it.each([
  { ...pendingRead(), participantId: id(999) },
  { ...pendingRead(), candidateDigest: `sha256:${'f'.repeat(64)}` },
  { ...pendingRead(), proposalState: 'CONSUMED' },
  { operationId: id(900), participantId: id(999), state: 'PROVISIONING' },
  {
    operationId: id(900),
    participantId: candidate.participantId,
    state: 'PROVISIONING',
    invitationLink: unsafeMarker,
  },
])(
  'fails closed on mismatched original readback %o before verification or mutation',
  async (reply) => {
    const original = seed();
    const fetcher = mockBootstrapFetch().mockResolvedValue(Response.json(reply));
    await renderPlatform();
    fireEvent.click(await controlFor('READ_ORIGINAL'));
    await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent(unavailable));
    expect(performWebAuthnStepUp).not.toHaveBeenCalled();
    expect(commands(fetcher)).toEqual([expectedBody('READ_ORIGINAL')]);
    expect(sessionStorage.getItem(storageKey)).toBe(original);
    expect(document.body.textContent).not.toContain(unsafeMarker);
    expect(
      screen.queryByRole('button', {
        name: /^Verify and (issue invitation|apply custody change)$/u,
      }),
    ).not.toBeInTheDocument();
  },
);

it('clears a previously displayed invitation when the next original read is denied', async () => {
  const original = seed();
  const fetcher = mockBootstrapFetch()
    .mockResolvedValueOnce(
      Response.json({
        operationId: id(900),
        participantId: candidate.participantId,
        state: 'PROVISIONING',
        invitationLink: 'http://localhost/govern/memberships#token=original',
      }),
    )
    .mockResolvedValueOnce(new Response(unsafeMarker, { status: 404 }));
  await renderPlatform();
  fireEvent.click(await controlFor('READ_ORIGINAL'));
  await screen.findByLabelText('First-administrator invitation link');
  await waitFor(() =>
    expect(screen.getByRole('button', { name: controls.READ_ORIGINAL })).toBeEnabled(),
  );
  fireEvent.click(screen.getByRole('button', { name: controls.READ_ORIGINAL }));
  await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent(failures[0].message));
  expect(screen.queryByLabelText('First-administrator invitation link')).not.toBeInTheDocument();
  expect(
    screen.queryByText(/The empty Participant and invitation are saved/),
  ).not.toBeInTheDocument();
  expect(commands(fetcher)).toEqual([expectedBody('READ_ORIGINAL'), expectedBody('READ_ORIGINAL')]);
  expect(performWebAuthnStepUp).not.toHaveBeenCalled();
  expect(sessionStorage.getItem(storageKey)).toBe(original);
});

it.each([undefined, 'ROTATE', 'REVOKE'] as const)(
  'reconciles interrupted %s COMMIT through the original receipt before another ceremony',
  async (mutation) => {
    const value = mutation ? changeReview(mutation) : review;
    const original = seed(value);
    let reads = 0;
    const receipt = {
      operationId: id(900),
      participantId: value.candidate.participantId,
      state:
        mutation === 'REVOKE' ? 'CANCELLED' : mutation === 'ROTATE' ? 'ACTIVE' : 'PROVISIONING',
      ...(mutation === 'REVOKE'
        ? {}
        : { invitationLink: 'http://localhost/govern/memberships#token=original-consumed' }),
    };
    const fetcher = mockBootstrapFetch().mockImplementation(async (_input, init) => {
      const body = JSON.parse(String(init!.body));
      if (body.command === 'READ_ORIGINAL')
        return Response.json(++reads === 1 ? pendingRead(value) : receipt);
      if (body.command === 'COMMIT') throw new Error(unsafeMarker);
      throw new Error('Unexpected bootstrap command');
    });
    await renderPlatform();
    fireEvent.click(await controlFor('READ_ORIGINAL'));
    const continuation = await screen.findByRole('button', {
      name: /^Verify and (issue invitation|apply custody change)$/u,
    });
    await waitFor(() => expect(continuation).toBeEnabled());
    expect(performWebAuthnStepUp).not.toHaveBeenCalled();
    fireEvent.click(continuation);
    await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent(unavailable));
    expect(performWebAuthnStepUp).toHaveBeenCalledTimes(1);
    expect(commands(fetcher)).toEqual([
      { command: 'READ_ORIGINAL', reviewToken: value.reviewToken },
      { command: 'COMMIT', reviewToken: value.reviewToken, approvalRequestId: approvalId },
    ]);
    expect(sessionStorage.getItem(storageKey)).toBe(original);
    fireEvent.click(screen.getByRole('button', { name: controls.READ_ORIGINAL }));
    await screen.findByText(
      mutation === 'REVOKE'
        ? 'The first-administrator invitation is permanently revoked. No administration was activated.'
        : mutation === 'ROTATE'
          ? 'The replacement invitation is saved with its original deadline. The old link and ceremony session are invalid.'
          : 'The empty Participant and invitation are saved. Administration remains inactive until recipient acceptance.',
    );
    expect(commands(fetcher)).toEqual([
      { command: 'READ_ORIGINAL', reviewToken: value.reviewToken },
      { command: 'COMMIT', reviewToken: value.reviewToken, approvalRequestId: approvalId },
      { command: 'READ_ORIGINAL', reviewToken: value.reviewToken },
    ]);
    expect(performWebAuthnStepUp).toHaveBeenCalledTimes(1);
    expect(sessionStorage.getItem(storageKey)).toBe(original);
    expect(document.body.textContent).not.toContain(unsafeMarker);
  },
);

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((yes) => {
    resolve = yes;
  });
  return { promise, resolve };
}
it('keeps saved private details out of the DOM until the current session is resolved', async () => {
  seed();
  const pending = deferred<Response>();
  sessionResponse = () => pending.promise;
  const fetcher = mockBootstrapFetch();
  render(<ParticipantBootstrapWorkflow />);
  expect(document.body.textContent).not.toContain(candidate.firstAdministrator.recipientSubject);
  expect(screen.queryByRole('region', { name: 'Prepared first administration' })).toBeNull();
  await act(async () => pending.resolve(Response.json(session)));
  await screen.findByRole('region', { name: 'Prepared first administration' });
  expect(document.body.textContent).toContain(candidate.firstAdministrator.recipientSubject);
  expect(fetcher).not.toHaveBeenCalled();
});
it.each([
  { name: 'signed out', current: { enabled: true, authenticated: false } },
  { name: 'session', current: { ...session, sessionId: id(22) } },
  { name: 'account', current: { ...session, principalId: checkerId } },
  { name: 'Participant', current: { ...session, participantId: id(23) } },
  { name: 'context epoch', current: { ...session, contextEpoch: '2' } },
  { name: 'privacy domain', current: { ...session, privacyDomainId: id(24) } },
  { name: 'Participant mode', current: { ...session, contextMode: 'PARTICIPANT' } },
])('does not disclose an original review after a $name change', async ({ current }) => {
  seed();
  sessionResponse = async () => Response.json(current);
  const fetcher = mockBootstrapFetch();
  render(<ParticipantBootstrapWorkflow />);
  await waitFor(() => expect(sessionStorage.getItem(storageKey)).toBeNull());
  expect(document.body.textContent).not.toContain(candidate.firstAdministrator.recipientSubject);
  expect(screen.queryByRole('region', { name: 'Prepared first administration' })).toBeNull();
  expect(fetcher).not.toHaveBeenCalled();
});
it('rejects an old unbound packet while retaining native proposal authority', async () => {
  sessionStorage.setItem(storageKey, JSON.stringify({ review, approvalId, savedAt: Date.now() }));
  const fetcher = mockBootstrapFetch();
  await renderPlatform();
  expect(sessionStorage.getItem(storageKey)).toBeNull();
  expect(document.body.textContent).not.toContain(candidate.firstAdministrator.recipientSubject);
  expect(fetcher).not.toHaveBeenCalled();
});
it('retains unchanged-session recovery after fresh authenticator verification', async () => {
  const original = seed();
  sessionResponse = async () =>
    Response.json({ ...session, stepUpVerifiedAt: '2030-01-01T00:00:00Z' });
  const fetcher = mockBootstrapFetch();
  await renderPlatform();
  await screen.findByRole('region', { name: 'Prepared first administration' });
  expect(sessionStorage.getItem(storageKey)).toBe(original);
  expect(fetcher).not.toHaveBeenCalled();
});
it.each(['focus', 'storage', 'transition', 'visibility'] as const)(
  'revalidates %s and removes private state on session loss',
  async (notification) => {
    seed();
    const fetcher = mockBootstrapFetch();
    await renderPlatform();
    await screen.findByRole('region', { name: 'Prepared first administration' });
    const pending = deferred<Response>();
    sessionResponse = () => pending.promise;
    act(() => {
      if (notification === 'storage')
        window.dispatchEvent(
          new StorageEvent('storage', {
            key: sessionTransitionStorageKey,
            newValue: JSON.stringify({ phase: 'settled' }),
          }),
        );
      else if (notification === 'transition')
        window.dispatchEvent(
          new CustomEvent(sessionTransitionEvent, {
            detail: { phase: 'settled' },
          }),
        );
      else if (notification === 'visibility') document.dispatchEvent(new Event('visibilitychange'));
      else window.dispatchEvent(new Event('focus'));
    });
    expect(
      screen.getByRole('region', { name: 'Prepared first administration', hidden: true }),
    ).not.toBeVisible();
    await act(async () => pending.resolve(Response.json({ enabled: true, authenticated: false })));
    await waitFor(() => expect(sessionStorage.getItem(storageKey)).toBeNull());
    expect(screen.queryByRole('region', { name: 'Prepared first administration' })).toBeNull();
    expect(fetcher).not.toHaveBeenCalled();
  },
);
it.each(['PREPARE', 'READ_ORIGINAL', 'READ_CUSTODY'] as const)(
  'cannot restore a delayed %s response after session invalidation',
  async (boundary) => {
    seed();
    const pending = deferred<Response>();
    const fetcher = mockBootstrapFetch().mockImplementation(() => pending.promise);
    await renderPlatform();
    const control = await controlFor(boundary);
    invoke(control, boundary);
    await waitFor(() => expect(commands(fetcher)).toHaveLength(1));
    const signal = fetcher.mock.calls[0]![1]!.signal!;
    act(() =>
      window.dispatchEvent(
        new CustomEvent(sessionTransitionEvent, { detail: { phase: 'changing' } }),
      ),
    );
    expect(signal.aborted).toBe(true);
    sessionStorage.removeItem(storageKey);
    await act(async () =>
      pending.resolve(
        Response.json(
          boundary === 'PREPARE'
            ? review
            : boundary === 'READ_CUSTODY'
              ? custody
              : {
                  operationId: id(900),
                  participantId: candidate.participantId,
                  state: 'PROVISIONING',
                  invitationLink: 'http://localhost/private-original-link',
                },
        ),
      ),
    );
    expect(document.body.textContent).not.toContain(candidate.firstAdministrator.recipientSubject);
    expect(document.body.textContent).not.toContain('private-original-link');
    expect(sessionStorage.getItem(storageKey)).toBeNull();
    expect(commands(fetcher)).toHaveLength(1);
  },
);
it('cannot issue after unmount during authenticator verification', async () => {
  seed();
  const pending = deferred<void>();
  vi.mocked(performWebAuthnStepUp).mockImplementationOnce(() => pending.promise);
  const fetcher = mockBootstrapFetch().mockResolvedValue(Response.json(pendingRead()));
  const result = await renderPlatform();
  fireEvent.click(await controlFor('COMMIT'));
  await waitFor(() => expect(performWebAuthnStepUp).toHaveBeenCalledTimes(1));
  result.unmount();
  await act(async () => pending.resolve());
  expect(commands(fetcher).map((body) => body.command)).toEqual(['READ_ORIGINAL']);
});
it('discards a delayed checker review after the checker edits its binding', async () => {
  seed();
  const pending = deferred<Response>();
  const fetcher = mockBootstrapFetch().mockImplementation(() => pending.promise);
  await renderPlatform();
  fireEvent.click(await controlFor('REVIEW'));
  await waitFor(() => expect(commands(fetcher)).toHaveLength(1));
  fireEvent.change(screen.getByLabelText('First-administrator candidate digest'), {
    target: { value: `sha256:${'c'.repeat(64)}` },
  });
  await act(async () => pending.resolve(Response.json(checked())));
  expect(screen.queryByText('Approval state: REQUESTED')).toBeNull();
  expect(screen.queryByRole('button', { name: controls.APPROVE })).toBeNull();
  expect(performWebAuthnStepUp).not.toHaveBeenCalled();
  expect(commands(fetcher)).toHaveLength(1);
});
it('blocks a command when the server reports another account without any browser notification', async () => {
  seed(review, '');
  const fetcher = mockBootstrapFetch();
  await renderPlatform();
  await screen.findByRole('region', { name: 'Prepared first administration' });
  sessionResponse = async () => Response.json({ ...session, principalId: checkerId });
  fireEvent.click(screen.getByRole('button', { name: controls.SUBMIT }));
  await waitFor(() => expect(sessionStorage.getItem(storageKey)).toBeNull());
  expect(document.body.textContent).not.toContain(candidate.firstAdministrator.recipientSubject);
  expect(fetcher).not.toHaveBeenCalled();
});

it.each(['focus', 'visibility'] as const)(
  'preserves one pending authenticator operation across same-actor %s revalidation',
  async (notification) => {
    const original = seed();
    const verification = deferred<void>();
    vi.mocked(performWebAuthnStepUp).mockImplementationOnce(() => verification.promise);
    const fetcher = mockBootstrapFetch().mockImplementation(async (_input, init) => {
      const body = JSON.parse(String(init!.body));
      return Response.json(
        body.command === 'READ_ORIGINAL'
          ? pendingRead()
          : {
              operationId: id(900),
              participantId: candidate.participantId,
              state: 'PROVISIONING',
              invitationLink: 'http://localhost/original-consumed-invitation',
            },
      );
    });
    await renderPlatform();
    fireEvent.click(await controlFor('COMMIT'));
    await waitFor(() => expect(performWebAuthnStepUp).toHaveBeenCalledTimes(1));
    await act(async () => {
      if (notification === 'focus') window.dispatchEvent(new Event('focus'));
      else document.dispatchEvent(new Event('visibilitychange'));
    });
    await screen.findByRole('region', { name: 'Prepared first administration' });
    await act(async () => verification.resolve());
    await screen.findByLabelText('First-administrator invitation link');
    expect(commands(fetcher).map((body) => body.command)).toEqual(['READ_ORIGINAL', 'COMMIT']);
    expect(sessionStorage.getItem(storageKey)).toBe(original);
  },
);
it.each(['transport', '503', 'malformed', 'disabled'] as const)(
  'retains original sealed custody through a %s session outage and same-actor recovery',
  async (failure) => {
    const original = seed();
    const fetcher = mockBootstrapFetch();
    await renderPlatform();
    await screen.findByRole('region', { name: 'Prepared first administration' });
    sessionResponse = async () => {
      if (failure === 'transport') throw new Error(unsafeMarker);
      return Response.json(failure === 'disabled' ? { enabled: false } : {}, {
        status: failure === '503' ? 503 : 200,
      });
    };
    act(() => window.dispatchEvent(new Event('focus')));
    await waitFor(() =>
      expect(
        screen.queryByRole('heading', {
          name: 'Create a Participant and invite its first administrator',
          hidden: true,
        }),
      ).toBeNull(),
    );
    expect(document.body.textContent).not.toContain(candidate.firstAdministrator.recipientSubject);
    expect(sessionStorage.getItem(storageKey)).toBe(original);
    sessionResponse = async () => Response.json(session);
    act(() => window.dispatchEvent(new Event('focus')));
    await screen.findByRole('region', { name: 'Prepared first administration' });
    expect(sessionStorage.getItem(storageKey)).toBe(original);
    expect(fetcher).not.toHaveBeenCalled();
    expect(performWebAuthnStepUp).not.toHaveBeenCalled();
  },
);
it('keeps an explicit session-changing interval fenced through focus until settled', async () => {
  const original = seed();
  const fetcher = mockBootstrapFetch();
  await renderPlatform();
  await screen.findByRole('region', { name: 'Prepared first administration' });
  const reads = sessionReads.mock.calls.length;
  await act(async () => {
    window.dispatchEvent(
      new CustomEvent(sessionTransitionEvent, { detail: { phase: 'changing' } }),
    );
    window.dispatchEvent(new Event('focus'));
    document.dispatchEvent(new Event('visibilitychange'));
  });
  expect(screen.queryByRole('region', { name: 'Prepared first administration' })).toBeNull();
  expect(sessionReads).toHaveBeenCalledTimes(reads);
  expect(sessionStorage.getItem(storageKey)).toBe(original);
  act(() =>
    window.dispatchEvent(new CustomEvent(sessionTransitionEvent, { detail: { phase: 'settled' } })),
  );
  await screen.findByRole('region', { name: 'Prepared first administration' });
  expect(fetcher).not.toHaveBeenCalled();
});
it('cancels checker verification when its input binding changes', async () => {
  seed();
  const verification = deferred<void>();
  vi.mocked(performWebAuthnStepUp).mockImplementationOnce(() => verification.promise);
  const fetcher = mockBootstrapFetch().mockResolvedValue(Response.json(checked()));
  await renderPlatform();
  fireEvent.click(await controlFor('APPROVE'));
  await waitFor(() => expect(performWebAuthnStepUp).toHaveBeenCalledTimes(1));
  fireEvent.change(screen.getByLabelText('First-administrator approval request ID'), {
    target: { value: id(999) },
  });
  await act(async () => verification.resolve());
  expect(commands(fetcher).map((body) => body.command)).toEqual(['REVIEW']);
});
