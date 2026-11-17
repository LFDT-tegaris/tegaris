import { act, fireEvent, render, screen, waitFor, cleanup } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { performWebAuthnStepUp } from '@openpc/ui-shell';
import { CredentialWorkflow } from './credential-workflow';
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
const credential = {
  credentialId: id('711'),
  state: 'ACTIVE',
  credentialEpoch: '1',
  revision: '1',
  issuer: 'webauthn://localhost',
  active: true,
  replacedCredentialId: null,
};
const state = {
  actor,
  inventory: {
    participantId: actor.participantId,
    principalId: actor.principalId,
    items: [
      credential,
      { ...credential, credentialId: id('712'), state: 'REVOKED', active: false },
    ],
    nextCursor: null,
  },
  approvals: [],
  nextCursor: null,
};
const review = {
  reviewToken: 'r'.repeat(100),
  approvalRequestId: id('801'),
  review: {
    enrollmentId: id('802'),
    replacedCredentialId: credential.credentialId,
    expectedRevision: '1',
    candidateDigest: `sha256:${'a'.repeat(64)}`,
    checkerPrincipalId: id('112'),
    reason: 'Replace the existing authenticator.',
    expiresAt: new Date(Date.now() + 300000).toISOString(),
    stepUp: {
      actionIntentId: 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
      actionIntentDigest: `sha256:${'b'.repeat(64)}`,
      resourceId: credential.credentialId,
      resourceDigest: `sha256:${'a'.repeat(64)}`,
    },
  },
};
beforeEach(() => {
  localStorage.clear();
  vi.clearAllMocks();
});
afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  if (originalCredentialsDescriptor)
    Object.defineProperty(navigator, 'credentials', originalCredentialsDescriptor);
  else Reflect.deleteProperty(navigator, 'credentials');
});
it('exposes accessible replacement controls and excludes revoked authenticators from selection', async () => {
  vi.spyOn(globalThis, 'fetch').mockResolvedValue(Response.json(state));
  render(<CredentialWorkflow />);
  await waitFor(() =>
    expect(
      screen.getByRole('button', { name: 'Register replacement authenticator' }),
    ).toBeEnabled(),
  );
  const selector = screen.getByRole('combobox', { name: /^Authenticator to replace/u });
  await userEvent.setup().selectOptions(selector, credential.credentialId);
  expect(selector).toHaveValue(credential.credentialId);
  expect(screen.queryByRole('option', { name: new RegExp(id('712')) })).not.toBeInTheDocument();
  expect(screen.getByRole('textbox', { name: 'Checker principal ID' })).toBeVisible();
  expect(screen.getByRole('textbox', { name: 'Reason for replacement' })).toBeVisible();
  expect(
    screen.getByRole('checkbox', { name: 'Request hardware-backed attestation' }),
  ).toBeVisible();
});
it('reconciles a completed saved registration before requesting another assertion or write', async () => {
  writeBoundPolicyState('openpc:credential-workflow:v1', actor, review);
  const fetch = vi.spyOn(globalThis, 'fetch').mockImplementation(async (url) =>
    Response.json(
      String(url).includes('/webauthn/enrollment')
        ? {
            enrollmentId: review.review.enrollmentId,
            participantId: actor.participantId,
            principalId: actor.principalId,
            principalEpoch: '1',
            state: 'COMPLETED',
            expiresAt: review.review.expiresAt,
            completedAt: new Date().toISOString(),
            credential: { credentialId: id('713'), credentialEpoch: '2', active: true },
          }
        : state,
    ),
  );
  render(<CredentialWorkflow />);
  await userEvent
    .setup()
    .click(await screen.findByRole('button', { name: 'Verify and commit replacement' }));
  await screen.findByText('This replacement is already committed.');
  expect(performWebAuthnStepUp).not.toHaveBeenCalled();
  expect(fetch.mock.calls.some(([, options]) => options?.method === 'POST')).toBe(false);
  expect(screen.getByRole('button', { name: 'Verify and commit replacement' })).toBeDisabled();
});
it.each(['revoked', 'missing'])(
  'clears a %s selection on a same-actor refresh without discarding saved intent',
  async (change) => {
    writeBoundPolicyState('openpc:credential-workflow:v1', actor, review);
    const fetch = vi
      .spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(Response.json(state))
      .mockResolvedValueOnce(
        Response.json({
          ...state,
          inventory: {
            ...state.inventory,
            items: change === 'revoked' ? [{ ...credential, state: 'REVOKED', active: false }] : [],
          },
        }),
      )
      .mockResolvedValueOnce(Response.json(state));
    const user = userEvent.setup();
    render(<CredentialWorkflow />);
    const selector = await screen.findByRole('combobox', { name: /^Authenticator to replace/u });
    await waitFor(() => expect(selector).toBeEnabled());
    await user.selectOptions(selector, credential.credentialId);
    await user.click(screen.getByRole('button', { name: 'Refresh replacement approvals' }));
    expect(selector).toHaveValue('');
    expect(
      screen.queryByRole('option', { name: new RegExp(credential.credentialId) }),
    ).not.toBeInTheDocument();
    expect(screen.getByText(`Reason: ${review.review.reason}`)).toBeVisible();
    expect(screen.getByRole('button', { name: 'Read saved registration' })).toBeEnabled();

    // A later page offering the credential again must not resurrect the cleared selection.
    await user.click(screen.getByRole('button', { name: 'Refresh replacement approvals' }));
    expect(
      screen.getByRole('option', { name: new RegExp(credential.credentialId) }),
    ).toBeInTheDocument();
    expect(selector).toHaveValue('');
    expect(fetch.mock.calls.some(([, options]) => options?.method === 'POST')).toBe(false);
  },
);
it('retains a selection that remains active on the refreshed inventory page', async () => {
  vi.spyOn(globalThis, 'fetch').mockImplementation(async () => Response.json(state));
  const user = userEvent.setup();
  render(<CredentialWorkflow />);
  const selector = screen.getByRole('combobox', { name: /^Authenticator to replace/u });
  await waitFor(() => expect(selector).toBeEnabled());
  await user.selectOptions(selector, credential.credentialId);
  await user.click(screen.getByRole('button', { name: 'Refresh replacement approvals' }));
  expect(selector).toHaveValue(credential.credentialId);
});
it.each(['success', 'failure'])(
  'ignores an older initial read %s after a newer context read completes',
  async (outcome) => {
    let resolve!: (response: Response) => void;
    let reject!: (cause: Error) => void;
    const initial = new Promise<Response>((accept, fail) => {
      resolve = accept;
      reject = fail;
    });
    const currentActor = { ...actor, sessionId: id('702'), principalId: id('113') };
    const currentCredential = { ...credential, credentialId: id('714') };
    const currentReview = {
      ...review,
      approvalRequestId: id('803'),
      review: {
        ...review.review,
        enrollmentId: id('804'),
        replacedCredentialId: currentCredential.credentialId,
        reason: 'Replace the current account authenticator.',
        stepUp: { ...review.review.stepUp, resourceId: currentCredential.credentialId },
      },
    };
    writeBoundPolicyState('openpc:credential-workflow:v1', currentActor, currentReview);
    const currentState = {
      ...state,
      actor: currentActor,
      inventory: {
        ...state.inventory,
        principalId: currentActor.principalId,
        items: [currentCredential],
      },
      approvals: [
        {
          approvalRequestId: currentReview.approvalRequestId,
          candidateDigest: currentReview.review.candidateDigest,
          makerSubjectRef: 'current-maker',
          checkerSubjectRef: 'current-checker',
          revision: '2',
          state: 'APPROVED',
          stepUp: currentReview.review.stepUp,
          proposal: {
            candidateDigest: currentReview.review.candidateDigest,
            resourceId: currentCredential.credentialId,
            makerPrincipalId: currentActor.principalId,
            catalogOperationId: 'ID-OP-WEBAUTHN-REGISTER',
            expectedRevision: '1',
            state: 'CONSUMED',
            expiresAt: currentReview.review.expiresAt,
            candidate: {
              enrollmentId: currentReview.review.enrollmentId,
              replacedCredentialId: currentCredential.credentialId,
              externalCredentialId: 'current-authenticator',
              publicKeyDigest: currentReview.review.candidateDigest,
              publicKeySpkiDer: 'current-public-key',
              signCount: '0',
              attestationDigest: currentReview.review.candidateDigest,
            },
          },
        },
      ],
    };
    const fetch = vi
      .spyOn(globalThis, 'fetch')
      // Deliberately ignore abort, as a response may already be arriving.
      .mockImplementationOnce(() => initial)
      .mockResolvedValueOnce(Response.json(currentState));
    const user = userEvent.setup();
    render(<CredentialWorkflow />);
    await user.click(screen.getByRole('button', { name: 'Refresh replacement approvals' }));
    await screen.findByText(`Signed-in principal: ${currentActor.principalId}`);
    const selector = screen.getByRole('combobox', { name: /^Authenticator to replace/u });
    await user.selectOptions(selector, currentCredential.credentialId);
    expect(fetch.mock.calls[0]?.[1]?.signal?.aborted).toBe(true);

    await act(async () => {
      if (outcome === 'success') resolve(Response.json(state));
      else reject(new Error('The obsolete request failed.'));
    });
    expect(screen.getByText(`Signed-in principal: ${currentActor.principalId}`)).toBeVisible();
    expect(screen.queryByText(`Signed-in principal: ${actor.principalId}`)).not.toBeInTheDocument();
    expect(selector).toHaveValue(currentCredential.credentialId);
    expect(
      screen.queryByRole('option', { name: new RegExp(credential.credentialId) }),
    ).not.toBeInTheDocument();
    expect(screen.getByText(`Reason: ${currentReview.review.reason}`)).toBeVisible();
    expect(screen.queryByText(`Reason: ${review.review.reason}`)).not.toBeInTheDocument();
    expect(screen.getByText('Approval state: APPROVED · Proposal state: CONSUMED')).toBeVisible();
    expect(screen.getByRole('button', { name: 'Verify and commit replacement' })).toBeDisabled();
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    expect(performWebAuthnStepUp).not.toHaveBeenCalled();
    expect(fetch.mock.calls.some(([, options]) => options?.method === 'POST')).toBe(false);
  },
);
it('cancels the active workbench read when unmounted', () => {
  const fetch = vi
    .spyOn(globalThis, 'fetch')
    .mockImplementation(() => new Promise<Response>(() => {}));
  const { unmount } = render(<CredentialWorkflow />);
  const signal = fetch.mock.calls[0]?.[1]?.signal;
  expect(signal?.aborted).toBe(false);
  unmount();
  expect(signal?.aborted).toBe(true);
});

const unsafeCredentialMarker = 'PRIVATE_CREDENTIAL_SERVER_TRANSPORT_OR_VALIDATOR_DETAIL';
const credentialUnavailable =
  'Credential request could not be confirmed. Read saved registration before retrying.';
const credentialFailures = [
  {
    name: 'authorization',
    status: 403,
    message:
      'Credential request was not authorized. Refresh the authenticated context before continuing.',
  },
  {
    name: 'conflict',
    status: 409,
    message: 'Credential state changed. Refresh or read saved registration before retrying.',
  },
  {
    name: 'input',
    status: 422,
    message: 'Credential request was rejected. Check the inputs before continuing.',
  },
  { name: 'unknown code', status: 503, message: credentialUnavailable },
  { name: 'transport', message: credentialUnavailable },
  { name: 'unknown thrown object', message: credentialUnavailable },
  { name: 'non-JSON success', message: credentialUnavailable },
] as const;
function failCredential(failure: (typeof credentialFailures)[number]): Response {
  if ('status' in failure)
    return Response.json(
      { title: unsafeCredentialMarker, code: unsafeCredentialMarker },
      { status: failure.status },
    );
  if (failure.name === 'transport') throw new Error(unsafeCredentialMarker);
  if (failure.name === 'unknown thrown object')
    throw { message: unsafeCredentialMarker, details: unsafeCredentialMarker };
  return new Response(unsafeCredentialMarker, { status: 200 });
}
const originalCredentialsDescriptor = Object.getOwnPropertyDescriptor(navigator, 'credentials');
function mockCredentialRegistration() {
  class Attestation {
    attestationObject = new ArrayBuffer(2);
    clientDataJSON = new ArrayBuffer(2);
    getTransports() {
      return ['internal'];
    }
  }
  class RegisteredCredential {
    static parseCreationOptionsFromJSON = vi.fn(() => ({}));
    id = 'new-browser-credential';
    rawId = new ArrayBuffer(2);
    response = new Attestation();
    authenticatorAttachment = 'platform';
    getClientExtensionResults() {
      return {};
    }
  }
  vi.stubGlobal('PublicKeyCredential', RegisteredCredential);
  vi.stubGlobal('AuthenticatorAttestationResponse', Attestation);
  const create = vi.fn(async () => new RegisteredCredential());
  Object.defineProperty(navigator, 'credentials', { configurable: true, value: { create } });
  return create;
}
const pendingEnrollment = {
  enrollmentId: review.review.enrollmentId,
  participantId: actor.participantId,
  principalId: actor.principalId,
  principalEpoch: '1',
  state: 'PENDING',
  expiresAt: review.review.expiresAt,
  completedAt: null,
  credential: null,
};
function credentialApproval() {
  return {
    approvalRequestId: `urn:openpc:resource:${review.approvalRequestId}`,
    candidateDigest: review.review.candidateDigest,
    makerSubjectRef: `urn:openpc:resource:${actor.principalId}`,
    checkerSubjectRef: `urn:openpc:resource:${review.review.checkerPrincipalId}`,
    revision: '1',
    state: 'REQUESTED',
    proposal: {
      candidateDigest: review.review.candidateDigest,
      resourceId: credential.credentialId,
      makerPrincipalId: actor.principalId,
      catalogOperationId: 'ID-OP-WEBAUTHN-REGISTER',
      expectedRevision: '1',
      state: 'REQUESTED',
      expiresAt: review.review.expiresAt,
      candidate: {
        enrollmentId: review.review.enrollmentId,
        replacedCredentialId: credential.credentialId,
        externalCredentialId: 'new-browser-credential',
        publicKeyDigest: review.review.candidateDigest,
        publicKeySpkiDer: 'browser-public-key',
        signCount: '0',
        attestationDigest: review.review.candidateDigest,
      },
    },
    stepUp: review.review.stepUp,
  };
}
function replacementInputs() {
  fireEvent.change(screen.getByLabelText('Authenticator to replace'), {
    target: { value: credential.credentialId },
  });
  fireEvent.change(screen.getByLabelText('Checker principal ID'), {
    target: { value: review.review.checkerPrincipalId },
  });
  fireEvent.change(screen.getByLabelText('Reason for replacement'), {
    target: { value: review.review.reason },
  });
}
it.each(credentialFailures)(
  'hides $name from the initial credential reader without inventing an inventory',
  async (failure) => {
    writeBoundPolicyState('openpc:credential-workflow:v1', actor, review);
    const original = localStorage.getItem('openpc:credential-workflow:v1');
    const fetcher = vi
      .spyOn(globalThis, 'fetch')
      .mockImplementation(async () => failCredential(failure));
    render(<CredentialWorkflow />);
    await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent(failure.message));
    expect(document.body.textContent).not.toContain(unsafeCredentialMarker);
    expect(screen.queryByText('No replacement approvals on this page.')).not.toBeInTheDocument();
    expect(
      screen.getByRole('button', { name: 'Register replacement authenticator' }),
    ).toBeDisabled();
    expect(localStorage.getItem('openpc:credential-workflow:v1')).toBe(original);
    expect(fetcher.mock.calls.some(([, init]) => init?.method === 'POST')).toBe(false);
  },
);
it.each(
  credentialFailures.flatMap((failure) =>
    ['OPTIONS', 'PREPARE', 'SUBMIT', 'APPROVE', 'COMMIT'].map((boundary) => ({
      ...failure,
      boundary,
    })),
  ),
)(
  'hides $name at credential $boundary and preserves the exact original review',
  async (failure) => {
    const value =
      failure.boundary === 'SUBMIT'
        ? { reviewToken: review.reviewToken, review: review.review }
        : review;
    writeBoundPolicyState('openpc:credential-workflow:v1', actor, value);
    const original = localStorage.getItem('openpc:credential-workflow:v1');
    const create = mockCredentialRegistration();
    const fetcher = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      if (init?.method === 'POST') {
        const body = JSON.parse(String(init.body));
        if (body.command === failure.boundary) return failCredential(failure);
        if (body.command === 'OPTIONS')
          return Response.json({
            enrollmentId: review.review.enrollmentId,
            replacedCredentialId: credential.credentialId,
            publicKey: {},
          });
        throw new Error('Unexpected credential mutation');
      }
      return Response.json(
        String(input).includes('/webauthn/enrollment')
          ? pendingEnrollment
          : { ...state, approvals: failure.boundary === 'APPROVE' ? [credentialApproval()] : [] },
      );
    });
    render(<CredentialWorkflow />);
    await screen.findByRole('heading', { name: 'Saved replacement request' });
    const names = {
      OPTIONS: 'Register replacement authenticator',
      PREPARE: 'Register replacement authenticator',
      SUBMIT: 'Request replacement approval',
      APPROVE: 'Verify and approve replacement',
      COMMIT: 'Verify and commit replacement',
    };
    const control = screen.getByRole('button', {
      name: names[failure.boundary as keyof typeof names],
    });
    if (failure.boundary === 'OPTIONS' || failure.boundary === 'PREPARE') {
      replacementInputs();
      fireEvent.submit(control.closest('form')!);
    } else fireEvent.click(control);
    await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent(failure.message));
    expect(document.body.textContent).not.toContain(unsafeCredentialMarker);
    expect(localStorage.getItem('openpc:credential-workflow:v1')).toBe(original);
    expect(screen.queryByText(/Replacement committed\./)).not.toBeInTheDocument();
    expect(screen.queryByText(/Approval requested\./)).not.toBeInTheDocument();
    const posts = fetcher.mock.calls.filter(([, init]) => init?.method === 'POST');
    expect(posts).toHaveLength(failure.boundary === 'PREPARE' ? 2 : 1);
    const body = JSON.parse(String(posts.at(-1)![1]!.body));
    expect(body.command).toBe(failure.boundary);
    if (failure.boundary === 'COMMIT')
      expect(body).toEqual({
        command: 'COMMIT',
        reviewToken: value.reviewToken,
        approvalRequestId: review.approvalRequestId,
      });
    if (failure.boundary === 'SUBMIT')
      expect(body).toEqual({ command: 'SUBMIT', reviewToken: value.reviewToken });
    if (failure.boundary === 'OPTIONS')
      expect(body).toEqual({
        command: 'OPTIONS',
        replacedCredentialId: credential.credentialId,
        hardwareAttestation: false,
        expectedSessionId: actor.sessionId,
      });
    expect(create).toHaveBeenCalledTimes(failure.boundary === 'PREPARE' ? 1 : 0);
  },
);
it.each([
  'initial inventory',
  'registration readback',
  'options',
  'prepared review',
  'submission',
  'commit',
] as const)(
  'hides structured validator details at credential %s and preserves custody',
  async (boundary) => {
    const value =
      boundary === 'submission'
        ? { reviewToken: review.reviewToken, review: review.review }
        : review;
    writeBoundPolicyState('openpc:credential-workflow:v1', actor, value);
    const original = localStorage.getItem('openpc:credential-workflow:v1');
    mockCredentialRegistration();
    const fetcher = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      if (init?.method === 'POST') {
        const body = JSON.parse(String(init.body));
        if (body.command === 'OPTIONS' && boundary === 'prepared review')
          return Response.json({
            enrollmentId: review.review.enrollmentId,
            replacedCredentialId: credential.credentialId,
            publicKey: {},
          });
        return Response.json({
          truthState: unsafeCredentialMarker,
          review: { reason: unsafeCredentialMarker },
        });
      }
      if (String(input).includes('/webauthn/enrollment'))
        return Response.json(
          boundary === 'registration readback'
            ? { principalId: unsafeCredentialMarker }
            : pendingEnrollment,
        );
      return Response.json(
        boundary === 'initial inventory'
          ? { actor: { principalId: unsafeCredentialMarker } }
          : state,
      );
    });
    render(<CredentialWorkflow />);
    if (boundary !== 'initial inventory') {
      await screen.findByRole('heading', { name: 'Saved replacement request' });
      const name =
        boundary === 'registration readback'
          ? 'Read saved registration'
          : boundary === 'submission'
            ? 'Request replacement approval'
            : boundary === 'commit'
              ? 'Verify and commit replacement'
              : 'Register replacement authenticator';
      const control = screen.getByRole('button', { name });
      if (boundary === 'options' || boundary === 'prepared review') {
        replacementInputs();
        fireEvent.submit(control.closest('form')!);
      } else fireEvent.click(control);
    }
    await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent(credentialUnavailable));
    expect(document.body.textContent).not.toContain(unsafeCredentialMarker);
    expect(document.body.textContent).not.toContain('invalid_type');
    expect(localStorage.getItem('openpc:credential-workflow:v1')).toBe(original);
    expect(fetcher.mock.calls.filter(([, init]) => init?.method === 'POST')).toHaveLength(
      boundary === 'initial inventory' || boundary === 'registration readback'
        ? 0
        : boundary === 'prepared review'
          ? 2
          : 1,
    );
  },
);
it.each(['refresh', 'inventory cursor', 'approval cursor', 'saved registration'] as const)(
  'hides a transport failure at credential %s without replaying or deleting the original',
  async (boundary) => {
    writeBoundPolicyState('openpc:credential-workflow:v1', actor, review);
    const original = localStorage.getItem('openpc:credential-workflow:v1');
    let fail = false;
    const fetcher = vi.spyOn(globalThis, 'fetch').mockImplementation(async () =>
      fail
        ? failCredential({ name: 'transport', message: credentialUnavailable })
        : Response.json({
            ...state,
            nextCursor: 'approval-cursor',
            inventory: { ...state.inventory, nextCursor: id('999') },
          }),
    );
    render(<CredentialWorkflow />);
    await screen.findByRole('heading', { name: 'Saved replacement request' });
    fail = true;
    const name =
      boundary === 'refresh'
        ? 'Refresh replacement approvals'
        : boundary === 'inventory cursor'
          ? 'Next authenticators'
          : boundary === 'approval cursor'
            ? 'Next approval page'
            : 'Read saved registration';
    fireEvent.click(screen.getByRole('button', { name }));
    await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent(credentialUnavailable));
    expect(document.body.textContent).not.toContain(unsafeCredentialMarker);
    expect(localStorage.getItem('openpc:credential-workflow:v1')).toBe(original);
    expect(fetcher.mock.calls.some(([, init]) => init?.method === 'POST')).toBe(false);
  },
);
it('hides browser registration exceptions and stops before preparing or staging a credential', async () => {
  const create = mockCredentialRegistration();
  create.mockRejectedValueOnce(new Error(unsafeCredentialMarker));
  const fetcher = vi.spyOn(globalThis, 'fetch').mockImplementation(async (_input, init) =>
    Response.json(
      init?.method === 'POST'
        ? {
            enrollmentId: review.review.enrollmentId,
            replacedCredentialId: credential.credentialId,
            publicKey: {},
          }
        : state,
    ),
  );
  render(<CredentialWorkflow />);
  const control = await screen.findByRole('button', { name: 'Register replacement authenticator' });
  await waitFor(() => expect(control).toBeEnabled());
  replacementInputs();
  fireEvent.submit(control.closest('form')!);
  await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent(credentialUnavailable));
  expect(document.body.textContent).not.toContain(unsafeCredentialMarker);
  expect(fetcher.mock.calls.filter(([, init]) => init?.method === 'POST')).toHaveLength(1);
  expect(localStorage.getItem('openpc:credential-workflow:v1')).toBeNull();
});
it('hides authenticator verification exceptions and sends no credential commit', async () => {
  writeBoundPolicyState('openpc:credential-workflow:v1', actor, review);
  const original = localStorage.getItem('openpc:credential-workflow:v1');
  vi.mocked(performWebAuthnStepUp).mockRejectedValueOnce(new Error(unsafeCredentialMarker));
  const fetcher = vi
    .spyOn(globalThis, 'fetch')
    .mockImplementation(async (input) =>
      Response.json(String(input).includes('/webauthn/enrollment') ? pendingEnrollment : state),
    );
  render(<CredentialWorkflow />);
  fireEvent.click(await screen.findByRole('button', { name: 'Verify and commit replacement' }));
  await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent(credentialUnavailable));
  expect(document.body.textContent).not.toContain(unsafeCredentialMarker);
  expect(localStorage.getItem('openpc:credential-workflow:v1')).toBe(original);
  expect(fetcher.mock.calls.some(([, init]) => init?.method === 'POST')).toBe(false);
});
it.each([200, 201])(
  'retains a valid HTTP %s prepared credential review without claiming activation',
  async (status) => {
    const create = mockCredentialRegistration();
    const prepared = { reviewToken: review.reviewToken, review: review.review };
    const fetcher = vi.spyOn(globalThis, 'fetch').mockImplementation(async (_input, init) =>
      Response.json(
        init?.method === 'POST'
          ? JSON.parse(String(init.body)).command === 'OPTIONS'
            ? {
                enrollmentId: review.review.enrollmentId,
                replacedCredentialId: credential.credentialId,
                publicKey: {},
              }
            : prepared
          : state,
        { status: init?.method === 'POST' ? status : 200 },
      ),
    );
    render(<CredentialWorkflow />);
    const control = await screen.findByRole('button', {
      name: 'Register replacement authenticator',
    });
    await waitFor(() => expect(control).toBeEnabled());
    replacementInputs();
    fireEvent.submit(control.closest('form')!);
    await screen.findByText(/The new authenticator is prepared\./);
    expect(JSON.parse(localStorage.getItem('openpc:credential-workflow:v1')!).value).toEqual(
      prepared,
    );
    expect(screen.getByRole('button', { name: 'Verify and commit replacement' })).toBeDisabled();
    expect(create).toHaveBeenCalledTimes(1);
    expect(fetcher.mock.calls.filter(([, init]) => init?.method === 'POST')).toHaveLength(2);
  },
);

it.each([
  'foreign principal',
  'foreign Participant',
  'foreign enrollment',
  'foreign authenticator',
  'cancelled registration',
] as const)(
  'preserves the fixed local credential message for %s and forbids a prepared mutation',
  async (boundary) => {
    writeBoundPolicyState('openpc:credential-workflow:v1', actor, review);
    const original = localStorage.getItem('openpc:credential-workflow:v1');
    mockCredentialRegistration();
    if (boundary === 'cancelled registration')
      Object.defineProperty(navigator, 'credentials', {
        configurable: true,
        value: { create: vi.fn(async () => null) },
      });
    const fetcher = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      if (init?.method === 'POST')
        return Response.json({
          enrollmentId: review.review.enrollmentId,
          replacedCredentialId:
            boundary === 'foreign authenticator' ? id('999') : credential.credentialId,
          publicKey: {},
        });
      if (String(input).includes('/webauthn/enrollment'))
        return Response.json({
          ...pendingEnrollment,
          ...(boundary === 'foreign principal'
            ? { principalId: id('999') }
            : boundary === 'foreign Participant'
              ? { participantId: id('999') }
              : { enrollmentId: id('999') }),
        });
      return Response.json(state);
    });
    render(<CredentialWorkflow />);
    await screen.findByRole('heading', { name: 'Saved replacement request' });
    const registration =
      boundary === 'foreign authenticator' || boundary === 'cancelled registration';
    if (registration) {
      replacementInputs();
      fireEvent.submit(
        screen.getByRole('button', { name: 'Register replacement authenticator' }).closest('form')!,
      );
    } else fireEvent.click(screen.getByRole('button', { name: 'Read saved registration' }));
    const message =
      boundary === 'foreign authenticator'
        ? 'The registration refers to another authenticator.'
        : boundary === 'cancelled registration'
          ? 'Authenticator registration was cancelled or unavailable.'
          : 'The saved registration does not belong to this account.';
    await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent(message));
    expect(localStorage.getItem('openpc:credential-workflow:v1')).toBe(original);
    expect(fetcher.mock.calls.filter(([, init]) => init?.method === 'POST')).toHaveLength(
      registration ? 1 : 0,
    );
    expect(screen.queryByLabelText('Replacement registration result')).not.toBeInTheDocument();
  },
);

it.each(['maker', 'checker'] as const)(
  'cancels a held %s proof on unmount without replacing original custody',
  async (lane) => {
    writeBoundPolicyState('openpc:credential-workflow:v1', actor, review);
    const original = localStorage.getItem('openpc:credential-workflow:v1');
    const held = holdStepUp();
    const fetcher = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) =>
      Response.json(
        String(input).includes('/webauthn/enrollment')
          ? pendingEnrollment
          : {
              ...state,
              approvals: [
                {
                  ...credentialApproval(),
                  state: lane === 'maker' ? 'APPROVED' : 'REQUESTED',
                  proposal: {
                    ...credentialApproval().proposal,
                    state: lane === 'maker' ? 'APPROVED' : 'REQUESTED',
                  },
                },
              ],
            },
      ),
    );
    const view = render(<CredentialWorkflow />);
    fireEvent.click(
      await screen.findByRole('button', {
        name: lane === 'maker' ? 'Verify and commit replacement' : 'Verify and approve replacement',
      }),
    );
    await waitFor(() => expect(held.entered).toHaveBeenCalledOnce());
    expect(held.lifecycle().isCurrent?.()).toBe(true);
    const finished = expect(held.completion()).rejects.toMatchObject({ name: 'AbortError' });
    view.unmount();
    expect(held.lifecycle().signal?.aborted).toBe(true);
    await act(async () => {
      held.release();
      await finished;
    });
    expect(fetcher.mock.calls.some(([, init]) => init?.method === 'POST')).toBe(false);
    expect(localStorage.getItem('openpc:credential-workflow:v1')).toBe(original);
  },
);
it.each(['maker', 'checker'] as const)(
  'sends one exact current %s command after held proof despite duplicate clicks',
  async (lane) => {
    writeBoundPolicyState('openpc:credential-workflow:v1', actor, review);
    const held = holdStepUp();
    const posts: unknown[] = [];
    const fetcher = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      if (init?.method === 'POST') {
        posts.push(JSON.parse(String(init.body)));
        return Response.json({ truthState: 'SUCCESS' });
      }
      if (String(input).includes('/webauthn/enrollment'))
        return Response.json(
          posts.length
            ? {
                ...pendingEnrollment,
                state: 'COMPLETED',
                completedAt: new Date().toISOString(),
                credential: { ...credential, credentialId: id('713') },
              }
            : pendingEnrollment,
        );
      return Response.json({
        ...state,
        approvals: [
          {
            ...credentialApproval(),
            state: lane === 'maker' ? 'APPROVED' : 'REQUESTED',
            proposal: {
              ...credentialApproval().proposal,
              state: lane === 'maker' ? 'APPROVED' : 'REQUESTED',
            },
          },
        ],
      });
    });
    render(<CredentialWorkflow />);
    const button = await screen.findByRole('button', {
      name: lane === 'maker' ? 'Verify and commit replacement' : 'Verify and approve replacement',
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
      expect(screen.getByRole('button', { name: 'Refresh replacement approvals' })).toBeEnabled(),
    );
    expect(posts).toEqual([
      lane === 'maker'
        ? {
            command: 'COMMIT',
            reviewToken: review.reviewToken,
            approvalRequestId: review.approvalRequestId,
          }
        : {
            command: 'APPROVE',
            approvalRequestId: review.approvalRequestId,
            candidateDigest: review.review.candidateDigest,
            expectedRevision: '1',
          },
    ]);
    expect(performWebAuthnStepUp).toHaveBeenCalledWith(
      { ...review.review.stepUp, stepUp: 'FRESH_WEBAUTHN_MAX_5M' },
      review.review.stepUp,
      expect.objectContaining({ signal: expect.anything(), isCurrent: expect.any(Function) }),
    );
    expect(fetcher.mock.calls.filter(([, init]) => init?.method === 'POST')).toHaveLength(1);
  },
);
it('composes the actual helper with a held navigator and emits no VERIFY or COMMIT after unmount', async () => {
  const actual = await vi.importActual<typeof import('@openpc/ui-shell')>('@openpc/ui-shell');
  vi.mocked(performWebAuthnStepUp).mockImplementation(actual.performWebAuthnStepUp);
  writeBoundPolicyState('openpc:credential-workflow:v1', actor, review);
  const original = localStorage.getItem('openpc:credential-workflow:v1');
  const bytes = (value: string) => new TextEncoder().encode(value).buffer;
  class AssertionCredential {
    rawId = bytes('synthetic-credential');
    response = {
      authenticatorData: bytes('synthetic-authenticator'),
      clientDataJSON: bytes('synthetic-client'),
      signature: bytes('synthetic-signature'),
    };
  }
  let release!: (credential: AssertionCredential) => void;
  const get = vi.fn(
    () =>
      new Promise<AssertionCredential>((resolve) => {
        release = resolve;
      }),
  );
  vi.stubGlobal('PublicKeyCredential', AssertionCredential);
  Object.defineProperty(navigator, 'credentials', { configurable: true, value: { get } });
  const fetcher = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
    const url = String(input);
    if (url.endsWith('/assertion/challenge'))
      return Response.json({
        publicKey: {
          challenge: 'Y2hhbGxlbmdlLWJpbmFyeS12YWx1ZS0wMDAwMDAwMDAwMDA',
          rpId: 'localhost',
          allowCredentials: [{ id: 'Y3JlZGVudGlhbA', type: 'public-key' }],
          timeout: 300000,
          userVerification: 'required',
        },
        expiresAt: new Date(Date.now() + 300000).toISOString().replace('Z', '000Z'),
      });
    if (url.includes('/webauthn/enrollment')) return Response.json(pendingEnrollment);
    if (url.startsWith('/api/v1/ui/credential-workbench')) return Response.json(state);
    throw new Error('Unexpected assertion or mutation suffix');
  });
  const view = render(<CredentialWorkflow />);
  fireEvent.click(await screen.findByRole('button', { name: 'Verify and commit replacement' }));
  await waitFor(() => expect(get).toHaveBeenCalledOnce());
  const completed = expect(
    vi.mocked(performWebAuthnStepUp).mock.results[0]!.value,
  ).rejects.toMatchObject({ name: 'AbortError' });
  view.unmount();
  await act(async () => {
    release(new AssertionCredential());
    await completed;
  });
  expect(fetcher.mock.calls.filter(([, init]) => init?.method === 'POST')).toHaveLength(1);
  expect(fetcher.mock.calls.some(([url]) => String(url).endsWith('/assertion/verify'))).toBe(false);
  expect(localStorage.getItem('openpc:credential-workflow:v1')).toBe(original);
});

it.each(['success', 'interruption'] as const)(
  'preserves issued credential original custody after late %s without starting post-unmount reads',
  async (outcome) => {
    writeBoundPolicyState('openpc:credential-workflow:v1', actor, review);
    const original = localStorage.getItem('openpc:credential-workflow:v1');
    let resolve!: (value: Response) => void, reject!: (cause: Error) => void;
    const pending = new Promise<Response>((yes, no) => {
      resolve = yes;
      reject = no;
    });
    const fetcher = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      if (init?.method === 'POST') return pending;
      return Response.json(
        String(input).includes('/webauthn/enrollment')
          ? pendingEnrollment
          : {
              ...state,
              approvals: [
                {
                  ...credentialApproval(),
                  state: 'APPROVED',
                  proposal: { ...credentialApproval().proposal, state: 'APPROVED' },
                },
              ],
            },
      );
    });
    const view = render(<CredentialWorkflow />);
    fireEvent.click(await screen.findByRole('button', { name: 'Verify and commit replacement' }));
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
    expect(localStorage.getItem('openpc:credential-workflow:v1')).toBe(original);
    expect(performWebAuthnStepUp).toHaveBeenCalledOnce();
  },
);
