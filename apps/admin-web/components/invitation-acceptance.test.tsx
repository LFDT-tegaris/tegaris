import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import { InvitationAcceptanceWorkflow } from './invitation-acceptance';
afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  window.history.replaceState(null, '', '/');
});

vi.mock('./first-administrator-acceptance', () => ({
  FirstAdministratorAcceptance: ({
    participantId,
    invitationId,
  }: {
    participantId: string;
    invitationId: string;
  }) => (
    <article aria-label="Bound first administrator recipient">
      Participant {participantId}; invitation {invitationId}
    </article>
  ),
}));

const id = (n: number) => `018f0000-0000-7000-8000-${String(n).padStart(12, '0')}`;
const accepted = {
  invitationId: id(1),
  participantId: id(2),
  privacyDomainId: id(3),
  state: 'ACCEPTED',
  tokenVersion: '1',
  membershipId: id(4),
  membershipStateAtAcceptance: 'PROVISIONED',
  roleIntent: { roleId: id(5), authorityGranted: false },
  acceptedAt: '2026-09-15T12:00:00.000Z',
  operationId: id(6),
};
const proof = (version = '1') => ({
  invitationId: id(1),
  participantId: id(2),
  privacyDomainId: id(3),
  tokenVersion: version,
  token: (version === '1' ? 'A' : 'B').repeat(43),
});
const fragment = (version = '1') => '#' + new URLSearchParams(proof(version));
async function replaceFragment(value: string) {
  await act(async () => {
    window.history.replaceState(null, '', value);
    window.dispatchEvent(new HashChangeEvent('hashchange'));
  });
}
function pendingResponse() {
  let resolve!: (response: Response) => void;
  let reject!: (error: Error) => void;
  const promise = new Promise<Response>((yes, no) => {
    resolve = yes;
    reject = no;
  });
  return { promise, resolve, reject };
}
const retry = () => screen.getByRole('button', { name: 'Retry acceptance result read' });
const alertMessage = 'The acceptance result is unavailable. Retry the acceptance result read.';
function expectNoReceipt() {
  expect(screen.queryByLabelText('Invitation accepted')).not.toBeInTheDocument();
  expect(screen.queryByLabelText('Bound first administrator recipient')).not.toBeInTheDocument();
}

const privateProofFailure =
  'PRIVATE_INVITATION_PROOF token=original-secret cookie=private sql=SELECT';
const proofDenied =
  'This invitation cannot be accepted in the current authenticated context. Check the invitation before retrying.';
const proofConflict = 'The invitation has changed. Check its current state before retrying.';
const identityUnavailable = 'The identity check could not start.';
it('explains a denied identity callback, clears its marker and never displays an older receipt', async () => {
  window.history.replaceState(
    null,
    '',
    '/govern/memberships?view=invitation-acceptance&invitationError=identity_not_verified',
  );
  const fetcher = vi
    .spyOn(globalThis, 'fetch')
    .mockResolvedValue(Response.json({ acceptance: accepted }));
  render(<InvitationAcceptanceWorkflow />);
  const message = await screen.findByRole('alert');
  expect(message).toHaveTextContent(
    'We could not verify this invitation. Reopen the latest invitation link and sign in with the account selected by its sender.',
  );
  await waitFor(() => expect(message).toHaveFocus());
  expect(window.location.search).toBe('?view=invitation-acceptance');
  expect(fetcher).not.toHaveBeenCalled();
  expectNoReceipt();
  expect(screen.getByLabelText('Invitation secret')).toHaveValue('');
  expect(screen.getByRole('button', { name: 'Verify identity and accept' })).toBeEnabled();
});
it('uses a newly opened invitation link instead of an old callback error marker', async () => {
  window.history.replaceState(
    null,
    '',
    '/govern/memberships?view=invitation-acceptance&invitationError=identity_not_verified' +
      fragment(),
  );
  const fetcher = vi.spyOn(globalThis, 'fetch');
  render(<InvitationAcceptanceWorkflow />);
  await waitFor(() =>
    expect(screen.getByLabelText('Invitation secret')).toHaveValue(proof().token),
  );
  expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  expect(window.location.search).toBe('?view=invitation-acceptance');
  expect(fetcher).not.toHaveBeenCalled();
  expectNoReceipt();
});
const authorizationUri =
  'https://issuer.example.test/authorize?response_type=code&code_challenge_method=S256&state=producer-owned-state';
const proofFailures = [
  401,
  403,
  409,
  412,
  500,
  'transport',
  'parse',
  'target',
  'extra',
  'unknown',
] as const;
it.each(
  ['success', 'denial', 'transport', 'json success', 'json failure'].flatMap((outcome) =>
    ['valid', 'incomplete'].map((link) => [outcome, link]),
  ),
)(
  'discards an obsolete %s after a %s rotated link without clearing its proof or replacing its error',
  async (outcome, link) => {
    window.history.replaceState(null, '', '/' + fragment());
    const pending = pendingResponse();
    let resolveJSON!: (value: unknown) => void;
    let rejectJSON!: (cause: Error) => void;
    const decoded = new Promise<unknown>((resolve, reject) => {
      resolveJSON = resolve;
      rejectJSON = reject;
    });
    const response = Response.json({ authorizationUri });
    const json = vi.spyOn(response, 'json').mockImplementation(() => decoded);
    const fetcher = vi
      .spyOn(globalThis, 'fetch')
      .mockImplementationOnce(() =>
        outcome.startsWith('json') ? Promise.resolve(response) : pending.promise,
      )
      .mockResolvedValue(Response.json({ authorizationUri }));
    render(<InvitationAcceptanceWorkflow />);
    await waitFor(() =>
      expect(screen.getByLabelText('Invitation secret')).toHaveValue(proof().token),
    );
    const assign = vi.fn();
    vi.stubGlobal('location', { hash: '', pathname: '/', search: '', assign });
    fireEvent.submit(
      screen.getByRole('button', { name: 'Verify identity and accept' }).closest('form')!,
    );
    await waitFor(() => expect(fetcher).toHaveBeenCalledTimes(1));
    if (outcome.startsWith('json')) await waitFor(() => expect(json).toHaveBeenCalledTimes(1));
    vi.unstubAllGlobals();
    await replaceFragment('/' + (link === 'valid' ? fragment('2') : '#invitationId=' + id(99)));
    expect(window.location.hash).toBe('');
    vi.stubGlobal('location', { hash: '', pathname: '/', search: '', assign });
    await act(async () => {
      if (outcome === 'json success') resolveJSON({ authorizationUri });
      else if (outcome === 'json failure') rejectJSON(new Error(privateProofFailure));
      else if (outcome === 'transport') pending.reject(new Error(privateProofFailure));
      else
        pending.resolve(
          outcome === 'success'
            ? Response.json({ authorizationUri })
            : Response.json({ title: privateProofFailure }, { status: 403 }),
        );
    });
    expect(assign).not.toHaveBeenCalled();
    expect(fetcher).toHaveBeenCalledTimes(1);
    expect(document.body).not.toHaveTextContent(privateProofFailure);
    expect(screen.getByLabelText('Invitation secret')).toHaveValue(
      link === 'valid' ? proof('2').token : '',
    );
    expect(screen.getByLabelText('Token version')).toHaveValue(link === 'valid' ? '2' : '');
    expect(screen.getByRole('button', { name: 'Verify identity and accept' })).toBeEnabled();
    expectNoReceipt();
    if (link === 'incomplete') {
      expect(screen.getByRole('alert')).toHaveTextContent(
        'The invitation link is incomplete. Ask its sender for a current link.',
      );
    } else {
      expect(screen.queryByRole('alert')).not.toBeInTheDocument();
      fireEvent.submit(
        screen.getByRole('button', { name: 'Verify identity and accept' }).closest('form')!,
      );
      await waitFor(() => expect(assign).toHaveBeenCalledExactlyOnceWith(authorizationUri));
      expect(fetcher.mock.calls.map(([, init]) => JSON.parse(String(init?.body)))).toEqual([
        proof(),
        proof('2'),
      ]);
      expect(screen.getByLabelText('Invitation secret')).toHaveValue('');
    }
  },
);
it.each(['success', 'failure'] as const)(
  'ignores a pending identity-start %s after unmount without redirecting',
  async (outcome) => {
    window.history.replaceState(null, '', '/' + fragment());
    const pending = pendingResponse();
    const fetcher = vi.spyOn(globalThis, 'fetch').mockReturnValue(pending.promise);
    const view = render(<InvitationAcceptanceWorkflow />);
    await waitFor(() =>
      expect(screen.getByLabelText('Invitation secret')).toHaveValue(proof().token),
    );
    const assign = vi.fn();
    vi.stubGlobal('location', { hash: '', pathname: '/', search: '', assign });
    fireEvent.submit(
      screen.getByRole('button', { name: 'Verify identity and accept' }).closest('form')!,
    );
    view.unmount();
    await act(async () => {
      if (outcome === 'success') pending.resolve(Response.json({ authorizationUri }));
      else pending.reject(new Error(privateProofFailure));
    });
    expect(assign).not.toHaveBeenCalled();
    expect(fetcher).toHaveBeenCalledTimes(1);
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  },
);
it.each(proofFailures)(
  'redacts a %s identity-start failure without losing proof custody, redirecting or replaying',
  async (failure) => {
    window.history.replaceState(null, '', '/invitations?source=recipient' + fragment());
    const fetcher = vi.spyOn(globalThis, 'fetch').mockImplementation(async () => {
      if (failure === 'transport') throw new Error(privateProofFailure);
      if (failure === 'unknown')
        return Promise.reject({
          name: 'InvitationAcceptanceFailure',
          message: privateProofFailure,
        });
      if (failure === 'parse')
        return new Response(privateProofFailure, {
          headers: { 'Content-Type': 'application/json' },
        });
      if (failure === 'target') return Response.json({ authorizationUri: privateProofFailure });
      if (failure === 'extra')
        return Response.json({ authorizationUri, privateDetail: privateProofFailure });
      return Response.json(
        { title: privateProofFailure, code: privateProofFailure, detail: privateProofFailure },
        { status: failure },
      );
    });
    render(<InvitationAcceptanceWorkflow />);
    await waitFor(() =>
      expect(screen.getByLabelText('Invitation secret')).toHaveValue(proof().token),
    );
    expect(window.location.hash).toBe('');
    expect(window.location.pathname + window.location.search).toBe('/invitations?source=recipient');
    const assign = vi.fn();
    vi.stubGlobal('location', {
      hash: '',
      pathname: '/invitations',
      search: '?source=recipient',
      assign,
    });
    fireEvent.change(screen.getByLabelText('Identity account hint (optional)'), {
      target: { value: '  exact-provider-account  ' },
    });
    fireEvent.submit(
      screen.getByRole('button', { name: 'Verify identity and accept' }).closest('form')!,
    );
    const alert = await screen.findByRole('alert');
    expect(alert).toHaveTextContent(
      failure === 401 || failure === 403
        ? proofDenied
        : failure === 409 || failure === 412
          ? proofConflict
          : typeof failure === 'number'
            ? 'The invitation identity check could not start. Retry after checking the invitation.'
            : identityUnavailable,
    );
    await waitFor(() => expect(alert).toHaveFocus());
    expect(document.body).not.toHaveTextContent(privateProofFailure);
    expect(screen.getByLabelText('Invitation secret')).toHaveValue(proof().token);
    expect(screen.getByLabelText('Invitation ID')).toHaveValue(proof().invitationId);
    expect(screen.getByLabelText('Participant ID')).toHaveValue(proof().participantId);
    expect(screen.getByLabelText('Privacy domain ID')).toHaveValue(proof().privacyDomainId);
    expect(screen.getByLabelText('Token version')).toHaveValue(proof().tokenVersion);
    expect(screen.getByLabelText('Identity account hint (optional)')).toHaveValue(
      '  exact-provider-account  ',
    );
    expectNoReceipt();
    expect(
      screen.queryByRole('button', { name: 'Retry acceptance result read' }),
    ).not.toBeInTheDocument();
    expect(assign).not.toHaveBeenCalled();
    expect(fetcher.mock.calls).toEqual([
      [
        '/api/v1/ui/invitation-proof',
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ ...proof(), loginHint: 'exact-provider-account' }),
        },
      ],
    ]);
    expect(screen.getByRole('button', { name: 'Verify identity and accept' })).toBeEnabled();
  },
);

it.each(['redirect', 'redirect failure'] as const)(
  'preserves the producer-owned authorization URI and token clearing during %s',
  async (outcome) => {
    window.history.replaceState(null, '', '/' + fragment());
    const fetcher = vi
      .spyOn(globalThis, 'fetch')
      .mockResolvedValue(Response.json({ authorizationUri }));
    render(<InvitationAcceptanceWorkflow />);
    await waitFor(() =>
      expect(screen.getByLabelText('Invitation secret')).toHaveValue(proof().token),
    );
    expect(window.location.hash).toBe('');
    const assign = vi.fn(() => {
      if (outcome === 'redirect failure') throw new Error(privateProofFailure);
    });
    vi.stubGlobal('location', { hash: '', pathname: '/', search: '', assign });
    fireEvent.submit(
      screen.getByRole('button', { name: 'Verify identity and accept' }).closest('form')!,
    );
    await waitFor(() => expect(assign).toHaveBeenCalledExactlyOnceWith(authorizationUri));
    await waitFor(() => expect(screen.getByLabelText('Invitation secret')).toHaveValue(''));
    expect(document.body).not.toHaveTextContent(privateProofFailure);
    expectNoReceipt();
    expect(
      screen.queryByRole('button', { name: 'Retry acceptance result read' }),
    ).not.toBeInTheDocument();
    expect(fetcher.mock.calls).toEqual([
      [
        '/api/v1/ui/invitation-proof',
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(proof()),
        },
      ],
    ]);
    if (outcome === 'redirect failure') {
      expect(await screen.findByRole('alert')).toHaveTextContent(identityUnavailable);
      expect(screen.getByRole('button', { name: 'Verify identity and accept' })).toBeEnabled();
    } else {
      expect(screen.queryByRole('alert')).not.toBeInTheDocument();
      expect(screen.getByRole('button', { name: 'Opening identity provider…' })).toBeDisabled();
    }
  },
);

it('retains the fixed local proof validation without exposing its entered value or making a POST', async () => {
  const fetcher = vi
    .spyOn(globalThis, 'fetch')
    .mockResolvedValue(Response.json({ acceptance: null }));
  render(<InvitationAcceptanceWorkflow />);
  await waitFor(() => expect(retry()).toBeEnabled());
  fireEvent.change(screen.getByLabelText('Invitation ID'), {
    target: { value: privateProofFailure },
  });
  fireEvent.submit(
    screen.getByRole('button', { name: 'Verify identity and accept' }).closest('form')!,
  );
  expect(await screen.findByRole('alert')).toHaveTextContent(
    'Check the invitation, Participant, privacy domain, token version and secret.',
  );
  expect(document.body).not.toHaveTextContent(privateProofFailure);
  expectNoReceipt();
  expect(fetcher.mock.calls).toEqual([['/api/v1/ui/invitation-proof', { cache: 'no-store' }]]);
});

it.each(['PROVISIONED', 'ACTIVE'] as const)(
  'shows the sealed historical %s receipt without claiming a new grant or session',
  async (membershipStateAtAcceptance) => {
    const fetcher = vi
      .spyOn(globalThis, 'fetch')
      .mockResolvedValue(
        Response.json({ acceptance: { ...accepted, membershipStateAtAcceptance } }),
      );
    render(<InvitationAcceptanceWorkflow />);
    const result = await screen.findByLabelText('Invitation accepted');
    expect(result).toHaveTextContent(membershipStateAtAcceptance);
    expect(result).toHaveTextContent(accepted.operationId);
    expect(result).toHaveTextContent('No sign-in session was created');
    expect(result).toHaveTextContent(
      membershipStateAtAcceptance === 'PROVISIONED'
        ? 'Your administrator must activate the membership and approve its access.'
        : 'Your existing membership was retained. This invitation granted no additional access.',
    );
    expect(within(result).getByRole('link', { name: 'Continue to sign in' })).toHaveAttribute(
      'href',
      `/signin?returnTo=%2Fhome%2Fsession&participantId=${accepted.participantId}`,
    );
    expect(fetcher.mock.calls).toEqual([['/api/v1/ui/invitation-proof', { cache: 'no-store' }]]);
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  },
);

it('treats an exact null receipt as absence, with an explicit GET-only read retry', async () => {
  const fetcher = vi
    .spyOn(globalThis, 'fetch')
    .mockImplementation(async () => Response.json({ acceptance: null }));
  render(<InvitationAcceptanceWorkflow />);
  await waitFor(() => expect(retry()).toBeEnabled());
  expectNoReceipt();
  expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Verify identity and accept' })).toBeEnabled();
  fireEvent.click(retry());
  await waitFor(() => expect(fetcher).toHaveBeenCalledTimes(2));
  await waitFor(() => expect(retry()).toBeEnabled());
  expect(fetcher.mock.calls.every(([, init]) => init?.method === undefined)).toBe(true);
});

it('delegates only the validated receipt participant and invitation to the existing first-administrator child', async () => {
  const fetcher = vi
    .spyOn(globalThis, 'fetch')
    .mockResolvedValue(Response.json({ acceptance: accepted, firstAdministrator: true }));
  render(<InvitationAcceptanceWorkflow />);
  const child = await screen.findByLabelText('Bound first administrator recipient');
  expect(child).toHaveTextContent(accepted.participantId);
  expect(child).toHaveTextContent(accepted.invitationId);
  expect(screen.queryByLabelText('Invitation accepted')).not.toBeInTheDocument();
  expect(fetcher).toHaveBeenCalledTimes(1);
});

it.each([201, 202, 206, 401, 403, 404, 503])(
  'refuses a %s receipt response even with an otherwise valid first-administrator body',
  async (status) => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      Response.json({ acceptance: accepted, firstAdministrator: true }, { status }),
    );
    render(<InvitationAcceptanceWorkflow />);
    const alert = await screen.findByRole('alert');
    expect(alert).toHaveTextContent(alertMessage);
    await waitFor(() => expect(alert).toHaveFocus());
    expectNoReceipt();
    expect(alert).not.toHaveTextContent(accepted.membershipId);
  },
);

it.each([
  ['missing acceptance', {}],
  ['null envelope', null],
  ['array envelope', [{ acceptance: accepted }]],
  ['invalid acceptance', { acceptance: { ...accepted, state: 'PENDING' } }],
  [
    'grant claim',
    { acceptance: { ...accepted, roleIntent: { ...accepted.roleIntent, authorityGranted: true } } },
  ],
  ['missing membership', { acceptance: { ...accepted, membershipId: undefined } }],
  ['private receipt field', { acceptance: { ...accepted, sessionToken: 'private-sentinel' } }],
  [
    'private envelope field',
    { acceptance: accepted, bootstrap: { sessionToken: 'private-sentinel' } },
  ],
  ['unsupported envelope field', { acceptance: accepted, current: true }],
  ['false marker', { acceptance: accepted, firstAdministrator: false }],
  ['string marker', { acceptance: accepted, firstAdministrator: 'true' }],
  ['null marker', { acceptance: accepted, firstAdministrator: null }],
  ['marker without receipt', { acceptance: null, firstAdministrator: true }],
] as const)(
  'refuses the %s receipt projection with a fixed private-safe error',
  async (_label, body) => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(Response.json(body));
    render(<InvitationAcceptanceWorkflow />);
    expect(await screen.findByRole('alert')).toHaveTextContent(alertMessage);
    expectNoReceipt();
    expect(document.body).not.toHaveTextContent('private-sentinel');
    expect(document.body).not.toHaveTextContent(accepted.membershipId);
  },
);

it('reports invalid JSON separately from a valid null receipt', async () => {
  vi.spyOn(globalThis, 'fetch').mockResolvedValue(
    new Response('{broken private-sentinel', { headers: { 'Content-Type': 'application/json' } }),
  );
  render(<InvitationAcceptanceWorkflow />);
  expect(await screen.findByRole('alert')).toHaveTextContent(alertMessage);
  expectNoReceipt();
  expect(document.body).not.toHaveTextContent('private-sentinel');
});

it('retries a failed receipt read without starting identity proof or exchanging the callback', async () => {
  const fetcher = vi
    .spyOn(globalThis, 'fetch')
    .mockRejectedValueOnce(new Error('private-sentinel'))
    .mockResolvedValueOnce(Response.json({ acceptance: accepted }));
  render(<InvitationAcceptanceWorkflow />);
  expect(await screen.findByRole('alert')).toHaveTextContent(alertMessage);
  expect(document.body).not.toHaveTextContent('private-sentinel');
  fireEvent.click(retry());
  expect(await screen.findByLabelText('Invitation accepted')).toHaveTextContent(
    accepted.operationId,
  );
  expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  expect(fetcher.mock.calls).toEqual([
    ['/api/v1/ui/invitation-proof', { cache: 'no-store' }],
    ['/api/v1/ui/invitation-proof', { cache: 'no-store' }],
  ]);
});

it.each([false, true])(
  'hides the old receipt/child before a retry, then keeps it hidden on failure (first administrator %s)',
  async (firstAdministrator) => {
    const next = pendingResponse();
    const fetcher = vi
      .spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(
        Response.json({
          acceptance: accepted,
          ...(firstAdministrator ? { firstAdministrator: true } : {}),
        }),
      )
      .mockReturnValueOnce(next.promise);
    render(<InvitationAcceptanceWorkflow />);
    await screen.findByLabelText(
      firstAdministrator ? 'Bound first administrator recipient' : 'Invitation accepted',
    );
    fireEvent.click(retry());
    expectNoReceipt();
    expect(screen.getByRole('status')).toHaveTextContent('Reading acceptance result');
    expect(retry()).toBeDisabled();
    await act(async () => next.resolve(Response.json({ acceptance: accepted }, { status: 503 })));
    expect(await screen.findByRole('alert')).toHaveTextContent(alertMessage);
    expectNoReceipt();
    expect(fetcher).toHaveBeenCalledTimes(2);
  },
);

it.each(['#token=invalid', '#invitationId=invalid&token=private-sentinel'])(
  'clears every previous proof field and account hint when a replacement is malformed (%s)',
  async (replacement) => {
    const fetcher = vi.spyOn(globalThis, 'fetch');
    window.history.replaceState(null, '', fragment());
    render(<InvitationAcceptanceWorkflow />);
    expect(screen.getByLabelText('Invitation secret')).toHaveValue(proof().token);
    fireEvent.change(screen.getByLabelText('Identity account hint (optional)'), {
      target: { value: 'previous-recipient' },
    });
    await replaceFragment(replacement);
    for (const label of [
      'Invitation ID',
      'Participant ID',
      'Privacy domain ID',
      'Token version',
      'Invitation secret',
      'Identity account hint (optional)',
    ]) {
      expect(screen.getByLabelText(label)).toHaveValue('');
    }
    expect(await screen.findByRole('alert')).toHaveTextContent('The invitation link is incomplete');
    expect(window.location.hash).toBe('');
    expect(
      screen.queryByRole('button', { name: 'Retry acceptance result read' }),
    ).not.toBeInTheDocument();
    fireEvent.submit(
      screen.getByRole('button', { name: 'Verify identity and accept' }).closest('form')!,
    );
    expect(await screen.findByRole('alert')).toHaveTextContent('Check the invitation');
    expect(fetcher).not.toHaveBeenCalled();
  },
);

it('replaces all proof inputs and clears the old account hint for a valid replacement', async () => {
  const fetcher = vi.spyOn(globalThis, 'fetch');
  window.history.replaceState(null, '', fragment());
  render(<InvitationAcceptanceWorkflow />);
  fireEvent.change(screen.getByLabelText('Identity account hint (optional)'), {
    target: { value: 'previous-recipient' },
  });
  const replacement = {
    ...proof('2'),
    invitationId: id(11),
    participantId: id(12),
    privacyDomainId: id(13),
  };
  await replaceFragment('#' + new URLSearchParams(replacement));
  expect(screen.getByLabelText('Invitation ID')).toHaveValue(replacement.invitationId);
  expect(screen.getByLabelText('Participant ID')).toHaveValue(replacement.participantId);
  expect(screen.getByLabelText('Privacy domain ID')).toHaveValue(replacement.privacyDomainId);
  expect(screen.getByLabelText('Token version')).toHaveValue('2');
  expect(screen.getByLabelText('Invitation secret')).toHaveValue(replacement.token);
  expect(screen.getByLabelText('Identity account hint (optional)')).toHaveValue('');
  expect(window.location.hash).toBe('');
  expect(fetcher).not.toHaveBeenCalled();
});

it.each(['receipt', 'failure'] as const)(
  'ignores a late initial %s after a new fragment replaces the result mode',
  async (outcome) => {
    const pending = pendingResponse();
    const fetcher = vi.spyOn(globalThis, 'fetch').mockReturnValueOnce(pending.promise);
    render(<InvitationAcceptanceWorkflow />);
    await replaceFragment(fragment('2'));
    await act(async () => {
      if (outcome === 'receipt')
        pending.resolve(Response.json({ acceptance: accepted, firstAdministrator: true }));
      else pending.reject(new Error('private-sentinel'));
    });
    expectNoReceipt();
    expect(screen.getByLabelText('Token version')).toHaveValue('2');
    expect(screen.getByLabelText('Invitation secret')).toHaveValue(proof('2').token);
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    expect(screen.queryByRole('status')).not.toBeInTheDocument();
    expect(
      screen.queryByRole('button', { name: 'Retry acceptance result read' }),
    ).not.toBeInTheDocument();
    expect(fetcher).toHaveBeenCalledTimes(1);
  },
);

it('does not use a late retry result as readiness for a malformed replacement link', async () => {
  const pending = pendingResponse();
  const fetcher = vi
    .spyOn(globalThis, 'fetch')
    .mockRejectedValueOnce(new Error('unavailable'))
    .mockReturnValueOnce(pending.promise);
  render(<InvitationAcceptanceWorkflow />);
  await screen.findByRole('alert');
  fireEvent.click(retry());
  await replaceFragment('#token=incomplete');
  await act(async () =>
    pending.resolve(Response.json({ acceptance: accepted, firstAdministrator: true })),
  );
  expectNoReceipt();
  expect(screen.getByRole('alert')).toHaveTextContent('The invitation link is incomplete');
  expect(screen.getByLabelText('Invitation secret')).toHaveValue('');
  expect(
    screen.queryByRole('button', { name: 'Retry acceptance result read' }),
  ).not.toBeInTheDocument();
  expect(fetcher).toHaveBeenCalledTimes(2);
});

it.each(['proof field', 'account hint', 'submission'] as const)(
  'invalidates an older receipt read on a new manual %s intent',
  async (intent) => {
    const pending = pendingResponse();
    const fetcher = vi.spyOn(globalThis, 'fetch').mockReturnValueOnce(pending.promise);
    render(<InvitationAcceptanceWorkflow />);
    if (intent === 'proof field')
      fireEvent.change(screen.getByLabelText('Invitation ID'), { target: { value: id(11) } });
    else if (intent === 'account hint')
      fireEvent.change(screen.getByLabelText('Identity account hint (optional)'), {
        target: { value: 'current-recipient' },
      });
    else
      fireEvent.submit(
        screen.getByRole('button', { name: 'Verify identity and accept' }).closest('form')!,
      );
    await act(async () =>
      pending.resolve(Response.json({ acceptance: accepted, firstAdministrator: true })),
    );
    expectNoReceipt();
    expect(
      screen.queryByRole('button', { name: 'Retry acceptance result read' }),
    ).not.toBeInTheDocument();
    if (intent === 'submission')
      expect(screen.getByRole('alert')).toHaveTextContent('Check the invitation');
    else expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    expect(fetcher).toHaveBeenCalledTimes(1);
  },
);

it.each(['receipt', 'failure'] as const)(
  'ignores a late %s after unmount and preserves a separate current reader',
  async (outcome) => {
    const pending = pendingResponse();
    const fetcher = vi
      .spyOn(globalThis, 'fetch')
      .mockReturnValueOnce(pending.promise)
      .mockResolvedValueOnce(Response.json({ acceptance: null }));
    const previous = render(<InvitationAcceptanceWorkflow />);
    previous.unmount();
    render(<InvitationAcceptanceWorkflow />);
    await waitFor(() => expect(retry()).toBeEnabled());
    await act(async () => {
      if (outcome === 'receipt')
        pending.resolve(Response.json({ acceptance: accepted, firstAdministrator: true }));
      else pending.reject(new Error('private-sentinel'));
    });
    expectNoReceipt();
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    expect(retry()).toBeEnabled();
    expect(fetcher).toHaveBeenCalledTimes(2);
  },
);

it('keeps a manual proof POST and its original error separate from a late old receipt', async () => {
  const pending = pendingResponse();
  const fetcher = vi
    .spyOn(globalThis, 'fetch')
    .mockReturnValueOnce(pending.promise)
    .mockResolvedValueOnce(
      Response.json(
        { title: 'This invitation cannot be accepted.', code: 'PC-AUTH-0002' },
        { status: 403 },
      ),
    );
  render(<InvitationAcceptanceWorkflow />);
  const input = proof('2');
  for (const [label, value] of [
    ['Invitation ID', input.invitationId],
    ['Participant ID', input.participantId],
    ['Privacy domain ID', input.privacyDomainId],
    ['Token version', input.tokenVersion],
    ['Invitation secret', input.token],
    ['Identity account hint (optional)', ' current-recipient '],
  ] as const)
    fireEvent.change(screen.getByLabelText(label), { target: { value } });
  fireEvent.submit(
    screen.getByRole('button', { name: 'Verify identity and accept' }).closest('form')!,
  );
  expect(await screen.findByRole('alert')).toHaveTextContent(
    'This invitation cannot be accepted in the current authenticated context. Check the invitation before retrying.',
  );
  await act(async () =>
    pending.resolve(Response.json({ acceptance: accepted, firstAdministrator: true })),
  );
  expectNoReceipt();
  expect(screen.getByRole('alert')).toHaveTextContent(
    'This invitation cannot be accepted in the current authenticated context. Check the invitation before retrying.',
  );
  expect(screen.getByLabelText('Invitation secret')).toHaveValue(input.token);
  expect(fetcher).toHaveBeenCalledTimes(2);
  expect(fetcher.mock.calls[1]).toEqual([
    '/api/v1/ui/invitation-proof',
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ...input, loginHint: 'current-recipient' }),
    },
  ]);
  expect(
    screen.queryByRole('button', { name: 'Retry acceptance result read' }),
  ).not.toBeInTheDocument();
});

it('fences receipt decoding that finishes after a replacement fragment is adopted', async () => {
  let resolve!: (value: unknown) => void;
  const decoded = new Promise<unknown>((yes) => {
    resolve = yes;
  });
  const response = Response.json({ acceptance: null });
  const decode = vi.spyOn(response, 'json').mockReturnValueOnce(decoded);
  vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(response);
  render(<InvitationAcceptanceWorkflow />);
  await waitFor(() => expect(decode).toHaveBeenCalledTimes(1));
  await replaceFragment(fragment('2'));
  await act(async () => resolve({ acceptance: accepted, firstAdministrator: true }));
  expectNoReceipt();
  expect(screen.getByLabelText('Token version')).toHaveValue('2');
  expect(screen.getByLabelText('Invitation secret')).toHaveValue(proof('2').token);
  expect(screen.queryByRole('alert')).not.toBeInTheDocument();
});
it('adopts a rotated invitation opened in the same tab and immediately removes its secret fragment', async () => {
  const id = (n: number) => `018f0000-0000-7000-8000-${String(n).padStart(12, '0')}`;
  const link = (version: string) =>
    '#' +
    new URLSearchParams({
      invitationId: id(1),
      participantId: id(2),
      privacyDomainId: id(3),
      tokenVersion: version,
      token: (version === '1' ? 'A' : 'B').repeat(43),
    });
  const fetcher = vi.spyOn(globalThis, 'fetch');
  window.history.replaceState(
    null,
    '',
    `/govern/memberships?view=invitation-acceptance${link('1')}`,
  );
  render(<InvitationAcceptanceWorkflow />);
  expect(await screen.findByLabelText('Token version')).toHaveValue('1');
  expect(window.location.hash).toBe('');
  await act(async () => {
    window.history.replaceState(null, '', link('2'));
    window.dispatchEvent(new HashChangeEvent('hashchange'));
  });
  await waitFor(() => expect(screen.getByLabelText('Token version')).toHaveValue('2'));
  expect(screen.getByLabelText('Invitation secret')).toHaveValue('B'.repeat(43));
  expect(window.location.hash).toBe('');
  expect(fetcher).not.toHaveBeenCalled();
});
