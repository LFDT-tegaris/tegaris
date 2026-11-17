import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, expect, it, vi } from 'vitest';
import { webcrypto } from 'node:crypto';
import { performWebAuthnStepUp } from '@openpc/ui-shell';
import { InvitationWorkflow } from './invitation-workflow';
vi.mock('@openpc/ui-shell', () => ({ performWebAuthnStepUp: vi.fn() }));
vi.mock('./local-session', () => ({ LocalSessionSurface: () => <p>Sign in</p> }));
afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  vi.clearAllMocks();
  vi.unstubAllGlobals();
  localStorage.clear();
});
it('keeps the reason field labelled and editable when an existing value is reused for resend', async () => {
  const id = (n: number) => `018f0000-0000-7000-8000-${String(n).padStart(12, '0')}`;
  vi.spyOn(globalThis, 'fetch').mockResolvedValue(
    Response.json({
      actor: {
        sessionId: id(1),
        principalId: id(2),
        participantId: id(3),
        privacyDomainId: id(4),
        contextEpoch: '1',
      },
      approvals: [],
      nextCursor: null,
    }),
  );
  render(<InvitationWorkflow />);
  const user = userEvent.setup();
  await user.type(
    await screen.findByLabelText('Reason', { exact: true }),
    'Invite the reviewed colleague.',
  );
  await user.selectOptions(screen.getByRole('combobox', { name: 'Change' }), 'RESEND');
  const reason = screen.getByLabelText('Reason', { exact: true });
  expect(reason).toHaveAccessibleName('Reason');
  await user.clear(reason);
  await user.type(reason, 'Resend with a replacement token.');
  expect(reason).toHaveValue('Resend with a replacement token.');
});

const id = (n: number) => `018f0000-0000-7000-8000-${String(n).padStart(12, '0')}`;
const actor = {
  sessionId: id(1),
  principalId: id(2),
  participantId: id(3),
  privacyDomainId: id(4),
  contextEpoch: '1',
};
const digest = `sha256:${'a'.repeat(64)}`;
const instant = '2026-10-04T00:00:00.000Z';
const storageKey = 'openpc:invitation-workflow:v1';
const candidate = {
  change: {
    mutation: 'CREATE',
    invitationId: id(50),
    displayName: 'Reviewed colleague',
    recipientSubject: 'provider-subject',
    intendedRoleId: id(7),
    tokenDigest: digest,
    ttlSeconds: 86400,
  },
  expectedRevision: '0',
  issuer: 'https://issuer.example.test',
  audience: 'openpc',
};
function savedReview(change: Record<string, unknown> = candidate.change) {
  return {
    reviewToken: 'sealed-original-review-token',
    review: {
      candidate: { ...candidate, change },
      candidateDigest: digest,
      resourceId: id(50),
      expectedRevision: '0',
      checkerPrincipalId: id(6),
      reason: 'Invite the independently reviewed colleague.',
      expiresAt: '2030-01-01T00:00:00.000Z',
      stepUp: {
        actionIntentId: 'ACT-IDENTITY_CREATE_SESSION-V1',
        actionIntentDigest: digest,
        resourceId: id(50),
        resourceDigest: digest,
      },
    },
  };
}
const record = {
  invitationId: id(50),
  participantId: actor.participantId,
  privacyDomainId: actor.privacyDomainId,
  displayName: 'Reviewed colleague',
  recipient: { issuer: candidate.issuer, subject: 'provider-subject', audience: 'openpc' },
  roleIntent: { roleId: id(7), authorityGranted: false },
  createdByPrincipalId: actor.principalId,
  state: 'PENDING',
  tokenVersion: '1',
  expiresAt: '2030-01-01T00:00:00.000Z',
  revision: '1',
  operationId: id(60),
  createdAt: instant,
  updatedAt: instant,
};
function approval(label = 'Reviewed colleague') {
  return {
    approvalRequestId: `urn:openpc:approval:${id(80)}`,
    actionIntentId: 'ACT-IDENTITY_CREATE_SESSION-V1',
    candidateDigest: digest,
    state: 'REQUESTED',
    makerSubjectRef: `urn:openpc:resource:${id(9)}`,
    checkerSubjectRef: `urn:openpc:resource:${actor.principalId}`,
    revision: '0',
    createdAt: instant,
    updatedAt: instant,
    proposal: {
      candidate: { ...candidate, change: { ...candidate.change, displayName: label } },
      candidateDigest: digest,
      resourceId: id(50),
      catalogOperationId: 'ID-OP-INVITATION-CREATE',
      expectedRevision: '0',
      state: 'APPROVAL_REQUESTED',
      expiresAt: '2030-01-01T00:00:00.000Z',
      makerPrincipalId: id(9),
      operationId: null,
      approval: { approvalRequestId: id(80), reason: 'Reviewed invitation request.' },
    },
    stepUp: savedReview().review.stepUp,
  };
}
const inventory = (
  value = actor,
  approvals: ReturnType<typeof approval>[] = [],
  nextCursor: string | null = null,
) => ({
  actor: value,
  approvals,
  nextCursor,
});
const sessionValue = (value = actor) => ({
  ...value,
  authenticated: true,
  contextMode: 'PARTICIPANT',
});
function deferred<T = Response>() {
  let resolve!: (value: T) => void;
  let reject!: (cause: unknown) => void;
  const promise = new Promise<T>((yes, no) => {
    resolve = yes;
    reject = no;
  });
  return { promise, resolve, reject };
}
async function focus() {
  await act(async () => {
    window.dispatchEvent(new Event('focus'));
  });
}
async function readInvitation(target = id(50)) {
  fireEvent.change(await screen.findByLabelText('Invitation ID', { exact: true }), {
    target: { value: target },
  });
  await userEvent.setup().click(screen.getByRole('button', { name: 'Read invitation' }));
}
const privateInvitationFailure =
  'PRIVATE_INVITATION_ERROR token=original-secret cookie=private sql=SELECT';
const invitationDenied =
  'The invitation request was not authorized. Refresh the authenticated context before continuing.';
const invitationConflict =
  'The invitation request could not continue with the current state. Read the invitation before retrying.';
const invitationInvalid = 'The invitation response is invalid. Refresh before continuing.';
const invitationReadUnavailable =
  'The invitation response is unavailable. Refresh before continuing.';
const invitationOperationUnavailable =
  'The operation is unavailable. Read its current state before retrying.';
async function failedInvitationResponse(failure: string): Promise<Response> {
  if (failure === 'transport') throw new Error(privateInvitationFailure);
  if (failure === 'unknown')
    return Promise.reject({ name: 'InvitationWorkflowFailure', message: privateInvitationFailure });
  if (failure === 'parse')
    return new Response(privateInvitationFailure, {
      headers: { 'Content-Type': 'application/json' },
    });
  return Response.json(
    {
      title: privateInvitationFailure,
      code: privateInvitationFailure,
      detail: privateInvitationFailure,
    },
    {
      status: failure === 'denial' ? 403 : failure === 'conflict' ? 409 : 500,
    },
  );
}
function failureMessage(failure: string, reading: boolean) {
  return failure === 'denial'
    ? invitationDenied
    : failure === 'conflict'
      ? invitationConflict
      : failure === 'parse'
        ? invitationInvalid
        : failure === 'server'
          ? 'The invitation request could not be completed. Read its current state before retrying.'
          : reading
            ? invitationReadUnavailable
            : invitationOperationUnavailable;
}
it.each(['denial', 'conflict', 'server', 'transport', 'parse', 'unknown'])(
  'redacts current invitation inventory %s and preserves custody for an explicit read retry',
  async (failure) => {
    localStorage.setItem(storageKey, JSON.stringify({ actor, value: savedReview() }));
    const original = localStorage.getItem(storageKey);
    let failed = true;
    const fetcher = vi
      .spyOn(globalThis, 'fetch')
      .mockImplementation(async () =>
        failed ? failedInvitationResponse(failure) : Response.json(inventory()),
      );
    render(<InvitationWorkflow />);
    expect(await screen.findByRole('alert')).toHaveTextContent(failureMessage(failure, true));
    expect(document.body).not.toHaveTextContent(privateInvitationFailure);
    expect(screen.queryByRole('article', { name: 'Invitation review' })).not.toBeInTheDocument();
    expect(localStorage.getItem(storageKey)).toBe(original);
    expect(fetcher).toHaveBeenCalledTimes(1);
    failed = false;
    await userEvent.setup().click(screen.getByRole('button', { name: 'Refresh invitations' }));
    expect(await screen.findByRole('article', { name: 'Invitation review' })).toBeVisible();
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    expect(localStorage.getItem(storageKey)).toBe(original);
    expect(fetcher.mock.calls.every(([, init]) => init?.method === undefined)).toBe(true);
    expect(performWebAuthnStepUp).not.toHaveBeenCalled();
  },
);
it.each(['denial', 'conflict', 'transport', 'parse', 'unknown'])(
  'redacts a current invitation detail %s without read-as-mutation or lost custody',
  async (failure) => {
    localStorage.setItem(storageKey, JSON.stringify({ actor, value: savedReview() }));
    const original = localStorage.getItem(storageKey);
    const fetcher = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      if (String(input).includes('invitationId=')) return failedInvitationResponse(failure);
      return Response.json(String(input).endsWith('local-session') ? sessionValue() : inventory());
    });
    render(<InvitationWorkflow />);
    await readInvitation();
    expect(await screen.findByRole('alert')).toHaveTextContent(failureMessage(failure, true));
    expect(document.body).not.toHaveTextContent(privateInvitationFailure);
    expect(screen.queryByRole('article', { name: 'Invitation state' })).not.toBeInTheDocument();
    expect(screen.queryByRole('article', { name: 'Invitation review' })).not.toBeInTheDocument();
    expect(localStorage.getItem(storageKey)).toBe(original);
    expect(
      fetcher.mock.calls.filter(([input]) => String(input).includes('invitationId=')),
    ).toHaveLength(1);
    expect(fetcher.mock.calls.every(([, init]) => init?.method === undefined)).toBe(true);
    expect(performWebAuthnStepUp).not.toHaveBeenCalled();
  },
);
it.each(
  ['PREPARE', 'SUBMIT', 'COMMIT', 'APPROVE'].flatMap((command) =>
    ['denial', 'conflict', 'server', 'transport', 'parse', 'unknown'].map((failure) => [
      command,
      failure,
    ]),
  ),
)(
  'redacts invitation %s %s while retaining its original review and exact command',
  async (command, failure) => {
    vi.stubGlobal('crypto', webcrypto);
    const saved =
      command === 'COMMIT' ? { ...savedReview(), approvalRequestId: id(80) } : savedReview();
    localStorage.setItem(storageKey, JSON.stringify({ actor, value: saved }));
    const original = localStorage.getItem(storageKey);
    const fetcher = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      if (init?.method === 'POST') return failedInvitationResponse(failure);
      return Response.json(
        String(input).endsWith('local-session') ? sessionValue() : inventory(actor, [approval()]),
      );
    });
    render(<InvitationWorkflow />);
    await screen.findByRole('article', { name: 'Invitation review' });
    const user = userEvent.setup();
    if (command === 'PREPARE') {
      await user.type(screen.getByLabelText('Recipient name'), 'Reviewed colleague');
      await user.type(screen.getByLabelText('Exact provider account ID'), 'provider-subject');
      await user.type(screen.getByLabelText('Intended role ID'), id(7));
      await user.type(screen.getByLabelText('Independent checker principal ID'), id(6));
      await user.type(
        screen.getByLabelText('Reason', { exact: true }),
        'Invite the independently reviewed colleague.',
      );
    }
    await user.click(
      screen.getByRole('button', {
        name:
          command === 'PREPARE'
            ? 'Prepare invitation'
            : command === 'SUBMIT'
              ? 'Request independent approval'
              : command === 'COMMIT'
                ? 'Commit approved invitation'
                : 'Approve invitation',
      }),
    );
    expect(await screen.findByRole('alert')).toHaveTextContent(failureMessage(failure, false));
    expect(document.body).not.toHaveTextContent(privateInvitationFailure);
    expect(localStorage.getItem(storageKey)).toBe(original);
    expect(screen.queryByLabelText('Invitation link')).not.toBeInTheDocument();
    expect(screen.queryByRole('article', { name: 'Invitation state' })).not.toBeInTheDocument();
    expect(screen.getByRole('status')).toBeEmptyDOMElement();
    const posts = fetcher.mock.calls.filter(([, init]) => init?.method === 'POST');
    expect(posts).toHaveLength(1);
    const body = JSON.parse(String(posts[0]?.[1]?.body));
    if (command === 'PREPARE')
      expect(body).toMatchObject({
        command,
        input: {
          mutation: 'CREATE',
          displayName: 'Reviewed colleague',
          recipientSubject: 'provider-subject',
          intendedRoleId: id(7),
          ttlSeconds: 86400,
        },
        reason: 'Invite the independently reviewed colleague.',
        checkerPrincipalId: id(6),
        expectedSessionId: actor.sessionId,
      });
    else
      expect(body).toEqual(
        command === 'SUBMIT'
          ? { command, reviewToken: saved.reviewToken }
          : command === 'COMMIT'
            ? { command, reviewToken: saved.reviewToken, approvalRequestId: id(80) }
            : {
                command,
                approvalRequestId: id(80),
                candidateDigest: digest,
                expectedRevision: '0',
              },
      );
    expect(performWebAuthnStepUp).toHaveBeenCalledTimes(
      command === 'COMMIT' || command === 'APPROVE' ? 1 : 0,
    );
  },
);
it.each(['COMMIT', 'APPROVE'])(
  'redacts a private %s step-up failure before posting or changing custody',
  async (command) => {
    const saved = { ...savedReview(), approvalRequestId: id(80) };
    localStorage.setItem(storageKey, JSON.stringify({ actor, value: saved }));
    const original = localStorage.getItem(storageKey);
    vi.mocked(performWebAuthnStepUp).mockRejectedValueOnce(new Error(privateInvitationFailure));
    const fetcher = vi
      .spyOn(globalThis, 'fetch')
      .mockImplementation(async (input) =>
        Response.json(
          String(input).endsWith('local-session') ? sessionValue() : inventory(actor, [approval()]),
        ),
      );
    render(<InvitationWorkflow />);
    await userEvent.setup().click(
      await screen.findByRole('button', {
        name: command === 'COMMIT' ? 'Commit approved invitation' : 'Approve invitation',
      }),
    );
    expect(await screen.findByRole('alert')).toHaveTextContent(invitationOperationUnavailable);
    expect(document.body).not.toHaveTextContent(privateInvitationFailure);
    expect(localStorage.getItem(storageKey)).toBe(original);
    expect(fetcher.mock.calls.every(([, init]) => init?.method === undefined)).toBe(true);
    expect(screen.getByRole('status')).toBeEmptyDOMElement();
  },
);
it('keeps the fixed local invitation ID validation without posting or exposing entered data', async () => {
  const fetcher = vi.spyOn(globalThis, 'fetch').mockResolvedValue(Response.json(inventory()));
  render(<InvitationWorkflow />);
  fireEvent.change(await screen.findByLabelText('Invitation ID', { exact: true }), {
    target: { value: privateInvitationFailure },
  });
  await userEvent.setup().click(screen.getByRole('button', { name: 'Read invitation' }));
  expect(await screen.findByRole('alert')).toHaveTextContent(
    'Enter a valid invitation ID to read.',
  );
  expect(document.body).not.toHaveTextContent(privateInvitationFailure);
  expect(fetcher).toHaveBeenCalledTimes(1);
  expect(performWebAuthnStepUp).not.toHaveBeenCalled();
});
it('renders a valid approval, reads current invitation and never turns a read into authority or token issuance', async () => {
  vi.stubGlobal('crypto', webcrypto);
  const random = vi.spyOn(webcrypto, 'getRandomValues');
  const fetcher = vi
    .spyOn(globalThis, 'fetch')
    .mockImplementation(async (url) =>
      Response.json(
        String(url).includes('invitationId=')
          ? { actor, effect: record }
          : String(url).endsWith('local-session')
            ? sessionValue()
            : inventory(actor, [approval()]),
      ),
    );
  render(<InvitationWorkflow />);
  expect(await screen.findByRole('heading', { name: 'REQUESTED invitation' })).toBeVisible();
  await readInvitation();
  const detail = await screen.findByRole('article', { name: 'Invitation state' });
  expect(
    within(detail).getByText('Recipient: Reviewed colleague · provider-subject'),
  ).toBeVisible();
  expect(within(detail).getByText(/No authority granted/u)).toBeVisible();
  expect(screen.queryByLabelText('Invitation link')).not.toBeInTheDocument();
  expect(fetcher.mock.calls.every(([, init]) => !init?.method || init.method === 'GET')).toBe(true);
  expect(performWebAuthnStepUp).not.toHaveBeenCalled();
  expect(random).not.toHaveBeenCalled();
});
it.each(['success', 'failure'] as const)(
  'ignores an obsolete inventory %s after a newer actor page',
  async (outcome) => {
    const old = deferred();
    let reads = 0;
    const next = { ...actor, privacyDomainId: id(40), contextEpoch: '2' };
    vi.spyOn(globalThis, 'fetch').mockImplementation(async () => {
      reads++;
      return reads === 2 ? old.promise : Response.json(inventory(reads > 2 ? next : actor));
    });
    render(<InvitationWorkflow />);
    await screen.findByLabelText('Reason', { exact: true });
    await focus();
    await focus();
    await screen.findByText(new RegExp(`Privacy domain: ${id(40)}`));
    await act(async () => {
      if (outcome === 'success') old.resolve(Response.json(inventory()));
      else old.reject(new Error('obsolete inventory error'));
    });
    expect(screen.getByText(new RegExp(`Privacy domain: ${id(40)}`))).toBeVisible();
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  },
);
it('does not resurrect a private page from an old success after current denial', async () => {
  const old = deferred();
  let reads = 0;
  vi.spyOn(globalThis, 'fetch').mockImplementation(async () => {
    reads++;
    return reads === 2
      ? old.promise
      : reads === 3
        ? Response.json({ title: 'Current invitation denial' }, { status: 403 })
        : Response.json(inventory());
  });
  render(<InvitationWorkflow />);
  await screen.findByLabelText('Reason', { exact: true });
  await focus();
  await focus();
  await screen.findByText(
    'The invitation request was not authorized. Refresh the authenticated context before continuing.',
  );
  await act(async () => old.resolve(Response.json(inventory())));
  expect(screen.queryByLabelText('Reason', { exact: true })).not.toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Refresh invitations' })).toBeVisible();
});
it.each(['denial', 'malformed', 'unreadable', 'transport'] as const)(
  'purges visible readback and original review on current %s while preserving stored intent and GET retry',
  async (mode) => {
    const original = JSON.stringify({ actor, value: savedReview() });
    localStorage.setItem(storageKey, original);
    let failed = false;
    const fetcher = vi.spyOn(globalThis, 'fetch').mockImplementation(async (url) => {
      if (String(url).endsWith('local-session')) return Response.json(sessionValue());
      if (String(url).includes('invitationId=')) return Response.json({ actor, effect: record });
      if (failed) {
        if (mode === 'denial')
          return Response.json({ title: 'Invitation read denied' }, { status: 403 });
        if (mode === 'malformed')
          return Response.json({
            ...inventory(),
            approvals: [{ privateField: 'must not display' }],
          });
        if (mode === 'unreadable') return new Response('not-json', { status: 200 });
        throw new Error('Invitation read unavailable');
      }
      return Response.json(inventory());
    });
    render(<InvitationWorkflow />);
    await screen.findByRole('article', { name: 'Invitation review' });
    await readInvitation();
    await screen.findByRole('article', { name: 'Invitation state' });
    failed = true;
    await userEvent
      .setup()
      .click(screen.getByRole('button', { name: 'Refresh invitation approvals' }));
    await screen.findByRole('button', { name: 'Refresh invitations' });
    expect(screen.queryByRole('article', { name: 'Invitation review' })).not.toBeInTheDocument();
    expect(screen.queryByRole('article', { name: 'Invitation state' })).not.toBeInTheDocument();
    expect(screen.queryByLabelText('Invitation link')).not.toBeInTheDocument();
    expect(screen.getByRole('alert')).not.toHaveTextContent('must not display');
    expect(localStorage.getItem(storageKey)).toBe(original);
    failed = false;
    await userEvent.setup().click(screen.getByRole('button', { name: 'Refresh invitations' }));
    expect(await screen.findByRole('article', { name: 'Invitation review' })).toBeVisible();
    expect(localStorage.getItem(storageKey)).toBe(original);
    expect(fetcher.mock.calls.every(([, init]) => !init?.method || init.method === 'GET')).toBe(
      true,
    );
    expect(performWebAuthnStepUp).not.toHaveBeenCalled();
  },
);
it('uses the current approval lane for focus and discards its old cursor and page', async () => {
  const queries: URLSearchParams[] = [];
  vi.spyOn(globalThis, 'fetch').mockImplementation(async (url) => {
    const query = new URL(String(url), 'http://localhost').searchParams;
    queries.push(query);
    return Response.json(
      inventory(
        actor,
        [approval(query.get('lane') === 'maker' ? 'Maker page' : 'Checker page')],
        query.get('lane') === 'checker' ? 'checker-original-cursor' : null,
      ),
    );
  });
  render(<InvitationWorkflow />);
  await screen.findByText('Name: Checker page');
  const user = userEvent.setup();
  await user.selectOptions(screen.getByLabelText('Approval lane'), 'maker');
  expect(screen.queryByText('Name: Checker page')).not.toBeInTheDocument();
  expect(screen.queryByRole('button', { name: 'Next approval page' })).not.toBeInTheDocument();
  expect(screen.queryByText('No invitations on this approval page.')).not.toBeInTheDocument();
  await focus();
  expect(await screen.findByText('Name: Maker page')).toBeVisible();
  expect(queries.map((q) => [q.get('lane'), q.get('cursor')])).toEqual([
    ['checker', null],
    ['maker', null],
  ]);
});
it('does not render a pending old lane page or its cursor after selection changes', async () => {
  const old = deferred();
  let reads = 0;
  vi.spyOn(globalThis, 'fetch').mockImplementation(async () =>
    ++reads === 2 ? old.promise : Response.json(inventory()),
  );
  render(<InvitationWorkflow />);
  await screen.findByLabelText('Approval lane');
  await userEvent
    .setup()
    .click(screen.getByRole('button', { name: 'Refresh invitation approvals' }));
  await userEvent.setup().selectOptions(screen.getByLabelText('Approval lane'), 'maker');
  await act(async () =>
    old.resolve(Response.json(inventory(actor, [approval('Obsolete lane')], 'obsolete-cursor'))),
  );
  expect(screen.queryByText('Name: Obsolete lane')).not.toBeInTheDocument();
  expect(screen.queryByRole('button', { name: 'Next approval page' })).not.toBeInTheDocument();
  expect(screen.getByLabelText('Approval lane')).toHaveValue('maker');
});
it.each(['success', 'failure'] as const)(
  'does not let a pending old invitation %s start a session read or clear a newer read',
  async (outcome) => {
    const old = deferred(),
      latest = deferred();
    let details = 0;
    let sessions = 0;
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (url) => {
      if (String(url).endsWith('local-session')) {
        sessions++;
        return Response.json(sessionValue());
      }
      if (String(url).includes('invitationId='))
        return ++details === 1 ? old.promise : latest.promise;
      return Response.json(inventory());
    });
    render(<InvitationWorkflow />);
    await readInvitation();
    await waitFor(() => expect(details).toBe(1));
    await readInvitation(id(51));
    await waitFor(() => expect(details).toBe(2));
    await act(async () => {
      if (outcome === 'success') old.resolve(Response.json({ actor, effect: record }));
      else old.reject(new Error('obsolete detail failure'));
    });
    expect(sessions).toBe(0);
    expect(screen.getByRole('button', { name: 'Read invitation' })).toBeDisabled();
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    await act(async () =>
      latest.resolve(
        Response.json({
          actor,
          effect: { ...record, invitationId: id(51), displayName: 'Latest colleague' },
        }),
      ),
    );
    const detail = await screen.findByRole('article', { name: 'Invitation state' });
    expect(
      within(detail).getByText('Recipient: Latest colleague · provider-subject'),
    ).toBeVisible();
  },
);
it('hides current detail immediately when its lookup changes', async () => {
  vi.spyOn(globalThis, 'fetch').mockImplementation(async (url) =>
    Response.json(
      String(url).endsWith('local-session')
        ? sessionValue()
        : String(url).includes('invitationId=')
          ? { actor, effect: record }
          : inventory(),
    ),
  );
  render(<InvitationWorkflow />);
  await readInvitation();
  await screen.findByRole('article', { name: 'Invitation state' });
  fireEvent.change(screen.getByLabelText('Invitation ID', { exact: true }), {
    target: { value: id(51) },
  });
  expect(screen.queryByRole('article', { name: 'Invitation state' })).not.toBeInTheDocument();
});
it.each([
  { invitationId: id(99) },
  { participantId: id(99) },
  { privacyDomainId: id(99) },
  { roleIntent: { roleId: id(7), authorityGranted: true } },
  { state: 'ACCEPTED' },
  { expiresAt: 'private-invalid-date' },
])('rejects mismatched or malformed invitation readback: %o', async (change) => {
  vi.spyOn(globalThis, 'fetch').mockImplementation(async (url) =>
    Response.json(
      String(url).endsWith('local-session')
        ? sessionValue()
        : String(url).includes('invitationId=')
          ? { actor, effect: { ...record, ...change } }
          : inventory(),
    ),
  );
  render(<InvitationWorkflow />);
  await readInvitation();
  await waitFor(() =>
    expect(screen.getByRole('alert')).toHaveTextContent(/invalid|does not match/u),
  );
  expect(screen.queryByRole('article', { name: 'Invitation state' })).not.toBeInTheDocument();
  expect(screen.getByRole('alert')).not.toHaveTextContent('private-invalid-date');
});
it('rejects readback when the authoritative after-session context has changed', async () => {
  vi.spyOn(globalThis, 'fetch').mockImplementation(async (url) =>
    Response.json(
      String(url).endsWith('local-session')
        ? sessionValue({ ...actor, contextEpoch: '2' })
        : String(url).includes('invitationId=')
          ? { actor, effect: record }
          : inventory(),
    ),
  );
  render(<InvitationWorkflow />);
  await readInvitation();
  await screen.findByText('The session or context changed. Refresh before continuing.');
  expect(screen.queryByRole('article', { name: 'Invitation state' })).not.toBeInTheDocument();
});
it('fences a stale inventory JSON body before actor adoption', async () => {
  const body = deferred<unknown>();
  const delayed = Response.json({});
  vi.spyOn(delayed, 'json').mockReturnValue(body.promise);
  let reads = 0;
  const next = { ...actor, privacyDomainId: id(40), contextEpoch: '2' };
  vi.spyOn(globalThis, 'fetch').mockImplementation(async () =>
    ++reads === 2 ? delayed : Response.json(inventory(reads > 2 ? next : actor)),
  );
  render(<InvitationWorkflow />);
  await screen.findByLabelText('Approval lane');
  await focus();
  await waitFor(() => expect(delayed.json).toHaveBeenCalled());
  await focus();
  await screen.findByText(new RegExp(`Privacy domain: ${id(40)}`));
  await act(async () => body.resolve(inventory()));
  expect(screen.getByText(new RegExp(`Privacy domain: ${id(40)}`))).toBeVisible();
});
it('discards old lookup and cursor on authoritative actor change without posting', async () => {
  let changed = false;
  const queries: URLSearchParams[] = [];
  const next = { ...actor, privacyDomainId: id(40), contextEpoch: '2' };
  const fetcher = vi.spyOn(globalThis, 'fetch').mockImplementation(async (url) => {
    const query = new URL(String(url), 'http://localhost').searchParams;
    queries.push(query);
    return Response.json(
      inventory(changed ? next : actor, [], changed ? null : 'old-actor-cursor'),
    );
  });
  render(<InvitationWorkflow />);
  await screen.findByLabelText('Invitation ID', { exact: true });
  fireEvent.change(screen.getByLabelText('Invitation ID', { exact: true }), {
    target: { value: id(50) },
  });
  changed = true;
  await focus();
  await screen.findByText(new RegExp(`Privacy domain: ${id(40)}`));
  expect(screen.getByLabelText('Invitation ID', { exact: true })).toHaveValue('');
  expect(screen.queryByRole('button', { name: 'Next approval page' })).not.toBeInTheDocument();
  await userEvent
    .setup()
    .click(screen.getByRole('button', { name: 'Refresh invitation approvals' }));
  await waitFor(() => expect(queries).toHaveLength(3));
  expect(queries.every((q) => q.get('cursor') === null)).toBe(true);
  expect(fetcher.mock.calls.every(([, init]) => !init?.method || init.method === 'GET')).toBe(true);
});
it('reads a compatible next approval page with its exact original cursor', async () => {
  const queries: URLSearchParams[] = [];
  vi.spyOn(globalThis, 'fetch').mockImplementation(async (url) => {
    const query = new URL(String(url), 'http://localhost').searchParams;
    queries.push(query);
    return Response.json(
      inventory(actor, [], queries.length === 1 ? 'opaque-original-cursor' : null),
    );
  });
  render(<InvitationWorkflow />);
  await userEvent.setup().click(await screen.findByRole('button', { name: 'Next approval page' }));
  await waitFor(() => expect(queries).toHaveLength(2));
  expect(queries.map((q) => [q.get('lane'), q.get('cursor')])).toEqual([
    ['checker', null],
    ['checker', 'opaque-original-cursor'],
  ]);
});
it('preserves original governed review and secret link while coalescing focus and ignoring an old failure', async () => {
  vi.stubGlobal('crypto', webcrypto);
  const old = deferred(),
    committed = deferred();
  let delayNext = false;
  let inventories = 0;
  let prepared = savedReview();
  const posts: Record<string, unknown>[] = [];
  vi.spyOn(globalThis, 'fetch').mockImplementation(async (url, init) => {
    if (String(url).endsWith('local-session')) return Response.json(sessionValue());
    if (init?.method === 'POST') {
      const body = JSON.parse(String(init.body)) as Record<string, unknown>;
      posts.push(body);
      if (body.command === 'PREPARE') {
        prepared = savedReview({
          ...(body.input as Record<string, unknown>),
          invitationId: id(50),
        });
        return Response.json(prepared);
      }
      if (body.command === 'SUBMIT')
        return Response.json({
          ...prepared,
          approval: { approvalRequestId: `urn:openpc:approval:${id(80)}` },
        });
      if (body.command === 'COMMIT') return committed.promise;
      throw new Error('Unexpected mutation');
    }
    inventories++;
    if (delayNext) {
      delayNext = false;
      return old.promise;
    }
    return Response.json(inventory());
  });
  render(<InvitationWorkflow />);
  const user = userEvent.setup();
  await user.type(await screen.findByLabelText('Recipient name'), 'Reviewed colleague');
  await user.type(screen.getByLabelText('Exact provider account ID'), 'provider-subject');
  await user.type(screen.getByLabelText('Intended role ID'), id(7));
  await user.type(screen.getByLabelText('Independent checker principal ID'), id(6));
  await user.type(
    screen.getByLabelText('Reason', { exact: true }),
    'Invite the independently reviewed colleague.',
  );
  await user.click(screen.getByRole('button', { name: 'Prepare invitation' }));
  await screen.findByRole('article', { name: 'Invitation review' });
  await waitFor(() =>
    expect(screen.getByRole('button', { name: 'Request independent approval' })).toBeEnabled(),
  );
  await user.click(screen.getByRole('button', { name: 'Request independent approval' }));
  const commitButton = await screen.findByRole('button', { name: 'Commit approved invitation' });
  await waitFor(() => expect(commitButton).toBeEnabled());
  const original = localStorage.getItem(storageKey);
  delayNext = true;
  await focus();
  await user.click(commitButton);
  await waitFor(() => expect(posts).toHaveLength(3));
  const before = inventories;
  await focus();
  await focus();
  expect(inventories).toBe(before);
  await act(async () => old.reject(new Error('obsolete background failure')));
  expect(commitButton).toBeDisabled();
  expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  await act(async () =>
    committed.resolve(
      Response.json({
        truthState: 'SUCCESS',
        operationId: record.operationId,
        readback: { effect: record },
      }),
    ),
  );
  const link = await screen.findByLabelText('Invitation link');
  await waitFor(() => expect(inventories).toBe(before + 1));
  const url = new URL((link as HTMLInputElement).value);
  const proof = new URLSearchParams(url.hash.slice(1));
  expect(proof.get('invitationId')).toBe(id(50));
  expect(proof.get('tokenVersion')).toBe('1');
  expect(proof.get('token')).toMatch(/^[A-Za-z0-9_-]{43}$/u);
  const hashed = await webcrypto.subtle.digest(
    'SHA-256',
    new TextEncoder().encode(proof.get('token')!),
  );
  const actualDigest = `sha256:${Array.from(new Uint8Array(hashed), (byte) => byte.toString(16).padStart(2, '0')).join('')}`;
  expect(prepared.review.candidate.change.tokenDigest).toBe(actualDigest);
  expect(localStorage.getItem(storageKey)).toBe(original);
  expect(original).not.toContain(proof.get('token')!);
  expect(posts.map((body) => body.command)).toEqual(['PREPARE', 'SUBMIT', 'COMMIT']);
  expect(posts[0]!.expectedSessionId).toBe(actor.sessionId);
  expect(posts[1]).toEqual({ command: 'SUBMIT', reviewToken: prepared.reviewToken });
  expect(posts[2]).toEqual({
    command: 'COMMIT',
    reviewToken: prepared.reviewToken,
    approvalRequestId: id(80),
  });
  expect(performWebAuthnStepUp).toHaveBeenCalledTimes(1);
  const originalLink = (link as HTMLInputElement).value;
  await focus();
  await waitFor(() => expect(inventories).toBe(before + 2));
  expect(screen.getByLabelText('Invitation link')).toHaveValue(originalLink);
  expect(posts).toHaveLength(3);
});
it('aborts an unmounted detail read before it can issue a session request', async () => {
  const pending = deferred();
  let signal: AbortSignal | null | undefined;
  let sessions = 0;
  vi.spyOn(globalThis, 'fetch').mockImplementation(async (url, init) => {
    if (String(url).endsWith('local-session')) {
      sessions++;
      return Response.json(sessionValue());
    }
    if (String(url).includes('invitationId=')) {
      signal = init?.signal;
      return pending.promise;
    }
    return Response.json(inventory());
  });
  const view = render(<InvitationWorkflow />);
  await readInvitation();
  await waitFor(() => expect(signal).toBeDefined());
  view.unmount();
  expect(signal?.aborted).toBe(true);
  await act(async () => pending.resolve(Response.json({ actor, effect: record })));
  expect(sessions).toBe(0);
});

it.each(['sessionId', 'principalId', 'participantId', 'privacyDomainId', 'contextEpoch'] as const)(
  'rejects a foreign detail response actor in %s',
  async (field) => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (url) =>
      Response.json(
        String(url).endsWith('local-session')
          ? sessionValue()
          : String(url).includes('invitationId=')
            ? {
                actor: { ...actor, [field]: field === 'contextEpoch' ? '2' : id(99) },
                effect: record,
              }
            : inventory(),
      ),
    );
    render(<InvitationWorkflow />);
    await readInvitation();
    await screen.findByText('Readback does not match this context.');
    expect(screen.queryByRole('article', { name: 'Invitation state' })).not.toBeInTheDocument();
  },
);
it('removes old detail and review after a current detail denial without deleting the original stored review', async () => {
  const original = JSON.stringify({ actor, value: savedReview() });
  localStorage.setItem(storageKey, original);
  let denied = false;
  vi.spyOn(globalThis, 'fetch').mockImplementation(async (url) => {
    if (String(url).endsWith('local-session')) return Response.json(sessionValue());
    if (String(url).includes('invitationId='))
      return denied
        ? Response.json({ title: 'Invitation detail denied' }, { status: 403 })
        : Response.json({ actor, effect: record });
    return Response.json(inventory());
  });
  render(<InvitationWorkflow />);
  await readInvitation();
  await screen.findByRole('article', { name: 'Invitation state' });
  denied = true;
  await userEvent.setup().click(screen.getByRole('button', { name: 'Read invitation' }));
  await screen.findByText(
    'The invitation request was not authorized. Refresh the authenticated context before continuing.',
  );
  expect(screen.queryByRole('article', { name: 'Invitation state' })).not.toBeInTheDocument();
  expect(screen.queryByRole('article', { name: 'Invitation review' })).not.toBeInTheDocument();
  expect(localStorage.getItem(storageKey)).toBe(original);
});
it('renders accepted membership readback without claiming role authority or repeating acceptance', async () => {
  const fetcher = vi.spyOn(globalThis, 'fetch').mockImplementation(async (url) =>
    Response.json(
      String(url).endsWith('local-session')
        ? sessionValue()
        : String(url).includes('invitationId=')
          ? {
              actor,
              effect: {
                ...record,
                state: 'ACCEPTED',
                acceptance: { membershipId: id(70), acceptedAt: instant },
              },
            }
          : inventory(),
    ),
  );
  render(<InvitationWorkflow />);
  await readInvitation();
  const detail = await screen.findByRole('article', { name: 'Invitation state' });
  expect(within(detail).getByText(`Accepted membership: ${id(70)}`)).toBeVisible();
  expect(within(detail).getByText(/No authority granted/u)).toBeVisible();
  expect(
    within(detail).getByRole('link', { name: 'Manage membership activation' }),
  ).toHaveAttribute('href', '/govern/memberships?view=principals');
  expect(fetcher.mock.calls.every(([, init]) => !init?.method || init.method === 'GET')).toBe(true);
});

it('does not let an obsolete after-session denial clear a newer invitation projection', async () => {
  const oldSession = deferred();
  let sessions = 0;
  vi.spyOn(globalThis, 'fetch').mockImplementation(async (url) => {
    if (String(url).endsWith('local-session'))
      return ++sessions === 1 ? oldSession.promise : Response.json(sessionValue());
    if (String(url).includes('invitationId=')) {
      const target = new URL(String(url), 'http://localhost').searchParams.get('invitationId');
      return Response.json({
        actor,
        effect: {
          ...record,
          invitationId: target,
          displayName: target === id(51) ? 'Latest colleague' : 'Old colleague',
        },
      });
    }
    return Response.json(inventory());
  });
  render(<InvitationWorkflow />);
  await readInvitation();
  await waitFor(() => expect(sessions).toBe(1));
  await readInvitation(id(51));
  const detail = await screen.findByRole('article', { name: 'Invitation state' });
  expect(within(detail).getByText('Recipient: Latest colleague · provider-subject')).toBeVisible();
  await act(async () =>
    oldSession.resolve(Response.json({ authenticated: false, contextMode: 'GLOBAL' })),
  );
  expect(screen.getByRole('article', { name: 'Invitation state' })).toBeVisible();
  expect(screen.queryByRole('alert')).not.toBeInTheDocument();
});
