import { StrictMode } from 'react';
import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, expect, it, vi } from 'vitest';
import { performWebAuthnStepUp } from '@openpc/ui-shell';
import { ParticipantRoleWorkflow } from './participant-role-workflow';
vi.mock('@openpc/ui-shell', async () => {
  const actual = await vi.importActual<typeof import('@openpc/ui-shell')>('@openpc/ui-shell');
  return { ...actual, performWebAuthnStepUp: vi.fn(async () => undefined) };
});
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
const roleId = '018f0000-0000-7000-8000-000000000891';
const secondId = '018f0000-0000-7000-8000-000000000892';
const session = { ...actor, authenticated: true, contextMode: 'PARTICIPANT' };
const state = { actor: { ...actor, role: 'operator' }, approvals: [], nextCursor: null };
const record = {
  id: roleId,
  participantId: actor.participantId,
  roleId: `urn:openpc:role:${roleId}`,
  displayName: 'Readback first',
  actionIntentIds: [],
  state: 'ACTIVE',
  revision: '1',
  origin: 'GOVERNED',
};
function selectedState(id = roleId, name = 'Readback first') {
  return {
    ...state,
    actor: { ...state.actor },
    effect: {
      effect: { ...record, id, roleId: `urn:openpc:role:${id}`, displayName: name },
      operationId: roleId,
    },
  };
}
function catalogue(bound = actor) {
  return {
    actor: bound,
    items: [
      { effect: { ...record, participantId: bound.participantId, displayName: 'Catalogue first' } },
      {
        effect: {
          ...record,
          participantId: bound.participantId,
          id: secondId,
          roleId: `urn:openpc:role:${secondId}`,
          displayName: 'Catalogue second',
        },
      },
    ],
    observedAt: '2026-09-14T00:00:00Z',
    nextCursor: null,
    authorizedEmpty: false,
  };
}
function deferredResponse() {
  let resolve!: (value: Response) => void;
  let reject!: (cause: Error) => void;
  const promise = new Promise<Response>((accept, fail) => {
    resolve = accept;
    reject = fail;
  });
  return { promise, resolve, reject };
}
function isSession(input: RequestInfo | URL) {
  return String(input) === '/api/v1/ui/local-session';
}
function isCatalogue(input: RequestInfo | URL) {
  return String(input).startsWith('/api/v1/ui/role-catalogue?');
}
function savedReview() {
  return {
    reviewToken: 'sealed-review-'.padEnd(80, 'x'),
    review: {
      mutation: 'CREATE',
      expectedRevision: '0',
      candidateDigest: `sha256:${'b'.repeat(64)}`,
      reason: 'Private maker-only proposal.',
      proposedRole: {
        id: roleId,
        participantId: actor.participantId,
        roleId: `urn:openpc:role:${roleId}`,
        displayName: 'Private draft role',
        actionIntentIds: [] as string[],
        state: 'ACTIVE',
      },
      stepUp: {
        actionIntentId: 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
        actionIntentDigest:
          'sha256:bec5bb71e10db36e744f98a55dd6b54a0c42f9f55b73ac322a1de6e8592fd529',
        resourceId: roleId,
        resourceDigest: `sha256:${'b'.repeat(64)}`,
      },
    },
  };
}
afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  localStorage.clear();
  vi.clearAllMocks();
  vi.mocked(performWebAuthnStepUp).mockReset().mockResolvedValue(undefined);
});

const privateFailure = 'PRIVATE_ROLE_ERROR cookie=secret-token sql=SELECT key custody=sealed';
const unauthorizedFailure =
  'The role request was not authorized. Refresh the authenticated context before continuing.';
const malformedFailure = 'The role response could not be confirmed. Refresh before continuing.';
const requestFailure = 'The role request could not be completed. Refresh before retrying.';

function approvalFor(review = savedReview(), phase = 'REQUESTED') {
  return {
    approvalRequestId: 'urn:openpc:resource:018f0000-0000-7000-8000-000000000801',
    actionIntentId: 'ACT-APPROVAL_REQUESTS_CREATE_RESOURCE-V1',
    candidateDigest: review.review.candidateDigest,
    state: phase,
    makerSubjectRef: `urn:openpc:resource:${actor.principalId}`,
    checkerSubjectRef: 'urn:openpc:resource:018f0000-0000-7000-8000-000000000112',
    revision: '1',
    createdAt: '2026-09-14T00:00:00Z',
    updatedAt: '2026-09-14T00:00:00Z',
    proposal: {
      ...review.review,
      resourceId: review.review.proposedRole.id,
      state: phase === 'APPROVED' ? 'APPROVED' : 'PROPOSED',
      expiresAt: new Date(Date.now() + 600000).toISOString(),
      consumption: null,
    },
    stepUp: review.review.stepUp,
  };
}
function approvalOperation() {
  return {
    operationId: '018f0000-0000-7000-8000-000000000802',
    actionIntentId: 'ACT-POLICY_APPROVE_REQUEST-V1',
    intentDigest: `sha256:${'a'.repeat(64)}`,
    idempotencyKey: 'workbench-approve-018f0000-0000-7000-8000-000000000801',
    resourceRef: approvalFor().approvalRequestId,
    revision: '1',
    state: 'SUCCEEDED',
    truthState: 'SUCCESS',
    createdAt: '2026-09-14T00:00:00Z',
    updatedAt: '2026-09-14T00:00:00Z',
  };
}
function approvedWorkbench(review = savedReview()) {
  return {
    ...state,
    approvals: [approvalFor(review, 'APPROVED')],
    ...(review.review.mutation === 'ARCHIVE'
      ? {
          effect: {
            effect: {
              ...review.review.proposedRole,
              state: 'ACTIVE',
              revision: review.review.expectedRevision,
              origin: 'GOVERNED',
            },
            operationId: roleId,
          },
        }
      : {}),
  };
}

function consumedApproval(review: ReturnType<typeof savedReview>, revision = '1') {
  const value = approvalFor(review, 'APPROVED');
  return {
    ...value,
    proposal: {
      ...value.proposal,
      state: 'CONSUMED',
      consumption: {
        operationId: '018f0000-0000-7000-8000-000000000802',
        effect: { ...review.review.proposedRole, revision, origin: 'GOVERNED' },
      },
    },
  };
}

it.each([
  ['CREATE', 'lost'],
  ['CREATE', 'malformed'],
  ['CREATE', 'ambiguity'],
  ['ARCHIVE', 'lost'],
  ['ARCHIVE', 'malformed'],
  ['ARCHIVE', 'ambiguity'],
] as const)(
  'recovers the cold original consumed %s after %s through its receipt and current role without another COMMIT',
  async (mutation, failure) => {
    const base = savedReview();
    const review = {
      ...base,
      approvalRequestId: approvalFor().approvalRequestId.slice(-36),
      review: {
        ...base.review,
        mutation,
        expectedRevision: mutation === 'CREATE' ? '0' : '1',
        proposedRole: {
          ...base.review.proposedRole,
          state: mutation === 'CREATE' ? 'ACTIVE' : 'ARCHIVED',
        },
      },
    };
    const stored = JSON.stringify({ actor, value: review });
    localStorage.setItem('openpc:role-workflow:v1', stored);
    let consumed = false;
    const currentRole = {
      ...review.review.proposedRole,
      state: consumed ? 'ARCHIVED' : 'ACTIVE',
      revision: '1',
      origin: 'GOVERNED',
    };
    const fetch = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      if (init?.method === 'POST') {
        consumed = true;
        if (failure === 'lost') throw new TypeError('PRIVATE lost original commit');
        return Response.json(failure === 'ambiguity' ? commitFor(review, true) : {}, {
          status: 202,
        });
      }
      if (isSession(input)) return Response.json(session);
      if (isCatalogue(input)) return Response.json(catalogue());
      return Response.json({
        ...state,
        approvals: [
          consumed
            ? consumedApproval(review, mutation === 'CREATE' ? '1' : '2')
            : approvalFor(review, 'APPROVED'),
        ],
        ...(String(input).includes(`roleId=${roleId}`)
          ? {
              effect: {
                effect: {
                  ...currentRole,
                  state: consumed ? 'ARCHIVED' : 'ACTIVE',
                  revision: consumed ? '2' : '1',
                },
                // A later/current operation is not used to identify the original receipt.
                operationId: secondId,
              },
            }
          : {}),
      });
    });
    const view = render(<ParticipantRoleWorkflow />);
    await userEvent
      .setup()
      .click(await screen.findByRole('button', { name: 'Commit approved role change' }));
    await screen.findByText(
      failure === 'lost'
        ? requestFailure
        : failure === 'ambiguity'
          ? 'The response was lost. Sign in again and read the role before retrying.'
          : 'The role change response could not be confirmed. Read the authoritative role before retrying.',
    );
    expect(localStorage.getItem('openpc:role-workflow:v1')).toBe(stored);
    view.unmount();
    render(<ParticipantRoleWorkflow />);
    const read = await screen.findByRole('button', { name: 'Read original role outcome' });
    expect(screen.queryByRole('button', { name: 'Commit approved role change' })).toBeNull();
    await userEvent.setup().click(read);
    await screen.findByText(
      'The original role change was committed. Its current role was read separately.',
    );
    expect(screen.getByRole('heading', { name: 'Role details' })).toBeVisible();
    expect(screen.queryByRole('button', { name: 'Commit approved role change' })).toBeNull();
    expect(fetch.mock.calls.filter(([, init]) => init?.method === 'POST')).toHaveLength(1);
    expect(performWebAuthnStepUp).toHaveBeenCalledOnce();
    expect(localStorage.getItem('openpc:role-workflow:v1')).toBe(stored);
    expect(document.body.textContent).not.toContain('PRIVATE');
  },
);

it.each([
  'unknown',
  'null receipt',
  'foreign receipt',
  'foreign digest',
  'expired pending',
  'denied',
  'session drift',
  'current role denial',
  'stale current role',
  'foreign current Participant',
  'invalid original',
])(
  'keeps the cold original read-only after %s without replay or replacing its bytes',
  async (defect) => {
    const review = {
      ...savedReview(),
      approvalRequestId: approvalFor().approvalRequestId.slice(-36),
    };
    if (defect === 'invalid original') review.review.expectedRevision = '01';
    const stored = JSON.stringify({ actor, value: review });
    localStorage.setItem('openpc:role-workflow:v1', stored);
    let reading = false;
    let ownerRead = false;
    const approval = consumedApproval(review);
    if (defect === 'unknown') approval.proposal.state = 'CANCELLED';
    if (defect === 'null receipt') {
      // Exercise the actual JSON boundary, not TypeScript's non-null fixture type.
      Reflect.set(approval.proposal, 'consumption', null);
    }
    if (defect === 'foreign receipt') approval.proposal.consumption.effect.id = secondId;
    if (defect === 'foreign digest') approval.proposal.candidateDigest = `sha256:${'f'.repeat(64)}`;
    if (defect === 'expired pending') {
      approval.proposal.state = 'APPROVED';
      approval.proposal.expiresAt = new Date(Date.now() - 1).toISOString();
      Reflect.set(approval.proposal, 'consumption', null);
    }
    const fetch = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      if (isSession(input))
        return Response.json(
          reading && ownerRead && defect === 'session drift'
            ? { ...session, sessionId: secondId }
            : session,
        );
      if (isCatalogue(input)) return Response.json(catalogue());
      if (reading && defect === 'denied')
        return Response.json({ code: 'PC-AUTH-0005' }, { status: 403 });
      if (reading && defect === 'current role denial' && String(input).includes('roleId='))
        return Response.json({ code: 'PC-AUTH-0005' }, { status: 403 });
      if (reading) ownerRead = true;
      return Response.json({
        ...state,
        approvals: [approval],
        ...(String(input).includes(`roleId=${roleId}`)
          ? {
              effect: {
                effect: {
                  ...review.review.proposedRole,
                  participantId:
                    defect === 'foreign current Participant' ? secondId : actor.participantId,
                  revision: defect === 'stale current role' ? '0' : '1',
                  origin: 'GOVERNED',
                },
                operationId: roleId,
              },
            }
          : {}),
      });
    });
    render(<ParticipantRoleWorkflow />);
    const read = await screen.findByRole('button', { name: 'Read original role outcome' });
    reading = true;
    await userEvent.setup().click(read);
    await waitFor(() =>
      expect(screen.getByRole('button', { name: 'Read original role outcome' })).toBeEnabled(),
    );
    expect(screen.queryByRole('button', { name: 'Commit approved role change' })).toBeNull();
    expect(
      screen.queryByText(
        'The original role change was committed. Its current role was read separately.',
      ),
    ).toBeNull();
    expect(localStorage.getItem('openpc:role-workflow:v1')).toBe(stored);
    expect(fetch.mock.calls.every(([, init]) => init?.method !== 'POST')).toBe(true);
    expect(performWebAuthnStepUp).not.toHaveBeenCalled();
  },
);

it.each(['input', 'unmount'] as const)(
  'retires a held cold original current-role read after %s without replay or lost custody',
  async (retirement) => {
    const review = {
      ...savedReview(),
      approvalRequestId: approvalFor().approvalRequestId.slice(-36),
    };
    const stored = JSON.stringify({ actor, value: review });
    localStorage.setItem('openpc:role-workflow:v1', stored);
    const pending = deferredResponse();
    const fetch = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      if (isSession(input)) return Response.json(session);
      if (isCatalogue(input)) return Response.json(catalogue());
      if (String(input).includes('roleId=')) return pending.promise;
      return Response.json({ ...state, approvals: [consumedApproval(review)] });
    });
    const view = render(<ParticipantRoleWorkflow />);
    fireEvent.click(await screen.findByRole('button', { name: 'Read original role outcome' }));
    await waitFor(() =>
      expect(fetch.mock.calls.some(([url]) => String(url).includes('roleId='))).toBe(true),
    );
    const signal = fetch.mock.calls
      .filter(([url]) => String(url).includes('roleId='))
      .at(-1)?.[1]?.signal;
    if (retirement === 'input')
      fireEvent.change(screen.getByLabelText('Authority role ID'), { target: { value: secondId } });
    else view.unmount();
    expect(signal?.aborted).toBe(true);
    await act(async () =>
      pending.resolve(
        Response.json({
          ...state,
          approvals: [consumedApproval(review)],
          effect: {
            effect: { ...review.review.proposedRole, revision: '1', origin: 'GOVERNED' },
            operationId: roleId,
          },
        }),
      ),
    );
    expect(
      screen.queryByText(
        'The original role change was committed. Its current role was read separately.',
      ),
    ).toBeNull();
    expect(screen.queryByRole('button', { name: 'Commit approved role change' })).toBeNull();
    expect(localStorage.getItem('openpc:role-workflow:v1')).toBe(stored);
    expect(fetch.mock.calls.every(([, init]) => init?.method !== 'POST')).toBe(true);
    expect(fetch.mock.calls.some(([url]) => String(url).includes(`roleId=${secondId}`))).toBe(
      false,
    );
    expect(performWebAuthnStepUp).not.toHaveBeenCalled();
  },
);

it('releases cold read custody only after the complete original fresh approved unconsumed proposal is read', async () => {
  const review = {
    ...savedReview(),
    approvalRequestId: approvalFor().approvalRequestId.slice(-36),
  };
  const stored = JSON.stringify({ actor, value: review });
  localStorage.setItem('openpc:role-workflow:v1', stored);
  let approved = false;
  const fetch = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
    if (isSession(input)) return Response.json(session);
    if (isCatalogue(input)) return Response.json(catalogue());
    const value = approvalFor(review, 'APPROVED');
    if (!approved) value.proposal.state = 'PROPOSED';
    return Response.json({ ...state, approvals: [value] });
  });
  render(<ParticipantRoleWorkflow />);
  const read = await screen.findByRole('button', { name: 'Read original role outcome' });
  expect(screen.queryByRole('button', { name: 'Commit approved role change' })).toBeNull();
  approved = true;
  await userEvent.setup().click(read);
  await screen.findByText(
    'The original role proposal is unconsumed. A fresh proof is required to commit it.',
  );
  expect(screen.getByRole('button', { name: 'Commit approved role change' })).toBeEnabled();
  expect(localStorage.getItem('openpc:role-workflow:v1')).toBe(stored);
  expect(fetch.mock.calls.every(([, init]) => init?.method !== 'POST')).toBe(true);
  expect(performWebAuthnStepUp).not.toHaveBeenCalled();
});
function commitFor(review = savedReview(), ambiguity = false) {
  if (ambiguity)
    return {
      truthState: 'WRITE_AMBIGUITY',
      roleId: review.review.proposedRole.id,
      reconciliation: 'READ_AUTHORITATIVE_EFFECT',
    };
  const effect = {
    ...review.review.proposedRole,
    revision: review.review.mutation === 'ARCHIVE' ? '2' : '1',
    origin: 'GOVERNED',
  };
  return review.review.mutation === 'ARCHIVE'
    ? {
        truthState: 'SUCCESS',
        effect,
        newEpoch: '3',
        revokedAssignments: 1,
        reauthenticationRequired: true,
        reconciliation: 'READ_AFTER_REAUTHENTICATION',
      }
    : { truthState: 'SUCCESS', effect, operationId: roleId };
}

it.each(['CREATE', 'ARCHIVE'])(
  'preserves the accepted %s preview and its original public arguments',
  async (mutation) => {
    const original = savedReview();
    const preview = {
      ...original,
      review: {
        ...original.review,
        mutation,
        expectedRevision: mutation === 'ARCHIVE' ? '1' : '0',
        reason: 'Review the requested role change.',
        proposedRole: {
          ...original.review.proposedRole,
          displayName: mutation === 'ARCHIVE' ? record.displayName : 'Requested new role',
          actionIntentIds:
            mutation === 'ARCHIVE'
              ? record.actionIntentIds
              : ['ACT-A_READ_RESOURCE-V1', 'ACT-Z_READ_RESOURCE-V1'],
          state: mutation === 'ARCHIVE' ? 'ARCHIVED' : 'ACTIVE',
        },
      },
    };
    const fetch = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      if (init?.method === 'POST') return Response.json(preview, { status: 201 });
      if (isSession(input)) return Response.json(session);
      if (isCatalogue(input)) return Response.json(catalogue());
      return Response.json(String(input).includes('roleId=') ? selectedState() : state);
    });
    const user = userEvent.setup();
    render(<ParticipantRoleWorkflow />);
    await screen.findByRole('heading', { name: 'Participant roles' });
    if (mutation === 'ARCHIVE') {
      await user.click(
        await screen.findByRole('button', { name: 'View details for Catalogue first' }),
      );
      await screen.findByText('Readback first');
      await user.type(screen.getByLabelText('Archive reason'), preview.review.reason);
      await user.click(screen.getByRole('button', { name: 'Review role archival' }));
    } else {
      await user.type(
        screen.getByLabelText('Role name'),
        `  ${preview.review.proposedRole.displayName}  `,
      );
      await user.type(screen.getByLabelText('Reason'), `  ${preview.review.reason}  `);
      await user.type(
        screen.getByLabelText('Administrative action IDs'),
        'ACT-Z_READ_RESOURCE-V1\nACT-A_READ_RESOURCE-V1',
      );
      await user.click(screen.getByRole('button', { name: 'Review role creation' }));
    }
    await screen.findByText('Review the exact role change before requesting approval.');
    expect(screen.getByRole('region', { name: 'Role change review' })).toBeVisible();
    expect(JSON.parse(localStorage.getItem('openpc:role-workflow:v1') ?? 'null')).toEqual({
      actor,
      value: preview,
    });
    const posts = fetch.mock.calls.filter(([, init]) => init?.method === 'POST');
    expect(posts).toHaveLength(1);
    expect(JSON.parse(String(posts[0]?.[1]?.body))).toEqual(
      mutation === 'ARCHIVE'
        ? {
            command: 'PREVIEW_ARCHIVE',
            roleId,
            reason: preview.review.reason,
          }
        : {
            command: 'PREVIEW_CREATE',
            displayName: `  ${preview.review.proposedRole.displayName}  `,
            reason: `  ${preview.review.reason}  `,
            actionIntentIds: ['ACT-Z_READ_RESOURCE-V1', 'ACT-A_READ_RESOURCE-V1'],
          },
    );
    expect(performWebAuthnStepUp).not.toHaveBeenCalled();
  },
);

it.each([
  'name',
  'reason',
  'actions',
  'mutation',
  'revision',
  'step-up target',
  'step-up digest',
  'role reference',
  'Participant',
])('rejects a shape-valid foreign CREATE preview %s before custody replacement', async (field) => {
  const original = savedReview();
  const preview = {
    ...original,
    review: {
      ...original.review,
      reason: 'Create the requested governed role.',
      proposedRole: { ...original.review.proposedRole, displayName: 'Requested bound role' },
      stepUp: { ...original.review.stepUp },
    },
  };
  if (field === 'name') preview.review.proposedRole.displayName = 'Foreign role';
  if (field === 'reason') preview.review.reason = 'An unrelated role change.';
  if (field === 'actions')
    preview.review.proposedRole.actionIntentIds = ['ACT-PARTICIPANTS_READ_RESOURCE-V1'];
  if (field === 'mutation') {
    preview.review.mutation = 'ARCHIVE';
    preview.review.expectedRevision = '1';
    preview.review.proposedRole.state = 'ARCHIVED';
  }
  if (field === 'revision') preview.review.expectedRevision = '1';
  if (field === 'step-up target') preview.review.stepUp.resourceId = secondId;
  if (field === 'step-up digest') preview.review.stepUp.resourceDigest = `sha256:${'c'.repeat(64)}`;
  if (field === 'role reference')
    preview.review.proposedRole.roleId = `urn:openpc:role:${secondId}`;
  if (field === 'Participant') preview.review.proposedRole.participantId = secondId;
  localStorage.setItem('openpc:role-workflow:v1', JSON.stringify({ actor, value: original }));
  const stored = localStorage.getItem('openpc:role-workflow:v1');
  const fetch = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
    if (init?.method === 'POST') return Response.json(preview, { status: 201 });
    if (isSession(input)) return Response.json(session);
    return Response.json(isCatalogue(input) ? catalogue() : state);
  });
  const user = userEvent.setup();
  render(<ParticipantRoleWorkflow />);
  await screen.findByText('Private draft role');
  await user.type(screen.getByLabelText('Role name'), 'Requested bound role');
  await user.type(screen.getByLabelText('Reason'), 'Create the requested governed role.');
  await user.click(screen.getByRole('button', { name: 'Review role creation' }));
  await screen.findByText('The role review could not be confirmed. Refresh before continuing.');
  expect(localStorage.getItem('openpc:role-workflow:v1')).toBe(stored);
  expect(screen.getByText('Private draft role')).toBeVisible();
  expect(
    screen.queryByText('Review the exact role change before requesting approval.'),
  ).not.toBeInTheDocument();
  expect(fetch.mock.calls.filter(([, init]) => init?.method === 'POST')).toHaveLength(1);
  expect(performWebAuthnStepUp).not.toHaveBeenCalled();
});
it.each(['role', 'revision', 'reason'])(
  'rejects a canonical foreign ARCHIVE preview %s against the captured selection',
  async (field) => {
    const original = savedReview();
    const preview = {
      ...original,
      review: {
        ...original.review,
        mutation: 'ARCHIVE',
        expectedRevision: '1',
        reason: 'Archive the selected governed role.',
        proposedRole: {
          ...original.review.proposedRole,
          displayName: record.displayName,
          state: 'ARCHIVED',
        },
        stepUp: { ...original.review.stepUp },
      },
    };
    if (field === 'role') {
      preview.review.proposedRole.id = secondId;
      preview.review.proposedRole.roleId = `urn:openpc:role:${secondId}`;
      preview.review.stepUp.resourceId = secondId;
    }
    if (field === 'revision') preview.review.expectedRevision = '2';
    if (field === 'reason') preview.review.reason = 'Archive a different governed role.';
    localStorage.setItem('openpc:role-workflow:v1', JSON.stringify({ actor, value: original }));
    const stored = localStorage.getItem('openpc:role-workflow:v1');
    const fetch = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      if (init?.method === 'POST') return Response.json(preview, { status: 201 });
      if (isSession(input)) return Response.json(session);
      if (isCatalogue(input)) return Response.json(catalogue());
      return Response.json(String(input).includes('roleId=') ? selectedState() : state);
    });
    const user = userEvent.setup();
    render(<ParticipantRoleWorkflow />);
    await user.click(
      await screen.findByRole('button', { name: 'View details for Catalogue first' }),
    );
    await screen.findByText('Readback first');
    await user.type(screen.getByLabelText('Archive reason'), 'Archive the selected governed role.');
    await user.click(screen.getByRole('button', { name: 'Review role archival' }));
    await screen.findByText('The role review could not be confirmed. Refresh before continuing.');
    expect(localStorage.getItem('openpc:role-workflow:v1')).toBe(stored);
    expect(screen.getByText('Private draft role')).toBeVisible();
    expect(fetch.mock.calls.filter(([, init]) => init?.method === 'POST')).toHaveLength(1);
    expect(performWebAuthnStepUp).not.toHaveBeenCalled();
  },
);
it.each([
  'role and step-up',
  'name',
  'reason',
  'actions',
  'mutation',
  'revision',
  'step-up action',
  'step-up action digest',
  'approval resource',
])(
  'rejects a shape-valid foreign submitted %s despite an echoed candidate digest',
  async (field) => {
    const original = savedReview();
    const result = {
      ...original,
      reviewToken: 'new-valid-resealed-token-'.padEnd(80, 'z'),
      review: {
        ...original.review,
        proposedRole: { ...original.review.proposedRole },
        stepUp: { ...original.review.stepUp },
      },
      approval: approvalFor(original),
    };
    if (field === 'role and step-up') {
      result.review.proposedRole.id = secondId;
      result.review.proposedRole.roleId = `urn:openpc:role:${secondId}`;
      result.review.stepUp.resourceId = secondId;
    }
    if (field === 'name') result.review.proposedRole.displayName = 'Foreign submitted role';
    if (field === 'reason') result.review.reason = 'An unrelated submitted reason.';
    if (field === 'actions')
      result.review.proposedRole.actionIntentIds = ['ACT-PARTICIPANTS_READ_RESOURCE-V1'];
    if (field === 'mutation') {
      result.review.mutation = 'ARCHIVE';
      result.review.expectedRevision = '1';
      result.review.proposedRole.state = 'ARCHIVED';
    }
    if (field === 'revision') result.review.expectedRevision = '2';
    if (field === 'step-up action')
      result.review.stepUp.actionIntentId = 'ACT-PARTICIPANTS_READ_RESOURCE-V1';
    if (field === 'step-up action digest')
      result.review.stepUp.actionIntentDigest = `sha256:${'c'.repeat(64)}`;
    if (field === 'approval resource')
      result.approval.approvalRequestId = `urn:foreign:resource:${result.approval.approvalRequestId.slice(-36)}`;
    localStorage.setItem('openpc:role-workflow:v1', JSON.stringify({ actor, value: original }));
    const stored = localStorage.getItem('openpc:role-workflow:v1');
    const fetch = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      if (init?.method === 'POST') return Response.json(result, { status: 202 });
      if (isSession(input)) return Response.json(session);
      return Response.json(isCatalogue(input) ? catalogue() : state);
    });
    render(<ParticipantRoleWorkflow />);
    await userEvent
      .setup()
      .click(await screen.findByRole('button', { name: 'Send role to checker' }));
    await screen.findByText(
      'The role submission could not be confirmed. Refresh approvals before retrying.',
    );
    expect(localStorage.getItem('openpc:role-workflow:v1')).toBe(stored);
    expect(screen.getByText('Private draft role')).toBeVisible();
    expect(screen.getByRole('button', { name: 'Send role to checker' })).toBeEnabled();
    expect(
      screen.queryByRole('button', { name: 'Commit approved role change' }),
    ).not.toBeInTheDocument();
    const posts = fetch.mock.calls.filter(([, init]) => init?.method === 'POST');
    expect(posts).toHaveLength(1);
    expect(JSON.parse(String(posts[0]?.[1]?.body))).toEqual({
      command: 'SUBMIT',
      reviewToken: original.reviewToken,
    });
    expect(performWebAuthnStepUp).not.toHaveBeenCalled();
  },
);

it.each([
  ['denial', unauthorizedFailure],
  [
    'conflict',
    'The role request could not continue with the current state. Refresh before retrying.',
  ],
  ['server', 'The role request was not completed. Refresh before retrying.'],
  ['transport', 'The authenticated role context could not be read. Refresh before retrying.'],
  ['throwable', 'The authenticated role context could not be read. Refresh before retrying.'],
  ['invalid JSON', malformedFailure],
  ['null', malformedFailure],
  ['array', malformedFailure],
])(
  'redacts initial role context %s without losing the sealed original',
  async (failure, message) => {
    localStorage.setItem(
      'openpc:role-workflow:v1',
      JSON.stringify({ actor, value: savedReview() }),
    );
    const original = localStorage.getItem('openpc:role-workflow:v1');
    const fetch = vi.spyOn(globalThis, 'fetch').mockImplementation(async () => {
      if (failure === 'transport') throw new Error(privateFailure);
      if (failure === 'throwable') throw { message: privateFailure, name: 'RoleWorkflowFailure' };
      if (failure === 'invalid JSON') return new Response(privateFailure);
      if (failure === 'null') return Response.json(null);
      if (failure === 'array') return Response.json([privateFailure]);
      return Response.json(
        { title: privateFailure, code: privateFailure, detail: privateFailure },
        { status: failure === 'denial' ? 403 : failure === 'conflict' ? 409 : 500 },
      );
    });
    render(<ParticipantRoleWorkflow />);
    await screen.findByText(message);
    expect(document.body.textContent).not.toContain(privateFailure);
    expect(screen.queryByRole('heading', { name: 'Participant roles' })).not.toBeInTheDocument();
    expect(screen.queryByText('Private draft role')).not.toBeInTheDocument();
    expect(screen.queryByText('Authenticated session controls')).not.toBeInTheDocument();
    expect(localStorage.getItem('openpc:role-workflow:v1')).toBe(original);
    expect(fetch).toHaveBeenCalledTimes(1);
    expect(performWebAuthnStepUp).not.toHaveBeenCalled();
  },
);

it.each(['denial', 'transport', 'invalid JSON', 'null', 'array', 'review', 'actions'])(
  'rejects a %s role preview before replacing original custody or sending another mutation',
  async (failure) => {
    localStorage.setItem(
      'openpc:role-workflow:v1',
      JSON.stringify({ actor, value: savedReview() }),
    );
    const original = localStorage.getItem('openpc:role-workflow:v1');
    const fetch = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      if (init?.method === 'POST') {
        if (failure === 'transport') throw new Error(privateFailure);
        if (failure === 'invalid JSON') return new Response(privateFailure, { status: 201 });
        if (failure === 'denial')
          return Response.json({ title: privateFailure, code: privateFailure }, { status: 403 });
        if (failure === 'null') return Response.json(null, { status: 201 });
        if (failure === 'array') return Response.json([privateFailure], { status: 201 });
        const review = savedReview();
        return Response.json(
          failure === 'review'
            ? { reviewToken: privateFailure }
            : {
                ...review,
                review: {
                  ...review.review,
                  proposedRole: { ...review.review.proposedRole, actionIntentIds: [{}] },
                },
              },
          { status: 201 },
        );
      }
      if (isSession(input)) return Response.json(session);
      if (isCatalogue(input)) return Response.json(catalogue());
      return Response.json(state);
    });
    const user = userEvent.setup();
    render(<ParticipantRoleWorkflow />);
    await screen.findByText('Private draft role');
    await user.type(screen.getByLabelText('Role name'), 'Safe requested role');
    await user.type(screen.getByLabelText('Reason'), 'Create an authorized role.');
    await user.click(screen.getByRole('button', { name: 'Review role creation' }));
    await screen.findByText(
      failure === 'denial'
        ? unauthorizedFailure
        : failure === 'transport'
          ? requestFailure
          : ['invalid JSON', 'null', 'array'].includes(failure)
            ? malformedFailure
            : 'The role review could not be confirmed. Refresh before continuing.',
    );
    expect(document.body.textContent).not.toContain(privateFailure);
    expect(screen.getByText('Private draft role')).toBeVisible();
    expect(
      screen.queryByText('Review the exact role change before requesting approval.'),
    ).not.toBeInTheDocument();
    expect(localStorage.getItem('openpc:role-workflow:v1')).toBe(original);
    const posts = fetch.mock.calls.filter(([, init]) => init?.method === 'POST');
    expect(posts).toHaveLength(1);
    expect(JSON.parse(String(posts[0]?.[1]?.body))).toEqual({
      command: 'PREVIEW_CREATE',
      displayName: 'Safe requested role',
      reason: 'Create an authorized role.',
      actionIntentIds: [],
    });
    expect(performWebAuthnStepUp).not.toHaveBeenCalled();
  },
);

it.each(['missing approval', 'bad approval ID', 'foreign candidate', 'bad review'])(
  'rejects %s on role submission without changing original custody or advancing',
  async (failure) => {
    const review = savedReview();
    localStorage.setItem('openpc:role-workflow:v1', JSON.stringify({ actor, value: review }));
    const original = localStorage.getItem('openpc:role-workflow:v1');
    const fetch = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      if (init?.method === 'POST') {
        const approval = approvalFor(review);
        return Response.json(
          {
            ...review,
            ...(failure === 'bad review' ? { review: { ...review.review, stepUp: {} } } : {}),
            ...(failure === 'missing approval'
              ? {}
              : {
                  approval: {
                    ...approval,
                    ...(failure === 'bad approval ID' ? { approvalRequestId: privateFailure } : {}),
                    ...(failure === 'foreign candidate' ? { candidateDigest: 'sha256:other' } : {}),
                  },
                }),
          },
          { status: 202 },
        );
      }
      if (isSession(input)) return Response.json(session);
      if (isCatalogue(input)) return Response.json(catalogue());
      return Response.json(state);
    });
    render(<ParticipantRoleWorkflow />);
    await userEvent
      .setup()
      .click(await screen.findByRole('button', { name: 'Send role to checker' }));
    await screen.findByText(
      'The role submission could not be confirmed. Refresh approvals before retrying.',
    );
    expect(document.body.textContent).not.toContain(privateFailure);
    expect(localStorage.getItem('openpc:role-workflow:v1')).toBe(original);
    expect(screen.getByRole('button', { name: 'Send role to checker' })).toBeEnabled();
    expect(
      screen.queryByRole('button', { name: 'Commit approved role change' }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByText('The role change is awaiting a distinct checker.'),
    ).not.toBeInTheDocument();
    const posts = fetch.mock.calls.filter(([, init]) => init?.method === 'POST');
    expect(posts).toHaveLength(1);
    expect(JSON.parse(String(posts[0]?.[1]?.body))).toEqual({
      command: 'SUBMIT',
      reviewToken: review.reviewToken,
    });
    expect(performWebAuthnStepUp).not.toHaveBeenCalled();
  },
);

it.each(['CREATE', 'ARCHIVE'])(
  'retains a resealed %s review and reads the distinct checker state',
  async (mutation) => {
    const initial = savedReview();
    const review = {
        ...initial,
        review: {
          ...initial.review,
          mutation,
          expectedRevision: mutation === 'ARCHIVE' ? '1' : '0',
          proposedRole: {
            ...initial.review.proposedRole,
            state: mutation === 'ARCHIVE' ? 'ARCHIVED' : 'ACTIVE',
          },
        },
      },
      approval = approvalFor(review);
    localStorage.setItem('openpc:role-workflow:v1', JSON.stringify({ actor, value: review }));
    let submitted = false;
    const fetch = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      if (init?.method === 'POST') {
        submitted = true;
        return Response.json(
          { ...review, reviewToken: 'freshly-resealed-review-'.padEnd(80, 'y'), approval },
          { status: 202 },
        );
      }
      if (isSession(input)) return Response.json(session);
      if (isCatalogue(input)) return Response.json(catalogue());
      return Response.json({ ...state, approvals: submitted ? [approval] : [] });
    });
    render(<ParticipantRoleWorkflow />);
    await userEvent
      .setup()
      .click(await screen.findByRole('button', { name: 'Send role to checker' }));
    await screen.findByText('The role change is awaiting a distinct checker.');
    expect(screen.getByText('Approval: Awaiting approval')).toBeVisible();
    expect(JSON.parse(localStorage.getItem('openpc:role-workflow:v1') ?? 'null')).toMatchObject({
      actor,
      value: {
        ...review,
        reviewToken: 'freshly-resealed-review-'.padEnd(80, 'y'),
        approvalRequestId: approval.approvalRequestId.slice(-36),
      },
    });
    expect(fetch.mock.calls.filter(([, init]) => init?.method === 'POST')).toHaveLength(1);
    expect(
      screen.queryByRole('button', { name: 'Commit approved role change' }),
    ).not.toBeInTheDocument();
    expect(performWebAuthnStepUp).not.toHaveBeenCalled();
  },
);

it.each([
  'operation',
  'reconciled',
  'missing',
  'foreign ID',
  'foreign candidate',
  'pending',
  'step-up',
])(
  'uses the %s approval result without exposing errors or fabricating an approved role',
  async (result) => {
    const checker = {
      ...actor,
      sessionId: '018f0000-0000-7000-8000-000000000118',
      principalId: '018f0000-0000-7000-8000-000000000112',
    };
    const approval = approvalFor();
    let confirmed = false;
    if (result === 'step-up')
      vi.mocked(performWebAuthnStepUp).mockRejectedValueOnce(new Error(privateFailure));
    const fetch = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      if (init?.method === 'POST') {
        confirmed = result === 'operation' || result === 'reconciled';
        return Response.json(
          result === 'missing'
            ? {}
            : {
                ...(result === 'reconciled'
                  ? { reconciled: true }
                  : { operation: approvalOperation() }),
                approval: {
                  ...approval,
                  state: result === 'pending' ? 'REQUESTED' : 'APPROVED',
                  ...(result === 'foreign ID'
                    ? { approvalRequestId: `urn:openpc:resource:${secondId}` }
                    : {}),
                  ...(result === 'foreign candidate' ? { candidateDigest: 'sha256:other' } : {}),
                },
              },
          { status: result === 'reconciled' ? 200 : 202 },
        );
      }
      if (isSession(input)) return Response.json({ ...session, ...checker });
      if (isCatalogue(input)) return Response.json(catalogue(checker));
      return Response.json({
        ...state,
        actor: { ...checker, role: 'viewer' },
        approvals: [{ ...approval, state: confirmed ? 'APPROVED' : 'REQUESTED' }],
      });
    });
    render(<ParticipantRoleWorkflow />);
    await userEvent
      .setup()
      .click(await screen.findByRole('button', { name: 'Approve Private draft role' }));
    await screen.findByText(
      result === 'operation' || result === 'reconciled'
        ? 'The reviewed role change is approved.'
        : result === 'step-up'
          ? requestFailure
          : 'The role approval could not be confirmed. Refresh approvals before retrying.',
    );
    expect(document.body.textContent).not.toContain(privateFailure);
    expect(
      screen.queryByRole('button', { name: 'Commit approved role change' }),
    ).not.toBeInTheDocument();
    expect(localStorage.getItem('openpc:role-workflow:v1')).toBeNull();
    const posts = fetch.mock.calls.filter(([, init]) => init?.method === 'POST');
    expect(posts).toHaveLength(result === 'step-up' ? 0 : 1);
    if (posts.length)
      expect(JSON.parse(String(posts[0]?.[1]?.body))).toEqual({
        command: 'APPROVE',
        approvalRequestId: approval.approvalRequestId.slice(-36),
        candidateDigest: approval.candidateDigest,
      });
    expect(performWebAuthnStepUp).toHaveBeenCalledWith(
      { ...approval.stepUp, stepUp: 'FRESH_WEBAUTHN_MAX_5M' },
      approval.stepUp,
      { signal: expect.any(AbortSignal), isCurrent: expect.any(Function) },
    );
    if (!confirmed)
      expect(screen.getByRole('button', { name: 'Approve Private draft role' })).toBeEnabled();
  },
);

it.each([
  ['CREATE', 'foreign role'],
  ['ARCHIVE', 'foreign role'],
  ['CREATE', 'role reference'],
  ['ARCHIVE', 'role reference'],
  ['CREATE', 'state'],
  ['ARCHIVE', 'state'],
  ['CREATE', 'other branch'],
  ['ARCHIVE', 'other branch'],
  ['CREATE', 'incomplete'],
  ['ARCHIVE', 'incomplete'],
  ['CREATE', 'reauthentication'],
  ['ARCHIVE', 'reauthentication'],
  ['CREATE', 'foreign ambiguity'],
  ['ARCHIVE', 'foreign ambiguity'],
  ['CREATE', 'ambiguity reconciliation'],
  ['ARCHIVE', 'ambiguity reconciliation'],
  ['CREATE', 'wrong status'],
  ['ARCHIVE', 'wrong status'],
  ['ARCHIVE', 'epoch'],
  ['ARCHIVE', 'revocation count'],
  ['ARCHIVE', 'archive reconciliation'],
])(
  'rejects %s commit %s before terminal state, custody change or replay',
  async (mutation, field) => {
    const original = savedReview();
    const review = {
      ...original,
      approvalRequestId: approvalFor().approvalRequestId.slice(-36),
      review: {
        ...original.review,
        mutation,
        expectedRevision: mutation === 'ARCHIVE' ? '1' : '0',
        proposedRole: {
          ...original.review.proposedRole,
          state: mutation === 'ARCHIVE' ? 'ARCHIVED' : 'ACTIVE',
        },
      },
    };
    const response: Record<string, unknown> = {
      ...commitFor(review, field.startsWith('ambiguity') || field === 'foreign ambiguity'),
    };
    if (field === 'foreign role')
      response.effect = {
        ...review.review.proposedRole,
        id: secondId,
        roleId: `urn:openpc:role:${secondId}`,
        revision: '2',
        origin: 'GOVERNED',
      };
    if (field === 'role reference')
      response.effect = {
        ...review.review.proposedRole,
        roleId: `urn:openpc:role:${secondId}`,
        revision: '2',
        origin: 'GOVERNED',
      };
    if (field === 'state')
      response.effect = {
        ...review.review.proposedRole,
        state: mutation === 'ARCHIVE' ? 'ACTIVE' : 'ARCHIVED',
        revision: '2',
        origin: 'GOVERNED',
      };
    if (field === 'other branch') {
      const other = {
        ...review,
        review: {
          ...review.review,
          mutation: mutation === 'ARCHIVE' ? 'CREATE' : 'ARCHIVE',
          proposedRole: {
            ...review.review.proposedRole,
            state: mutation === 'ARCHIVE' ? 'ACTIVE' : 'ARCHIVED',
          },
        },
      };
      for (const key of Object.keys(response)) delete response[key];
      Object.assign(response, commitFor(other));
    }
    if (field === 'incomplete')
      delete response[mutation === 'ARCHIVE' ? 'revokedAssignments' : 'operationId'];
    if (field === 'reauthentication') response.reauthenticationRequired = mutation === 'CREATE';
    if (field === 'foreign ambiguity') response.roleId = secondId;
    if (field === 'ambiguity reconciliation')
      response.reconciliation = 'READ_AFTER_REAUTHENTICATION';
    if (field === 'epoch') response.newEpoch = '01';
    if (field === 'revocation count') response.revokedAssignments = -1;
    if (field === 'archive reconciliation') response.reconciliation = 'READ_AUTHORITATIVE_EFFECT';
    localStorage.setItem('openpc:role-workflow:v1', JSON.stringify({ actor, value: review }));
    const stored = localStorage.getItem('openpc:role-workflow:v1');
    const fetch = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      if (init?.method === 'POST')
        return Response.json(response, { status: field === 'wrong status' ? 200 : 202 });
      if (isSession(input)) return Response.json(session);
      return Response.json(isCatalogue(input) ? catalogue() : approvedWorkbench(review));
    });
    render(<ParticipantRoleWorkflow />);
    await userEvent
      .setup()
      .click(await screen.findByRole('button', { name: 'Commit approved role change' }));
    await screen.findByText(
      field === 'wrong status'
        ? malformedFailure
        : 'The role change response could not be confirmed. Read the authoritative role before retrying.',
    );
    expect(localStorage.getItem('openpc:role-workflow:v1')).toBe(stored);
    expect(screen.getByRole('heading', { name: 'Participant roles' })).toBeVisible();
    expect(screen.queryByRole('button', { name: 'Commit approved role change' })).toBeNull();
    expect(screen.getByRole('button', { name: 'Read original role outcome' })).toBeEnabled();
    expect(
      screen.queryByRole('button', { name: 'Read role after signing in' }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByText('Role created and its durable effect read back.'),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByText(
        'Role archived. Its assignments were revoked. Sign in again to read the new authority state.',
      ),
    ).not.toBeInTheDocument();
    expect(fetch.mock.calls.some(([url]) => String(url).includes('roleId='))).toBe(
      mutation === 'ARCHIVE',
    );
    const posts = fetch.mock.calls.filter(([, init]) => init?.method === 'POST');
    expect(posts).toHaveLength(1);
    expect(JSON.parse(String(posts[0]?.[1]?.body))).toEqual({
      command: 'COMMIT',
      reviewToken: review.reviewToken,
      approvalRequestId: review.approvalRequestId,
    });
  },
);

it('retains the exact CREATE ambiguity and offers manual authoritative readback without replay', async () => {
  const review = {
    ...savedReview(),
    approvalRequestId: approvalFor().approvalRequestId.slice(-36),
  };
  localStorage.setItem('openpc:role-workflow:v1', JSON.stringify({ actor, value: review }));
  const stored = localStorage.getItem('openpc:role-workflow:v1');
  const fetch = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
    if (init?.method === 'POST') return Response.json(commitFor(review, true), { status: 202 });
    if (isSession(input)) return Response.json(session);
    return Response.json(
      isCatalogue(input) ? catalogue() : { ...state, approvals: [approvalFor(review, 'APPROVED')] },
    );
  });
  render(<ParticipantRoleWorkflow />);
  await userEvent
    .setup()
    .click(await screen.findByRole('button', { name: 'Commit approved role change' }));
  await screen.findByText(
    'The response was lost. Sign in again and read the role before retrying.',
  );
  expect(screen.getByRole('button', { name: 'Read role after signing in' })).toBeVisible();
  expect(screen.queryByRole('heading', { name: 'Participant roles' })).not.toBeInTheDocument();
  expect(localStorage.getItem('openpc:role-workflow:v1')).toBe(stored);
  expect(fetch.mock.calls.filter(([, init]) => init?.method === 'POST')).toHaveLength(1);
  expect(fetch.mock.calls.some(([url]) => String(url).includes('roleId='))).toBe(false);
});

it.each(['empty', 'unknown truth', 'bad reauthentication', 'transport', 'denial', 'step-up'])(
  'keeps original commit custody on %s without false readback success or automatic replay',
  async (failure) => {
    const review = {
      ...savedReview(),
      approvalRequestId: approvalFor().approvalRequestId.slice(-36),
    };
    localStorage.setItem('openpc:role-workflow:v1', JSON.stringify({ actor, value: review }));
    const original = localStorage.getItem('openpc:role-workflow:v1');
    if (failure === 'step-up')
      vi.mocked(performWebAuthnStepUp).mockRejectedValueOnce(new Error(privateFailure));
    const fetch = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      if (init?.method === 'POST') {
        if (failure === 'transport') throw new Error(privateFailure);
        if (failure === 'denial')
          return Response.json({ title: privateFailure, code: privateFailure }, { status: 403 });
        return Response.json(
          failure === 'empty'
            ? {}
            : failure === 'unknown truth'
              ? { truthState: privateFailure }
              : { truthState: 'SUCCESS', reauthenticationRequired: privateFailure },
          { status: 202 },
        );
      }
      if (isSession(input)) return Response.json(session);
      if (isCatalogue(input)) return Response.json(catalogue());
      return Response.json({ ...state, approvals: [approvalFor(savedReview(), 'APPROVED')] });
    });
    render(<ParticipantRoleWorkflow />);
    await userEvent
      .setup()
      .click(await screen.findByRole('button', { name: 'Commit approved role change' }));
    await screen.findByText(
      failure === 'denial'
        ? unauthorizedFailure
        : ['transport', 'step-up'].includes(failure)
          ? requestFailure
          : 'The role change response could not be confirmed. Read the authoritative role before retrying.',
    );
    expect(document.body.textContent).not.toContain(privateFailure);
    expect(
      screen.queryByText('Role created and its durable effect read back.'),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByText(
        'Role archived. Its assignments were revoked. Sign in again to read the new authority state.',
      ),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole('button', { name: 'Read role after signing in' }),
    ).not.toBeInTheDocument();
    expect(localStorage.getItem('openpc:role-workflow:v1')).toBe(original);
    expect(fetch.mock.calls.filter(([, init]) => init?.method === 'POST')).toHaveLength(
      failure === 'step-up' ? 0 : 1,
    );
    expect(fetch.mock.calls.some(([url]) => String(url).includes('roleId='))).toBe(false);
    expect(performWebAuthnStepUp).toHaveBeenCalledWith(
      { ...review.review.stepUp, stepUp: 'FRESH_WEBAUTHN_MAX_5M' },
      review.review.stepUp,
      { signal: expect.any(AbortSignal), isCurrent: expect.any(Function) },
    );
  },
);

it('clears another actor’s persisted proposal before displaying an authenticated role page', async () => {
  localStorage.setItem('openpc:role-workflow:v1', JSON.stringify({ actor, value: savedReview() }));
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
    )
    .mockResolvedValueOnce(
      Response.json({
        actor: checker,
        items: [],
        nextCursor: null,
        observedAt: '2026-09-14T00:00:00Z',
        authorizedEmpty: true,
      }),
    );
  render(<ParticipantRoleWorkflow />);
  await screen.findByRole('heading', { name: 'Participant roles' });
  expect(screen.queryByText('Private draft role')).not.toBeInTheDocument();
  expect(screen.getByLabelText('Authority role ID')).toHaveValue('');
  expect(localStorage.getItem('openpc:role-workflow:v1')).toBeNull();
});

it('restores a valid review only after the same actor and context are read from Identity', async () => {
  localStorage.setItem('openpc:role-workflow:v1', JSON.stringify({ actor, value: savedReview() }));
  vi.spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(
      Response.json({ ...actor, authenticated: true, contextMode: 'PARTICIPANT' }),
    )
    .mockResolvedValueOnce(
      Response.json({ actor: { ...actor, role: 'operator' }, approvals: [], nextCursor: null }),
    )
    .mockResolvedValueOnce(
      Response.json({
        actor,
        items: [],
        nextCursor: null,
        observedAt: '2026-09-14T00:00:00Z',
        authorizedEmpty: true,
      }),
    );
  render(<ParticipantRoleWorkflow />);
  await waitFor(() => expect(screen.getByText('Private draft role')).toBeVisible());
  expect(screen.getByLabelText('Authority role ID')).toHaveValue(roleId);
  expect(screen.getByText('None')).toBeVisible();
});

it('shows authoritative role details and the immutable archive lifecycle to an operator', async () => {
  const effect = {
    id: roleId,
    participantId: actor.participantId,
    roleId: `urn:openpc:role:${roleId}`,
    displayName: 'Debtor',
    actionIntentIds: [],
    state: 'ACTIVE',
    revision: '1',
    origin: 'GOVERNED',
  };
  vi.spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(
      Response.json({ ...actor, authenticated: true, contextMode: 'PARTICIPANT' }),
    )
    .mockResolvedValueOnce(
      Response.json({
        actor: { ...actor, role: 'operator' },
        approvals: [],
        effect: { effect, operationId: roleId },
        nextCursor: null,
      }),
    )
    .mockResolvedValueOnce(
      Response.json({
        actor,
        items: [],
        nextCursor: null,
        observedAt: '2026-09-14T00:00:00Z',
        authorizedEmpty: true,
      }),
    );

  render(<ParticipantRoleWorkflow />);
  expect(await screen.findByRole('heading', { name: 'Role details' })).toHaveFocus();
  expect(screen.getByText('Debtor')).toBeVisible();
  expect(screen.getByText(`urn:openpc:role:${roleId}`)).toBeVisible();
  expect(screen.getByText('GOVERNED')).toBeVisible();
  expect(screen.getByText(`Operation reference: ${roleId}`)).toBeVisible();
  expect(screen.getByText(/Roles are immutable/u)).toBeVisible();
  expect(screen.getByRole('form', { name: 'Archive role' })).toBeVisible();
});
it.each([
  ['session', 'denial'],
  ['session', 'malformed'],
  ['session', 'missing context'],
  ['session', 'unknown context'],
  ['session', 'unavailable'],
  ['workbench', 'denial'],
  ['workbench', 'malformed'],
  ['workbench', 'malformed actions'],
  ['workbench', 'malformed approvals'],
  ['workbench', 'malformed proposal actions'],
  ['workbench', 'malformed cursor'],
  ['workbench', 'unavailable'],
])(
  'drops current role projections on %s %s, preserving the original through late read and fresh retry',
  async (phase, failure) => {
    localStorage.setItem(
      'openpc:role-workflow:v1',
      JSON.stringify({ actor, value: savedReview() }),
    );
    const original = localStorage.getItem('openpc:role-workflow:v1');
    const old = deferredResponse();
    let denied = false;
    const fetch = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      if (isCatalogue(input)) return Response.json(catalogue());
      if (denied && isSession(input) === (phase === 'session')) {
        if (failure === 'unavailable') throw new Error('Current role read unavailable.');
        return failure === 'denial'
          ? Response.json({ title: 'Current role read denied' }, { status: 403 })
          : Response.json(
              failure === 'missing context'
                ? { ...session, privacyDomainId: undefined }
                : failure === 'unknown context'
                  ? { ...session, contextMode: 'UNKNOWN' }
                  : failure === 'malformed actions'
                    ? {
                        ...selectedState(),
                        effect: {
                          ...selectedState().effect,
                          effect: { ...record, actionIntentIds: [{}] },
                        },
                      }
                    : failure === 'malformed approvals'
                      ? { ...state, approvals: [false] }
                      : failure === 'malformed proposal actions'
                        ? {
                            ...state,
                            approvals: [
                              {
                                approvalRequestId: '018f0000-0000-7000-8000-000000000801',
                                candidateDigest: 'sha256:review',
                                state: 'REQUESTED',
                                proposal: {
                                  ...savedReview().review,
                                  proposedRole: {
                                    ...savedReview().review.proposedRole,
                                    actionIntentIds: {},
                                  },
                                },
                                stepUp: savedReview().review.stepUp,
                              },
                            ],
                          }
                        : failure === 'malformed cursor'
                          ? { ...state, nextCursor: {} }
                          : {},
            );
      }
      if (isSession(input)) return Response.json(session);
      if (String(input).includes(secondId)) return old.promise;
      return Response.json(String(input).includes(roleId) ? selectedState() : state);
    });
    const user = userEvent.setup();
    render(<ParticipantRoleWorkflow />);
    await screen.findByText('Private draft role');
    await user.click(
      await screen.findByRole('button', { name: 'View details for Catalogue first' }),
    );
    await screen.findByText('Readback first');
    await user.click(screen.getByRole('button', { name: 'View details for Catalogue second' }));
    await waitFor(() =>
      expect(fetch.mock.calls.some(([url]) => String(url).includes(`roleId=${secondId}`))).toBe(
        true,
      ),
    );
    const signal = fetch.mock.calls.find(([url]) => String(url).includes(`roleId=${secondId}`))?.[1]
      ?.signal;
    denied = true;
    await user.click(screen.getByRole('button', { name: 'View details for Catalogue first' }));
    await screen.findByText(
      failure === 'denial'
        ? 'The role request was not authorized. Refresh the authenticated context before continuing.'
        : failure === 'unavailable'
          ? 'The role request could not be completed. Refresh before retrying.'
          : phase === 'session'
            ? 'Authenticated context could not be confirmed. Refresh before continuing.'
            : 'Role approvals could not be confirmed. Refresh before continuing.',
    );
    expect(signal?.aborted).toBe(true);
    expect(screen.queryByRole('heading', { name: 'Participant roles' })).not.toBeInTheDocument();
    expect(screen.queryByText('Readback first')).not.toBeInTheDocument();
    expect(screen.queryByText('Private draft role')).not.toBeInTheDocument();
    expect(screen.queryByText('Authenticated session controls')).not.toBeInTheDocument();
    expect(localStorage.getItem('openpc:role-workflow:v1')).toBe(original);
    await act(async () => old.resolve(Response.json(selectedState(secondId, 'Obsolete readback'))));
    expect(screen.queryByText('Obsolete readback')).not.toBeInTheDocument();
    expect(localStorage.getItem('openpc:role-workflow:v1')).toBe(original);
    denied = false;
    await user.click(screen.getByRole('button', { name: 'Refresh approvals' }));
    await screen.findByText('Private draft role');
    fireEvent.click(screen.getByRole('button', { name: 'Workspace details' }));
    expect(
      within(screen.getByRole('dialog', { name: 'Workspace details' })).getByText('2'),
    ).toBeVisible();
    fireEvent.click(screen.getByRole('button', { name: 'Close Workspace details' }));
    expect(screen.getByLabelText('Authority role ID')).toHaveValue(roleId);
    expect(screen.queryByText('Readback first')).not.toBeInTheDocument();
    expect(localStorage.getItem('openpc:role-workflow:v1')).toBe(original);
    expect(fetch.mock.calls.some(([, init]) => init?.method === 'POST')).toBe(false);
    expect(performWebAuthnStepUp).not.toHaveBeenCalled();
  },
);
it.each(['actor', 'ID', 'reference'])(
  'rejects current role %s mismatch and preserves the sealed original',
  async (field) => {
    localStorage.setItem(
      'openpc:role-workflow:v1',
      JSON.stringify({ actor, value: savedReview() }),
    );
    const original = localStorage.getItem('openpc:role-workflow:v1');
    const fetch = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      if (isSession(input)) return Response.json(session);
      if (isCatalogue(input)) return Response.json(catalogue());
      if (!String(input).includes('roleId=')) return Response.json(state);
      const next = selectedState();
      if (field === 'actor') next.actor.contextEpoch = '3';
      if (field === 'ID') next.effect.effect.id = secondId;
      if (field === 'reference') next.effect.effect.roleId = `urn:openpc:role:${secondId}`;
      return Response.json(next);
    });
    render(<ParticipantRoleWorkflow />);
    await userEvent
      .setup()
      .click(await screen.findByRole('button', { name: 'View details for Catalogue first' }));
    await screen.findByText(
      field === 'actor'
        ? 'The working context changed. Refresh the role workflow before continuing.'
        : 'Role readback belongs to a different selection.',
    );
    expect(screen.queryByRole('heading', { name: 'Participant roles' })).not.toBeInTheDocument();
    expect(localStorage.getItem('openpc:role-workflow:v1')).toBe(original);
    expect(fetch.mock.calls.some(([, init]) => init?.method === 'POST')).toBe(false);
  },
);
it.each([
  ['session', 'success'],
  ['session', 'failure'],
  ['workbench', 'success'],
  ['workbench', 'failure'],
])('fences obsolete role %s %s behind a newer selected role', async (phase, result) => {
  const old = deferredResponse();
  let pendingFirst = false;
  let oldSignal: AbortSignal | null | undefined;
  const fetch = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
    if (isCatalogue(input)) return Response.json(catalogue());
    if (
      pendingFirst &&
      (phase === 'session' ? isSession(input) : String(input).includes(`roleId=${roleId}`))
    ) {
      oldSignal = init?.signal;
      return old.promise;
    }
    if (isSession(input)) return Response.json(session);
    return Response.json(
      String(input).includes(secondId) ? selectedState(secondId, 'Readback second') : state,
    );
  });
  const user = userEvent.setup();
  render(<ParticipantRoleWorkflow />);
  await screen.findByRole('button', { name: 'View details for Catalogue first' });
  pendingFirst = true;
  await user.click(screen.getByRole('button', { name: 'View details for Catalogue first' }));
  await waitFor(() => expect(oldSignal?.aborted).toBe(false));
  pendingFirst = false;
  await user.click(screen.getByRole('button', { name: 'View details for Catalogue second' }));
  await screen.findByText('Readback second');
  expect(oldSignal?.aborted).toBe(true);
  await act(async () =>
    result === 'success'
      ? old.resolve(Response.json(phase === 'session' ? session : selectedState()))
      : old.reject(new Error('Obsolete role read failed.')),
  );
  expect(screen.getByText('Readback second')).toBeVisible();
  expect(screen.queryByText('Readback first')).not.toBeInTheDocument();
  expect(screen.queryByText('Obsolete role read failed.')).not.toBeInTheDocument();
  expect(screen.getByLabelText('Authority role ID')).toHaveValue(secondId);
  expect(screen.getByRole('button', { name: 'Find role' })).toBeEnabled();
  if (phase === 'session')
    expect(fetch.mock.calls.some(([url]) => String(url).includes(`roleId=${roleId}`))).toBe(false);
  expect(fetch.mock.calls.some(([, init]) => init?.method === 'POST')).toBe(false);
});
it.each(['success', 'failure'])(
  'ignores obsolete initial session %s and does not start its workbench read',
  async (result) => {
    const old = deferredResponse();
    let reads = 0;
    const fetch = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      if (isSession(input)) return ++reads === 1 ? old.promise : Response.json(session);
      return Response.json(isCatalogue(input) ? catalogue() : state);
    });
    render(
      <StrictMode>
        <ParticipantRoleWorkflow />
      </StrictMode>,
    );
    await screen.findByRole('heading', { name: 'Participant roles' });
    const signal = fetch.mock.calls.find(([url]) => isSession(url))?.[1]?.signal;
    expect(signal?.aborted).toBe(true);
    await act(async () =>
      result === 'success'
        ? old.resolve(Response.json(session))
        : old.reject(new Error('Obsolete initial session failed.')),
    );
    expect(screen.queryByText('Obsolete initial session failed.')).not.toBeInTheDocument();
    expect(
      fetch.mock.calls.filter(([url]) => String(url).startsWith('/api/v1/ui/role-workbench?')),
    ).toHaveLength(1);
  },
);
it('reports a current initial context failure and offers a supported read retry without anonymous authority', async () => {
  const fetch = vi
    .spyOn(globalThis, 'fetch')
    .mockRejectedValueOnce(new Error('Context unavailable.'));
  render(<ParticipantRoleWorkflow />);
  await screen.findByText(
    'The authenticated role context could not be read. Refresh before retrying.',
  );
  expect(screen.queryByText('Authenticated session controls')).not.toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Refresh approvals' })).toBeEnabled();
  expect(fetch).toHaveBeenCalledTimes(1);
});
it('drops the previous cursor and proposal when an authoritative Identity reread changes actor', async () => {
  localStorage.setItem('openpc:role-workflow:v1', JSON.stringify({ actor, value: savedReview() }));
  const nextActor = {
    ...actor,
    privacyDomainId: '018f0000-0000-7000-8000-000000000202',
    contextEpoch: '3',
  };
  let next = false;
  const fetch = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
    if (isCatalogue(input)) return Response.json(catalogue(next ? nextActor : actor));
    if (isSession(input)) return Response.json(next ? { ...session, ...nextActor } : session);
    return Response.json(
      next
        ? { ...state, actor: { ...nextActor, role: 'operator' } }
        : { ...state, nextCursor: 'old-approval-cursor' },
    );
  });
  render(<ParticipantRoleWorkflow />);
  await screen.findByText('Private draft role');
  next = true;
  await userEvent.setup().click(screen.getByRole('button', { name: 'Next approval page' }));
  fireEvent.click(screen.getByRole('button', { name: 'Workspace details' }));
  await within(screen.getByRole('dialog', { name: 'Workspace details' })).findByText('3');
  fireEvent.click(screen.getByRole('button', { name: 'Close Workspace details' }));
  expect(screen.queryByText('Private draft role')).not.toBeInTheDocument();
  expect(screen.getByLabelText('Authority role ID')).toHaveValue('');
  expect(localStorage.getItem('openpc:role-workflow:v1')).toBeNull();
  const url = fetch.mock.calls
    .filter(([url]) => String(url).startsWith('/api/v1/ui/role-workbench?'))
    .at(-1)?.[0];
  expect(String(url)).not.toContain('cursor=');
  expect(String(url)).not.toContain('roleId=');
});
it.each([
  ['session', 'success'],
  ['session', 'failure'],
  ['workbench', 'success'],
  ['workbench', 'failure'],
])('fences an obsolete unsent role preview behind the selected %s %s', async (phase, result) => {
  const preview = deferredResponse(),
    old = deferredResponse();
  const original = savedReview();
  const fresh = {
    ...original,
    reviewToken: 'fresh-sealed-review'.padEnd(80, 'y'),
    review: {
      ...original.review,
      reason: 'Create this separate governed role.',
      stepUp: { ...original.review.stepUp, resourceId: secondId },
      proposedRole: {
        ...original.review.proposedRole,
        id: secondId,
        roleId: `urn:openpc:role:${secondId}`,
        displayName: 'Fresh sealed role',
      },
    },
  };
  let pendingRead = false;
  let signal: AbortSignal | null | undefined;
  const fetch = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
    if (init?.method === 'POST') return preview.promise;
    if (isCatalogue(input)) return Response.json(catalogue());
    if (
      pendingRead &&
      (phase === 'session' ? isSession(input) : String(input).includes(`roleId=${roleId}`))
    ) {
      signal = init?.signal;
      return old.promise;
    }
    return Response.json(
      isSession(input) ? session : String(input).includes(roleId) ? selectedState() : state,
    );
  });
  const user = userEvent.setup();
  render(<ParticipantRoleWorkflow />);
  await screen.findByRole('button', { name: 'View details for Catalogue first' });
  await user.type(screen.getByRole('textbox', { name: 'Role name' }), 'Fresh sealed role');
  await user.type(
    screen.getByRole('textbox', { name: 'Reason' }),
    'Create this separate governed role.',
  );
  await user.click(screen.getByRole('button', { name: 'Review role creation' }));
  await waitFor(() =>
    expect(fetch.mock.calls.some(([, init]) => init?.method === 'POST')).toBe(true),
  );
  pendingRead = true;
  await user.click(screen.getByRole('button', { name: 'View details for Catalogue first' }));
  await waitFor(() => expect(signal?.aborted).toBe(false));
  await act(async () => preview.resolve(Response.json(fresh, { status: 201 })));
  expect(signal?.aborted).toBe(false);
  await act(async () =>
    result === 'success'
      ? old.resolve(Response.json(phase === 'session' ? session : selectedState()))
      : old.reject(new Error('Old review read failed.')),
  );
  expect(screen.queryByRole('region', { name: 'Role change review' })).not.toBeInTheDocument();
  expect(screen.queryByText('Fresh sealed role')).not.toBeInTheDocument();
  if (result === 'success') expect(await screen.findByText('Readback first')).toBeVisible();
  else expect(await screen.findByText(requestFailure)).toBeVisible();
  expect(localStorage.getItem('openpc:role-workflow:v1')).toBeNull();
  expect(fetch.mock.calls.filter(([, init]) => init?.method === 'POST')).toHaveLength(1);
  expect(performWebAuthnStepUp).not.toHaveBeenCalled();
});
it.each(['session', 'workbench'])(
  'aborts an unmounted role %s read and ignores late failure',
  async (phase) => {
    const pending = deferredResponse();
    const fetch = vi
      .spyOn(globalThis, 'fetch')
      .mockImplementation(async (input) =>
        phase === 'session' || !isSession(input) ? pending.promise : Response.json(session),
      );
    const view = render(<ParticipantRoleWorkflow />);
    await waitFor(() => expect(fetch).toHaveBeenCalledTimes(phase === 'session' ? 1 : 2));
    const signal = fetch.mock.calls.at(-1)?.[1]?.signal;
    view.unmount();
    expect(signal?.aborted).toBe(true);
    await act(async () => pending.reject(new Error('Unmounted read failed.')));
    expect(fetch).toHaveBeenCalledTimes(phase === 'session' ? 1 : 2);
  },
);
it('preserves the approved CREATE command and reads its durable effect through the same public owner', async () => {
  const original = savedReview();
  const review = {
    ...original,
    approvalRequestId: '018f0000-0000-7000-8000-000000000801',
    review: {
      ...original.review,
      proposedRole: { ...original.review.proposedRole, displayName: 'Durable created role' },
    },
  };
  localStorage.setItem('openpc:role-workflow:v1', JSON.stringify({ actor, value: review }));
  const approved = {
    ...state,
    approvals: [
      {
        ...approvalFor(review, 'APPROVED'),
      },
    ],
  };
  const fetch = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
    if (init?.method === 'POST') return Response.json(commitFor(review), { status: 202 });
    if (isSession(input)) return Response.json(session);
    if (isCatalogue(input)) return Response.json(catalogue());
    if (String(input).includes(`roleId=${roleId}`)) {
      const selected = selectedState(roleId, 'Durable created role');
      return Response.json({
        ...selected,
        hint: {},
        actor: { ...selected.actor, hint: [] },
        effect: {
          ...selected.effect,
          hint: false,
          effect: { ...selected.effect.effect, hint: {} },
        },
      });
    }
    return Response.json({ ...approved, hint: [], actor: { ...approved.actor, hint: {} } });
  });
  render(<ParticipantRoleWorkflow />);
  await userEvent
    .setup()
    .click(await screen.findByRole('button', { name: 'Commit approved role change' }));
  await screen.findByText('Role created and its durable effect read back.');
  expect(
    within(screen.getByRole('region', { name: 'Role details' })).getByText('Durable created role'),
  ).toBeVisible();
  expect(screen.getByText(`Operation reference: ${roleId}`)).toBeVisible();
  const posts = fetch.mock.calls.filter(([, init]) => init?.method === 'POST');
  expect(posts).toHaveLength(1);
  expect(JSON.parse(String(posts[0]?.[1]?.body))).toEqual({
    command: 'COMMIT',
    reviewToken: review.reviewToken,
    approvalRequestId: review.approvalRequestId,
  });
  expect(performWebAuthnStepUp).toHaveBeenCalledOnce();
  expect(JSON.parse(localStorage.getItem('openpc:role-workflow:v1') ?? 'null')).toEqual({
    actor,
    value: review,
  });
});
it.each(['reauthentication', 'ambiguity'])(
  'preserves original archive intent and %s after a pending older GET arrives',
  async (boundary) => {
    const mutation = deferredResponse(),
      old = deferredResponse();
    const original = savedReview();
    const review = {
      ...original,
      approvalRequestId: '018f0000-0000-7000-8000-000000000801',
      review: {
        ...original.review,
        mutation: 'ARCHIVE',
        expectedRevision: '1',
        proposedRole: { ...original.review.proposedRole, state: 'ARCHIVED' },
      },
    };
    localStorage.setItem('openpc:role-workflow:v1', JSON.stringify({ actor, value: review }));
    const stored = localStorage.getItem('openpc:role-workflow:v1');
    const approved = {
      ...state,
      approvals: [
        {
          ...approvalFor(review, 'APPROVED'),
        },
      ],
    };
    const fetch = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      if (init?.method === 'POST') return mutation.promise;
      if (isSession(input)) return Response.json(session);
      if (isCatalogue(input)) return Response.json(catalogue());
      if (String(input).includes('roleId=')) {
        if (fetch.mock.calls.some(([, init]) => init?.method === 'POST')) return old.promise;
        return Response.json({
          ...approved,
          effect: {
            effect: {
              ...review.review.proposedRole,
              state: 'ACTIVE',
              revision: '1',
              origin: 'GOVERNED',
            },
            operationId: roleId,
          },
        });
      }
      return Response.json(approved);
    });
    const user = userEvent.setup();
    render(<ParticipantRoleWorkflow />);
    await user.click(await screen.findByRole('button', { name: 'Commit approved role change' }));
    await waitFor(() =>
      expect(fetch.mock.calls.some(([, init]) => init?.method === 'POST')).toBe(true),
    );
    const beforeSelectedRead = fetch.mock.calls.filter(([url]) =>
      String(url).includes('roleId='),
    ).length;
    await user.click(
      await screen.findByRole('button', { name: 'View details for Catalogue first' }),
    );
    await waitFor(() =>
      expect(
        fetch.mock.calls.filter(([url]) => String(url).includes('roleId=')).length,
      ).toBeGreaterThan(beforeSelectedRead),
    );
    const signal = fetch.mock.calls
      .filter(([url]) => String(url).includes('roleId='))
      .at(-1)?.[1]?.signal;
    await act(async () =>
      mutation.resolve(Response.json(commitFor(review, boundary === 'ambiguity'), { status: 202 })),
    );
    expect(signal?.aborted).toBe(true);
    await act(async () => old.resolve(Response.json(selectedState())));
    expect(screen.queryByRole('heading', { name: 'Participant roles' })).not.toBeInTheDocument();
    expect(screen.queryByText('Readback first')).not.toBeInTheDocument();
    expect(
      screen.getByText(
        boundary === 'ambiguity'
          ? 'The response was lost. Sign in again and read the role before retrying.'
          : 'Role archived. Its assignments were revoked. Sign in again to read the new authority state.',
      ),
    ).toBeVisible();
    expect(screen.getByRole('button', { name: 'Read role after signing in' })).toBeVisible();
    expect(localStorage.getItem('openpc:role-workflow:v1')).toBe(stored);
    const posts = fetch.mock.calls.filter(([, init]) => init?.method === 'POST');
    expect(posts).toHaveLength(1);
    expect(JSON.parse(String(posts[0]?.[1]?.body))).toEqual({
      command: 'COMMIT',
      reviewToken: review.reviewToken,
      approvalRequestId: review.approvalRequestId,
    });
    expect(performWebAuthnStepUp).toHaveBeenCalledOnce();
  },
);

function heldRole<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((yes) => {
    resolve = yes;
  });
  return { promise, resolve };
}
function retainApprovedRole(archive = false) {
  const original = savedReview();
  const review = {
    ...original,
    approvalRequestId: approvalFor().approvalRequestId.slice(-36),
    review: {
      ...original.review,
      mutation: archive ? 'ARCHIVE' : 'CREATE',
      expectedRevision: archive ? '1' : '0',
      proposedRole: { ...original.review.proposedRole, state: archive ? 'ARCHIVED' : 'ACTIVE' },
    },
  };
  localStorage.setItem('openpc:role-workflow:v1', JSON.stringify({ actor, value: review }));
  return review;
}
function rolePosts(fetch: ReturnType<typeof roleLifecycleFetch>) {
  return fetch.mock.calls.filter(
    ([url, init]) => String(url) === '/api/v1/ui/role-workbench' && init?.method === 'POST',
  );
}
function roleLifecycleFetch(
  original = retainApprovedRole(),
  post: () => Response | Promise<Response> = () =>
    Response.json(commitFor(original), { status: 202 }),
) {
  let sent = false;
  return vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
    if (String(input) === '/api/v1/ui/role-workbench' && init?.method === 'POST') {
      sent = true;
      return post();
    }
    if (isSession(input)) return Response.json(session);
    if (isCatalogue(input)) return Response.json(catalogue());
    if (original.review.mutation === 'ARCHIVE' && !sent)
      return Response.json(approvedWorkbench(original));
    return Response.json(
      String(input).includes('roleId=')
        ? selectedState()
        : { ...state, approvals: [approvalFor(original, 'APPROVED')] },
    );
  });
}
it('excludes duplicate same-turn role COMMIT entries and preserves the original payload', async () => {
  const original = retainApprovedRole();
  const pending = heldRole<void>();
  vi.mocked(performWebAuthnStepUp).mockImplementationOnce(() => pending.promise);
  const fetch = roleLifecycleFetch(original);
  render(<ParticipantRoleWorkflow />);
  const commit = await screen.findByRole('button', { name: 'Commit approved role change' });
  act(() => {
    fireEvent.click(commit);
    fireEvent.click(commit);
  });
  await waitFor(() => expect(performWebAuthnStepUp).toHaveBeenCalledTimes(1));
  expect(rolePosts(fetch)).toHaveLength(0);
  await act(async () => pending.resolve());
  await screen.findByText('Role created and its durable effect read back.');
  expect(rolePosts(fetch)).toHaveLength(1);
  expect(JSON.parse(String(rolePosts(fetch)[0]![1]!.body))).toEqual({
    command: 'COMMIT',
    reviewToken: original.reviewToken,
    approvalRequestId: original.approvalRequestId,
  });
});
it.each([
  'sessionId',
  'principalId',
  'participantId',
  'privacyDomainId',
  'contextEpoch',
  'role',
] as const)(
  'retires the pending role ceremony when a selected public read changes %s',
  async (changedField) => {
    const original = retainApprovedRole();
    const pending = heldRole<void>();
    vi.mocked(performWebAuthnStepUp).mockImplementationOnce(() => pending.promise);
    let changed = false;
    const nextActor = {
      ...actor,
      [changedField]:
        changedField === 'role' ? 'viewer' : changedField === 'contextEpoch' ? '3' : secondId,
    };
    const fetch = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      if (init?.method === 'POST') return Response.json(commitFor(original), { status: 202 });
      if (isSession(input))
        return Response.json(
          changed ? { ...session, ...nextActor } : { ...session, role: 'operator' },
        );
      if (isCatalogue(input)) return Response.json(catalogue(changed ? nextActor : actor));
      return Response.json({
        ...state,
        actor: {
          ...(changed ? nextActor : actor),
          role: changed && changedField === 'role' ? 'viewer' : 'operator',
        },
        approvals: changed ? [] : [approvalFor(original, 'APPROVED')],
      });
    });
    render(<ParticipantRoleWorkflow />);
    fireEvent.click(await screen.findByRole('button', { name: 'Commit approved role change' }));
    await waitFor(() => expect(performWebAuthnStepUp).toHaveBeenCalledTimes(1));
    const controls = vi.mocked(performWebAuthnStepUp).mock.calls[0]![2]!;
    changed = true;
    fireEvent.click(
      await screen.findByRole('button', { name: 'View details for Catalogue second' }),
    );
    await waitFor(() => expect(controls.signal!.aborted).toBe(true));
    await waitFor(() => expect(screen.queryByText('Private draft role')).not.toBeInTheDocument());
    await act(async () => pending.resolve());
    expect(rolePosts(fetch)).toHaveLength(0);
    expect(controls.isCurrent!()).toBe(false);
    expect(
      screen.queryByText('Role created and its durable effect read back.'),
    ).not.toBeInTheDocument();
  },
);
it.each(['reauthentication', 'ambiguity'] as const)(
  'keeps already-sent role %s and original read selector after a local field edit',
  async (boundary) => {
    const original = retainApprovedRole(true);
    const pending = heldRole<Response>();
    const fetch = roleLifecycleFetch(original, () => pending.promise);
    render(<ParticipantRoleWorkflow />);
    fireEvent.click(await screen.findByRole('button', { name: 'Commit approved role change' }));
    await waitFor(() => expect(rolePosts(fetch)).toHaveLength(1));
    const stored = localStorage.getItem('openpc:role-workflow:v1');
    fireEvent.change(screen.getByLabelText('Authority role ID'), { target: { value: secondId } });
    await act(async () =>
      pending.resolve(
        Response.json(commitFor(original, boundary === 'ambiguity'), { status: 202 }),
      ),
    );
    await screen.findByRole('button', { name: 'Read role after signing in' });
    expect(rolePosts(fetch)).toHaveLength(1);
    expect(localStorage.getItem('openpc:role-workflow:v1')).toBe(stored);
    fireEvent.click(screen.getByRole('button', { name: 'Read role after signing in' }));
    await waitFor(() =>
      expect(fetch.mock.calls.some(([url]) => String(url).includes(`roleId=${roleId}`))).toBe(true),
    );
    expect(fetch.mock.calls.some(([url]) => String(url).includes(`roleId=${secondId}`))).toBe(
      false,
    );
  },
);
it.each(['sessionId', 'principalId', 'participantId', 'privacyDomainId'] as const)(
  'reads sent role history after %s changes without rebinding the original seal',
  async (changedField) => {
    const original = retainApprovedRole(true);
    const stored = localStorage.getItem('openpc:role-workflow:v1');
    let changed = false;
    const nextActor = { ...actor, [changedField]: secondId };
    const fetch = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      if (init?.method === 'POST') return Response.json(commitFor(original), { status: 202 });
      if (isSession(input)) return Response.json(changed ? { ...session, ...nextActor } : session);
      if (isCatalogue(input)) return Response.json(catalogue(changed ? nextActor : actor));
      if (!fetch.mock.calls.some(([, options]) => options?.method === 'POST'))
        return Response.json(approvedWorkbench(original));
      return Response.json(
        String(input).includes('roleId=')
          ? { ...selectedState(), actor: { ...nextActor, role: 'operator' } }
          : { ...state, approvals: [approvalFor(original, 'APPROVED')] },
      );
    });
    render(<ParticipantRoleWorkflow />);
    fireEvent.click(await screen.findByRole('button', { name: 'Commit approved role change' }));
    await screen.findByRole('button', { name: 'Read role after signing in' });
    const before = fetch.mock.calls.length;
    changed = true;
    fireEvent.click(screen.getByRole('button', { name: 'Read role after signing in' }));
    await waitFor(() => expect(fetch.mock.calls.length).toBeGreaterThan(before));
    if (changedField === 'sessionId') await screen.findByText('Readback first');
    else
      await waitFor(() => expect(screen.queryByText('Private draft role')).not.toBeInTheDocument());
    expect(fetch.mock.calls.slice(before).some(([url]) => String(url).includes('roleId='))).toBe(
      changedField === 'sessionId',
    );
    expect(localStorage.getItem('openpc:role-workflow:v1')).toBe(stored);
    expect(
      screen.queryByRole('button', { name: 'Commit approved role change' }),
    ).not.toBeInTheDocument();
    expect(rolePosts(fetch)).toHaveLength(1);
  },
);
it.each(['success', 'failure'] as const)(
  'suppresses late role PREVIEW %s and custody after the form changes',
  async (outcome) => {
    const post = deferredResponse();
    const fetch = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      if (init?.method === 'POST') return post.promise;
      if (isSession(input)) return Response.json(session);
      return Response.json(isCatalogue(input) ? catalogue() : state);
    });
    render(<ParticipantRoleWorkflow />);
    fireEvent.change(await screen.findByLabelText('Role name'), {
      target: { value: 'Private draft role' },
    });
    fireEvent.change(screen.getByLabelText('Reason'), {
      target: { value: savedReview().review.reason },
    });
    const form = screen.getByRole('button', { name: 'Review role creation' }).closest('form')!;
    act(() => {
      fireEvent.submit(form);
      fireEvent.submit(form);
    });
    await waitFor(() => expect(rolePosts(fetch)).toHaveLength(1));
    fireEvent.change(screen.getByLabelText('Role name'), {
      target: { value: 'Changed local input' },
    });
    await act(async () =>
      post.resolve(
        outcome === 'success'
          ? Response.json(savedReview(), { status: 201 })
          : Response.json({ title: privateFailure }, { status: 503 }),
      ),
    );
    expect(localStorage.getItem('openpc:role-workflow:v1')).toBeNull();
    expect(document.body.textContent).not.toContain(privateFailure);
    expect(
      screen.queryByText('Review the exact role change before requesting approval.'),
    ).not.toBeInTheDocument();
  },
);
it.each(['challenge', 'navigator', 'verification'] as const)(
  'composes the actual role helper and suppresses post-unmount effects at held %s',
  async (phase) => {
    const original = retainApprovedRole();
    const actual = await vi.importActual<typeof import('@openpc/ui-shell')>('@openpc/ui-shell');
    vi.mocked(performWebAuthnStepUp).mockImplementation(actual.performWebAuthnStepUp);
    const bytes = (value: string) => new TextEncoder().encode(value).buffer;
    class Credential {
      rawId = bytes('credential');
      response = {
        authenticatorData: bytes('authenticator'),
        clientDataJSON: bytes('client'),
        signature: bytes('signature'),
      };
    }
    const challenge = {
      publicKey: {
        challenge: 'Y2hhbGxlbmdl',
        rpId: 'localhost',
        allowCredentials: [{ id: 'Y3JlZGVudGlhbA', type: 'public-key' }],
        timeout: 300000,
        userVerification: 'required',
      },
      expiresAt: new Date(Date.now() + 300_000).toISOString().replace('Z', '000Z'),
    };
    const verified = {
      status: 'verified',
      stepUpVerifiedAt: new Date().toISOString().replace('Z', '000Z'),
    };
    const pending = heldRole<Response | Credential>();
    const get = vi.fn(async () => (phase === 'navigator' ? pending.promise : new Credential()));
    vi.stubGlobal('PublicKeyCredential', Credential);
    vi.stubGlobal('navigator', { credentials: { get } });
    const fetch = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const url = String(input);
      if (url.endsWith('/assertion/challenge'))
        return phase === 'challenge'
          ? (pending.promise as Promise<Response>)
          : Response.json(challenge);
      if (url.endsWith('/assertion/verify'))
        return phase === 'verification'
          ? (pending.promise as Promise<Response>)
          : Response.json(verified);
      if (init?.method === 'POST') return Response.json(commitFor(original), { status: 202 });
      if (isSession(input)) return Response.json(session);
      return Response.json(
        isCatalogue(input)
          ? catalogue()
          : { ...state, approvals: [approvalFor(original, 'APPROVED')] },
      );
    });
    const view = render(<ParticipantRoleWorkflow />);
    fireEvent.click(await screen.findByRole('button', { name: 'Commit approved role change' }));
    await waitFor(() => {
      if (phase === 'navigator') expect(get).toHaveBeenCalledTimes(1);
      else
        expect(
          fetch.mock.calls.some(([url]) =>
            String(url).endsWith(
              phase === 'challenge' ? '/assertion/challenge' : '/assertion/verify',
            ),
          ),
        ).toBe(true);
    });
    const stored = localStorage.getItem('openpc:role-workflow:v1');
    const controls = vi.mocked(performWebAuthnStepUp).mock.calls[0]![2]!;
    view.unmount();
    expect(controls.signal!.aborted).toBe(true);
    await act(async () =>
      pending.resolve(
        phase === 'navigator'
          ? new Credential()
          : Response.json(phase === 'challenge' ? challenge : verified),
      ),
    );
    expect(rolePosts(fetch)).toHaveLength(0);
    expect(get).toHaveBeenCalledTimes(phase === 'challenge' ? 0 : 1);
    expect(
      fetch.mock.calls.filter(([url]) => String(url).endsWith('/assertion/verify')),
    ).toHaveLength(phase === 'verification' ? 1 : 0);
    expect(localStorage.getItem('openpc:role-workflow:v1')).toBe(stored);
  },
);

it('clears a saved maker review on a verified role change without restoring its old seal', async () => {
  const original = retainApprovedRole();
  const stored = localStorage.getItem('openpc:role-workflow:v1');
  let changed = false;
  const fetch = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
    if (isSession(input))
      return Response.json({ ...session, role: changed ? 'viewer' : 'operator' });
    if (isCatalogue(input)) return Response.json(catalogue());
    return Response.json({
      ...state,
      actor: { ...actor, role: changed ? 'viewer' : 'operator' },
      approvals: changed ? [] : [approvalFor(original, 'APPROVED')],
    });
  });
  render(<ParticipantRoleWorkflow />);
  await screen.findByRole('button', { name: 'Commit approved role change' });
  changed = true;
  fireEvent.click(screen.getByRole('button', { name: 'Refresh approvals' }));
  await screen.findByText('Checker');
  expect(screen.queryByText('Private draft role')).not.toBeInTheDocument();
  expect(
    screen.queryByRole('button', { name: 'Commit approved role change' }),
  ).not.toBeInTheDocument();
  expect(localStorage.getItem('openpc:role-workflow:v1')).toBe(stored);
  expect(rolePosts(fetch)).toHaveLength(0);
});
it('rejects a role workspace whose declared role differs from the authenticated session', async () => {
  retainApprovedRole();
  const stored = localStorage.getItem('openpc:role-workflow:v1');
  const fetch = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
    if (isSession(input)) return Response.json({ ...session, role: 'viewer' });
    return Response.json({ ...state, approvals: [approvalFor(savedReview(), 'APPROVED')] });
  });
  render(<ParticipantRoleWorkflow />);
  await screen.findByText(
    'The working context changed. Refresh the role workflow before continuing.',
  );
  expect(screen.queryByText('Private draft role')).not.toBeInTheDocument();
  expect(screen.queryByRole('heading', { name: 'Participant roles' })).not.toBeInTheDocument();
  expect(localStorage.getItem('openpc:role-workflow:v1')).toBe(stored);
  expect(rolePosts(fetch)).toHaveLength(0);
});

it.each(['navigator', 'verification'] as const)(
  'composes the actual role helper and checks the actual session after held %s without a UI invalidation',
  async (phase) => {
    const original = retainApprovedRole();
    const actual = await vi.importActual<typeof import('@openpc/ui-shell')>('@openpc/ui-shell');
    vi.mocked(performWebAuthnStepUp).mockImplementation(actual.performWebAuthnStepUp);
    const bytes = (value: string) => new TextEncoder().encode(value).buffer;
    class Credential {
      rawId = bytes('credential');
      response = {
        authenticatorData: bytes('authenticator'),
        clientDataJSON: bytes('client'),
        signature: bytes('signature'),
      };
    }
    const challenge = {
      publicKey: {
        challenge: 'Y2hhbGxlbmdl',
        rpId: 'localhost',
        allowCredentials: [{ id: 'Y3JlZGVudGlhbA', type: 'public-key' }],
        timeout: 300000,
        userVerification: 'required',
      },
      expiresAt: new Date(Date.now() + 300_000).toISOString().replace('Z', '000Z'),
    };
    const verified = {
      status: 'verified',
      stepUpVerifiedAt: new Date().toISOString().replace('Z', '000Z'),
    };
    let changedSession = false;
    const pending = heldRole<Response | Credential>();
    const get = vi.fn(async () => (phase === 'navigator' ? pending.promise : new Credential()));
    vi.stubGlobal('PublicKeyCredential', Credential);
    vi.stubGlobal('navigator', { credentials: { get } });
    const fetch = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const url = String(input);
      if (url.endsWith('/assertion/challenge')) return Response.json(challenge);
      if (url.endsWith('/assertion/verify'))
        return phase === 'verification'
          ? (pending.promise as Promise<Response>)
          : Response.json(verified);
      if (init?.method === 'POST') return Response.json(commitFor(original), { status: 202 });
      if (isSession(input))
        return Response.json(changedSession ? { ...session, principalId: secondId } : session);
      return Response.json(
        isCatalogue(input)
          ? catalogue()
          : { ...state, approvals: [approvalFor(original, 'APPROVED')] },
      );
    });
    render(<ParticipantRoleWorkflow />);
    fireEvent.click(await screen.findByRole('button', { name: 'Commit approved role change' }));
    await waitFor(() => {
      if (phase === 'navigator') expect(get).toHaveBeenCalledTimes(1);
      else
        expect(fetch.mock.calls.some(([url]) => String(url).endsWith('/assertion/verify'))).toBe(
          true,
        );
    });
    const stored = localStorage.getItem('openpc:role-workflow:v1');
    const controls = vi.mocked(performWebAuthnStepUp).mock.calls[0]![2]!;
    changedSession = true;
    await act(async () =>
      pending.resolve(phase === 'navigator' ? new Credential() : Response.json(verified)),
    );
    await waitFor(() => expect(controls.signal!.aborted).toBe(true));
    expect(fetch.mock.calls.filter(([url]) => isSession(url))).toHaveLength(3);
    expect(screen.queryByText('Private draft role')).not.toBeInTheDocument();
    expect(rolePosts(fetch)).toHaveLength(0);
    expect(get).toHaveBeenCalledTimes(1);
    expect(
      fetch.mock.calls.filter(([url]) => String(url).endsWith('/assertion/verify')),
    ).toHaveLength(1);
    expect(localStorage.getItem('openpc:role-workflow:v1')).toBe(stored);
  },
);

it.each([
  'sessionId',
  'principalId',
  'participantId',
  'privacyDomainId',
  'contextEpoch',
  'contextMode',
  'role',
] as const)(
  'qualifies the actual role session after held step-up when %s changes without a UI read',
  async (field) => {
    const original = retainApprovedRole();
    const pending = heldRole<void>();
    vi.mocked(performWebAuthnStepUp).mockImplementationOnce(() => pending.promise);
    let changed = false;
    const actual = {
      ...session,
      [field]:
        field === 'role'
          ? 'viewer'
          : field === 'contextMode'
            ? 'PLATFORM'
            : field === 'contextEpoch'
              ? '3'
              : secondId,
    };
    const fetch = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      if (init?.method === 'POST') return Response.json(commitFor(original), { status: 202 });
      if (isSession(input)) return Response.json(changed ? actual : session);
      return Response.json(
        isCatalogue(input)
          ? catalogue()
          : { ...state, approvals: [approvalFor(original, 'APPROVED')] },
      );
    });
    render(<ParticipantRoleWorkflow />);
    fireEvent.click(await screen.findByRole('button', { name: 'Commit approved role change' }));
    await waitFor(() => expect(performWebAuthnStepUp).toHaveBeenCalledTimes(1));
    const stored = localStorage.getItem('openpc:role-workflow:v1');
    changed = true;
    await act(async () => pending.resolve());
    await screen.findByText('The authenticated role context changed. Refresh before continuing.');
    expect(rolePosts(fetch)).toHaveLength(0);
    expect(fetch.mock.calls.filter(([url]) => isSession(url))).toHaveLength(3);
    expect(screen.queryByText('Private draft role')).not.toBeInTheDocument();
    expect(localStorage.getItem('openpc:role-workflow:v1')).toBe(stored);
  },
);
it.each(['lost', '503', '403', 'malformed'] as const)(
  'keeps an unconfirmed SENT role %s locked to its original body and read selector',
  async (failure) => {
    const original = retainApprovedRole();
    const pending = deferredResponse();
    const fetch = roleLifecycleFetch(original, () => pending.promise);
    render(<ParticipantRoleWorkflow />);
    fireEvent.click(await screen.findByRole('button', { name: 'Commit approved role change' }));
    await waitFor(() => expect(rolePosts(fetch)).toHaveLength(1));
    const stored = localStorage.getItem('openpc:role-workflow:v1');
    const sent = String(rolePosts(fetch)[0]![1]!.body);
    fireEvent.change(screen.getByLabelText('Authority role ID'), { target: { value: secondId } });
    await act(async () => {
      if (failure === 'lost') pending.reject(new Error(privateFailure));
      else
        pending.resolve(
          Response.json(
            { title: privateFailure },
            { status: failure === '503' ? 503 : failure === '403' ? 403 : 202 },
          ),
        );
    });
    await waitFor(() =>
      expect(screen.getByRole('button', { name: 'Read original role outcome' })).toBeEnabled(),
    );
    expect(screen.queryByRole('button', { name: 'Commit approved role change' })).toBeNull();
    expect(performWebAuthnStepUp).toHaveBeenCalledTimes(1);
    fireEvent.submit(screen.getByRole('button', { name: 'Find role' }).closest('form')!);
    await screen.findByText('Readback first');
    expect(fetch.mock.calls.some(([url]) => String(url).includes(`roleId=${roleId}`))).toBe(true);
    expect(fetch.mock.calls.some(([url]) => String(url).includes(`roleId=${secondId}`))).toBe(
      false,
    );
    fireEvent.submit(screen.getByRole('button', { name: 'Review role creation' }).closest('form')!);
    expect(rolePosts(fetch)).toHaveLength(1);
    expect(String(rolePosts(fetch)[0]![1]!.body)).toBe(sent);
    expect(JSON.parse(sent)).toEqual({
      command: 'COMMIT',
      reviewToken: original.reviewToken,
      approvalRequestId: original.approvalRequestId,
    });
    expect(localStorage.getItem('openpc:role-workflow:v1')).toBe(stored);
    expect(document.body.textContent).not.toContain(privateFailure);
    expect(
      screen.queryByText('Role created and its durable effect read back.'),
    ).not.toBeInTheDocument();
  },
);
it.each(['sessionId', 'principalId', 'participantId', 'privacyDomainId'] as const)(
  'preserves unconfirmed original role custody after a new %s without forwarding foreign selectors',
  async (field) => {
    const original = retainApprovedRole();
    const pending = deferredResponse();
    let changed = false;
    const nextActor = { ...actor, [field]: secondId };
    const fetch = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      if (init?.method === 'POST') return pending.promise;
      if (isSession(input)) return Response.json(changed ? { ...session, ...nextActor } : session);
      if (isCatalogue(input)) return Response.json(catalogue(changed ? nextActor : actor));
      return Response.json(
        String(input).includes('roleId=')
          ? { ...selectedState(), actor: { ...nextActor, role: 'operator' } }
          : { ...state, approvals: [approvalFor(original, 'APPROVED')] },
      );
    });
    render(<ParticipantRoleWorkflow />);
    fireEvent.click(await screen.findByRole('button', { name: 'Commit approved role change' }));
    await waitFor(() => expect(rolePosts(fetch)).toHaveLength(1));
    const stored = localStorage.getItem('openpc:role-workflow:v1');
    fireEvent.change(screen.getByLabelText('Authority role ID'), { target: { value: secondId } });
    await act(async () => pending.reject(new Error(privateFailure)));
    await waitFor(() => expect(screen.getByRole('button', { name: 'Find role' })).toBeEnabled());
    changed = true;
    const before = fetch.mock.calls.length;
    fireEvent.submit(screen.getByRole('button', { name: 'Find role' }).closest('form')!);
    if (field === 'sessionId') await screen.findByText('Readback first');
    else
      await waitFor(() =>
        expect(
          screen.queryByRole('heading', { name: 'Participant roles' }),
        ).not.toBeInTheDocument(),
      );
    expect(
      fetch.mock.calls.slice(before).some(([url]) => String(url).includes(`roleId=${roleId}`)),
    ).toBe(field === 'sessionId');
    expect(
      fetch.mock.calls.slice(before).some(([url]) => String(url).includes(`roleId=${secondId}`)),
    ).toBe(false);
    expect(localStorage.getItem('openpc:role-workflow:v1')).toBe(stored);
    expect(screen.queryByText('Private draft role')).not.toBeInTheDocument();
    expect(rolePosts(fetch)).toHaveLength(1);
  },
);

it.each(['input', 'unmount'] as const)(
  'retires a held role session qualification on %s before any business POST',
  async (retirement) => {
    const original = retainApprovedRole();
    const pending = deferredResponse();
    let sessions = 0;
    const fetch = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      if (init?.method === 'POST') return Response.json(commitFor(original), { status: 202 });
      if (isSession(input)) return ++sessions <= 2 ? Response.json(session) : pending.promise;
      return Response.json(
        isCatalogue(input)
          ? catalogue()
          : { ...state, approvals: [approvalFor(original, 'APPROVED')] },
      );
    });
    const view = render(<ParticipantRoleWorkflow />);
    fireEvent.click(await screen.findByRole('button', { name: 'Commit approved role change' }));
    await waitFor(() => expect(sessions).toBe(3));
    const stored = localStorage.getItem('openpc:role-workflow:v1');
    const controls = vi.mocked(performWebAuthnStepUp).mock.calls[0]![2]!;
    if (retirement === 'input')
      fireEvent.change(screen.getByLabelText('Authority role ID'), { target: { value: secondId } });
    else view.unmount();
    expect(controls.signal!.aborted).toBe(true);
    await act(async () => pending.resolve(Response.json(session)));
    expect(rolePosts(fetch)).toHaveLength(0);
    expect(localStorage.getItem('openpc:role-workflow:v1')).toBe(stored);
    expect(
      screen.queryByText('Role created and its durable effect read back.'),
    ).not.toBeInTheDocument();
  },
);
