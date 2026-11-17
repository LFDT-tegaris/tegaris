import { performWebAuthnStepUp } from '@openpc/ui-shell';
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';

import { RpcPlatformAccess } from './rpc-platform-access';
vi.mock('@openpc/ui-shell', () => ({
  performWebAuthnStepUp: vi.fn().mockResolvedValue(undefined),
}));

const actor = {
  sessionId: '018f0000-0000-7000-8000-000000000701',
  principalId: '018f0000-0000-7000-8000-000000000111',
  participantId: '018f0000-0000-7000-8000-000000000101',
  privacyDomainId: '018f0000-0000-7000-8000-000000000201',
  contextMode: 'PLATFORM',
  contextEpoch: '2',
  role: 'operator',
} as const;
const envelopeId = '01a0f079-1648-72ac-abe1-c0aa60dd66c3';
const participant = {
  participantId: String(actor.participantId),
  displayName: 'Local QA Participant A',
  state: 'ACTIVE',
  rowVersion: '1',
};
function state(envelopeState: 'ACTIVE' | 'REVOKED') {
  return {
    actor,
    items: [
      {
        participant,
        envelopes: [
          {
            effect: {
              id: envelopeId,
              state: envelopeState,
              revision: envelopeState === 'ACTIVE' ? '4' : '5',
              capabilityIds: ['CALL_RESULT_DISCLOSURE', 'SIGNED_TRANSACTION_SUBMISSION'],
            },
            operationId: '018f0000-0000-7000-8000-000000000901',
          },
        ],
      },
    ],
    approvals: [],
    nextCursor: null,
    authorizedEmpty: false,
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
  delete currentSession.privacyDomainId;
});

afterEach(() => {
  cleanup();
  localStorage.clear();
  vi.restoreAllMocks();
  vi.clearAllMocks();
});

it('keeps administration replacement procedures off the ordinary RPC assignment page', async () => {
  mockRequests().mockResolvedValue(Response.json(state('ACTIVE')));
  render(<RpcPlatformAccess />);
  expect(
    await screen.findByRole('heading', { name: 'RPC methods assigned to Participants' }),
  ).toBeVisible();
  expect(screen.getByLabelText('Reserved approval operation ID')).not.toBeVisible();
  expect(
    screen.queryByRole('heading', { name: 'Prepare a declared successor administrator' }),
  ).toBeNull();
  expect(
    screen.getByRole('heading', { name: 'Assign RPC methods to a Participant' }),
  ).toBeVisible();
});

it('uses the exact administration handoff surface without offering RPC grants', async () => {
  const fetch = mockRequests().mockResolvedValue(
    Response.json({
      actor,
      items: [],
      approvals: [],
      nextCursor: null,
      authorizedEmpty: false,
      handoff: {
        replacementId: '018f0000-0000-7000-8000-000000000881',
        administrator: {
          principalId: actor.principalId,
          envelopeId,
          assignmentId: '018f0000-0000-7000-8000-000000000882',
        },
        envelope: { effect: { id: envelopeId, state: 'DRAFT', revision: '1' }, operationId: null },
      },
    }),
  );
  render(<RpcPlatformAccess handoffOnly />);
  expect(await screen.findByRole('button', { name: 'Review envelope submission' })).toBeVisible();
  expect(fetch.mock.calls[0]?.[0]).toBe('/api/v1/ui/rpc-access-workbench?mode=platform-handoff');
  expect(screen.queryByRole('button', { name: 'Review RPC envelope' })).toBeNull();
  expect(screen.queryByRole('button', { name: 'Review RPC envelope revocation' })).toBeNull();
  expect(screen.getByText('DRAFT · revision 1')).toBeVisible();
});

it('reviews an active RPC envelope revocation and keeps revoked envelopes visible', async () => {
  const review = {
    reviewToken: 'r'.repeat(100),
    review: {
      kind: 'REVOKE_ENVELOPE',
      expectedRevision: '4',
      reason: 'Remove these RPC capability bounds from the Participant.',
      resourceId: envelopeId,
      targetParticipantId: actor.participantId,
      targetPrivacyDomainId: actor.privacyDomainId,
      candidateDigest: `sha256:${'a'.repeat(64)}`,
      stepUp: {
        actionIntentId: 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
        actionIntentDigest: `sha256:${'b'.repeat(64)}`,
        resourceId: envelopeId,
        resourceDigest: `sha256:${'a'.repeat(64)}`,
      },
    },
  };
  const fetch = mockRequests()
    .mockResolvedValueOnce(Response.json(state('ACTIVE')))
    .mockResolvedValueOnce(Response.json(review, { status: 201 }));
  render(<RpcPlatformAccess />);
  const user = userEvent.setup();
  await user.click(await screen.findByRole('button', { name: 'Review RPC envelope revocation' }));
  await screen.findByText('The RPC envelope revocation review is locked.');
  const request = fetch.mock.calls[1];
  expect(request?.[0]).toBe('/api/v1/ui/rpc-access-workbench');
  expect(JSON.parse(String((request?.[1] as RequestInit).body))).toEqual({
    command: 'PREVIEW_REVOKE',
    envelopeId,
    reason: 'Remove these RPC capability bounds from the Participant.',
  });

  cleanup();
  localStorage.clear();
  fetch.mockResolvedValueOnce(Response.json(state('REVOKED')));
  render(<RpcPlatformAccess />);
  expect(await screen.findByText(/REVOKED · revision 5/u)).toBeVisible();
  await waitFor(() =>
    expect(screen.queryByRole('button', { name: 'Review RPC envelope revocation' })).toBeNull(),
  );
});

it('sends the selected workload conditions and displays them in the locked review', async () => {
  const review = {
    reviewToken: 'r'.repeat(100),
    review: {
      kind: 'CREATE_ENVELOPE',
      expectedRevision: '0',
      reason: 'Permit this Participant to govern the selected RPC methods.',
      administrationActionIntentIds: [],
      administrationResourceIds: [],
      resourceId: envelopeId,
      candidateDigest: `sha256:${'a'.repeat(64)}`,
      targetParticipantId: actor.participantId,
      targetPrivacyDomainId: actor.privacyDomainId,
      makerCheckerRequired: false,
      stepUpRequired: false,
      capabilityIds: ['CALL_RESULT_DISCLOSURE'],
      stepUp: {
        actionIntentId: 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
        actionIntentDigest: `sha256:${'b'.repeat(64)}`,
        resourceId: envelopeId,
        resourceDigest: `sha256:${'a'.repeat(64)}`,
      },
    },
  };
  const fetch = mockRequests()
    .mockResolvedValueOnce(Response.json(state('ACTIVE')))
    .mockResolvedValueOnce(Response.json(review, { status: 201 }));
  render(<RpcPlatformAccess />);
  const user = userEvent.setup();
  await user.click(
    await screen.findByRole('checkbox', { name: 'Require approval for workload calls' }),
  );
  await user.click(screen.getByRole('checkbox', { name: 'Require WebAuthn for workload calls' }));
  await user.click(screen.getByRole('checkbox', { name: 'eth_sendRawTransaction' }));
  await user.type(
    screen.getByRole('textbox', { name: /Runtime binding resource IDs/u }),
    '018f0000-0000-7000-8000-000000000301',
  );
  await user.type(
    screen.getByRole('textbox', { name: 'Runtime target profile IDs' }),
    'example-rpc-v1',
  );
  await user.click(screen.getByRole('button', { name: 'Review RPC envelope' }));
  await screen.findByText('The Platform-root RPC envelope review is locked.');
  expect(JSON.parse(String(fetch.mock.calls[1]?.[1]?.body))).toMatchObject({
    command: 'PREVIEW_ENVELOPE',
    makerCheckerRequired: false,
    stepUpRequired: false,
    capabilityIds: ['CALL_RESULT_DISCLOSURE'],
  });
  expect(
    screen.getByText(/Workload approval: not required · Workload WebAuthn: not required/u),
  ).toBeVisible();
  expect(screen.getByRole('button', { name: 'Verify and request approval' })).toBeEnabled();
});

const id = (suffix: number) => `018f0000-0000-7000-8000-${String(suffix).padStart(12, '0')}`;
const digest = `sha256:${'a'.repeat(64)}`;
const storageKey = 'openpc:rpc-platform-envelope:v1';
const stepUp = {
  actionIntentId: 'ACT-IDENTITY_UPDATE_STEP_UP-V1',
  actionIntentDigest: digest,
  resourceId: actor.sessionId,
  resourceDigest: digest,
};
function handoffState(principalId: string = actor.principalId) {
  return {
    actor,
    items: [],
    approvals: [],
    nextCursor: null,
    authorizedEmpty: false,
    approvalsLoaded: false,
    handoff: {
      replacementId: id(881),
      administrator: { principalId, envelopeId, assignmentId: id(882) },
      envelope: { effect: { id: envelopeId, state: 'DRAFT', revision: '1' }, operationId: null },
    },
  };
}
function continuationReview() {
  return {
    reviewToken: 'r'.repeat(100),
    review: {
      kind: 'ACTIVATE_ENVELOPE',
      resourceId: envelopeId,
      expectedRevision: '3',
      candidateDigest: digest,
      reason:
        'Resume the original unconsumed Platform administrator handoff under fresh independent recovery custody.',
      targetParticipantId: actor.participantId,
      targetPrivacyDomainId: actor.privacyDomainId,
      continuationHandoff: { preparationApprovalId: id(919), principalId: actor.principalId },
      resumeDraft: {
        approvalRequestId: id(920),
        enrollmentId: id(921),
        recoveryId: id(922),
        intentDigest: `sha256:${'b'.repeat(64)}`,
        expiresAt: new Date(Date.now() + 600000).toISOString(),
        expectedAttempt: '1',
        requestDigest: `sha256:${'c'.repeat(64)}`,
      },
      stepUp: {
        actionIntentId: 'ACT-APPROVAL_REQUESTS_UPDATE_RESOURCE-V1',
        actionIntentDigest: digest,
        resourceId: id(920),
        resourceDigest: `sha256:${'c'.repeat(64)}`,
      },
    },
  };
}
async function reviewContinuation() {
  const user = userEvent.setup();
  await user.type(await screen.findByLabelText('Original activation approval ID'), id(920));
  await user.type(screen.getByLabelText('Receiving recovery enrollment ID'), id(921));
  await user.type(screen.getByLabelText('Receiving recovery case ID'), id(922));
  await user.click(screen.getByRole('button', { name: 'Review original activation continuation' }));
  return user;
}
it('proves the receiving request and adopts the new approval review without changing the business digest', async () => {
  const original = continuationReview();
  const base = { ...original.review, resumeDraft: undefined };
  const resumed = {
    reviewToken: 'n'.repeat(100),
    approvalRequestId: id(923),
    review: {
      ...base,
      stepUp: {
        actionIntentId: 'ACT-PARTICIPANT_ACTIVATE_CONTEXT-V1',
        actionIntentDigest: digest,
        resourceId: envelopeId,
        resourceDigest: digest,
      },
    },
  };
  const after = {
    ...handoffState(),
    approvalsLoaded: true,
    approvals: [
      {
        approvalRequestId: `urn:openpc:resource:${id(923)}`,
        state: 'REQUESTED',
        candidateDigest: digest,
      },
    ],
  };
  const fetch = mockRequests()
    .mockResolvedValueOnce(Response.json(handoffState()))
    .mockResolvedValueOnce(Response.json(original, { status: 201 }))
    .mockResolvedValueOnce(Response.json(resumed, { status: 202 }))
    .mockResolvedValueOnce(Response.json(after));
  render(<RpcPlatformAccess handoffOnly />);
  const user = await reviewContinuation();
  await user.click(
    await screen.findByRole('button', { name: 'Verify and resume original activation approval' }),
  );
  await screen.findByText(
    'The original activation approval was resumed. Independent checker approval is required.',
  );
  expect(JSON.parse(String(fetch.mock.calls[1]?.[1]?.body))).toEqual({
    command: 'PREVIEW_CONTINUE_ACTIVATION',
    approvalRequestId: id(920),
    enrollmentId: id(921),
    recoveryId: id(922),
  });
  expect(performWebAuthnStepUp).toHaveBeenCalledWith(
    expect.objectContaining({ actionIntentId: 'ACT-APPROVAL_REQUESTS_UPDATE_RESOURCE-V1' }),
    { resourceId: id(920), resourceDigest: `sha256:${'c'.repeat(64)}` },
    expect.objectContaining({ isCurrent: expect.any(Function), signal: expect.any(AbortSignal) }),
  );
  expect(JSON.parse(String(fetch.mock.calls[2]?.[1]?.body))).toEqual({
    command: 'RESUME',
    reviewToken: original.reviewToken,
  });
  expect(JSON.parse(localStorage.getItem(storageKey)!)).toMatchObject({
    reviewToken: resumed.reviewToken,
    approvalRequestId: id(923),
    review: { candidateDigest: digest },
  });
  expect(screen.queryByRole('button', { name: 'Verify and commit activation' })).toBeNull();
});
it.each(['case', 'expired', 'proof'])(
  'keeps %s continuation failure from advancing approval custody',
  async (defect) => {
    const original = continuationReview();
    if (defect === 'case') original.review.resumeDraft.recoveryId = id(999);
    if (defect === 'expired')
      original.review.resumeDraft.expiresAt = new Date(Date.now() - 1).toISOString();
    const fetch = mockRequests()
      .mockResolvedValueOnce(Response.json(handoffState()))
      .mockResolvedValueOnce(Response.json(original, { status: 201 }))
      .mockResolvedValueOnce(Response.json(handoffState()));
    render(<RpcPlatformAccess handoffOnly />);
    const user = await reviewContinuation();
    if (defect === 'proof') {
      vi.mocked(performWebAuthnStepUp).mockRejectedValueOnce(
        new Error('Receiving assertion denied'),
      );
      await user.click(
        await screen.findByRole('button', {
          name: 'Verify and resume original activation approval',
        }),
      );
    }
    await screen.findByText('The request was not completed. Refresh RPC access before continuing.');
    expect(fetch).toHaveBeenCalledTimes(2);
    expect(screen.queryByRole('button', { name: 'Verify and commit activation' })).toBeNull();
  },
);
it('keeps receiving proof controls available without reading the handoff before its assertion', async () => {
  const original = continuationReview();
  const fetch = mockRequests()
    .mockResolvedValueOnce(Response.json(handoffState()))
    .mockResolvedValueOnce(Response.json(original, { status: 201 }))
    .mockResolvedValue(Response.json({ code: 'PC-AUTH-0005' }, { status: 404 }));
  render(<RpcPlatformAccess handoffOnly />);
  await reviewContinuation();
  expect(
    await screen.findByRole('button', { name: 'Verify and resume original activation approval' }),
  ).toBeEnabled();
  expect(fetch).toHaveBeenCalledTimes(2);
  expect(performWebAuthnStepUp).not.toHaveBeenCalled();
  expect(screen.queryByRole('button', { name: 'Verify and commit activation' })).toBeNull();
});
it('reopens a resumed approval only after reading the stored exact handoff selectors', async () => {
  const original = continuationReview();
  const saved = {
    actor,
    reviewToken: 'n'.repeat(100),
    approvalRequestId: id(923),
    review: {
      ...original.review,
      resumeDraft: undefined,
      stepUp: {
        actionIntentId: 'ACT-PARTICIPANT_ACTIVATE_CONTEXT-V1',
        actionIntentDigest: digest,
        resourceId: envelopeId,
        resourceDigest: digest,
      },
    },
  };
  localStorage.setItem(storageKey, JSON.stringify(saved));
  const loaded = {
    ...handoffState(),
    approvalsLoaded: true,
    approvals: [
      {
        approvalRequestId: `urn:openpc:resource:${id(923)}`,
        state: 'REQUESTED',
        candidateDigest: digest,
      },
    ],
  };
  const fetch = mockRequests().mockResolvedValue(Response.json(loaded));
  render(<RpcPlatformAccess handoffOnly />);
  expect(await screen.findByText('Approval: REQUESTED')).toBeVisible();
  const query = new URL(String(fetch.mock.calls[0]?.[0]), 'http://owner.invalid').searchParams;
  expect(query.get('preparationApprovalId')).toBe(id(919));
  expect(query.get('principalId')).toBe(actor.principalId);
  expect(query.get('approvalRequestId')).toBe(id(923));
  expect(screen.queryByRole('button', { name: 'Verify and commit activation' })).toBeNull();
});
function linkedContinuationReview() {
  const original = continuationReview();
  return {
    reviewToken: 'n'.repeat(100),
    approvalRequestId: id(923),
    review: {
      ...original.review,
      resumeDraft: undefined,
      stepUp: {
        actionIntentId: 'ACT-PARTICIPANT_ACTIVATE_CONTEXT-V1',
        actionIntentDigest: digest,
        resourceId: envelopeId,
        resourceDigest: digest,
      },
    },
  };
}
it.each(['lost', '503', 'malformed success', 'invalid JSON'] as const)(
  'reconciles the original RESUME after %s through its effect-free reader and survives remount',
  async (failure) => {
    const original = continuationReview();
    const linked = linkedContinuationReview();
    const after = {
      ...handoffState(),
      approvalsLoaded: true,
      approvals: [
        {
          approvalRequestId: `urn:openpc:resource:${id(923)}`,
          state: 'REQUESTED',
          candidateDigest: digest,
        },
      ],
    };
    let sent = false;
    const requests = mockRequests().mockImplementation(async (_, options) => {
      if (options?.method === 'POST') {
        const body = JSON.parse(String(options.body));
        if (body.command === 'PREVIEW_CONTINUE_ACTIVATION')
          return Response.json(sent ? linked : original, { status: sent ? 200 : 201 });
        if (body.command === 'RESUME') {
          sent = true;
          if (failure === 'lost') throw new Error('PRIVATE original response loss');
          if (failure === 'invalid JSON')
            return new Response('PRIVATE invalid JSON', { status: 202 });
          return Response.json(
            { detail: 'PRIVATE malformed original response' },
            { status: failure === '503' ? 503 : 202 },
          );
        }
        throw new Error('Unexpected business command');
      }
      return Response.json(sent ? after : handoffState());
    });
    const view = render(<RpcPlatformAccess handoffOnly />);
    const user = await reviewContinuation();
    await user.click(
      await screen.findByRole('button', { name: 'Verify and resume original activation approval' }),
    );
    await screen.findByText(
      'The original activation approval was resumed. Independent checker approval is required.',
    );
    expect(screen.getByText('Approval: REQUESTED')).toBeVisible();
    const posts = requests.mock.calls
      .filter(([, options]) => options?.method === 'POST')
      .map(([, options]) => JSON.parse(String(options?.body)));
    expect(posts).toEqual([
      {
        command: 'PREVIEW_CONTINUE_ACTIVATION',
        approvalRequestId: id(920),
        enrollmentId: id(921),
        recoveryId: id(922),
      },
      { command: 'RESUME', reviewToken: original.reviewToken },
      {
        command: 'PREVIEW_CONTINUE_ACTIVATION',
        approvalRequestId: id(920),
        enrollmentId: id(921),
        recoveryId: id(922),
      },
    ]);
    expect(performWebAuthnStepUp).toHaveBeenCalledTimes(1);
    const saved = localStorage.getItem(storageKey)!;
    expect(JSON.parse(saved)).toEqual(JSON.parse(JSON.stringify({ ...linked, actor })));
    view.unmount();
    render(<RpcPlatformAccess handoffOnly />);
    expect(await screen.findByText('Approval: REQUESTED')).toBeVisible();
    const lastRead = new URL(String(requests.mock.calls.at(-1)![0]), 'https://example.test')
      .searchParams;
    expect(lastRead.get('approvalRequestId')).toBe(id(923));
    expect(lastRead.get('preparationApprovalId')).toBe(id(919));
    expect(lastRead.get('principalId')).toBe(actor.principalId);
    expect(localStorage.getItem(storageKey)).toBe(saved);
    expect(requests.mock.calls.filter(([, options]) => options?.method === 'POST')).toHaveLength(3);
    expect(screen.queryByRole('button', { name: 'Verify and commit activation' })).toBeNull();
    expect(screen.queryByText(/PRIVATE/u)).toBeNull();
  },
);
it.each(['denied', 'still draft', 'digest', 'same approval', 'changed session'] as const)(
  'keeps original RESUME custody and prevents another dispatch when reconciliation is %s',
  async (defect) => {
    const original = continuationReview();
    const linked = linkedContinuationReview();
    if (defect === 'digest') linked.review.candidateDigest = `sha256:${'e'.repeat(64)}`;
    if (defect === 'same approval') linked.approvalRequestId = id(920);
    let sent = false;
    const requests = mockRequests().mockImplementation(async (_, options) => {
      if (options?.method === 'POST') {
        const body = JSON.parse(String(options.body));
        if (body.command === 'RESUME') {
          sent = true;
          throw new Error('PRIVATE original response loss');
        }
        if (body.command === 'PREVIEW_CONTINUE_ACTIVATION') {
          if (!sent) return Response.json(original, { status: 201 });
          if (defect === 'changed session')
            currentSession = { ...currentSession, sessionId: id(799) };
          return Response.json(
            defect === 'still draft'
              ? original
              : defect === 'denied'
                ? { code: 'PC-AUTH-0005' }
                : linked,
            { status: defect === 'denied' ? 404 : 200 },
          );
        }
        throw new Error('Unexpected business command');
      }
      return Response.json(handoffState());
    });
    render(<RpcPlatformAccess handoffOnly />);
    const user = await reviewContinuation();
    const saved = localStorage.getItem(storageKey)!;
    await user.click(
      await screen.findByRole('button', { name: 'Verify and resume original activation approval' }),
    );
    await waitFor(() =>
      expect(requests.mock.calls.filter(([, options]) => options?.method === 'POST')).toHaveLength(
        3,
      ),
    );
    await waitFor(() =>
      expect(
        screen.queryByText(
          'The original activation approval was resumed. Independent checker approval is required.',
        ),
      ).toBeNull(),
    );
    expect(localStorage.getItem(storageKey)).toBe(saved);
    const resume = screen.queryByRole('button', {
      name: 'Verify and resume original activation approval',
    });
    if (resume) await user.click(resume);
    const posts = requests.mock.calls
      .filter(([, options]) => options?.method === 'POST')
      .map(([, options]) => JSON.parse(String(options?.body)));
    expect(posts.filter((body) => body.command === 'RESUME')).toEqual([
      { command: 'RESUME', reviewToken: original.reviewToken },
    ]);
    expect(posts.filter((body) => body.command === 'PREVIEW_CONTINUE_ACTIVATION').at(-1)).toEqual({
      command: 'PREVIEW_CONTINUE_ACTIVATION',
      approvalRequestId: id(920),
      enrollmentId: id(921),
      recoveryId: id(922),
    });
    expect(screen.queryByRole('button', { name: 'Verify and commit activation' })).toBeNull();
    expect(screen.queryByText(/PRIVATE/u)).toBeNull();
  },
);

it.each([
  ['mounted', 'denied'],
  ['mounted', 'still draft'],
  ['cold', 'denied'],
  ['cold', 'still draft'],
] as const)(
  'reads the original RESUME outcome after a %s %s observation without another business send',
  async (restoration, failure) => {
    const original = continuationReview();
    const linked = linkedContinuationReview();
    let sent = false;
    let available = false;
    const requests = mockRequests().mockImplementation(async (_, options) => {
      if (options?.method === 'POST') {
        const body = JSON.parse(String(options.body));
        if (body.command === 'RESUME') {
          sent = true;
          throw new Error('PRIVATE response lost after original metadata commit');
        }
        if (body.command === 'PREVIEW_CONTINUE_ACTIVATION') {
          if (!sent) return Response.json(original, { status: 201 });
          if (available) return Response.json(linked);
          return failure === 'denied'
            ? Response.json({ code: 'PC-AUTH-0005' }, { status: 404 })
            : Response.json(original);
        }
        throw new Error('Unexpected business replay');
      }
      const approval = new URL(String(_), 'https://example.test').searchParams.get(
        'approvalRequestId',
      );
      return Response.json({
        ...handoffState(),
        approvalsLoaded: !!approval,
        approvals: approval
          ? [
              {
                approvalRequestId: `urn:openpc:resource:${approval}`,
                state: 'REQUESTED',
                candidateDigest: digest,
              },
            ]
          : [],
      });
    });
    const view = render(<RpcPlatformAccess handoffOnly />);
    const user = await reviewContinuation();
    const saved = localStorage.getItem(storageKey)!;
    await user.click(
      await screen.findByRole('button', { name: 'Verify and resume original activation approval' }),
    );
    const outcome = await screen.findByRole('button', { name: 'Read original activation outcome' });
    await waitFor(() => expect(outcome).toBeEnabled());
    if (restoration === 'cold') {
      view.unmount();
      render(<RpcPlatformAccess handoffOnly />);
      await screen.findByRole('button', { name: 'Read original activation outcome' });
      const initialRead = new URL(String(requests.mock.calls.at(-1)![0]), 'https://example.test')
        .searchParams;
      expect(initialRead.get('approvalRequestId')).toBe(id(920));
      expect(initialRead.get('preparationApprovalId')).toBe(id(919));
      await user.click(
        screen.getByRole('button', { name: 'Verify and resume original activation approval' }),
      );
    }
    await user.click(screen.getByRole('button', { name: 'Read original activation outcome' }));
    await waitFor(() =>
      expect(
        screen.getByRole('button', { name: 'Read original activation outcome' }),
      ).toBeEnabled(),
    );
    expect(localStorage.getItem(storageKey)).toBe(saved);
    available = true;
    await user.click(screen.getByRole('button', { name: 'Read original activation outcome' }));
    await screen.findByText(
      'The original activation approval was resumed. Independent checker approval is required.',
    );
    expect(screen.getByText('Approval: REQUESTED')).toBeVisible();
    expect(JSON.parse(localStorage.getItem(storageKey)!)).toEqual(
      JSON.parse(JSON.stringify({ ...linked, actor })),
    );
    const posts = requests.mock.calls
      .filter(([, options]) => options?.method === 'POST')
      .map(([, options]) => JSON.parse(String(options?.body)));
    expect(posts.filter((body) => body.command === 'RESUME')).toEqual([
      { command: 'RESUME', reviewToken: original.reviewToken },
    ]);
    expect(
      posts.every((body) => ['RESUME', 'PREVIEW_CONTINUE_ACTIVATION'].includes(body.command)),
    ).toBe(true);
    expect(performWebAuthnStepUp).toHaveBeenCalledTimes(1);
    expect(screen.queryByRole('button', { name: 'Verify and commit activation' })).toBeNull();
    expect(screen.queryByText(/PRIVATE/u)).toBeNull();
  },
);

it.each(['digest', 'preparation', 'same approval', 'changed session'] as const)(
  'preserves cold original custody when its later outcome has %s',
  async (defect) => {
    const original = continuationReview();
    const saved = JSON.stringify({ ...original, actor });
    localStorage.setItem(storageKey, saved);
    const linked = linkedContinuationReview();
    if (defect === 'digest') linked.review.candidateDigest = `sha256:${'e'.repeat(64)}`;
    if (defect === 'preparation') linked.review.continuationHandoff.preparationApprovalId = id(998);
    if (defect === 'same approval') linked.approvalRequestId = id(920);
    const requests = mockRequests().mockImplementation(async (_, options) => {
      if (options?.method === 'POST') {
        expect(JSON.parse(String(options.body))).toEqual({
          command: 'PREVIEW_CONTINUE_ACTIVATION',
          approvalRequestId: id(920),
          enrollmentId: id(921),
          recoveryId: id(922),
        });
        if (defect === 'changed session')
          currentSession = { ...currentSession, sessionId: id(799) };
        return Response.json(linked);
      }
      return Response.json(handoffState());
    });
    render(<RpcPlatformAccess handoffOnly />);
    const user = userEvent.setup();
    await user.click(
      await screen.findByRole('button', { name: 'Read original activation outcome' }),
    );
    await waitFor(() =>
      expect(
        screen.getByRole('button', { name: 'Read original activation outcome' }),
      ).toBeEnabled(),
    );
    await user.click(
      screen.getByRole('button', { name: 'Verify and resume original activation approval' }),
    );
    expect(localStorage.getItem(storageKey)).toBe(saved);
    expect(requests.mock.calls.filter(([, options]) => options?.method === 'POST')).toHaveLength(1);
    expect(performWebAuthnStepUp).not.toHaveBeenCalled();
    expect(
      screen.queryByText(
        'The original activation approval was resumed. Independent checker approval is required.',
      ),
    ).toBeNull();
    expect(screen.queryByRole('button', { name: 'Verify and commit activation' })).toBeNull();
  },
);

it.each(['failure', 'proof', 'foreign digest', 'missing approval'] as const)(
  'keeps cold original custody when linked child handoff read has %s',
  async (defect) => {
    const original = continuationReview();
    const saved = JSON.stringify({ ...original, actor });
    localStorage.setItem(storageKey, saved);
    const requests = mockRequests().mockImplementation(async (input, options) => {
      if (options?.method === 'POST') {
        expect(JSON.parse(String(options.body)).command).toBe('PREVIEW_CONTINUE_ACTIVATION');
        return Response.json(linkedContinuationReview());
      }
      if (
        new URL(String(input), 'https://example.test').searchParams.get('approvalRequestId') ===
        id(923)
      ) {
        if (defect === 'failure')
          return Response.json({ code: 'PC-INTEGRATION-5001' }, { status: 503 });
        if (defect === 'proof') return Response.json({ actor, requiresStepUp: stepUp });
        return Response.json({
          ...handoffState(),
          approvalsLoaded: true,
          approvals:
            defect === 'missing approval'
              ? []
              : [
                  {
                    approvalRequestId: `urn:openpc:resource:${id(923)}`,
                    candidateDigest: `sha256:${'e'.repeat(64)}`,
                    state: 'REQUESTED',
                  },
                ],
        });
      }
      return Response.json(handoffState());
    });
    render(<RpcPlatformAccess handoffOnly />);
    const user = userEvent.setup();
    await user.click(
      await screen.findByRole('button', { name: 'Read original activation outcome' }),
    );
    await waitFor(() =>
      expect(
        requests.mock.calls.some(([input]) =>
          String(input).includes(`approvalRequestId=${id(923)}`),
        ),
      ).toBe(true),
    );
    await waitFor(() =>
      expect(screen.queryByRole('button', { name: 'Read original activation outcome' })).toBeNull(),
    );
    expect(localStorage.getItem(storageKey)).toBe(saved);
    expect(requests.mock.calls.filter(([, options]) => options?.method === 'POST')).toHaveLength(1);
    expect(performWebAuthnStepUp).not.toHaveBeenCalled();
    expect(
      screen.queryByText(
        'The original activation approval was resumed. Independent checker approval is required.',
      ),
    ).toBeNull();
    expect(screen.queryByRole('button', { name: 'Verify and commit activation' })).toBeNull();
  },
);

it.each(['lost', '503'] as const)(
  'retains the original RESUME custody after %s and reads it without replay',
  async (failure) => {
    const original = continuationReview();
    const requests = mockRequests().mockImplementation(async (_, options) => {
      if (options?.method === 'POST') {
        const body = JSON.parse(String(options.body));
        if (body.command === 'PREVIEW_CONTINUE_ACTIVATION')
          return Response.json(original, { status: 201 });
        if (body.command === 'RESUME') {
          if (failure === '503')
            return Response.json({ code: 'PC-INTEGRATION-5001' }, { status: 503 });
          throw new Error('Response lost after metadata dispatch');
        }
      }
      return Response.json(handoffState());
    });
    render(<RpcPlatformAccess handoffOnly />);
    const user = await reviewContinuation();
    await user.click(
      await screen.findByRole('button', { name: 'Verify and resume original activation approval' }),
    );
    await screen.findByText(
      'The original RPC envelope request requires authoritative reconciliation before continuing.',
    );
    expect(JSON.parse(localStorage.getItem(storageKey)!)).toMatchObject({
      reviewToken: original.reviewToken,
    });
    expect(requests.mock.calls.filter(([, options]) => options?.method === 'POST')).toHaveLength(3);
    expect(
      requests.mock.calls.some(([url]) => String(url).includes(`approvalRequestId=${id(920)}`)),
    ).toBe(true);
  },
);
function savedReview() {
  return {
    actor,
    reviewToken: 'r'.repeat(100),
    review: {
      kind: 'CREATE_ENVELOPE',
      expectedRevision: '0',
      reason: 'Permit this Participant to govern the selected RPC methods.',
      administrationActionIntentIds: [],
      administrationResourceIds: [],
      resourceId: id(990),
      candidateDigest: digest,
      targetParticipantId: actor.participantId,
      targetPrivacyDomainId: actor.privacyDomainId,
      makerCheckerRequired: true,
      stepUpRequired: true,
      capabilityIds: ['CALL_RESULT_DISCLOSURE'],
      stepUp: {
        ...stepUp,
        actionIntentId: 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
        resourceId: id(990),
      },
    },
  };
}
function savedReviewFor(handoffOnly: boolean) {
  const original = savedReview();
  return handoffOnly
    ? {
        ...original,
        review: {
          ...original.review,
          resourceId: envelopeId,
          platformScopeReplacementId: id(881),
          capabilityIds: [],
          stepUp: { ...original.review.stepUp, resourceId: envelopeId },
        },
      }
    : original;
}
function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((yes, no) => {
    resolve = yes;
    reject = no;
  });
  return { promise, resolve, reject };
}
const refreshName = (handoffOnly: boolean) =>
  handoffOnly ? 'Refresh administrator handoff' : 'Refresh Platform RPC access';

it.each([false, true])(
  'discards old mode readbacks after a newer read (handoff=%s)',
  async (handoffOnly) => {
    const old = deferred<Response>();
    const fetch = mockRequests()
      .mockReturnValueOnce(old.promise)
      .mockResolvedValueOnce(Response.json(handoffOnly ? state('ACTIVE') : handoffState()));
    const view = render(<RpcPlatformAccess handoffOnly={handoffOnly} />);
    await waitFor(() => expect(fetch).toHaveBeenCalledTimes(1));
    view.rerender(<RpcPlatformAccess handoffOnly={!handoffOnly} />);
    await screen.findByRole('button', {
      name: handoffOnly ? 'Review RPC envelope revocation' : 'Review envelope submission',
    });
    expect(fetch.mock.calls[0]?.[1]?.signal?.aborted).toBe(true);
    await act(async () =>
      old.resolve(Response.json(handoffOnly ? handoffState() : state('REVOKED'))),
    );
    expect(screen.queryByText(/REVOKED · revision/u)).toBeNull();
    expect(
      screen.queryByRole('button', {
        name: handoffOnly ? 'Review envelope submission' : 'Review RPC envelope revocation',
      }),
    ).toBeNull();
    expect(fetch).toHaveBeenCalledTimes(2);
  },
);

it.each([false, true])(
  'keeps newer data/status after an old read rejects (handoff=%s)',
  async (handoffOnly) => {
    const old = deferred<Response>();
    const fetch = mockRequests()
      .mockReturnValueOnce(old.promise)
      .mockResolvedValueOnce(Response.json(handoffOnly ? handoffState() : state('ACTIVE')));
    render(<RpcPlatformAccess handoffOnly={handoffOnly} />);
    await waitFor(() => expect(fetch).toHaveBeenCalledTimes(1));
    await userEvent.setup().click(screen.getByRole('button', { name: refreshName(handoffOnly) }));
    await screen.findByRole('button', {
      name: handoffOnly ? 'Review envelope submission' : 'Review RPC envelope revocation',
    });
    await act(async () => old.reject(new Error('secret old transport diagnostic')));
    expect(screen.getByRole('status')).toHaveTextContent(
      handoffOnly ? 'Platform administrator handoff loaded.' : 'Platform RPC assignments loaded.',
    );
    expect(screen.queryByText(/secret|unavailable/u)).toBeNull();
  },
);

it.each([false, true])(
  'guards the JSON continuation as well as fetch completion (handoff=%s)',
  async (handoffOnly) => {
    const body = deferred<unknown>();
    const old = Response.json({});
    vi.spyOn(old, 'json').mockReturnValue(body.promise);
    const fetch = mockRequests()
      .mockResolvedValueOnce(old)
      .mockResolvedValueOnce(Response.json(handoffOnly ? handoffState() : state('ACTIVE')));
    render(<RpcPlatformAccess handoffOnly={handoffOnly} />);
    await waitFor(() => expect(old.json).toHaveBeenCalled());
    await userEvent.setup().click(screen.getByRole('button', { name: refreshName(handoffOnly) }));
    await screen.findByRole('button', {
      name: handoffOnly ? 'Review envelope submission' : 'Review RPC envelope revocation',
    });
    await act(async () => body.resolve({ title: 'secret late body', items: 'invalid' }));
    expect(screen.queryByText(/secret|unavailable/u)).toBeNull();
    expect(fetch).toHaveBeenCalledTimes(2);
  },
);

it.each([false, true])(
  'masks all stale actions during refresh and after failure (handoff=%s)',
  async (handoffOnly) => {
    const pending = deferred<Response>();
    const original = JSON.stringify(savedReviewFor(handoffOnly));
    localStorage.setItem(storageKey, original);
    mockRequests()
      .mockResolvedValueOnce(Response.json(handoffOnly ? handoffState() : state('ACTIVE')))
      .mockReturnValueOnce(pending.promise);
    render(<RpcPlatformAccess handoffOnly={handoffOnly} />);
    await screen.findByRole('button', { name: 'Verify and request approval' });
    await userEvent.setup().click(screen.getByRole('button', { name: refreshName(handoffOnly) }));
    expect(screen.queryByRole('button', { name: 'Verify and request approval' })).toBeNull();
    expect(screen.queryByRole('button', { name: 'Review envelope submission' })).toBeNull();
    expect(screen.queryByRole('button', { name: 'Review RPC envelope revocation' })).toBeNull();
    await act(async () =>
      pending.resolve(
        Response.json({ title: 'secret upstream title', code: 'SECRET-CODE' }, { status: 403 }),
      ),
    );
    expect(screen.getByRole('status')).toHaveTextContent(
      'Platform RPC access is unavailable. Refresh to try again.',
    );
    expect(screen.queryByText(/secret|SECRET-CODE/u)).toBeNull();
    expect(localStorage.getItem(storageKey)).toBe(original);
  },
);

it.each([false, true])(
  'hides foreign custody on context change and preserves its bytes (handoff=%s)',
  async (handoffOnly) => {
    const original = JSON.stringify(savedReviewFor(handoffOnly));
    localStorage.setItem(storageKey, original);
    const next = {
      ...(handoffOnly ? handoffState() : state('ACTIVE')),
      actor: { ...actor, contextEpoch: '3', privacyDomainId: id(202) },
    };
    mockRequests()
      .mockResolvedValueOnce(Response.json(handoffOnly ? handoffState() : state('ACTIVE')))
      .mockResolvedValueOnce(Response.json(next));
    render(<RpcPlatformAccess handoffOnly={handoffOnly} />);
    await screen.findByRole('button', { name: 'Verify and request approval' });
    currentSession = { ...next.actor };
    await userEvent.setup().click(screen.getByRole('button', { name: refreshName(handoffOnly) }));
    await waitFor(() =>
      expect(screen.getByRole('status')).toHaveTextContent(
        handoffOnly ? 'Platform administrator handoff loaded.' : 'Platform RPC assignments loaded.',
      ),
    );
    expect(screen.queryByRole('button', { name: 'Verify and request approval' })).toBeNull();
    expect(localStorage.getItem(storageKey)).toBe(original);
    if (handoffOnly) {
      expect(screen.queryByRole('button', { name: 'Review envelope submission' })).toBeNull();
      expect(screen.getByRole('textbox', { name: 'Envelope approval ID' })).toHaveValue('');
    } else
      expect(screen.getByRole('textbox', { name: 'Participant privacy domain ID' })).toHaveValue(
        id(202),
      );
  },
);

it('replaces the Participant selector with the new eligible list and distinguishes authorized empty', async () => {
  const next = state('ACTIVE');
  next.items[0]!.participant = {
    ...participant,
    participantId: id(102),
    displayName: 'Participant B',
  };
  mockRequests()
    .mockResolvedValueOnce(Response.json(state('ACTIVE')))
    .mockResolvedValueOnce(Response.json(next))
    .mockResolvedValueOnce(Response.json({ ...next, items: [], authorizedEmpty: true }));
  render(<RpcPlatformAccess />);
  await screen.findByRole('combobox', { name: 'Participant' });
  const user = userEvent.setup();
  await user.click(screen.getByRole('button', { name: refreshName(false) }));
  expect(await screen.findByRole('combobox', { name: 'Participant' })).toHaveValue(id(102));
  expect(screen.queryByRole('option', { name: participant.displayName })).toBeNull();
  await user.click(screen.getByRole('button', { name: refreshName(false) }));
  await waitFor(() =>
    expect(screen.getByRole('status')).toHaveTextContent(
      'No authorized Participants are available.',
    ),
  );
  const emptySelector = screen.getByRole('combobox', { name: 'Participant' });
  expect(emptySelector).toHaveProperty('value', '');
  expect(emptySelector.querySelectorAll('option')).toHaveLength(0);
  expect(screen.getByRole('button', { name: 'Review RPC envelope' })).toBeDisabled();
});

it('masks old catalogue and custody for step-up, then preserves the exact authenticator binding', async () => {
  const { performWebAuthnStepUp } = await import('@openpc/ui-shell');
  const original = JSON.stringify(savedReview());
  localStorage.setItem(storageKey, original);
  mockRequests()
    .mockResolvedValueOnce(Response.json(state('ACTIVE')))
    .mockResolvedValueOnce(Response.json({ actor, requiresStepUp: stepUp }))
    .mockResolvedValueOnce(Response.json(state('ACTIVE')));
  render(<RpcPlatformAccess />);
  await screen.findByRole('button', { name: 'Verify and request approval' });
  const user = userEvent.setup();
  await user.click(screen.getByRole('button', { name: refreshName(false) }));
  const verify = await screen.findByRole('button', {
    name: 'Verify Platform authenticator and load RPC assignments',
  });
  expect(screen.queryByRole('combobox')).toBeNull();
  expect(screen.queryByRole('button', { name: 'Verify and request approval' })).toBeNull();
  expect(localStorage.getItem(storageKey)).toBe(original);
  await user.click(verify);
  expect(await screen.findByRole('button', { name: 'Verify and request approval' })).toBeVisible();
  expect(performWebAuthnStepUp).toHaveBeenCalledWith(
    { ...stepUp, stepUp: 'FRESH_WEBAUTHN_MAX_5M' },
    { resourceId: stepUp.resourceId, resourceDigest: stepUp.resourceDigest },
    expect.objectContaining({ signal: expect.any(AbortSignal), isCurrent: expect.any(Function) }),
  );
});

it('invalidates an old approval decision as soon as the handoff selector changes', async () => {
  const first = {
    ...handoffState(),
    actor: { ...actor, role: 'viewer' },
    approvalsLoaded: true,
    approvals: [
      {
        approvalRequestId: `urn:openpc:resource:${id(991)}`,
        candidateDigest: digest,
        state: 'REQUESTED',
        stepUp,
      },
    ],
  };
  currentSession = { ...first.actor };
  const fetch = mockRequests()
    .mockResolvedValueOnce(Response.json(first))
    .mockResolvedValueOnce(Response.json({ ...first, approvals: [] }));
  render(<RpcPlatformAccess handoffOnly />);
  await screen.findByRole('button', { name: 'Approve with saved passkey' });
  const user = userEvent.setup();
  await user.type(screen.getByRole('textbox', { name: 'Envelope approval ID' }), id(992));
  expect(screen.queryByRole('button', { name: 'Approve with saved passkey' })).toBeNull();
  await user.click(screen.getByRole('button', { name: 'Load envelope approval' }));
  await screen.findByText('No RPC envelope request currently requires a decision.');
  const query = new URL(String(fetch.mock.calls[1]?.[0]), 'https://example.test').searchParams;
  expect(query.get('approvalRequestId')).toBe(id(992));
});

it('masks an old administrator record on input change and reads the exact declared selection', async () => {
  const fetch = mockRequests()
    .mockResolvedValueOnce(Response.json(handoffState()))
    .mockResolvedValueOnce(Response.json(handoffState(id(112))));
  render(<RpcPlatformAccess handoffOnly />);
  await screen.findByRole('button', { name: 'Review envelope submission' });
  const user = userEvent.setup();
  await user.type(
    screen.getByRole('textbox', { name: 'Consumed replacement preparation approval ID' }),
    id(883),
  );
  expect(screen.queryByRole('button', { name: 'Review envelope submission' })).toBeNull();
  await user.type(
    screen.getByRole('textbox', { name: 'Declared administrator principal ID' }),
    id(112),
  );
  await user.click(screen.getByRole('button', { name: 'Read declared administrator records' }));
  expect(await screen.findByText(`Principal: ${id(112)}`)).toBeVisible();
  const query = new URL(String(fetch.mock.calls[1]?.[0]), 'https://example.test').searchParams;
  expect(query.get('preparationApprovalId')).toBe(id(883));
  expect(query.get('principalId')).toBe(id(112));
  expect(
    screen.getByRole('textbox', { name: 'Consumed replacement preparation approval ID' }),
  ).toHaveValue(id(883));
  expect(screen.getByRole('textbox', { name: 'Declared administrator principal ID' })).toHaveValue(
    id(112),
  );
});

it.each([
  ['invalid actor', { ...state('ACTIVE'), actor: { ...actor, contextEpoch: 'invalid' } }, false],
  ['wrong context', { ...state('ACTIVE'), actor: { ...actor, contextMode: 'PARTICIPANT' } }, false],
  [
    'invalid Participant',
    { ...state('ACTIVE'), items: [{ participant: {}, envelopes: [] }] },
    false,
  ],
  [
    'invalid envelope',
    {
      ...state('ACTIVE'),
      items: [
        {
          participant,
          envelopes: [{ effect: { id: envelopeId, state: 'INVENTED' }, operationId: null }],
        },
      ],
    },
    false,
  ],
  ['invalid approval', { ...state('ACTIVE'), approvals: [{ state: 'APPROVED' }] }, false],
  ['invalid step-up', { actor, requiresStepUp: {} }, false],
  ['wrong mode', state('ACTIVE'), true],
  [
    'mismatched handoff envelope',
    {
      ...handoffState(),
      handoff: {
        ...handoffState().handoff,
        envelope: { effect: { id: id(997), state: 'ACTIVE' }, operationId: null },
      },
    },
    true,
  ],
  [
    'invalid administrator',
    { ...handoffState(), handoff: { ...handoffState().handoff, administrator: {} } },
    true,
  ],
] as const)('rejects %s with safe failure and no action', async (_name, malformed, handoffOnly) => {
  mockRequests().mockResolvedValue(Response.json(malformed));
  render(<RpcPlatformAccess handoffOnly={handoffOnly} />);
  await waitFor(() =>
    expect(screen.getByRole('status')).toHaveTextContent('Platform RPC access is unavailable.'),
  );
  expect(screen.queryByRole('combobox')).toBeNull();
  expect(screen.queryByRole('button', { name: /Review|Approve|Verify/u })).toBeNull();
});

it.each([false, true])('redacts transport and JSON failures (handoff=%s)', async (handoffOnly) => {
  mockRequests()
    .mockRejectedValueOnce(new Error('secret transport diagnostic'))
    .mockResolvedValueOnce(new Response('secret malformed success body'));
  render(<RpcPlatformAccess handoffOnly={handoffOnly} />);
  await waitFor(() =>
    expect(screen.getByRole('status')).toHaveTextContent('Platform RPC access is unavailable.'),
  );
  await userEvent.setup().click(screen.getByRole('button', { name: refreshName(handoffOnly) }));
  await waitFor(() =>
    expect(screen.getByRole('status')).toHaveTextContent('Platform RPC access is unavailable.'),
  );
  expect(screen.queryByText(/secret/u)).toBeNull();
});

it.each([false, true])(
  'aborts on unmount and ignores a late result (handoff=%s)',
  async (handoffOnly) => {
    const pending = deferred<Response>();
    const fetch = mockRequests().mockReturnValueOnce(pending.promise);
    const view = render(<RpcPlatformAccess handoffOnly={handoffOnly} />);
    await waitFor(() => expect(fetch).toHaveBeenCalledTimes(1));
    view.unmount();
    expect(fetch.mock.calls[0]?.[1]?.signal?.aborted).toBe(true);
    await act(async () =>
      pending.resolve(Response.json(handoffOnly ? handoffState() : state('ACTIVE'))),
    );
    expect(view.container).toBeEmptyDOMElement();
  },
);

it.each([false, true])(
  'preserves malformed stored custody without rendering it (handoff=%s)',
  async (handoffOnly) => {
    const original = JSON.stringify({
      actor,
      reviewToken: 'secret invalid custody',
      review: { kind: 'invented' },
    });
    localStorage.setItem(storageKey, original);
    mockRequests().mockResolvedValueOnce(
      Response.json(handoffOnly ? handoffState() : state('ACTIVE')),
    );
    render(<RpcPlatformAccess handoffOnly={handoffOnly} />);
    await screen.findByRole('button', {
      name: handoffOnly ? 'Review envelope submission' : 'Review RPC envelope revocation',
    });
    expect(screen.queryByText(/secret|invented/u)).toBeNull();
    expect(localStorage.getItem(storageKey)).toBe(original);
  },
);

it('redacts mutation errors without changing the command or inventing a locked review', async () => {
  const fetch = mockRequests()
    .mockResolvedValueOnce(Response.json(state('ACTIVE')))
    .mockResolvedValueOnce(
      Response.json({ title: 'secret command failure', code: 'SECRET-CODE' }, { status: 403 }),
    );
  render(<RpcPlatformAccess />);
  await userEvent
    .setup()
    .click(await screen.findByRole('button', { name: 'Review RPC envelope revocation' }));
  await waitFor(() =>
    expect(screen.getByRole('status')).toHaveTextContent('The request was not completed.'),
  );
  expect(screen.queryByText(/secret|SECRET-CODE/u)).toBeNull();
  expect(screen.queryByRole('heading', { name: 'Immutable envelope review' })).toBeNull();
  expect(JSON.parse(String(fetch.mock.calls[1]?.[1]?.body))).toMatchObject({
    command: 'PREVIEW_REVOKE',
    envelopeId,
  });
});

it('keeps exact review-token custody and independent approval payload through refresh', async () => {
  const { performWebAuthnStepUp } = await import('@openpc/ui-shell');
  const original = savedReview();
  localStorage.setItem(storageKey, JSON.stringify(original));
  const submitted = {
    reviewToken: 's'.repeat(100),
    review: original.review,
    approvalRequestId: id(991),
  };
  const fetch = mockRequests()
    .mockResolvedValueOnce(Response.json(state('ACTIVE')))
    .mockResolvedValueOnce(Response.json(submitted))
    .mockResolvedValueOnce(
      Response.json({
        ...state('ACTIVE'),
        approvals: [
          {
            approvalRequestId: `urn:openpc:resource:${id(991)}`,
            candidateDigest: digest,
            state: 'REQUESTED',
          },
        ],
      }),
    );
  render(<RpcPlatformAccess />);
  await userEvent
    .setup()
    .click(await screen.findByRole('button', { name: 'Verify and request approval' }));
  expect(await screen.findByText('Approval: REQUESTED')).toBeVisible();
  expect(JSON.parse(String(fetch.mock.calls[1]?.[1]?.body))).toEqual({
    command: 'SUBMIT',
    reviewToken: original.reviewToken,
  });
  expect(performWebAuthnStepUp).toHaveBeenCalledWith(
    { ...original.review.stepUp, stepUp: 'FRESH_WEBAUTHN_MAX_5M' },
    {
      resourceId: original.review.stepUp.resourceId,
      resourceDigest: original.review.stepUp.resourceDigest,
    },
    expect.objectContaining({ signal: expect.any(AbortSignal), isCurrent: expect.any(Function) }),
  );
  expect(JSON.parse(localStorage.getItem(storageKey)!)).toEqual({
    ...submitted,
    reviewToken: original.reviewToken,
    actor,
  });
  expect(screen.queryByRole('button', { name: 'Verify and commit RPC envelope' })).toBeNull();
});

it('preserves a late mutation original without attaching its outcome to a new mode', async () => {
  const pending = deferred<Response>();
  const original = {
    ...savedReview(),
    review: {
      ...savedReview().review,
      kind: 'REVOKE_ENVELOPE',
      resourceId: envelopeId,
      expectedRevision: '4',
      stepUp: {
        ...stepUp,
        actionIntentId: 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
        resourceId: envelopeId,
      },
    },
  };
  const fetch = mockRequests()
    .mockResolvedValueOnce(Response.json(state('ACTIVE')))
    .mockReturnValueOnce(pending.promise)
    .mockResolvedValueOnce(Response.json(handoffState()));
  const view = render(<RpcPlatformAccess />);
  await userEvent
    .setup()
    .click(await screen.findByRole('button', { name: 'Review RPC envelope revocation' }));
  view.rerender(<RpcPlatformAccess handoffOnly />);
  await screen.findByText('DRAFT · revision 1');
  await act(async () =>
    pending.resolve(Response.json({ reviewToken: original.reviewToken, review: original.review })),
  );
  expect(screen.queryByRole('heading', { name: 'Immutable envelope review' })).toBeNull();
  expect(screen.getByRole('status')).toHaveTextContent('Platform administrator handoff loaded.');
  expect(JSON.parse(localStorage.getItem(storageKey)!)).toEqual(original);
  expect(fetch).toHaveBeenCalledTimes(3);
});

it.each(['approval', 'actor', 'token', 'review', 'malformed'] as const)(
  'preserves stored %s custody when an old preview arrives after a mode change',
  async (collision) => {
    const pending = deferred<Response>();
    const original = {
      ...savedReview(),
      review: {
        ...savedReview().review,
        kind: 'REVOKE_ENVELOPE',
        resourceId: envelopeId,
        expectedRevision: '4',
        stepUp: {
          ...stepUp,
          actionIntentId: 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
          resourceId: envelopeId,
        },
      },
    };
    const fetch = mockRequests()
      .mockResolvedValueOnce(Response.json(state('ACTIVE')))
      .mockReturnValueOnce(pending.promise)
      .mockResolvedValueOnce(Response.json(handoffState()));
    const view = render(<RpcPlatformAccess />);
    await userEvent
      .setup()
      .click(await screen.findByRole('button', { name: 'Review RPC envelope revocation' }));
    view.rerender(<RpcPlatformAccess handoffOnly />);
    await screen.findByText('DRAFT · revision 1');
    const retained =
      collision === 'malformed'
        ? '{retained original'
        : JSON.stringify({
            ...original,
            ...(collision === 'approval' ? { approvalRequestId: id(991) } : {}),
            ...(collision === 'actor' ? { actor: { ...actor, sessionId: id(992) } } : {}),
            ...(collision === 'token' ? { reviewToken: 'n'.repeat(100) } : {}),
            ...(collision === 'review'
              ? {
                  review: {
                    ...original.review,
                    reason: 'A different original review must remain in custody.',
                  },
                }
              : {}),
          });
    localStorage.setItem(storageKey, retained);
    await act(async () =>
      pending.resolve(
        Response.json({ reviewToken: original.reviewToken, review: original.review }),
      ),
    );
    expect(localStorage.getItem(storageKey)).toBe(retained);
    expect(screen.queryByRole('heading', { name: 'Immutable envelope review' })).toBeNull();
    expect(screen.getByRole('status')).toHaveTextContent('Platform administrator handoff loaded.');
    expect(fetch).toHaveBeenCalledTimes(3);
  },
);

it('does not restore an unrelated RPC review as the declared administrator review', async () => {
  const original = JSON.stringify(savedReview());
  localStorage.setItem(storageKey, original);
  mockRequests().mockResolvedValueOnce(Response.json(handoffState()));
  render(<RpcPlatformAccess handoffOnly />);
  await screen.findByRole('button', { name: 'Review envelope submission' });
  expect(screen.queryByRole('button', { name: 'Verify and request approval' })).toBeNull();
  expect(screen.queryByRole('heading', { name: 'Immutable envelope review' })).toBeNull();
  expect(localStorage.getItem(storageKey)).toBe(original);
});

it('requires the exact original candidate digest before offering an approved commit', async () => {
  const original = { ...savedReview(), approvalRequestId: id(991) };
  localStorage.setItem(storageKey, JSON.stringify(original));
  mockRequests().mockResolvedValueOnce(
    Response.json({
      ...state('ACTIVE'),
      approvals: [
        {
          approvalRequestId: `urn:openpc:resource:${id(991)}`,
          candidateDigest: `sha256:${'b'.repeat(64)}`,
          state: 'APPROVED',
        },
      ],
    }),
  );
  render(<RpcPlatformAccess />);
  await screen.findByRole('heading', { name: 'Immutable envelope review' });
  expect(screen.queryByRole('button', { name: 'Verify and commit RPC envelope' })).toBeNull();
  expect(localStorage.getItem(storageKey)).toBe(JSON.stringify(original));
});

it.each([false, true])(
  'accepts a current Platform session without fabricating a privacy field (handoff=%s)',
  async (handoffOnly) => {
    expect(currentSession.privacyDomainId).toBeUndefined();
    mockRequests().mockResolvedValueOnce(
      Response.json(handoffOnly ? handoffState() : state('ACTIVE')),
    );
    render(<RpcPlatformAccess handoffOnly={handoffOnly} />);
    await screen.findByRole('button', {
      name: handoffOnly ? 'Review envelope submission' : 'Review RPC envelope revocation',
    });
    expect(sessionRequests).toHaveBeenCalledTimes(2);
    expect(screen.getByRole('status')).toHaveTextContent(
      handoffOnly ? 'Platform administrator handoff loaded.' : 'Platform RPC assignments loaded.',
    );
  },
);

it.each(
  [false, true].flatMap((handoffOnly) =>
    (['fetch', 'body', 'error'] as const).map((continuation) => ({ handoffOnly, continuation })),
  ),
)(
  'checks the actual session after a delayed $continuation (handoff=$handoffOnly)',
  async ({ handoffOnly, continuation }) => {
    const pending = deferred<Response>();
    const body = deferred<unknown>();
    const response = Response.json({});
    vi.spyOn(response, 'json').mockReturnValue(body.promise);
    const requests = mockRequests().mockReturnValueOnce(
      continuation === 'body' ? Promise.resolve(response) : pending.promise,
    );
    const original = JSON.stringify(savedReviewFor(handoffOnly));
    localStorage.setItem(storageKey, original);
    render(<RpcPlatformAccess handoffOnly={handoffOnly} />);
    await waitFor(() => expect(requests).toHaveBeenCalledTimes(1));
    if (continuation === 'body') await waitFor(() => expect(response.json).toHaveBeenCalled());
    currentSession = { enabled: true, authenticated: false };
    await act(async () => {
      const payload = handoffOnly ? handoffState() : state('ACTIVE');
      if (continuation === 'body') body.resolve(payload);
      else if (continuation === 'fetch') pending.resolve(Response.json(payload));
      else pending.reject(new Error('private stale error'));
    });
    await waitFor(() =>
      expect(screen.getByRole('status')).toHaveTextContent('Platform RPC access is unavailable.'),
    );
    expect(sessionRequests).toHaveBeenCalledTimes(2);
    expect(requests).toHaveBeenCalledTimes(1);
    expect(screen.queryByRole('button', { name: /Review|Verify|Approve/u })).toBeNull();
    expect(screen.queryByText(/private stale/u)).toBeNull();
    expect(localStorage.getItem(storageKey)).toBe(original);
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
  { contextMode: 'PARTICIPANT' },
  { role: 'viewer' },
  { enabled: false },
])(
  'does not display an old Platform catalogue after session binding changes to %s',
  async (change) => {
    const pending = deferred<Response>();
    const requests = mockRequests().mockReturnValueOnce(pending.promise);
    render(<RpcPlatformAccess />);
    await waitFor(() => expect(requests).toHaveBeenCalledTimes(1));
    currentSession = { ...currentSession, ...change };
    await act(async () => pending.resolve(Response.json(state('ACTIVE'))));
    await waitFor(() =>
      expect(screen.getByRole('status')).toHaveTextContent('Platform RPC access is unavailable.'),
    );
    expect(screen.queryByRole('combobox')).toBeNull();
    expect(screen.queryByRole('button', { name: 'Review RPC envelope revocation' })).toBeNull();
    expect(requests).toHaveBeenCalledTimes(1);
  },
);

it.each([
  { sessionId: id(702) },
  { principalId: id(112) },
  { participantId: id(102) },
  { contextEpoch: '3' },
  { role: 'viewer' },
])(
  'rejects a Platform RPC actor that differs from its stable current session by %s',
  async (change) => {
    mockRequests().mockResolvedValueOnce(
      Response.json({ ...state('ACTIVE'), actor: { ...actor, ...change } }),
    );
    render(<RpcPlatformAccess />);
    await waitFor(() =>
      expect(screen.getByRole('status')).toHaveTextContent('Platform RPC access is unavailable.'),
    );
    expect(screen.queryByRole('button', { name: 'Review RPC envelope revocation' })).toBeNull();
    expect(sessionRequests).toHaveBeenCalledTimes(2);
  },
);

it('matches Platform privacy when the actual session provides it', async () => {
  currentSession = { ...actor };
  mockRequests().mockResolvedValueOnce(
    Response.json({ ...state('ACTIVE'), actor: { ...actor, privacyDomainId: id(202) } }),
  );
  render(<RpcPlatformAccess />);
  await waitFor(() =>
    expect(screen.getByRole('status')).toHaveTextContent('Platform RPC access is unavailable.'),
  );
  expect(screen.queryByRole('button', { name: 'Review RPC envelope revocation' })).toBeNull();
});

it.each([{ enabled: false }, { authenticated: false }, { contextMode: 'PARTICIPANT' }])(
  'does not start the RPC read without a current Platform session (%s)',
  async (change) => {
    currentSession = { ...currentSession, ...change };
    const requests = mockRequests();
    render(<RpcPlatformAccess />);
    await waitFor(() =>
      expect(screen.getByRole('status')).toHaveTextContent('Platform RPC access is unavailable.'),
    );
    expect(requests).not.toHaveBeenCalled();
    expect(sessionRequests).toHaveBeenCalledTimes(1);
  },
);

it.each(
  (['pending-administrator', 'submission'] as const).flatMap((preview) =>
    (['preparation', 'administrator', 'envelope-approval'] as const).map((selector) => ({
      preview,
      selector,
    })),
  ),
)(
  'keeps a late $preview review masked after a same-actor $selector edit',
  async ({ preview, selector }) => {
    const pending = deferred<Response>();
    const retained = savedReviewFor(true);
    const next = {
      reviewToken: retained.reviewToken,
      review: {
        ...retained.review,
        kind: preview === 'submission' ? 'SUBMIT_ENVELOPE' : 'CREATE_ENVELOPE',
        expectedRevision: preview === 'submission' ? '1' : '0',
        capabilityIds: [],
        platformScopeReplacementId: id(881),
        stepUp: {
          ...retained.review.stepUp,
          actionIntentId:
            preview === 'submission'
              ? 'ACT-APPROVAL_REQUESTS_CREATE_RESOURCE-V1'
              : 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
          resourceDigest: preview === 'submission' ? `sha256:${'b'.repeat(64)}` : digest,
        },
      },
    };
    const requests = mockRequests()
      .mockResolvedValueOnce(Response.json(handoffState()))
      .mockReturnValueOnce(pending.promise);
    render(<RpcPlatformAccess handoffOnly />);
    const user = userEvent.setup();
    await screen.findByRole('button', { name: 'Review envelope submission' });
    if (preview === 'pending-administrator') {
      await user.type(
        screen.getByRole('textbox', { name: 'Consumed replacement preparation approval ID' }),
        id(883),
      );
      await user.type(
        screen.getByRole('textbox', { name: 'Declared administrator principal ID' }),
        id(112),
      );
      await user.click(
        screen.getByRole('button', { name: 'Review declared administration envelope' }),
      );
    } else await user.click(screen.getByRole('button', { name: 'Review envelope submission' }));
    await waitFor(() => expect(requests).toHaveBeenCalledTimes(2));
    const originalRequest = String(requests.mock.calls[1]?.[1]?.body);
    const label =
      selector === 'preparation'
        ? 'Consumed replacement preparation approval ID'
        : selector === 'administrator'
          ? 'Declared administrator principal ID'
          : 'Envelope approval ID';
    const input = screen.getByRole('textbox', { name: label });
    await user.clear(input);
    await user.type(input, id(994));
    await act(async () => pending.resolve(Response.json(next)));
    await waitFor(() =>
      expect(
        screen.getByRole('button', { name: 'Review declared administration envelope' }),
      ).toBeEnabled(),
    );
    expect(screen.queryByRole('heading', { name: 'Immutable envelope review' })).toBeNull();
    expect(screen.queryByRole('button', { name: 'Verify and request approval' })).toBeNull();
    expect(screen.getByRole('status')).not.toHaveTextContent(
      /review is locked|ready for independent approval/u,
    );
    expect(String(requests.mock.calls[1]?.[1]?.body)).toBe(originalRequest);
    expect(JSON.parse(originalRequest)).toMatchObject(
      preview === 'submission'
        ? { command: 'PREVIEW_SUBMIT', envelopeId }
        : {
            command: 'PREVIEW_PENDING_ADMINISTRATOR',
            approvalRequestId: id(883),
            principalId: id(112),
          },
    );
    // Preserve the late original; storage collision/custody policy is separately OPEN.
    expect(JSON.parse(localStorage.getItem(storageKey)!)).toEqual({ ...next, actor });
    expect(requests).toHaveBeenCalledTimes(2);
    expect(sessionRequests).toHaveBeenCalledTimes(2);
  },
);

it.each(['success', 'failure'] as const)(
  'does not restore a late revocation %s after the reserved approval selection changes',
  async (outcome) => {
    const pending = deferred<Response>();
    const retained = savedReview();
    const requests = mockRequests()
      .mockResolvedValueOnce(Response.json(state('ACTIVE')))
      .mockReturnValueOnce(pending.promise);
    render(<RpcPlatformAccess />);
    const user = userEvent.setup();
    await user.click(await screen.findByRole('button', { name: 'Review RPC envelope revocation' }));
    await waitFor(() => expect(requests).toHaveBeenCalledTimes(2));
    await user.click(screen.getByRole('button', { name: 'Approval references' }));
    await user.type(
      screen.getByRole('textbox', { name: 'Reserved approval operation ID' }),
      id(991),
    );
    await act(async () => {
      if (outcome === 'success')
        pending.resolve(
          Response.json({
            reviewToken: retained.reviewToken,
            review: {
              ...retained.review,
              kind: 'REVOKE_ENVELOPE',
              resourceId: envelopeId,
              expectedRevision: '4',
              stepUp: {
                ...stepUp,
                actionIntentId: 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
                resourceId: envelopeId,
              },
            },
          }),
        );
      else pending.reject(new Error('private old command error'));
    });
    await waitFor(() =>
      expect(screen.getByRole('button', { name: 'Review RPC envelope revocation' })).toBeEnabled(),
    );
    expect(screen.queryByRole('heading', { name: 'Immutable envelope review' })).toBeNull();
    expect(screen.getByRole('status')).toHaveTextContent('Platform RPC assignments loaded.');
    expect(requests).toHaveBeenCalledTimes(2);
  },
);

function revokeReview() {
  const original = savedReview();
  return {
    ...original,
    review: {
      ...original.review,
      kind: 'REVOKE_ENVELOPE',
      resourceId: envelopeId,
      expectedRevision: '4',
      reason: 'Remove these RPC capability bounds from the Participant.',
      stepUp: { ...original.review.stepUp, resourceId: envelopeId },
    },
  };
}
function fullDecisionApproval() {
  return {
    approvalRequestId: `urn:openpc:resource:${id(991)}`,
    actionIntentId: 'ACT-APPROVAL_REQUESTS_CREATE_RESOURCE-V1',
    candidateDigest: digest,
    state: 'APPROVED',
    makerSubjectRef: `urn:openpc:resource:${id(111)}`,
    checkerSubjectRef: `urn:openpc:resource:${id(112)}`,
    revision: '2',
    createdAt: '2026-10-04T00:00:00.000Z',
    updatedAt: '2026-10-04T00:00:01.000Z',
  };
}
function decisionOperation() {
  return {
    operationId: id(902),
    actionIntentId: 'ACT-POLICY_APPROVE_REQUEST-V1',
    intentDigest: digest,
    idempotencyKey: 'workbench-approve-original',
    resourceRef: `urn:openpc:resource:${id(991)}`,
    revision: '1',
    state: 'SUCCEEDED',
    truthState: 'SUCCESS',
    createdAt: '2026-10-04T00:00:00.000Z',
    updatedAt: '2026-10-04T00:00:01.000Z',
  };
}
function committedRpc(
  original: ReturnType<typeof savedReview> & {
    review: ReturnType<typeof savedReview>['review'] & { platformScopeReplacementId?: string };
  } = savedReview(),
) {
  return {
    effect: {
      operationId: null,
      effect: {
        id: original.review.resourceId,
        participantId: original.review.targetParticipantId,
        privacyDomainIds: [original.review.targetPrivacyDomainId],
        state:
          original.review.kind === 'CREATE_ENVELOPE'
            ? 'DRAFT'
            : original.review.kind === 'ACTIVATE_ENVELOPE'
              ? 'ACTIVE'
              : 'REVOKED',
        authorityEpoch: '2',
        revision: '5',
        capabilityIds: original.review.capabilityIds,
        resourceIds: [],
        validFrom: '2026-10-04T00:00:00.000Z',
        validUntil: null,
        makerCheckerRequired: true,
        stepUpRequired: true,
        semanticDigest: `sha256:${'b'.repeat(64)}`,
        ...(original.review.platformScopeReplacementId
          ? { platformScopeReplacementId: original.review.platformScopeReplacementId }
          : {}),
      },
    },
  };
}

it.each([
  {
    name: 'different capability',
    required: ['CALL_RESULT_DISCLOSURE'],
    returned: ['SIGNED_TRANSACTION_SUBMISSION'],
    handoffOnly: false,
  },
  {
    name: 'extra capability',
    required: ['CALL_RESULT_DISCLOSURE'],
    returned: ['CALL_RESULT_DISCLOSURE', 'SIGNED_TRANSACTION_SUBMISSION'],
    handoffOnly: false,
  },
  {
    name: 'missing one required capability',
    required: ['CALL_RESULT_DISCLOSURE', 'SIGNED_TRANSACTION_SUBMISSION'],
    returned: ['CALL_RESULT_DISCLOSURE'],
    handoffOnly: false,
  },
  {
    name: 'empty capabilities instead of required capability',
    required: ['CALL_RESULT_DISCLOSURE'],
    returned: [],
    handoffOnly: false,
  },
  {
    name: 'omitted required capabilities',
    required: ['CALL_RESULT_DISCLOSURE'],
    returned: undefined,
    handoffOnly: false,
  },
  {
    name: 'runtime capability in runtime-free administrator handoff',
    required: [],
    returned: ['CALL_RESULT_DISCLOSURE'],
    handoffOnly: true,
  },
])('retains exact CREATE custody after $name', async ({ required, returned, handoffOnly }) => {
  const saved = savedReviewFor(handoffOnly);
  const original = {
    ...saved,
    approvalRequestId: id(991),
    review: { ...saved.review, capabilityIds: required },
  };
  const raw = JSON.stringify(original);
  localStorage.setItem(storageKey, raw);
  const effect = committedRpc(original).effect;
  const response = { effect: { ...effect, effect: { ...effect.effect, capabilityIds: returned } } };
  const requests = mockRequests()
    .mockResolvedValueOnce(
      Response.json({
        ...(handoffOnly ? handoffState() : state('ACTIVE')),
        approvals: [fullDecisionApproval()],
      }),
    )
    .mockResolvedValueOnce(Response.json(response));
  render(<RpcPlatformAccess handoffOnly={handoffOnly} />);
  await userEvent
    .setup()
    .click(await screen.findByRole('button', { name: 'Verify and commit RPC envelope' }));
  await waitFor(() =>
    expect(screen.getByRole('status')).toHaveTextContent('The request was not completed.'),
  );
  expect(localStorage.getItem(storageKey)).toBe(raw);
  expect(screen.getByRole('heading', { name: 'Immutable envelope review' })).toBeVisible();
  expect(screen.getByRole('button', { name: 'Verify and commit RPC envelope' })).toBeEnabled();
  expect(requests).toHaveBeenCalledTimes(2);
  expect(sessionRequests).toHaveBeenCalledTimes(3);
  expect(JSON.parse(String(requests.mock.calls[1]?.[1]?.body))).toEqual({
    command: 'COMMIT',
    reviewToken: original.reviewToken,
    approvalRequestId: original.approvalRequestId,
  });
  expect(requests.mock.calls.filter(([, options]) => options?.method === 'POST')).toHaveLength(1);
  expect(requests.mock.calls.filter(([url]) => String(url).includes('/envelopes/'))).toHaveLength(
    0,
  );
});

it.each([
  {
    name: 'order-equivalent capabilities',
    required: ['CALL_RESULT_DISCLOSURE', 'SIGNED_TRANSACTION_SUBMISSION'],
    returned: ['SIGNED_TRANSACTION_SUBMISSION', 'CALL_RESULT_DISCLOSURE'],
    handoffOnly: false,
  },
  {
    name: 'empty runtime-free administrator capabilities',
    required: [],
    returned: [],
    handoffOnly: true,
  },
  {
    name: 'omitted runtime-free administrator capabilities',
    required: [],
    returned: undefined,
    handoffOnly: true,
  },
])('accepts authoritative CREATE with $name', async ({ required, returned, handoffOnly }) => {
  const saved = savedReviewFor(handoffOnly);
  const original = {
    ...saved,
    approvalRequestId: id(991),
    review: { ...saved.review, capabilityIds: required },
  };
  localStorage.setItem(storageKey, JSON.stringify(original));
  const effect = committedRpc(original).effect;
  const response = { effect: { ...effect, effect: { ...effect.effect, capabilityIds: returned } } };
  const next = {
    ...(handoffOnly ? handoffState() : state('ACTIVE')),
    approvals: [fullDecisionApproval()],
  };
  const requests = mockRequests()
    .mockResolvedValueOnce(Response.json(next))
    .mockResolvedValueOnce(Response.json(response))
    .mockResolvedValueOnce(Response.json(next));
  render(<RpcPlatformAccess handoffOnly={handoffOnly} />);
  await userEvent
    .setup()
    .click(await screen.findByRole('button', { name: 'Verify and commit RPC envelope' }));
  await waitFor(() => expect(localStorage.getItem(storageKey)).toBeNull());
  await waitFor(() => expect(screen.getByRole('status')).toHaveTextContent('is durable'));
  expect(screen.queryByRole('heading', { name: 'Immutable envelope review' })).toBeNull();
  expect(requests).toHaveBeenCalledTimes(3);
  expect(sessionRequests).toHaveBeenCalledTimes(5);
  expect(JSON.parse(String(requests.mock.calls[1]?.[1]?.body))).toEqual({
    command: 'COMMIT',
    reviewToken: original.reviewToken,
    approvalRequestId: original.approvalRequestId,
  });
  expect(requests.mock.calls.filter(([, options]) => options?.method === 'POST')).toHaveLength(1);
  expect(requests.mock.calls.filter(([url]) => String(url).includes('/envelopes/'))).toHaveLength(
    0,
  );
});

it.each([
  null,
  {},
  { reviewToken: 'SECRET-TOKEN', review: revokeReview().review },
  { ...revokeReview(), review: { ...revokeReview().review, expectedRevision: undefined } },
  { ...revokeReview(), review: { ...revokeReview().review, kind: 'SUBMIT_ENVELOPE' } },
  { ...revokeReview(), review: { ...revokeReview().review, resourceId: id(999) } },
  { ...revokeReview(), review: { ...revokeReview().review, targetParticipantId: id(102) } },
  { ...revokeReview(), review: { ...revokeReview().review, targetPrivacyDomainId: id(202) } },
  { ...revokeReview(), review: { ...revokeReview().review, candidateDigest: 'SECRET-DIGEST' } },
  {
    ...revokeReview(),
    review: {
      ...revokeReview().review,
      stepUp: { ...revokeReview().review.stepUp, resourceId: id(999) },
    },
  },
])('rejects a malformed or foreign revocation preview before saving it (%j)', async (response) => {
  const requests = mockRequests()
    .mockResolvedValueOnce(Response.json(state('ACTIVE')))
    .mockResolvedValueOnce(Response.json(response));
  render(<RpcPlatformAccess />);
  await userEvent
    .setup()
    .click(await screen.findByRole('button', { name: 'Review RPC envelope revocation' }));
  await waitFor(() =>
    expect(screen.getByRole('status')).toHaveTextContent('The request was not completed.'),
  );
  expect(localStorage.getItem(storageKey)).toBeNull();
  expect(screen.queryByRole('heading', { name: 'Immutable envelope review' })).toBeNull();
  expect(screen.queryByText(/SECRET-/u)).toBeNull();
  expect(requests).toHaveBeenCalledTimes(2);
});

it('accepts the actual runtime-free pending-administrator review DTO', async () => {
  const original = savedReviewFor(true);
  const response = {
    ...original,
    review: {
      ...original.review,
      administrationActionIntentIds: ['ACT-PARTICIPANTS_UPDATE_RESOURCE-V1'],
      administrationResourceIds: ['*'],
    },
  };
  const requests = mockRequests()
    .mockResolvedValueOnce(Response.json(handoffState()))
    .mockResolvedValueOnce(Response.json(response));
  render(<RpcPlatformAccess handoffOnly />);
  const user = userEvent.setup();
  await user.type(
    await screen.findByRole('textbox', { name: 'Consumed replacement preparation approval ID' }),
    id(883),
  );
  await user.type(
    screen.getByRole('textbox', { name: 'Declared administrator principal ID' }),
    actor.principalId,
  );
  await user.click(screen.getByRole('button', { name: 'Review declared administration envelope' }));
  expect(await screen.findByRole('heading', { name: 'Immutable envelope review' })).toBeVisible();
  expect(JSON.parse(localStorage.getItem(storageKey)!)).toEqual(response);
  expect(JSON.parse(String(requests.mock.calls[1]?.[1]?.body))).toMatchObject({
    command: 'PREVIEW_PENDING_ADMINISTRATOR',
    principalId: actor.principalId,
  });
});

it('accepts submission review step-up digest distinct from the candidate and forbids COMMIT', async () => {
  const original = savedReviewFor(true);
  const next = {
    reviewToken: original.reviewToken,
    review: {
      kind: 'SUBMIT_ENVELOPE',
      resourceId: envelopeId,
      candidateDigest: digest,
      targetParticipantId: actor.participantId,
      targetPrivacyDomainId: actor.privacyDomainId,
      expectedRevision: '1',
      reason: 'Submit the typed Platform-root RPC envelope for independent approval.',
      stepUp: {
        ...original.review.stepUp,
        actionIntentId: 'ACT-APPROVAL_REQUESTS_CREATE_RESOURCE-V1',
        resourceDigest: `sha256:${'b'.repeat(64)}`,
      },
    },
  };
  mockRequests()
    .mockResolvedValueOnce(Response.json(handoffState()))
    .mockResolvedValueOnce(Response.json(next))
    .mockResolvedValueOnce(
      Response.json({ ...next, reviewToken: 's'.repeat(100), approvalRequestId: id(991) }),
    )
    .mockResolvedValueOnce(
      Response.json({
        ...handoffState(),
        approvalsLoaded: true,
        approvals: [fullDecisionApproval()],
      }),
    );
  render(<RpcPlatformAccess handoffOnly />);
  const user = userEvent.setup();
  await user.click(await screen.findByRole('button', { name: 'Review envelope submission' }));
  await user.click(
    await screen.findByRole('button', { name: 'Verify and request submission approval' }),
  );
  expect(await screen.findByText('Envelope submission approval requested.')).toBeVisible();
  expect(JSON.parse(localStorage.getItem(storageKey)!)).toMatchObject({
    reviewToken: original.reviewToken,
    approvalRequestId: id(991),
  });
  expect(screen.queryByRole('button', { name: 'Verify and commit RPC envelope' })).toBeNull();
});

it.each([
  {},
  { ...savedReview(), approvalRequestId: 'SECRET-ID' },
  {
    ...savedReview(),
    approvalRequestId: id(991),
    review: {
      ...savedReview().review,
      candidateDigest: `sha256:${'b'.repeat(64)}`,
      stepUp: { ...savedReview().review.stepUp, resourceDigest: `sha256:${'b'.repeat(64)}` },
    },
  },
  {
    ...savedReview(),
    approvalRequestId: id(991),
    review: { ...savedReview().review, reason: 'A different immutable business intent.' },
  },
])('retains exact raw custody after invalid SUBMIT success (%j)', async (response) => {
  const original = JSON.stringify(savedReview());
  localStorage.setItem(storageKey, original);
  const requests = mockRequests()
    .mockResolvedValueOnce(Response.json(state('ACTIVE')))
    .mockResolvedValueOnce(Response.json(response));
  render(<RpcPlatformAccess />);
  await userEvent
    .setup()
    .click(await screen.findByRole('button', { name: 'Verify and request approval' }));
  await waitFor(() =>
    expect(screen.getByRole('status')).toHaveTextContent('The request was not completed.'),
  );
  expect(localStorage.getItem(storageKey)).toBe(original);
  expect(requests).toHaveBeenCalledTimes(2);
  expect(screen.queryByText(/SECRET-ID/u)).toBeNull();
});

it.each(['CREATE_ENVELOPE', 'ACTIVATE_ENVELOPE', 'REVOKE_ENVELOPE'] as const)(
  'accepts the direct authoritative %s COMMIT row with null operation id',
  async (kind) => {
    const original = {
      ...savedReview(),
      approvalRequestId: id(991),
      review: {
        ...savedReview().review,
        kind,
        expectedRevision:
          kind === 'CREATE_ENVELOPE' ? '0' : kind === 'ACTIVATE_ENVELOPE' ? '3' : '4',
        stepUp: {
          ...savedReview().review.stepUp,
          actionIntentId:
            kind === 'ACTIVATE_ENVELOPE'
              ? 'ACT-PARTICIPANT_ACTIVATE_CONTEXT-V1'
              : 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
        },
      },
    };
    localStorage.setItem(storageKey, JSON.stringify(original));
    const requests = mockRequests()
      .mockResolvedValueOnce(
        Response.json({ ...state('ACTIVE'), approvals: [fullDecisionApproval()] }),
      )
      .mockResolvedValueOnce(Response.json(committedRpc(original)))
      .mockResolvedValueOnce(
        Response.json(state(kind === 'REVOKE_ENVELOPE' ? 'REVOKED' : 'ACTIVE')),
      );
    render(<RpcPlatformAccess />);
    await userEvent.setup().click(
      await screen.findByRole('button', {
        name:
          kind === 'CREATE_ENVELOPE'
            ? 'Verify and commit RPC envelope'
            : kind === 'ACTIVATE_ENVELOPE'
              ? 'Verify and commit activation'
              : 'Verify and commit revocation',
      }),
    );
    await waitFor(() => expect(localStorage.getItem(storageKey)).toBeNull());
    await waitFor(() =>
      expect(screen.getByRole('status')).toHaveTextContent(
        kind === 'CREATE_ENVELOPE'
          ? 'is durable'
          : `is ${kind === 'ACTIVATE_ENVELOPE' ? 'ACTIVE' : 'REVOKED'}`,
      ),
    );
    expect(requests).toHaveBeenCalledTimes(3);
    expect(requests.mock.calls.filter(([url]) => String(url).includes('/envelopes/'))).toHaveLength(
      0,
    );
  },
);

it.each([
  {},
  { operationId: id(902) },
  { effect: { ...committedRpc().effect, operationId: id(902) } },
  {
    effect: { ...committedRpc().effect, effect: { ...committedRpc().effect.effect, id: id(999) } },
  },
  {
    effect: {
      ...committedRpc().effect,
      effect: { ...committedRpc().effect.effect, state: 'ACTIVE' },
    },
  },
  {
    effect: {
      ...committedRpc().effect,
      effect: { ...committedRpc().effect.effect, privacyDomainIds: [id(202)] },
    },
  },
  {
    effect: {
      ...committedRpc().effect,
      effect: { ...committedRpc().effect.effect, participantId: id(102) },
    },
  },
])('does not clear custody for malformed or mismatched COMMIT success (%j)', async (response) => {
  const original = JSON.stringify({ ...savedReview(), approvalRequestId: id(991) });
  localStorage.setItem(storageKey, original);
  const requests = mockRequests()
    .mockResolvedValueOnce(
      Response.json({ ...state('ACTIVE'), approvals: [fullDecisionApproval()] }),
    )
    .mockResolvedValueOnce(Response.json(response));
  render(<RpcPlatformAccess />);
  await userEvent
    .setup()
    .click(await screen.findByRole('button', { name: 'Verify and commit RPC envelope' }));
  await waitFor(() =>
    expect(screen.getByRole('status')).toHaveTextContent('The request was not completed.'),
  );
  expect(localStorage.getItem(storageKey)).toBe(original);
  expect(requests).toHaveBeenCalledTimes(2);
  expect(screen.getByRole('heading', { name: 'Immutable envelope review' })).toBeVisible();
});

it.each([true, false])(
  'accepts the actual reconciled=%s checker decision variant',
  async (reconciled) => {
    const checker = { ...actor, principalId: id(112), role: 'viewer' };
    currentSession = { ...checker };
    delete currentSession.privacyDomainId;
    const requests = mockRequests()
      .mockResolvedValueOnce(
        Response.json({
          ...state('ACTIVE'),
          actor: checker,
          approvals: [
            {
              ...fullDecisionApproval(),
              state: 'REQUESTED',
              stepUp: { ...stepUp, resourceId: id(991) },
            },
          ],
        }),
      )
      .mockResolvedValueOnce(
        Response.json(
          reconciled
            ? { reconciled: true, approval: fullDecisionApproval() }
            : { operation: decisionOperation(), approval: fullDecisionApproval() },
        ),
      )
      .mockResolvedValueOnce(
        Response.json({ ...state('ACTIVE'), actor: checker, approvals: [fullDecisionApproval()] }),
      );
    render(<RpcPlatformAccess />);
    await userEvent
      .setup()
      .click(await screen.findByRole('button', { name: 'Approve with saved passkey' }));
    expect(await screen.findByText('The exact RPC envelope candidate was approved.')).toBeVisible();
    expect(requests).toHaveBeenCalledTimes(3);
  },
);

it.each([
  {},
  { approval: fullDecisionApproval() },
  {
    reconciled: true,
    approval: { ...fullDecisionApproval(), candidateDigest: `sha256:${'b'.repeat(64)}` },
  },
  {
    reconciled: true,
    approval: { ...fullDecisionApproval(), approvalRequestId: `urn:openpc:resource:${id(992)}` },
  },
  {
    reconciled: true,
    approval: { ...fullDecisionApproval(), checkerSubjectRef: `urn:openpc:resource:${id(113)}` },
  },
  {
    operation: { ...decisionOperation(), resourceRef: `urn:openpc:resource:${id(992)}` },
    approval: fullDecisionApproval(),
  },
])('does not refresh or claim approval after mismatched checker success (%j)', async (response) => {
  const checker = { ...actor, principalId: id(112), role: 'viewer' };
  currentSession = { ...checker };
  delete currentSession.privacyDomainId;
  const requests = mockRequests()
    .mockResolvedValueOnce(
      Response.json({
        ...state('ACTIVE'),
        actor: checker,
        approvals: [
          {
            ...fullDecisionApproval(),
            state: 'REQUESTED',
            stepUp: { ...stepUp, resourceId: id(991) },
          },
        ],
      }),
    )
    .mockResolvedValueOnce(Response.json(response));
  render(<RpcPlatformAccess />);
  await userEvent
    .setup()
    .click(await screen.findByRole('button', { name: 'Approve with saved passkey' }));
  await waitFor(() =>
    expect(screen.getByRole('status')).toHaveTextContent('The request was not completed.'),
  );
  expect(requests).toHaveBeenCalledTimes(2);
  expect(screen.queryByText('The exact RPC envelope candidate was approved.')).toBeNull();
});

it.each([true, false])(
  'matches declared handoff replacement in direct COMMIT (matching=%s)',
  async (matching) => {
    const original = { ...savedReviewFor(true), approvalRequestId: id(991) };
    const raw = JSON.stringify(original);
    localStorage.setItem(storageKey, raw);
    const response = committedRpc(original);
    const requests = mockRequests()
      .mockResolvedValueOnce(
        Response.json({
          ...handoffState(),
          approvalsLoaded: true,
          approvals: [fullDecisionApproval()],
        }),
      )
      .mockResolvedValueOnce(
        Response.json({
          effect: {
            ...response.effect,
            effect: {
              ...response.effect.effect,
              platformScopeReplacementId: matching ? id(881) : id(884),
            },
          },
        }),
      )
      .mockResolvedValueOnce(Response.json(handoffState()));
    render(<RpcPlatformAccess handoffOnly />);
    await userEvent
      .setup()
      .click(await screen.findByRole('button', { name: 'Verify and commit RPC envelope' }));
    await waitFor(() =>
      expect(screen.getByRole('status')).toHaveTextContent(
        matching ? 'is durable' : 'The request was not completed.',
      ),
    );
    expect(localStorage.getItem(storageKey)).toBe(matching ? null : raw);
    expect(requests).toHaveBeenCalledTimes(matching ? 3 : 2);
  },
);

function originalRpcReview(
  kind: 'CREATE_ENVELOPE' | 'ACTIVATE_ENVELOPE' | 'REVOKE_ENVELOPE' = 'CREATE_ENVELOPE',
  handoffOnly = false,
) {
  const saved = savedReviewFor(handoffOnly);
  return {
    ...saved,
    approvalRequestId: id(991),
    review: {
      ...saved.review,
      kind,
      expectedRevision: kind === 'CREATE_ENVELOPE' ? '0' : kind === 'ACTIVATE_ENVELOPE' ? '3' : '4',
      stepUp: {
        ...saved.review.stepUp,
        actionIntentId:
          kind === 'ACTIVATE_ENVELOPE'
            ? 'ACT-PARTICIPANT_ACTIVATE_CONTEXT-V1'
            : 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
      },
    },
  };
}

it.each(['SUBMIT', 'APPROVE', 'COMMIT'] as const)(
  'synchronously reserves one %s ceremony and preserves its entire original POST',
  async (command) => {
    const proof = deferred<void>();
    const posted = deferred<Response>();
    const original = command === 'SUBMIT' ? savedReview() : originalRpcReview();
    const checker = { ...actor, principalId: id(112), role: 'viewer' };
    const approval = {
      ...fullDecisionApproval(),
      state: 'REQUESTED',
      stepUp: { ...stepUp, actionIntentId: 'ACT-POLICY_APPROVE_REQUEST-V1', resourceId: id(991) },
    };
    const current =
      command === 'APPROVE'
        ? { ...state('ACTIVE'), actor: checker, approvals: [approval] }
        : { ...state('ACTIVE'), approvals: [fullDecisionApproval()] };
    if (command === 'APPROVE') currentSession = { ...checker };
    else localStorage.setItem(storageKey, JSON.stringify(original));
    vi.mocked(performWebAuthnStepUp).mockReturnValueOnce(proof.promise);
    const requests = mockRequests().mockImplementation(async (_, options) =>
      options?.method === 'POST' ? posted.promise : Response.json(current),
    );
    render(<RpcPlatformAccess />);
    const name =
      command === 'SUBMIT'
        ? 'Verify and request approval'
        : command === 'APPROVE'
          ? 'Approve with saved passkey'
          : 'Verify and commit RPC envelope';
    const button = await screen.findByRole('button', { name });
    act(() => {
      button.click();
      button.click();
    });
    expect(performWebAuthnStepUp).toHaveBeenCalledTimes(1);
    const [action, binding, lifecycle] = vi.mocked(performWebAuthnStepUp).mock.calls[0]!;
    const exact = command === 'APPROVE' ? approval.stepUp : original.review.stepUp;
    expect(action).toEqual({ ...exact, stepUp: 'FRESH_WEBAUTHN_MAX_5M' });
    expect(binding).toEqual({ resourceId: exact.resourceId, resourceDigest: exact.resourceDigest });
    expect(lifecycle?.isCurrent?.()).toBe(true);
    await act(async () => proof.resolve());
    await waitFor(() =>
      expect(requests.mock.calls.filter(([, options]) => options?.method === 'POST')).toHaveLength(
        1,
      ),
    );
    const body = JSON.parse(
      String(requests.mock.calls.find(([, options]) => options?.method === 'POST')![1]?.body),
    );
    expect(body).toEqual(
      command === 'SUBMIT'
        ? { command, reviewToken: original.reviewToken }
        : command === 'APPROVE'
          ? { command, approvalRequestId: id(991), candidateDigest: approval.candidateDigest }
          : { command, approvalRequestId: id(991), reviewToken: original.reviewToken },
    );
    await act(async () =>
      posted.resolve(Response.json({ code: 'PRIVATE-OWNER-CODE' }, { status: 409 })),
    );
    await waitFor(() => expect(screen.getByRole('button', { name })).toBeEnabled());
    expect(requests.mock.calls.filter(([, options]) => options?.method === 'POST')).toHaveLength(1);
    expect(screen.queryByText(/PRIVATE-OWNER/u)).toBeNull();
  },
);

it.each([
  { sessionId: id(702) },
  { principalId: id(112) },
  { participantId: id(102) },
  { privacyDomainId: id(202) },
  { contextEpoch: '3' },
  { role: 'viewer' },
  { contextMode: 'PARTICIPANT' },
  { authenticated: false },
])(
  'fences an unsent COMMIT after the actual Platform actor changes by %s during proof',
  async (change) => {
    const original = originalRpcReview();
    const raw = JSON.stringify(original);
    localStorage.setItem(storageKey, raw);
    const held = deferred<void>();
    vi.mocked(performWebAuthnStepUp).mockReturnValueOnce(held.promise);
    const requests = mockRequests().mockImplementation(async () =>
      Response.json({ ...state('ACTIVE'), approvals: [fullDecisionApproval()] }),
    );
    render(<RpcPlatformAccess />);
    await userEvent
      .setup()
      .click(await screen.findByRole('button', { name: 'Verify and commit RPC envelope' }));
    currentSession = { ...actor, ...change };
    await act(async () => held.resolve());
    await waitFor(() =>
      expect(screen.getByRole('status')).toHaveTextContent('Platform RPC access is unavailable.'),
    );
    expect(requests).toHaveBeenCalledTimes(1);
    expect(requests.mock.calls.filter(([, options]) => options?.method === 'POST')).toHaveLength(0);
    expect(localStorage.getItem(storageKey)).toBe(raw);
    expect(screen.queryByRole('heading', { name: 'Immutable envelope review' })).toBeNull();
    expect(screen.queryByText(original.review.candidateDigest)).toBeNull();
  },
);

it.each([
  'Reserved approval operation ID',
  'Envelope approval ID',
  'Declared administrator principal ID',
] as const)(
  'aborts a held unsent ceremony after its %s changes while retaining original custody',
  async (label) => {
    const original = originalRpcReview('CREATE_ENVELOPE', true);
    const raw = JSON.stringify(original);
    localStorage.setItem(storageKey, raw);
    const held = deferred<void>();
    vi.mocked(performWebAuthnStepUp).mockReturnValueOnce(held.promise);
    const requests = mockRequests().mockImplementation(async () =>
      Response.json({ ...handoffState(), approvals: [fullDecisionApproval()] }),
    );
    render(<RpcPlatformAccess handoffOnly />);
    const user = userEvent.setup();
    await user.click(await screen.findByRole('button', { name: 'Verify and commit RPC envelope' }));
    const lifecycle = vi.mocked(performWebAuthnStepUp).mock.calls[0]![2]!;
    await user.type(screen.getByRole('textbox', { name: label }), id(994));
    expect(lifecycle.signal?.aborted).toBe(true);
    expect(lifecycle.isCurrent?.()).toBe(false);
    await act(async () => held.resolve());
    await waitFor(() =>
      expect(screen.getByRole('button', { name: 'Refresh administrator handoff' })).toBeEnabled(),
    );
    expect(requests).toHaveBeenCalledTimes(1);
    expect(requests.mock.calls.filter(([, options]) => options?.method === 'POST')).toHaveLength(0);
    expect(localStorage.getItem(storageKey)).toBe(raw);
    expect(screen.queryByText('The Platform-root RPC envelope is durable.')).toBeNull();
  },
);

it.each(['unmount', 'mode'] as const)(
  'retires a held Platform mutation on %s without unlocking or posting from the old ceremony',
  async (retirement) => {
    const original = originalRpcReview();
    localStorage.setItem(storageKey, JSON.stringify(original));
    const held = deferred<void>();
    vi.mocked(performWebAuthnStepUp).mockReturnValueOnce(held.promise);
    const requests = mockRequests().mockImplementation(async (url) =>
      Response.json(
        String(url).includes('platform-handoff')
          ? handoffState()
          : { ...state('ACTIVE'), approvals: [fullDecisionApproval()] },
      ),
    );
    const view = render(<RpcPlatformAccess />);
    await userEvent
      .setup()
      .click(await screen.findByRole('button', { name: 'Verify and commit RPC envelope' }));
    const lifecycle = vi.mocked(performWebAuthnStepUp).mock.calls[0]![2]!;
    if (retirement === 'unmount') view.unmount();
    else {
      view.rerender(<RpcPlatformAccess handoffOnly />);
      await screen.findByRole('button', { name: 'Review envelope submission' });
    }
    expect(lifecycle.signal?.aborted).toBe(true);
    expect(lifecycle.isCurrent?.()).toBe(false);
    await act(async () => held.resolve());
    expect(requests.mock.calls.filter(([, options]) => options?.method === 'POST')).toHaveLength(0);
    expect(localStorage.getItem(storageKey)).toBe(JSON.stringify(original));
  },
);

it.each(['lost', '503', 'malformed success'] as const)(
  'reads the original SENT activation after %s and local approval edit without business replay',
  async (failure) => {
    const original = originalRpcReview('ACTIVATE_ENVELOPE', true);
    const raw = JSON.stringify(original);
    localStorage.setItem(storageKey, raw);
    const held = deferred<Response>();
    const current = { ...handoffState(), approvals: [fullDecisionApproval()] };
    current.handoff.envelope.effect.state = 'APPROVED';
    current.handoff.envelope.effect.revision = '3';
    const requests = mockRequests().mockImplementation(async (_, options) =>
      options?.method === 'POST' ? held.promise : Response.json(current),
    );
    render(<RpcPlatformAccess handoffOnly />);
    const user = userEvent.setup();
    await user.click(await screen.findByRole('button', { name: 'Verify and commit activation' }));
    await waitFor(() =>
      expect(requests.mock.calls.filter(([, options]) => options?.method === 'POST')).toHaveLength(
        1,
      ),
    );
    const sent = requests.mock.calls.find(([, options]) => options?.method === 'POST')![1]!;
    const body = String(sent.body);
    if (failure !== 'malformed success')
      await user.type(screen.getByRole('textbox', { name: 'Envelope approval ID' }), id(994));
    await act(async () => {
      if (failure === 'lost') held.reject(new Error('PRIVATE-TRANSPORT-ERROR'));
      else
        held.resolve(
          Response.json(
            { detail: 'PRIVATE-TRANSPORT-ERROR' },
            { status: failure === '503' ? 503 : 200 },
          ),
        );
    });
    await waitFor(() =>
      expect(screen.getByRole('status')).toHaveTextContent(
        'original RPC envelope request requires authoritative reconciliation',
      ),
    );
    if (failure === 'malformed success') {
      await user.type(screen.getByRole('textbox', { name: 'Envelope approval ID' }), id(994));
      await waitFor(() =>
        expect(screen.getByRole('button', { name: 'Refresh administrator handoff' })).toBeEnabled(),
      );
      await user.click(screen.getByRole('button', { name: 'Refresh administrator handoff' }));
      await waitFor(() =>
        expect(screen.getByRole('status')).toHaveTextContent(
          'Platform administrator handoff loaded.',
        ),
      );
    }
    const reads = requests.mock.calls.filter(([, options]) => options?.method !== 'POST');
    const query = new URL(String(reads.at(-1)![0]), 'https://example.test').searchParams;
    expect(query.get('approvalRequestId')).toBe(id(991));
    expect(query.get('approvalRequestId')).not.toBe(id(994));
    expect(JSON.parse(body)).toEqual({
      command: 'COMMIT',
      reviewToken: original.reviewToken,
      approvalRequestId: id(991),
    });
    expect(String(sent.body)).toBe(body);
    expect(localStorage.getItem(storageKey)).toBe(raw);
    expect(requests.mock.calls.filter(([, options]) => options?.method === 'POST')).toHaveLength(1);
    expect(screen.queryByText(/PRIVATE-TRANSPORT|envelope is ACTIVE/u)).toBeNull();
    const commit = screen.queryByRole('button', { name: 'Verify and commit activation' });
    if (commit) await user.click(commit);
    expect(requests.mock.calls.filter(([, options]) => options?.method === 'POST')).toHaveLength(1);
  },
);

it.each([
  ['ACTIVATE_ENVELOPE', 'ACTIVE', 'lost'],
  ['ACTIVATE_ENVELOPE', 'ACTIVE', '503'],
  ['ACTIVATE_ENVELOPE', 'ACTIVE', 'malformed'],
  ['REVOKE_ENVELOPE', 'REVOKED', 'lost'],
  ['REVOKE_ENVELOPE', 'REVOKED', '503'],
  ['REVOKE_ENVELOPE', 'REVOKED', 'malformed'],
] as const)(
  'preserves unresolved %s custody across a %s catalogue after %s and remount',
  async (kind, catalogueState, failure) => {
    const original = originalRpcReview(kind, true);
    const raw = JSON.stringify(original);
    localStorage.setItem(storageKey, raw);
    const held = deferred<Response>();
    let sent = false;
    const requests = mockRequests().mockImplementation(async (_, options) => {
      if (options?.method === 'POST') {
        sent = true;
        return held.promise;
      }
      const next = { ...handoffState(), approvals: [fullDecisionApproval()] };
      next.handoff.envelope.effect.state = sent
        ? catalogueState
        : kind === 'ACTIVATE_ENVELOPE'
          ? 'APPROVED'
          : 'ACTIVE';
      next.handoff.envelope.effect.revision = sent
        ? kind === 'ACTIVATE_ENVELOPE'
          ? '4'
          : '5'
        : original.review.expectedRevision;
      return Response.json(next);
    });
    const view = render(<RpcPlatformAccess handoffOnly />);
    const user = userEvent.setup();
    const name =
      kind === 'ACTIVATE_ENVELOPE'
        ? 'Verify and commit activation'
        : 'Verify and commit revocation';
    await user.click(await screen.findByRole('button', { name }));
    await waitFor(() =>
      expect(requests.mock.calls.filter(([, options]) => options?.method === 'POST')).toHaveLength(
        1,
      ),
    );
    await act(async () => {
      if (failure === 'lost') held.reject(new Error('PRIVATE-LOST-OUTCOME'));
      else
        held.resolve(
          Response.json(
            { detail: 'PRIVATE-LOST-OUTCOME' },
            { status: failure === '503' ? 503 : 200 },
          ),
        );
    });
    await waitFor(() =>
      expect(screen.getByRole('status')).toHaveTextContent(
        'original RPC envelope request requires authoritative reconciliation',
      ),
    );
    await waitFor(() =>
      expect(screen.getByRole('button', { name: 'Refresh administrator handoff' })).toBeEnabled(),
    );
    await user.click(screen.getByRole('button', { name: 'Refresh administrator handoff' }));
    await screen.findByRole('heading', { name: 'Immutable envelope review' });
    expect(localStorage.getItem(storageKey)).toBe(raw);
    await user.click(screen.getByRole('button', { name }));
    expect(requests.mock.calls.filter(([, options]) => options?.method === 'POST')).toHaveLength(1);
    expect(localStorage.getItem(storageKey)).toBe(raw);
    expect(screen.queryByText(/envelope is ACTIVE|envelope is REVOKED|PRIVATE-LOST/u)).toBeNull();
    view.unmount();
    render(<RpcPlatformAccess handoffOnly />);
    await screen.findByRole('button', { name: 'Refresh administrator handoff' });
    await waitFor(() =>
      expect(screen.getByRole('status')).toHaveTextContent(
        'Platform administrator handoff loaded.',
      ),
    );
    expect(localStorage.getItem(storageKey)).toBe(raw);
    expect(screen.queryByRole('button', { name })).toBeNull();
    expect(screen.queryByText(/envelope is ACTIVE|envelope is REVOKED|PRIVATE-LOST/u)).toBeNull();
    expect(requests.mock.calls.filter(([, options]) => options?.method === 'POST')).toHaveLength(1);
    expect(
      JSON.parse(
        String(requests.mock.calls.find(([, options]) => options?.method === 'POST')![1]?.body),
      ),
    ).toEqual({
      command: 'COMMIT',
      reviewToken: original.reviewToken,
      approvalRequestId: id(991),
    });
  },
);

it.each(['transport', '503'] as const)(
  'does not publish an obsolete Platform PREVIEW %s failure after an uncontrolled reason edit',
  async (failure) => {
    const held = deferred<Response>();
    const requests = mockRequests().mockImplementation(async (_, options) =>
      options?.method === 'POST' ? held.promise : Response.json(state('ACTIVE')),
    );
    render(<RpcPlatformAccess />);
    const button = await screen.findByRole('button', { name: 'Review RPC envelope' });
    const form = button.closest('form')!;
    const user = userEvent.setup();
    await user.type(screen.getByRole('textbox', { name: 'Reason' }), 'Original envelope reason');
    const status = screen.getByRole('status').textContent;
    fireEvent.submit(form);
    await waitFor(() => expect(requests).toHaveBeenCalledTimes(2));
    await user.type(screen.getByRole('textbox', { name: 'Reason' }), ' changed locally');
    expect(requests.mock.calls[1]?.[1]?.signal?.aborted).toBe(true);
    await act(async () => {
      if (failure === 'transport') held.reject(new Error('PRIVATE-RETIRED-PREVIEW'));
      else held.resolve(Response.json({ detail: 'PRIVATE-RETIRED-PREVIEW' }, { status: 503 }));
    });
    await waitFor(() => expect(button).toBeEnabled());
    expect(screen.getByRole('status').textContent).toBe(status);
    expect(screen.queryByRole('heading', { name: 'Immutable envelope review' })).toBeNull();
    expect(screen.queryByText(/PRIVATE-RETIRED|request was not completed/u)).toBeNull();
    expect(localStorage.getItem(storageKey)).toBeNull();
    expect(requests).toHaveBeenCalledTimes(2);
    expect(sessionRequests).toHaveBeenCalledTimes(2);
    expect(requests.mock.calls.filter(([, options]) => options?.method === 'POST')).toHaveLength(1);
  },
);

it.each(['remove failure', 'newer review', 'foreign actor'] as const)(
  'retains a SENT success after local selector edit without clearing %s custody',
  async (custody) => {
    const original = originalRpcReview('CREATE_ENVELOPE', true);
    const raw = JSON.stringify(original);
    localStorage.setItem(storageKey, raw);
    const held = deferred<Response>();
    const requests = mockRequests().mockImplementation(async (_, options) =>
      options?.method === 'POST'
        ? held.promise
        : Response.json({ ...handoffState(), approvals: [fullDecisionApproval()] }),
    );
    render(<RpcPlatformAccess handoffOnly />);
    const user = userEvent.setup();
    await user.click(await screen.findByRole('button', { name: 'Verify and commit RPC envelope' }));
    await waitFor(() =>
      expect(requests.mock.calls.filter(([, options]) => options?.method === 'POST')).toHaveLength(
        1,
      ),
    );
    await user.type(screen.getByRole('textbox', { name: 'Envelope approval ID' }), id(994));
    let retained = raw;
    if (custody === 'remove failure')
      vi.spyOn(Storage.prototype, 'removeItem').mockImplementation(() => {
        throw new Error('PRIVATE-STORAGE-ERROR');
      });
    else {
      retained = JSON.stringify(
        custody === 'newer review'
          ? { ...original, reviewToken: 'n'.repeat(100), approvalRequestId: id(995) }
          : { ...original, actor: { ...actor, sessionId: id(702) } },
      );
      localStorage.setItem(storageKey, retained);
    }
    await act(async () => held.resolve(Response.json(committedRpc(original))));
    await waitFor(() => expect(screen.getByRole('status')).toHaveTextContent('is durable'));
    expect(screen.queryByRole('heading', { name: 'Immutable envelope review' })).toBeNull();
    expect(localStorage.getItem(storageKey)).toBe(retained);
    const reads = requests.mock.calls.filter(([, options]) => options?.method !== 'POST');
    expect(
      new URL(String(reads.at(-1)![0]), 'https://example.test').searchParams.get(
        'approvalRequestId',
      ),
    ).toBe(id(991));
    expect(
      JSON.parse(
        String(requests.mock.calls.find(([, options]) => options?.method === 'POST')![1]?.body),
      ),
    ).toEqual({
      command: 'COMMIT',
      reviewToken: original.reviewToken,
      approvalRequestId: id(991),
    });
    await waitFor(() =>
      expect(screen.getByRole('button', { name: 'Refresh administrator handoff' })).toBeEnabled(),
    );
    await user.click(screen.getByRole('button', { name: 'Refresh administrator handoff' }));
    await waitFor(() =>
      expect(screen.getByRole('status')).toHaveTextContent(
        'Platform administrator handoff loaded.',
      ),
    );
    expect(screen.queryByRole('heading', { name: 'Immutable envelope review' })).toBeNull();
    expect(localStorage.getItem(storageKey)).toBe(retained);
    expect(screen.queryByText(/PRIVATE-STORAGE/u)).toBeNull();
    expect(requests.mock.calls.filter(([, options]) => options?.method === 'POST')).toHaveLength(1);
  },
);

it('keeps the original opaque SUBMIT token and accepted approval when optional storage fails', async () => {
  const original = savedReview();
  const raw = JSON.stringify(original);
  localStorage.setItem(storageKey, raw);
  const submitted = { ...original, reviewToken: 'f'.repeat(100), approvalRequestId: id(991) };
  let sent = false;
  const requests = mockRequests().mockImplementation(async (_, options) => {
    if (options?.method === 'POST') {
      sent = true;
      return Response.json(submitted, { status: 202 });
    }
    return Response.json({
      ...state('ACTIVE'),
      approvals: sent ? [{ ...fullDecisionApproval(), state: 'REQUESTED' }] : [],
    });
  });
  render(<RpcPlatformAccess />);
  const user = userEvent.setup();
  const submit = await screen.findByRole('button', { name: 'Verify and request approval' });
  vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => {
    throw new Error('PRIVATE-STORAGE-ERROR');
  });
  await user.click(submit);
  expect(await screen.findByText('Approval: REQUESTED')).toBeVisible();
  expect(localStorage.getItem(storageKey)).toBe(raw);
  expect(
    JSON.parse(
      String(requests.mock.calls.find(([, options]) => options?.method === 'POST')![1]?.body),
    ),
  ).toEqual({ command: 'SUBMIT', reviewToken: original.reviewToken });
  await waitFor(() =>
    expect(screen.getByRole('button', { name: 'Refresh Platform RPC access' })).toBeEnabled(),
  );
  await user.click(screen.getByRole('button', { name: 'Refresh Platform RPC access' }));
  expect(await screen.findByText('Approval: REQUESTED')).toBeVisible();
  expect(screen.queryByRole('button', { name: 'Verify and request approval' })).toBeNull();
  expect(screen.queryByText(/PRIVATE-STORAGE/u)).toBeNull();
  expect(requests.mock.calls.filter(([, options]) => options?.method === 'POST')).toHaveLength(1);
});

it.each(['navigator', 'verification'] as const)(
  'composes the published helper at held %s and prevents a retired ceremony from reaching business POST',
  async (phase) => {
    const real = await vi.importActual<typeof import('@openpc/ui-shell')>('@openpc/ui-shell');
    vi.mocked(performWebAuthnStepUp).mockImplementation(real.performWebAuthnStepUp);
    const bytes = () => new Uint8Array([1, 2, 3]).buffer;
    class Credential {
      rawId = bytes();
      response = { authenticatorData: bytes(), clientDataJSON: bytes(), signature: bytes() };
    }
    const credential = deferred<Credential>();
    const verification = deferred<Response>();
    const get = vi.fn<(options: CredentialRequestOptions) => Promise<Credential>>(async () =>
      phase === 'navigator' ? credential.promise : new Credential(),
    );
    const oldCredentials = Object.getOwnPropertyDescriptor(navigator, 'credentials');
    Object.defineProperty(navigator, 'credentials', { configurable: true, value: { get } });
    vi.stubGlobal('PublicKeyCredential', Credential);
    const original = originalRpcReview();
    const raw = JSON.stringify(original);
    localStorage.setItem(storageKey, raw);
    const requests = mockRequests().mockImplementation(async (url) => {
      if (String(url).endsWith('/assertion/challenge'))
        return Response.json({
          publicKey: {
            challenge: 'Y2hhbGxlbmdl',
            rpId: '127.0.0.1',
            allowCredentials: [{ id: 'Y3JlZGVudGlhbA', type: 'public-key' }],
            timeout: 300000,
            userVerification: 'required',
          },
          expiresAt: new Date(Date.now() + 60000).toISOString().replace('Z', '000Z'),
        });
      if (String(url).endsWith('/assertion/verify')) return verification.promise;
      return Response.json({ ...state('ACTIVE'), approvals: [fullDecisionApproval()] });
    });
    try {
      const view = render(<RpcPlatformAccess />);
      await userEvent
        .setup()
        .click(await screen.findByRole('button', { name: 'Verify and commit RPC envelope' }));
      await waitFor(() => expect(get).toHaveBeenCalledTimes(1));
      if (phase === 'verification')
        await waitFor(() =>
          expect(
            requests.mock.calls.some(([url]) => String(url).endsWith('/assertion/verify')),
          ).toBe(true),
        );
      const lifecycle = vi.mocked(performWebAuthnStepUp).mock.calls[0]![2]!;
      expect(get.mock.calls[0]?.[0]).toMatchObject({ signal: lifecycle.signal });
      view.unmount();
      expect(lifecycle.signal?.aborted).toBe(true);
      await act(async () => {
        if (phase === 'navigator') credential.resolve(new Credential());
        else
          verification.resolve(
            Response.json({
              status: 'verified',
              stepUpVerifiedAt: new Date().toISOString().replace('Z', '000Z'),
            }),
          );
      });
      expect(
        requests.mock.calls
          .filter(([, options]) => options?.method === 'POST')
          .map(([url]) => String(url)),
      ).toEqual(
        phase === 'navigator'
          ? ['/api/v1/ui/webauthn/assertion/challenge']
          : ['/api/v1/ui/webauthn/assertion/challenge', '/api/v1/ui/webauthn/assertion/verify'],
      );
      expect(localStorage.getItem(storageKey)).toBe(raw);
      expect(sessionRequests).toHaveBeenCalledTimes(2);
    } finally {
      if (oldCredentials) Object.defineProperty(navigator, 'credentials', oldCredentials);
      else Reflect.deleteProperty(navigator, 'credentials');
      vi.unstubAllGlobals();
    }
  },
);

it.each([false, true])(
  'keeps original handoff custody through read-specific proof (denied=%s)',
  async (denied) => {
    const initial = continuationReview();
    const { resumeDraft: _resume, ...normal } = initial.review;
    expect(_resume.approvalRequestId).toBe(id(920));
    const approvalRequestId = id(930);
    const retained = {
      ...initial,
      approvalRequestId,
      review: {
        ...normal,
        stepUp: {
          actionIntentId: 'ACT-PARTICIPANT_ACTIVATE_CONTEXT-V1',
          actionIntentDigest: digest,
          resourceId: envelopeId,
          resourceDigest: digest,
        },
      },
      actor,
    };
    const original = JSON.stringify(retained);
    localStorage.setItem(storageKey, original);
    const readProof = {
      actionIntentId: 'ACT-PARTICIPANTS_READ_RESOURCE-V1',
      actionIntentDigest: digest,
      resourceId: id(881),
      resourceDigest: 'sha256:' + 'd'.repeat(64),
    };
    const loaded = {
      ...handoffState(),
      approvalsLoaded: true,
      approvals: [
        {
          approvalRequestId: `urn:openpc:resource:${approvalRequestId}`,
          candidateDigest: digest,
          state: 'APPROVED',
        },
      ],
    };
    const requests = mockRequests()
      .mockResolvedValueOnce(Response.json({ actor, requiresStepUp: readProof }))
      .mockResolvedValueOnce(Response.json(loaded));
    if (denied) vi.mocked(performWebAuthnStepUp).mockRejectedValueOnce(Error('Read proof denied'));
    render(<RpcPlatformAccess handoffOnly />);
    const verify = await screen.findByRole('button', {
      name: 'Verify Platform authenticator and read administrator handoff',
    });
    expect(screen.queryByRole('button', { name: 'Verify and commit activation' })).toBeNull();
    expect(localStorage.getItem(storageKey)).toBe(original);
    await userEvent.setup().click(verify);
    expect(performWebAuthnStepUp).toHaveBeenCalledWith(
      { ...readProof, stepUp: 'FRESH_WEBAUTHN_MAX_5M' },
      { resourceId: readProof.resourceId, resourceDigest: readProof.resourceDigest },
      expect.objectContaining({ signal: expect.any(AbortSignal), isCurrent: expect.any(Function) }),
    );
    if (denied) {
      await waitFor(() => expect(verify).toBeEnabled());
      expect(requests).toHaveBeenCalledTimes(1);
      expect(screen.queryByRole('button', { name: 'Verify and commit activation' })).toBeNull();
    } else {
      expect(
        await screen.findByRole('button', { name: 'Verify and commit activation' }),
      ).toBeVisible();
      expect(requests).toHaveBeenCalledTimes(2);
    }
    expect(requests.mock.calls.every(([, init]) => init?.method !== 'POST')).toBe(true);
    const selector = new URL(String(requests.mock.calls[0]![0]), 'http://example.test')
      .searchParams;
    expect(selector.get('preparationApprovalId')).toBe(id(919));
    expect(selector.get('principalId')).toBe(actor.principalId);
    expect(selector.get('approvalRequestId')).toBe(approvalRequestId);
    expect(localStorage.getItem(storageKey)).toBe(original);
  },
);

it.each(['newer', 'removed', 'unavailable'] as const)(
  'pins the original handoff READ selectors while custody becomes %s during proof',
  async (change) => {
    const initial = continuationReview();
    const retained = { ...initial, approvalRequestId: id(930), actor };
    localStorage.setItem(storageKey, JSON.stringify(retained));
    const readProof = {
      actionIntentId: 'ACT-PARTICIPANTS_READ_RESOURCE-V1',
      actionIntentDigest: digest,
      resourceId: id(881),
      resourceDigest: `sha256:${'d'.repeat(64)}`,
    };
    const requests = mockRequests()
      .mockResolvedValueOnce(Response.json({ actor, requiresStepUp: readProof }))
      .mockResolvedValueOnce(Response.json(handoffState()));
    const held = deferred<void>();
    vi.mocked(performWebAuthnStepUp).mockReturnValueOnce(held.promise);
    render(<RpcPlatformAccess handoffOnly />);
    await userEvent.setup().click(
      await screen.findByRole('button', {
        name: 'Verify Platform authenticator and read administrator handoff',
      }),
    );
    await waitFor(() => expect(performWebAuthnStepUp).toHaveBeenCalledTimes(1));
    const newer = JSON.stringify({
      ...retained,
      reviewToken: 's'.repeat(100),
      review: {
        ...retained.review,
        continuationHandoff: { preparationApprovalId: id(929), principalId: actor.principalId },
      },
    });
    if (change === 'newer') localStorage.setItem(storageKey, newer);
    else if (change === 'removed') localStorage.removeItem(storageKey);
    const inaccessible =
      change === 'unavailable'
        ? vi.spyOn(Storage.prototype, 'getItem').mockImplementation(() => {
            throw Error('Custody storage unavailable');
          })
        : undefined;
    await act(async () => held.resolve());
    await waitFor(() => expect(requests).toHaveBeenCalledTimes(2));
    expect(requests.mock.calls[1]![0]).toBe(requests.mock.calls[0]![0]);
    const selectors = new URL(String(requests.mock.calls[1]![0]), 'http://example.test')
      .searchParams;
    expect(selectors.get('preparationApprovalId')).toBe(id(919));
    expect(selectors.get('principalId')).toBe(actor.principalId);
    expect(selectors.get('approvalRequestId')).toBe(id(930));
    expect(requests.mock.calls.every(([, options]) => options?.method !== 'POST')).toBe(true);
    inaccessible?.mockRestore();
    expect(localStorage.getItem(storageKey)).toBe(
      change === 'newer' ? newer : change === 'removed' ? null : JSON.stringify(retained),
    );
  },
);

it('resumes only the entered original creation approval and keeps its fresh independent approval requirement visible', async () => {
  const original = originalRpcReview();
  const nextId = '018f0000-0000-7000-8000-000000000802';
  const requests = mockRequests()
    .mockResolvedValueOnce(Response.json(state('ACTIVE')))
    .mockResolvedValueOnce(
      Response.json(
        { ...original, approvalRequestId: nextId, originalApprovalRequestId: id(801) },
        { status: 202 },
      ),
    );
  render(<RpcPlatformAccess />);
  const user = userEvent.setup();
  await user.type(
    await screen.findByRole('textbox', { name: 'Original creation approval ID' }),
    '018f0000-0000-7000-8000-000000000801',
  );
  await user.click(screen.getByRole('button', { name: 'Resume original envelope creation' }));
  expect(
    await screen.findByText(
      'The original RPC envelope creation was resumed. Fresh independent approval is required.',
    ),
  ).toBeVisible();
  const submitted = requests.mock.calls.find(([, options]) => options?.method === 'POST');
  expect(JSON.parse(String(submitted?.[1]?.body))).toMatchObject({
    command: 'RESUME_CREATE',
    approvalRequestId: '018f0000-0000-7000-8000-000000000801',
  });
  expect(screen.queryByRole('button', { name: 'Verify and commit RPC envelope' })).toBeNull();
});

it.each(['transport', 'server', 'body', 'review'] as const)(
  'keeps the original creation selector and blocks a second mutation after an ambiguous %s response',
  async (failure) => {
    const originalId = '018f0000-0000-7000-8000-000000000801';
    const requests = mockRequests().mockResolvedValueOnce(Response.json(state('ACTIVE')));
    if (failure === 'transport') requests.mockRejectedValueOnce(Error('Response lost'));
    else if (failure === 'server')
      requests.mockResolvedValueOnce(Response.json({}, { status: 503 }));
    else if (failure === 'body')
      requests.mockResolvedValueOnce(new Response('lost JSON', { status: 200 }));
    else requests.mockResolvedValueOnce(Response.json({}));
    requests.mockResolvedValue(Response.json(state('ACTIVE')));
    render(<RpcPlatformAccess />);
    const user = userEvent.setup();
    await user.type(
      await screen.findByRole('textbox', { name: 'Original creation approval ID' }),
      originalId,
    );
    const resume = screen.getByRole('button', { name: 'Resume original envelope creation' });
    await user.click(resume);
    await waitFor(() =>
      expect(screen.getByText(/requires authoritative reconciliation/)).toBeVisible(),
    );
    await waitFor(() =>
      expect(
        screen.getByRole('button', { name: 'Resume original envelope creation' }),
      ).toBeEnabled(),
    );
    const observations = requests.mock.calls.filter(([, options]) => options?.method !== 'POST');
    expect(observations).toHaveLength(2);
    const observed = new URL(String(observations[1]![0]), 'http://example.test');
    expect(observed.searchParams.get('mode')).toBe('platform-handoff');
    expect(observed.searchParams.get('approvalRequestId')).toBe(originalId);
    await user.type(
      screen.getByRole('textbox', { name: 'Original creation approval ID' }),
      originalId,
    );
    await user.click(screen.getByRole('button', { name: 'Resume original envelope creation' }));
    expect(requests.mock.calls.filter(([, options]) => options?.method === 'POST')).toHaveLength(1);
    expect(performWebAuthnStepUp).not.toHaveBeenCalled();
    expect(screen.queryByRole('button', { name: 'Verify and commit RPC envelope' })).toBeNull();
  },
);

it.each(['foreign', 'denied', 'missing'] as const)(
  'retains the original creation request after %s reconciliation readback',
  async (failure) => {
    const originalId = '018f0000-0000-7000-8000-000000000801';
    const requests = mockRequests()
      .mockResolvedValueOnce(Response.json(state('ACTIVE')))
      .mockResolvedValueOnce(Response.json({}, { status: 503 }));
    if (failure === 'foreign')
      requests.mockResolvedValueOnce(
        Response.json({
          ...state('ACTIVE'),
          approvals: [
            {
              ...fullDecisionApproval(),
              approvalRequestId: 'urn:openpc:resource:018f0000-0000-7000-8000-000000000802',
            },
          ],
        }),
      );
    else if (failure === 'denied')
      requests.mockResolvedValueOnce(Response.json({}, { status: 403 }));
    else requests.mockResolvedValueOnce(Response.json({}));
    requests.mockResolvedValue(Response.json(state('ACTIVE')));
    render(<RpcPlatformAccess />);
    const user = userEvent.setup();
    await user.type(
      await screen.findByRole('textbox', { name: 'Original creation approval ID' }),
      originalId,
    );
    await user.click(screen.getByRole('button', { name: 'Resume original envelope creation' }));
    await waitFor(() =>
      expect(screen.getByRole('status')).toHaveTextContent('Platform RPC access is unavailable.'),
    );
    expect(screen.queryByRole('button', { name: 'Resume original envelope creation' })).toBeNull();
    await user.click(screen.getByRole('button', { name: 'Refresh Platform RPC access' }));
    const resumed = await screen.findByRole('button', {
      name: 'Resume original envelope creation',
    });
    await user.type(
      screen.getByRole('textbox', { name: 'Original creation approval ID' }),
      '018f0000-0000-7000-8000-000000000803',
    );
    await user.click(resumed);
    expect(requests.mock.calls.filter(([, options]) => options?.method === 'POST')).toHaveLength(1);
    const observations = requests.mock.calls.filter(([, options]) => options?.method !== 'POST');
    expect(observations).toHaveLength(3);
    for (const [url] of observations.slice(1)) {
      const observed = new URL(String(url), 'http://example.test');
      expect(observed.searchParams.get('mode')).toBe('platform-handoff');
      expect(observed.searchParams.get('approvalRequestId')).toBe(originalId);
    }
    expect(performWebAuthnStepUp).not.toHaveBeenCalled();
  },
);

async function ambiguousCreation() {
  const requests = mockRequests()
    .mockResolvedValueOnce(Response.json(state('ACTIVE')))
    .mockRejectedValueOnce(Error('Response lost after metadata submission'))
    .mockResolvedValueOnce(Response.json(state('ACTIVE')))
    .mockResolvedValue(Response.json(state('ACTIVE')));
  render(<RpcPlatformAccess />);
  const user = userEvent.setup();
  await user.type(
    await screen.findByRole('textbox', { name: 'Original creation approval ID' }),
    id(801),
  );
  await user.click(screen.getByRole('button', { name: 'Resume original envelope creation' }));
  await screen.findByRole('button', { name: 'Read original creation outcome' });
  await waitFor(() =>
    expect(screen.getByRole('button', { name: 'Read original creation outcome' })).toBeEnabled(),
  );
  return { requests, user };
}
function creationSuccess() {
  return {
    ...originalRpcReview(),
    originalApprovalRequestId: id(801),
    approvalRequestId: id(802),
  };
}
it('releases creation custody only after read-only confirmation of its linked successor', async () => {
  const { requests, user } = await ambiguousCreation();
  requests.mockResolvedValueOnce(Response.json(creationSuccess()));
  await user.type(screen.getByRole('textbox', { name: 'Original creation approval ID' }), id(803));
  await user.click(screen.getByRole('button', { name: 'Read original creation outcome' }));
  await screen.findByText(
    'The original RPC envelope creation was confirmed. Fresh independent approval is required.',
  );
  expect(screen.getByRole('heading', { name: 'Immutable envelope review' })).toBeVisible();
  expect(screen.queryByRole('button', { name: 'Read original creation outcome' })).toBeNull();
  expect(screen.queryByRole('button', { name: 'Verify and commit RPC envelope' })).toBeNull();
  const posts = requests.mock.calls.filter(([, options]) => options?.method === 'POST');
  expect(posts.map(([, options]) => JSON.parse(String(options?.body)))).toMatchObject([
    { command: 'RESUME_CREATE', approvalRequestId: id(801) },
    { command: 'PREVIEW_CONTINUE_CREATION', approvalRequestId: id(801) },
  ]);
  expect(performWebAuthnStepUp).not.toHaveBeenCalled();
});
it.each(['denied', 'malformed', 'foreign original', 'foreign privacy'] as const)(
  'preserves creation custody after %s read-only confirmation',
  async (failure) => {
    const { requests, user } = await ambiguousCreation();
    const reply = creationSuccess();
    if (failure === 'denied') requests.mockResolvedValueOnce(Response.json({}, { status: 403 }));
    else if (failure === 'malformed') requests.mockResolvedValueOnce(Response.json({}));
    else if (failure === 'foreign original')
      requests.mockResolvedValueOnce(
        Response.json({ ...reply, originalApprovalRequestId: id(804) }),
      );
    else
      requests.mockResolvedValueOnce(
        Response.json({ ...reply, review: { ...reply.review, targetPrivacyDomainId: id(204) } }),
      );
    await user.click(screen.getByRole('button', { name: 'Read original creation outcome' }));
    await waitFor(() =>
      expect(screen.getByRole('button', { name: 'Read original creation outcome' })).toBeEnabled(),
    );
    expect(screen.queryByRole('heading', { name: 'Immutable envelope review' })).toBeNull();
    await user.type(
      screen.getByRole('textbox', { name: 'Original creation approval ID' }),
      id(803),
    );
    await user.click(screen.getByRole('button', { name: 'Resume original envelope creation' }));
    const posts = requests.mock.calls.filter(([, options]) => options?.method === 'POST');
    expect(posts).toHaveLength(2);
    expect(posts.map(([, options]) => JSON.parse(String(options?.body)).command)).toEqual([
      'RESUME_CREATE',
      'PREVIEW_CONTINUE_CREATION',
    ]);
    expect(screen.getByRole('status')).toHaveTextContent('requires authoritative reconciliation');
  },
);
it.each(['input', 'session'] as const)(
  'rejects a late creation confirmation after %s changes',
  async (changed) => {
    const { requests, user } = await ambiguousCreation();
    const pending = deferred<Response>();
    requests.mockReturnValueOnce(pending.promise);
    await user.click(screen.getByRole('button', { name: 'Read original creation outcome' }));
    await waitFor(() =>
      expect(requests.mock.calls.filter(([, options]) => options?.method === 'POST')).toHaveLength(
        2,
      ),
    );
    const request = requests.mock.calls.find(
      ([, options]) =>
        options?.method === 'POST' &&
        JSON.parse(String(options.body)).command === 'PREVIEW_CONTINUE_CREATION',
    )!;
    if (changed === 'input') {
      await user.type(
        screen.getByRole('textbox', { name: 'Original creation approval ID' }),
        id(803),
      );
      expect(request[1]?.signal?.aborted).toBe(true);
    } else currentSession = { ...actor, contextEpoch: '3' };
    await act(async () => pending.resolve(Response.json(creationSuccess())));
    await waitFor(() =>
      expect(screen.getByRole('button', { name: 'Read original creation outcome' })).toBeEnabled(),
    );
    expect(screen.queryByRole('heading', { name: 'Immutable envelope review' })).toBeNull();
    expect(requests.mock.calls.filter(([, options]) => options?.method === 'POST')).toHaveLength(2);
    expect(performWebAuthnStepUp).not.toHaveBeenCalled();
  },
);
it('releases the creation latch after a proven pre-effect denial', async () => {
  const requests = mockRequests()
    .mockResolvedValueOnce(Response.json(state('ACTIVE')))
    .mockResolvedValue(Response.json({}, { status: 403 }));
  render(<RpcPlatformAccess />);
  const user = userEvent.setup();
  const input = await screen.findByRole('textbox', { name: 'Original creation approval ID' });
  await user.type(input, id(801));
  await user.click(screen.getByRole('button', { name: 'Resume original envelope creation' }));
  await waitFor(() =>
    expect(screen.getByRole('button', { name: 'Resume original envelope creation' })).toBeEnabled(),
  );
  expect(screen.queryByRole('button', { name: 'Read original creation outcome' })).toBeNull();
  await user.clear(input);
  await user.type(input, id(803));
  await user.click(screen.getByRole('button', { name: 'Resume original envelope creation' }));
  expect(requests.mock.calls.filter(([, options]) => options?.method === 'POST')).toHaveLength(2);
});
