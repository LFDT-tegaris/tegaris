import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { performWebAuthnStepUp } from '@openpc/ui-shell';
import { GroupWorkflow } from './group-workflow';
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
vi.mock('./group-catalogue', () => ({
  GroupCatalogue: ({ onOpen }: { onOpen(id: string): void }) => (
    <button onClick={() => onOpen(id('193'))}>Open another group</button>
  ),
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
  mutation: 'CREATE',
  groupId: id('192'),
  groupName: 'Operators',
  expectedRevision: '0',
};
const review = {
  reviewToken: 'r'.repeat(100),
  approvalRequestId: id('801'),
  review: {
    mutation: 'CREATE',
    candidate,
    resourceId: candidate.groupId,
    expectedRevision: '0',
    candidateDigest: `sha256:${'a'.repeat(64)}`,
    checkerPrincipalId: id('112'),
    reason: 'Authorize this group certificate.',
    expiresAt: new Date(Date.now() + 300000).toISOString(),
    stepUp: {
      actionIntentId: 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
      actionIntentDigest: `sha256:${'b'.repeat(64)}`,
      resourceId: candidate.groupId,
      resourceDigest: `sha256:${'a'.repeat(64)}`,
    },
  },
};
const readback = {
  effect: {
    groupId: candidate.groupId,
    participantId: actor.participantId,
    groupName: candidate.groupName,
    state: 'ACTIVE',
    revision: '1',
    createdAt: '2026-09-29T12:00:00.000Z',
    updatedAt: '2026-09-29T12:00:00.000Z',
    operationId: id('850'),
  },
  members: [],
  nextCursor: null,
};
const catalogue = {
  actor,
  items: [{ effect: readback.effect }],
  nextCursor: null,
  observedAt: '2026-09-29T12:00:00.000Z',
  authorizedEmpty: false,
};
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
it('shows only the inputs meaningful to the selected group change', async () => {
  vi.spyOn(globalThis, 'fetch').mockResolvedValue(Response.json(state));
  render(<GroupWorkflow />);
  await waitFor(() =>
    expect(screen.getByRole('button', { name: 'Prepare group change' })).toBeEnabled(),
  );
  expect(screen.getByRole('textbox', { name: 'Group name' })).toBeVisible();
  await userEvent
    .setup()
    .selectOptions(screen.getByRole('combobox', { name: /^Change/u }), 'ADD_MEMBER');
  expect(screen.getByRole('textbox', { name: 'Member principal ID' })).toBeVisible();
  expect(screen.queryByRole('textbox', { name: 'Group name' })).not.toBeInTheDocument();
  await userEvent
    .setup()
    .selectOptions(screen.getByRole('combobox', { name: /^Change/u }), 'RETIRE');
  expect(screen.getByRole('textbox', { name: 'Group ID' })).toBeVisible();
  expect(screen.queryByRole('textbox', { name: 'Member principal ID' })).not.toBeInTheDocument();
});
it('restores the actor-bound review and prevents a second write after the owner consumed it', async () => {
  writeBoundPolicyState('openpc:group-workflow:v1', actor, review);
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
          resourceId: candidate.groupId,
          makerPrincipalId: actor.principalId,
          catalogOperationId: 'ID-OP-GROUP-CREATE',
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
  vi.spyOn(globalThis, 'fetch').mockResolvedValue(Response.json(consumed));
  render(<GroupWorkflow />);
  await waitFor(() => expect(screen.getByLabelText('Group change review')).toBeVisible());
  expect(screen.getByRole('button', { name: 'Verify and commit group change' })).toBeDisabled();
  expect(performWebAuthnStepUp).not.toHaveBeenCalled();
});
it('does not restore another session’s review', async () => {
  writeBoundPolicyState('openpc:group-workflow:v1', actor, review);
  vi.spyOn(globalThis, 'fetch').mockResolvedValue(
    Response.json({ ...state, actor: { ...actor, sessionId: id('702') } }),
  );
  render(<GroupWorkflow />);
  await waitFor(() =>
    expect(screen.getByRole('button', { name: 'Prepare group change' })).toBeEnabled(),
  );
  expect(screen.queryByLabelText('Group change review')).not.toBeInTheDocument();
});

it('reconciles an already consumed review without replaying the mutation', async () => {
  writeBoundPolicyState('openpc:group-workflow:v1', actor, review);
  const fetch = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
    const url = String(input);
    if (url.startsWith('/api/v1/ui/group-catalogue')) return Response.json(catalogue);
    if (url.includes('resumeApprovalRequestId='))
      return Response.json({
        candidateDigest: review.review.candidateDigest,
        state: 'CONSUMED',
        operationId: id('850'),
        readback,
      });
    return Response.json(state);
  });
  render(<GroupWorkflow />);
  await screen.findByText(`Group change already committed. Operation: ${id('850')}`);
  expect(screen.queryByLabelText('Group change review')).not.toBeInTheDocument();
  expect(screen.getByText('Group: Operators')).toBeVisible();
  expect(localStorage.getItem('openpc:group-workflow:v1')).toBeNull();
  expect(
    fetch.mock.calls.filter(([, init]) => init && (init as RequestInit).method === 'POST'),
  ).toHaveLength(0);
});

it.each(['matching', 'foreign group', 'foreign Participant'])(
  'clears the actor-bound review only after a successful commit with %s readback',
  async (binding) => {
    writeBoundPolicyState('openpc:group-workflow:v1', actor, review);
    const approved = {
      ...state,
      approvals: [
        {
          approvalRequestId: `urn:openpc:resource:${review.approvalRequestId}`,
          candidateDigest: review.review.candidateDigest,
          makerSubjectRef: `urn:openpc:resource:${actor.principalId}`,
          checkerSubjectRef: `urn:openpc:resource:${review.review.checkerPrincipalId}`,
          revision: '1',
          state: 'APPROVED',
          proposal: {
            candidateDigest: review.review.candidateDigest,
            resourceId: candidate.groupId,
            makerPrincipalId: actor.principalId,
            catalogOperationId: 'ID-OP-GROUP-CREATE',
            expectedRevision: '0',
            state: 'APPROVED',
            operationId: null,
            expiresAt: review.review.expiresAt,
            candidate,
          },
          stepUp: review.review.stepUp,
        },
      ],
    };
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const url = String(input);
      if (url.startsWith('/api/v1/ui/group-catalogue')) return Response.json(catalogue);
      if (url.includes('resumeApprovalRequestId='))
        return Response.json({
          candidateDigest: review.review.candidateDigest,
          state: 'APPROVED',
          operationId: null,
        });
      if (init?.method === 'POST')
        return Response.json({
          truthState: 'SUCCESS',
          operationId: id('850'),
          readback: {
            ...readback,
            effect: {
              ...readback.effect,
              ...(binding === 'foreign group'
                ? { groupId: id('193') }
                : binding === 'foreign Participant'
                  ? { participantId: id('102') }
                  : {}),
            },
          },
        });
      return Response.json(approved);
    });
    render(<GroupWorkflow />);
    const commit = await screen.findByRole('button', { name: 'Verify and commit group change' });
    expect(commit).toBeEnabled();
    await userEvent.setup().click(commit);
    if (binding !== 'matching') {
      expect(await screen.findByRole('alert')).toHaveTextContent(
        'Group readback belongs to a different context.',
      );
      expect(screen.getByLabelText('Group change review')).toBeVisible();
      expect(localStorage.getItem('openpc:group-workflow:v1')).not.toBeNull();
      expect(screen.queryByText('Group: Operators')).not.toBeInTheDocument();
      expect(performWebAuthnStepUp).toHaveBeenCalledOnce();
      return;
    }
    await waitFor(() =>
      expect(screen.queryByLabelText('Group change review')).not.toBeInTheDocument(),
    );
    expect(screen.getByText(`Group change committed. Operation: ${id('850')}`)).toBeVisible();
    expect(localStorage.getItem('openpc:group-workflow:v1')).toBeNull();
    expect(performWebAuthnStepUp).toHaveBeenCalledOnce();
  },
);

it.each(['success', 'failure'])(
  'discards an older initial group inventory %s after a newer lane and actor read',
  async (outcome) => {
    const pending = deferredResponse();
    const nextActor = { ...actor, sessionId: id('702'), principalId: id('113') };
    writeBoundPolicyState('openpc:group-workflow:v1', nextActor, review);
    let inventoryReads = 0;
    const fetch = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      if (String(input).includes('resumeApprovalRequestId='))
        return Response.json({
          candidateDigest: review.review.candidateDigest,
          state: 'APPROVED',
          operationId: null,
        });
      inventoryReads += 1;
      return inventoryReads === 1 ? pending.promise : Response.json({ ...state, actor: nextActor });
    });
    const user = userEvent.setup();
    render(<GroupWorkflow />);
    const lane = screen.getByRole('combobox', { name: 'Approval lane' });
    await user.selectOptions(lane, 'maker');
    await screen.findByText(`Signed-in principal: ${nextActor.principalId}`);
    expect(fetch.mock.calls[0]?.[1]?.signal?.aborted).toBe(true);
    await act(async () => {
      if (outcome === 'success') pending.resolve(Response.json(state));
      else pending.reject(new Error('Obsolete group inventory failed.'));
    });
    expect(lane).toHaveValue('maker');
    expect(screen.getByText(`Signed-in principal: ${nextActor.principalId}`)).toBeVisible();
    expect(screen.queryByText(`Signed-in principal: ${actor.principalId}`)).not.toBeInTheDocument();
    expect(screen.getByLabelText('Group change review')).toBeVisible();
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    expect(fetch.mock.calls.some(([, options]) => options?.method === 'POST')).toBe(false);
  },
);
it.each(['success', 'failure'])(
  'ignores an old consumed-resume %s without clearing a newer actor’s original review',
  async (outcome) => {
    const pending = deferredResponse();
    const nextActor = { ...actor, sessionId: id('702'), contextEpoch: '3' };
    const nextReview = {
      ...review,
      approvalRequestId: id('802'),
      review: {
        ...review.review,
        candidateDigest: `sha256:${'c'.repeat(64)}`,
        reason: 'Keep the newer original group intent.',
      },
    };
    writeBoundPolicyState('openpc:group-workflow:v1', actor, review);
    let inventoryReads = 0;
    const fetch = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      const url = String(input);
      if (url.includes('resumeApprovalRequestId='))
        return url.includes(review.approvalRequestId)
          ? pending.promise
          : Response.json({
              candidateDigest: nextReview.review.candidateDigest,
              state: 'APPROVED',
              operationId: null,
            });
      inventoryReads += 1;
      return Response.json(inventoryReads === 1 ? state : { ...state, actor: nextActor });
    });
    const user = userEvent.setup();
    render(<GroupWorkflow />);
    await waitFor(() =>
      expect(
        fetch.mock.calls.some(([url]) => String(url).includes('resumeApprovalRequestId=')),
      ).toBe(true),
    );
    const signal = fetch.mock.calls.find(([url]) =>
      String(url).includes('resumeApprovalRequestId='),
    )?.[1]?.signal;
    writeBoundPolicyState('openpc:group-workflow:v1', nextActor, nextReview);
    await user.click(screen.getByRole('button', { name: 'Refresh group approvals' }));
    await screen.findByText(nextReview.review.reason);
    expect(signal?.aborted).toBe(true);
    await act(async () => {
      if (outcome === 'success')
        pending.resolve(
          Response.json({
            candidateDigest: review.review.candidateDigest,
            state: 'CONSUMED',
            operationId: id('850'),
            readback,
          }),
        );
      else pending.reject(new Error('The old resume failed.'));
    });
    expect(screen.getByText(nextReview.review.reason)).toBeVisible();
    expect(screen.queryByText('Group: Operators')).not.toBeInTheDocument();
    expect(JSON.parse(localStorage.getItem('openpc:group-workflow:v1')!)).toEqual({
      actor: nextActor,
      value: nextReview,
    });
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    expect(fetch.mock.calls.some(([, options]) => options?.method === 'POST')).toBe(false);
  },
);
it.each(['candidate', 'group', 'Participant'])(
  'keeps original intent when consumed-resume readback has a foreign %s binding',
  async (field) => {
    writeBoundPolicyState('openpc:group-workflow:v1', actor, review);
    const fetch = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) =>
      Response.json(
        String(input).includes('resumeApprovalRequestId=')
          ? {
              candidateDigest:
                field === 'candidate' ? `sha256:${'c'.repeat(64)}` : review.review.candidateDigest,
              state: 'CONSUMED',
              operationId: id('850'),
              readback: {
                ...readback,
                effect: {
                  ...readback.effect,
                  ...(field === 'group'
                    ? { groupId: id('193') }
                    : field === 'Participant'
                      ? { participantId: id('102') }
                      : {}),
                },
              },
            }
          : state,
      ),
    );
    render(<GroupWorkflow />);
    await waitFor(() =>
      expect(
        fetch.mock.calls.some(([url]) => String(url).includes('resumeApprovalRequestId=')),
      ).toBe(true),
    );
    await act(async () => {});
    expect(screen.getByLabelText('Group change review')).toBeVisible();
    expect(localStorage.getItem('openpc:group-workflow:v1')).not.toBeNull();
    expect(screen.queryByText('Group: Operators')).not.toBeInTheDocument();
    expect(fetch.mock.calls.some(([, options]) => options?.method === 'POST')).toBe(false);
  },
);
it('preserves a newer same-actor candidate when the previous consumed-resume arrives late', async () => {
  const pending = deferredResponse();
  const nextDigest = `sha256:${'c'.repeat(64)}`;
  const nextReview = {
    reviewToken: 's'.repeat(100),
    review: {
      ...review.review,
      candidate: { ...candidate, groupId: id('193'), groupName: 'New draft group' },
      resourceId: id('193'),
      candidateDigest: nextDigest,
      reason: 'Prepare a distinct new group.',
      stepUp: { ...review.review.stepUp, resourceId: id('193'), resourceDigest: nextDigest },
    },
  };
  writeBoundPolicyState('openpc:group-workflow:v1', actor, review);
  const fetch = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
    if (init?.method === 'POST') return Response.json(nextReview);
    return String(input).includes('resumeApprovalRequestId=')
      ? pending.promise
      : Response.json(state);
  });
  const user = userEvent.setup();
  render(<GroupWorkflow />);
  await screen.findByLabelText('Group change review');
  await waitFor(() =>
    expect(fetch.mock.calls.some(([url]) => String(url).includes('resumeApprovalRequestId='))).toBe(
      true,
    ),
  );
  const signal = fetch.mock.calls.find(([url]) =>
    String(url).includes('resumeApprovalRequestId='),
  )?.[1]?.signal;
  await user.type(screen.getByRole('textbox', { name: 'Group name' }), 'New draft group');
  await user.type(screen.getByRole('textbox', { name: 'Checker principal ID' }), id('112'));
  await user.type(
    screen.getByRole('textbox', { name: 'Reason for group change' }),
    nextReview.review.reason,
  );
  await user.click(screen.getByRole('button', { name: 'Prepare group change' }));
  await screen.findByText(nextReview.review.reason, { selector: 'dd' });
  expect(signal?.aborted).toBe(true);
  await act(async () =>
    pending.resolve(
      Response.json({
        candidateDigest: review.review.candidateDigest,
        state: 'CONSUMED',
        operationId: id('850'),
        readback,
      }),
    ),
  );
  expect(screen.getByText(nextReview.review.reason, { selector: 'dd' })).toBeVisible();
  expect(screen.queryByText('Group: Operators')).not.toBeInTheDocument();
  expect(JSON.parse(localStorage.getItem('openpc:group-workflow:v1')!)).toEqual({
    actor,
    value: nextReview,
  });
  const writes = fetch.mock.calls.filter(([, init]) => init?.method === 'POST');
  expect(writes).toHaveLength(1);
  expect(JSON.parse(String(writes[0]?.[1]?.body)).command).toBe('PREPARE');
  expect(performWebAuthnStepUp).not.toHaveBeenCalled();
});
it('does not let an older consumed resume replace a newer selected group readback', async () => {
  const pending = deferredResponse();
  writeBoundPolicyState('openpc:group-workflow:v1', actor, review);
  const selected = {
    ...readback,
    effect: {
      ...readback.effect,
      groupId: id('193'),
      groupName: 'Selected group',
      operationId: id('851'),
    },
  };
  const fetch = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
    const url = String(input);
    if (url.includes('resumeApprovalRequestId=')) return pending.promise;
    if (url.includes('groupId=')) return Response.json(selected);
    return Response.json(state);
  });
  const user = userEvent.setup();
  render(<GroupWorkflow />);
  await screen.findByRole('button', { name: 'Open another group' });
  await waitFor(() =>
    expect(fetch.mock.calls.some(([url]) => String(url).includes('resumeApprovalRequestId='))).toBe(
      true,
    ),
  );
  const signal = fetch.mock.calls.find(([url]) =>
    String(url).includes('resumeApprovalRequestId='),
  )?.[1]?.signal;
  await user.click(screen.getByRole('button', { name: 'Open another group' }));
  await screen.findByText('Group: Selected group');
  expect(signal?.aborted).toBe(true);
  await act(async () =>
    pending.resolve(
      Response.json({
        candidateDigest: review.review.candidateDigest,
        state: 'CONSUMED',
        operationId: id('850'),
        readback,
      }),
    ),
  );
  expect(screen.getByText('Group: Selected group')).toBeVisible();
  expect(screen.queryByText('Group: Operators')).not.toBeInTheDocument();
  expect(screen.getByRole('textbox', { name: 'Saved group ID' })).toHaveValue(id('193'));
  expect(localStorage.getItem('openpc:group-workflow:v1')).not.toBeNull();
  expect(fetch.mock.calls.some(([, options]) => options?.method === 'POST')).toBe(false);
});
it('clears a displayed group and skips the old saved ID when inventory refresh changes actor', async () => {
  writeBoundPolicyState('openpc:group-workflow:v1', actor, review);
  let inventoryReads = 0;
  const fetch = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
    const url = String(input);
    if (url.includes('resumeApprovalRequestId='))
      return Response.json({
        candidateDigest: review.review.candidateDigest,
        state: 'APPROVED',
        operationId: null,
      });
    if (url.includes('groupId='))
      return Response.json({
        ...readback,
        effect: {
          ...readback.effect,
          groupId: id('193'),
          groupName: 'Selected group',
          operationId: id('851'),
        },
      });
    inventoryReads += 1;
    return Response.json(
      inventoryReads === 1 ? state : { ...state, actor: { ...actor, sessionId: id('702') } },
    );
  });
  const user = userEvent.setup();
  render(<GroupWorkflow />);
  await screen.findByLabelText('Group change review');
  await user.click(screen.getByRole('button', { name: 'Open another group' }));
  await screen.findByText('Group: Selected group');
  await user.click(screen.getByRole('button', { name: 'Read saved group' }));
  expect(screen.queryByText('Group: Selected group')).not.toBeInTheDocument();
  expect(screen.queryByLabelText('Group change review')).not.toBeInTheDocument();
  expect(screen.getByRole('textbox', { name: 'Saved group ID' })).toHaveValue('');
  expect(fetch.mock.calls.filter(([url]) => String(url).includes('groupId='))).toHaveLength(1);
  expect(fetch.mock.calls.some(([, options]) => options?.method === 'POST')).toBe(false);
});
it.each(['group', 'Participant'])(
  'rejects a current manually selected group read with a foreign %s binding',
  async (field) => {
    const fetch = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) =>
      Response.json(
        String(input).includes('groupId=')
          ? {
              ...readback,
              effect: {
                ...readback.effect,
                groupId: field === 'group' ? candidate.groupId : id('193'),
                participantId: field === 'Participant' ? id('102') : actor.participantId,
              },
            }
          : state,
      ),
    );
    const user = userEvent.setup();
    render(<GroupWorkflow />);
    await user.click(await screen.findByRole('button', { name: 'Open another group' }));
    expect(await screen.findByRole('alert')).toHaveTextContent(
      'Group readback belongs to a different context.',
    );
    expect(screen.queryByText('Group: Operators')).not.toBeInTheDocument();
    expect(fetch.mock.calls.some(([, options]) => options?.method === 'POST')).toBe(false);
  },
);
it.each(['inventory', 'readback', 'resume'])(
  'aborts an active group %s on unmount and discards late success',
  async (kind) => {
    const pending = deferredResponse();
    if (kind === 'resume') writeBoundPolicyState('openpc:group-workflow:v1', actor, review);
    const fetch = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      const url = String(input);
      if (
        kind === 'inventory' ||
        url.includes('resumeApprovalRequestId=') ||
        url.includes('groupId=')
      )
        return pending.promise;
      return Response.json(state);
    });
    const user = userEvent.setup();
    const view = render(<GroupWorkflow />);
    if (kind === 'readback')
      await user.click(await screen.findByRole('button', { name: 'Open another group' }));
    if (kind !== 'inventory')
      await waitFor(() =>
        expect(
          fetch.mock.calls.some(([url]) =>
            String(url).includes(kind === 'resume' ? 'resumeApprovalRequestId=' : 'groupId='),
          ),
        ).toBe(true),
      );
    const signal = fetch.mock.calls.at(-1)?.[1]?.signal;
    expect(signal?.aborted).toBe(false);
    view.unmount();
    expect(signal?.aborted).toBe(true);
    await act(async () =>
      pending.resolve(
        Response.json(
          kind === 'inventory'
            ? state
            : kind === 'readback'
              ? readback
              : {
                  candidateDigest: review.review.candidateDigest,
                  state: 'CONSUMED',
                  operationId: id('850'),
                  readback,
                },
        ),
      ),
    );
    if (kind === 'resume') expect(localStorage.getItem('openpc:group-workflow:v1')).not.toBeNull();
    expect(fetch.mock.calls.some(([, options]) => options?.method === 'POST')).toBe(false);
  },
);
it.each(['denial', 'malformed', 'unavailable'])(
  'invalidates current group projections on inventory %s, retaining the original for a fresh read',
  async (failure) => {
    writeBoundPolicyState('openpc:group-workflow:v1', actor, review);
    const storedOriginal = localStorage.getItem('openpc:group-workflow:v1');
    const oldResume = deferredResponse();
    let denied = false;
    let holdResume = false;
    let oldSignal: AbortSignal | null | undefined;
    const fetch = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const url = String(input);
      if (url.includes('resumeApprovalRequestId=')) {
        if (holdResume) {
          oldSignal = init?.signal;
          return oldResume.promise;
        }
        return Response.json({
          candidateDigest: review.review.candidateDigest,
          state: 'APPROVED',
          operationId: null,
        });
      }
      if (url.includes('groupId=')) return Response.json(readback);
      if (denied) {
        if (failure === 'unavailable') throw new Error('Current group inventory unavailable.');
        return failure === 'denial'
          ? Response.json({ title: 'Current group inventory denied' }, { status: 403 })
          : Response.json({});
      }
      return Response.json(state);
    });
    const user = userEvent.setup();
    render(<GroupWorkflow />);
    await screen.findByLabelText('Group change review');
    await user.type(screen.getByLabelText('Saved group ID'), candidate.groupId);
    await user.click(screen.getByRole('button', { name: 'Read group' }));
    await screen.findByText('Group: Operators');
    holdResume = true;
    await user.click(screen.getByRole('button', { name: 'Refresh group approvals' }));
    await waitFor(() => expect(oldSignal?.aborted).toBe(false));
    denied = true;
    await user.click(screen.getByRole('button', { name: 'Refresh group approvals' }));
    expect(await screen.findByRole('alert')).toHaveTextContent(
      failure === 'denial'
        ? 'Group request was not authorized. Refresh the authenticated context before continuing.'
        : failure === 'unavailable'
          ? 'Group request could not be confirmed. Refresh or read the original operation before retrying.'
          : 'Group approvals could not be confirmed. Refresh before continuing.',
    );
    expect(screen.queryByLabelText('Group change review')).not.toBeInTheDocument();
    expect(oldSignal?.aborted).toBe(true);
    expect(screen.queryByLabelText('Group result')).not.toBeInTheDocument();
    expect(screen.queryByText(/Signed-in principal:/u)).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Open another group' })).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Prepare group change' })).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Read group' })).toBeDisabled();
    expect(screen.getByLabelText('Saved group ID')).toHaveValue('');
    expect(localStorage.getItem('openpc:group-workflow:v1')).toBe(storedOriginal);
    await act(async () =>
      oldResume.resolve(
        Response.json({
          candidateDigest: review.review.candidateDigest,
          state: 'CONSUMED',
          operationId: id('850'),
          readback,
        }),
      ),
    );
    expect(screen.queryByLabelText('Group result')).not.toBeInTheDocument();
    expect(screen.queryByLabelText('Group change review')).not.toBeInTheDocument();
    expect(localStorage.getItem('openpc:group-workflow:v1')).toBe(storedOriginal);
    denied = false;
    holdResume = false;
    await user.click(screen.getByRole('button', { name: 'Refresh group approvals' }));
    await screen.findByLabelText('Group change review');
    expect(screen.getByText(`Signed-in principal: ${actor.principalId}`)).toBeVisible();
    expect(screen.queryByLabelText('Group result')).not.toBeInTheDocument();
    expect(screen.getByLabelText('Saved group ID')).toHaveValue('');
    expect(localStorage.getItem('openpc:group-workflow:v1')).toBe(storedOriginal);
    expect(fetch.mock.calls.some(([, options]) => options?.method === 'POST')).toBe(false);
    expect(performWebAuthnStepUp).not.toHaveBeenCalled();
  },
);

const unsafeGroupMarker = 'PRIVATE_GROUP_SERVER_TRANSPORT_OR_VALIDATOR_DETAIL';
const groupUnavailable =
  'Group request could not be confirmed. Refresh or read the original operation before retrying.';
const groupFailures = [
  {
    name: 'authorization',
    status: 403,
    message:
      'Group request was not authorized. Refresh the authenticated context before continuing.',
  },
  {
    name: 'conflict',
    status: 409,
    message: 'Group state changed. Refresh or read the original operation before retrying.',
  },
  {
    name: 'input',
    status: 422,
    message: 'Group request was rejected. Check the inputs before continuing.',
  },
  { name: 'unknown code', status: 503, message: groupUnavailable },
  { name: 'transport', message: groupUnavailable },
  { name: 'unknown thrown object', message: groupUnavailable },
  { name: 'non-JSON success', message: groupUnavailable },
] as const;
function failGroup(failure: (typeof groupFailures)[number]): Response {
  if ('status' in failure)
    return Response.json(
      { title: unsafeGroupMarker, code: unsafeGroupMarker },
      { status: failure.status },
    );
  if (failure.name === 'transport') throw new Error(unsafeGroupMarker);
  if (failure.name === 'unknown thrown object')
    throw { message: unsafeGroupMarker, details: unsafeGroupMarker };
  return new Response(unsafeGroupMarker, { status: 200 });
}
function groupApproval(approvalState: string) {
  return {
    approvalRequestId: `urn:openpc:resource:${review.approvalRequestId}`,
    candidateDigest: review.review.candidateDigest,
    makerSubjectRef: `urn:openpc:resource:${actor.principalId}`,
    checkerSubjectRef: `urn:openpc:resource:${review.review.checkerPrincipalId}`,
    revision: '1',
    state: approvalState,
    proposal: {
      candidateDigest: review.review.candidateDigest,
      resourceId: candidate.groupId,
      makerPrincipalId: actor.principalId,
      catalogOperationId: 'ID-OP-GROUP-CREATE',
      expectedRevision: '0',
      state: approvalState,
      operationId: null,
      expiresAt: review.review.expiresAt,
      candidate,
    },
    stepUp: review.review.stepUp,
  };
}
function groupReader(input: RequestInfo | URL, approvals: ReturnType<typeof groupApproval>[] = []) {
  if (String(input).includes('resumeApprovalRequestId='))
    return Response.json({
      candidateDigest: review.review.candidateDigest,
      state: 'APPROVED',
      operationId: null,
    });
  return Response.json({ ...state, approvals, nextCursor: 'next-group-page' });
}
it.each(groupFailures)(
  'hides $name from the initial group reader without inventing an empty inventory',
  async (failure) => {
    writeBoundPolicyState('openpc:group-workflow:v1', actor, review);
    const original = localStorage.getItem('openpc:group-workflow:v1');
    const fetcher = vi
      .spyOn(globalThis, 'fetch')
      .mockImplementation(async () => failGroup(failure));
    render(<GroupWorkflow />);
    await screen.findByRole('alert');
    expect(screen.getByRole('alert')).toHaveTextContent(failure.message);
    expect(document.body.textContent).not.toContain(unsafeGroupMarker);
    expect(screen.queryByText('No group approvals on this page.')).not.toBeInTheDocument();
    expect(localStorage.getItem('openpc:group-workflow:v1')).toBe(original);
    expect(fetcher.mock.calls.some(([, init]) => init?.method === 'POST')).toBe(false);
  },
);
it.each(
  groupFailures.flatMap((failure) =>
    ['prepare', 'submit', 'approve', 'commit'].map((boundary) => ({ ...failure, boundary })),
  ),
)('hides $name from group $boundary and retains the exact original review', async (failure) => {
  const value =
    failure.boundary === 'submit'
      ? { reviewToken: review.reviewToken, review: review.review }
      : review;
  writeBoundPolicyState('openpc:group-workflow:v1', actor, value);
  const original = localStorage.getItem('openpc:group-workflow:v1');
  const approvals =
    failure.boundary === 'approve' || failure.boundary === 'commit'
      ? [groupApproval(failure.boundary === 'approve' ? 'REQUESTED' : 'APPROVED')]
      : [];
  const fetcher = vi
    .spyOn(globalThis, 'fetch')
    .mockImplementation(async (input, init) =>
      init?.method === 'POST' ? failGroup(failure) : groupReader(input, approvals),
    );
  render(<GroupWorkflow />);
  await screen.findByLabelText('Group change review');
  const names = {
    prepare: 'Prepare group change',
    submit: 'Verify and request group approval',
    approve: 'Verify and approve group change',
    commit: 'Verify and commit group change',
  };
  const control = screen.getByRole('button', {
    name: names[failure.boundary as keyof typeof names],
  });
  if (failure.boundary === 'prepare') {
    fireEvent.change(screen.getByLabelText('Group name'), { target: { value: 'New group' } });
    fireEvent.change(screen.getByLabelText('Checker principal ID'), {
      target: { value: id('112') },
    });
    fireEvent.change(screen.getByLabelText('Reason for group change'), {
      target: { value: 'Review the exact proposed group.' },
    });
    fireEvent.submit(control.closest('form')!);
  } else fireEvent.click(control);
  await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent(failure.message));
  expect(document.body.textContent).not.toContain(unsafeGroupMarker);
  expect(localStorage.getItem('openpc:group-workflow:v1')).toBe(original);
  expect(screen.queryByText(/Group change committed\. Operation:/)).not.toBeInTheDocument();
  expect(screen.queryByText(/Approval requested\./)).not.toBeInTheDocument();
  const posts = fetcher.mock.calls.filter(([, init]) => init?.method === 'POST');
  expect(posts).toHaveLength(1);
  const body = JSON.parse(String(posts[0]![1]!.body));
  if (failure.boundary === 'commit')
    expect(body).toEqual({
      command: 'COMMIT',
      reviewToken: value.reviewToken,
      approvalRequestId: review.approvalRequestId,
    });
  else if (failure.boundary === 'approve')
    expect(body).toEqual({
      command: 'APPROVE',
      approvalRequestId: review.approvalRequestId,
      candidateDigest: review.review.candidateDigest,
      expectedRevision: '1',
    });
  else
    expect(body).toMatchObject({ command: failure.boundary === 'prepare' ? 'PREPARE' : 'SUBMIT' });
});
it.each(['prepare', 'submit', 'commit', 'readback'] as const)(
  'hides structured validator details at group %s without replacing stored custody',
  async (boundary) => {
    const value =
      boundary === 'submit' ? { reviewToken: review.reviewToken, review: review.review } : review;
    writeBoundPolicyState('openpc:group-workflow:v1', actor, value);
    const original = localStorage.getItem('openpc:group-workflow:v1');
    const fetcher = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) =>
      init?.method === 'POST' || String(input).includes('groupId=')
        ? Response.json({
            review: { mutation: unsafeGroupMarker },
            truthState: unsafeGroupMarker,
            effect: { state: unsafeGroupMarker },
          })
        : groupReader(input, boundary === 'commit' ? [groupApproval('APPROVED')] : []),
    );
    render(<GroupWorkflow />);
    await screen.findByLabelText('Group change review');
    const name =
      boundary === 'prepare'
        ? 'Prepare group change'
        : boundary === 'submit'
          ? 'Verify and request group approval'
          : boundary === 'commit'
            ? 'Verify and commit group change'
            : 'Read saved group';
    const control = screen.getByRole('button', { name });
    if (boundary === 'prepare') {
      fireEvent.change(screen.getByLabelText('Group name'), { target: { value: 'New group' } });
      fireEvent.change(screen.getByLabelText('Checker principal ID'), {
        target: { value: id('112') },
      });
      fireEvent.change(screen.getByLabelText('Reason for group change'), {
        target: { value: 'Review the exact proposed group.' },
      });
      fireEvent.submit(control.closest('form')!);
    } else fireEvent.click(control);
    await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent(groupUnavailable));
    expect(document.body.textContent).not.toContain(unsafeGroupMarker);
    expect(document.body.textContent).not.toContain('invalid_type');
    expect(localStorage.getItem('openpc:group-workflow:v1')).toBe(original);
    expect(fetcher.mock.calls.filter(([, init]) => init?.method === 'POST')).toHaveLength(
      boundary === 'readback' ? 0 : 1,
    );
  },
);
it.each(['saved readback', 'approval cursor', 'membership cursor', 'silent resume'] as const)(
  'hides unsafe group errors from %s while preserving the original intent',
  async (boundary) => {
    writeBoundPolicyState('openpc:group-workflow:v1', actor, review);
    const original = localStorage.getItem('openpc:group-workflow:v1');
    let fail = boundary === 'silent resume';
    const fetcher = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      const url = String(input);
      if (fail && (boundary !== 'silent resume' || url.includes('resumeApprovalRequestId=')))
        return failGroup({ name: 'transport', message: groupUnavailable });
      if (url.includes('groupId=')) return Response.json({ ...readback, nextCursor: id('999') });
      return groupReader(input);
    });
    render(<GroupWorkflow />);
    await screen.findByLabelText('Group change review');
    if (boundary === 'silent resume') {
      await waitFor(() =>
        expect(
          fetcher.mock.calls.some(([input]) => String(input).includes('resumeApprovalRequestId=')),
        ).toBe(true),
      );
      expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    } else {
      if (boundary === 'membership cursor') {
        fireEvent.click(screen.getByRole('button', { name: 'Read saved group' }));
        await screen.findByRole('button', { name: 'Next memberships' });
      }
      fail = true;
      fireEvent.click(
        screen.getByRole('button', {
          name:
            boundary === 'membership cursor'
              ? 'Next memberships'
              : boundary === 'approval cursor'
                ? 'Next group approvals'
                : 'Read saved group',
        }),
      );
      await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent(groupUnavailable));
    }
    expect(document.body.textContent).not.toContain(unsafeGroupMarker);
    expect(localStorage.getItem('openpc:group-workflow:v1')).toBe(original);
    expect(fetcher.mock.calls.some(([, init]) => init?.method === 'POST')).toBe(false);
    expect(screen.queryByText(/Group change already committed\./)).not.toBeInTheDocument();
  },
);
it('keeps the local authenticator failure message and sends no group submission on a thrown private error', async () => {
  writeBoundPolicyState('openpc:group-workflow:v1', actor, {
    reviewToken: review.reviewToken,
    review: review.review,
  });
  const original = localStorage.getItem('openpc:group-workflow:v1');
  vi.mocked(performWebAuthnStepUp).mockRejectedValueOnce(new Error(unsafeGroupMarker));
  const fetcher = vi
    .spyOn(globalThis, 'fetch')
    .mockImplementation(async (input) => groupReader(input));
  render(<GroupWorkflow />);
  fireEvent.click(await screen.findByRole('button', { name: 'Verify and request group approval' }));
  await waitFor(() =>
    expect(screen.getByRole('alert')).toHaveTextContent(
      'WebAuthn verification was not completed. Connect the registered authenticator and retry; no group request was staged.',
    ),
  );
  expect(document.body.textContent).not.toContain(unsafeGroupMarker);
  expect(localStorage.getItem('openpc:group-workflow:v1')).toBe(original);
  expect(fetcher.mock.calls.some(([, init]) => init?.method === 'POST')).toBe(false);
});

it.each(['submit', 'commit', 'checker'] as const)(
  'cancels held group %s proof on unmount and preserves original custody',
  async (kind) => {
    const value =
      kind === 'submit' ? { reviewToken: review.reviewToken, review: review.review } : review;
    writeBoundPolicyState('openpc:group-workflow:v1', actor, value);
    const original = localStorage.getItem('openpc:group-workflow:v1');
    const held = holdStepUp();
    const fetcher = vi
      .spyOn(globalThis, 'fetch')
      .mockImplementation(async (input) =>
        groupReader(input, [groupApproval(kind === 'checker' ? 'REQUESTED' : 'APPROVED')]),
      );
    const view = render(<GroupWorkflow />);
    fireEvent.click(
      await screen.findByRole('button', {
        name:
          kind === 'submit'
            ? 'Verify and request group approval'
            : kind === 'commit'
              ? 'Verify and commit group change'
              : 'Verify and approve group change',
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
    expect(localStorage.getItem('openpc:group-workflow:v1')).toBe(original);
  },
);
it('stops held group commit when original owner resume confirms consumption before proof returns', async () => {
  writeBoundPolicyState('openpc:group-workflow:v1', actor, review);
  const held = holdStepUp(),
    resume = deferredResponse();
  const fetcher = vi
    .spyOn(globalThis, 'fetch')
    .mockImplementation(async (input) =>
      String(input).includes('resumeApprovalRequestId=')
        ? resume.promise.then((response) => response.clone())
        : Response.json({ ...state, approvals: [groupApproval('APPROVED')] }),
    );
  render(<GroupWorkflow />);
  fireEvent.click(await screen.findByRole('button', { name: 'Verify and commit group change' }));
  await waitFor(() => expect(held.entered).toHaveBeenCalledOnce());
  await act(async () =>
    resume.resolve(
      Response.json({
        candidateDigest: review.review.candidateDigest,
        state: 'CONSUMED',
        operationId: id('850'),
        readback,
      }),
    ),
  );
  await screen.findByText(/Group change already committed/);
  expect(held.lifecycle().isCurrent?.()).toBe(false);
  const completed = expect(held.completion()).rejects.toMatchObject({ name: 'AbortError' });
  await act(async () => {
    held.release();
    await completed;
  });
  await waitFor(() =>
    expect(screen.getByRole('button', { name: 'Refresh group approvals' })).toBeEnabled(),
  );
  expect(fetcher.mock.calls.some(([, init]) => init?.method === 'POST')).toBe(false);
  expect(localStorage.getItem('openpc:group-workflow:v1')).toBeNull();
  expect(screen.queryByLabelText('Group change review')).not.toBeInTheDocument();
});
it.each(['submit', 'commit', 'checker'] as const)(
  'sends one exact current group %s command after proof and preserves original owner semantics',
  async (kind) => {
    writeBoundPolicyState(
      'openpc:group-workflow:v1',
      actor,
      kind === 'submit' ? { reviewToken: review.reviewToken, review: review.review } : review,
    );
    const held = holdStepUp(),
      posts: unknown[] = [];
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      if (init?.method === 'POST') {
        posts.push(JSON.parse(String(init.body)));
        return Response.json(
          kind === 'submit'
            ? { ...review, approval: { approvalRequestId: review.approvalRequestId } }
            : { truthState: 'SUCCESS', operationId: id('850'), readback },
        );
      }
      return groupReader(input, [groupApproval(kind === 'checker' ? 'REQUESTED' : 'APPROVED')]);
    });
    render(<GroupWorkflow />);
    const button = await screen.findByRole('button', {
      name:
        kind === 'submit'
          ? 'Verify and request group approval'
          : kind === 'commit'
            ? 'Verify and commit group change'
            : 'Verify and approve group change',
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
      expect(screen.getByRole('button', { name: 'Refresh group approvals' })).toBeEnabled(),
    );
    expect(posts).toEqual([
      kind === 'submit'
        ? { command: 'SUBMIT', reviewToken: review.reviewToken }
        : kind === 'commit'
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
  },
);

it.each(['success', 'interruption'] as const)(
  'preserves issued group original custody after late %s without starting post-unmount reads',
  async (outcome) => {
    writeBoundPolicyState('openpc:group-workflow:v1', actor, review);
    const original = localStorage.getItem('openpc:group-workflow:v1');
    let resolve!: (value: Response) => void, reject!: (cause: Error) => void;
    const pending = new Promise<Response>((yes, no) => {
      resolve = yes;
      reject = no;
    });
    const fetcher = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      if (init?.method === 'POST') return pending;
      return Response.json(
        String(input).includes('resumeApprovalRequestId=')
          ? { candidateDigest: review.review.candidateDigest, state: 'APPROVED', operationId: null }
          : { ...state, approvals: [groupApproval('APPROVED')] },
      );
    });
    const view = render(<GroupWorkflow />);
    fireEvent.click(await screen.findByRole('button', { name: 'Verify and commit group change' }));
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
    expect(localStorage.getItem('openpc:group-workflow:v1')).toBe(original);
    expect(performWebAuthnStepUp).toHaveBeenCalledOnce();
  },
);
