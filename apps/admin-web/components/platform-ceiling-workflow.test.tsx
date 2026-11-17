import { act, cleanup, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { webcrypto } from 'node:crypto';
import { canonicalAuthorizationDigest } from '../../../services/identity-service/src/contracts/authorization';
import { envelopeFixtureId as id } from '../../../packages/security-kernel/src/identity-envelope/fixture';
import { PlatformCeilingWorkflow } from './platform-ceiling-workflow';
import { performWebAuthnStepUp } from '@openpc/ui-shell';
import { platformRecoveryFixture } from '../../../services/identity-service/src/domain/platform-recovery.test-fixture';
vi.mock('@openpc/ui-shell', () => ({ performWebAuthnStepUp: vi.fn() }));
beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(performWebAuthnStepUp).mockReset().mockResolvedValue(undefined);
  vi.stubGlobal('crypto', webcrypto);
  let custodyQueue = Promise.resolve();
  vi.stubGlobal(
    'navigator',
    Object.assign(Object.create(navigator), {
      locks: {
        request: (_name: string, _options: unknown, work: () => unknown) => {
          const result = custodyQueue.then(work);
          custodyQueue = result.then(
            () => undefined,
            () => undefined,
          );
          return result;
        },
      } as unknown as LockManager,
    }),
  );
});

afterEach(() => {
  cleanup();
  localStorage.clear();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});
it('keeps commit review disabled until signed withdrawal and both administrator handoffs are ready', async () => {
  let ready = false;
  const fetchMock = vi.spyOn(globalThis, 'fetch').mockImplementation(async (url) => {
    const query = new URL(String(url), 'http://localhost').searchParams;
    return Response.json(
      query.get('replacementId')
        ? {
            readiness: {
              state: 'WITHDRAWING',
              unacknowledgedTargets: ready ? 0 : 1,
              unpreparedAdministrators: ready ? 0 : 1,
              administrators: [
                { principalId: 'maker', envelopeId: 'envelope', assignmentId: 'assignment', ready },
              ],
            },
          }
        : {
            actor: {
              sessionId: id(900),
              principalId: id(901),
              participantId: id(902),
              privacyDomainId: id(903),
              contextEpoch: '1',
            },
            suggestedIds: { replacementId: '018f0000-0000-7000-8000-000000000901' },
          },
    );
  });
  const user = userEvent.setup();
  render(<PlatformCeilingWorkflow />);
  await user.type(
    screen.getByLabelText('Platform context ID'),
    '018f0000-0000-7000-8000-000000000401',
  );
  await user.click(screen.getByRole('button', { name: 'Read withdrawal and handoff readiness' }));
  expect(
    await screen.findByRole('button', { name: 'Review ready successor commit' }),
  ).toBeDisabled();
  ready = true;
  await user.click(screen.getByRole('button', { name: 'Read withdrawal and handoff readiness' }));
  expect(
    await screen.findByRole('button', { name: 'Review ready successor commit' }),
  ).toBeEnabled();
  expect(fetchMock.mock.calls.every(([, init]) => init?.method !== 'POST')).toBe(true);
});

it.each(['PREPARE', 'COMMIT'] as const)(
  'retains the %s original before submission and always requires fresh maker proof for execution',
  async (phase) => {
    const { intent } = platformRecoveryFixture(),
      plan = intent.preparation;
    const actor = {
      sessionId: id(900),
      principalId: plan.administrators[0]!.principalId,
      participantId: id(902),
      privacyDomainId: id(903),
      contextEpoch: '1',
    };
    const body =
      phase === 'PREPARE'
        ? plan
        : {
            schema: 'pc.identity.platform-scope-replacement-commit',
            schemaVersion: 1,
            replacementId: plan.replacementId,
            platformContextId: plan.platformContextId,
            expectedRootRevision: plan.expectedRootRevision,
            expectedReplacementRevision: '1',
            predecessorEpoch: plan.predecessorEpoch,
            predecessorDigest: plan.predecessorDigest,
            successorDigest: 'sha256:' + 'c'.repeat(64),
            readinessDigest: 'sha256:' + 'd'.repeat(64),
            reason: 'Commit the exact stored ready handoff.',
          };
    const step = {
      actionIntentId: 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
      actionIntentDigest: 'sha256:' + 'a'.repeat(64),
      resourceId: plan.replacementId,
      resourceDigest: canonicalAuthorizationDigest(body),
    };
    const reviewed = {
      reviewToken: 'original-sealed-key-body-actor',
      review: {
        phase,
        businessIdempotencyKey: 'original-reviewed-business-key',
        body,
        candidateDigest: step.resourceDigest,
        checkerPrincipalId: plan.administrators[1]!.principalId,
        stepUp: step,
      },
    };
    const key = 'openpc:platform-ceiling-review:v1';
    localStorage.setItem(key, JSON.stringify({ ...reviewed, actor }));
    const events: string[] = [];
    vi.mocked(performWebAuthnStepUp).mockImplementation(async () => {
      events.push('proof');
    });
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (url, init) => {
      if (init?.method === 'POST') {
        const command = JSON.parse(String(init.body));
        events.push(command.command);
        expect(JSON.parse(localStorage.getItem(key)!)).toMatchObject({ ...reviewed, actor });
        expect(command.reviewToken).toBe(reviewed.reviewToken);
        return Response.json(
          command.command === 'SUBMIT'
            ? { ...reviewed, approvalRequestId: id(909) }
            : { result: { state: 'COMMITTED' } },
        );
      }
      if (new URL(String(url), 'http://localhost').searchParams.get('approvalRequestId'))
        return Response.json({
          approval: { state: 'APPROVED', makerSubjectRef: 'maker', checkerSubjectRef: 'checker' },
          body,
          stepUp: null,
        });
      return Response.json({
        actor,
        suggestedIds: {},
        administratorLifetime: { minimumSeconds: 60, maximumSeconds: 3600, defaultSeconds: 3600 },
      });
    });
    const user = userEvent.setup();
    render(<PlatformCeilingWorkflow />);
    await user.click(
      await screen.findByRole('button', { name: 'Request independent replacement approval' }),
    );
    expect(events).toEqual(phase === 'PREPARE' ? ['proof', 'SUBMIT'] : ['SUBMIT']);
    await user.click(screen.getByRole('button', { name: 'Load replacement approval' }));
    await screen.findByText(/Approval state: APPROVED/);
    await user.click(screen.getByRole('button', { name: 'Execute approved replacement phase' }));
    expect(events).toEqual(
      phase === 'PREPARE'
        ? ['proof', 'SUBMIT', 'proof', 'EXECUTE']
        : ['SUBMIT', 'proof', 'EXECUTE'],
    );
    expect(performWebAuthnStepUp).toHaveBeenLastCalledWith(
      { ...step, stepUp: 'FRESH_WEBAUTHN_MAX_5M' },
      { resourceId: step.resourceId, resourceDigest: step.resourceDigest },
      expect.objectContaining({ signal: expect.anything(), isCurrent: expect.any(Function) }),
    );
  },
);
function retainedFixture(phase: 'PREPARE' | 'COMMIT' = 'COMMIT') {
  const { intent } = platformRecoveryFixture(),
    plan = intent.preparation;
  const actor = {
    sessionId: id(900),
    principalId: plan.administrators[0]!.principalId,
    participantId: id(902),
    privacyDomainId: id(903),
    contextEpoch: '1',
  };
  const body =
    phase === 'PREPARE'
      ? plan
      : {
          schema: 'pc.identity.platform-scope-replacement-commit',
          schemaVersion: 1,
          replacementId: plan.replacementId,
          platformContextId: plan.platformContextId,
          expectedRootRevision: plan.expectedRootRevision,
          expectedReplacementRevision: '1',
          predecessorEpoch: plan.predecessorEpoch,
          predecessorDigest: plan.predecessorDigest,
          successorDigest: 'sha256:' + 'c'.repeat(64),
          readinessDigest: 'sha256:' + 'd'.repeat(64),
          reason: 'Commit the original ready handoff.',
        };
  const digest = canonicalAuthorizationDigest(body);
  const reviewed = {
    reviewToken: 'unchanged-original-token',
    review: {
      phase,
      businessIdempotencyKey: 'original-reviewed-business-key',
      checkerPrincipalId: plan.administrators[1]!.principalId,
      candidateDigest: digest,
      body,
      stepUp: {
        actionIntentId: 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
        actionIntentDigest: 'sha256:' + 'a'.repeat(64),
        resourceId: plan.replacementId,
        resourceDigest: digest,
      },
    },
  };
  const key = 'openpc:platform-ceiling-review:v1';
  localStorage.setItem(key, JSON.stringify({ ...reviewed, actor }));
  return { actor, reviewed, key };
}
it('retains the caller-held commit review after an ambiguous stage response without automatic retry or private error exposure', async () => {
  const v = retainedFixture(),
    post = vi.fn();
  vi.spyOn(globalThis, 'fetch').mockImplementation(async (_url, init) => {
    if (init?.method === 'POST') {
      post();
      throw new Error('private upstream secret exception');
    }
    return Response.json({ actor: v.actor, suggestedIds: {} });
  });
  const user = userEvent.setup();
  render(<PlatformCeilingWorkflow />);
  await user.click(
    await screen.findByRole('button', { name: 'Request independent replacement approval' }),
  );
  expect(await screen.findByRole('status')).toHaveTextContent(
    'The original request could not be confirmed.',
  );
  expect(document.body).not.toHaveTextContent('private upstream');
  expect(JSON.parse(localStorage.getItem(v.key)!)).toMatchObject({
    ...v.reviewed,
    actor: v.actor,
    disposition: 'UNCERTAIN',
  });
  expect(post).toHaveBeenCalledOnce();
  expect(performWebAuthnStepUp).not.toHaveBeenCalled();
});
it.each(['throw', 'ignored'] as const)(
  'fails closed when original review storage is %s before any proof or durable request',
  async (mode) => {
    const v = retainedFixture('PREPARE'),
      post = vi.fn();
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (_url, init) => {
      if (init?.method === 'POST') post();
      return Response.json({ actor: v.actor, suggestedIds: {} });
    });
    const user = userEvent.setup();
    render(<PlatformCeilingWorkflow />);
    const submit = await screen.findByRole('button', {
      name: 'Request independent replacement approval',
    });
    vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => {
      if (mode === 'throw') throw new Error('private quota metadata');
    });
    await user.click(submit);
    expect(await screen.findByRole('status')).toHaveTextContent(
      'The original review could not be saved.',
    );
    expect(post).not.toHaveBeenCalled();
    expect(performWebAuthnStepUp).not.toHaveBeenCalled();
  },
);
it.each(['unmount', 'edited context'] as const)(
  'stops a held proof suffix after %s and preserves original uncertainty',
  async (mode) => {
    const v = retainedFixture('PREPARE'),
      post = vi.fn();
    let complete!: () => void;
    vi.mocked(performWebAuthnStepUp).mockImplementation(
      () =>
        new Promise<void>((resolve) => {
          complete = resolve;
        }),
    );
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (_url, init) => {
      if (init?.method === 'POST') post();
      return Response.json({ actor: v.actor, suggestedIds: {} });
    });
    const user = userEvent.setup(),
      view = render(<PlatformCeilingWorkflow />);
    const submit = await screen.findByRole('button', {
      name: 'Request independent replacement approval',
    });
    await user.click(submit);
    await user.click(submit);
    expect(performWebAuthnStepUp).toHaveBeenCalledOnce();
    if (mode === 'unmount') view.unmount();
    else await user.type(screen.getByLabelText('Platform context ID'), 'changed');
    complete();
    await Promise.resolve();
    await Promise.resolve();
    expect(post).not.toHaveBeenCalled();
    expect(JSON.parse(localStorage.getItem(v.key)!)).toMatchObject({
      reviewToken: v.reviewed.reviewToken,
      disposition: 'UNCERTAIN',
    });
  },
);
it('rejects a tampered full commit review without showing private candidate content or issuing a proof', async () => {
  const v = retainedFixture();
  localStorage.setItem(
    v.key,
    JSON.stringify({
      ...v.reviewed,
      actor: v.actor,
      review: {
        ...v.reviewed.review,
        body: { ...v.reviewed.review.body, reason: 'Private tampered candidate' },
      },
    }),
  );
  vi.spyOn(globalThis, 'fetch').mockResolvedValue(
    Response.json({ actor: v.actor, suggestedIds: {} }),
  );
  render(<PlatformCeilingWorkflow />);
  expect(
    await screen.findByText(
      'The original review could not be saved. Restore browser storage before continuing.',
    ),
  ).toBeVisible();
  expect(
    screen.queryByRole('button', { name: 'Request independent replacement approval' }),
  ).toBeNull();
  expect(document.body).not.toHaveTextContent('Private tampered');
  expect(performWebAuthnStepUp).not.toHaveBeenCalled();
});
it('removes another actor plaintext view while preserving opaque original custody and no continuation', async () => {
  const v = retainedFixture();
  vi.spyOn(globalThis, 'fetch').mockResolvedValue(
    Response.json({ actor: { ...v.actor, sessionId: id(999) }, suggestedIds: {} }),
  );
  render(<PlatformCeilingWorkflow />);
  expect(await screen.findByRole('status')).toHaveTextContent('The working context changed.');
  const stored = JSON.parse(localStorage.getItem(v.key)!);
  expect(stored.reviewToken).toBe(v.reviewed.reviewToken);
  expect(stored.review).toBeUndefined();
  expect(
    screen.queryByRole('button', { name: 'Request independent replacement approval' }),
  ).toBeNull();
});

it.each([
  'valid',
  'missing-proof-binding',
  'wrong-action',
  'wrong-resource',
  'failed-assertion',
  'unmounted-assertion',
] as const)(
  'requires exact fresh receiving proof before adopting the same-original resumed seal: %s',
  async (mode) => {
    const v = retainedFixture(),
      a = id(777),
      b = id(778),
      readSeal = 'owner-recovered-same-original-token',
      resumeSeal = 'owner-resumed-same-original-token';
    const read = { ...v.reviewed, reviewToken: readSeal, approvalRequestId: a },
      resumed = { ...read, reviewToken: resumeSeal, approvalRequestId: b };
    const receivingStep = {
      actionIntentId:
        mode === 'wrong-action'
          ? 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1'
          : 'ACT-APPROVAL_REQUESTS_UPDATE_RESOURCE-V1',
      actionIntentDigest: 'sha256:' + 'a'.repeat(64),
      resourceId: mode === 'wrong-resource' ? b : a,
      resourceDigest: 'sha256:' + 'b'.repeat(64),
    };
    if (mode === 'failed-assertion')
      vi.mocked(performWebAuthnStepUp).mockRejectedValueOnce(new Error('Actual assertion failed'));
    let releaseAssertion: (() => void) | undefined;
    if (mode === 'unmounted-assertion')
      vi.mocked(performWebAuthnStepUp).mockImplementationOnce(
        () =>
          new Promise<void>((resolve) => {
            releaseAssertion = resolve;
          }),
      );
    const posts: Record<string, unknown>[] = [];
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (_url, init) => {
      if (init?.method === 'POST') {
        const body = JSON.parse(String(init.body));
        posts.push(body);
        return Response.json(resumed);
      }
      const q = new URL(String(_url), 'http://localhost').searchParams;
      if (q.get('approvalRequestId'))
        return Response.json({
          approval: {
            state: 'APPROVED',
            makerSubjectRef: 'urn:openpc:resource:' + v.actor.principalId,
            checkerSubjectRef: 'checker',
          },
          candidate: { canRequestResume: true },
          body: v.reviewed.review.body,
          stepUp: null,
          resumeStepUp: mode === 'missing-proof-binding' ? null : receivingStep,
          resumableReview: read,
        });
      return Response.json({ actor: v.actor, suggestedIds: {} });
    });
    const user = userEvent.setup();
    const rendered = render(<PlatformCeilingWorkflow />);
    await screen.findByRole('button', { name: 'Request independent replacement approval' });
    await user.type(screen.getByLabelText('Replacement approval ID'), a);
    await user.click(screen.getByRole('button', { name: 'Load replacement approval' }));
    await screen.findByText('Authoritative immutable replacement approval loaded.');
    expect(JSON.parse(localStorage.getItem(v.key)!)).toMatchObject({
      reviewToken: readSeal,
      originalReviewToken: v.reviewed.reviewToken,
    });
    const resumeButton = screen.getByRole('button', {
      name: 'Request fresh approval for unchanged replacement',
    });
    if (['missing-proof-binding', 'wrong-action', 'wrong-resource'].includes(mode)) {
      expect(resumeButton).toBeDisabled();
      expect(performWebAuthnStepUp).not.toHaveBeenCalled();
      expect(posts).toEqual([]);
      return;
    }
    expect(resumeButton).toBeEnabled();
    await user.click(resumeButton);
    await waitFor(() => expect(performWebAuthnStepUp).toHaveBeenCalledTimes(1));
    expect(performWebAuthnStepUp).toHaveBeenCalledWith(
      { ...receivingStep, stepUp: 'FRESH_WEBAUTHN_MAX_5M' },
      { resourceId: a, resourceDigest: receivingStep.resourceDigest },
      expect.objectContaining({ signal: expect.any(AbortSignal), isCurrent: expect.any(Function) }),
    );
    if (mode === 'unmounted-assertion') {
      const options = vi.mocked(performWebAuthnStepUp).mock.calls[0]![2]!;
      rendered.unmount();
      expect(options.signal?.aborted).toBe(true);
      expect(options.isCurrent?.()).toBe(false);
      await act(async () => {
        releaseAssertion?.();
        await Promise.resolve();
      });
      expect(posts).toEqual([]);
      return;
    }
    if (mode === 'failed-assertion') {
      await screen.findByText(
        'The original request could not be confirmed. Read its authoritative state before retrying.',
      );
      expect(posts).toEqual([]);
      expect(JSON.parse(localStorage.getItem(v.key)!)).toMatchObject({
        reviewToken: readSeal,
        originalReviewToken: v.reviewed.reviewToken,
      });
      return;
    }
    await screen.findByText(/A successor approval was requested/);
    expect(posts).toEqual([{ command: 'RESUME', reviewToken: readSeal, approvalRequestId: a }]);
    expect(JSON.parse(localStorage.getItem(v.key)!)).toMatchObject({
      reviewToken: resumeSeal,
      originalReviewToken: v.reviewed.reviewToken,
      review: { candidateDigest: v.reviewed.review.candidateDigest, body: v.reviewed.review.body },
    });
  },
);

it.each(['UNCERTAIN', 'REQUESTED'] as const)(
  'refreshes the same recovery review without clearing its %s custody or requesting a new effect',
  async (disposition) => {
    const v = retainedFixture('PREPARE'),
      approvalRequestId = disposition === 'REQUESTED' ? id(777) : undefined;
    localStorage.setItem(
      v.key,
      JSON.stringify({
        ...v.reviewed,
        actor: v.actor,
        disposition,
        ...(approvalRequestId ? { approvalRequestId } : {}),
      }),
    );
    const posts: Record<string, unknown>[] = [];
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (_url, init) => {
      if (init?.method === 'POST') {
        posts.push(JSON.parse(String(init.body)));
        return Response.json({ ...v.reviewed, reviewToken: 'current-owner-same-original-seal' });
      }
      return Response.json({ actor: v.actor, suggestedIds: {} });
    });
    const user = userEvent.setup();
    render(<PlatformCeilingWorkflow />);
    await screen.findByRole('button', { name: 'Request independent replacement approval' });
    await user.type(screen.getByLabelText('Recovery enrollment ID'), id(700));
    await user.type(screen.getByLabelText('Recovery case ID'), id(701));
    await user.click(screen.getByRole('button', { name: 'Review original recovery handoff' }));
    await screen.findByText(
      'The original recovery preparation is loaded for independent approval. No Root handoff has executed.',
    );
    expect(posts).toEqual([
      {
        command: 'PREVIEW_RECOVERY_HANDOFF',
        enrollmentId: id(700),
        recoveryId: id(701),
        retainedReviewToken: v.reviewed.reviewToken,
      },
    ]);
    expect(JSON.parse(localStorage.getItem(v.key)!)).toMatchObject({
      actor: v.actor,
      disposition,
      reviewToken: 'current-owner-same-original-seal',
      originalReviewToken: v.reviewed.reviewToken,
      review: v.reviewed.review,
      ...(approvalRequestId ? { approvalRequestId } : {}),
    });
    expect(performWebAuthnStepUp).not.toHaveBeenCalled();
    expect(
      screen.getByRole('button', { name: 'Request independent replacement approval' }),
    ).toHaveProperty('disabled', disposition === 'REQUESTED');
  },
);
function closedRecoveryFixture(v: ReturnType<typeof retainedFixture>) {
  return {
    enrollmentId: id(700),
    recoveryId: id(701),
    state: 'EXPIRED',
    authority: 'NONE',
    intentDigest: 'sha256:' + 'c'.repeat(64),
    activationOperationId: id(702),
    candidateDigest: v.reviewed.review.candidateDigest,
    businessIdempotencyKey: v.reviewed.review.businessIdempotencyKey,
    principalId: v.actor.principalId,
    participantId: v.actor.participantId,
    privacyDomainId: v.actor.privacyDomainId,
  };
}
it('reconciles closed opaque custody after a fresh session while preserving the original approval and removing stale plaintext', async () => {
  const v = retainedFixture('PREPARE'),
    closedRecovery = closedRecoveryFixture(v);
  localStorage.setItem(
    v.key,
    JSON.stringify({
      ...v.reviewed,
      actor: v.actor,
      disposition: 'REQUESTED',
      approvalRequestId: id(777),
    }),
  );
  vi.spyOn(globalThis, 'fetch').mockImplementation(async (_url, init) =>
    init?.method === 'POST'
      ? Response.json({ closedRecovery })
      : Response.json({
          actor: { ...v.actor, sessionId: id(999), contextEpoch: '2' },
          suggestedIds: {},
        }),
  );
  const user = userEvent.setup();
  render(<PlatformCeilingWorkflow />);
  await screen.findByText(
    'The working context changed. Read the original operation before continuing.',
  );
  expect(JSON.parse(localStorage.getItem(v.key)!)).toMatchObject({
    disposition: 'REQUESTED',
    approvalRequestId: id(777),
  });
  expect(JSON.parse(localStorage.getItem(v.key)!)).not.toHaveProperty('review');
  await user.type(screen.getByLabelText('Recovery enrollment ID'), id(700));
  await user.type(screen.getByLabelText('Recovery case ID'), id(701));
  await user.click(screen.getByRole('button', { name: 'Retain closed recovery review' }));
  await screen.findByText(/The closed recovery review is retained/);
  const archived = JSON.parse(
    localStorage.getItem(v.key + ':closed:' + closedRecovery.candidateDigest)!,
  );
  expect(archived.originalCustody).toMatchObject({
    originalReviewToken: v.reviewed.reviewToken,
    approvalRequestId: id(777),
    disposition: 'REQUESTED',
    actor: v.actor,
  });
  expect(archived.originalCustody).not.toHaveProperty('review');
  expect(archived.businessOutcome).toBe('UNRECONCILED');
  expect(performWebAuthnStepUp).not.toHaveBeenCalled();
});
it.each(['UNCERTAIN', 'REQUESTED'] as const)(
  'retains closed recovery opaque %s custody before releasing its active review without asserting a business outcome',
  async (disposition) => {
    const v = retainedFixture('PREPARE'),
      closedRecovery = closedRecoveryFixture(v);
    const approvalRequestId = disposition === 'REQUESTED' ? id(777) : undefined;
    localStorage.setItem(
      v.key,
      JSON.stringify({ ...v.reviewed, actor: v.actor, disposition, approvalRequestId }),
    );
    const posts: unknown[] = [];
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (_url, init) => {
      if (init?.method === 'POST') {
        posts.push(JSON.parse(String(init.body)));
        return Response.json({ closedRecovery });
      }
      return Response.json({ actor: v.actor, suggestedIds: {} });
    });
    const user = userEvent.setup();
    render(<PlatformCeilingWorkflow />);
    await screen.findByRole('button', { name: 'Request independent replacement approval' });
    await user.type(screen.getByLabelText('Recovery enrollment ID'), id(700));
    await user.type(screen.getByLabelText('Recovery case ID'), id(701));
    await user.click(screen.getByRole('button', { name: 'Retain closed recovery review' }));
    await screen.findByText(/The closed recovery review is retained/);
    expect(localStorage.getItem(v.key)).toBeNull();
    const archived = JSON.parse(
      localStorage.getItem(v.key + ':closed:' + closedRecovery.candidateDigest)!,
    );
    expect(archived).toEqual({
      originalCustody: {
        actor: v.actor,
        reviewToken: v.reviewed.reviewToken,
        originalReviewToken: v.reviewed.reviewToken,
        disposition,
        candidateDigest: closedRecovery.candidateDigest,
        businessIdempotencyKey: closedRecovery.businessIdempotencyKey,
        ...(approvalRequestId ? { approvalRequestId } : {}),
      },
      closedRecovery,
      businessOutcome: 'UNRECONCILED',
    });
    expect(archived.originalCustody.review).toBeUndefined();
    expect(posts).toEqual([
      {
        command: 'RECONCILE_CLOSED_RECOVERY_HANDOFF',
        enrollmentId: id(700),
        recoveryId: id(701),
        retainedReviewToken: v.reviewed.reviewToken,
      },
    ]);
    expect(performWebAuthnStepUp).not.toHaveBeenCalled();
    expect(
      screen.queryByRole('button', { name: 'Request independent replacement approval' }),
    ).toBeNull();
  },
);
it.each([
  'denied',
  'wrong-case',
  'wrong-actor',
  'storage-throw',
  'storage-ignored',
  'archive-conflict',
  'remove-failure',
  'active-replaced-during-archive',
  'unsupported-lock',
] as const)(
  'preserves active closed recovery custody on %s without proving or submitting business',
  async (failure) => {
    const v = retainedFixture('PREPARE'),
      closedRecovery = closedRecoveryFixture(v);
    localStorage.setItem(
      v.key,
      JSON.stringify({ ...v.reviewed, actor: v.actor, disposition: 'UNCERTAIN' }),
    );
    const original = localStorage.getItem(v.key);
    const archiveKey = v.key + ':closed:' + closedRecovery.candidateDigest;
    if (failure === 'wrong-case') closedRecovery.recoveryId = id(999);
    if (failure === 'wrong-actor') closedRecovery.principalId = id(999);
    if (failure === 'archive-conflict')
      localStorage.setItem(archiveKey, 'retained-original-archive');
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (_url, init) =>
      init?.method === 'POST'
        ? Response.json({ closedRecovery }, { status: failure === 'denied' ? 404 : 200 })
        : Response.json({ actor: v.actor, suggestedIds: {} }),
    );
    const user = userEvent.setup();
    render(<PlatformCeilingWorkflow />);
    await screen.findByRole('button', { name: 'Request independent replacement approval' });
    await user.type(screen.getByLabelText('Recovery enrollment ID'), id(700));
    await user.type(screen.getByLabelText('Recovery case ID'), id(701));
    const setItem = Storage.prototype.setItem;
    const replacement = JSON.stringify({
      ...v.reviewed,
      reviewToken: 'other-tab-original',
      actor: v.actor,
      disposition: 'UNCERTAIN',
    });
    if (failure === 'unsupported-lock')
      vi.stubGlobal('navigator', Object.assign(Object.create(navigator), { locks: undefined }));
    if (failure === 'active-replaced-during-archive')
      vi.spyOn(Storage.prototype, 'setItem').mockImplementation(function (
        this: Storage,
        key,
        value,
      ) {
        setItem.call(this, key, value);
        if (key === archiveKey) setItem.call(this, v.key, replacement);
      });
    if (failure.startsWith('storage'))
      vi.spyOn(Storage.prototype, 'setItem').mockImplementation(function (
        this: Storage,
        key,
        value,
      ) {
        if (key === archiveKey) {
          if (failure === 'storage-throw') throw new Error('private storage failure');
          return;
        }
        setItem.call(this, key, value);
      });
    if (failure === 'remove-failure')
      vi.spyOn(Storage.prototype, 'removeItem').mockImplementation(() => {
        throw new Error('private removal failure');
      });
    await user.click(screen.getByRole('button', { name: 'Retain closed recovery review' }));
    await waitFor(() =>
      expect(screen.getByRole('button', { name: 'Retain closed recovery review' })).toBeEnabled(),
    );
    expect(localStorage.getItem(v.key)).toBe(
      failure === 'active-replaced-during-archive' ? replacement : original,
    );
    expect(screen.getByRole('status')).not.toHaveTextContent('private');
    expect(performWebAuthnStepUp).not.toHaveBeenCalled();
  },
);
it('preserves original custody when closed recovery readback returns after the selected case changes', async () => {
  const v = retainedFixture('PREPARE'),
    closedRecovery = closedRecoveryFixture(v);
  localStorage.setItem(
    v.key,
    JSON.stringify({ ...v.reviewed, actor: v.actor, disposition: 'UNCERTAIN' }),
  );
  const original = localStorage.getItem(v.key);
  let release!: () => void, entered!: () => void;
  const pending = new Promise<void>((resolve) => {
    entered = resolve;
  });
  vi.spyOn(globalThis, 'fetch').mockImplementation(async (_url, init) => {
    if (init?.method === 'POST') {
      await new Promise<void>((resolve) => {
        release = resolve;
        entered();
      });
      return Response.json({ closedRecovery });
    }
    return Response.json({ actor: v.actor, suggestedIds: {} });
  });
  const user = userEvent.setup();
  render(<PlatformCeilingWorkflow />);
  await screen.findByRole('button', { name: 'Request independent replacement approval' });
  await user.type(screen.getByLabelText('Recovery enrollment ID'), id(700));
  await user.type(screen.getByLabelText('Recovery case ID'), id(701));
  await user.click(screen.getByRole('button', { name: 'Retain closed recovery review' }));
  await pending;
  await user.clear(screen.getByLabelText('Recovery case ID'));
  await user.type(screen.getByLabelText('Recovery case ID'), id(703));
  await act(async () => release());
  await waitFor(() =>
    expect(screen.getByRole('button', { name: 'Retain closed recovery review' })).toBeEnabled(),
  );
  expect(localStorage.getItem(v.key)).toBe(original);
  expect(localStorage.getItem(v.key + ':closed:' + closedRecovery.candidateDigest)).toBeNull();
  expect(performWebAuthnStepUp).not.toHaveBeenCalled();
});

it('rejects held approval readback after its selected ID changes', async () => {
  const v = retainedFixture();
  let release!: () => void;
  let entered!: () => void;
  const operationEntered = new Promise<void>((resolve) => {
    entered = resolve;
  });
  vi.spyOn(globalThis, 'fetch').mockImplementation(async (url) => {
    if (new URL(String(url), 'http://localhost').searchParams.get('approvalRequestId')) {
      await new Promise<void>((resolve) => {
        release = resolve;
        entered();
      });
      return Response.json({
        approval: { state: 'REQUESTED', makerSubjectRef: 'maker', checkerSubjectRef: 'checker' },
        body: v.reviewed.review.body,
        stepUp: {
          actionIntentId: 'ACT-POLICY_APPROVE_REQUEST-V1',
          actionIntentDigest: 'digest',
          resourceId: id(777),
          resourceDigest: 'original-A',
        },
      });
    }
    return Response.json({ actor: v.actor, suggestedIds: {} });
  });
  const user = userEvent.setup();
  render(<PlatformCeilingWorkflow />);
  await screen.findByRole('button', { name: 'Request independent replacement approval' });
  const input = screen.getByLabelText('Replacement approval ID');
  await user.type(input, id(777));
  await user.click(screen.getByRole('button', { name: 'Load replacement approval' }));
  await operationEntered;
  await user.clear(input);
  await user.type(input, id(778));
  await act(async () => release());
  await waitFor(() =>
    expect(screen.getByRole('button', { name: 'Load replacement approval' })).toBeEnabled(),
  );
  expect(screen.queryByText(/Approval state: REQUESTED/)).toBeNull();
  expect(performWebAuthnStepUp).not.toHaveBeenCalled();
  expect(JSON.parse(localStorage.getItem(v.key)!)).toMatchObject({
    reviewToken: v.reviewed.reviewToken,
  });
});
it('rejects a held checker proof suffix after the selected approval ID changes', async () => {
  const v = retainedFixture(),
    posts = vi.fn();
  let release!: () => void;
  let entered!: () => void;
  const operationEntered = new Promise<void>((resolve) => {
    entered = resolve;
  });
  vi.mocked(performWebAuthnStepUp).mockImplementation(
    () =>
      new Promise<void>((resolve) => {
        release = resolve;
        entered();
      }),
  );
  vi.spyOn(globalThis, 'fetch').mockImplementation(async (url, init) => {
    if (init?.method === 'POST') {
      posts();
      return Response.json({});
    }
    if (new URL(String(url), 'http://localhost').searchParams.get('approvalRequestId'))
      return Response.json({
        approval: { state: 'REQUESTED', makerSubjectRef: 'maker', checkerSubjectRef: 'checker' },
        body: v.reviewed.review.body,
        stepUp: {
          actionIntentId: 'ACT-POLICY_APPROVE_REQUEST-V1',
          actionIntentDigest: 'digest',
          resourceId: id(777),
          resourceDigest: 'original-A',
        },
      });
    return Response.json({ actor: v.actor, suggestedIds: {} });
  });
  const user = userEvent.setup();
  render(<PlatformCeilingWorkflow />);
  await screen.findByRole('button', { name: 'Request independent replacement approval' });
  const input = screen.getByLabelText('Replacement approval ID');
  await user.type(input, id(777));
  await user.click(screen.getByRole('button', { name: 'Load replacement approval' }));
  await screen.findByText(/Approval state: REQUESTED/);
  await user.click(screen.getByRole('button', { name: 'Approve replacement with saved passkey' }));
  await operationEntered;
  await user.clear(input);
  await user.type(input, id(778));
  await act(async () => release());
  await waitFor(() =>
    expect(screen.getByRole('button', { name: 'Load replacement approval' })).toBeEnabled(),
  );
  expect(posts).not.toHaveBeenCalled();
});

it('rejects an owner readback seal for a different original business key without overwriting custody', async () => {
  const v = retainedFixture();
  vi.spyOn(globalThis, 'fetch').mockImplementation(async (url) =>
    new URL(String(url), 'http://localhost').searchParams.get('approvalRequestId')
      ? Response.json({
          approval: {
            state: 'APPROVED',
            makerSubjectRef: 'urn:openpc:resource:' + v.actor.principalId,
            checkerSubjectRef: 'checker',
          },
          body: v.reviewed.review.body,
          stepUp: null,
          resumableReview: {
            ...v.reviewed,
            reviewToken: 'different-business-owner-token',
            review: {
              ...v.reviewed.review,
              businessIdempotencyKey: 'different-original-business-key',
            },
          },
        })
      : Response.json({ actor: v.actor, suggestedIds: {} }),
  );
  const user = userEvent.setup();
  render(<PlatformCeilingWorkflow />);
  await screen.findByRole('button', { name: 'Request independent replacement approval' });
  await user.type(screen.getByLabelText('Replacement approval ID'), id(777));
  await user.click(screen.getByRole('button', { name: 'Load replacement approval' }));
  await screen.findByText(
    'The original state changed. Read its authoritative state before continuing.',
  );
  expect(JSON.parse(localStorage.getItem(v.key)!)).toMatchObject({
    reviewToken: v.reviewed.reviewToken,
    review: { businessIdempotencyKey: 'original-reviewed-business-key' },
  });
});

it('preserves legacy uncertain original storage with a missing key and enables no new intent or proof', async () => {
  const v = retainedFixture();
  const legacy = {
    ...v.reviewed,
    actor: v.actor,
    disposition: 'UNCERTAIN',
    review: { ...v.reviewed.review },
  };
  delete (legacy.review as Partial<typeof legacy.review>).businessIdempotencyKey;
  const original = JSON.stringify(legacy);
  localStorage.setItem(v.key, original);
  const post = vi.fn();
  vi.spyOn(globalThis, 'fetch').mockImplementation(async (_url, init) => {
    if (init?.method === 'POST') post();
    return Response.json({ actor: v.actor, suggestedIds: {} });
  });
  render(<PlatformCeilingWorkflow />);
  await screen.findByText(
    'The original review could not be saved. Restore browser storage before continuing.',
  );
  expect(localStorage.getItem(v.key)).toBe(original);
  expect(
    screen.queryByRole('button', { name: 'Request independent replacement approval' }),
  ).toBeNull();
  expect(post).not.toHaveBeenCalled();
  expect(performWebAuthnStepUp).not.toHaveBeenCalled();
});

it('does not replace another tab custody when this tab persists uncertainty before a business submission', async () => {
  const v = retainedFixture('PREPARE');
  vi.spyOn(globalThis, 'fetch').mockResolvedValue(
    Response.json({ actor: v.actor, suggestedIds: {} }),
  );
  const user = userEvent.setup();
  render(<PlatformCeilingWorkflow />);
  await screen.findByRole('button', { name: 'Request independent replacement approval' });
  const replacement = JSON.stringify({
    ...v.reviewed,
    reviewToken: 'other-tab-retained-original',
    actor: v.actor,
    disposition: 'UNCERTAIN',
  });
  localStorage.setItem(v.key, replacement);
  await user.click(
    screen.getByRole('button', { name: 'Request independent replacement approval' }),
  );
  await waitFor(() =>
    expect(
      screen.getByRole('button', { name: 'Request independent replacement approval' }),
    ).toBeEnabled(),
  );
  expect(localStorage.getItem(v.key)).toBe(replacement);
  expect(performWebAuthnStepUp).not.toHaveBeenCalled();
  expect(vi.mocked(fetch).mock.calls.filter(([, init]) => init?.method === 'POST')).toHaveLength(0);
});

it('a queued custody lock rechecks the selected case generation before any archive or retirement', async () => {
  const v = retainedFixture('PREPARE'),
    closedRecovery = closedRecoveryFixture(v);
  localStorage.setItem(
    v.key,
    JSON.stringify({ ...v.reviewed, actor: v.actor, disposition: 'UNCERTAIN' }),
  );
  const original = localStorage.getItem(v.key);
  vi.spyOn(globalThis, 'fetch').mockImplementation(async (_url, init) =>
    Response.json(
      init?.method === 'POST' ? { closedRecovery } : { actor: v.actor, suggestedIds: {} },
    ),
  );
  const user = userEvent.setup();
  render(<PlatformCeilingWorkflow />);
  await screen.findByRole('button', { name: 'Request independent replacement approval' });
  await user.type(screen.getByLabelText('Recovery enrollment ID'), id(700));
  await user.type(screen.getByLabelText('Recovery case ID'), id(701));
  let release!: () => void, entered!: () => void;
  const waiting = new Promise<void>((resolve) => {
    entered = resolve;
  });
  vi.stubGlobal(
    'navigator',
    Object.assign(Object.create(navigator), {
      locks: {
        request: async (name: string, _options: unknown, work: () => unknown) => {
          expect(name).toBe(v.key);
          entered();
          await new Promise<void>((resolve) => {
            release = resolve;
          });
          return work();
        },
      },
    }),
  );
  await user.click(screen.getByRole('button', { name: 'Retain closed recovery review' }));
  await waiting;
  await user.clear(screen.getByLabelText('Recovery case ID'));
  await user.type(screen.getByLabelText('Recovery case ID'), id(703));
  await act(async () => release());
  await waitFor(() =>
    expect(screen.getByRole('button', { name: 'Retain closed recovery review' })).toBeEnabled(),
  );
  expect(localStorage.getItem(v.key)).toBe(original);
  expect(localStorage.getItem(v.key + ':closed:' + closedRecovery.candidateDigest)).toBeNull();
  expect(performWebAuthnStepUp).not.toHaveBeenCalled();
});
it('serializes two custody writers and denies the stale writer before it proves or submits business', async () => {
  const v = retainedFixture('PREPARE');
  let release!: () => void, entered!: () => void;
  const proofEntered = new Promise<void>((resolve) => {
    entered = resolve;
  });
  vi.mocked(performWebAuthnStepUp).mockImplementation(async () => {
    entered();
    await new Promise<void>((resolve) => {
      release = resolve;
    });
  });
  const posts: unknown[] = [];
  vi.spyOn(globalThis, 'fetch').mockImplementation(async (_url, init) => {
    if (init?.method === 'POST') {
      posts.push(JSON.parse(String(init.body)));
      return Response.json({ ...v.reviewed, approvalRequestId: id(777) });
    }
    return Response.json({ actor: v.actor, suggestedIds: {} });
  });
  const user = userEvent.setup();
  render(
    <>
      <PlatformCeilingWorkflow />
      <PlatformCeilingWorkflow />
    </>,
  );
  await waitFor(() =>
    expect(
      screen.getAllByRole('button', { name: 'Request independent replacement approval' }),
    ).toHaveLength(2),
  );
  const buttons = screen.getAllByRole('button', {
    name: 'Request independent replacement approval',
  });
  await user.click(buttons[0]!);
  await proofEntered;
  await user.click(buttons[1]!);
  await waitFor(() => expect(buttons[1]).toBeEnabled());
  expect(performWebAuthnStepUp).toHaveBeenCalledTimes(1);
  expect(posts).toHaveLength(0);
  await act(async () => release());
  await waitFor(() => expect(posts).toHaveLength(1));
  await waitFor(() =>
    expect(JSON.parse(localStorage.getItem(v.key)!).disposition).toBe('REQUESTED'),
  );
  expect(JSON.parse(localStorage.getItem(v.key)!).originalReviewToken).toBe(v.reviewed.reviewToken);
});

it('keeps the original archive but rejects stale UI updates after the custody lock callback has released', async () => {
  const v = retainedFixture('PREPARE'),
    closedRecovery = closedRecoveryFixture(v);
  localStorage.setItem(
    v.key,
    JSON.stringify({ ...v.reviewed, actor: v.actor, disposition: 'UNCERTAIN' }),
  );
  vi.spyOn(globalThis, 'fetch').mockImplementation(async (_url, init) =>
    Response.json(
      init?.method === 'POST' ? { closedRecovery } : { actor: v.actor, suggestedIds: {} },
    ),
  );
  const user = userEvent.setup();
  render(<PlatformCeilingWorkflow />);
  await screen.findByRole('button', { name: 'Request independent replacement approval' });
  await user.type(screen.getByLabelText('Recovery enrollment ID'), id(700));
  await user.type(screen.getByLabelText('Recovery case ID'), id(701));
  let entered!: () => void, release!: () => void;
  const callbackFinished = new Promise<void>((resolve) => {
    entered = resolve;
  });
  vi.stubGlobal(
    'navigator',
    Object.assign(Object.create(navigator), {
      locks: {
        request: async (_name: string, _options: unknown, work: () => unknown) => {
          const result = work();
          entered();
          await new Promise<void>((resolve) => {
            release = resolve;
          });
          return result;
        },
      },
    }),
  );
  await user.click(screen.getByRole('button', { name: 'Retain closed recovery review' }));
  await callbackFinished;
  expect(localStorage.getItem(v.key)).toBeNull();
  const archive = localStorage.getItem(v.key + ':closed:' + closedRecovery.candidateDigest);
  expect(archive).not.toBeNull();
  await user.clear(screen.getByLabelText('Recovery case ID'));
  await user.type(screen.getByLabelText('Recovery case ID'), id(703));
  await act(async () => release());
  await waitFor(() =>
    expect(screen.getByRole('button', { name: 'Retain closed recovery review' })).toBeEnabled(),
  );
  expect(screen.getByRole('status')).not.toHaveTextContent(
    'The closed recovery review is retained',
  );
  expect(screen.getByLabelText('Recovery case ID')).toHaveValue(id(703));
  expect(localStorage.getItem(v.key + ':closed:' + closedRecovery.candidateDigest)).toBe(archive);
  expect(performWebAuthnStepUp).not.toHaveBeenCalled();
});

it.each([
  'valid',
  'wrong-token-digest',
  'wrong-business-key',
  'foreign-actor',
  'storage-race',
  'generation-race',
] as const)(
  'adopts old-session opaque custody only through exact owner correspondence and origin CAS: %s',
  async (mode) => {
    const v = retainedFixture('PREPARE'),
      approvalRequestId = id(777),
      currentActor = { ...v.actor, sessionId: id(999), contextEpoch: '2' };
    localStorage.setItem(
      v.key,
      JSON.stringify({
        ...v.reviewed,
        actor: v.actor,
        disposition: 'REQUESTED',
        approvalRequestId,
      }),
    );
    let release: (value: Response) => void = () => {};
    const pending = new Promise<Response>((resolve) => {
      release = resolve;
    });
    const commands: Record<string, unknown>[] = [];
    let originalOpaque: string | undefined;
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (_url, init) => {
      if (init?.method !== 'POST') return Response.json({ actor: currentActor, suggestedIds: {} });
      const body = JSON.parse(String(init.body));
      commands.push(body);
      if (body.command !== 'RECONCILE_APPROVAL_REVIEW') throw Error('Forbidden business dispatch');
      originalOpaque = localStorage.getItem(v.key)!;
      expect(JSON.parse(originalOpaque)).not.toHaveProperty('review');
      return pending;
    });
    const user = userEvent.setup();
    render(<PlatformCeilingWorkflow />);
    await screen.findByText(
      'The working context changed. Read the original operation before continuing.',
    );
    await user.type(screen.getByLabelText('Replacement approval ID'), approvalRequestId);
    await user.click(screen.getByRole('button', { name: 'Load replacement approval' }));
    await waitFor(() => expect(commands).toHaveLength(1));
    const retainedReviewToken = v.reviewed.reviewToken;
    const response = {
      actor: mode === 'foreign-actor' ? { ...currentActor, principalId: id(998) } : currentActor,
      approval: {
        state: 'APPROVED',
        makerSubjectRef: 'urn:openpc:resource:' + v.actor.principalId,
        checkerSubjectRef: 'urn:openpc:resource:' + v.reviewed.review.checkerPrincipalId,
      },
      candidate: { canRequestResume: true },
      body: v.reviewed.review.body,
      stepUp: null,
      resumeStepUp: {
        actionIntentId: 'ACT-APPROVAL_REQUESTS_UPDATE_RESOURCE-V1',
        actionIntentDigest: 'sha256:' + 'a'.repeat(64),
        resourceId: approvalRequestId,
        resourceDigest: 'sha256:' + 'b'.repeat(64),
      },
      resumableReview: {
        ...v.reviewed,
        reviewToken: 'server-current-same-original-seal',
        approvalRequestId,
      },
      custodyCorrespondence: {
        retainedReviewTokenDigest:
          mode === 'wrong-token-digest'
            ? 'sha256:' + 'f'.repeat(64)
            : canonicalAuthorizationDigest(retainedReviewToken),
        approvalRequestId,
        candidateDigest: v.reviewed.review.candidateDigest,
        businessIdempotencyKey:
          mode === 'wrong-business-key'
            ? 'different-business-key'
            : v.reviewed.review.businessIdempotencyKey,
        checkerPrincipalId: v.reviewed.review.checkerPrincipalId,
      },
    };
    let foreignRaw: string | undefined;
    if (mode === 'storage-race') {
      foreignRaw = JSON.stringify({
        reviewToken: 'foreign-tab-original-custody',
        disposition: 'UNCERTAIN',
      });
      localStorage.setItem(v.key, foreignRaw);
    }
    if (mode === 'generation-race')
      await user.type(screen.getByLabelText('Replacement approval ID'), 'changed');
    await act(async () => {
      release(Response.json(response));
      await Promise.resolve();
    });
    expect(commands).toEqual([
      { command: 'RECONCILE_APPROVAL_REVIEW', approvalRequestId, retainedReviewToken },
    ]);
    expect(performWebAuthnStepUp).not.toHaveBeenCalled();
    if (mode === 'valid') {
      await screen.findByText('Authoritative immutable replacement approval loaded.');
      expect(
        screen.getByRole('button', { name: 'Request fresh approval for unchanged replacement' }),
      ).toBeEnabled();
      expect(JSON.parse(localStorage.getItem(v.key)!)).toMatchObject({
        actor: currentActor,
        reviewToken: 'server-current-same-original-seal',
        originalReviewToken: retainedReviewToken,
        approvalRequestId,
        disposition: 'REQUESTED',
        review: v.reviewed.review,
      });
    } else {
      await waitFor(() =>
        expect(
          screen.queryByRole('button', {
            name: 'Request fresh approval for unchanged replacement',
          }),
        ).toBeNull(),
      );
      expect(localStorage.getItem(v.key)).toBe(foreignRaw ?? originalOpaque);
    }
  },
);

it('keeps owner-read controls disabled until the authenticated actor is loaded', async () => {
  let release!: (value: Response) => void;
  const initial = new Promise<Response>((resolve) => {
    release = resolve;
  });
  const { intent } = platformRecoveryFixture();
  const fetchMock = vi.spyOn(globalThis, 'fetch').mockImplementation(async (url) => {
    const query = new URL(String(url), 'http://localhost').searchParams;
    if (!query.has('approvalRequestId')) return initial;
    return Response.json({
      approval: { state: 'REQUESTED', makerSubjectRef: 'maker', checkerSubjectRef: 'checker' },
      body: intent.preparation,
      stepUp: null,
    });
  });
  const user = userEvent.setup();
  render(<PlatformCeilingWorkflow />);
  await user.type(screen.getByLabelText('Replacement approval ID'), id(905));
  const load = screen.getByRole('button', { name: 'Load replacement approval' });
  expect(load).toBeDisabled();
  await user.click(load);
  expect(fetchMock).toHaveBeenCalledTimes(1);
  await act(async () => {
    release(
      Response.json({
        actor: {
          sessionId: id(900),
          principalId: id(901),
          participantId: id(902),
          privacyDomainId: id(903),
          contextEpoch: '1',
        },
        suggestedIds: { replacementId: id(904) },
      }),
    );
  });
  await waitFor(() => expect(load).toBeEnabled());
  await user.click(load);
  await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(2));
  expect(fetchMock.mock.calls[1]?.[1]?.method).not.toBe('POST');
  expect(performWebAuthnStepUp).not.toHaveBeenCalled();
});
