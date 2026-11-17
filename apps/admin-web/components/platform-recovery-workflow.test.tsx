import { act, cleanup, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { PlatformRecoveryWorkflow } from './platform-recovery-workflow';
import { DiscoveryCertificateRecoveryWorkflow } from './discovery-certificate-recovery-workflow';
import { trustFixture as discoveryFixture } from '../../../services/identity-service/src/domain/discovery-certificate-recovery.test-fixture';
import { platformRecoveryFixture } from '../../../services/identity-service/src/domain/platform-recovery.test-fixture';
import { localRootExpiryRecoveryFixture } from '../../../services/identity-service/src/domain/local-root-expiry-recovery.test-fixture';
import {
  localRootExpiryRecoveryIntent,
  localRootExpiryRecoverySourceView,
  localRootExpiryRecoveryReceiptView,
} from '../../../services/identity-service/src/contracts/local-root-expiry-recovery';
import { canonicalAuthorizationDigest } from '../../../services/identity-service/src/contracts/authorization';
import {
  identityEnvelopeRecoveryFixture,
  recoveryFixtureId as signerId,
} from '../../../services/identity-service/src/domain/identity-envelope-recovery.test-fixture';
const { source, intent } = platformRecoveryFixture();
const fixed = source.enrollment;
const actors = {
  executorPrincipalId: fixed.recoveryPrincipal.principalId,
  custodianPrincipalIds: fixed.custodians.map((v) => v.principalId),
  administratorPrincipalIds: fixed.administratorPrincipalIds,
};
function receipt(principalId: string, approvals = 2) {
  return {
    actor: {
      sessionId: intent.recoveryId,
      participantId: fixed.participantId,
      principalId,
      contextEpoch: '1',
    },
    view: {
      recoveryId: intent.recoveryId,
      enrollmentId: intent.enrollmentId,
      intent,
      intentDigest: 'sha256:' + 'a'.repeat(64),
      state: 'REQUESTED',
      revision: '2',
      authority: 'NONE',
      assurance: fixed.assurance,
      actors,
      proofs: [
        {
          principalId: fixed.recoveryPrincipal.principalId,
          phase: 'REQUEST',
          proofId: fixed.recoveryPrincipal.credentialId,
        },
        ...fixed.custodians
          .slice(0, approvals)
          .map((v) => ({ principalId: v.principalId, phase: 'APPROVE', proofId: v.credentialId })),
      ],
    },
  };
}
beforeEach(() => {
  vi.useFakeTimers({ toFake: ['Date'] });
  vi.setSystemTime(source.now);
  localStorage.setItem(
    'openpc:platform-recovery-case:v1',
    JSON.stringify({
      enrollmentId: intent.enrollmentId,
      privacyDomainId: fixed.privacyDomainId,
      recoveryId: intent.recoveryId,
    }),
  );
});
afterEach(() => {
  cleanup();
  vi.useRealTimers();
  vi.restoreAllMocks();
  localStorage.clear();
});
const user = () => userEvent.setup();
it.each([1, 2, 3] as const)(
  'routes Root expiry v%s source and completed readback without administration authority',
  async (version) => {
    const f = localRootExpiryRecoveryFixture(),
      e = f.enrollment;
    const purpose =
      version === 1
        ? 'LOCAL_ROOT_EXPIRY_RECOVERY_ONLY'
        : version === 2
          ? 'LOCAL_ROOT_EXPIRY_PENDING_RECOVERY_ONLY'
          : 'LOCAL_ROOT_EXPIRY_PENDING_ANCESTRY_RECOVERY_ONLY';
    const pending = {
      schema: 'pc.identity.local-root-expiry-pending-witness',
      schemaVersion: 1,
      replacementId: intent.preparation.replacementId,
      replacementRevision: '1',
      predecessorEpoch: version === 3 ? String(BigInt(e.rootEpoch) - 1n) : e.rootEpoch,
      expectedRootRevision: version === 3 ? String(BigInt(e.rootRevision) - 1n) : e.rootRevision,
      predecessorDigest: e.rootDigest,
      preparationCandidateId: intent.recoveryId,
      preparationOperationId: e.enrollmentId,
      preparationApprovalId: e.recoveryPrincipal.credentialId,
      preparationDigest: canonicalAuthorizationDigest(intent.preparation),
      preparationReceiptDigest: canonicalAuthorizationDigest(intent),
      successorDigest: canonicalAuthorizationDigest(f.root.grantable),
      pendingRecordDigest: canonicalAuthorizationDigest(e),
      administrationEffectsDigest: canonicalAuthorizationDigest(e.custodians),
      affectedTargetCount: 1,
      readinessDigest: canonicalAuthorizationDigest(f.root),
    };
    const rootAncestry = {
      schema: 'pc.identity.local-root-expiry-pending-ancestry',
      schemaVersion: 1,
      rootEpoch: e.rootEpoch,
      rootRevision: e.rootRevision,
      rootDigest: e.rootDigest,
      receipts: [
        {
          enrollmentId: e.enrollmentId,
          recoveryId: e.custodians[0].principalId,
          activationOperationId: e.custodians[1].principalId,
          enrollmentDigest: e.rootDigest,
          intentDigest: e.rootDigest,
          receiptDigest: e.rootDigest,
          predecessorEpoch: pending.predecessorEpoch,
          predecessorRevision: pending.expectedRootRevision,
          predecessorDigest: pending.predecessorDigest,
          rootEpoch: e.rootEpoch,
          rootRevision: e.rootRevision,
          rootDigest: e.rootDigest,
        },
      ],
    };
    const rootSource = localRootExpiryRecoverySourceView.parse({
      enrollmentId: e.enrollmentId,
      purpose,
      authority: 'NONE',
      assurance: e.assurance,
      actors: {
        executorPrincipalId: e.recoveryPrincipal.principalId,
        custodianPrincipalIds: e.custodians.map((v) => v.principalId),
      },
      source: {
        rootEpoch: e.rootEpoch,
        rootRevision: e.rootRevision,
        rootDigest: e.rootDigest,
        expiredAt: new Date(f.now.getTime() - 1000).toISOString(),
        ...(version !== 1 ? { pending } : {}),
        ...(version === 3 ? { rootAncestry } : {}),
      },
      successorScope: f.root.grantable,
      liveCase: null,
    });
    const rootIntent = localRootExpiryRecoveryIntent.parse({
      schema: 'pc.identity.local-root-expiry-recovery-intent',
      schemaVersion: version,
      purpose,
      recoveryId: intent.recoveryId,
      enrollmentId: e.enrollmentId,
      enrollmentRevision: '1',
      enrollmentDigest: canonicalAuthorizationDigest(e),
      sourceParticipantEpoch: '1',
      predecessorEpoch: e.rootEpoch,
      predecessorRevision: e.rootRevision,
      predecessorDigest: e.rootDigest,
      successorScope: f.root.grantable,
      validFrom: f.now.toISOString(),
      validUntil: new Date(f.now.getTime() + 900000).toISOString(),
      ...(version !== 1 ? { pending } : {}),
      ...(version === 3 ? { rootAncestry } : {}),
    });
    const completed = localRootExpiryRecoveryReceiptView.parse({
      actors: rootSource.actors,
      recoveryId: rootIntent.recoveryId,
      enrollmentId: e.enrollmentId,
      purpose,
      intent: rootIntent,
      intentDigest: canonicalAuthorizationDigest(rootIntent),
      revision: '3',
      state: 'COMPLETED',
      authority: 'NONE',
      assurance: e.assurance,
      proofs: [],
      result: {
        rootEpoch: '6',
        rootRevision: '6',
        rootDigest: e.rootDigest,
        operationId: rootIntent.recoveryId,
      },
    });
    const actor = {
      ...receipt(e.recoveryPrincipal.principalId).actor,
      principalId: e.recoveryPrincipal.principalId,
    };
    const fetch = vi
      .spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(Response.json({ actor, view: rootSource }))
      .mockResolvedValueOnce(Response.json({ actor, view: completed }));
    const stored = localStorage.getItem('openpc:platform-recovery-case:v1');
    render(<PlatformRecoveryWorkflow />);
    await user().click(screen.getByRole('button', { name: 'Read recovery source' }));
    expect(await screen.findByText(/Original Root digest:/)).toHaveTextContent(e.rootDigest);
    expect(screen.getByText(/Current authority: NONE/)).toBeInTheDocument();
    expect(
      screen.getByRole('button', { name: 'Create reviewed Root expiry recovery case' }),
    ).toBeEnabled();
    if (version !== 1)
      expect(screen.getByText(/Administrator effects:/)).toHaveTextContent(
        pending.administrationEffectsDigest,
      );
    if (version === 3)
      expect(screen.getByText(/Verified Root recovery history/)).toHaveTextContent(
        `1 completed receipts ending at Root epoch ${e.rootEpoch}. These receipts grant no current authority.`,
      );
    expect(
      screen.queryByRole('button', { name: 'Create reviewed administration recovery case' }),
    ).not.toBeInTheDocument();
    await user().click(screen.getByRole('button', { name: 'Read original recovery case' }));
    expect(await screen.findByText(/Committed Root epoch 6/)).toBeInTheDocument();
    expect(
      screen.getByRole('button', { name: 'Commit governed Root expiry successor' }),
    ).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Close Root expiry recovery case' })).toBeDisabled();
    expect(localStorage.getItem('openpc:platform-recovery-case:v1')).toBe(stored);
    expect(fetch.mock.calls.map((call) => JSON.parse(String(call[1]?.body)).command.kind)).toEqual([
      'SOURCE',
      'READ',
    ]);
  },
);
it.each(['ADMINISTRATION', 'DISCOVERY_CERTIFICATE_REPLACEMENT'] as const)(
  'an unconfirmed %s closure clears displayed authority and preserves original custody for readback',
  async (purpose) => {
    const f = discoveryFixture();
    const enrolled = f.source.enrollment;
    const administration = receipt(fixed.recoveryPrincipal.principalId);
    const original =
      purpose === 'ADMINISTRATION'
        ? {
            ...administration,
            view: {
              ...administration.view,
              state: 'ACTIVE',
              authority: 'FIXED_PLATFORM_HANDOFF_ONLY',
            },
          }
        : {
            actor: {
              sessionId: f.intent.recoveryId,
              participantId: enrolled.participantId,
              principalId: enrolled.recoveryPrincipal.principalId,
              contextEpoch: '1',
            },
            view: {
              recoveryId: f.intent.recoveryId,
              enrollmentId: enrolled.enrollmentId,
              intent: f.intent,
              intentDigest: 'sha256:' + 'a'.repeat(64),
              state: 'ACTIVE',
              revision: '3',
              authority: 'DISCOVERY_CERTIFICATE_REPLACEMENT_ONLY',
              assurance: enrolled.assurance,
              actors: {
                executorPrincipalId: enrolled.recoveryPrincipal.principalId,
                custodianPrincipalIds: enrolled.custodians.map((v) => v.principalId),
                administratorPrincipalIds: enrolled.administratorPrincipalIds,
              },
              proofs: [],
            },
          };
    vi.setSystemTime(Date.parse(original.view.intent.validFrom) + 1000);
    const saved = JSON.stringify({
      enrollmentId: original.view.enrollmentId,
      privacyDomainId: fixed.privacyDomainId,
      recoveryId: original.view.recoveryId,
      purpose,
    });
    localStorage.setItem('openpc:platform-recovery-case:v1', saved);
    const custodyKey = 'openpc:discovery-certificate-review:original-retained-custody';
    localStorage.setItem(custodyKey, 'original-signed-review-and-approval');
    let durableState = 'ACTIVE';
    const fetch = vi.spyOn(globalThis, 'fetch').mockImplementation(async (_url, options) => {
      const command = JSON.parse(String(options?.body)).command;
      if (command.kind === 'CLOSE') {
        durableState = 'REVOKED';
        throw new TypeError('Response lost after durable closure');
      }
      return Response.json({
        ...original,
        view: {
          ...original.view,
          state: durableState,
          authority: durableState === 'ACTIVE' ? original.view.authority : 'NONE',
        },
      });
    });
    render(<PlatformRecoveryWorkflow />);
    await user().click(screen.getByRole('button', { name: 'Read original recovery case' }));
    expect(screen.getByText(/(?:Current authority|Authority):/)).toHaveTextContent(
      original.view.authority,
    );
    await user().click(
      screen.getByRole('button', {
        name:
          purpose === 'ADMINISTRATION' ? 'Close recovery case' : 'Close certificate recovery case',
      }),
    );
    await waitFor(() =>
      expect(screen.getByRole('status')).toHaveTextContent(
        'Case closure could not be confirmed. Read the original case again.',
      ),
    );
    expect(durableState).toBe('REVOKED');
    expect(screen.queryByText(/(?:Current authority|Authority):/)).not.toBeInTheDocument();
    expect(
      screen.queryByRole('button', { name: /Close (certificate )?recovery case/u }),
    ).not.toBeInTheDocument();
    expect(localStorage.getItem(custodyKey)).toBe('original-signed-review-and-approval');
    expect(localStorage.getItem('openpc:platform-recovery-case:v1')).toBe(saved);
    expect(screen.getByLabelText('Recovery case ID')).toHaveValue(original.view.recoveryId);
    await user().click(screen.getByRole('button', { name: 'Read original recovery case' }));
    await waitFor(() =>
      expect(screen.getByText(/(?:Current authority|Authority):/)).toHaveTextContent('NONE'),
    );
    expect(fetch).toHaveBeenCalledTimes(3);
    expect(JSON.parse(String(fetch.mock.calls[2]?.[1]?.body)).command).toEqual({
      kind: 'READ',
      recoveryId: original.view.recoveryId,
    });
  },
);
it('a late Close transport failure preserves a changed authenticated context and its next readback', async () => {
  let rejectClose: ((error: Error) => void) | undefined;
  let nextPrincipal = fixed.recoveryPrincipal.principalId;
  const fetch = vi.spyOn(globalThis, 'fetch').mockImplementation(async (url, options) => {
    if (url === '/api/v1/ui/local-session')
      return Response.json({
        authenticated: true,
        contextMode: 'PLATFORM',
        ...receipt(fixed.custodians[0].principalId).actor,
      });
    const command = JSON.parse(String(options?.body)).command;
    if (command.kind === 'CLOSE')
      return new Promise<Response>((_resolve, reject) => {
        rejectClose = reject;
      });
    return Response.json(receipt(nextPrincipal));
  });
  render(<PlatformRecoveryWorkflow />);
  await user().click(screen.getByRole('button', { name: 'Read original recovery case' }));
  await user().click(screen.getByRole('button', { name: 'Close recovery case' }));
  await waitFor(() => expect(rejectClose).toBeTypeOf('function'));
  act(() => window.dispatchEvent(new Event('focus')));
  await waitFor(() =>
    expect(screen.getByRole('status')).toHaveTextContent(
      'The recovery context changed. Sign in and read the original case again.',
    ),
  );
  await act(async () => {
    rejectClose!(new TypeError('Old Close response lost'));
  });
  expect(screen.getByRole('status')).toHaveTextContent(
    'The recovery context changed. Sign in and read the original case again.',
  );
  expect(screen.queryByText(/Reviewed intent:/)).not.toBeInTheDocument();
  nextPrincipal = fixed.custodians[0].principalId;
  await user().click(screen.getByRole('button', { name: 'Read original recovery case' }));
  await waitFor(() => expect(screen.getByText(/Reviewed intent:/)).toBeInTheDocument());
  expect(screen.getByRole('status')).toHaveTextContent('Original case REQUESTED loaded.');
  expect(fetch).toHaveBeenCalledTimes(4);
});
it.each([
  ['executor', 'executor', true],
  ['custodian', 'custodian', true],
  ['administrator', 'administrator', false],
  ['foreign actor', 'foreign', false],
] as const)(
  'expired Discovery case closure admits only the enrolled %s',
  async (_label, role, enabled) => {
    const f = discoveryFixture();
    const enrolled = f.source.enrollment;
    const principalId =
      role === 'executor'
        ? enrolled.recoveryPrincipal.principalId
        : role === 'custodian'
          ? enrolled.custodians[0].principalId
          : role === 'administrator'
            ? enrolled.administratorPrincipalIds[0]
            : intent.recoveryId;
    const view: Parameters<typeof DiscoveryCertificateRecoveryWorkflow>[0]['view'] = {
      recoveryId: f.intent.recoveryId,
      enrollmentId: enrolled.enrollmentId,
      intent: f.intent,
      intentDigest: 'sha256:' + 'a'.repeat(64),
      state: 'REQUESTED',
      revision: '2',
      authority: 'NONE',
      assurance: enrolled.assurance,
      actors: {
        executorPrincipalId: enrolled.recoveryPrincipal.principalId,
        custodianPrincipalIds: [
          enrolled.custodians[0].principalId,
          enrolled.custodians[1].principalId,
        ],
        administratorPrincipalIds: enrolled.administratorPrincipalIds,
      },
      proofs: [],
    };
    const closed = { ...view, state: 'EXPIRED' as const, revision: '3' };
    const post = vi.fn().mockResolvedValue(closed),
      onView = vi.fn(),
      onStatus = vi.fn();
    render(
      <DiscoveryCertificateRecoveryWorkflow
        view={view}
        actor={{
          sessionId: intent.recoveryId,
          participantId: enrolled.participantId,
          principalId,
          contextEpoch: '1',
        }}
        enrollmentId={enrolled.enrollmentId}
        privacyDomainId={enrolled.privacyDomainId}
        recoveryId={f.intent.recoveryId}
        busy={false}
        now={Date.parse(f.intent.validUntil) + 1}
        post={post}
        assertion={vi.fn()}
        run={async (work) => {
          await work();
        }}
        onView={onView}
        onCase={vi.fn()}
        onStatus={onStatus}
      />,
    );
    const close = screen.getByRole('button', { name: 'Close certificate recovery case' });
    if (enabled) {
      expect(close).toBeEnabled();
      await user().click(close);
      await waitFor(() => expect(onView).toHaveBeenCalledWith(closed));
      expect(post).toHaveBeenCalledExactlyOnceWith({
        kind: 'CLOSE',
        recoveryId: f.intent.recoveryId,
      });
      expect(onStatus).toHaveBeenCalledWith('Case EXPIRED; current authority: NONE.');
    } else {
      expect(close).toBeDisabled();
      await user().click(close);
      expect(post).not.toHaveBeenCalled();
    }
  },
);
it.each([
  ['executor with both custodians', fixed.recoveryPrincipal.principalId, 2, true],
  ['executor missing a custodian', fixed.recoveryPrincipal.principalId, 1, false],
  ['custodian cannot activate', fixed.custodians[0].principalId, 2, false],
  ['administrator cannot activate', fixed.administratorPrincipalIds[0], 2, false],
])('activation control respects %s', async (_name, principalId, approvals, enabled) => {
  vi.spyOn(globalThis, 'fetch').mockResolvedValue(Response.json(receipt(principalId, approvals)));
  render(<PlatformRecoveryWorkflow />);
  await user().click(screen.getByRole('button', { name: 'Read original recovery case' }));
  const activate = screen.getByRole('button', { name: 'Executor: activate handoff lease' });
  if (enabled) expect(activate).toBeEnabled();
  else expect(activate).toBeDisabled();
  expect(screen.getByText(/Assurance: LOCAL_QA_VIRTUAL_AUTHENTICATOR/)).toBeInTheDocument();
});
it('removes reviewed case data immediately when enrollment scope changes', async () => {
  vi.spyOn(globalThis, 'fetch').mockResolvedValue(
    Response.json(receipt(fixed.recoveryPrincipal.principalId)),
  );
  render(<PlatformRecoveryWorkflow />);
  await user().click(screen.getByRole('button', { name: 'Read original recovery case' }));
  expect(screen.getByText(/Reviewed intent:/)).toBeInTheDocument();
  await user().type(screen.getByLabelText('Recovery enrollment ID'), '0');
  expect(screen.queryByText(/Reviewed intent:/)).not.toBeInTheDocument();
});
it('clears stale review data on an authenticated owner denial', async () => {
  const fetch = vi
    .spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(Response.json(receipt(fixed.recoveryPrincipal.principalId)))
    .mockResolvedValueOnce(
      Response.json({ code: 'PC-AUTH-0005', title: 'Access unavailable' }, { status: 403 }),
    );
  render(<PlatformRecoveryWorkflow />);
  await user().click(screen.getByRole('button', { name: 'Read original recovery case' }));
  await user().click(screen.getByRole('button', { name: 'Read original recovery case' }));
  expect(fetch).toHaveBeenCalledTimes(2);
  expect(screen.queryByText(/Reviewed intent:/)).not.toBeInTheDocument();
  expect(screen.getByRole('status')).toHaveTextContent('PC-AUTH-0005');
});
it('expires the visible authority and ceremony controls at the original deadline', async () => {
  const v = receipt(fixed.recoveryPrincipal.principalId);
  v.view.authority = 'FIXED_PLATFORM_HANDOFF_ONLY';
  vi.spyOn(globalThis, 'fetch').mockResolvedValue(Response.json(v));
  render(<PlatformRecoveryWorkflow />);
  await user().click(screen.getByRole('button', { name: 'Read original recovery case' }));
  expect(screen.getByRole('button', { name: 'Executor: activate handoff lease' })).toBeEnabled();
  await act(async () => {
    vi.setSystemTime(new Date(Date.parse(intent.validUntil) + 1));
  });
  await waitFor(
    () =>
      expect(
        screen.getByRole('button', { name: 'Executor: activate handoff lease' }),
      ).toBeDisabled(),
    { timeout: 2500 },
  );
  expect(screen.getByText(/Authority: NONE/)).toBeInTheDocument();
});

it('shows owner-selected QA lifetime limits before a fresh case is created', async () => {
  const response = receipt(fixed.recoveryPrincipal.principalId);
  vi.spyOn(globalThis, 'fetch').mockResolvedValue(
    Response.json({
      actor: response.actor,
      view: {
        enrollmentId: fixed.enrollmentId,
        assurance: fixed.assurance,
        authority: 'NONE',
        source: { ...actors, rootEpoch: '2', rootRevision: '2' },
        preparation: intent.preparation,
        proposalBefore: new Date(Date.now() + 60000).toISOString(),
        lifetimes: { profile: 'LOCAL_QA', leaseMs: 3600000, administratorMs: 28800000 },
        supersession: {
          recoveryId: intent.recoveryId,
          replacementId: intent.preparation.replacementId,
        },
      },
    }),
  );
  render(<PlatformRecoveryWorkflow />);
  await user().click(screen.getByRole('button', { name: 'Read recovery source' }));
  expect(screen.getByText(/Local QA custody limit:/)).toHaveTextContent('60 minutes');
  expect(screen.getByText(/New administrator scope limit:/)).toHaveTextContent('8 hours');
  expect(screen.queryByText(/Lease deadline:/)).not.toBeInTheDocument();
  expect(
    screen.getByText(/Fresh governed handoff supersedes expired preparation/),
  ).toHaveTextContent(intent.recoveryId);
});

function signerReceipt(principal: 'executor' | 'custodian' | 'admin' = 'executor', active = false) {
  const f = identityEnvelopeRecoveryFixture();
  const actor = {
    sessionId: signerId(650),
    participantId: f.enrollment.participantId,
    principalId:
      principal === 'executor'
        ? f.enrollment.recoveryPrincipal.principalId
        : principal === 'custodian'
          ? f.enrollment.custodians[0].principalId
          : f.enrollment.administratorPrincipalIds[0],
    contextEpoch: '1',
  };
  const intent = {
    schema: 'pc.identity.identity-envelope-recovery-intent',
    schemaVersion: 1,
    purpose: 'IDENTITY_ENVELOPE_SIGNER_REPAIR_ONLY',
    recoveryId: signerId(400),
    enrollmentId: f.enrollment.enrollmentId,
    enrollmentRevision: '1',
    enrollmentDigest: 'sha256:' + '11'.repeat(32),
    rotationId: signerId(401),
    creationOperationId: signerId(402),
    sourceParticipantEpoch: '7',
    sourceIssuerPrincipalEpoch: '1',
    sourceIssuerCredentialEpoch: '1',
    oldTrustDigest: f.enrollment.oldTrustDigest,
    selectionAdmissionVersion: '1',
    validFrom: new Date(Date.now() - 60000).toISOString(),
    validUntil: new Date(Date.now() + 840000).toISOString(),
    postReviewRequired: true,
  };
  const view = {
    actors: {
      executorPrincipalId: f.enrollment.recoveryPrincipal.principalId,
      custodianPrincipalIds: f.enrollment.custodians.map((c) => c.principalId),
    },
    assurance: f.enrollment.assurance,
    recoveryId: intent.recoveryId,
    enrollmentId: intent.enrollmentId,
    intent,
    intentDigest: 'sha256:' + '22'.repeat(32),
    revision: '2',
    state: active ? 'ACTIVE' : 'REQUESTED',
    authority: active ? 'IDENTITY_ENVELOPE_SIGNER_REPAIR_ONLY' : 'NONE',
    proofs: [
      {
        principalId: f.enrollment.recoveryPrincipal.principalId,
        phase: 'REQUEST',
        proofId: signerId(500),
        verifiedAt: new Date(Date.now() - 60000).toISOString(),
      },
      ...f.enrollment.custodians.map((c, i) => ({
        principalId: c.principalId,
        phase: 'APPROVE',
        proofId: signerId(501 + i),
        verifiedAt: new Date(Date.now() - 60000).toISOString(),
      })),
    ],
    expired: false,
    enrollmentState: 'ACTIVE',
    receivingTrustState: 'ACTIVE',
    postReviewRequired: true,
    postReviewStatus: 'REQUIRED',
    ...(active
      ? { lease: { validUntil: intent.validUntil, activationOperationId: signerId(510) } }
      : {}),
  };
  localStorage.setItem(
    'openpc:platform-recovery-case:v1',
    JSON.stringify({
      enrollmentId: f.enrollment.enrollmentId,
      privacyDomainId: f.enrollment.privacyDomainId,
      recoveryId: intent.recoveryId,
    }),
  );
  return { f, actor, view };
}
it.each(['executor', 'custodian', 'admin'] as const)(
  'signer lease activation respects enrolled %s and remains separate from handoff',
  async (principal) => {
    const response = signerReceipt(principal);
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(Response.json(response));
    render(<PlatformRecoveryWorkflow />);
    await user().click(screen.getByRole('button', { name: 'Read original recovery case' }));
    const activation = screen.getByRole('button', {
      name: 'Executor: activate signer repair lease',
    });
    if (principal === 'executor') expect(activation).toBeEnabled();
    else expect(activation).toBeDisabled();
    expect(
      screen.queryByRole('button', { name: 'Executor: activate handoff lease' }),
    ).not.toBeInTheDocument();
    expect(screen.getByText(/at most 15 minutes/)).toBeInTheDocument();
  },
);
it('disables signer activation for stale proofs even before the original case expires', async () => {
  const response = signerReceipt();
  response.view.proofs[1]!.verifiedAt = new Date(Date.now() - 300001).toISOString();
  vi.spyOn(globalThis, 'fetch').mockResolvedValue(Response.json(response));
  render(<PlatformRecoveryWorkflow />);
  await user().click(screen.getByRole('button', { name: 'Read original recovery case' }));
  expect(
    screen.getByRole('button', { name: 'Executor: activate signer repair lease' }),
  ).toBeDisabled();
  expect(screen.getByText(/fresh approvals:/)).toHaveTextContent('fresh approvals: 1/2');
});
it('removes signer state after an external session/context change on focus', async () => {
  const response = signerReceipt(undefined, true);
  vi.spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(Response.json(response))
    .mockResolvedValueOnce(Response.json({ authenticated: false }));
  render(<PlatformRecoveryWorkflow />);
  await user().click(screen.getByRole('button', { name: 'Read original recovery case' }));
  expect(screen.getByText(/Reviewed signer intent:/)).toBeInTheDocument();
  await act(async () => window.dispatchEvent(new Event('focus')));
  await waitFor(() =>
    expect(screen.queryByText(/Reviewed signer intent:/)).not.toBeInTheDocument(),
  );
});
it('preserves the original phase key across response loss and browser remount', async () => {
  const response = signerReceipt(undefined, true);
  const creation = {
    operationId: signerId(402),
    rotationId: signerId(401),
    recoveryId: signerId(400),
    state: 'APPROVED',
    revision: '2',
    currentState: 'APPROVED',
    currentRevision: '2',
    authority: 'IDENTITY_ENVELOPE_SIGNER_REPAIR_ONLY',
  };
  const keys: string[] = [];
  const fetch = vi.spyOn(globalThis, 'fetch').mockImplementation(async (_url, options) => {
    const command = JSON.parse(String(options?.body)).command;
    if (command.kind === 'READ') return Response.json(response);
    if (command.kind === 'ROTATION_CREATE')
      return Response.json({ actor: response.actor, view: creation });
    if (command.kind === 'ROTATION_ADVANCE') {
      keys.push(command.idempotencyKey);
      if (keys.length === 1) throw Error('response lost');
      return Response.json({
        actor: response.actor,
        view: {
          operationId: signerId(600),
          rotationId: signerId(401),
          recoveryId: signerId(400),
          fromRevision: '2',
          fromState: 'APPROVED',
          toState: 'PREPARED',
          state: 'WRITE_AMBIGUITY',
          authority: 'IDENTITY_ENVELOPE_SIGNER_REPAIR_ONLY',
          permissionEffect: 'NONE',
          attempts: [
            {
              attemptId: signerId(601),
              method: 'PREPARE',
              state: 'WRITE_AMBIGUITY',
              ambiguityKind: 'UNKNOWN',
            },
          ],
        },
      });
    }
    throw Error('unexpected command');
  });
  const first = render(<PlatformRecoveryWorkflow />);
  await user().click(screen.getByRole('button', { name: 'Read original recovery case' }));
  await user().click(
    screen.getByRole('button', { name: 'Create or read reserved signer rotation' }),
  );
  await user().click(screen.getByRole('button', { name: 'Advance signer rotation' }));
  expect(keys).toHaveLength(1);
  first.unmount();
  render(<PlatformRecoveryWorkflow />);
  await user().click(screen.getByRole('button', { name: 'Read original recovery case' }));
  await user().click(
    screen.getByRole('button', { name: 'Create or read reserved signer rotation' }),
  );
  await user().click(screen.getByRole('button', { name: 'Advance signer rotation' }));
  expect(keys).toHaveLength(2);
  expect(keys[1]).toBe(keys[0]);
  expect(screen.getByText(/Queue: WRITE_AMBIGUITY/)).toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Reconcile original rotation phase' })).toBeEnabled();
  expect(fetch).toHaveBeenCalledTimes(6);
});

it('explains fresh expiry custody while preserving the expired handoff and waiting for an explicit new proposal', async () => {
  const response = receipt(fixed.recoveryPrincipal.principalId);
  const fetch = vi.spyOn(globalThis, 'fetch').mockResolvedValue(
    Response.json({
      actor: response.actor,
      view: {
        enrollmentId: fixed.enrollmentId,
        assurance: fixed.assurance,
        authority: 'NONE',
        source: { ...actors, rootEpoch: '5', rootRevision: '5' },
        preparation: intent.preparation,
        proposalBefore: new Date(Date.now() + 60000).toISOString(),
        pendingExpiry: { preparation: { replacementId: intent.preparation.replacementId } },
      },
    }),
  );
  render(<PlatformRecoveryWorkflow />);
  await user().click(screen.getByRole('button', { name: 'Read recovery source' }));
  expect(
    screen.getByText(/Create a new governed handoff for the two existing administrators/),
  ).toHaveTextContent('expired handoff and its recorded effects remain preserved');
  expect(fetch).toHaveBeenCalledOnce();
  expect(JSON.parse(fetch.mock.calls[0]![1]!.body as string).command).toEqual({ kind: 'SOURCE' });
  expect(screen.queryByText(/Authority: FIXED_PLATFORM_HANDOFF_ONLY/)).not.toBeInTheDocument();
});
