import { render, screen, cleanup } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, expect, it, vi } from 'vitest';
import { LocalRootExpiryRecoveryWorkflow } from './local-root-expiry-recovery-workflow';
import { localRootExpiryRecoveryFixture } from '../../../services/identity-service/src/domain/local-root-expiry-recovery.test-fixture';
import { localRootExpiryRecoveryIntent } from '../../../services/identity-service/src/contracts/local-root-expiry-recovery';
import { canonicalAuthorizationDigest } from '../../../services/identity-service/src/contracts/authorization';
const f = localRootExpiryRecoveryFixture(),
  e = f.enrollment;
const actors = {
  executorPrincipalId: e.recoveryPrincipal.principalId,
  custodianPrincipalIds: e.custodians.map((v) => v.principalId) as [string, string],
};
const source = {
  enrollmentId: e.enrollmentId,
  purpose: 'LOCAL_ROOT_EXPIRY_RECOVERY_ONLY' as const,
  authority: 'NONE' as const,
  actors,
  assurance: e.assurance,
  source: {
    rootEpoch: e.rootEpoch,
    rootRevision: e.rootRevision,
    rootDigest: e.rootDigest,
    expiredAt: new Date(Number(BigInt(f.root.grantable.validUntilNs) / 1000000n)).toISOString(),
  },
  successorScope: f.root.grantable,
  liveCase: null,
};
const intent = localRootExpiryRecoveryIntent.parse({
  schema: 'pc.identity.local-root-expiry-recovery-intent',
  schemaVersion: 1,
  purpose: 'LOCAL_ROOT_EXPIRY_RECOVERY_ONLY',
  recoveryId: e.enrollmentId,
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
});
const receipt = {
  actors,
  recoveryId: intent.recoveryId,
  enrollmentId: e.enrollmentId,
  purpose: 'LOCAL_ROOT_EXPIRY_RECOVERY_ONLY' as const,
  intent,
  intentDigest: canonicalAuthorizationDigest(intent),
  revision: '2',
  state: 'REQUESTED' as const,
  authority: 'NONE' as const,
  assurance: e.assurance,
  proofs: [],
  result: null,
};
const props = {
  view: source,
  actor: { principalId: e.recoveryPrincipal.principalId },
  recoveryId: intent.recoveryId,
  busy: false,
  now: f.now.getTime(),
  post: vi.fn(),
  assertion: vi.fn(),
  run: async (work: () => Promise<void>) => work(),
  onView: vi.fn(),
  onCase: vi.fn(),
  onStatus: vi.fn(),
};
afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});
it('shows the exact Root and validity with no authority and reserves a reviewed draft once', async () => {
  props.post.mockResolvedValue({ ...receipt, state: 'DRAFT' });
  render(<LocalRootExpiryRecoveryWorkflow {...props} />);
  expect(screen.getByText(/Current authority: NONE/)).toBeInTheDocument();
  expect(screen.getByText(/Original Root digest/)).toHaveTextContent(e.rootDigest);
  await userEvent.click(
    screen.getByRole('button', { name: 'Create reviewed Root expiry recovery case' }),
  );
  expect(props.post).toHaveBeenCalledExactlyOnceWith({ kind: 'CREATE' });
  expect(props.onCase).toHaveBeenCalledWith(intent.recoveryId);
});
it('prevents another actor creating a case and commits only after both custodians', () => {
  const { rerender } = render(
    <LocalRootExpiryRecoveryWorkflow
      {...props}
      actor={{ principalId: e.custodians[0].principalId }}
    />,
  );
  expect(
    screen.getByRole('button', { name: 'Create reviewed Root expiry recovery case' }),
  ).toBeDisabled();
  rerender(<LocalRootExpiryRecoveryWorkflow {...props} view={receipt} />);
  expect(
    screen.getByRole('button', { name: 'Commit governed Root expiry successor' }),
  ).toBeDisabled();
  const approved = {
    ...receipt,
    proofs: e.custodians.map((v) => ({
      principalId: v.principalId,
      phase: 'APPROVE' as const,
      proofId: v.credentialId,
    })),
  };
  rerender(<LocalRootExpiryRecoveryWorkflow {...props} view={approved} />);
  expect(
    screen.getByRole('button', { name: 'Commit governed Root expiry successor' }),
  ).toBeEnabled();
  rerender(
    <LocalRootExpiryRecoveryWorkflow
      {...props}
      view={approved}
      now={Date.parse(intent.validUntil)}
    />,
  );
  expect(
    screen.getByRole('button', { name: 'Commit governed Root expiry successor' }),
  ).toBeDisabled();
});
it('keeps completed original readback while disabling all further proofs and close', () => {
  const completed = {
    ...receipt,
    state: 'COMPLETED' as const,
    result: {
      rootEpoch: '3',
      rootRevision: '3',
      rootDigest: e.rootDigest,
      operationId: intent.recoveryId,
    },
  };
  render(<LocalRootExpiryRecoveryWorkflow {...props} view={completed} />);
  expect(screen.getByText(/Committed Root epoch 3/)).toBeInTheDocument();
  expect(
    screen.getByRole('button', { name: 'Commit governed Root expiry successor' }),
  ).toBeDisabled();
  expect(screen.getByRole('button', { name: 'Close Root expiry recovery case' })).toBeDisabled();
  expect(screen.getByRole('button', { name: 'Read original Root expiry result' })).toBeEnabled();
});

it('shows ancestry as retained history and keeps fresh approval controls separate', () => {
  const rootAncestry = {
    schema: 'pc.identity.local-root-expiry-pending-ancestry' as const,
    schemaVersion: 1 as const,
    rootEpoch: '6',
    rootRevision: '6',
    rootDigest: e.rootDigest,
    receipts: [
      {
        enrollmentId: e.enrollmentId,
        recoveryId: e.custodians[0].principalId,
        activationOperationId: e.custodians[1].principalId,
        enrollmentDigest: e.rootDigest,
        intentDigest: e.rootDigest,
        receiptDigest: e.rootDigest,
        predecessorEpoch: '5',
        predecessorRevision: '5',
        predecessorDigest: e.rootDigest,
        rootEpoch: '6',
        rootRevision: '6',
        rootDigest: e.rootDigest,
      },
    ],
  };
  const v3 = {
    ...source,
    purpose: 'LOCAL_ROOT_EXPIRY_PENDING_ANCESTRY_RECOVERY_ONLY' as const,
    source: { ...source.source, rootEpoch: '6', rootRevision: '6', rootAncestry },
  };
  render(<LocalRootExpiryRecoveryWorkflow {...props} view={v3} />);
  expect(screen.getByText(/Verified Root recovery history/)).toHaveTextContent(
    '1 completed receipts ending at Root epoch 6',
  );
  expect(screen.getByText(/These receipts grant no current authority/)).toBeInTheDocument();
  expect(screen.getByText(/Current authority: NONE/)).toBeInTheDocument();
  expect(
    screen.getByRole('button', { name: 'Create reviewed Root expiry recovery case' }),
  ).toBeEnabled();
  expect(props.assertion).not.toHaveBeenCalled();
});
