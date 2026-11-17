import type {
  PlatformRecoveryIntent,
  RootExpiryPlatformRecoveryEnrollment,
} from '../contracts/platform-recovery.js';
import { canonicalAuthorizationDigest } from '../contracts/authorization.js';
import type { PlatformRecoverySource } from './platform-recovery-policy.js';

export type UneffectedRootBridge = NonNullable<PlatformRecoverySource['rootExpiryPendingBridge']>;

function bridgeMatches(
  bridge: UneffectedRootBridge,
  original: { epoch: string; revision: string; digest: string },
  replacementId: string,
  preparationDigest: string,
) {
  return (
    bridge.pending.replacementId === replacementId &&
    bridge.pending.replacementRevision === '1' &&
    bridge.pending.predecessorEpoch === original.epoch &&
    bridge.pending.expectedRootRevision === original.revision &&
    bridge.pending.predecessorDigest === original.digest &&
    bridge.pending.preparationDigest === preparationDigest &&
    BigInt(bridge.rootEpoch) === BigInt(original.epoch) + 1n &&
    BigInt(bridge.rootRevision) === BigInt(original.revision) + 1n
  );
}

const deny = (): never => {
  throw new Error('Uneffected Platform recovery unavailable');
};

/** Renew finite custody with identical permissions. A verified pending Root
 * recovery may add its receipt ahead of the exact original receipt history. */
export function assertUneffectedEnrollmentPermissions(
  fresh: RootExpiryPlatformRecoveryEnrollment,
  original: RootExpiryPlatformRecoveryEnrollment,
  bridge?: UneffectedRootBridge,
) {
  if (!fresh.uneffectedPredecessor || original.uneffectedPredecessor) return deny();
  const comparable = structuredClone(fresh);
  delete comparable.uneffectedPredecessor;
  comparable.enrollmentId = original.enrollmentId;
  comparable.validFrom = original.validFrom;
  comparable.validUntil = original.validUntil;
  if (
    fresh.rootEpoch !== original.rootEpoch ||
    fresh.rootRevision !== original.rootRevision ||
    fresh.rootDigest !== original.rootDigest
  ) {
    const link = fresh.uneffectedPredecessor;
    const reference = ({
      recoveryId,
      enrollmentId,
      activationOperationId,
      receiptDigest,
    }: typeof original.source) => ({
      recoveryId,
      enrollmentId,
      activationOperationId,
      receiptDigest,
    });
    if (
      !bridge ||
      !bridge.receipt ||
      canonicalAuthorizationDigest(reference(fresh.source)) !==
        canonicalAuthorizationDigest(bridge.receipt) ||
      !bridgeMatches(
        bridge,
        { epoch: original.rootEpoch, revision: original.rootRevision, digest: original.rootDigest },
        link.replacementId,
        link.preparationDigest,
      ) ||
      fresh.rootEpoch !== bridge.rootEpoch ||
      fresh.rootRevision !== bridge.rootRevision ||
      fresh.rootDigest !== bridge.rootDigest ||
      bridge.pending.preparationCandidateId !== link.preparationCandidateId ||
      bridge.pending.preparationOperationId !== link.preparationOperationId ||
      bridge.pending.preparationApprovalId !== link.preparationApprovalId ||
      bridge.pending.successorDigest !== link.successorDigest ||
      canonicalAuthorizationDigest(fresh.source.ancestorReceipts) !==
        canonicalAuthorizationDigest([
          reference(original.source),
          ...(original.source.ancestorReceipts ?? []),
        ])
    )
      return deny();
    comparable.rootEpoch = original.rootEpoch;
    comparable.rootRevision = original.rootRevision;
    comparable.rootDigest = original.rootDigest;
    Object.assign(comparable.source, reference(original.source));
    if (original.source.ancestorReceipts)
      comparable.source.ancestorReceipts = structuredClone(original.source.ancestorReceipts);
    else delete comparable.source.ancestorReceipts;
  }
  for (const [index, administrator] of comparable.source.originalAdministrators.entries()) {
    const old = original.source.originalAdministrators[index];
    if (!old) return deny();
    for (const dimension of ['usable', 'grantable'] as const) {
      administrator[dimension].validFromNs = old[dimension].validFromNs;
      administrator[dimension].validUntilNs = old[dimension].validUntilNs;
    }
  }
  if (canonicalAuthorizationDigest(comparable) !== canonicalAuthorizationDigest(original))
    return deny();
}

/** Compare the full successor after the five prescribed name substitutions.
 * The ordinary recovery owner separately enforces live Root/default lifetimes. */
export function assertUneffectedRecoverySuccessor(
  intent: PlatformRecoveryIntent,
  original: PlatformRecoveryIntent['preparation'],
  bridge?: UneffectedRootBridge,
) {
  if (
    !intent.supersession ||
    intent.preparation.supersedes?.replacementId !== original.replacementId
  )
    return deny();
  const oldNames = [
    original.replacementId,
    ...original.administrators.flatMap((admin) => [admin.envelopeId, admin.assignmentId]),
  ];
  const next = intent.preparation;
  const newNames = [
    next.replacementId,
    ...next.administrators.flatMap((admin) => [admin.envelopeId, admin.assignmentId]),
  ];
  if (
    oldNames.length !== 5 ||
    newNames.length !== 5 ||
    new Set(newNames).size !== 5 ||
    newNames.some((name) => oldNames.includes(name))
  )
    return deny();
  const expected = structuredClone(original);
  if (
    next.predecessorEpoch !== original.predecessorEpoch ||
    next.expectedRootRevision !== original.expectedRootRevision ||
    next.predecessorDigest !== original.predecessorDigest
  ) {
    if (
      !bridge ||
      !bridgeMatches(
        bridge,
        {
          epoch: original.predecessorEpoch,
          revision: original.expectedRootRevision,
          digest: original.predecessorDigest,
        },
        original.replacementId,
        canonicalAuthorizationDigest(original),
      ) ||
      bridge.pending.preparationOperationId !== intent.supersession.preparationOperationId ||
      bridge.pending.preparationApprovalId !== intent.supersession.preparationApprovalId ||
      bridge.pending.successorDigest !== intent.supersession.successorDigest
    )
      return deny();
    expected.predecessorEpoch = bridge.rootEpoch;
    expected.expectedRootRevision = bridge.rootRevision;
    expected.predecessorDigest = bridge.rootDigest;
  }
  expected.replacementId = newNames[0]!;
  expected.supersedes = {
    replacementId: intent.supersession.replacementId,
    expectedRevision: intent.supersession.expectedRevision,
    successorDigest: intent.supersession.successorDigest,
  };
  const scope = (old: typeof expected.successorScope, fresh: typeof next.successorScope) => {
    old.administration.resourceIds = old.administration.resourceIds
      .map((name) => {
        const index = oldNames.indexOf(name);
        return index < 0 ? name : newNames[index]!;
      })
      .sort((a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b)));
    old.validFromNs = fresh.validFromNs;
    old.validUntilNs = fresh.validUntilNs;
  };
  scope(expected.successorScope, next.successorScope);
  for (const [index, administrator] of expected.administrators.entries()) {
    const fresh = next.administrators[index];
    if (!fresh) return deny();
    administrator.envelopeId = newNames[index * 2 + 1]!;
    administrator.assignmentId = newNames[index * 2 + 2]!;
    scope(administrator.usable, fresh.usable);
    scope(administrator.grantable, fresh.grantable);
  }
  if (canonicalAuthorizationDigest(expected) !== canonicalAuthorizationDigest(next)) return deny();
}
