import {
  assertEnvelopeScopeNarrowing,
  type PlatformEnvelopeScopeAdmission,
} from '@openpc/security-kernel';
import {
  platformAdministrationRecoveryEnrollment,
  platformRecoveryIntent,
  type PlatformAdministrationRecoveryEnrollment,
  type PlatformRecoveryIntent,
  type RootExpiryPlatformRecoveryEnrollment,
  type PlatformRecoveryContinuation,
  type PlatformPendingAdministrationExpiry,
} from '../contracts/platform-recovery.js';
import {
  defaultRecoveryLifetimes,
  recoveryLifetimeSettings,
} from './platform-recovery-lifetimes.js';
import { canonicalAuthorizationDigest } from '../contracts/authorization.js';
import { assertUneffectedRecoverySuccessor } from './platform-recovery-uneffected.js';

export class PlatformRecoveryError extends Error {
  constructor() {
    super('Platform recovery unavailable');
  }
}

export interface PlatformRecoverySource {
  readonly root: PlatformEnvelopeScopeAdmission;
  readonly rootRevision: string;
  readonly rootDigest: string;
  readonly rootState: string;
  readonly enrollment: PlatformAdministrationRecoveryEnrollment;
  readonly enrollmentRevision: string;
  readonly enrollmentState: string;
  readonly expiredReplacementId: string | null;
  /** Set only after receipt authentication and exact original assignment readback. */
  readonly originalAdministrationDisplaced?: boolean;
  readonly administratorPrincipalIds: readonly string[];
  readonly originalAdministrators: PlatformRecoveryIntent['preparation']['administrators'];
  readonly administratorEpochs: readonly {
    readonly principalId: string;
    readonly principalEpoch: string;
  }[];
  /** Five names generated and retained by the recovery owner, never supplied as authority by a caller. */
  readonly plannedRecordIds: readonly string[];
  readonly pendingReplacementId: string | null;
  /** Present only after owner verification of the closed, expired, uneffected predecessor. */
  readonly recoverySupersession?: PlatformRecoveryIntent['supersession'];
  /** Authenticated wholly uneffected preparation from a different expired enrollment. */
  readonly uneffectedPreparation?: PlatformRecoveryIntent['preparation'];
  /** Authenticated historical source for exactly the same already-effected handoff. */
  readonly recoveryContinuation?: PlatformRecoveryContinuation;
  readonly continuationPreparation?: PlatformRecoveryIntent['preparation'];
  /** Populated only by the exact current-root/partial-effect witness owner. */
  readonly pendingExpiry?: PlatformPendingAdministrationExpiry;
  readonly expiryPreparation?: PlatformRecoveryIntent['preparation'];
  /** Authenticated original unconsumed PREPARE, never a current grant. */
  readonly approvalContinuation?: PlatformRecoveryIntent['approvalContinuation'];
  readonly approvalContinuationPreparation?: PlatformRecoveryIntent['preparation'];
  /** Authenticated V2 Root receipt, separately rechecked by the SQL owner. */
  readonly rootExpiryPendingBridge?: {
    readonly pending: import('../contracts/local-root-expiry-recovery.js').LocalRootExpiryPendingWitness;
    readonly rootEpoch: string;
    readonly rootRevision: string;
    readonly rootDigest: string;
    readonly receipt?: {
      readonly recoveryId: string;
      readonly enrollmentId: string;
      readonly activationOperationId: string;
      readonly receiptDigest: string;
    };
  };
  /** Exact persisted case and linked WITHDRAWING successor, read after PREPARE.
   * Never derived from a caller's proposed replacement or from the latest ID. */
  readonly expiryPendingSuccessor?: {
    readonly replacementId: string;
    readonly recoveryId: string;
    readonly intentDigest: string;
    readonly preparationDigest: string;
    readonly plannedRecordIds: readonly string[];
  };
  /** Authoritative all-of readback of both signed usable/grantable deadlines. */
  readonly administrationExpired: boolean;
  readonly now: Date;
  readonly localQaEnabled: boolean;
}

/** Restricts an owner-read enrollment; this predicate cannot authenticate a caller or grant a lease. */
export function assertPlatformRecoverySource(source: PlatformRecoverySource): void {
  const enrollment = platformAdministrationRecoveryEnrollment.parse(source.enrollment);
  const now = source.now.getTime();
  if (
    !Number.isFinite(now) ||
    source.rootState !== 'ACTIVE' ||
    source.enrollmentState !== 'ACTIVE' ||
    (enrollment.schemaVersion === 1
      ? !source.administrationExpired ||
        enrollment.expiredReplacementId !== source.expiredReplacementId
      : !source.originalAdministrationDisplaced ||
        source.expiredReplacementId !== null ||
        !source.localQaEnabled ||
        enrollment.assurance !== 'LOCAL_QA_VIRTUAL_AUTHENTICATOR' ||
        Object.values(source.root.grantable.administration).some(
          (values) => values.length !== 0,
        )) ||
    enrollment.platformContextId !== source.root.platformContextId ||
    enrollment.participantId !== source.root.ownerParticipantId ||
    enrollment.privacyDomainId !== source.root.installationPrivacyDomainId ||
    enrollment.rootEpoch !== source.root.platformAuthorityEpoch ||
    enrollment.rootRevision !== source.rootRevision ||
    enrollment.rootDigest !== source.rootDigest ||
    source.administratorPrincipalIds.length !== 2 ||
    new Set(source.administratorPrincipalIds).size !== 2 ||
    enrollment.administratorPrincipalIds.some(
      (id) => !source.administratorPrincipalIds.includes(id),
    ) ||
    Date.parse(enrollment.validFrom) > now ||
    Date.parse(enrollment.validUntil) <= now ||
    BigInt(source.root.grantable.validFromNs) > BigInt(now) * 1_000_000n ||
    BigInt(source.root.grantable.validUntilNs) <= BigInt(now) * 1_000_000n ||
    (enrollment.assurance === 'LOCAL_QA_VIRTUAL_AUTHENTICATOR' && !source.localQaEnabled)
  )
    throw new PlatformRecoveryError();
}

/** The normal replacement owner still owns preparation, approval, withdrawal and commit. */
export function assertPlatformRecoveryIntent(
  value: PlatformRecoveryIntent,
  source: PlatformRecoverySource,
): void {
  assertPlatformRecoverySource(source);
  const intent = platformRecoveryIntent.parse(value);
  const enrollment = source.enrollment;
  const from = Date.parse(intent.validFrom);
  const until = Date.parse(intent.validUntil);
  const preparation = intent.preparation;
  if (enrollment.schemaVersion === 2 && enrollment.uneffectedPredecessor) {
    if (!source.uneffectedPreparation) throw new PlatformRecoveryError();
    try {
      assertUneffectedRecoverySuccessor(
        intent,
        source.uneffectedPreparation,
        source.rootExpiryPendingBridge,
      );
    } catch {
      throw new PlatformRecoveryError();
    }
  } else if (source.uneffectedPreparation) throw new PlatformRecoveryError();
  const completion =
    enrollment.schemaVersion === 3 ? enrollment.source.activatedHandoff : undefined;
  if (
    intent.completionSourceDigest !==
    (completion ? canonicalAuthorizationDigest(completion) : undefined)
  )
    throw new PlatformRecoveryError();
  const closed = enrollment.schemaVersion === 4 ? enrollment.source.closedApproval : undefined;
  if (
    intent.closedApprovalSourceDigest !==
    (closed ? canonicalAuthorizationDigest(closed) : undefined)
  )
    throw new PlatformRecoveryError();
  if (enrollment.schemaVersion === 4) {
    assertPendingAdministrationExpiryRenewal(intent, source);
  } else if (
    intent.pendingExpiry ||
    source.pendingExpiry ||
    source.expiryPreparation ||
    source.expiryPendingSuccessor ||
    intent.approvalContinuation ||
    source.approvalContinuation ||
    source.approvalContinuationPreparation ||
    (intent.supersession === undefined
      ? (!completion && preparation.supersedes !== undefined) ||
        source.recoverySupersession !== undefined
      : !source.recoverySupersession ||
        canonicalAuthorizationDigest(intent.supersession) !==
          canonicalAuthorizationDigest(source.recoverySupersession) ||
        preparation.supersedes?.replacementId !== intent.supersession.replacementId ||
        preparation.supersedes?.expectedRevision !== intent.supersession.expectedRevision ||
        preparation.supersedes?.successorDigest !== intent.supersession.successorDigest ||
        intent.recoveryId === intent.supersession.recoveryId ||
        preparation.replacementId === intent.supersession.replacementId)
  )
    throw new PlatformRecoveryError();
  const continuation = intent.continuation;
  if (enrollment.schemaVersion === 3) {
    if (
      !continuation ||
      !source.recoveryContinuation ||
      !source.continuationPreparation ||
      source.pendingReplacementId !== continuation.replacementId ||
      canonicalAuthorizationDigest(continuation) !==
        canonicalAuthorizationDigest(source.recoveryContinuation) ||
      canonicalAuthorizationDigest(continuation) !==
        canonicalAuthorizationDigest(enrollment.source.continuation) ||
      canonicalAuthorizationDigest(preparation) !== continuation.preparationDigest ||
      canonicalAuthorizationDigest(preparation) !==
        canonicalAuthorizationDigest(source.continuationPreparation) ||
      intent.supersession ||
      (!completion && preparation.supersedes)
    )
      throw new PlatformRecoveryError();
  } else if (continuation || source.recoveryContinuation || source.continuationPreparation) {
    throw new PlatformRecoveryError();
  }
  const lifetimes = recoveryLifetimeSettings.parse(intent.lifetimes ?? defaultRecoveryLifetimes);
  if (
    lifetimes.profile !== 'C17' &&
    (!source.localQaEnabled || enrollment.assurance !== 'LOCAL_QA_VIRTUAL_AUTHENTICATOR')
  )
    throw new PlatformRecoveryError();
  if (
    intent.enrollmentId !== enrollment.enrollmentId ||
    intent.enrollmentRevision !== source.enrollmentRevision ||
    intent.enrollmentDigest !== canonicalAuthorizationDigest(enrollment) ||
    from > source.now.getTime() ||
    until <= source.now.getTime() ||
    until <= from ||
    until - from > lifetimes.leaseMs ||
    from < Date.parse(enrollment.validFrom) ||
    until > Date.parse(enrollment.validUntil) ||
    BigInt(until) * 1_000_000n > BigInt(source.root.grantable.validUntilNs) ||
    preparation.platformContextId !== enrollment.platformContextId ||
    preparation.predecessorEpoch !== enrollment.rootEpoch ||
    preparation.expectedRootRevision !== enrollment.rootRevision ||
    preparation.predecessorDigest !== enrollment.rootDigest ||
    (source.pendingReplacementId !== null &&
      source.pendingReplacementId !== preparation.replacementId &&
      source.pendingReplacementId !== intent.supersession?.replacementId &&
      source.pendingReplacementId !== intent.pendingExpiry?.preparation.replacementId) ||
    preparation.administrators.some(
      (v) => !enrollment.administratorPrincipalIds.includes(v.principalId),
    ) ||
    preparation.administrators.length !== 2 ||
    new Set(intent.administratorEpochs.map((v) => v.principalId)).size !== 2 ||
    intent.administratorEpochs.some(
      (v) =>
        !source.administratorEpochs.some(
          (current) =>
            current.principalId === v.principalId && current.principalEpoch === v.principalEpoch,
        ),
    )
  )
    throw new PlatformRecoveryError();

  // Only fresh administration record names may be added to the finite source.
  // Business resources/actions and all runtime dimensions remain inside the current Root.
  const freshNames = new Set([
    preparation.replacementId,
    ...preparation.administrators.flatMap((v) => [v.envelopeId, v.assignmentId]),
  ]);
  if (
    freshNames.size !== 5 ||
    source.plannedRecordIds.length !== 5 ||
    new Set(source.plannedRecordIds).size !== 5 ||
    source.plannedRecordIds.some((id) => !freshNames.has(id))
  )
    throw new PlatformRecoveryError();
  const comparable = structuredClone(preparation.successorScope);
  comparable.administration.resourceIds = comparable.administration.resourceIds.filter(
    (id) => !freshNames.has(id),
  );
  try {
    assertEnvelopeScopeNarrowing(platformRecoverySourceCeiling(source), comparable);
    for (const administrator of preparation.administrators) {
      const original = source.originalAdministrators.find(
        (v) => v.principalId === administrator.principalId,
      );
      if (
        !original ||
        administrator.roleId !== original.roleId ||
        administrator.expectedRoleRevision !== original.expectedRoleRevision ||
        administrator.roleDigest !== original.roleDigest
      )
        throw new PlatformRecoveryError();
      for (const dimension of ['usable', 'grantable'] as const) {
        const bounded = structuredClone(administrator[dimension]);
        if (BigInt(bounded.validUntilNs) > BigInt(from + lifetimes.administratorMs) * 1000000n)
          throw new PlatformRecoveryError();
        bounded.administration.resourceIds = bounded.administration.resourceIds.filter(
          (id) => !freshNames.has(id),
        );
        bounded.validFromNs = original[dimension].validFromNs;
        bounded.validUntilNs = original[dimension].validUntilNs;
        assertEnvelopeScopeNarrowing(original[dimension], bounded);
      }
      assertEnvelopeScopeNarrowing(preparation.successorScope, administrator.usable);
      assertEnvelopeScopeNarrowing(preparation.successorScope, administrator.grantable);
      if (
        (!continuation &&
          !intent.approvalContinuation &&
          (BigInt(administrator.usable.validFromNs) < BigInt(from) * 1_000_000n ||
            BigInt(administrator.grantable.validFromNs) < BigInt(from) * 1_000_000n)) ||
        BigInt(administrator.usable.validUntilNs) < BigInt(until) * 1_000_000n ||
        BigInt(administrator.grantable.validUntilNs) < BigInt(until) * 1_000_000n
      )
        throw new PlatformRecoveryError();
    }
  } catch {
    throw new PlatformRecoveryError();
  }
}

/** Independent installation custody declares finite administration; the
 * authenticated receipt supplies only the unchanged runtime and time ceiling.
 * This produces a comparison bound, never an admitted Root or an actor grant. */
export function platformRecoverySourceCeiling(source: {
  readonly root: PlatformRecoverySource['root'];
  readonly enrollment:
    | { readonly schemaVersion: 1 }
    | {
        readonly schemaVersion: 2 | 3 | 4;
        readonly source: RootExpiryPlatformRecoveryEnrollment['source'];
      };
}) {
  const ceiling = structuredClone(source.root.grantable);
  if (source.enrollment.schemaVersion === 1) return ceiling;
  const declarations = source.enrollment.source.originalAdministrators.flatMap((v) => [
    v.usable.administration,
    v.grantable.administration,
  ]);
  const union = <T extends string>(read: (scope: typeof ceiling.administration) => readonly T[]) =>
    [...new Set(declarations.flatMap(read))].sort((a, b) =>
      Buffer.compare(Buffer.from(a), Buffer.from(b)),
    );
  ceiling.administration = {
    participantIds: union((v) => v.participantIds),
    privacyDomainIds: union((v) => v.privacyDomainIds),
    actionIntentIds: union((v) => v.actionIntentIds),
    resourceIds: union((v) => v.resourceIds),
    dataClasses: union((v) => v.dataClasses),
    targetProfileIds: union((v) => v.targetProfileIds),
    riskClasses: union((v) => v.riskClasses),
  };
  return ceiling;
}

export const pendingAdministrationExpiryReason =
  'Renew the exact expired partial Platform administrator handoff under fresh independent recovery custody.';

/** The historical signed preparation stays unchanged. Only this newly governed
 * purpose may substitute owner-generated record names and finite current time.
 * Authentication, effect certainty and role/revocation fences remain DB-owned. */
export function assertPendingAdministrationExpiryRenewal(
  intent: PlatformRecoveryIntent,
  source: PlatformRecoverySource,
): void {
  const enrollment = source.enrollment;
  const original = source.expiryPreparation;
  const witness = source.pendingExpiry;
  const bridge = source.rootExpiryPendingBridge;
  if (
    witness?.schemaVersion === 2 &&
    (intent.approvalContinuation ||
      intent.closedApprovalSourceDigest ||
      source.approvalContinuation ||
      source.approvalContinuationPreparation)
  )
    throw new PlatformRecoveryError();

  const exactBridge =
    !!original &&
    !!bridge &&
    bridge.rootEpoch === source.root.platformAuthorityEpoch &&
    bridge.rootRevision === source.rootRevision &&
    bridge.rootDigest === source.rootDigest &&
    bridge.pending.replacementId === original.replacementId &&
    bridge.pending.predecessorEpoch === original.predecessorEpoch &&
    bridge.pending.expectedRootRevision === original.expectedRootRevision &&
    bridge.pending.predecessorDigest === original.predecessorDigest &&
    bridge.pending.preparationDigest === canonicalAuthorizationDigest(original) &&
    BigInt(bridge.rootEpoch) === BigInt(original.predecessorEpoch) + 1n &&
    BigInt(bridge.rootRevision) === BigInt(original.expectedRootRevision) + 1n;
  if (
    enrollment.schemaVersion !== 4 ||
    !original ||
    !witness ||
    !intent.pendingExpiry ||
    intent.continuation ||
    intent.supersession ||
    source.recoveryContinuation ||
    source.recoverySupersession ||
    canonicalAuthorizationDigest(witness) !==
      canonicalAuthorizationDigest(enrollment.source.pendingExpiry) ||
    canonicalAuthorizationDigest(witness) !== canonicalAuthorizationDigest(intent.pendingExpiry) ||
    canonicalAuthorizationDigest(original) !== witness.preparation.preparationDigest ||
    original.replacementId !== witness.preparation.replacementId ||
    original.platformContextId !== source.root.platformContextId ||
    (!!bridge && !exactBridge) ||
    (!exactBridge &&
      (original.expectedRootRevision !== source.rootRevision ||
        original.predecessorEpoch !== source.root.platformAuthorityEpoch ||
        original.predecessorDigest !== source.rootDigest)) ||
    original.administrators.some(
      (admin, index) =>
        admin.principalId !== witness.administrators[index]?.principalId ||
        admin.envelopeId !== witness.administrators[index]?.envelopeId ||
        admin.assignmentId !== witness.administrators[index]?.assignmentId ||
        [admin.usable, admin.grantable].some(
          (scope) => BigInt(scope.validUntilNs) > BigInt(source.now.getTime()) * 1000000n,
        ),
    )
  )
    throw new PlatformRecoveryError();
  if (
    intent.approvalContinuation ||
    source.approvalContinuation ||
    source.approvalContinuationPreparation
  ) {
    if (
      !intent.approvalContinuation ||
      !source.approvalContinuation ||
      !source.approvalContinuationPreparation ||
      canonicalAuthorizationDigest(intent.approvalContinuation) !==
        canonicalAuthorizationDigest(source.approvalContinuation) ||
      canonicalAuthorizationDigest(intent.preparation) !==
        canonicalAuthorizationDigest(source.approvalContinuationPreparation) ||
      canonicalAuthorizationDigest(intent.preparation) !==
        intent.approvalContinuation.candidateDigest ||
      intent.recoveryId === intent.approvalContinuation.recoveryId
    )
      throw new PlatformRecoveryError();
  }
  const successor = source.expiryPendingSuccessor;
  if (
    successor
      ? source.pendingReplacementId !== successor.replacementId ||
        successor.replacementId !== intent.preparation.replacementId ||
        successor.recoveryId !== intent.recoveryId ||
        successor.intentDigest !== canonicalAuthorizationDigest(intent) ||
        successor.preparationDigest !== canonicalAuthorizationDigest(intent.preparation) ||
        canonicalAuthorizationDigest(successor.plannedRecordIds) !==
          canonicalAuthorizationDigest(source.plannedRecordIds)
      : source.pendingReplacementId !== original.replacementId
  )
    throw new PlatformRecoveryError();
  const oldNames = [
    original.replacementId,
    ...original.administrators.flatMap((admin) => [admin.envelopeId, admin.assignmentId]),
  ];
  const newNames = [
    intent.preparation.replacementId,
    ...intent.preparation.administrators.flatMap((admin) => [admin.envelopeId, admin.assignmentId]),
  ];
  if (
    source.plannedRecordIds.length !== 5 ||
    new Set(newNames).size !== 5 ||
    newNames.some(
      (name, index) => name !== source.plannedRecordIds[index] || oldNames.includes(name),
    )
  )
    throw new PlatformRecoveryError();
  const substitute = (scope: PlatformRecoveryIntent['preparation']['successorScope']) => {
    scope.administration.resourceIds = scope.administration.resourceIds
      .map((name) => {
        const index = oldNames.indexOf(name);
        return index < 0 ? name : newNames[index]!;
      })
      .sort((a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b)));
  };
  const expected = structuredClone(original);
  if (exactBridge) {
    expected.predecessorEpoch = source.root.platformAuthorityEpoch;
    expected.expectedRootRevision = source.rootRevision;
    expected.predecessorDigest = source.rootDigest;
  }
  expected.reason = pendingAdministrationExpiryReason;
  expected.replacementId = newNames[0]!;
  expected.supersedes = {
    replacementId: original.replacementId,
    expectedRevision: witness.preparation.expectedRevision,
    successorDigest: witness.preparation.successorDigest,
  };
  substitute(expected.successorScope);
  const proposed = intent.preparation.successorScope;
  if (
    BigInt(proposed.validFromNs) < BigInt(original.successorScope.validFromNs) ||
    BigInt(proposed.validFromNs) > BigInt(source.now.getTime()) * 1000000n ||
    (!exactBridge &&
      BigInt(proposed.validUntilNs) > BigInt(original.successorScope.validUntilNs)) ||
    (exactBridge && BigInt(proposed.validFromNs) < BigInt(source.root.grantable.validFromNs)) ||
    BigInt(proposed.validUntilNs) > BigInt(source.root.grantable.validUntilNs)
  )
    throw new PlatformRecoveryError();
  expected.successorScope.validFromNs = proposed.validFromNs;
  expected.successorScope.validUntilNs = proposed.validUntilNs;
  for (const [index, admin] of expected.administrators.entries()) {
    admin.envelopeId = newNames[index * 2 + 1]!;
    admin.assignmentId = newNames[index * 2 + 2]!;
    for (const dimension of ['usable', 'grantable'] as const) {
      substitute(admin[dimension]);
      const current = intent.preparation.administrators[index]?.[dimension];
      if (!current) throw new PlatformRecoveryError();
      admin[dimension].validFromNs = current.validFromNs;
      admin[dimension].validUntilNs = current.validUntilNs;
    }
  }
  if (canonicalAuthorizationDigest(expected) !== canonicalAuthorizationDigest(intent.preparation))
    throw new PlatformRecoveryError();
}
