import {
  assertEnvelopeScopeNarrowing,
  encodeEnvelopeScope,
  type EnvelopeScope,
  type PlatformEnvelopeScopeAdmission,
} from '@openpc/security-kernel';
import {
  platformScopeReplacementPreparation,
  platformScopeReplacementCommit,
  type PlatformScopeAffectedTarget,
  type PlatformScopeReplacementPreparation,
  type PlatformScopeReplacementCommit,
} from '../../../participant-service/src/contracts/platform-scope-replacement.js';

export class PlatformScopeReplacementError extends Error {
  constructor(
    readonly disposition:
      'STALE_SOURCE' | 'INVALID_SCOPE' | 'PENDING_WITHDRAWAL' | 'INVALID_HANDOFF',
  ) {
    super('Platform scope replacement unavailable');
  }
}

/** Read under the real authority/credential/role and root fences. These
 * predicates restrict an already authorized operation; none grants authority. */
export interface PlatformScopeReplacementSource {
  readonly root: PlatformEnvelopeScopeAdmission;
  readonly rootRevision: string;
  readonly rootDigest: string;
  readonly rootState: string;
  readonly makerPrincipalId: string;
  readonly checkerPrincipalId: string;
  readonly sourceExpiresAtNs: string;
  readonly nowNs: string;
  readonly affectedTargets: readonly PlatformScopeAffectedTarget[];
  readonly pendingReplacementId: string | null;
  readonly pendingIntent?: PlatformScopeReplacementPreparation['supersedes'] | null;
  readonly pendingAdministrationExpiresAtNs?: string | null;
}

function sameTargets(
  left: readonly PlatformScopeAffectedTarget[],
  right: readonly PlatformScopeAffectedTarget[],
) {
  const sorted = (values: readonly PlatformScopeAffectedTarget[]) =>
    [...values].sort((a, b) => a.targetId.localeCompare(b.targetId));
  const a = sorted(left),
    b = sorted(right);
  return (
    a.length === b.length &&
    a.every((entry, index) =>
      Object.entries(entry).every(
        ([key, value]) => value === b[index]![key as keyof PlatformScopeAffectedTarget],
      ),
    )
  );
}

export function assertPlatformScopeReplacementPreparation(
  candidate: PlatformScopeReplacementPreparation,
  source: PlatformScopeReplacementSource,
): void {
  candidate = platformScopeReplacementPreparation.parse(candidate);
  if (
    source.rootState !== 'ACTIVE' ||
    (source.pendingReplacementId === null
      ? candidate.supersedes !== undefined
      : candidate.supersedes === undefined ||
        candidate.supersedes.replacementId !== source.pendingReplacementId ||
        candidate.supersedes.expectedRevision !== source.pendingIntent?.expectedRevision ||
        candidate.supersedes.successorDigest !== source.pendingIntent?.successorDigest ||
        source.pendingAdministrationExpiresAtNs === null ||
        source.pendingAdministrationExpiresAtNs === undefined ||
        BigInt(source.pendingAdministrationExpiresAtNs) > BigInt(source.nowNs)) ||
    candidate.platformContextId !== source.root.platformContextId ||
    candidate.expectedRootRevision !== source.rootRevision ||
    candidate.predecessorEpoch !== source.root.platformAuthorityEpoch ||
    candidate.predecessorDigest !== source.rootDigest ||
    BigInt(source.sourceExpiresAtNs) <= BigInt(source.nowNs) ||
    !sameTargets(candidate.affectedTargets, source.affectedTargets)
  )
    throw new PlatformScopeReplacementError('STALE_SOURCE');

  if (
    source.makerPrincipalId === source.checkerPrincipalId ||
    !candidate.administrators.some((entry) => entry.principalId === source.makerPrincipalId) ||
    !candidate.administrators.some((entry) => entry.principalId === source.checkerPrincipalId)
  )
    throw new PlatformScopeReplacementError('INVALID_HANDOFF');

  const scope = candidate.successorScope,
    previous = source.root.grantable;
  if (
    BigInt(scope.validFromNs) < BigInt(previous.validFromNs) ||
    BigInt(scope.validUntilNs) > BigInt(previous.validUntilNs) ||
    BigInt(scope.validUntilNs) > BigInt(source.sourceExpiresAtNs) ||
    BigInt(scope.validUntilNs) <= BigInt(source.nowNs) ||
    BigInt(scope.validFromNs) > BigInt(source.nowNs) ||
    scope.onwardDelegationDepth !== 0 ||
    encodeEnvelopeScope(scope).equals(encodeEnvelopeScope(previous))
  )
    throw new PlatformScopeReplacementError('INVALID_SCOPE');

  // This extension may change root conditions and enumerate administration.
  // It cannot widen any runtime dimension or the original source lifetime.
  for (const key of Object.keys(previous.runtime) as (keyof EnvelopeScope['runtime'])[]) {
    const permitted: readonly string[] = previous.runtime[key];
    if (scope.runtime[key].some((value) => !permitted.includes(value)))
      throw new PlatformScopeReplacementError('INVALID_SCOPE');
  }
  try {
    for (const administrator of candidate.administrators) {
      assertEnvelopeScopeNarrowing(scope, administrator.usable);
      assertEnvelopeScopeNarrowing(scope, administrator.grantable);
      for (const declared of [administrator.usable, administrator.grantable])
        if (
          declared.administration.participantIds.some(
            (id) => id !== source.root.ownerParticipantId,
          ) ||
          declared.administration.privacyDomainIds.some(
            (id) => id !== source.root.installationPrivacyDomainId,
          )
        )
          throw new PlatformScopeReplacementError('INVALID_SCOPE');
    }
  } catch {
    throw new PlatformScopeReplacementError('INVALID_SCOPE');
  }
}

export interface PlatformScopeReplacementReadiness {
  readonly replacementId: string;
  readonly platformContextId: string;
  readonly rootRevision: string;
  readonly predecessorEpoch: string;
  readonly predecessorDigest: string;
  readonly successorDigest: string;
  readonly readinessDigest: string;
  readonly replacementRevision: string;
  readonly state: 'WITHDRAWING' | 'COMMITTED';
  readonly unacknowledgedTargets: number;
  readonly unpreparedAdministrators: number;
  readonly sourceExpiresAtNs: string;
  readonly nowNs: string;
}

/** The database and signed acknowledgement owner establish readiness. A
 * caller-provided digest, zero count or signed history is never readiness. */
export function assertPlatformScopeReplacementCommit(
  candidate: PlatformScopeReplacementCommit,
  current: PlatformScopeReplacementReadiness,
): void {
  candidate = platformScopeReplacementCommit.parse(candidate);
  if (
    current.state !== 'WITHDRAWING' ||
    candidate.replacementId !== current.replacementId ||
    candidate.platformContextId !== current.platformContextId ||
    candidate.expectedRootRevision !== current.rootRevision ||
    candidate.predecessorEpoch !== current.predecessorEpoch ||
    candidate.predecessorDigest !== current.predecessorDigest ||
    candidate.successorDigest !== current.successorDigest ||
    candidate.expectedReplacementRevision !== current.replacementRevision ||
    candidate.readinessDigest !== current.readinessDigest ||
    BigInt(current.sourceExpiresAtNs) <= BigInt(current.nowNs)
  )
    throw new PlatformScopeReplacementError('STALE_SOURCE');
  if (!Number.isSafeInteger(current.unacknowledgedTargets) || current.unacknowledgedTargets !== 0)
    throw new PlatformScopeReplacementError('PENDING_WITHDRAWAL');
  if (
    !Number.isSafeInteger(current.unpreparedAdministrators) ||
    current.unpreparedAdministrators !== 0
  )
    throw new PlatformScopeReplacementError('INVALID_HANDOFF');
}
