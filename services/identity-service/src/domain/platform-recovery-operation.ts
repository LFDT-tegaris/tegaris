import type { PlatformRecoveryIntent } from '../contracts/platform-recovery.js';
import { canonicalAuthorizationDigest } from '../contracts/authorization.js';
import {
  typedEnvelopeCreateCandidate,
  envelopeActivationCandidate,
} from '../../../participant-service/src/contracts/envelope.js';
import { assignmentCreateCandidate } from '../../../participant-service/src/contracts/assignment.js';
import { platformScopeReplacementCommit } from '../../../participant-service/src/contracts/platform-scope-replacement.js';
import { PlatformRecoveryError } from './platform-recovery-policy.js';

/** Additional restriction on an already selected recovery lease. It never authenticates, approves or grants an operation. */
export function assertPlatformRecoveryOperation(
  intent: PlatformRecoveryIntent,
  participantId: string,
  catalogOperationId: string,
  resourceId: string,
  candidate: unknown,
): void {
  const plan = intent.preparation;
  const fail = () => {
    throw new PlatformRecoveryError();
  };
  if (catalogOperationId === 'ID-OP-PLATFORM-SCOPE-PREPARE') {
    if (intent.continuation) return fail();
    if (
      (resourceId !== plan.replacementId && resourceId !== plan.platformContextId) ||
      canonicalAuthorizationDigest(candidate) !== canonicalAuthorizationDigest(plan)
    )
      fail();
    return;
  }
  if (catalogOperationId === 'ID-OP-PLATFORM-SCOPE-COMMIT') {
    const value = platformScopeReplacementCommit.parse(candidate);
    if (
      (resourceId !== plan.replacementId && resourceId !== plan.platformContextId) ||
      value.replacementId !== plan.replacementId ||
      value.platformContextId !== plan.platformContextId ||
      value.predecessorEpoch !== plan.predecessorEpoch ||
      value.predecessorDigest !== plan.predecessorDigest ||
      value.expectedRootRevision !== plan.expectedRootRevision
    )
      fail();
    // The existing commit owner derives and verifies the pending successor, readiness and all effects.
    return;
  }
  if (
    intent.completionSourceDigest &&
    ['ID-OP-ENVELOPE-CREATE', 'ID-OP-ENVELOPE-ACTIVATE'].includes(catalogOperationId) &&
    resourceId === plan.administrators[0]?.envelopeId
  )
    return fail();
  if (catalogOperationId === 'ID-OP-ENVELOPE-CREATE') {
    const value = typedEnvelopeCreateCandidate.parse(candidate);
    const administrator = plan.administrators.find((v) => v.envelopeId === resourceId);
    if (
      !administrator ||
      value.envelopeId !== resourceId ||
      value.participantId !== participantId ||
      value.issuance !== 'PLATFORM_ROOT' ||
      value.platformScopeReplacementId !== plan.replacementId ||
      canonicalAuthorizationDigest(value.usable) !==
        canonicalAuthorizationDigest(administrator.usable) ||
      canonicalAuthorizationDigest(value.grantable) !==
        canonicalAuthorizationDigest(administrator.grantable)
    )
      fail();
    return;
  }
  if (catalogOperationId === 'ID-OP-ENVELOPE-ACTIVATE') {
    const value = envelopeActivationCandidate.parse(candidate);
    if (
      value.envelopeId !== resourceId ||
      !plan.administrators.some((v) => v.envelopeId === resourceId)
    )
      fail();
    return;
  }
  if (catalogOperationId === 'ID-OP-ASSIGNMENT-CREATE') {
    const value = assignmentCreateCandidate.parse(candidate);
    const administrator = plan.administrators.find((v) => v.assignmentId === resourceId);
    if (!administrator) return fail();
    const scope = administrator.usable;
    const equal = (a: unknown, b: unknown) =>
      canonicalAuthorizationDigest(a) === canonicalAuthorizationDigest(b);
    if (
      value.assignmentId !== resourceId ||
      value.participantId !== participantId ||
      value.principalId !== administrator.principalId ||
      value.authorityEnvelopeId !== administrator.envelopeId ||
      value.groupId !== undefined ||
      value.roleId !== `urn:openpc:role:${administrator.roleId}` ||
      (value.capabilityIds?.length ?? 0) !== 0 ||
      !value.makerCheckerRequired ||
      !value.stepUpRequired ||
      value.onwardDelegationDepth !== 0 ||
      !equal(value.privacyDomainIds, scope.administration.privacyDomainIds) ||
      !equal(value.actionIntentIds, scope.administration.actionIntentIds) ||
      !equal(value.resourceIds, scope.administration.resourceIds) ||
      !equal(value.riskClasses, scope.administration.riskClasses) ||
      BigInt(Date.parse(value.validFrom)) * 1000000n < BigInt(scope.validFromNs) ||
      BigInt(Date.parse(value.validUntil)) * 1000000n > BigInt(scope.validUntilNs) ||
      Date.parse(value.validUntil) <= Date.parse(value.validFrom)
    )
      fail();
    return;
  }
  fail();
}
