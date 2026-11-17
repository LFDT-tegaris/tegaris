import { pendingExpiryPlatformRecoveryFixture } from './platform-recovery.test-fixture.js';
import {
  activatedPendingAdministrationExpiry,
  pendingExpiryPlatformRecoveryEnrollment,
  pendingPlatformRecoveryEnrollment,
  platformRecoveryContinuation,
  type PlatformRecoveryIntent,
} from '../contracts/platform-recovery.js';
import { canonicalAuthorizationDigest } from '../contracts/authorization.js';
import type { PlatformRecoverySource } from './platform-recovery-policy.js';
import {
  envelopeFixtureId as id,
  envelopeFixtureDigest as digest,
} from '../../../../packages/security-kernel/src/identity-envelope/fixture.js';

/** Synthetic signed-shape inputs; native state and signatures need separate qualification. */
export function completionContinuationFixture() {
  const original = pendingExpiryPlatformRecoveryFixture();
  const previous = original.source.pendingExpiry;
  if (
    original.source.enrollment.schemaVersion !== 4 ||
    previous?.schemaVersion !== 1 ||
    previous.administrators[0].effect.state !== 'APPROVED_PROPOSAL'
  )
    throw Error('fixture');
  const pendingExpiry = activatedPendingAdministrationExpiry.parse({
    ...previous,
    schemaVersion: 2,
    predecessorEnrollmentDigest: digest(810),
    predecessorClosedApprovalDigest: digest(811),
    administrators: [
      {
        ...previous.administrators[0],
        effect: {
          ...previous.administrators[0].effect,
          state: 'ACTIVE_UNASSIGNED',
          envelopeRevision: '4',
          activationOperationId: id(812),
          activationAttemptId: id(813),
          activationEvidenceDigest: digest(814),
          activationPayloadDigest: digest(815),
        },
      },
      previous.administrators[1],
    ],
  });
  original.source.enrollment = pendingExpiryPlatformRecoveryEnrollment.parse({
    ...original.source.enrollment,
    source: { ...original.source.enrollment.source, pendingExpiry },
  });
  original.source.pendingExpiry = pendingExpiry;
  original.intent.pendingExpiry = pendingExpiry;
  original.intent.enrollmentDigest = canonicalAuthorizationDigest(original.source.enrollment);
  const now = new Date(Date.parse(original.intent.validUntil) + 1000);
  const continuation = platformRecoveryContinuation.parse({
    schema: 'pc.identity.platform-pending-recovery-continuation',
    schemaVersion: 1,
    enrollmentId: original.intent.enrollmentId,
    recoveryId: original.intent.recoveryId,
    intentDigest: canonicalAuthorizationDigest(original.intent),
    activationOperationId: id(820),
    activationReceiptDigest: digest(821),
    replacementId: original.intent.preparation.replacementId,
    preparationCandidateId: id(822),
    preparationDigest: canonicalAuthorizationDigest(original.intent.preparation),
    preparationOperationId: id(823),
    preparationApprovalId: id(824),
    expectedRevision: '1',
    successorDigest: digest(825),
  });
  const { pendingExpiry: _old, ...root } = original.source.enrollment.source;
  void _old;
  const administrators = original.intent.preparation.administrators.map((admin, index) => ({
    principalId: admin.principalId,
    envelopeId: admin.envelopeId,
    assignmentId: admin.assignmentId,
    effect:
      index === 0
        ? { ...pendingExpiry.administrators[0].effect, proposalEnvelopeId: admin.envelopeId }
        : { state: 'ABSENT' },
  }));
  const enrollment = pendingPlatformRecoveryEnrollment.parse({
    ...original.source.enrollment,
    schemaVersion: 3,
    enrollmentId: id(826),
    validFrom: now.toISOString(),
    validUntil: new Date(now.getTime() + 120000).toISOString(),
    source: {
      ...root,
      continuation,
      activatedHandoff: {
        schemaVersion: 1,
        predecessorEnrollmentDigest: canonicalAuthorizationDigest(original.source.enrollment),
        administrators,
      },
    },
  });
  const source: PlatformRecoverySource = {
    ...original.source,
    enrollment,
    now,
    pendingExpiry: undefined,
    expiryPreparation: undefined,
    pendingReplacementId: continuation.replacementId,
    recoveryContinuation: continuation,
    continuationPreparation: structuredClone(original.intent.preparation),
  };
  const { pendingExpiry: _intentExpiry, ...oldIntent } = original.intent;
  void _intentExpiry;
  const intent: PlatformRecoveryIntent = {
    ...oldIntent,
    recoveryId: id(827),
    enrollmentId: enrollment.enrollmentId,
    enrollmentDigest: canonicalAuthorizationDigest(enrollment),
    continuation,
    completionSourceDigest: canonicalAuthorizationDigest(enrollment.source.activatedHandoff),
    validFrom: now.toISOString(),
    validUntil: new Date(now.getTime() + 60000).toISOString(),
    preparation: structuredClone(original.intent.preparation),
  };
  return { source, intent, original };
}
