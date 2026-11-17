import { expect, it } from 'vitest';
import { pendingExpiryPlatformRecoveryFixture } from './platform-recovery.test-fixture.js';
import {
  activatedPendingAdministrationExpiry,
  pendingExpiryPlatformRecoveryEnrollment,
  platformPendingAdministrationExpiry,
  platformRecoveryIntent,
} from '../contracts/platform-recovery.js';
import { canonicalAuthorizationDigest } from '../contracts/authorization.js';
import { assertPlatformRecoveryIntent } from './platform-recovery-policy.js';
import { platformRecoveryLeaseActions } from './platform-recovery-lease.js';
import {
  envelopeFixtureId as id,
  envelopeFixtureDigest as digest,
} from '../../../../packages/security-kernel/src/identity-envelope/fixture.js';

function fixture() {
  const v = pendingExpiryPlatformRecoveryFixture();
  if (v.source.enrollment.schemaVersion !== 4 || v.source.pendingExpiry?.schemaVersion !== 1)
    throw Error('fixture');
  const old = v.source.pendingExpiry;
  const first = old.administrators[0];
  if (first.effect.state !== 'APPROVED_PROPOSAL') throw Error('fixture effect');
  const witness = activatedPendingAdministrationExpiry.parse({
    ...old,
    schemaVersion: 2,
    predecessorEnrollmentDigest: digest(810),
    predecessorClosedApprovalDigest: digest(811),
    administrators: [
      {
        ...first,
        effect: {
          ...first.effect,
          state: 'ACTIVE_UNASSIGNED',
          envelopeRevision: '4',
          activationOperationId: id(812),
          activationAttemptId: id(813),
          activationEvidenceDigest: digest(814),
          activationPayloadDigest: digest(815),
        },
      },
      old.administrators[1],
    ],
  });
  v.source.enrollment = pendingExpiryPlatformRecoveryEnrollment.parse({
    ...v.source.enrollment,
    source: { ...v.source.enrollment.source, pendingExpiry: witness },
  });
  v.source.pendingExpiry = witness;
  v.intent.pendingExpiry = witness;
  v.intent.enrollmentDigest = canonicalAuthorizationDigest(v.source.enrollment);
  return v;
}

it('keeps the legacy witness strict and admits the distinct activated-unassigned witness', () => {
  const v = fixture();
  expect(platformPendingAdministrationExpiry.safeParse(v.intent.pendingExpiry).success).toBe(true);
  expect(
    platformPendingAdministrationExpiry.safeParse({ ...v.intent.pendingExpiry, schemaVersion: 1 })
      .success,
  ).toBe(false);
  const legacy = pendingExpiryPlatformRecoveryFixture();
  expect(platformPendingAdministrationExpiry.safeParse(legacy.intent.pendingExpiry).success).toBe(
    true,
  );
});

it.each([
  'missing history digest',
  'wrong active revision',
  'second active envelope',
  'unknown version',
  'extra property',
])('rejects malformed activated witness: %s', (defect) => {
  const v = fixture().intent.pendingExpiry!;
  if (v.schemaVersion !== 2) throw Error('fixture');
  const input = structuredClone(v) as unknown as Record<string, unknown>;
  if (defect === 'missing history digest') delete input.predecessorEnrollmentDigest;
  if (defect === 'wrong active revision')
    input.administrators = [
      { ...v.administrators[0], effect: { ...v.administrators[0].effect, envelopeRevision: '3' } },
      v.administrators[1],
    ];
  if (defect === 'second active envelope')
    input.administrators = [v.administrators[0], v.administrators[0]];
  if (defect === 'unknown version') input.schemaVersion = 3;
  if (defect === 'extra property') input.verified = true;
  expect(platformPendingAdministrationExpiry.safeParse(input).success).toBe(false);
});

it('permits only the existing governed successor transformation with fresh terms', () => {
  const v = fixture();
  const original = structuredClone(v.source.expiryPreparation);
  expect(() => assertPlatformRecoveryIntent(v.intent, v.source)).not.toThrow();
  expect(v.source.expiryPreparation).toEqual(original);
  expect(v.intent.preparation.replacementId).not.toBe(original!.replacementId);
  expect(v.intent.approvalContinuation).toBeUndefined();
  expect(platformRecoveryLeaseActions).not.toContain('ACT-APPROVAL_REQUESTS_UPDATE_RESOURCE-V1');
  v.intent.preparation.administrators[0]!.usable.validUntilNs = '18446744073709551615';
  expect(() => assertPlatformRecoveryIntent(v.intent, v.source)).toThrow();
});

it('rejects inherited approval continuation before it can add resume authority', () => {
  const v = fixture();
  v.intent.approvalContinuation = {
    schema: 'pc.identity.platform-prepare-approval-continuation',
    schemaVersion: 1,
    recoveryId: id(820),
    intentDigest: digest(821),
    activationOperationId: id(822),
    activationReceiptDigest: digest(823),
    candidateId: id(824),
    approvalId: id(825),
    candidateDigest: canonicalAuthorizationDigest(v.intent.preparation),
    businessKey: 'original-business-key',
    attempt: '1',
  };
  v.source.approvalContinuation = v.intent.approvalContinuation;
  v.source.approvalContinuationPreparation = v.intent.preparation;
  expect(platformRecoveryIntent.safeParse(v.intent).success).toBe(false);
  expect(() => assertPlatformRecoveryIntent(v.intent, v.source)).toThrow();
});
