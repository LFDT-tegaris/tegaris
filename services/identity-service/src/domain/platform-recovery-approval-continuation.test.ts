import { expect, it } from 'vitest';
import { pendingExpiryPlatformRecoveryFixture } from './platform-recovery.test-fixture.js';
import { canonicalAuthorizationDigest } from '../contracts/authorization.js';
import { platformRecoveryIntent } from '../contracts/platform-recovery.js';
import { assertPlatformRecoveryIntent } from './platform-recovery-policy.js';
import {
  platformRecoveryLeaseActions,
  platformRecoveryLeasePermissions,
} from './platform-recovery-lease.js';
import {
  envelopeFixtureId as id,
  envelopeFixtureDigest as digest,
} from '../../../../packages/security-kernel/src/identity-envelope/fixture.js';

function fixture() {
  const v = pendingExpiryPlatformRecoveryFixture();
  const witness = {
    schema: 'pc.identity.platform-prepare-approval-continuation' as const,
    schemaVersion: 1 as const,
    recoveryId: id(700),
    intentDigest: digest(701),
    activationOperationId: id(702),
    activationReceiptDigest: digest(703),
    candidateId: id(704),
    approvalId: id(705),
    candidateDigest: canonicalAuthorizationDigest(v.intent.preparation),
    businessKey: 'same-original-business-key',
    attempt: '1',
  };
  v.source.approvalContinuation = structuredClone(witness);
  v.source.approvalContinuationPreparation = structuredClone(v.intent.preparation);
  v.intent.approvalContinuation = structuredClone(witness);
  v.source.now = new Date(v.source.now.getTime() + 60000);
  v.intent.validFrom = v.source.now.toISOString();
  v.intent.validUntil = new Date(v.source.now.getTime() + 600000).toISOString();
  return v;
}

it('admits fresh prospective custody while retaining the original preparation deadlines and record names', () => {
  const v = fixture(),
    original = structuredClone(v.intent.preparation);
  expect(() => assertPlatformRecoveryIntent(v.intent, v.source)).not.toThrow();
  expect(v.intent.preparation).toEqual(original);
  expect(BigInt(original.administrators[0]!.usable.validFromNs)).toBeLessThan(
    BigInt(Date.parse(v.intent.validFrom)) * 1000000n,
  );
  delete v.intent.approvalContinuation;
  delete v.source.approvalContinuation;
  delete v.source.approvalContinuationPreparation;
  expect(() => assertPlatformRecoveryIntent(v.intent, v.source)).toThrow();
});

it.each([
  'unverified witness',
  'changed body',
  'changed key',
  'changed approval',
  'changed digest',
  'changed deadline',
  'changed names',
  'same case',
  'nonlocal',
])('rejects original approval continuation %s', (defect) => {
  const v = fixture();
  if (defect === 'unverified witness') delete v.source.approvalContinuation;
  if (defect === 'changed body') v.intent.preparation.reason = 'different intent';
  if (defect === 'changed key') v.intent.approvalContinuation!.businessKey = 'another-business-key';
  if (defect === 'changed approval') v.intent.approvalContinuation!.approvalId = id(999);
  if (defect === 'changed digest') v.intent.approvalContinuation!.candidateDigest = digest(999);
  if (defect === 'changed deadline')
    v.intent.preparation.administrators[0]!.usable.validUntilNs = '9999999999999999999';
  if (defect === 'changed names') v.intent.preparation.replacementId = id(999);
  if (defect === 'same case') v.intent.recoveryId = v.intent.approvalContinuation!.recoveryId;
  if (defect === 'nonlocal') v.source.localQaEnabled = false;
  expect(() => assertPlatformRecoveryIntent(v.intent, v.source)).toThrow();
});

it('does not parse an approval continuation as a standalone or Source3 purpose', () => {
  const v = fixture();
  delete v.intent.pendingExpiry;
  expect(platformRecoveryIntent.safeParse(v.intent).success).toBe(false);
});

it('adds only the declared approval-update action to a newly proven Source4 continuation, preserving the old thirteen-action lease', () => {
  const v = fixture();
  if (v.source.enrollment.schemaVersion !== 4) throw new Error('fixture purpose');
  v.intent.preparation.successorScope.administration.actionIntentIds = [
    ...platformRecoveryLeaseActions,
  ];
  for (const a of v.source.enrollment.source.originalAdministrators)
    for (const scope of [a.usable, a.grantable])
      scope.administration.actionIntentIds.push('ACT-APPROVAL_REQUESTS_UPDATE_RESOURCE-V1');
  const admin = v.source.enrollment.administratorPrincipalIds[0];
  const fresh = platformRecoveryLeasePermissions(
    v.source.enrollment,
    v.intent,
    admin,
    v.source.now,
  );
  expect(fresh.actionIntentIds).toHaveLength(14);
  expect(fresh.capabilityIds).toEqual([]);
  expect(fresh.onwardDelegationDepth).toBe(0);
  expect(fresh.validUntil).toBe(v.intent.validUntil);
  delete v.intent.approvalContinuation;
  const original = platformRecoveryLeasePermissions(
    v.source.enrollment,
    v.intent,
    admin,
    v.source.now,
  );
  expect(original.actionIntentIds).toHaveLength(13);
  expect(original.actionIntentIds).not.toContain('ACT-APPROVAL_REQUESTS_UPDATE_RESOURCE-V1');
});

it('fails closed when either original scope does not declare approval update', () => {
  const v = fixture();
  if (v.source.enrollment.schemaVersion !== 4) throw new Error('fixture purpose');
  v.intent.preparation.successorScope.administration.actionIntentIds = [
    ...platformRecoveryLeaseActions,
  ];
  const admin = v.source.enrollment.administratorPrincipalIds[0];
  for (const a of v.source.enrollment.source.originalAdministrators)
    a.grantable.administration.actionIntentIds = a.grantable.administration.actionIntentIds.filter(
      (v) => v !== 'ACT-APPROVAL_REQUESTS_UPDATE_RESOURCE-V1',
    );
  expect(() =>
    platformRecoveryLeasePermissions(v.source.enrollment, v.intent, admin, v.source.now),
  ).toThrow();
});
