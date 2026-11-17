import { expect, it } from 'vitest';
import { completionContinuationFixture } from './platform-recovery-completion.test-fixture.js';
import { assertPlatformRecoveryIntent } from './platform-recovery-policy.js';
import { assertPlatformRecoveryOperation } from './platform-recovery-operation.js';
import {
  platformRecoveryLeasePermissions,
  platformRecoveryContinuationLeaseActions,
} from './platform-recovery-lease.js';
import {
  platformRecoveryIntent,
  pendingPlatformRecoveryEnrollment,
} from '../contracts/platform-recovery.js';
import { canonicalAuthorizationDigest } from '../contracts/authorization.js';

it('preserves the prepared handoff and admits a separately signed finite completion', () => {
  const v = completionContinuationFixture();
  const before = structuredClone(v.original);
  expect(() => assertPlatformRecoveryIntent(v.intent, v.source)).not.toThrow();
  expect(platformRecoveryIntent.parse(v.intent)).toEqual(v.intent);
  expect(v.intent.preparation).toEqual(v.original.intent.preparation);
  expect(v.intent.preparation.supersedes).toBeDefined();
  expect(v.intent.continuation?.preparationDigest).toBe(
    canonicalAuthorizationDigest(v.original.intent.preparation),
  );
  expect(v.original).toEqual(before);
  const leaseIntent = structuredClone(v.intent);
  leaseIntent.preparation.successorScope.administration.actionIntentIds = [
    ...platformRecoveryContinuationLeaseActions,
  ];
  const grant = platformRecoveryLeasePermissions(
    v.source.enrollment,
    leaseIntent,
    v.intent.administratorEpochs[0]!.principalId,
    v.source.now,
  );
  expect(grant.actionIntentIds).not.toContain('ACT-APPROVAL_REQUESTS_UPDATE_RESOURCE-V1');
  expect(grant.capabilityIds).toEqual([]);
});
it.each([
  'missing digest',
  'wrong digest',
  'changed preparation',
  'changed source',
  'extra purpose',
  'extended lease',
  'expired lease',
  'missing history',
])('denies %s', (defect) => {
  const v = completionContinuationFixture();
  if (defect === 'missing digest') delete v.intent.completionSourceDigest;
  if (defect === 'wrong digest') v.intent.completionSourceDigest = 'sha256:' + 'f'.repeat(64);
  if (defect === 'changed preparation') v.intent.preparation.reason += 'changed';
  if (defect === 'changed source' && v.source.enrollment.schemaVersion === 3)
    delete v.source.enrollment.source.activatedHandoff;
  if (defect === 'extra purpose') v.intent.pendingExpiry = v.original.intent.pendingExpiry;
  if (defect === 'extended lease')
    v.intent.validUntil = new Date(v.source.now.getTime() + 10000000).toISOString();
  if (defect === 'expired lease') v.intent.validUntil = v.source.now.toISOString();
  if (defect === 'missing history')
    delete (v.source as { recoveryContinuation?: unknown }).recoveryContinuation;
  expect(() => assertPlatformRecoveryIntent(v.intent, v.source)).toThrow();
});
it.each(['ID-OP-PLATFORM-SCOPE-PREPARE', 'ID-OP-ENVELOPE-CREATE', 'ID-OP-ENVELOPE-ACTIVATE'])(
  'never repeats consumed %s',
  (operation) => {
    const v = completionContinuationFixture();
    expect(() =>
      assertPlatformRecoveryOperation(
        v.intent,
        v.source.enrollment.participantId,
        operation,
        operation.endsWith('PREPARE')
          ? v.intent.preparation.replacementId
          : v.intent.preparation.administrators[0]!.envelopeId,
        {},
      ),
    ).toThrow();
  },
);
it('rejects an unknown marker version and a second active administrator declaration', () => {
  const v = completionContinuationFixture();
  if (v.source.enrollment.schemaVersion !== 3 || !v.source.enrollment.source.activatedHandoff)
    throw Error('fixture');
  const marker = v.source.enrollment.source.activatedHandoff;
  expect(
    pendingPlatformRecoveryEnrollment.safeParse({
      ...v.source.enrollment,
      source: { ...v.source.enrollment.source, activatedHandoff: { ...marker, schemaVersion: 2 } },
    }).success,
  ).toBe(false);
  expect(
    pendingPlatformRecoveryEnrollment.safeParse({
      ...v.source.enrollment,
      source: {
        ...v.source.enrollment.source,
        activatedHandoff: {
          ...marker,
          administrators: [marker.administrators[0], marker.administrators[0]],
        },
      },
    }).success,
  ).toBe(false);
});
