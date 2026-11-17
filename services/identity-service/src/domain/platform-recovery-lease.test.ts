import { expect, it } from 'vitest';
import { platformRecoveryFixture } from './platform-recovery.test-fixture.js';
import {
  platformRecoveryLeaseActions,
  platformRecoveryLeasePermissions,
} from './platform-recovery-lease.js';
import { envelopeFixtureId as id } from '../../../../packages/security-kernel/src/identity-envelope/fixture.js';
it('issues no business or runtime permission and never extends the approved deadline', () => {
  const { source, intent } = platformRecoveryFixture();
  intent.preparation.successorScope.administration.actionIntentIds = [
    ...platformRecoveryLeaseActions,
    'ACT-PROVIDER_PROFILES_UPDATE_RESOURCE-V1',
  ];
  intent.preparation.successorScope.administration.resourceIds.push(id(999));
  const lease = platformRecoveryLeasePermissions(
    source.enrollment,
    intent,
    source.enrollment.administratorPrincipalIds[0],
    new Date(source.now.getTime() + 60000),
  );
  expect(lease.validUntil).toBe(intent.validUntil);
  expect(lease.actionIntentIds).not.toContain('ACT-PROVIDER_PROFILES_UPDATE_RESOURCE-V1');
  expect(lease.resourceIds).not.toContain(id(999));
  expect(lease.resourceIds).not.toContain('*');
  expect(lease.capabilityIds).toEqual([]);
  expect(lease).toMatchObject({
    onwardDelegationDepth: 0,
    makerCheckerRequired: true,
    stepUpRequired: true,
  });
});
it('fails closed when the current ceiling lacks a required handoff action', () => {
  const { source, intent } = platformRecoveryFixture();
  expect(() =>
    platformRecoveryLeasePermissions(
      source.enrollment,
      intent,
      source.enrollment.administratorPrincipalIds[0],
      source.now,
    ),
  ).toThrow();
});
it('does not grant ordinary administration to the recovery executor or custodians', () => {
  const { source, intent } = platformRecoveryFixture();
  intent.preparation.successorScope.administration.actionIntentIds = [
    ...platformRecoveryLeaseActions,
  ];
  for (const actor of [source.enrollment.recoveryPrincipal, ...source.enrollment.custodians])
    expect(() =>
      platformRecoveryLeasePermissions(source.enrollment, intent, actor.principalId, source.now),
    ).toThrow();
});
it('refuses an expired lease instead of issuing a new deadline', () => {
  const { source, intent } = platformRecoveryFixture();
  intent.preparation.successorScope.administration.actionIntentIds = [
    ...platformRecoveryLeaseActions,
  ];
  expect(() =>
    platformRecoveryLeasePermissions(
      source.enrollment,
      intent,
      source.enrollment.administratorPrincipalIds[0],
      new Date(intent.validUntil),
    ),
  ).toThrow();
});
