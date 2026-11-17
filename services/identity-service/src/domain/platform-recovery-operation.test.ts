import { expect, it } from 'vitest';
import { platformRecoveryFixture } from './platform-recovery.test-fixture.js';
import { assertPlatformRecoveryOperation } from './platform-recovery-operation.js';
import { envelopeFixtureId as id } from '../../../../packages/security-kernel/src/identity-envelope/fixture.js';

it('allows only the exact reviewed preparation', () => {
  const { source, intent } = platformRecoveryFixture();
  expect(() =>
    assertPlatformRecoveryOperation(
      intent,
      source.enrollment.participantId,
      'ID-OP-PLATFORM-SCOPE-PREPARE',
      intent.preparation.replacementId,
      intent.preparation,
    ),
  ).not.toThrow();
  expect(() =>
    assertPlatformRecoveryOperation(
      intent,
      source.enrollment.participantId,
      'ID-OP-PLATFORM-SCOPE-PREPARE',
      intent.preparation.replacementId,
      { ...intent.preparation, reason: 'changed after custodian approval' },
    ),
  ).toThrow();
});
it('bounds normal envelope issuance to the two exact reviewed scopes and identifiers', () => {
  const { source, intent } = platformRecoveryFixture();
  const administrator = intent.preparation.administrators[0]!;
  const candidate = {
    schema: 'pc.identity.authority-envelope-proposal',
    schemaVersion: 1,
    id: administrator.envelopeId,
    envelopeId: administrator.envelopeId,
    participantId: source.enrollment.participantId,
    state: 'DRAFT',
    issuance: 'PLATFORM_ROOT',
    platformScopeReplacementId: intent.preparation.replacementId,
    usable: administrator.usable,
    grantable: administrator.grantable,
  };
  expect(() =>
    assertPlatformRecoveryOperation(
      intent,
      source.enrollment.participantId,
      'ID-OP-ENVELOPE-CREATE',
      administrator.envelopeId,
      candidate,
    ),
  ).not.toThrow();
  for (const changed of [
    { ...candidate, issuance: 'CHILD' },
    { ...candidate, participantId: id(999) },
    { ...candidate, platformScopeReplacementId: id(999) },
    { ...candidate, grantable: { ...candidate.grantable, validUntilNs: '2051222400000000000' } },
  ])
    expect(() =>
      assertPlatformRecoveryOperation(
        intent,
        source.enrollment.participantId,
        'ID-OP-ENVELOPE-CREATE',
        administrator.envelopeId,
        changed,
      ),
    ).toThrow();
});
it.each([
  'ID-OP-PROVIDER-QUALIFY',
  'ID-OP-POLICY-CREATE',
  'ID-OP-ROLE-CREATE',
  'ID-OP-RECOVERY-COMPLETE',
  'ID-OP-ASSIGNMENT-REVOKE',
  'unregistered',
])('denies business or unrelated operation %s', (operation) => {
  const { source, intent } = platformRecoveryFixture();
  expect(() =>
    assertPlatformRecoveryOperation(
      intent,
      source.enrollment.participantId,
      operation,
      intent.preparation.replacementId,
      {},
    ),
  ).toThrow();
});
it('refuses activation of any envelope outside the reviewed handoff', () => {
  const { source, intent } = platformRecoveryFixture();
  const envelopeId = intent.preparation.administrators[0]!.envelopeId;
  expect(() =>
    assertPlatformRecoveryOperation(
      intent,
      source.enrollment.participantId,
      'ID-OP-ENVELOPE-ACTIVATE',
      envelopeId,
      { envelopeId },
    ),
  ).not.toThrow();
  expect(() =>
    assertPlatformRecoveryOperation(
      intent,
      source.enrollment.participantId,
      'ID-OP-ENVELOPE-ACTIVATE',
      id(999),
      { envelopeId: id(999) },
    ),
  ).toThrow();
});

function assignmentFixture() {
  const { source, intent } = platformRecoveryFixture();
  const administrator = intent.preparation.administrators[0]!;
  const scope = administrator.usable;
  const value = {
    id: administrator.assignmentId,
    assignmentId: administrator.assignmentId,
    participantId: source.enrollment.participantId,
    principalId: administrator.principalId,
    authorityEnvelopeId: administrator.envelopeId,
    roleId: `urn:openpc:role:${administrator.roleId}`,
    scopeDigest: 'sha256:' + 'a'.repeat(64),
    state: 'ACTIVE',
    delegationEpoch: '0',
    privacyDomainIds: scope.administration.privacyDomainIds,
    actionIntentIds: scope.administration.actionIntentIds,
    resourceIds: scope.administration.resourceIds,
    riskClasses: scope.administration.riskClasses,
    capabilityIds: [],
    validFrom: new Date(Number(BigInt(scope.validFromNs) / 1000000n)).toISOString(),
    validUntil: new Date(Number(BigInt(scope.validUntilNs) / 1000000n)).toISOString(),
    makerCheckerRequired: true,
    stepUpRequired: true,
    onwardDelegationDepth: 0,
  };
  return { source, intent, administrator, value };
}
it('admits the exact recipient assignment under the already reviewed role and scope', () => {
  const v = assignmentFixture();
  expect(() =>
    assertPlatformRecoveryOperation(
      v.intent,
      v.source.enrollment.participantId,
      'ID-OP-ASSIGNMENT-CREATE',
      v.administrator.assignmentId,
      v.value,
    ),
  ).not.toThrow();
});
it.each([
  ['recipient', { principalId: id(999) }],
  ['envelope', { authorityEnvelopeId: id(999) }],
  ['role', { roleId: `urn:openpc:platform:${id(999)}` }],
  ['role namespace', { roleId: `urn:openpc:platform:${id(400)}` }],
  ['group', { groupId: id(999) }],
  ['resource wildcard', { resourceIds: ['*'] }],
  ['runtime capability', { capabilityIds: [id(999)] }],
  ['governance', { makerCheckerRequired: false }],
  ['step-up', { stepUpRequired: false }],
  ['delegation', { onwardDelegationDepth: 1 }],
  ['window', { validUntil: '2035-01-01T00:00:00.000Z' }],
])('denies assignment widening through %s', (_name, changed) => {
  const v = assignmentFixture();
  expect(() =>
    assertPlatformRecoveryOperation(
      v.intent,
      v.source.enrollment.participantId,
      'ID-OP-ASSIGNMENT-CREATE',
      v.administrator.assignmentId,
      { ...v.value, ...changed },
    ),
  ).toThrow();
});
