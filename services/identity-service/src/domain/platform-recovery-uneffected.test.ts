import { expect, it } from 'vitest';
import { rootExpiryPlatformRecoveryFixture } from './platform-recovery.test-fixture.js';
import { rootExpiryPlatformRecoveryEnrollment } from '../contracts/platform-recovery.js';
import { canonicalAuthorizationDigest } from '../contracts/authorization.js';
import {
  envelopeFixtureId as id,
  envelopeFixtureDigest as digest,
} from '../../../../packages/security-kernel/src/identity-envelope/fixture.js';
import {
  assertUneffectedEnrollmentPermissions,
  assertUneffectedRecoverySuccessor,
  type UneffectedRootBridge,
} from './platform-recovery-uneffected.js';
import { rootExpiryTrustFixture } from './discovery-certificate-recovery.test-fixture.js';
import { discoveryCertificateRecoveryEnrollment } from '../contracts/discovery-certificate-recovery.js';

function fixture() {
  const v = rootExpiryPlatformRecoveryFixture(),
    original = structuredClone(v.source.enrollment);
  const fresh = structuredClone(original);
  fresh.enrollmentId = id(800);
  fresh.validFrom = new Date(Date.parse(original.validFrom) + 60000).toISOString();
  fresh.validUntil = new Date(Date.parse(original.validUntil) + 60000).toISOString();
  fresh.uneffectedPredecessor = {
    schema: 'pc.identity.platform-expired-uneffected-recovery',
    schemaVersion: 1,
    enrollmentId: original.enrollmentId,
    recoveryId: v.intent.recoveryId,
    intentDigest: canonicalAuthorizationDigest(v.intent),
    activationOperationId: id(801),
    activationReceiptDigest: digest(802),
    replacementId: v.intent.preparation.replacementId,
    preparationCandidateId: id(803),
    preparationDigest: canonicalAuthorizationDigest(v.intent.preparation),
    preparationOperationId: id(804),
    preparationApprovalId: id(805),
    expectedRevision: '1',
    successorDigest: digest(806),
  };
  for (const a of fresh.source.originalAdministrators)
    for (const key of ['usable', 'grantable'] as const) {
      a[key].validFromNs = (BigInt(a[key].validFromNs) + 60000000000n).toString();
      a[key].validUntilNs = (BigInt(a[key].validUntilNs) + 60000000000n).toString();
    }
  const intent = structuredClone(v.intent),
    old = structuredClone(v.intent.preparation);
  const oldNames = [
    old.replacementId,
    ...old.administrators.flatMap((a) => [a.envelopeId, a.assignmentId]),
  ];
  const newNames = [810, 811, 812, 813, 814].map(id);
  intent.supersession = {
    recoveryId: v.intent.recoveryId,
    intentDigest: canonicalAuthorizationDigest(v.intent),
    replacementId: old.replacementId,
    preparationDigest: canonicalAuthorizationDigest(old),
    preparationOperationId: id(804),
    preparationApprovalId: id(805),
    expectedRevision: '1',
    successorDigest: digest(806),
  };
  const p = intent.preparation;
  p.replacementId = newNames[0]!;
  p.supersedes = {
    replacementId: old.replacementId,
    expectedRevision: '1',
    successorDigest: digest(806),
  };
  const replace = (scope: typeof p.successorScope) => {
    scope.administration.resourceIds = scope.administration.resourceIds
      .map((name) => (oldNames.includes(name) ? newNames[oldNames.indexOf(name)]! : name))
      .sort((a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b)));
    scope.validFromNs = (BigInt(scope.validFromNs) + 60000000000n).toString();
    scope.validUntilNs = (BigInt(scope.validUntilNs) + 60000000000n).toString();
  };
  replace(p.successorScope);
  for (const [i, a] of p.administrators.entries()) {
    a.envelopeId = newNames[i * 2 + 1]!;
    a.assignmentId = newNames[i * 2 + 2]!;
    replace(a.usable);
    replace(a.grantable);
  }
  return { original, fresh, intent, old };
}
it('retains the old document and exact permissions while permitting fresh installation custody times', () => {
  const v = fixture(),
    before = structuredClone(v);
  expect(rootExpiryPlatformRecoveryEnrollment.safeParse(v.fresh).success).toBe(true);
  expect(() => assertUneffectedEnrollmentPermissions(v.fresh, v.original)).not.toThrow();
  expect(v).toEqual(before);
});
function bridgeFixture() {
  const v = fixture();
  const link = v.fresh.uneffectedPredecessor!;
  v.fresh.rootEpoch = (BigInt(v.original.rootEpoch) + 1n).toString();
  v.fresh.rootRevision = (BigInt(v.original.rootRevision) + 1n).toString();
  v.fresh.rootDigest = digest(950);
  const { recoveryId, enrollmentId, activationOperationId, receiptDigest } = v.original.source;
  v.fresh.source.ancestorReceipts = [
    { recoveryId, enrollmentId, activationOperationId, receiptDigest },
  ];
  Object.assign(v.fresh.source, {
    recoveryId: id(951),
    enrollmentId: id(952),
    activationOperationId: id(953),
    receiptDigest: digest(954),
  });
  const bridge = {
    rootEpoch: v.fresh.rootEpoch,
    rootRevision: v.fresh.rootRevision,
    rootDigest: v.fresh.rootDigest,
    receipt: {
      recoveryId: v.fresh.source.recoveryId,
      enrollmentId: v.fresh.source.enrollmentId,
      activationOperationId: v.fresh.source.activationOperationId,
      receiptDigest: v.fresh.source.receiptDigest,
    },
    pending: {
      schema: 'pc.identity.local-root-expiry-pending-witness',
      schemaVersion: 1,
      replacementId: link.replacementId,
      replacementRevision: '1',
      predecessorEpoch: v.original.rootEpoch,
      expectedRootRevision: v.original.rootRevision,
      predecessorDigest: v.original.rootDigest,
      preparationCandidateId: link.preparationCandidateId,
      preparationOperationId: link.preparationOperationId,
      preparationApprovalId: link.preparationApprovalId,
      preparationDigest: link.preparationDigest,
      preparationReceiptDigest: digest(955),
      successorDigest: link.successorDigest,
      pendingRecordDigest: digest(956),
      administrationEffectsDigest: digest(957),
      affectedTargetCount: v.old.affectedTargets.length,
      readinessDigest: digest(958),
    },
  } satisfies UneffectedRootBridge;
  Object.assign(v.intent.preparation, {
    predecessorEpoch: bridge.rootEpoch,
    expectedRootRevision: bridge.rootRevision,
    predecessorDigest: bridge.rootDigest,
  });
  return { ...v, bridge };
}
it('permits the exact next Root receipt while retaining its original ancestry and every permission', () => {
  const v = bridgeFixture(),
    before = structuredClone(v);
  expect(rootExpiryPlatformRecoveryEnrollment.safeParse(v.fresh).success).toBe(true);
  expect(() => assertUneffectedEnrollmentPermissions(v.fresh, v.original, v.bridge)).not.toThrow();
  expect(() => assertUneffectedRecoverySuccessor(v.intent, v.old, v.bridge)).not.toThrow();
  expect(v).toEqual(before);
  expect(() => assertUneffectedEnrollmentPermissions(v.fresh, v.original)).toThrow();
  expect(() => assertUneffectedRecoverySuccessor(v.intent, v.old)).toThrow();
});
it.each([
  'skipped Root',
  'Root digest',
  'pending replacement',
  'pending predecessor',
  'preparation',
  'candidate',
  'operation',
  'approval',
  'successor',
  'new receipt',
  'missing ancestry',
  'duplicate ancestry',
  'substituted ancestry',
  'role',
  'signer',
  'permissions',
])('rejects a bridged enrollment with %s', (failure) => {
  const v = bridgeFixture();
  if (failure === 'skipped Root') v.bridge.rootEpoch = '99';
  if (failure === 'Root digest') v.bridge.rootDigest = digest(999);
  if (failure === 'pending replacement') v.bridge.pending.replacementId = id(999);
  if (failure === 'pending predecessor') v.bridge.pending.predecessorDigest = digest(999);
  if (failure === 'preparation') v.bridge.pending.preparationDigest = digest(999);
  if (failure === 'candidate') v.bridge.pending.preparationCandidateId = id(999);
  if (failure === 'operation') v.bridge.pending.preparationOperationId = id(999);
  if (failure === 'approval') v.bridge.pending.preparationApprovalId = id(999);
  if (failure === 'successor') v.bridge.pending.successorDigest = digest(999);
  if (failure === 'new receipt') v.fresh.source.receiptDigest = digest(999);
  if (failure === 'missing ancestry') delete v.fresh.source.ancestorReceipts;
  if (failure === 'duplicate ancestry')
    v.fresh.source.ancestorReceipts!.push(structuredClone(v.fresh.source.ancestorReceipts![0]!));
  if (failure === 'substituted ancestry')
    v.fresh.source.ancestorReceipts![0]!.receiptDigest = digest(999);
  if (failure === 'role') v.fresh.source.originalAdministrators[0].roleDigest = digest(999);
  if (failure === 'signer') v.fresh.custodians[0].credentialId = id(999);
  if (failure === 'permissions')
    v.fresh.source.originalAdministrators[0].usable.runtime.capabilityIds.push(
      'SIGNED_TRANSACTION_SUBMISSION',
    );
  expect(() => assertUneffectedEnrollmentPermissions(v.fresh, v.original, v.bridge)).toThrow();
});
it.each(['Root header', 'actions', 'resources', 'approval', 'onward delegation'])(
  'rejects bridged successor drift in %s',
  (failure) => {
    const v = bridgeFixture(),
      p = v.intent.preparation;
    if (failure === 'Root header') p.predecessorDigest = digest(999);
    if (failure === 'actions')
      p.successorScope.administration.actionIntentIds.push('ACT-PARTICIPANTS_DELETE_RESOURCE-V1');
    if (failure === 'resources') p.administrators[0]!.usable.runtime.resourceIds.push(id(999));
    if (failure === 'approval') p.administrators[0]!.usable.makerCheckerRequired = false;
    if (failure === 'onward delegation') p.administrators[0]!.grantable.onwardDelegationDepth = 1;
    expect(() => assertUneffectedRecoverySuccessor(v.intent, v.old, v.bridge)).toThrow();
  },
);
it.each([
  'Root',
  'receipt',
  'administrator',
  'signer',
  'role',
  'action',
  'risk',
  'runtime',
  'governance',
  'delegation',
])('rejects changed %s in the fresh enrollment', (failure) => {
  const v = fixture(),
    a = v.fresh.source.originalAdministrators[0];
  if (failure === 'Root') v.fresh.rootDigest = digest(900);
  if (failure === 'receipt') v.fresh.source.receiptDigest = digest(900);
  if (failure === 'administrator') v.fresh.administratorPrincipalIds[0] = id(900);
  if (failure === 'signer') v.fresh.custodians[0].credentialId = id(900);
  if (failure === 'role') a.roleDigest = digest(900);
  if (failure === 'action')
    a.usable.administration.actionIntentIds.push('ACT-PARTICIPANTS_DELETE_RESOURCE-V1');
  if (failure === 'risk') a.grantable.administration.riskClasses.push('HIGH');
  if (failure === 'runtime') a.usable.runtime.resourceIds.push(id(900));
  if (failure === 'governance') a.usable.makerCheckerRequired = false;
  if (failure === 'delegation') a.grantable.onwardDelegationDepth = 1;
  expect(() => assertUneffectedEnrollmentPermissions(v.fresh, v.original)).toThrow();
});
it('rejects missing historical reference, self-reference, or a chained uneffected source', () => {
  const v = fixture();
  v.fresh.uneffectedPredecessor!.enrollmentId = v.fresh.enrollmentId;
  expect(rootExpiryPlatformRecoveryEnrollment.safeParse(v.fresh).success).toBe(false);
  delete v.fresh.uneffectedPredecessor;
  expect(() => assertUneffectedEnrollmentPermissions(v.fresh, v.original)).toThrow();
  const w = fixture();
  w.original.uneffectedPredecessor = structuredClone(w.fresh.uneffectedPredecessor);
  expect(() => assertUneffectedEnrollmentPermissions(w.fresh, w.original)).toThrow();
});
it('cannot turn discovery-certificate custody into administrator supersession', () => {
  const discovery = rootExpiryTrustFixture();
  expect(
    discoveryCertificateRecoveryEnrollment.safeParse({
      ...discovery.source.enrollment,
      uneffectedPredecessor: fixture().fresh.uneffectedPredecessor,
    }).success,
  ).toBe(false);
});
it('permits only the five governed name substitutions and renewed bounded time fields without mutating history', () => {
  const v = fixture(),
    before = structuredClone(v);
  expect(() => assertUneffectedRecoverySuccessor(v.intent, v.old)).not.toThrow();
  expect(v).toEqual(before);
});
it.each([
  'old identity',
  'duplicate identity',
  'missing predecessor',
  'actions',
  'risk',
  'resource',
  'runtime',
  'role',
  'administrator',
  'governance',
  'delegation',
  'reason',
  'target',
])('rejects successor drift: %s', (failure) => {
  const v = fixture(),
    p = v.intent.preparation;
  if (failure === 'old identity')
    p.administrators[0]!.envelopeId = v.old.administrators[0]!.envelopeId;
  if (failure === 'duplicate identity')
    p.administrators[0]!.assignmentId = p.administrators[0]!.envelopeId;
  if (failure === 'missing predecessor') delete p.supersedes;
  if (failure === 'actions')
    p.administrators[0]!.usable.administration.actionIntentIds.push(
      'ACT-PARTICIPANTS_DELETE_RESOURCE-V1',
    );
  if (failure === 'risk') p.successorScope.administration.riskClasses.push('HIGH');
  if (failure === 'resource') p.successorScope.administration.resourceIds.push(id(900));
  if (failure === 'runtime') p.successorScope.runtime.resourceIds.push(id(900));
  if (failure === 'role') p.administrators[0]!.roleDigest = digest(900);
  if (failure === 'administrator') p.administrators[0]!.principalId = id(900);
  if (failure === 'governance') p.administrators[0]!.usable.stepUpRequired = false;
  if (failure === 'delegation') p.successorScope.onwardDelegationDepth = 1;
  if (failure === 'reason') p.reason = 'A different recovery intent';
  if (failure === 'target') p.platformContextId = id(900);
  expect(() => assertUneffectedRecoverySuccessor(v.intent, v.old)).toThrow();
});
