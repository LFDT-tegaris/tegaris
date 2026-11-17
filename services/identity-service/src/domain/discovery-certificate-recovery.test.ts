import { expect, it } from 'vitest';
import {
  discoveryCertificateRecovery,
  discoveryCertificateRotationCandidate,
  discoveryCertificateRecoveryEnrollment,
} from '../contracts/discovery-certificate-recovery.js';
import {
  assertDiscoveryCertificateRecoveryOperation,
  discoveryCertificateRecoveryAdministratorEpochs,
  assertDiscoveryCertificateRecoverySource,
  assertDiscoveryCertificateRecoveryIntent,
  discoveryCertificateRecoveryPermissions,
  discoveryCertificateRecoveryResumeActions,
} from './discovery-certificate-recovery.js';
import {
  platformRecoveryEnrollment,
  platformRecoveryIntent,
} from '../contracts/platform-recovery.js';
import { canonicalAuthorizationDigest } from '../contracts/authorization.js';
import {
  assertPlatformRecoveryCeremony,
  type PlatformRecoveryProof,
} from './platform-recovery-ceremony.js';

import {
  id,
  digest,
  publicKey,
  fixture,
  trustFixture,
  rootExpiryTrustFixture,
} from './discovery-certificate-recovery.test-fixture.js';

it('admits only the distinct local receipt source without changing original V1 bytes or purpose', () => {
  const original = trustFixture();
  const before = canonicalAuthorizationDigest(original.source.enrollment);
  const f = rootExpiryTrustFixture();
  expect(discoveryCertificateRecoveryEnrollment.parse(f.source.enrollment)).toEqual(
    f.source.enrollment,
  );
  expect(() => assertDiscoveryCertificateRecoveryIntent(f.intent, f.source)).not.toThrow();
  expect(f.source.enrollment).not.toHaveProperty('expiredReplacementId');
  expect(platformRecoveryEnrollment.safeParse(f.source.enrollment).success).toBe(false);
  expect(canonicalAuthorizationDigest(original.source.enrollment)).toBe(before);
});

it.each([
  'unknown version',
  'mixed original source',
  'duplicate receipt',
  'hardware profile',
  'wrong beneficiary',
  'missing displaced proof',
  'nonempty Root',
  'missing QA',
  'changed role',
  'uncovered action',
  'uncovered risk',
])('denies receipt discovery %s without falling back to V1', (failure) => {
  const f = rootExpiryTrustFixture();
  const source = { ...f.source };
  const changed: Record<string, unknown> = structuredClone(f.source.enrollment);
  if (failure === 'unknown version') changed.schemaVersion = 3;
  if (failure === 'mixed original source') changed.expiredReplacementId = id(999);
  if (failure === 'hardware profile') changed.assurance = 'HARDWARE_ATTESTED';
  if (failure === 'duplicate receipt' && f.source.enrollment.schemaVersion === 2)
    changed.source = {
      ...f.source.enrollment.source,
      ancestorReceipts: [f.source.enrollment.source],
    };
  if (failure === 'wrong beneficiary') changed.administratorPrincipalIds = [id(999), id(998)];
  if (
    [
      'unknown version',
      'mixed original source',
      'duplicate receipt',
      'hardware profile',
      'wrong beneficiary',
    ].includes(failure)
  ) {
    expect(discoveryCertificateRecoveryEnrollment.safeParse(changed).success).toBe(false);
    return;
  }
  if (failure === 'missing displaced proof') source.originalAdministrationDisplaced = false;
  if (failure === 'nonempty Root') source.rootAdministrationEmpty = false;
  if (failure === 'missing QA') source.localQaEnabled = false;
  if (failure === 'changed role') f.source.administrators[0].roleDigest = digest(999);
  if (f.source.enrollment.schemaVersion === 2) {
    if (failure === 'uncovered action')
      f.source.enrollment.source.originalAdministrators[0].grantable.administration.actionIntentIds =
        [];
    if (failure === 'uncovered risk')
      f.source.enrollment.source.originalAdministrators[0].grantable.administration.riskClasses =
        [];
  }
  expect(() => assertDiscoveryCertificateRecoveryIntent(f.intent, source)).toThrow();
});

it('uses separate immutable enrollment and intent schemas rejected by the old handoff purpose', () => {
  const f = trustFixture();
  expect(discoveryCertificateRecoveryEnrollment.safeParse(f.source.enrollment).success).toBe(true);
  expect(platformRecoveryEnrollment.safeParse(f.source.enrollment).success).toBe(false);
  expect(platformRecoveryIntent.safeParse(f.intent).success).toBe(false);
  expect(() => assertDiscoveryCertificateRecoveryIntent(f.intent, f.source)).not.toThrow();
  expect(f.original.source.enrollment).not.toHaveProperty('certificateRecovery');
  expect(f.intent).not.toHaveProperty('preparation');
});

it('requires fresh independent custody bound to the new purpose and rejects handoff-proof substitution', () => {
  const f = trustFixture();
  const enrollment = f.source.enrollment;
  const proofs: PlatformRecoveryProof[] = [
    enrollment.recoveryPrincipal,
    ...enrollment.custodians,
  ].map((signer, index) => ({
    ...signer,
    proofId: id(600 + index),
    sessionId: id(700 + index),
    sessionEpoch: '1',
    phase: index === 0 ? 'REQUEST' : 'APPROVE',
    intentDigest: canonicalAuthorizationDigest(f.intent),
    verifiedAt: f.source.now,
  }));
  expect(() =>
    assertPlatformRecoveryCeremony(
      enrollment,
      f.intent,
      'REQUESTED',
      proofs,
      'ACTIVATE',
      enrollment.recoveryPrincipal.principalId,
      f.source.now,
    ),
  ).not.toThrow();
  expect(() =>
    assertPlatformRecoveryCeremony(
      enrollment,
      f.original.intent,
      'REQUESTED',
      proofs,
      'ACTIVATE',
      enrollment.recoveryPrincipal.principalId,
      f.source.now,
    ),
  ).toThrow();
  expect(() =>
    assertPlatformRecoveryCeremony(
      enrollment,
      f.intent,
      'REQUESTED',
      proofs.slice(0, 2),
      'ACTIVATE',
      enrollment.recoveryPrincipal.principalId,
      f.source.now,
    ),
  ).toThrow();
  expect(() =>
    assertPlatformRecoveryCeremony(
      enrollment,
      f.intent,
      'REQUESTED',
      proofs,
      'ACTIVATE',
      enrollment.administratorPrincipalIds[0],
      f.source.now,
    ),
  ).toThrow();
  expect(() =>
    assertPlatformRecoveryCeremony(
      enrollment,
      f.intent,
      'REQUESTED',
      proofs,
      'ACTIVATE',
      enrollment.recoveryPrincipal.principalId,
      new Date(f.source.now.getTime() + 300000),
    ),
  ).toThrow();
  const changed = structuredClone(f.intent);
  changed.certificateRecovery.successorCredentialId = id(999);
  expect(() =>
    assertPlatformRecoveryCeremony(
      enrollment,
      changed,
      'REQUESTED',
      proofs,
      'ACTIVATE',
      enrollment.recoveryPrincipal.principalId,
      f.source.now,
    ),
  ).toThrow();
});

it.each([
  ['revoked enrollment', { enrollmentState: 'REVOKED' }],
  ['terminal Root', { rootState: 'TERMINATED' }],
  ['foreign Root owner', { rootOwnerParticipantId: id(99) }],
  ['foreign Root privacy', { rootPrivacyDomainId: id(99) }],
  ['different Root', { platformContextId: id(99) }],
  ['stale Root epoch', { rootEpoch: '3' }],
  ['stale Root revision', { rootRevision: '3' }],
  ['different Root digest', { rootDigest: digest(99) }],
  ['stale enrollment revision', { enrollmentRevision: '2' }],
  ['existing administrator authority', { administrationExpired: false }],
  ['QA trust in normal runtime', { localQaEnabled: false }],
  ['expired Root', { rootValidUntil: new Date('2026-10-02T06:00:00.000Z') }],
  ['not yet valid Root', { rootValidFrom: new Date('2026-10-02T06:00:01.000Z') }],
  ['expired intent', { now: new Date('2026-10-02T06:15:00.000Z') }],
])('denies %s at the trusted purpose boundary', (_name, change) => {
  const f = trustFixture();
  expect(() =>
    assertDiscoveryCertificateRecoveryIntent(f.intent, { ...f.source, ...change }),
  ).toThrow();
});

it('rejects changes to the enrolled replacement or actual administrator epochs/role', () => {
  const f = trustFixture();
  expect(() =>
    assertDiscoveryCertificateRecoveryIntent(
      {
        ...f.intent,
        certificateRecovery: { ...f.intent.certificateRecovery, successorCredentialId: id(99) },
      },
      f.source,
    ),
  ).toThrow();
  const changed = structuredClone(f.intent);
  changed.administrators[0].principalEpoch = '4';
  expect(() => assertDiscoveryCertificateRecoveryIntent(changed, f.source)).toThrow();
  changed.administrators[0].principalEpoch = '3';
  changed.administrators[0].roleDigest = digest(99);
  expect(() => assertDiscoveryCertificateRecoveryIntent(changed, f.source)).toThrow();
});

it('admits only an expired active transport credential for its exact target and stored identities', () => {
  const f = fixture();
  expect(() => assertDiscoveryCertificateRecoverySource(f.binding, f.source)).not.toThrow();
  const candidate = discoveryCertificateRotationCandidate(f.binding);
  expect(candidate).toEqual({
    replacedCredentialId: id(12),
    credentialId: id(13),
    publicKeySpkiDer: publicKey.toString('base64'),
  });
  expect(() =>
    assertDiscoveryCertificateRecoveryOperation(
      f.binding,
      'ID-OP-WORKLOAD-ROTATE',
      id(12),
      '1',
      candidate,
    ),
  ).not.toThrow();
});

it.each([
  ['terminal Participant', { participantState: 'ARCHIVED' }],
  ['suspended privacy', { privacyState: 'SUSPENDED' }],
  ['foreign target Participant', { targetParticipantId: id(99) }],
  ['foreign target privacy', { targetPrivacyDomainId: id(99) }],
  ['different target', { targetId: id(99) }],
  ['changed target revision', { targetRevision: '43' }],
  ['unauthenticated discovery', { requiresAuthenticatedDiscovery: false }],
  ['different workload principal', { workloadPrincipalId: id(99) }],
  ['foreign workload principal', { workloadPrincipalParticipantId: id(99) }],
  ['suspended workload', { workloadPrincipalState: 'SUSPENDED' }],
  ['human principal', { workloadPrincipalKind: 'USER' }],
  ['changed workload epoch', { workloadPrincipalEpoch: '3' }],
  ['foreign credential', { credentialParticipantId: id(99) }],
  ['different credential', { credentialId: id(99) }],
  ['different credential owner', { credentialPrincipalId: id(99) }],
  ['revoked credential', { credentialState: 'REVOKED' }],
  ['rotating credential', { credentialState: 'ROTATING' }],
  ['human credential', { credentialKind: 'WEBAUTHN' }],
  ['changed credential revision', { credentialRevision: '2' }],
  ['changed credential epoch', { credentialEpoch: '3' }],
  ['different certificate', { certificateFingerprint: digest(3) }],
  ['corrupt stored certificate', { certificateBytesDigest: digest(3) }],
  ['different predecessor key', { publicKeyDigest: digest(3) }],
  ['corrupt stored public key', { publicKeyBytesDigest: digest(3) }],
  ['different issuer', { issuer: 'other-issuer' }],
  ['different SAN', { subject: 'foreign' }],
  ['different audience', { audience: 'foreign' }],
  ['changed signed expiry', { notAfter: new Date('2026-10-02T01:00:01.000Z') }],
  ['not yet expired', { now: new Date('2026-10-02T00:59:59.000Z') }],
  ['invalid clock', { now: new Date(NaN) }],
  ['invalid certificate time', { notBefore: new Date(NaN) }],
  ['competing successor', { competingSuccessor: true }],
  ['already installed successor', { successorExists: true }],
])('denies %s without converting expiry recovery into other authority', (_name, change) => {
  const f = fixture();
  expect(() =>
    assertDiscoveryCertificateRecoverySource(f.binding, { ...f.source, ...change }),
  ).toThrow();
});

it.each([
  'ID-OP-WORKLOAD-ISSUE',
  'ID-OP-PLATFORM-SCOPE-PREPARE',
  'ID-OP-ENVELOPE-CREATE',
  'ID-OP-ASSIGNMENT-CREATE',
  'ID-OP-PROVIDER-QUALIFY',
])('denies unrelated operation %s', (operation) => {
  const f = fixture();
  expect(() =>
    assertDiscoveryCertificateRecoveryOperation(
      f.binding,
      operation,
      id(12),
      '1',
      discoveryCertificateRotationCandidate(f.binding),
    ),
  ).toThrow();
});

it.each([
  ['different resource', id(99), '1', {}],
  ['stale revision', id(12), '2', {}],
  ['different predecessor', id(12), '1', { replacedCredentialId: id(99) }],
  ['different successor', id(12), '1', { credentialId: id(99) }],
  ['different key', id(12), '1', { publicKeySpkiDer: 'other' }],
  ['additional caller authority', id(12), '1', { bypass: true }],
])('denies %s in the mutation candidate', (_name, resource, revision, change) => {
  const f = fixture();
  expect(() =>
    assertDiscoveryCertificateRecoveryOperation(
      f.binding,
      'ID-OP-WORKLOAD-ROTATE',
      resource,
      revision,
      { ...discoveryCertificateRotationCandidate(f.binding), ...change },
    ),
  ).toThrow();
});

it('keeps the lease finite, with no collection permission, runtime capability or handoff permission', () => {
  const f = fixture();
  const permissions = discoveryCertificateRecoveryPermissions(f.binding, id(2), id(20));
  expect(permissions.capabilityIds).toEqual([]);
  expect(permissions.onwardDelegationDepth).toBe(0);
  expect(permissions.resourceIds).not.toContain('*');
  expect(permissions.resourceIds).not.toContain(id(21));
  expect(permissions.actionIntentIds).not.toContain('ACT-APPROVAL_REQUESTS_READ_COLLECTION-V1');
  expect(permissions.actionIntentIds).not.toContain('ACT-PARTICIPANT_CREATE_MEMBER-V1');
  expect(permissions.actionIntentIds).not.toContain('ACT-PARTICIPANT_ACTIVATE_CONTEXT-V1');
  expect(permissions).toMatchObject({ makerCheckerRequired: true, stepUpRequired: true });
});

it('rejects malformed, noncanonical, misbound or aliased public-key bindings', () => {
  const f = fixture();
  for (const change of [
    { successorPublicKeySpkiDer: Buffer.from('invalid-SPKI').toString('base64') },
    { successorPublicKeySpkiDer: f.binding.successorPublicKeySpkiDer + '\n' },
    { successorPublicKeyDigest: digest(9) },
    { successorCredentialId: f.binding.predecessorCredentialId },
    { purpose: 'PLATFORM_HANDOFF' },
    { runtimeCapabilityIds: ['forged'] },
  ])
    expect(discoveryCertificateRecovery.safeParse({ ...f.binding, ...change }).success).toBe(false);
});

it('rechecks a frozen administrator epoch against exactly one durable activation increment', () => {
  const f = trustFixture();
  const current = structuredClone(f.intent.administrators);
  current.forEach((v) => (v.principalEpoch = '4'));
  const bindings = current.map((v) => ({
    principalId: v.principalId,
    principalEpoch: v.principalEpoch,
  }));
  expect(
    discoveryCertificateRecoveryAdministratorEpochs(current, f.intent, 'ACTIVE', bindings),
  ).toEqual(f.intent.administrators);
  for (const bad of [
    null,
    bindings.slice(0, 1),
    [bindings[0]!, bindings[0]!],
    bindings.map((v) => ({ ...v, principalEpoch: '5' })),
  ])
    expect(() =>
      discoveryCertificateRecoveryAdministratorEpochs(current, f.intent, 'ACTIVE', bad),
    ).toThrow();
  expect(() =>
    discoveryCertificateRecoveryAdministratorEpochs(current, f.intent, 'REQUESTED', null),
  ).toThrow();
  const changed = structuredClone(current);
  changed[0].roleDigest = digest(99);
  expect(() =>
    discoveryCertificateRecoveryAdministratorEpochs(changed, f.intent, 'ACTIVE', bindings),
  ).toThrow();
  changed[0].roleDigest = current[0].roleDigest;
  changed[0].riskClasses = ['LOW'];
  expect(() =>
    discoveryCertificateRecoveryAdministratorEpochs(changed, f.intent, 'ACTIVE', bindings),
  ).toThrow();
});

it('keeps original ten-action intent bytes and separately qualifies eleven-action resume custody', () => {
  const original = rootExpiryTrustFixture();
  const originalDigest = canonicalAuthorizationDigest(original.intent);
  expect(
    discoveryCertificateRecoveryPermissions(
      original.intent.certificateRecovery,
      original.source.enrollment.privacyDomainId,
      original.intent.administrators[0].principalId,
    ).actionIntentIds,
  ).toHaveLength(10);
  const next = structuredClone(original);
  next.intent.schemaVersion = 2;
  expect(() => assertDiscoveryCertificateRecoveryIntent(next.intent, next.source)).toThrow();
  if (next.source.enrollment.schemaVersion !== 2)
    throw new Error('Receipt source fixture required');
  for (const administrator of next.source.enrollment.source.originalAdministrators)
    for (const scope of [administrator.usable, administrator.grantable])
      scope.administration.actionIntentIds = [...discoveryCertificateRecoveryResumeActions];
  next.intent.enrollmentDigest = canonicalAuthorizationDigest(next.source.enrollment);
  expect(() => assertDiscoveryCertificateRecoveryIntent(next.intent, next.source)).not.toThrow();
  expect(
    discoveryCertificateRecoveryPermissions(
      next.intent.certificateRecovery,
      next.source.enrollment.privacyDomainId,
      next.intent.administrators[0].principalId,
      2,
    ).actionIntentIds,
  ).toEqual(discoveryCertificateRecoveryResumeActions);
  expect(canonicalAuthorizationDigest(original.intent)).toBe(originalDigest);
  next.source.enrollment.source.originalAdministrators[1].grantable.administration.actionIntentIds.pop();
  next.intent.enrollmentDigest = canonicalAuthorizationDigest(next.source.enrollment);
  expect(() => assertDiscoveryCertificateRecoveryIntent(next.intent, next.source)).toThrow();
});
