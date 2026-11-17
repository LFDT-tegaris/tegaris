import { createHash, generateKeyPairSync } from 'node:crypto';
import type {
  DiscoveryCertificateRecovery,
  DiscoveryCertificateRecoveryEnrollment,
  DiscoveryCertificateRecoveryIntent,
} from '../contracts/discovery-certificate-recovery.js';
import type {
  DiscoveryCertificateRecoverySource,
  DiscoveryCertificateRecoveryTrustSource,
} from './discovery-certificate-recovery.js';
import {
  platformRecoveryFixture,
  rootExpiryPlatformRecoveryFixture,
} from './platform-recovery.test-fixture.js';
import { canonicalAuthorizationDigest } from '../contracts/authorization.js';
import { discoveryCertificateRecoveryPermissions } from './discovery-certificate-recovery.js';

export const id = (n: number) => `018f0000-0000-7000-8000-${n.toString().padStart(12, '0')}`;
export const digest = (n: number) => `sha256:${n.toString(16).padStart(64, '0')}`;
export const publicKey = Buffer.from(
  generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).publicKey.export({
    format: 'der',
    type: 'spki',
  }),
);

/** Mocked authoritative facts only. No database, enrollment or business state is created. */
export function fixture() {
  const binding: DiscoveryCertificateRecovery = {
    purpose: 'DISCOVERY_CERTIFICATE_REPLACEMENT',
    targetId: id(10),
    targetRevision: '42',
    workloadPrincipalId: id(11),
    workloadPrincipalEpoch: '2',
    predecessorCredentialId: id(12),
    predecessorRevision: '1',
    predecessorEpoch: '2',
    predecessorFingerprint: digest(1),
    predecessorPublicKeyDigest: digest(2),
    predecessorNotAfter: '2026-10-02T01:00:00.000Z',
    issuer: 'unit-issuer',
    successorCredentialId: id(13),
    successorPublicKeySpkiDer: publicKey.toString('base64'),
    successorPublicKeyDigest: `sha256:${createHash('sha256').update(publicKey).digest('hex')}`,
  };
  const source: DiscoveryCertificateRecoverySource = {
    participantId: id(1),
    privacyDomainId: id(2),
    participantState: 'ACTIVE',
    privacyState: 'ACTIVE',
    targetId: id(10),
    targetParticipantId: id(1),
    targetPrivacyDomainId: id(2),
    targetRevision: '42',
    requiresAuthenticatedDiscovery: true,
    workloadPrincipalId: id(11),
    workloadPrincipalParticipantId: id(1),
    workloadPrincipalState: 'ACTIVE',
    workloadPrincipalKind: 'WORKLOAD',
    workloadPrincipalEpoch: '2',
    credentialId: id(12),
    credentialParticipantId: id(1),
    credentialPrincipalId: id(11),
    credentialState: 'ACTIVE',
    credentialKind: 'WORKLOAD_MTLS',
    credentialRevision: '1',
    credentialEpoch: '2',
    certificateFingerprint: digest(1),
    certificateBytesDigest: digest(1),
    publicKeyDigest: digest(2),
    publicKeyBytesDigest: digest(2),
    issuer: 'unit-issuer',
    subject: `urn:openpc:participant:${id(1)}:workload:${id(10)}`,
    audience: `urn:openpc:workload:${id(10)}`,
    notBefore: new Date('2026-10-01T01:00:00.000Z'),
    notAfter: new Date(binding.predecessorNotAfter),
    competingSuccessor: false,
    successorExists: false,
    now: new Date('2026-10-02T06:00:00.000Z'),
  };
  return { binding, source };
}

export function trustFixture() {
  const f = fixture();
  const original = platformRecoveryFixture();
  const enrollment: DiscoveryCertificateRecoveryEnrollment = {
    ...original.source.enrollment,
    schema: 'pc.identity.discovery-certificate-recovery-enrollment',
    validFrom: new Date(f.source.now.getTime() - 60000).toISOString(),
    validUntil: new Date(f.source.now.getTime() + 3600000).toISOString(),
    certificateRecovery: f.binding,
  };
  const administrators: DiscoveryCertificateRecoveryIntent['administrators'] = [
    {
      principalId: enrollment.administratorPrincipalIds[0],
      principalEpoch: '3',
      roleId: id(400),
      roleRevision: '1',
      roleDigest: digest(400),
      riskClasses: ['HIGH'],
    },
    {
      principalId: enrollment.administratorPrincipalIds[1],
      principalEpoch: '3',
      roleId: id(400),
      roleRevision: '1',
      roleDigest: digest(400),
      riskClasses: ['HIGH'],
    },
  ];
  const intent: DiscoveryCertificateRecoveryIntent = {
    schema: 'pc.identity.discovery-certificate-recovery-intent',
    schemaVersion: 1,
    recoveryId: id(500),
    enrollmentId: enrollment.enrollmentId,
    enrollmentRevision: '1',
    enrollmentDigest: canonicalAuthorizationDigest(enrollment),
    certificateRecovery: f.binding,
    administrators,
    validFrom: f.source.now.toISOString(),
    validUntil: new Date(f.source.now.getTime() + 900000).toISOString(),
    lifetimes: { profile: 'C17', leaseMs: 900000, administratorMs: 3600000 },
  };
  const source: DiscoveryCertificateRecoveryTrustSource = {
    enrollment,
    enrollmentState: 'ACTIVE',
    enrollmentRevision: '1',
    rootState: 'ACTIVE',
    platformContextId: enrollment.platformContextId,
    rootOwnerParticipantId: enrollment.participantId,
    rootPrivacyDomainId: enrollment.privacyDomainId,
    rootEpoch: enrollment.rootEpoch,
    rootRevision: enrollment.rootRevision,
    rootDigest: enrollment.rootDigest,
    rootValidFrom: new Date(enrollment.validFrom),
    rootValidUntil: new Date(enrollment.validUntil),
    administrationExpired: true,
    administrators,
    localQaEnabled: true,
    now: f.source.now,
  };
  return { source, intent, original };
}

/** Mocked receipt-source facts; not an installed receipt or recovery lease. */
export function rootExpiryTrustFixture() {
  const f = trustFixture();
  const original = rootExpiryPlatformRecoveryFixture();
  const enrollment: DiscoveryCertificateRecoveryEnrollment = {
    ...original.source.enrollment,
    schema: 'pc.identity.discovery-certificate-recovery-enrollment',
    assurance: 'LOCAL_QA_VIRTUAL_AUTHENTICATOR',
    certificateRecovery: f.intent.certificateRecovery,
  };
  for (const declared of enrollment.source.originalAdministrators)
    for (const scope of [declared.usable, declared.grantable])
      scope.administration.actionIntentIds = discoveryCertificateRecoveryPermissions(
        enrollment.certificateRecovery,
        enrollment.privacyDomainId,
        declared.principalId,
      ).actionIntentIds;
  const administrators = enrollment.source.originalAdministrators.map((v, index) => ({
    ...f.intent.administrators[index]!,
    roleId: v.roleId,
    roleRevision: v.expectedRoleRevision,
    roleDigest: v.roleDigest,
    riskClasses: v.usable.administration.riskClasses,
  })) as DiscoveryCertificateRecoveryIntent['administrators'];
  const source: DiscoveryCertificateRecoveryTrustSource = {
    ...f.source,
    enrollment,
    administrationExpired: false,
    originalAdministrationDisplaced: true,
    rootAdministrationEmpty: true,
    administrators,
    now: original.source.now,
    rootValidFrom: new Date(Number(BigInt(original.source.root.grantable.validFromNs) / 1000000n)),
    rootValidUntil: new Date(
      Number(BigInt(original.source.root.grantable.validUntilNs) / 1000000n),
    ),
  };
  const intent = {
    ...f.intent,
    enrollmentDigest: canonicalAuthorizationDigest(enrollment),
    administrators,
    validFrom: source.now.toISOString(),
    validUntil: new Date(source.now.getTime() + 900000).toISOString(),
  };
  return { source, intent, original };
}
