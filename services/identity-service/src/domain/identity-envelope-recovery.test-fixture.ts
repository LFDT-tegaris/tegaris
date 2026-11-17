import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { canonicalAuthorizationDigest } from '../contracts/authorization.js';
import {
  identityEnvelopeRecoveryCustodyPurpose,
  identityEnvelopeRecoveryEnrollment,
  identityEnvelopeRecoveryReceivingTrust,
} from '../contracts/identity-envelope-recovery.js';
import { identityEnvelopeRecoveryCustodyPreimage } from './identity-envelope-recovery-custody.js';
import { identityEnvelopeContext } from '@openpc/security-kernel';
import { signingRotationActions } from './signing-rotation.js';

export const recoveryFixtureId = (n: number) =>
  `01990000-0000-7000-8000-${n.toString(16).padStart(12, '0')}`;

export function identityEnvelopeRecoveryFixture() {
  const key = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const publicKey = Buffer.from(key.publicKey.export({ format: 'der', type: 'spki' }));
  const now = new Date('2026-10-03T06:00:00.000Z');
  const trust = identityEnvelopeRecoveryReceivingTrust.parse({
    schema: 'pc.installation.identity-envelope-recovery-receiving-trust',
    schemaVersion: 1,
    custodyTrustId: recoveryFixtureId(1),
    participantId: recoveryFixtureId(2),
    privacyDomainId: recoveryFixtureId(3),
    platformContextId: recoveryFixtureId(5),
    installationDigest:
      'sha256:' + createHash('sha256').update('{"pins":{"profile":"local"}}').digest('hex'),
    installationEnvironmentId: 'qa-rpc-platform-a',
    profile: 'LOCAL_QA',
    purpose: identityEnvelopeRecoveryCustodyPurpose,
    algorithm: 'ES256',
    issuerKeyId: 'sha256:' + createHash('sha256').update(publicKey).digest('hex'),
    issuerPublicKeySpkiDer: publicKey.toString('base64'),
    issuerEpoch: '1',
    validFrom: '2026-10-03T05:00:00.000Z',
    validUntil: '2026-10-03T08:00:00.000Z',
  });
  const human = (n: number) => ({
    principalId: recoveryFixtureId(n),
    credentialId: recoveryFixtureId(n + 10),
    principalEpoch: '1',
    credentialEpoch: '1',
  });
  const enrollment = identityEnvelopeRecoveryEnrollment.parse({
    schema: 'pc.identity.identity-envelope-recovery-enrollment',
    schemaVersion: 1,
    purpose: identityEnvelopeRecoveryCustodyPurpose,
    enrollmentId: recoveryFixtureId(4),
    participantId: trust.participantId,
    privacyDomainId: trust.privacyDomainId,
    platformContextId: recoveryFixtureId(5),
    rootEpoch: '1',
    rootRevision: '1',
    rootDigest: 'sha256:' + '22'.repeat(32),
    custodyTrustId: trust.custodyTrustId,
    custodyTrustDigest: canonicalAuthorizationDigest(trust),
    custodyIssuerKeyId: trust.issuerKeyId,
    custodyIssuerEpoch: trust.issuerEpoch,
    installationDigest: trust.installationDigest,
    installationEnvironmentId: trust.installationEnvironmentId,
    profile: trust.profile,
    administratorPrincipalIds: [recoveryFixtureId(101), recoveryFixtureId(102)],
    recoveryPrincipal: human(103),
    custodians: [human(104), human(105)],
    issuerPrincipalId: recoveryFixtureId(194),
    issuerPrincipalEpoch: '1',
    issuerParticipantEpoch: '7',
    issuerCredentialEpoch: '1',
    issuerCredentialPublicKeyDigest: 'sha256:' + '33'.repeat(32),
    oldTrustDigest: 'sha256:' + '44'.repeat(32),
    selectionAdmissionVersion: '1',
    request: {
      actionIntentId: signingRotationActions.create,
      actionIntentDigest: 'sha256:' + '55'.repeat(32),
      secretClass: 'SECRET-SIGNING-KEY',
      signerRole: 'IDENTITY_ENVELOPE',
      purpose: identityEnvelopeContext.purpose,
      environmentId: 'local',
      workloadCredentialId: recoveryFixtureId(195),
      oldReference: 'secret://local/identity-envelope-key#1',
      oldFingerprint: 'sha256:' + '66'.repeat(32),
      newReference: 'secret://local/identity-envelope-key#2',
      reason: 'Repair stale issuer trust without general administrator authority',
    },
    validFrom: now.toISOString(),
    validUntil: '2026-10-03T07:00:00.000Z',
    assurance: 'LOCAL_QA_VIRTUAL_AUTHENTICATOR',
  });
  const signature = sign('sha256', identityEnvelopeRecoveryCustodyPreimage(enrollment), {
    key: key.privateKey,
    dsaEncoding: 'ieee-p1363',
  }).toString('base64url');
  return { now, trust, enrollment, signed: { document: enrollment, signature }, key };
}
