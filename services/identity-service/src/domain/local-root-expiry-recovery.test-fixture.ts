import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { platformRecoveryFixture } from './platform-recovery.test-fixture.js';
import { envelopeFixtureId as id } from '../../../../packages/security-kernel/src/identity-envelope/fixture.js';
import {
  localRootExpiryRecoveryEnrollment,
  localRootExpiryRecoveryReceivingTrust,
} from '../contracts/local-root-expiry-recovery.js';
import { canonicalAuthorizationDigest } from '../contracts/authorization.js';
import { localRootExpiryRecoveryCustodyPreimage } from './local-root-expiry-recovery.js';
export function localRootExpiryRecoveryFixture() {
  const f = platformRecoveryFixture(),
    now = f.source.now;
  const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const der = publicKey.export({ format: 'der', type: 'spki' });
  const root = {
    ...f.source.root,
    platformAuthorityDigest: f.source.rootDigest,
    grantable: structuredClone(f.source.root.grantable),
  };
  root.grantable.validFromNs = (BigInt(now.getTime() - 86401000) * 1000000n).toString();
  root.grantable.validUntilNs = (BigInt(now.getTime() - 1000) * 1000000n).toString();
  const validFrom = new Date(now.getTime() - 1000).toISOString(),
    validUntil = new Date(now.getTime() + 3600000).toISOString();
  const trust = localRootExpiryRecoveryReceivingTrust.parse({
    schema: 'pc.installation.local-root-expiry-recovery-receiving-trust',
    schemaVersion: 1,
    purpose: 'pc.installation.local-root-expiry-recovery-custody.v1',
    custodyTrustId: id(450),
    participantId: root.ownerParticipantId,
    privacyDomainId: root.installationPrivacyDomainId,
    platformContextId: root.platformContextId,
    installationDigest: root.installationDigest,
    installationEnvironmentId: root.environmentId,
    profile: 'LOCAL_QA',
    algorithm: 'ES256',
    issuerKeyId: `sha256:${createHash('sha256').update(der).digest('hex')}`,
    issuerPublicKeySpkiDer: der.toString('base64'),
    issuerEpoch: '1',
    validFrom,
    validUntil,
  });
  const original = f.source.enrollment;
  const actors = {
    enrollmentId: original.enrollmentId,
    participantId: original.participantId,
    privacyDomainId: original.privacyDomainId,
    platformContextId: original.platformContextId,
    rootEpoch: original.rootEpoch,
    rootRevision: original.rootRevision,
    rootDigest: original.rootDigest,
    administratorPrincipalIds: original.administratorPrincipalIds,
    recoveryPrincipal: original.recoveryPrincipal,
    custodians: original.custodians,
    assurance: original.assurance,
  };
  const enrollment = localRootExpiryRecoveryEnrollment.parse({
    ...actors,
    schema: 'pc.identity.local-root-expiry-recovery-enrollment',
    schemaVersion: 1,
    purpose: trust.purpose,
    custodyTrustId: trust.custodyTrustId,
    custodyTrustDigest: canonicalAuthorizationDigest(trust),
    custodyIssuerKeyId: trust.issuerKeyId,
    custodyIssuerEpoch: trust.issuerEpoch,
    installationDigest: root.installationDigest,
    installationEnvironmentId: root.environmentId,
    profile: 'LOCAL_QA',
    successorValidFrom: validFrom,
    successorValidUntil: validUntil,
    validFrom,
    validUntil,
  });
  const signed = {
    document: enrollment,
    signature: sign('sha256', localRootExpiryRecoveryCustodyPreimage(enrollment), {
      key: privateKey,
      dsaEncoding: 'ieee-p1363',
    }).toString('base64url'),
  };
  return { root, trust, enrollment, signed, privateKey, now, rootRevision: f.source.rootRevision };
}
