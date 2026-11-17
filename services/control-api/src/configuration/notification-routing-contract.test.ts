import { generateKeyPairSync } from 'node:crypto';
import { expect, it } from 'vitest';
import {
  evidenceKeyId,
  signNotificationClaim,
  type NotificationRoutingProfileClaims,
} from '@openpc/security-kernel';
import {
  notificationPayloadEncryptionProfileDigest,
  type NotificationPayloadBinding,
} from '../evidence/notification-payload-crypto.js';
import { sha256 } from './digest.js';
import {
  assertNotificationPayloadRouting,
  verifyInstalledNotificationRouting,
} from './notification-routing-contract.js';

const id = (n: number) => `018f0000-0000-7000-8000-${String(n).padStart(12, '0')}`;
const hash = (n: number) => sha256(Buffer.from(String(n)));
function fixture(change: Partial<NotificationRoutingProfileClaims> = {}) {
  const key = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const spki = key.publicKey.export({ format: 'der', type: 'spki' });
  const claims: NotificationRoutingProfileClaims = {
    environmentId: 'local',
    participantId: id(1),
    privacyDomainId: id(2),
    profileId: id(3),
    revision: '1',
    validFromMs: 1000,
    validUntilMs: 2000,
    sourceEvent: 'EvidenceExportCompleted',
    endpointId: id(4),
    endpointRevision: '2',
    signedChannelProfileDigest: hash(1),
    templateDigest: hash(2),
    recipientSetDigest: hash(3),
    redactionProfileDigest: hash(4),
    preferenceGeneration: '1',
    encryptionProfileDigest: notificationPayloadEncryptionProfileDigest,
    payloadKeyPolicyDigest: hash(5),
    issuerKeyId: evidenceKeyId(spki),
    ...change,
  };
  const bytes = signNotificationClaim(
    'NotificationRoutingProfileV1',
    key.privateKey.export({ format: 'der', type: 'pkcs8' }),
    spki,
    claims,
  );
  const signed = { payloadHex: bytes.payload.toString('hex'), coseHex: bytes.cose.toString('hex') };
  const trust = {
    environmentId: 'local',
    participantId: id(1),
    privacyDomainId: id(2),
    signedProfileDigest: sha256(bytes.cose),
    issuerSpkiHex: spki.toString('hex'),
  };
  const binding: NotificationPayloadBinding = {
    environmentId: 'local',
    participantId: id(1),
    privacyDomainId: id(2),
    payloadObjectId: id(5),
    objectVersion: '1',
    notificationOccurrenceRef: `urn:openpc:resource:${id(6)}`,
    routingProfileDigest: trust.signedProfileDigest,
    templateDigest: claims.templateDigest,
    recipientSetDigest: claims.recipientSetDigest,
    redactionProfileDigest: claims.redactionProfileDigest,
    preferenceGeneration: claims.preferenceGeneration,
    payloadDigest: hash(6),
    keyId: hash(7),
  };
  return { claims, signed, trust, binding };
}
it('authenticates the exact independently pinned historical route and connects payload AAD', () => {
  const f = fixture();
  const route = verifyInstalledNotificationRouting(f.trust, f.signed);
  expect(route.claims).toEqual(f.claims);
  expect(route.signedProfileDigest).toBe(f.trust.signedProfileDigest);
  expect(() => assertNotificationPayloadRouting(route, f.binding)).not.toThrow();
  // Historic validity is deliberately not current admission; no clock-based
  // helper converts this expired installation into fresh dispatch permission.
  expect(route.claims.validUntilMs).toBe(2000);
  f.trust.signedProfileDigest = hash(90);
  expect(route.signedProfileDigest).not.toBe(f.trust.signedProfileDigest);
});
it.each([
  { environmentId: 'foreign' },
  { participantId: id(11) },
  { privacyDomainId: id(12) },
  { signedProfileDigest: hash(90) },
  { issuerSpkiHex: fixture().trust.issuerSpkiHex },
  { unexpected: 'secret-canary' },
])('rejects altered installed trust without leaking inputs', (change) => {
  const f = fixture();
  expect(() => verifyInstalledNotificationRouting({ ...f.trust, ...change }, f.signed)).toThrow(
    /^Notification routing contract invalid$/u,
  );
});
it('rejects altered signed bytes, an unsupported encryption domain and extra signed fields', () => {
  const f = fixture();
  for (const signed of [
    { ...f.signed, coseHex: f.signed.coseHex.slice(2) },
    { ...f.signed, payloadHex: f.signed.payloadHex + '00' },
    { ...f.signed, secret: 'secret-canary' },
  ])
    expect(() => verifyInstalledNotificationRouting(f.trust, signed)).toThrow(
      /^Notification routing contract invalid$/u,
    );
  const unsupported = fixture({ encryptionProfileDigest: hash(91) });
  expect(() => verifyInstalledNotificationRouting(unsupported.trust, unsupported.signed)).toThrow(
    /^Notification routing contract invalid$/u,
  );
});
it.each([
  { environmentId: 'foreign' },
  { participantId: id(11) },
  { privacyDomainId: id(12) },
  { routingProfileDigest: hash(90) },
  { templateDigest: hash(90) },
  { recipientSetDigest: hash(90) },
  { redactionProfileDigest: hash(90) },
  { preferenceGeneration: '2' },
])('rejects substituted routing bindings in the payload AAD', (change) => {
  const f = fixture();
  const route = verifyInstalledNotificationRouting(f.trust, f.signed);
  expect(() => assertNotificationPayloadRouting(route, { ...f.binding, ...change })).toThrow(
    /^Notification routing contract invalid$/u,
  );
});
