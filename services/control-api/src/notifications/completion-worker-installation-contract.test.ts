import { generateKeyPairSync } from 'node:crypto';
import { it, expect } from 'vitest';
import {
  signNotificationClaim,
  type NotificationCompletionWorkerProfileClaims,
} from '../../../../packages/security-kernel/src/notification-gateway/codec.js';
import { sha256 } from '../configuration/digest.js';
import {
  validateNotificationCompletionWorkerInstallation,
  validateNotificationCompletionWorkerOriginal,
} from './completion-worker-installation-contract.js';
function fixture() {
  const key = generateKeyPairSync('ec', { namedCurve: 'prime256v1' }),
    spki = key.publicKey.export({ format: 'der', type: 'spki' });
  const id = (n: number) => `01900000-0000-7000-8000-${String(n).padStart(12, '0')}`;
  const p: NotificationCompletionWorkerProfileClaims = {
    environmentId: 'test',
    participantId: id(1),
    privacyDomainId: id(2),
    profileId: id(3),
    revision: '1',
    validFromMs: 1000,
    validUntilMs: 10000,
    serviceId: 'LS-CONTROL-WORK',
    processRole: 'ROLE-CONTROL-WORKER',
    subscriptionId: 'SUB-NOTIFICATIONDELIVERYCOMPLETED-CONTROL_WORK-V1',
    principalId: id(4),
    workloadCredentialId: id(5),
    workloadEpoch: '1',
    workloadId: 'control-work',
    workloadKeyDigest: `sha256:${'1'.repeat(64)}`,
    producerTrustDigest: `sha256:${'2'.repeat(64)}`,
    maximumAttempts: 3,
    initialBackoffMs: 100,
    maximumBackoffMs: 1000,
    issuerKeyId: sha256(spki),
  };
  const signed = signNotificationClaim(
    'NotificationCompletionWorkerProfileV1',
    key.privateKey.export({ format: 'der', type: 'pkcs8' }),
    spki,
    p,
  );
  const pins = {
    environmentId: p.environmentId,
    participantId: p.participantId,
    privacyDomainId: p.privacyDomainId,
    profileId: p.profileId,
    revision: p.revision,
    serviceId: p.serviceId,
    processRole: p.processRole,
    subscriptionId: p.subscriptionId,
    principalId: p.principalId,
    workloadCredentialId: p.workloadCredentialId,
    workloadEpoch: p.workloadEpoch,
    workloadId: p.workloadId,
    workloadKeyDigest: p.workloadKeyDigest,
    producerTrustDigest: p.producerTrustDigest,
  };
  return {
    pins: {
      ...pins,
      issuerSpkiHex: spki.toString('hex'),
      signedProfileDigest: sha256(signed.cose),
    },
    signed: { payloadHex: signed.payload.toString('hex'), coseHex: signed.cose.toString('hex') },
    installationReference: 'test-installation',
  };
}
it('retains immutable original bytes, copied buffers and strict current lifetime', () => {
  const input = fixture(),
    current = validateNotificationCompletionWorkerInstallation(input, 1000),
    bytes = current.bytes;
  bytes.fill(0);
  expect(current.bytes).not.toEqual(bytes);
  expect(Object.isFrozen(current.input.pins)).toBe(true);
  expect(validateNotificationCompletionWorkerOriginal(input).installationDigest).toBe(
    current.installationDigest,
  );
  expect(() => validateNotificationCompletionWorkerInstallation(input, 10000)).toThrow();
  input.installationReference = 'changed';
  expect(current.input.installationReference).toBe('test-installation');
});
it.each([
  'subscription',
  'scope',
  'key',
  'epoch',
  'producer',
  'signature',
  'limit',
  'extra',
  'accessor',
])('rejects %s installation substitution', (cause) => {
  const input = fixture();
  if (cause === 'subscription')
    Object.assign(input.pins, {
      subscriptionId: 'SUB-NOTIFICATIONDELIVERYREQUESTED-NOTIFICATION-V1',
    });
  if (cause === 'scope') input.pins.privacyDomainId = input.pins.participantId;
  if (cause === 'key') input.pins.workloadKeyDigest = input.pins.signedProfileDigest;
  if (cause === 'epoch') input.pins.workloadEpoch = '2';
  if (cause === 'producer') input.pins.producerTrustDigest = input.pins.signedProfileDigest;
  if (cause === 'signature') input.signed.coseHex = '00';
  if (cause === 'limit') Object.assign(input.pins, { maximumAttempts: 100 });
  if (cause === 'extra') Object.assign(input, { authorized: true });
  if (cause === 'accessor')
    Object.defineProperty(input.pins, 'workloadId', {
      get() {
        throw new Error('getter invoked');
      },
      enumerable: true,
    });
  expect(() => validateNotificationCompletionWorkerInstallation(input, 2000)).toThrow(
    'Notification completion worker admission unavailable',
  );
});
