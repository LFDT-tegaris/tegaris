import { createHash, generateKeyPairSync } from 'node:crypto';
import { it, expect } from 'vitest';
import { evidenceKeyId } from '../business-transition/cose.js';
import { signNotificationClaim, type NotificationCompletionWorkerProfileClaims } from './codec.js';
import {
  verifyInstalledNotificationCompletionWorkerProfile,
  verifyNotificationCompletionWorkerProfileOriginal,
  notificationCompletionConsumerBackoff,
} from './completion-worker-contract.js';
const id = (n: number) => `01900000-0000-7000-8000-${String(n).padStart(12, '0')}`;
const key = generateKeyPairSync('ec', { namedCurve: 'prime256v1' }),
  spki = key.publicKey.export({ format: 'der', type: 'spki' });
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
  maximumAttempts: 5,
  initialBackoffMs: 100,
  maximumBackoffMs: 250,
  issuerKeyId: evidenceKeyId(spki),
};
function fixture() {
  const signed = signNotificationClaim(
    'NotificationCompletionWorkerProfileV1',
    key.privateKey.export({ format: 'der', type: 'pkcs8' }),
    spki,
    p,
  );
  return {
    signed,
    pins: {
      ...p,
      issuerSpki: spki,
      signedProfileDigest: `sha256:${createHash('sha256').update(signed.cose).digest('hex')}`,
    },
  };
}
it('verifies original signatures independently of present expiry and never renews them', () => {
  const { signed, pins } = fixture();
  expect(
    verifyInstalledNotificationCompletionWorkerProfile(pins, signed.payload, signed.cose, 1000),
  ).toEqual(p);
  for (const now of [999, 10000, Infinity, NaN, 1000.5, -0])
    expect(() =>
      verifyInstalledNotificationCompletionWorkerProfile(pins, signed.payload, signed.cose, now),
    ).toThrow();
  expect(
    verifyNotificationCompletionWorkerProfileOriginal(pins, signed.payload, signed.cose),
  ).toEqual(p);
});
it.each([
  'participantId',
  'privacyDomainId',
  'profileId',
  'revision',
  'principalId',
  'workloadCredentialId',
  'workloadEpoch',
  'workloadId',
  'workloadKeyDigest',
  'producerTrustDigest',
  'signedProfileDigest',
] as const)('rejects detached installed %s', (name) => {
  const { signed, pins } = fixture();
  expect(() =>
    verifyNotificationCompletionWorkerProfileOriginal(
      { ...pins, [name]: 'different' },
      signed.payload,
      signed.cose,
    ),
  ).toThrow();
});
it('uses first-attempt-inclusive capped exponential consumer retry without granting quarantine', () => {
  expect([1, 2, 3, 4, 5, 6].map((n) => notificationCompletionConsumerBackoff(p, n))).toEqual([
    100,
    200,
    250,
    250,
    null,
    null,
  ]);
  expect(notificationCompletionConsumerBackoff({ ...p, maximumAttempts: 1 }, 1)).toBeNull();
  for (const n of [0, -1, 1.5, NaN, Infinity])
    expect(() => notificationCompletionConsumerBackoff(p, n)).toThrow();
});
it('rejects changed signed limits and wrong key without a fallback verifier', () => {
  const { signed, pins } = fixture();
  const changed = Buffer.from(signed.cose);
  changed[changed.length - 1] = changed[changed.length - 1]! ^ 1;
  expect(() =>
    verifyNotificationCompletionWorkerProfileOriginal(
      {
        ...pins,
        signedProfileDigest: `sha256:${createHash('sha256').update(changed).digest('hex')}`,
      },
      signed.payload,
      changed,
    ),
  ).toThrow();
});
