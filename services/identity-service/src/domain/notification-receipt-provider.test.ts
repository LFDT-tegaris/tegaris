import { expect, it } from 'vitest';
import { signNotificationClaim, encodeNotificationClaim } from '@openpc/security-kernel';
import { notificationReceiptProviderSample } from '../../../../tests/integration/identity/notification-receipt-provider-fixture.js';
import { sha256 } from '../../../control-api/src/configuration/digest.js';
import {
  createNotificationReceiptRequest,
  notificationReceiptRequestDigest,
  validateNotificationReceiptRequest,
  validateNotificationReceiptObservation,
  validateNotificationReceiptLookup,
  type NotificationReceiptProviderObservation,
} from './notification-receipt-provider.js';
const sample = notificationReceiptProviderSample({ nowMs: 1800000000000 });
function signed(): NotificationReceiptProviderObservation {
  return {
    schemaVersion: 1,
    providerId: sample.request.providerId,
    signingAttemptId: sample.request.signingAttemptId,
    requestDigest: notificationReceiptRequestDigest(sample.request),
    recordedAtMs: sample.claims.startedAtMs + 1,
    outcome: 'SIGNED',
    reason: null,
    coseHex: signNotificationClaim(
      'NotificationDeliveryStartedReceiptV1',
      sample.signerPrivateKey,
      Buffer.from(sample.trust.signer.publicKeySpkiHex, 'hex'),
      sample.claims,
    ).cose.toString('hex'),
  };
}
it('verifies only native profile 24021/purpose 358 with exact payload, original request and delivery subscription', () => {
  const value = signed();
  expect(validateNotificationReceiptObservation(sample.request, value, sample.trust)).toEqual(
    value,
  );
  expect(validateNotificationReceiptRequest(sample.request, sample.trust).claims).toEqual(
    sample.claims,
  );
  expect(notificationReceiptRequestDigest(sample.request)).not.toBe(sha256(sample.request));
});
it.each([
  'reference',
  'version',
  'purpose',
  'secretClass',
  'workerInstallationDigest',
  'workerProfileDigest',
  'workloadCredentialId',
  'workloadEpoch',
  'keyEpoch',
  'signerKeyId',
  'signerInstallationDigest',
  'providerId',
  'participantId',
  'privacyDomainId',
  'operationId',
  'signingAttemptId',
  'deliveryAttemptId',
] as const)('rejects original request substitution: %s', (field) => {
  expect(() =>
    validateNotificationReceiptRequest(
      {
        ...sample.request,
        [field]:
          field.endsWith('Digest') || field === 'signerKeyId'
            ? sha256('other')
            : field.endsWith('Id')
              ? '01990000-0000-7000-8000-000000000099'
              : field.includes('Epoch')
                ? '2'
                : 'other',
      },
      sample.trust,
    ),
  ).toThrow('Notification receipt signing outcome requires reconciliation');
});
it('binds payload bytes and refuses source/channel/profile/signature or provider-result substitution', () => {
  const original = signed();
  for (const patch of [
    { providerId: 'other' },
    { signingAttemptId: '01990000-0000-7000-8000-000000000099' },
    { requestDigest: sha256('other') },
    { recordedAtMs: sample.claims.deadlineAtMs },
    { recordedAtMs: sample.claims.startedAtMs - 1 },
    { coseHex: '00' },
    { privateKey: 'PRIVATE_CANARY' },
    { reason: 'REVOKED' },
  ])
    expect(() =>
      validateNotificationReceiptObservation(
        sample.request,
        { ...original, ...patch },
        sample.trust,
      ),
    ).toThrow('Notification receipt signing outcome requires reconciliation');
  const payload = encodeNotificationClaim('NotificationDeliveryStartedReceiptV1', {
    ...sample.claims,
    payloadDigest: sha256('other'),
  });
  const request = createNotificationReceiptRequest(sample.trust, {
    payloadHex: payload.toString('hex'),
    deliveryPreparationDigest: sample.request.deliveryPreparationDigest,
  });
  expect(() =>
    validateNotificationReceiptObservation(
      request,
      { ...original, requestDigest: notificationReceiptRequestDigest(request) },
      sample.trust,
    ),
  ).toThrow();
  const different = notificationReceiptProviderSample({ nowMs: sample.claims.startedAtMs });
  expect(() =>
    validateNotificationReceiptObservation(sample.request, original, different.trust),
  ).toThrow();
});
it('historical lookup returns only exact original proof and never replaces it with a valid re-signature', () => {
  const first = signed(),
    second = signed();
  expect(second.coseHex).not.toBe(first.coseHex);
  expect(
    validateNotificationReceiptLookup(
      sample.request,
      { state: 'OBSERVED', observation: first },
      sample.trust,
      first,
    ),
  ).toEqual(first);
  expect(() =>
    validateNotificationReceiptLookup(
      sample.request,
      { state: 'OBSERVED', observation: second },
      sample.trust,
      first,
    ),
  ).toThrow();
  const absent = {
    state: 'ABSENT',
    signingAttemptId: sample.request.signingAttemptId,
    requestDigest: notificationReceiptRequestDigest(sample.request),
  };
  expect(validateNotificationReceiptLookup(sample.request, absent, sample.trust)).toBeUndefined();
  expect(() =>
    validateNotificationReceiptLookup(sample.request, absent, sample.trust, first),
  ).toThrow();
  expect(() =>
    validateNotificationReceiptLookup(
      sample.request,
      { ...absent, requestDigest: sha256('other') },
      sample.trust,
    ),
  ).toThrow();
  expect(() =>
    validateNotificationReceiptLookup(sample.request, { state: 'UNKNOWN' }, sample.trust),
  ).toThrow();
});
it('strict original bytes reject appended CBOR, unknown flags and getters without leaking provider data', () => {
  for (const request of [
    { ...sample.request, payloadHex: sample.request.payloadHex + '00' },
    { ...sample.request, ready: true },
    { ...sample.request, privateKey: 'PRIVATE_CANARY' },
  ])
    expect(() => validateNotificationReceiptRequest(request, sample.trust)).toThrow(
      'Notification receipt signing outcome requires reconciliation',
    );
  let reads = 0;
  const accessor = Object.defineProperty({ ...sample.request }, 'payloadHex', {
    enumerable: true,
    get() {
      reads++;
      throw new Error('PRIVATE_CANARY');
    },
  });
  expect(() => validateNotificationReceiptRequest(accessor, sample.trust)).toThrow(
    'Notification receipt signing outcome requires reconciliation',
  );
  expect(reads).toBe(0);
});

it('rejects noncanonical hexadecimal and digest suffixes even when decoders would ignore them', () => {
  const observation = signed();
  expect(() =>
    validateNotificationReceiptObservation(
      sample.request,
      { ...observation, coseHex: observation.coseHex + '\n' },
      sample.trust,
    ),
  ).toThrow();
  expect(() =>
    validateNotificationReceiptRequest(
      { ...sample.request, payloadHex: sample.request.payloadHex + '\n' },
      sample.trust,
    ),
  ).toThrow();
  expect(() =>
    validateNotificationReceiptRequest(
      {
        ...sample.request,
        deliveryPreparationDigest: sample.request.deliveryPreparationDigest + '\n',
      },
      sample.trust,
    ),
  ).toThrow();
});
