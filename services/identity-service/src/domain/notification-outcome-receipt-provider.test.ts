import { expect, it } from 'vitest';
import { sha256 } from '../../../control-api/src/configuration/digest.js';
import { notificationOutcomeReceiptProviderSample } from '../../../../tests/integration/identity/notification-receipt-provider-fixture.js';
import {
  validateNotificationOutcomeReceiptRequest,
  validateNotificationOutcomeReceiptObservation,
  validateNotificationOutcomeReceiptLookup,
} from './notification-outcome-receipt-provider.js';
import { validateNotificationReceiptRequest } from './notification-receipt-provider.js';

const id = (n: number) => `01990000-0000-7000-8000-${String(n).padStart(12, '0')}`;
const sample = () => notificationOutcomeReceiptProviderSample({ nowMs: 1800000000000 });
it('binds exact outcome bytes and original STARTED and native result under separate native purpose', () => {
  const x = sample();
  expect(validateNotificationOutcomeReceiptObservation(x.request, x.observation, x.trust)).toEqual(
    x.observation,
  );
  expect(
    validateNotificationOutcomeReceiptLookup(
      x.request,
      { state: 'OBSERVED', observation: x.observation },
      x.trust,
      x.observation,
    ),
  ).toEqual(x.observation);
  expect(() => validateNotificationReceiptRequest(x.request, x.trust)).toThrow();
  expect(() => validateNotificationOutcomeReceiptRequest(x.original.request, x.trust)).toThrow();
  expect(() => validateNotificationOutcomeReceiptRequest(x.request, x.original.trust)).toThrow();
});
it('rejects altered STARTED, attempt, source bytes, trust, method and undeclared send fields', () => {
  const x = sample();
  for (const patch of [
    { startOperationId: id(91) },
    { operationId: id(92) },
    { attemptId: id(96) },
    { signingAttemptId: id(93) },
    { purpose: x.original.request.purpose },
    { method: x.original.request.method },
    { deliveryAttemptId: id(94) },
    { signerInstallationDigest: sha256('other') },
    { workerProfileDigest: sha256('other') },
    { privacyDomainId: id(95) },
    { payloadHex: x.original.request.payloadHex },
  ])
    expect(() =>
      validateNotificationOutcomeReceiptRequest({ ...x.request, ...patch }, x.trust),
    ).toThrow();
  expect(() =>
    validateNotificationOutcomeReceiptObservation(
      { ...x.request, outcomePreparationDigest: sha256('changed') },
      x.observation,
      x.trust,
    ),
  ).toThrow();
});
it('preserves first exact authenticated result and treats absence as unknown without resend authority', () => {
  const x = sample();
  const absent = {
    state: 'ABSENT',
    signingAttemptId: x.request.signingAttemptId,
    requestDigest: x.bound.requestDigest,
  };
  expect(validateNotificationOutcomeReceiptLookup(x.request, absent, x.trust)).toBeUndefined();
  expect(() =>
    validateNotificationOutcomeReceiptLookup(x.request, absent, x.trust, x.observation),
  ).toThrow();
  const resigned = { ...x.observation, coseHex: x.sign().cose.toString('hex') };
  expect(validateNotificationOutcomeReceiptObservation(x.request, resigned, x.trust)).toEqual(
    resigned,
  );
  expect(() =>
    validateNotificationOutcomeReceiptObservation(x.request, resigned, x.trust, x.observation),
  ).toThrow();
  for (const patch of [
    { requestDigest: sha256('other') },
    { signingAttemptId: id(99) },
    { recordedAtMs: x.bound.notBeforeMs - 1 },
    { recordedAtMs: x.bound.notAfterMs },
    { coseHex: '00' },
  ])
    expect(() =>
      validateNotificationOutcomeReceiptObservation(
        x.request,
        { ...x.observation, ...patch },
        x.trust,
      ),
    ).toThrow();
});
it('rejects accessors before evaluation and never exposes a caller capability', () => {
  const x = sample();
  let reads = 0;
  const request = Object.defineProperty({ ...x.request }, 'payloadHex', {
    enumerable: true,
    get() {
      reads++;
      return x.request.payloadHex;
    },
  });
  expect(() => validateNotificationOutcomeReceiptRequest(request, x.trust)).toThrow();
  expect(reads).toBe(0);
  expect(x.bound).not.toHaveProperty('admitted');
});
