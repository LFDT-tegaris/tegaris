import { expect, it } from 'vitest';
import {
  encodeNotificationClaim,
  signNotificationClaim,
  type NotificationDeliveryOutcomeReceiptClaims,
} from '@openpc/security-kernel';
import { notificationOutcomeReceiptProviderSample } from '../../../../tests/integration/identity/notification-receipt-provider-fixture.js';
import { notificationFailureWorkItem } from './delivery-failure-work-contract.js';
import { sha256 } from '../configuration/digest.js';

function fixture(patch: Partial<NotificationDeliveryOutcomeReceiptClaims> = {}) {
  const s = notificationOutcomeReceiptProviderSample({ nowMs: 1800000000000 });
  const claims: NotificationDeliveryOutcomeReceiptClaims = {
    ...s.claims,
    outcome: 'PERMANENT_FAILURE',
    afterDeliveryState: 'FAILED',
    ...patch,
  };
  const signed = signNotificationClaim(
    'NotificationDeliveryOutcomeReceiptV1',
    s.original.signerPrivateKey,
    Buffer.from(s.trust.signer.publicKeySpkiHex, 'hex'),
    claims,
  );
  s.original.signerPrivateKey.fill(0);
  return {
    s,
    claims,
    input: {
      workerInstallation: s.trust.worker,
      payloadHex: signed.payload.toString('hex'),
      coseHex: signed.cose.toString('hex'),
    },
  };
}
it('derives native failure work solely from the signed FAILED receipt and its worker', () => {
  const { s, claims, input } = fixture();
  const work = notificationFailureWorkItem(input);
  expect(work.workItemId).toBe(claims.receiptId);
  expect(work.outcomeOperationId).toBe(claims.operationId);
  expect(work.resourceRef).toBe(`urn:openpc:resource:${claims.notificationOccurrenceId}`);
  expect(work.createdByPrincipalId).toBe(s.original.profile.principalId);
  expect(work.payloadDigest).toBe(sha256(Buffer.from(input.payloadHex, 'hex')));
  expect(work.outcomeCoseDigest).toBe(sha256(Buffer.from(input.coseHex, 'hex')));
  expect(work).toMatchObject({
    kind: 'DELIVERY_FAILURE',
    state: 'OPEN',
    revision: '1',
    reason: 'Notification delivery failed.',
    assigneePrincipalId: null,
    claimedByPrincipalId: null,
    completedByPrincipalId: null,
  });
  expect(notificationFailureWorkItem(input)).toEqual(work);
  expect(work).not.toHaveProperty('admitted');
});
it('recognizes authenticated exhausted no-effect without granting retry or send', () => {
  const x = fixture({ outcome: 'RETRYABLE_NO_EFFECT', attemptCount: 6, attemptLimit: 6 });
  expect(notificationFailureWorkItem(x.input).kind).toBe('DELIVERY_FAILURE');
});
it('does not create failure work for other authentic terminal, retry or ambiguous outcomes', () => {
  for (const patch of [
    { outcome: 'DELIVERED', afterDeliveryState: 'DELIVERED' },
    { outcome: 'AMBIGUOUS', afterDeliveryState: 'AMBIGUOUS' },
    { outcome: 'RETRYABLE_NO_EFFECT', afterDeliveryState: 'CANCELLED', cancelRequested: 'YES' },
    {
      outcome: 'RETRYABLE_NO_EFFECT',
      afterDeliveryState: 'RETRY_WAIT',
      nextAttemptAtMs: 1800000005000,
    },
  ] as const) {
    const x = fixture(patch);
    expect(() => notificationFailureWorkItem(x.input)).toThrow(
      'Notification failure work unavailable',
    );
  }
});
it('rejects altered identity, bytes, signature, worker, IDs and noncanonical caller properties', () => {
  const x = fixture();
  for (const patch of [
    { workItemId: x.claims.receiptId },
    { admitted: true },
    { coseHex: '00' },
    {
      payloadHex: encodeNotificationClaim('NotificationDeliveryOutcomeReceiptV1', {
        ...x.claims,
        participantId: '01990000-0000-7000-8000-000000000999',
      }).toString('hex'),
    },
    { workerInstallation: notificationOutcomeReceiptProviderSample().trust.worker },
  ])
    expect(() => notificationFailureWorkItem({ ...x.input, ...patch })).toThrow();
  let reads = 0;
  const input = Object.defineProperty({ ...x.input }, 'payloadHex', {
    enumerable: true,
    get() {
      reads++;
      return x.input.payloadHex;
    },
  });
  expect(() => notificationFailureWorkItem(input)).toThrow();
  expect(reads).toBe(0);
});
