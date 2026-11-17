import { expect, it } from 'vitest';
import { canonicalJson, sha256 } from '../configuration/digest.js';
import { notificationDeliverySigningSample } from '../../../../tests/integration/identity/notification-delivery-signing-cases.js';
import {
  decodeNotificationDeliverySigning,
  validateNotificationDeliverySigning,
  notificationSigningObservation,
  notificationSigningTransition,
  notificationSigningSnapshot,
} from './delivery-signing-contract.js';
it('binds canonical original request to the reserved native attempt and exact transition', () => {
  const { signing, observe } = notificationDeliverySigningSample(),
    text = canonicalJson(signing),
    bytes = Buffer.from(text);
  expect(canonicalJson(decodeNotificationDeliverySigning(bytes, sha256(bytes)))).toBe(text);
  const transition = notificationSigningTransition(signing, observe());
  expect(transition.receipt.operationId).toBe(signing.deliveryPreparation.operationId);
  expect(transition.receipt.receiptId).toBe(signing.request.signingAttemptId);
  expect(transition.before.attemptCount).toBe(0);
  expect(transition.after.attemptCount).toBe(1);
  expect(transition.receipt.attemptId).not.toBe(transition.receipt.receiptId);
  expect(Date.now()).toBeGreaterThan(transition.receipt.deadlineAtMs);
});
it.each([
  'receipt',
  'preparation',
  'scope',
  'worker',
  'context',
  'source',
  'extra',
  'generation',
  'cancel',
  'zero',
] as const)('rejects modified %s before authority or I/O', (kind) => {
  const p = structuredClone(notificationDeliverySigningSample().signing);
  if (kind === 'receipt') p.request.signingAttemptId = p.request.operationId;
  if (kind === 'preparation') p.request.deliveryPreparationDigest = sha256('other');
  if (kind === 'scope') p.request.privacyDomainId = p.request.participantId;
  if (kind === 'worker') p.trust.signer.workloadEpoch = '2';
  if (kind === 'context')
    p.deliveryPreparation.context.auditCorrelationId = p.deliveryPreparation.sourceOperationId;
  if (kind === 'source') p.sourceClaims.eventId = p.sourceClaims.sourceEventId;
  if (kind === 'extra') Object.assign(p, { ready: true });
  if (kind === 'generation') p.deliveryPreparation.generationId = p.sourceClaims.eventId;
  if (kind === 'cancel') p.deliveryPreparation.before.cancelRequested = true;
  if (kind === 'zero') p.deliveryPreparation.configuredLimit = 0;
  expect(() => validateNotificationDeliverySigning(p)).toThrow(
    'Notification delivery signing unavailable',
  );
});
it('keeps the first valid signature immutable and rejection cannot become STARTED', () => {
  const { signing, observe } = notificationDeliverySigningSample(),
    first = observe();
  expect(notificationSigningObservation(signing, first, first)).toEqual(first);
  const resigned = observe();
  expect(resigned.coseHex).not.toBe(first.coseHex);
  expect(() => notificationSigningObservation(signing, resigned, first)).toThrow();
  const rejected = {
    ...first,
    outcome: 'REJECTED' as const,
    reason: 'REVOKED' as const,
    coseHex: null,
  };
  expect(notificationSigningObservation(signing, rejected).outcome).toBe('REJECTED');
  expect(() => notificationSigningTransition(signing, rejected)).toThrow();
  expect(() => notificationSigningObservation(signing, first, rejected)).toThrow();
});
it('rejects noncanonical bytes, wrong retained digest and getters without evaluating them', () => {
  const { signing } = notificationDeliverySigningSample(),
    bytes = Buffer.from(canonicalJson(signing));
  for (const bad of [
    Buffer.from(' ' + bytes.toString()),
    Buffer.from(bytes.toString().replace('{', '{"schema":"wrong",')),
  ])
    expect(() => decodeNotificationDeliverySigning(bad, sha256(bad))).toThrow();
  expect(() => decodeNotificationDeliverySigning(bytes, sha256('other'))).toThrow();
  let accessed = 0;
  const unsafe = Object.defineProperty({}, 'participantId', {
    enumerable: true,
    get() {
      accessed++;
      return 'PRIVATE_CANARY';
    },
  });
  expect(() => notificationSigningSnapshot(unsafe)).toThrow();
  expect(accessed).toBe(0);
});
