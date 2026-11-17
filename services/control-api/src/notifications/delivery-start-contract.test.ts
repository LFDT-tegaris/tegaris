import { generateKeyPairSync } from 'node:crypto';
import { expect, it } from 'vitest';
import {
  encodeNotificationClaim,
  encodeNotificationDeliveryRequestedData,
  evidenceKeyId,
  signNotificationClaim,
  type NotificationDeliveryRequestedReceiptClaims,
  type NotificationDeliveryStartedReceiptClaims,
} from '@openpc/security-kernel';
import { sha256 } from '../configuration/digest.js';
import {
  notificationIdempotencyDigest,
  notificationScopeDigest,
  verifyInstalledNotificationChannel,
  type AdapterCallContextV1,
  type NotificationDeliveryAttemptBinding,
  type NotificationGatewayTransportV1,
} from './gateway-contracts.js';
import { initialDeliverySnapshot, planNotificationDelivery } from './delivery-policy.js';
import {
  assertNotificationDeliveryStartBinding,
  notificationDeliveryStateDigest,
} from './delivery-start-contract.js';
const id = (n: number) => `01900000-0000-7000-8000-${String(n).padStart(12, '0')}`;
const h = (n: number) => sha256(String(n));
function fixture() {
  const issuer = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const signer = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const issuerSpki = issuer.publicKey.export({ type: 'spki', format: 'der' });
  const signerSpki = signer.publicKey.export({ type: 'spki', format: 'der' });
  const transport: NotificationGatewayTransportV1 = {
    protocol: 'OPENPC_NOTIFICATION_GATEWAY_V1',
    channel: 'WEBHOOK',
    destinationRef: `urn:openpc:resource:${id(4)}`,
    credentialRef: `urn:openpc:resource:${id(5)}`,
    endpoint: 'https://gateway.test/',
    addresses: ['127.0.0.1'],
    serverSpkiDigest: h(1),
    requestTimeoutMs: 1000,
    maxPayloadBytes: 1024,
  };
  const profile = {
    environmentId: 'test',
    participantId: id(1),
    privacyDomainId: id(2),
    profileId: id(3),
    revision: '1',
    validFromMs: 1000,
    validUntilMs: 10000,
    transportProfileDigest: sha256(transport),
    receiptSignerSpki: signerSpki.toString('hex'),
    issuerKeyId: evidenceKeyId(issuerSpki),
  };
  const signed = signNotificationClaim(
    'NotificationChannelProfileV1',
    issuer.privateKey.export({ type: 'pkcs8', format: 'der' }),
    issuerSpki,
    profile,
  );
  const channel = verifyInstalledNotificationChannel(
    {
      environmentId: 'test',
      participantId: id(1),
      privacyDomainId: id(2),
      signedProfileDigest: sha256(signed.cose),
      issuerSpkiHex: issuerSpki.toString('hex'),
    },
    { transport, payloadHex: signed.payload.toString('hex'), coseHex: signed.cose.toString('hex') },
  );
  const source: NotificationDeliveryRequestedReceiptClaims = {
    environmentId: 'test',
    participantId: id(1),
    privacyDomainId: id(2),
    receiptId: id(10),
    operationId: id(11),
    notificationId: id(12),
    notificationOccurrenceId: id(13),
    payloadObjectId: id(14),
    keyPreparationId: id(15),
    sourceEventId: id(16),
    sourceDataDigest: h(2),
    sourceReceiptDigest: h(3),
    routingProfileDigest: h(4),
    workerProfileDigest: h(5),
    authoritySnapshotDigest: h(6),
    custodyDigest: h(7),
    endpointId: id(17),
    endpointRevision: '1',
    templateDigest: h(8),
    payloadDigest: h(9),
    encryptedObjectDigest: h(10),
    keyId: h(11),
    recordedAtMs: 2000,
    signerKeyId: evidenceKeyId(signerSpki),
    occurrenceReceiptDigest: h(12),
    eventId: id(18),
    sourceId: id(19),
    sequence: '1',
    dataDigest: '',
  };
  source.dataDigest = sha256(
    encodeNotificationDeliveryRequestedData({
      notificationOccurrenceId: source.notificationOccurrenceId,
      endpointId: source.endpointId,
      templateDigest: source.templateDigest,
      payloadDigest: source.payloadDigest,
    }),
  );
  const attempt: NotificationDeliveryAttemptBinding = {
    version: 'NotificationDeliveryAttemptV1',
    participantId: id(1),
    privacyDomainId: id(2),
    notificationOccurrenceId: `urn:openpc:resource:${source.notificationOccurrenceId}`,
    endpointId: `urn:openpc:resource:${source.endpointId}`,
    endpointRevision: '1',
    channel: transport.channel,
    destinationRef: transport.destinationRef,
    credentialRef: transport.credentialRef,
    channelProfileDigest: channel.signedProfileDigest,
    templateDigest: source.templateDigest,
    payloadDigest: source.payloadDigest,
    payloadBytes: 100,
    attemptId: id(20),
    attemptNumber: 1,
    startedAtMs: 3000,
    deadlineAtMs: 4000,
  };
  const context: AdapterCallContextV1 = {
    authorizationDigest: h(13),
    profileDigest: channel.signedProfileDigest,
    authorizationContextId: id(21),
    authorizationContextEpoch: 1,
    accessClassIds: ['ACCESS-NOTIFICATION'],
    scopeDigest: notificationScopeDigest(attempt),
    deadlineAt: new Date(4000).toISOString(),
    idempotencyDigest: notificationIdempotencyDigest(attempt),
    occurrenceId: source.notificationOccurrenceId,
    auditCorrelationId: id(22),
    cancellation: {
      mode: 'NO_NEW_EFFECT_AFTER_CANCELLATION',
      occurrenceId: source.notificationOccurrenceId,
    },
    reconciliation: { mode: 'EXACT_OCCURRENCE', occurrenceId: source.notificationOccurrenceId },
  };
  const before = initialDeliverySnapshot(
    {
      participantId: id(1),
      privacyDomainId: id(2),
      notificationOccurrenceId: source.notificationOccurrenceId,
      payloadDigest: source.payloadDigest,
    },
    6,
    2000,
  );
  const after = planNotificationDelivery(before, 6, 3000).next;
  const receipt: NotificationDeliveryStartedReceiptClaims = {
    environmentId: 'test',
    participantId: id(1),
    privacyDomainId: id(2),
    receiptId: id(23),
    operationId: context.auditCorrelationId,
    attemptId: attempt.attemptId,
    notificationOccurrenceId: source.notificationOccurrenceId,
    payloadObjectId: source.payloadObjectId,
    keyPreparationId: source.keyPreparationId,
    sourceEventId: source.eventId,
    sourceDataDigest: source.dataDigest,
    sourceReceiptDigest: sha256(
      encodeNotificationClaim('NotificationDeliveryRequestedReceiptV1', source),
    ),
    routingProfileDigest: source.routingProfileDigest,
    workerProfileDigest: h(14),
    authoritySnapshotDigest: context.authorizationDigest,
    endpointId: source.endpointId,
    endpointRevision: source.endpointRevision,
    templateDigest: source.templateDigest,
    payloadDigest: source.payloadDigest,
    encryptedObjectDigest: source.encryptedObjectDigest,
    keyId: source.keyId,
    signedChannelProfileDigest: channel.signedProfileDigest,
    attemptDigest: sha256(attempt),
    contextDigest: sha256(context),
    attemptNumber: 1,
    startedAtMs: 3000,
    deadlineAtMs: 4000,
    deliveryRevision: '1',
    beforeStateDigest: notificationDeliveryStateDigest(before, '1'),
    afterStateDigest: notificationDeliveryStateDigest(after, '2'),
    signerKeyId: evidenceKeyId(signerSpki),
  };
  return { receipt, source, channel, attempt, context, before, after, configuredLimit: 6 };
}
it('joins the exact original request, installed channel, adapter context and typed monotonic START transition', () => {
  const value = fixture();
  expect(() => assertNotificationDeliveryStartBinding(value)).not.toThrow();
  const prior = structuredClone(value);
  assertNotificationDeliveryStartBinding(value);
  expect(value).toEqual(prior);
  expect(notificationDeliveryStateDigest(value.before, '1')).not.toBe(
    notificationDeliveryStateDigest(value.before, '2'),
  );
});
it('rejects independently forged operation, state, scope, endpoint, payload and adapter context', () => {
  const original = fixture();
  for (const mutate of [
    (v: typeof original) => {
      v.receipt.operationId = id(99);
    },
    (v: typeof original) => {
      v.receipt.deliveryRevision = '2';
    },
    (v: typeof original) => {
      v.receipt.beforeStateDigest = h(99);
    },
    (v: typeof original) => {
      v.receipt.afterStateDigest = h(99);
    },
    (v: typeof original) => {
      v.before.privacyDomainId = id(99);
    },
    (v: typeof original) => {
      v.after.attemptLimit = 5;
    },
    (v: typeof original) => {
      v.attempt.endpointRevision = '2';
    },
    (v: typeof original) => {
      v.attempt.attemptId = id(99);
    },
    (v: typeof original) => {
      v.attempt.payloadDigest = h(99);
    },
    (v: typeof original) => {
      v.attempt.payloadBytes++;
    },
    (v: typeof original) => {
      v.attempt.credentialRef = `urn:openpc:resource:${id(99)}`;
    },
    (v: typeof original) => {
      v.context.authorizationDigest = h(99);
      v.receipt.contextDigest = sha256(v.context);
    },
    (v: typeof original) => {
      v.context.auditCorrelationId = id(99);
      v.receipt.contextDigest = sha256(v.context);
    },
    (v: typeof original) => {
      v.context.idempotencyDigest = h(99);
    },
    (v: typeof original) => {
      v.context.scopeDigest = h(99);
    },
    (v: typeof original) => {
      v.source.eventId = id(99);
    },
    (v: typeof original) => {
      v.source.keyId = h(99);
    },
  ]) {
    const value = structuredClone(original);
    mutate(value);
    expect(() => assertNotificationDeliveryStartBinding(value)).toThrow();
  }
});
it('never turns WAIT, cancellation, exhausted budget, STARTED or AMBIGUOUS into another START', () => {
  const original = fixture();
  for (const before of [
    { ...original.before, nextAttemptAtMs: 3001 },
    { ...original.before, cancelRequested: true },
    { ...original.before, attemptLimit: 0 },
    original.after,
    { ...original.after, state: 'AMBIGUOUS' as const },
    { ...original.after, state: 'DELIVERED' as const },
  ]) {
    const value = { ...structuredClone(original), before };
    value.receipt.beforeStateDigest = notificationDeliveryStateDigest(before, '1');
    expect(() => assertNotificationDeliveryStartBinding(value)).toThrow();
  }
  expect(() =>
    assertNotificationDeliveryStartBinding({ ...original, configuredLimit: 0 }),
  ).toThrow();
  expect(() => notificationDeliveryStateDigest(original.before, '01')).toThrow();
  expect(() => notificationDeliveryStateDigest(original.before, 1 as unknown as string)).toThrow();
  expect(() => notificationDeliveryStateDigest(original.before, '18446744073709551616')).toThrow();
});
