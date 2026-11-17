import { expect, it } from 'vitest';
import { assertNotificationPreparedContext } from './delivery-adapter-context.js';
import {
  notificationIdempotencyDigest,
  notificationScopeDigest,
  type NotificationDeliveryAttemptBinding,
  type AdapterCallContextV1,
  type InstalledNotificationChannel,
} from './gateway-contracts.js';
const id = (n: number) => `01900000-0000-7000-8000-${String(n).padStart(12, '0')}`;
const h = `sha256:${'1'.repeat(64)}`;
function fixture() {
  const channel: InstalledNotificationChannel = {
    claims: {
      environmentId: 'test',
      participantId: id(1),
      privacyDomainId: id(2),
      profileId: id(3),
      revision: '1',
      validFromMs: 0,
      validUntilMs: 5000,
      transportProfileDigest: h,
      receiptSignerSpki: '',
      issuerKeyId: h,
    },
    signedProfileDigest: h,
    transport: {
      protocol: 'OPENPC_NOTIFICATION_GATEWAY_V1',
      channel: 'EMAIL',
      destinationRef: `urn:openpc:resource:${id(4)}`,
      credentialRef: `urn:openpc:resource:${id(5)}`,
      endpoint: 'https://gateway.test/',
      addresses: ['127.0.0.1'],
      serverSpkiDigest: h,
      requestTimeoutMs: 1000,
      maxPayloadBytes: 100,
    },
  };
  const attempt: NotificationDeliveryAttemptBinding = {
    version: 'NotificationDeliveryAttemptV1',
    participantId: id(1),
    privacyDomainId: id(2),
    notificationOccurrenceId: `urn:openpc:resource:${id(6)}`,
    endpointId: `urn:openpc:resource:${id(7)}`,
    endpointRevision: '1',
    channel: 'EMAIL',
    destinationRef: channel.transport.destinationRef,
    credentialRef: channel.transport.credentialRef,
    channelProfileDigest: h,
    templateDigest: h,
    payloadDigest: h,
    payloadBytes: 10,
    attemptId: id(8),
    attemptNumber: 1,
    startedAtMs: 1000,
    deadlineAtMs: 2000,
  };
  const context: AdapterCallContextV1 = {
    authorizationDigest: h,
    authorizationContextId: id(9),
    authorizationContextEpoch: 1,
    accessClassIds: ['ACCESS-NOTIFICATION'],
    profileDigest: h,
    scopeDigest: notificationScopeDigest(attempt),
    idempotencyDigest: notificationIdempotencyDigest(attempt),
    deadlineAt: new Date(2000).toISOString(),
    occurrenceId: id(6),
    auditCorrelationId: id(10),
    cancellation: { mode: 'NO_NEW_EFFECT_AFTER_CANCELLATION', occurrenceId: id(6) },
    reconciliation: { mode: 'EXACT_OCCURRENCE', occurrenceId: id(6) },
  };
  return {
    operationId: id(10),
    sourceOperationId: id(11),
    occurrenceId: id(6),
    workerCredentialId: id(9),
    workerEpoch: '1',
    authorityDigest: h,
    validUntilMs: 2000,
    channel,
    attempt,
    context,
  };
}
it('binds UUID context occurrence to resource URN while retaining original operation and deadline', () => {
  const p = fixture();
  expect(assertNotificationPreparedContext(p).context).toEqual(p.context);
  expect(p.attempt.notificationOccurrenceId).toBe(`urn:openpc:resource:${p.context.occurrenceId}`);
});
it.each(['9007199254740992', '18446744073709551615', '0', '01', '1.0'])(
  'refuses non-exact epoch %s',
  (epoch) => {
    const p = fixture();
    p.workerEpoch = epoch;
    expect(() => assertNotificationPreparedContext(p)).toThrow();
  },
);
it.each([
  'audit',
  'credential',
  'epoch',
  'cancellation',
  'reconciliation',
  'class',
  'deadline',
  'profile',
  'namespace',
] as const)('rejects %s substitution', (kind) => {
  const p = fixture();
  if (kind === 'audit') p.context.auditCorrelationId = p.sourceOperationId;
  if (kind === 'credential') p.context.authorizationContextId = id(99);
  if (kind === 'epoch') p.context.authorizationContextEpoch = 2;
  if (kind === 'cancellation') p.context.cancellation.occurrenceId = id(99);
  if (kind === 'reconciliation') p.context.reconciliation.occurrenceId = id(99);
  if (kind === 'class') p.context.accessClassIds = ['ACCESS-EVIDENCE'];
  if (kind === 'deadline') {
    p.attempt.deadlineAtMs = 2001;
    p.context.deadlineAt = new Date(2001).toISOString();
  }
  if (kind === 'profile') p.context.profileDigest = `sha256:${'2'.repeat(64)}`;
  if (kind === 'namespace')
    p.attempt.notificationOccurrenceId = `urn:openpc:notification-occurrence:${id(6)}`;
  expect(() => assertNotificationPreparedContext(p)).toThrow();
});
it('keeps business idempotency across distinct original attempt ordinals', () => {
  const p = fixture();
  expect(notificationIdempotencyDigest({ ...p.attempt, attemptId: id(20), attemptNumber: 2 })).toBe(
    p.context.idempotencyDigest,
  );
});
