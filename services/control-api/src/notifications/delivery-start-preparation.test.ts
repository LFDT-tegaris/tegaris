import { generateKeyPairSync } from 'node:crypto';
import { expect, it } from 'vitest';
import { evidenceKeyId } from '@openpc/security-kernel';
import { canonicalJson, sha256 } from '../configuration/digest.js';
import { initialDeliverySnapshot, planNotificationDelivery } from './delivery-policy.js';
import { notificationDeliveryStateDigest } from './delivery-start-contract.js';
import {
  notificationIdempotencyDigest,
  notificationScopeDigest,
  type NotificationDeliveryAttemptBinding,
  type NotificationGatewayTransportV1,
} from './gateway-contracts.js';
import {
  validateNotificationDeliveryPreparation,
  notificationPreparationDisposition,
  decodeNotificationDeliveryPreparation,
} from './delivery-start-preparation.js';
const id = (n: number) => `01900000-0000-7000-8000-${String(n).padStart(12, '0')}`;
const h = (n: number) => sha256(String(n));
// Pure historical corpus only. No fake worker admission or SQL success path.
function fixture() {
  const spki = generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).publicKey.export({
    type: 'spki',
    format: 'der',
  });
  const transport: NotificationGatewayTransportV1 = {
    protocol: 'OPENPC_NOTIFICATION_GATEWAY_V1',
    channel: 'WEBHOOK',
    destinationRef: `urn:openpc:resource:${id(8)}`,
    credentialRef: `urn:openpc:resource:${id(9)}`,
    endpoint: 'https://gateway.test/',
    addresses: ['127.0.0.1'],
    serverSpkiDigest: h(1),
    requestTimeoutMs: 1000,
    maxPayloadBytes: 4096,
  };
  const channel = {
    claims: {
      environmentId: 'test',
      participantId: id(1),
      privacyDomainId: id(2),
      profileId: id(10),
      revision: '1',
      validFromMs: 1000,
      validUntilMs: 10000,
      transportProfileDigest: sha256(transport),
      receiptSignerSpki: spki.toString('hex'),
      issuerKeyId: evidenceKeyId(
        generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).publicKey.export({
          type: 'spki',
          format: 'der',
        }),
      ),
    },
    transport,
    signedProfileDigest: h(2),
  };
  const source = {
    worker: { participantId: id(1), privacyDomainId: id(2), installationDigest: h(3) },
    notificationOccurrenceId: id(3),
    eventId: id(4),
  };
  const snapshot = initialDeliverySnapshot(
    {
      participantId: id(1),
      privacyDomainId: id(2),
      notificationOccurrenceId: id(3),
      payloadDigest: h(4),
    },
    6,
    1500,
  );
  const before = {
    ...snapshot,
    revision: '1',
    deliveryRequestEventId: id(4),
    deliveryRequestOperationId: id(5),
    budgetEnvironmentId: 'test',
    budgetGenerationId: id(6),
    budgetEffectiveDigest: h(5),
    budgetConfiguredLimit: 6,
    budgetWorkerInstallationDigest: h(3),
  };
  const attempt: NotificationDeliveryAttemptBinding = {
    version: 'NotificationDeliveryAttemptV1',
    participantId: id(1),
    privacyDomainId: id(2),
    notificationOccurrenceId: `urn:openpc:resource:${id(3)}`,
    endpointId: `urn:openpc:resource:${id(7)}`,
    endpointRevision: '1',
    channel: transport.channel,
    destinationRef: transport.destinationRef,
    credentialRef: transport.credentialRef,
    channelProfileDigest: channel.signedProfileDigest,
    templateDigest: h(6),
    payloadDigest: before.payloadDigest,
    payloadBytes: 100,
    attemptId: id(11),
    attemptNumber: 1,
    startedAtMs: 2000,
    deadlineAtMs: 3000,
  };
  const context = {
    authorizationDigest: h(7),
    authorizationContextId: id(12),
    authorizationContextEpoch: 1,
    accessClassIds: ['ACCESS-NOTIFICATION'],
    profileDigest: channel.signedProfileDigest,
    scopeDigest: notificationScopeDigest(attempt),
    idempotencyDigest: notificationIdempotencyDigest(attempt),
    deadlineAt: new Date(3000).toISOString(),
    occurrenceId: id(3),
    auditCorrelationId: id(13),
    cancellation: { mode: 'NO_NEW_EFFECT_AFTER_CANCELLATION', occurrenceId: id(3) },
    reconciliation: { mode: 'EXACT_OCCURRENCE', occurrenceId: id(3) },
  };
  const plannedAfter = planNotificationDelivery(snapshot, 6, 2000).next;
  return {
    schema: 'pc.notification.delivery-preparation.v1',
    operationId: id(13),
    source,
    sourceOperationId: id(5),
    sourceReceiptDigest: h(8),
    workerCredentialId: id(12),
    workerEpoch: '1',
    authorityDigest: h(7),
    authorityValidUntilMs: 9000,
    generationId: id(6),
    effectiveDigest: h(5),
    configuredLimit: 6,
    before,
    plannedAfter,
    beforeStateDigest: notificationDeliveryStateDigest(snapshot, '1'),
    plannedAfterStateDigest: notificationDeliveryStateDigest(plannedAfter, '2'),
    channel,
    attempt,
    context,
    attemptDigest: sha256(attempt),
    contextDigest: sha256(context),
  };
}
it('retains canonical original bytes and the distinction between before and planned state after deadline', () => {
  const value = fixture(),
    before = canonicalJson(value.before),
    bytes = Buffer.from(canonicalJson(value));
  const p = decodeNotificationDeliveryPreparation(bytes, sha256(bytes));
  expect(p.before.state).toBe('PENDING');
  expect(p.before.attemptCount).toBe(0);
  expect(p.plannedAfter.state).toBe('STARTED');
  expect(p.plannedAfter.attemptCount).toBe(1);
  expect(canonicalJson(p.before)).toBe(before);
  expect(Date.now()).toBeGreaterThan(p.attempt.deadlineAtMs);
  expect(canonicalJson(decodeNotificationDeliveryPreparation(bytes, sha256(bytes)))).toBe(
    bytes.toString(),
  );
  expect(p.context.auditCorrelationId).toBe(p.operationId);
  expect(p.context.auditCorrelationId).not.toBe(p.sourceOperationId);
});
it.each(['cap-zero', 'exhausted', 'not-due', 'cancelled', 'ambiguous', 'started'] as const)(
  'rejects non-START preparation: %s',
  (kind) => {
    const p = fixture();
    if (kind === 'cap-zero') p.configuredLimit = 0;
    if (kind === 'exhausted') {
      p.before.attemptLimit = 0;
    }
    if (kind === 'not-due') p.before.nextAttemptAtMs = 2001;
    if (kind === 'cancelled') p.before.cancelRequested = true;
    if (kind === 'ambiguous' || kind === 'started')
      Object.assign(p.before, {
        state: kind === 'ambiguous' ? 'AMBIGUOUS' : 'STARTED',
        attemptCount: 1,
        lastStartedAtMs: 1500,
        nextAttemptAtMs: null,
      });
    expect(() => validateNotificationDeliveryPreparation(p)).toThrow(
      'Notification delivery preparation unavailable',
    );
  },
);
it.each([
  'correlation',
  'occurrence',
  'source',
  'generation-extra',
  'planned-count',
  'deadline',
  'epoch',
  'profile',
  'context-digest',
  'attempt-digest',
  'before-digest',
  'authority',
] as const)('rejects altered %s even as parseable JSON', (kind) => {
  const p = fixture();
  if (kind === 'correlation') p.context.auditCorrelationId = p.sourceOperationId;
  if (kind === 'occurrence') p.source.notificationOccurrenceId = id(99);
  if (kind === 'source') p.source.eventId = id(99);
  if (kind === 'generation-extra') Object.assign(p, { ready: true });
  if (kind === 'planned-count') p.plannedAfter.attemptCount = 2;
  if (kind === 'deadline') p.authorityValidUntilMs = 2999;
  if (kind === 'epoch') p.workerEpoch = '9007199254740993';
  if (kind === 'profile') p.channel.claims.transportProfileDigest = h(99);
  if (kind === 'context-digest') p.contextDigest = h(99);
  if (kind === 'attempt-digest') p.attemptDigest = h(99);
  if (kind === 'before-digest') p.beforeStateDigest = h(99);
  if (kind === 'authority') p.context.authorizationDigest = h(99);
  expect(() => validateNotificationDeliveryPreparation(p)).toThrow();
});
it('rejects changed, duplicate-member and noncanonical bytes without replacing the original', () => {
  const p = fixture(),
    text = canonicalJson(p),
    bytes = Buffer.from(text);
  for (const changed of [
    Buffer.from(` ${text}`),
    Buffer.from(text.replace('{', '{"schema":"wrong",')),
    Buffer.from(text + '\n'),
  ])
    expect(() => decodeNotificationDeliveryPreparation(changed, sha256(changed))).toThrow();
  expect(() => decodeNotificationDeliveryPreparation(bytes, h(90))).toThrow();
  expect(canonicalJson(decodeNotificationDeliveryPreparation(bytes, sha256(bytes)))).toBe(text);
});
it('detaches inputs and rejects unsafe lifetime or a caller attempt counter', () => {
  const p = fixture(),
    checked = validateNotificationDeliveryPreparation(p);
  p.context.auditCorrelationId = id(99);
  expect(checked.context.auditCorrelationId).toBe(id(13));
  const changed = fixture();
  changed.attempt.attemptNumber = 2;
  changed.attemptDigest = sha256(changed.attempt);
  expect(() => validateNotificationDeliveryPreparation(changed)).toThrow();
  const unsafe = fixture();
  unsafe.authorityValidUntilMs = Number.MAX_SAFE_INTEGER + 1;
  expect(() => validateNotificationDeliveryPreparation(unsafe)).toThrow();
});

it('only durable resolved progress permits the next ordinal; changed revision/expiry/cap never does', () => {
  const original = validateNotificationDeliveryPreparation(fixture());
  for (const current of [
    original.before,
    { ...original.before, revision: '2', attemptLimit: 2 },
    { ...original.before, revision: '2', cancelRequested: true },
    {
      ...original.before,
      revision: '2',
      state: 'AMBIGUOUS' as const,
      attemptCount: 1,
      lastStartedAtMs: 2000,
      nextAttemptAtMs: null,
    },
  ])
    expect(notificationPreparationDisposition(original, current)).toBe('ORIGINAL');
  const resolved = {
    ...original.before,
    revision: '3',
    state: 'RETRY_WAIT' as const,
    attemptCount: 1,
    lastStartedAtMs: 2000,
    nextAttemptAtMs: 8000,
  };
  expect(notificationPreparationDisposition(original, resolved)).toBe('NEXT');
  expect(() =>
    notificationPreparationDisposition(original, { ...resolved, lastStartedAtMs: 2001 }),
  ).toThrow();
  expect(() =>
    notificationPreparationDisposition(original, { ...resolved, revision: '1' }),
  ).toThrow();
  expect(() =>
    notificationPreparationDisposition(original, { ...resolved, attemptCount: 2 }),
  ).toThrow();
});
