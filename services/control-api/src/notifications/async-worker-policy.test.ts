import { expect, it } from 'vitest';
import type { NotificationAsyncInputClaims } from '../../../../packages/security-kernel/src/operations-configuration/notification-async.js';
import {
  assertNotificationWorkerSchedule,
  notificationWorkDeadline,
  notificationQueueAdmission,
  notificationLeaseDeadline,
} from './async-worker-policy.js';
import {
  notificationWorkerLeaseSelector,
  notificationWorkerLeaseSignal,
} from './async-worker-state.js';

const digest = `sha256:${'a'.repeat(64)}`;
const id = '01900000-0000-7000-8000-000000000001';
// Pure declared-input corpus. These bytes are never installed as qualification.
const input: NotificationAsyncInputClaims = {
  authorityId: 'local',
  environmentId: 'test',
  profile: 'test',
  participantId: id,
  privacyDomainId: id,
  task: 'ASYNC-NOTIFICATION',
  generationId: id,
  configurationDigest: digest,
  configurationSchemaDigest: digest,
  namedProfileDigest: digest,
  buildDigest: digest,
  sourceTreeDigest: digest,
  workloadIdentityDigest: digest,
  environmentIdentityDigest: digest,
  storeProfileDigest: digest,
  gatewayProfileDigest: digest,
  ratePolicyDigest: digest,
  inputId: id,
  slot: 'QINPUT-ASYNC-NOTIFICATION',
  concurrency: 2,
  batchSize: 2,
  leaseMs: 10000,
  heartbeatMs: 1000,
  attemptTimeoutMs: 1000,
  retryDelaysMs: [5000, 30000, 120000, 600000, 1800000],
  domainDeadlineMs: 3000000,
  queueItems: 8,
  queueBytes: 8000,
  maximumQueueAgeMs: 4000000,
  maximumPayloadBytes: 1000,
  dispatchRatePerSecond: 2,
  issuerKeyId: digest,
  issuerEpoch: '1',
  validFromMs: 1000,
  validUntilMs: 6001000,
};
it('anchors the domain once to the source and caps renewals at that original deadline', () => {
  expect(notificationWorkDeadline(input, 2000)).toBe(3002000);
  expect(notificationLeaseDeadline(input, 3002000, 3001000)).toBe(3002000);
  expect(() => notificationLeaseDeadline(input, 3002000, 3002000)).toThrow();
  expect(notificationWorkDeadline(input, 5000000)).toBe(input.validUntilMs);
  expect(() => notificationWorkDeadline(input, input.validUntilMs)).toThrow();
});
it('rejects a well-formed declaration that silently changes the canonical retry schedule', () => {
  expect(() => assertNotificationWorkerSchedule(input)).not.toThrow();
  expect(() =>
    assertNotificationWorkerSchedule({ ...input, retryDelaysMs: [0, 0, 0, 0, 0] }),
  ).toThrow();
  expect(() =>
    assertNotificationWorkerSchedule({
      ...input,
      retryDelaysMs: [5000, 30000, 120000, 600000, 1800001],
    }),
  ).toThrow();
});
it('separates actual rendered-body bounds from receipt-envelope queue occupancy', () => {
  const empty = { items: 0, bytes: 0 };
  expect(
    notificationQueueAdmission(input, empty, { envelopeBytes: 1000, payloadBytes: 1000 }),
  ).toBe('ADMIT');
  expect(
    notificationQueueAdmission(input, empty, { envelopeBytes: 1001, payloadBytes: 1001 }),
  ).toBe('PAYLOAD_LIMIT');
  expect(
    notificationQueueAdmission(
      input,
      { ...empty, items: 8 },
      { envelopeBytes: 1, payloadBytes: 1 },
    ),
  ).toBe('QUEUE_FULL');
  expect(
    notificationQueueAdmission(
      input,
      { ...empty, bytes: 8000 },
      { envelopeBytes: 1, payloadBytes: 1 },
    ),
  ).toBe('QUEUE_FULL');
  expect(notificationQueueAdmission(input, empty, { envelopeBytes: 10, payloadBytes: 1001 })).toBe(
    'PAYLOAD_LIMIT',
  );
  expect(notificationQueueAdmission(input, empty, { envelopeBytes: 8001, payloadBytes: 1 })).toBe(
    'QUEUE_FULL',
  );
  expect(notificationQueueAdmission(input, empty, { envelopeBytes: 2000, payloadBytes: 1 })).toBe(
    'ADMIT',
  );
  expect(() =>
    notificationQueueAdmission(
      input,
      { ...empty, bytes: -1 },
      { envelopeBytes: 1, payloadBytes: 1 },
    ),
  ).toThrow();
});
it.each([NaN, Infinity, -1, -0, Number.MAX_SAFE_INTEGER + 1])(
  'rejects unsafe time %s before arithmetic',
  (value) => {
    expect(() => notificationWorkDeadline(input, value)).toThrow();
    expect(() => notificationLeaseDeadline(input, 3002000, value)).toThrow();
  },
);
it('accepts only exact selectors and never an attached ready flag', () => {
  const lease = { eventId: id, ownerId: 'actual-mounted-process', epoch: '1' };
  expect(notificationWorkerLeaseSelector.parse(lease)).toEqual(lease);
  for (const extra of ['ready', 'validUntilMs', 'signal', 'nativeAdmission'])
    expect(() => notificationWorkerLeaseSelector.parse({ ...lease, [extra]: true })).toThrow();
  for (const epoch of ['0', '-1', '01', '18446744073709551616'])
    expect(() => notificationWorkerLeaseSelector.parse({ ...lease, epoch })).toThrow();
});
it('expired leases and parent abort synchronously prevent native I/O', () => {
  const window = { validUntilMs: 0, heartbeatMs: 1000, ownerId: 'process', epoch: '1' };
  expect(notificationWorkerLeaseSignal(window).aborted).toBe(true);
  expect(
    notificationWorkerLeaseSignal(
      { ...window, validUntilMs: Date.now() + 10000 },
      AbortSignal.abort(),
    ).aborted,
  ).toBe(true);
  expect(() => notificationWorkerLeaseSignal({ ...window, validUntilMs: NaN })).toThrow();
});
