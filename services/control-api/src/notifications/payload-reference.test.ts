import { expect, it } from 'vitest';
import type { PoolClient } from 'pg';
import type { NotificationWorkerAdmission } from '../../../identity-service/src/domain/notification-worker.js';
import {
  NotificationPayloadReferenceGate,
  assertNotificationPayloadReference,
  assertNotificationDeliveryPayloadReference,
  assertNotificationDeliveryMaterialStage,
  type NotificationDeliveryMaterialStage,
  type NotificationDeliveryPayloadReference,
  type NotificationPayloadReference,
} from './payload-reference.js';

const worker = {
  participantId: '018f0000-0000-7000-8000-000000000001',
  privacyDomainId: '018f0000-0000-7000-8000-000000000002',
  installationDigest: `sha256:${'a'.repeat(64)}`,
};
it('rejects forged or copied authority before any database or vault access', async () => {
  let queries = 0,
    calls = 0;
  const client = {
    query() {
      queries++;
      throw new Error('PRIVATE_CANARY');
    },
  } as unknown as PoolClient;
  const gate = new NotificationPayloadReferenceGate('/must-not-open');
  for (const admission of [
    {},
    { installation: { profile: { ...worker } }, authorityDigest: worker.installationDigest },
  ])
    await expect(
      gate.withCurrent(
        client,
        admission as unknown as NotificationWorkerAdmission,
        { worker, keyPreparationId: worker.participantId },
        async () => {
          calls++;
        },
      ),
    ).rejects.toThrow('Notification payload reference unavailable');
  expect(queries).toBe(0);
  expect(calls).toBe(0);
  expect(() =>
    assertNotificationPayloadReference({} as NotificationPayloadReference, client),
  ).toThrow('Notification payload reference unavailable');
});
it('rejects caller readiness, scope getters and invalid identities without evaluating accessors', async () => {
  let calls = 0;
  const gate = new NotificationPayloadReferenceGate('/must-not-open');
  const accessor = Object.defineProperty({}, 'worker', {
    enumerable: true,
    get() {
      calls++;
      throw new Error('PRIVATE_CANARY');
    },
  });
  for (const value of [
    { worker, keyPreparationId: 'not-an-id' },
    { worker, keyPreparationId: worker.participantId, ready: true },
    accessor,
  ])
    await expect(
      gate.withCurrent(
        {} as PoolClient,
        {} as NotificationWorkerAdmission,
        value as Parameters<typeof gate.withCurrent>[2],
        async () => {
          calls++;
        },
      ),
    ).rejects.toThrow('Notification payload reference unavailable');
  expect(calls).toBe(0);
});

const deliverySource = {
  worker,
  notificationOccurrenceId: '018f0000-0000-7000-8000-000000000003',
  eventId: '018f0000-0000-7000-8000-000000000004',
};
it('delivery entry rejects structural worker authority before source, database or vault access', async () => {
  let queries = 0,
    calls = 0;
  const client = {
    query() {
      queries++;
      throw new Error('PRIVATE_CANARY');
    },
  } as unknown as PoolClient;
  const gate = new NotificationPayloadReferenceGate('/must-not-open');
  for (const admission of [
    {},
    {
      installation: {
        profile: { ...worker, subscriptionId: 'SUB-NOTIFICATIONDELIVERYREQUESTED-NOTIFICATION-V1' },
      },
      authorityDigest: worker.installationDigest,
    },
  ])
    await expect(
      gate.withDeliveryCurrent(
        client,
        admission as unknown as NotificationWorkerAdmission,
        deliverySource,
        async () => {
          calls++;
        },
      ),
    ).rejects.toThrow('Notification payload reference unavailable');
  expect(queries).toBe(0);
  expect(calls).toBe(0);
});
it.each([
  'key-selector',
  'prepared-object',
  'caller-ready',
  'generation',
  'foreign-field',
  'namespace',
] as const)('delivery source forbids caller substitution: %s', async (kind) => {
  let queries = 0,
    calls = 0;
  const client = {
    query() {
      queries++;
      throw new Error('PRIVATE_CANARY');
    },
  } as unknown as PoolClient;
  const value: Record<string, unknown> = { ...deliverySource };
  if (kind === 'key-selector') value.keyPreparationId = worker.participantId;
  if (kind === 'prepared-object')
    value.preparation = { occurrenceId: deliverySource.notificationOccurrenceId };
  if (kind === 'caller-ready') value.ready = true;
  if (kind === 'generation') value.generationId = worker.participantId;
  if (kind === 'foreign-field') value.authorizationDigest = worker.installationDigest;
  if (kind === 'namespace')
    value.notificationOccurrenceId = `urn:openpc:notification-occurrence:${deliverySource.notificationOccurrenceId}`;
  await expect(
    new NotificationPayloadReferenceGate('/must-not-open').withDeliveryCurrent(
      client,
      {} as NotificationWorkerAdmission,
      value as unknown as Parameters<NotificationPayloadReferenceGate['withDeliveryCurrent']>[2],
      async () => {
        calls++;
      },
    ),
  ).rejects.toThrow('Notification payload reference unavailable');
  expect(queries).toBe(0);
  expect(calls).toBe(0);
});
it('delivery input rejects accessors without reading them', async () => {
  let calls = 0;
  const value = Object.defineProperty({ ...deliverySource }, 'worker', {
    enumerable: true,
    get() {
      calls++;
      throw new Error('PRIVATE_CANARY');
    },
  });
  await expect(
    new NotificationPayloadReferenceGate('/must-not-open').withDeliveryCurrent(
      {} as PoolClient,
      {} as NotificationWorkerAdmission,
      value,
      async () => {
        calls++;
      },
    ),
  ).rejects.toThrow('Notification payload reference unavailable');
  expect(calls).toBe(0);
});
it('neither purpose assertion accepts constructed, copied or malformed historical metadata', () => {
  const client = {} as PoolClient;
  for (const value of [
    {},
    {
      preparation: { occurrenceId: deliverySource.notificationOccurrenceId },
      deliverySourceReceiptDigest: worker.installationDigest,
    },
  ]) {
    expect(() =>
      assertNotificationPayloadReference(value as unknown as NotificationPayloadReference, client),
    ).toThrow('Notification payload reference unavailable');
    expect(() =>
      assertNotificationDeliveryPayloadReference(
        value as unknown as NotificationDeliveryPayloadReference,
        client,
        deliverySource,
      ),
    ).toThrow('Notification payload reference unavailable');
  }
  let reads = 0;
  const accessor = Object.defineProperty({}, 'worker', {
    enumerable: true,
    get() {
      reads++;
      return worker;
    },
  });
  expect(() =>
    assertNotificationDeliveryPayloadReference(
      {} as NotificationDeliveryPayloadReference,
      client,
      accessor as typeof deliverySource,
    ),
  ).toThrow('Notification payload reference unavailable');
  expect(reads).toBe(0);
});

it('unwrap stage cannot be fabricated or borrow a local worker admission', async () => {
  let queries = 0,
    calls = 0;
  const client = {
    query() {
      queries++;
      throw new Error('PRIVATE_CANARY');
    },
  } as unknown as PoolClient;
  const gate = new NotificationPayloadReferenceGate('/must-not-open');
  await expect(
    gate.withDeliveryMaterialStage(
      client,
      {} as NotificationWorkerAdmission,
      deliverySource,
      async () => {
        calls++;
      },
    ),
  ).rejects.toThrow('Notification payload reference unavailable');
  expect(() =>
    assertNotificationDeliveryMaterialStage(
      { purpose: 'DELIVERY_UNWRAP_PREPARATION' } as NotificationDeliveryMaterialStage,
      client,
      deliverySource,
    ),
  ).toThrow('Notification payload reference unavailable');
  expect(queries).toBe(0);
  expect(calls).toBe(0);
});
