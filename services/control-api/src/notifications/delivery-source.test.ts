import { Client, type PoolClient } from 'pg';
import { expect, it } from 'vitest';
import type { NotificationWorkerAdmission } from '../../../identity-service/src/domain/notification-worker.js';
import {
  readHistoricalNotificationDeliveryRequest,
  readPublishedNotificationDeliveryRequest,
} from './delivery-source.js';

const id = '01900000-0000-7000-8000-000000000001';
const source = {
  worker: {
    participantId: id,
    privacyDomainId: id,
    installationDigest: `sha256:${'a'.repeat(64)}`,
  },
  notificationOccurrenceId: id,
  eventId: id,
};
// Actual unconnected client: copied metadata must fail at the private live
// admission registry before any SQL. These are denials, not historical proof.
it.each([readHistoricalNotificationDeliveryRequest, readPublishedNotificationDeliveryRequest])(
  'requires a genuine live worker admission before original publication reads (%#)',
  async (read) => {
    const client = new Client() as PoolClient;
    for (const admission of [
      {},
      {
        installation: {
          profile: {
            ...source.worker,
            serviceId: 'LS-NOTIFICATION',
            processRole: 'ROLE-NOTIFICATION-WORKER',
            subscriptionId: 'SUB-NOTIFICATIONDELIVERYREQUESTED-NOTIFICATION-V1',
          },
        },
        authorityDigest: source.worker.installationDigest,
      },
    ]) {
      await expect(
        read(client, admission as unknown as NotificationWorkerAdmission, source),
      ).rejects.toThrow('Notification delivery source unavailable');
    }
    await client.end();
  },
);
it('does not accept a caller historical or dispatch exemption on a source selector', async () => {
  const client = new Client() as PoolClient;
  for (const extra of [{ historical: true }, { admitted: true }, { quarantine: true }])
    await expect(
      readHistoricalNotificationDeliveryRequest(client, {} as NotificationWorkerAdmission, {
        ...source,
        ...extra,
      }),
    ).rejects.toThrow();
  await client.end();
});
