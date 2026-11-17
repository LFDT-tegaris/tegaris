import type { Pool, PoolClient } from 'pg';
import type { TLSSocket } from 'node:tls';
import { z } from 'zod';
import type { IdentityKernel } from '../../../identity-service/src/domain/identity-kernel.js';
import {
  withNotificationWorkerPeer,
  type NotificationWorkerAdmission,
} from '../../../identity-service/src/domain/notification-worker.js';
import { lockEvidenceLifecycle } from '../evidence/lifecycle-fence.js';
import {
  notificationDeliverySourceSelector,
  readPublishedNotificationDeliveryRequest,
  NotificationDeliverySourceError,
  type PublishedNotificationDeliveryRequest,
} from './delivery-source.js';
import { immutableJsonCopy } from '../privacy-explorer/immutable.js';

/** Trusted Control composition for source/STARTED database work only. The
 * existing peer owner retains actual TLS/Identity and installation fences and
 * performs its final current-authority check before COMMIT. No external I/O,
 * provider signing, credential consumption or payload disclosure belongs in this
 * callback. A returned source is historical proof, never a later dispatch lease.
 */
export async function withNotificationDeliveryRequest<T>(
  pool: Pool,
  kernel: IdentityKernel,
  socket: TLSSocket,
  value: unknown,
  operation: (
    client: PoolClient,
    admission: NotificationWorkerAdmission,
    source: PublishedNotificationDeliveryRequest,
  ) => Promise<T>,
): Promise<T> {
  try {
    const input = notificationDeliverySourceSelector.parse(immutableJsonCopy(value));
    return await withNotificationWorkerPeer(
      pool,
      kernel,
      socket,
      input.worker,
      async (client, admission) => {
        await client.query(
          "select set_config('openpc.action_intent_id','ACT-EVIDENCE_EXPORT_RECORDS-V1',true)",
        );
        await lockEvidenceLifecycle(
          client,
          input.worker.participantId,
          input.worker.privacyDomainId,
        );
        const source = await readPublishedNotificationDeliveryRequest(client, admission, input);
        const result = await operation(client, admission, source);
        await client.query(
          "select set_config('openpc.action_intent_id','ACT-POLICY_READ_EFFECTIVE_ACCESS-V1',true)",
        );
        return result;
      },
    );
  } catch {
    throw new NotificationDeliverySourceError();
  }
}

const currentConfiguration = z.strictObject({
  generation_id: z.uuidv7(),
  effective_digest: z.string().regex(/^sha256:[0-9a-f]{64}$/u),
  configured_limit: z.number().int().min(0).max(100),
});
export type NotificationDeliveryConfiguration = z.infer<typeof currentConfiguration>;

/** Admission for the pending durable STARTED owner. Read the environment from
 * the authenticated published source, never a caller-supplied cap or generation.
 * The SQL owner holds its shared generation fence until the same worker/Identity
 * transaction commits. An absent accepted generation prevents even preparation.
 * This callback still grants no signing, payload, provider or network authority;
 * endpoint/attempt admission and atomic STARTED persistence remain separate.
 */
export async function withNotificationDeliveryConfiguration<T>(
  pool: Pool,
  kernel: IdentityKernel,
  socket: TLSSocket,
  value: unknown,
  operation: (
    client: PoolClient,
    admission: NotificationWorkerAdmission,
    source: PublishedNotificationDeliveryRequest,
    configuration: NotificationDeliveryConfiguration,
  ) => Promise<T>,
): Promise<T> {
  return withNotificationDeliveryRequest(
    pool,
    kernel,
    socket,
    value,
    async (client, admission, source) => {
      const rows = await client.query(
        'select * from openpc.current_notification_delivery_limit($1)',
        [source.claims.environmentId],
      );
      if (rows.rowCount !== 1) throw new NotificationDeliverySourceError();
      const configuration = currentConfiguration.parse(rows.rows[0]);
      return operation(client, admission, source, configuration);
    },
  );
}
