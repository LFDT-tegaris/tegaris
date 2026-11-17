import type { Pool } from 'pg';
import type { TLSSocket } from 'node:tls';
import { z } from 'zod';
import type { IdentityKernel } from '../../../identity-service/src/domain/identity-kernel.js';
import { withNotificationDeliveryWorkerPeer } from '../../../identity-service/src/domain/notification-worker.js';
import { lockEvidenceLifecycle } from '../evidence/lifecycle-fence.js';
import { immutableJsonCopy } from '../privacy-explorer/immutable.js';
import { notificationWorkerSelector } from './worker-installation.js';
import { withCurrentNotificationRouting } from './routing-installation.js';
import type { NotificationDeliverySourceSelector } from './delivery-source.js';
import {
  withCurrentNotificationAsync,
  NotificationAsyncOwnerUnavailable,
} from './async-admission.js';
import { assertNotificationWorkerSchedule } from './async-worker-policy.js';
import type { NotificationAsyncInputClaims } from '../../../../packages/security-kernel/src/operations-configuration/notification-async.js';

/** Physical package ceilings are restrictions, never qualification or defaults.
 * A signed input exceeding one is rejected in full, not silently clamped. */
export const notificationConsumerCeilings = z.strictObject({
  poolMax: z.number().int().min(7).max(32),
  maximumConcurrency: z.number().int().min(1).max(6),
  maximumBatchSize: z.number().int().min(1).max(64),
  cycleTimeoutMs: z.number().int().min(1000).max(30000),
  connectionLifetimeMs: z.number().int().min(11000).max(300000),
});
export type NotificationConsumerCeilings = z.infer<typeof notificationConsumerCeilings>;
export class NotificationConsumerUnavailable extends Error {
  constructor(readonly code: 'INPUT' | 'CAPACITY' | 'SOURCE' | 'CURRENT' | 'STOPPED' = 'CURRENT') {
    super(`Notification consumer ${code}`);
  }
}
export function assertNotificationConsumerCapacity(
  value: unknown,
  input: NotificationAsyncInputClaims,
) {
  const c = notificationConsumerCeilings.parse(value);
  assertNotificationWorkerSchedule(input);
  // Per concurrent item: live delivery/material owner, KMS/secret owner, their
  // Identity admission, plus heartbeat; reserve one additional connection per
  // item and two scheduler/transport connections. No claim waits for a pool slot
  // held by its own enclosing callback. Runtime qualification still must measure
  // the exact deployed envelope and bound its actual workload.
  if (
    c.poolMax < 5 * input.concurrency + 2 ||
    input.concurrency > c.maximumConcurrency ||
    input.batchSize > c.maximumBatchSize ||
    input.leaseMs > c.cycleTimeoutMs ||
    input.attemptTimeoutMs > c.cycleTimeoutMs ||
    c.connectionLifetimeMs < 2 * c.cycleTimeoutMs + 10000
  )
    throw new NotificationConsumerUnavailable('CAPACITY');
  return c;
}
/** Real scope/current-native discovery. Neither mounted source IDs nor caller
 * readiness is accepted. Results are selectors/descriptors only; enqueue and
 * every effect reacquire their original live owners independently. */
export async function discoverNotificationDeliverySources(
  pool: Pool,
  kernel: IdentityKernel,
  socket: TLSSocket,
  workerValue: unknown,
  ceilingValue: unknown,
) {
  const worker = notificationWorkerSelector.parse(immutableJsonCopy(workerValue));
  const ceiling = notificationConsumerCeilings.parse(immutableJsonCopy(ceilingValue));
  let nativeMissing: NotificationAsyncOwnerUnavailable | undefined;
  try {
    return await withNotificationDeliveryWorkerPeer(
      pool,
      kernel,
      socket,
      worker,
      async (client, admission) => {
        await client.query(
          "select set_config('openpc.action_intent_id','ACT-EVIDENCE_EXPORT_RECORDS-V1',true)",
        );
        try {
          await lockEvidenceLifecycle(client, worker.participantId, worker.privacyDomainId);
          const profile = admission.installation.profile;
          const configuration = await client.query<{
            generation_id: string;
            effective_digest: string;
          }>(
            'select generation_id::text,effective_digest from openpc.current_notification_delivery_limit($1)',
            [profile.environmentId],
          );
          if (configuration.rowCount !== 1) throw new NotificationConsumerUnavailable();
          const tx = await client.query<{ request: string }>(
            'select openpc.current_operation_id()::text request',
          );
          try {
            return await withCurrentNotificationAsync(
              client,
              {
                participantId: worker.participantId,
                privacyDomainId: worker.privacyDomainId,
                environmentId: profile.environmentId,
                generationId: configuration.rows[0]!.generation_id,
                requestId: tx.rows[0]!.request,
                workerInstallationDigest: worker.installationDigest,
              },
              async (same, native) => {
                if (
                  same !== client ||
                  native.original.consumer.stage !== 'EFFECTIVE' ||
                  native.input.participantId !== worker.participantId ||
                  native.input.privacyDomainId !== worker.privacyDomainId ||
                  native.capacity.participantId !== worker.participantId ||
                  native.capacity.privacyDomainId !== worker.privacyDomainId ||
                  native.capacity.environmentId !== profile.environmentId ||
                  native.input.environmentId !== profile.environmentId ||
                  native.input.generationId !== configuration.rows[0]!.generation_id ||
                  native.committedGenerationDigest !== configuration.rows[0]!.effective_digest
                )
                  throw new NotificationConsumerUnavailable();
                assertNotificationConsumerCapacity(ceiling, native.input);
                // The retained installed route identifies this consumer's owner
                // scope even when its endpoint is no longer dispatchable. Do not
                // let one live worker quarantine another route's valid sources.
                const ownedRoute = await client.query<{ endpoint_id: string }>(
                  'select endpoint_id::text from control.installed_notification_routing where participant_id=$1 and privacy_domain_id=$2 and signed_profile_digest=$3',
                  [worker.participantId, worker.privacyDomainId, profile.routingProfileDigest],
                );
                if (ownedRoute.rowCount !== 1) throw new NotificationConsumerUnavailable('SOURCE');
                const candidates = await client.query<{
                  event_id: string;
                  notification_occurrence_id: string;
                }>(
                  `select e.event_id::text,n.notification_occurrence_id::text from control.outbox_event e
           join control.notification_occurrence n on n.participant_id=e.participant_id and n.privacy_domain_id=e.privacy_domain_id and n.notification_occurrence_id=e.aggregate_id
           left join control.notification_occurrence_observation proof on proof.participant_id=e.participant_id and proof.privacy_domain_id=e.privacy_domain_id and proof.operation_id=e.correlation_id
           left join control.notification_occurrence_preparation prep on prep.participant_id=proof.participant_id and prep.privacy_domain_id=proof.privacy_domain_id and prep.preparation_id=proof.preparation_id
           left join control.notification_async_work w on w.participant_id=e.participant_id and w.privacy_domain_id=e.privacy_domain_id and w.event_id=e.event_id
           where e.participant_id=$1 and e.privacy_domain_id=$2 and e.aggregate_type='notification-occurrence'
           and e.sequence_namespace='NOTIFICATION_DELIVERY_REQUESTED_V1' and n.endpoint_id=$9
           and (prep.preparation_id is null or prep.preparation->'workerProfile'->>'routingProfileDigest' is null or prep.preparation->'workerProfile'->>'routingProfileDigest'=$10)
           and (prep.preparation_id is null or prep.preparation->'workerProfile'->>'environmentId'=$3)
           and (w.event_id is null or (w.worker_installation_digest=$4 and w.generation_id=$5 and w.input_payload_digest=$6 and w.capacity_payload_digest=$7
            and (w.state='PENDING' or (w.state='RETRY_WAIT' and w.next_at_ms<=floor(extract(epoch from clock_timestamp())*1000))
             or (w.state in ('LEASED','RECONCILING') and w.lease_until_ms<=floor(extract(epoch from clock_timestamp())*1000))
             or (w.state='QUARANTINED' and w.charged and w.deadline_at_ms>floor(extract(epoch from clock_timestamp())*1000)))))
           order by (w.event_id is null),e.occurred_at,e.event_id limit $8`,
                  [
                    worker.participantId,
                    worker.privacyDomainId,
                    profile.environmentId,
                    worker.installationDigest,
                    native.input.generationId,
                    native.original.inputPayloadDigest,
                    native.original.capacityPayloadDigest,
                    native.input.batchSize,
                    ownedRoute.rows[0]!.endpoint_id,
                    profile.routingProfileDigest,
                  ],
                );
                const sources: NotificationDeliverySourceSelector[] = [];
                for (const row of candidates.rows) {
                  const source = {
                    worker,
                    eventId: row.event_id,
                    notificationOccurrenceId: row.notification_occurrence_id,
                  };
                  // Selectors are not admissions. The per-source enqueue owner
                  // verifies original publication and records its disposition
                  // in an independent transaction. One denied source must not
                  // roll back discovery of its independent siblings.
                  sources.push(source);
                }
                return immutableJsonCopy({
                  sources,
                  wakeMs: native.input.heartbeatMs,
                  cycleTimeoutMs: ceiling.cycleTimeoutMs,
                  authorityUntilMs: Math.min(
                    native.input.validUntilMs,
                    native.capacity.expiresAtMs,
                    profile.validUntilMs,
                  ),
                  processInstanceId: native.original.consumer.processInstanceId,
                });
              },
            );
          } catch (error) {
            if (error instanceof NotificationAsyncOwnerUnavailable) nativeMissing = error;
            throw error;
          }
        } finally {
          await client.query(
            "select set_config('openpc.action_intent_id','ACT-POLICY_READ_EFFECTIVE_ACCESS-V1',true)",
          );
        }
      },
    );
  } catch {
    if (nativeMissing) throw nativeMissing;
    throw new NotificationConsumerUnavailable();
  }
}

/** Resolve recipient authority only for actual execution. Historical source
 * disposition must not depend on a withdrawn endpoint remaining dispatchable. */
export async function readNotificationConsumerRecipient(
  pool: Pool,
  kernel: IdentityKernel,
  socket: TLSSocket,
  workerValue: unknown,
) {
  const worker = notificationWorkerSelector.parse(immutableJsonCopy(workerValue));
  return withNotificationDeliveryWorkerPeer(
    pool,
    kernel,
    socket,
    worker,
    async (client, admission) => {
      await client.query(
        "select set_config('openpc.action_intent_id','ACT-EVIDENCE_EXPORT_RECORDS-V1',true)",
      );
      try {
        await lockEvidenceLifecycle(client, worker.participantId, worker.privacyDomainId);
        const profile = admission.installation.profile;
        const routing = await client.query<{ profile_id: string; revision: string }>(
          'select profile_id::text,revision::text from control.installed_notification_routing where participant_id=$1 and privacy_domain_id=$2 and signed_profile_digest=$3',
          [worker.participantId, worker.privacyDomainId, profile.routingProfileDigest],
        );
        if (routing.rowCount !== 1) throw new NotificationConsumerUnavailable('SOURCE');
        return await withCurrentNotificationRouting(
          client,
          {
            participantId: worker.participantId,
            privacyDomainId: worker.privacyDomainId,
            profileId: routing.rows[0]!.profile_id,
            revision: routing.rows[0]!.revision,
            signedProfileDigest: profile.routingProfileDigest,
            producerTrustDigest: profile.producerTrustDigest,
          },
          async (route) => immutableJsonCopy(route.channel.credential),
        );
      } finally {
        await client.query(
          "select set_config('openpc.action_intent_id','ACT-POLICY_READ_EFFECTIVE_ACCESS-V1',true)",
        );
      }
    },
  );
}
