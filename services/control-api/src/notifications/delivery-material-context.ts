import {
  withNotificationWorkerLease,
  notificationWorkerLeaseSelector,
  type NotificationWorkerLeaseSelector,
  type NotificationWorkerLeaseWindow,
} from './async-worker-state.js';
import type { Pool, PoolClient } from 'pg';
import type { TLSSocket } from 'node:tls';
import type { IdentityKernel } from '../../../identity-service/src/domain/identity-kernel.js';
import {
  withNotificationDeliveryWorkerPeer,
  assertNotificationDeliveryWorkerCurrent,
  type NotificationWorkerAdmission,
} from '../../../identity-service/src/domain/notification-worker.js';
import { canonicalJson } from '../configuration/digest.js';
import { immutableJsonCopy } from '../privacy-explorer/immutable.js';
import { lockEvidenceLifecycle } from '../evidence/lifecycle-fence.js';
import {
  notificationDeliverySigningSelector,
  notificationSigningTransition,
  type NotificationDeliverySigningSelector,
} from './delivery-signing-contract.js';
import { readNotificationSigningRecord } from './delivery-signing-state.js';
import { decodeNotificationDeliveryStartTransition } from './delivery-start-transition.js';
import { readPublishedNotificationDeliveryRequest } from './delivery-source.js';
import { currentNotificationChannel } from './endpoint-admission.js';
import {
  NotificationPayloadReferenceGate,
  assertNotificationDeliveryMaterialStage,
  assertNotificationDeliveryPayloadReference,
  type NotificationDeliveryMaterialStage,
  type NotificationDeliveryPayloadReference,
} from './payload-reference.js';

export class NotificationDeliveryMaterialContextError extends Error {
  constructor() {
    super('Notification delivery material context unavailable');
  }
}
export interface NotificationDeliveryMaterialContext {
  readonly client: PoolClient;
  readonly admission: NotificationWorkerAdmission;
  readonly selector: NotificationDeliverySigningSelector;
  readonly original: ReturnType<typeof decodeNotificationDeliveryStartTransition>;
  readonly stage: NotificationDeliveryMaterialStage;
  readonly leaseWindow?: NotificationWorkerLeaseWindow;
  /** Rechecks real peer/source/configuration/cancellation/time under held fences. */
  assertCurrent(): Promise<void>;
  /** Call after the existing KMS unwrap promise commits. This acquires the
   * original-attempt lock; no further KMS exchanges may run inside this callback. */
  withCurrent<T>(use: (reference: NotificationDeliveryPayloadReference) => Promise<T>): Promise<T>;
}
const active = new WeakSet<object>();
export function assertNotificationDeliveryMaterialContext(
  value: NotificationDeliveryMaterialContext,
) {
  if (!active.has(value)) throw new NotificationDeliveryMaterialContextError();
}

/** Canonical live material boundary. Actual signed STARTED, current generation,
 * worker, published source, routing/endpoint and uncancelled delivery are required.
 * The staged gate leaves ONLY the KMS attempt row unlocked until unwrap commits.
 * This grants no gateway claim: the separate durable claim owner must authorize
 * every external send, and commit uncertainty remains an unknown external result.
 * No plaintext/key, external provider callback, retry or alternate authority here. */
export async function withNotificationDeliveryMaterialContext<T>(
  pool: Pool,
  kernel: IdentityKernel,
  socket: TLSSocket,
  gate: NotificationPayloadReferenceGate,
  value: unknown,
  operation: (context: NotificationDeliveryMaterialContext) => Promise<T>,
  lease?: NotificationWorkerLeaseSelector,
): Promise<T> {
  let claimedWindow: NotificationWorkerLeaseWindow | undefined;

  try {
    const q = notificationDeliverySigningSelector.parse(immutableJsonCopy(value));
    return await withNotificationDeliveryWorkerPeer(
      pool,
      kernel,
      socket,
      q.source.worker,
      async (client, admission) => {
        await client.query(
          "select set_config('openpc.action_intent_id','ACT-EVIDENCE_EXPORT_RECORDS-V1',true)",
        );
        try {
          const execute = async () => {
            const scope = [q.source.worker.participantId, q.source.worker.privacyDomainId];
            await lockEvidenceLifecycle(client, scope[0]!, scope[1]!);
            const signing = await readNotificationSigningRecord(client, q);
            if (!signing?.observation) throw new Error();
            const preparation = signing.preparation.deliveryPreparation;
            const expected = notificationSigningTransition(
              signing.preparation,
              signing.observation,
            );
            const stored = await client.query<{
              transition_bytes: Buffer;
              transition_digest: string;
            }>(
              `select transition_bytes,transition_digest from control.notification_delivery_start
             where participant_id=$1 and privacy_domain_id=$2 and operation_id=$3`,
              [...scope, q.operationId],
            );
            if (stored.rowCount !== 1) throw new Error();
            const original = decodeNotificationDeliveryStartTransition(
              stored.rows[0]!.transition_bytes,
              stored.rows[0]!.transition_digest,
            );
            if (
              canonicalJson(original) !== canonicalJson(expected) ||
              canonicalJson(preparation.source) !== canonicalJson(q.source) ||
              preparation.authorityDigest !== admission.authorityDigest
            )
              throw new Error();
            const current = async (checkDelivery = true) => {
              if (lease !== undefined)
                await withNotificationWorkerLease(
                  client,
                  q.source,
                  lease,
                  'MATERIAL',
                  async () => {},
                );
              await assertNotificationDeliveryWorkerCurrent(admission, client, q.source.worker);
              await client.query('select openpc.check_notification_delivery_start_complete($1)', [
                q.operationId,
              ]);
              const source = await readPublishedNotificationDeliveryRequest(
                client,
                admission,
                q.source,
              );
              if (
                source.sourceReceiptDigest !== preparation.sourceReceiptDigest ||
                source.sourceOperationId !== preparation.sourceOperationId
              )
                throw new Error();
              const configuration = await client.query<{
                generation_id: string;
                effective_digest: string;
                configured_limit: number;
              }>('select * from openpc.current_notification_delivery_limit($1)', [
                source.claims.environmentId,
              ]);
              const c = configuration.rows[0];
              if (
                configuration.rowCount !== 1 ||
                c?.generation_id !== preparation.generationId ||
                c.effective_digest !== preparation.effectiveDigest ||
                c.configured_limit !== preparation.configuredLimit ||
                c.configured_limit === 0
              )
                throw new Error();
              const channel = await currentNotificationChannel(
                client,
                source.claims,
                preparation.attempt.credentialRef,
              );
              if (canonicalJson(channel.channel) !== canonicalJson(preparation.channel))
                throw new Error();
              if (!checkDelivery) return;
              // FOR SHARE excludes committed cancellation/terminal/revision changes
              // throughout unwrap and gateway use without blocking KMS exchanges.
              const delivery = await client.query(
                `select 1 from control.notification_delivery
              where participant_id=$1 and privacy_domain_id=$2 and notification_occurrence_id=$3
                and state='STARTED' and not cancel_requested and revision=$4 and payload_digest=$5
                and attempt_count=$6 and last_started_at_ms=$7 and attempt_limit=$8
                and delivery_request_event_id=$9 and delivery_request_operation_id=$10
                and budget_environment_id=$11 and budget_generation_id=$12 and budget_effective_digest=$13
                and budget_configured_limit=$14 and budget_worker_installation_digest=$15
                and floor(extract(epoch from clock_timestamp())*1000)>=$7
                and floor(extract(epoch from clock_timestamp())*1000)<$16
                and floor(extract(epoch from clock_timestamp())*1000)<$17
              for share`,
                [
                  ...scope,
                  q.source.notificationOccurrenceId,
                  (BigInt(preparation.before.revision) + 1n).toString(),
                  preparation.attempt.payloadDigest,
                  preparation.attempt.attemptNumber,
                  preparation.attempt.startedAtMs,
                  preparation.plannedAfter.attemptLimit,
                  q.source.eventId,
                  preparation.sourceOperationId,
                  preparation.before.budgetEnvironmentId,
                  preparation.before.budgetGenerationId,
                  preparation.before.budgetEffectiveDigest,
                  preparation.before.budgetConfiguredLimit,
                  preparation.before.budgetWorkerInstallationDigest,
                  preparation.attempt.deadlineAtMs,
                  preparation.authorityValidUntilMs,
                ],
              );
              if (delivery.rowCount !== 1) throw new Error();
            };
            await current(false);
            return await gate.withDeliveryMaterialStage(
              client,
              admission,
              q.source,
              async (stage) => {
                assertNotificationDeliveryMaterialStage(stage, client, q.source);
                await current();
                let finalized = false,
                  completed = false;
                const context: NotificationDeliveryMaterialContext = Object.freeze({
                  client,
                  admission,
                  selector: q,
                  original,
                  stage,
                  ...(claimedWindow ? { leaseWindow: claimedWindow } : {}),
                  async assertCurrent() {
                    assertNotificationDeliveryMaterialContext(context);
                    await current();
                  },
                  async withCurrent<R>(
                    use: (reference: NotificationDeliveryPayloadReference) => Promise<R>,
                  ): Promise<R> {
                    assertNotificationDeliveryMaterialContext(context);
                    if (finalized) throw new NotificationDeliveryMaterialContextError();
                    finalized = true;
                    await current();
                    const result = await gate.withDeliveryCurrent(
                      client,
                      admission,
                      q.source,
                      async (reference) => {
                        assertNotificationDeliveryPayloadReference(reference, client, q.source);
                        const { purpose, ...originalStage } = stage;
                        if (purpose !== 'DELIVERY_UNWRAP_PREPARATION') throw new Error();
                        if (canonicalJson(reference) !== canonicalJson(originalStage))
                          throw new Error();
                        const result = await use(reference);
                        await current();
                        return result;
                      },
                    );
                    completed = true;
                    return result;
                  },
                });
                active.add(context);
                try {
                  const result = await operation(context);
                  if (!completed) throw new Error();
                  await current();
                  return result;
                } finally {
                  active.delete(context);
                }
              },
            );
          };
          return await (lease === undefined
            ? execute()
            : withNotificationWorkerLease(client, q.source, lease, 'MATERIAL', async (window) => {
                claimedWindow = window;
                return execute();
              }));
        } finally {
          await client.query(
            "select set_config('openpc.action_intent_id','ACT-POLICY_READ_EFFECTIVE_ACCESS-V1',true)",
          );
        }
      },
    );
  } catch {
    throw new NotificationDeliveryMaterialContextError();
  }
}

/** Leased production entry; original API remains available to existing owners. */
export function withNotificationDeliveryMaterialContextLeased<T>(
  lease: unknown,
  pool: Pool,
  kernel: IdentityKernel,
  socket: TLSSocket,
  gate: NotificationPayloadReferenceGate,
  value: unknown,
  operation: (context: NotificationDeliveryMaterialContext) => Promise<T>,
) {
  return withNotificationDeliveryMaterialContext(
    pool,
    kernel,
    socket,
    gate,
    value,
    operation,
    notificationWorkerLeaseSelector.parse(immutableJsonCopy(lease)),
  );
}
