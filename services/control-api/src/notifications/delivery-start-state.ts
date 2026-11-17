import {
  withNotificationWorkerLease,
  notificationWorkerLeaseSelector,
  type NotificationWorkerLeaseSelector,
} from './async-worker-state.js';
import type { Pool, PoolClient } from 'pg';
import type { TLSSocket } from 'node:tls';
import { z } from 'zod';
import type { IdentityKernel } from '../../../identity-service/src/domain/identity-kernel.js';
import { assertNotificationDeliveryWorkerAdmission } from '../../../identity-service/src/domain/notification-worker.js';
import { immutableJsonCopy } from '../privacy-explorer/immutable.js';
import {
  withNotificationDeliveryConfiguration,
  type NotificationDeliveryConfiguration,
} from './delivery-admission.js';
import {
  notificationDeliverySourceSelector,
  type PublishedNotificationDeliveryRequest,
} from './delivery-source.js';
import { currentNotificationChannel } from './endpoint-admission.js';
import {
  assertNotificationEndpointVerificationState,
  readNotificationEndpointBusinessState,
  type NotificationEndpointVerificationBinding,
} from './endpoint-business-state.js';
import { notificationRevision } from './endpoint-binding.js';
import { notificationDeliverySnapshot } from './delivery-policy.js';

const digest = z.string().regex(/^sha256:[0-9a-f]{64}$/u);
const configurationInput = z.strictObject({
  generation_id: z.uuidv7(),
  effective_digest: digest,
  configured_limit: z.number().int().min(0).max(100),
});
export const notificationDeliveryBudgetRecord = notificationDeliverySnapshot
  .safeExtend({
    revision: notificationRevision,
    deliveryRequestEventId: z.uuidv7(),
    deliveryRequestOperationId: z.uuidv7(),
    budgetEnvironmentId: z.string().regex(/^[a-zA-Z0-9][a-zA-Z0-9:._-]{0,159}$/u),
    budgetGenerationId: z.uuidv7(),
    budgetEffectiveDigest: digest,
    budgetConfiguredLimit: z.number().int().min(0).max(100),
    budgetWorkerInstallationDigest: digest,
  })
  .refine((p) => p.attemptLimit <= Math.min(p.budgetConfiguredLimit, 6));
export type NotificationDeliveryBudgetRecord = z.infer<typeof notificationDeliveryBudgetRecord>;
export class NotificationDeliveryBudgetError extends Error {
  constructor() {
    super('Notification delivery budget unavailable');
  }
}

/** Pure cap projection, never admission. In particular, do not call the delivery
 * policy planner here: its START/terminal proposals are not budget mutations.
 * Provenance identifies the generation that last lowered this lifetime ceiling.
 * Observing an equal/higher cap has no revision or provenance effect. */
export function lowerNotificationDeliveryBudget(
  value: NotificationDeliveryBudgetRecord,
  configuration: NotificationDeliveryConfiguration,
  workerInstallationDigest: string,
): NotificationDeliveryBudgetRecord {
  try {
    const before = notificationDeliveryBudgetRecord.parse(immutableJsonCopy(value));
    const current = configurationInput.parse(immutableJsonCopy(configuration));
    digest.parse(workerInstallationDigest);
    const attemptLimit = Math.min(before.attemptLimit, current.configured_limit, 6);
    if (attemptLimit === before.attemptLimit) return before;
    const revision = BigInt(before.revision) + 1n;
    return notificationDeliveryBudgetRecord.parse({
      ...before,
      attemptLimit,
      revision: revision.toString(),
      budgetGenerationId: current.generation_id,
      budgetEffectiveDigest: current.effective_digest,
      budgetConfiguredLimit: current.configured_limit,
      budgetWorkerInstallationDigest: workerInstallationDigest,
    });
  } catch {
    throw new NotificationDeliveryBudgetError();
  }
}

const projection = `participant_id::text as "participantId",privacy_domain_id::text as "privacyDomainId",
 notification_occurrence_id::text as "notificationOccurrenceId",payload_digest as "payloadDigest",
 state,attempt_count as "attemptCount",attempt_limit as "attemptLimit",
 next_attempt_at_ms::float8 as "nextAttemptAtMs",last_started_at_ms::float8 as "lastStartedAtMs",
 cancel_requested as "cancelRequested",revision::text,
 delivery_request_event_id::text as "deliveryRequestEventId",delivery_request_operation_id::text as "deliveryRequestOperationId",
 budget_environment_id as "budgetEnvironmentId",budget_generation_id::text as "budgetGenerationId",
 budget_effective_digest as "budgetEffectiveDigest",budget_configured_limit as "budgetConfiguredLimit",
 budget_worker_installation_digest as "budgetWorkerInstallationDigest"`;

async function endpoint(client: PoolClient, source: PublishedNotificationDeliveryRequest) {
  const p = source.claims;
  // Discover immutable credential identity before any business row locks.
  const occurrence = await client.query<{ credential_ref: string; verification_id: string }>(
    `select credential_ref,verification_id from control.notification_occurrence
     where participant_id=$1 and privacy_domain_id=$2 and notification_occurrence_id=$3
     and endpoint_id=$4 and endpoint_revision=$5 and payload_digest=$6`,
    [
      p.participantId,
      p.privacyDomainId,
      p.notificationOccurrenceId,
      p.endpointId,
      p.endpointRevision,
      p.payloadDigest,
    ],
  );
  if (occurrence.rowCount !== 1) throw new NotificationDeliveryBudgetError();
  const row = occurrence.rows[0]!;
  const installed = await currentNotificationChannel(client, p, row.credential_ref);
  const scope = {
    participantId: p.participantId,
    privacyDomainId: p.privacyDomainId,
    aggregateId: p.endpointId,
  };
  await client.query(
    `select endpoint_id from control.notification_endpoint
    where participant_id=$1 and privacy_domain_id=$2 and endpoint_id=$3 for share`,
    [p.participantId, p.privacyDomainId, p.endpointId],
  );
  const state = await readNotificationEndpointBusinessState(client, scope, 'NONE');
  if (
    !state ||
    state.revision !== p.endpointRevision ||
    state.credentialRef !== row.credential_ref ||
    state.verificationId !== row.verification_id ||
    state.channelProfileDigest !== installed.channel.signedProfileDigest ||
    state.channel !== installed.credential.channel ||
    state.destinationRef !== installed.credential.destinationRef ||
    installed.channel.claims.environmentId !== p.environmentId
  )
    throw new NotificationDeliveryBudgetError();
  const verified = await client.query<NotificationEndpointVerificationBinding>(
    `select participant_id::text as "participantId",privacy_domain_id::text as "privacyDomainId",
     endpoint_id::text as "endpointId",endpoint_revision::text as revision,channel,destination_ref as "destinationRef",
     channel_profile_digest as "channelProfileDigest",credential_ref as "credentialRef",verification_id::text as "verificationId"
     from control.notification_endpoint_verification where participant_id=$1 and privacy_domain_id=$2 and verification_id=$3`,
    [p.participantId, p.privacyDomainId, row.verification_id],
  );
  if (verified.rowCount !== 1) throw new NotificationDeliveryBudgetError();
  assertNotificationEndpointVerificationState(scope, state, verified.rows[0]!);
}

/** The only effectful entrypoint. Source-only input enters the existing real
 * TLS/Identity, source and current-configuration owners. No injected admission,
 * configuration, signer, credential material or provider callback is accepted.
 * Resolution occurs only after the containing transaction's final checks/commit.
 * Missing schema/guards/grants/configuration fails closed; no fallback state. */
export async function synchronizeNotificationDeliveryBudget(
  pool: Pool,
  kernel: IdentityKernel,
  socket: TLSSocket,
  value: unknown,
  lease?: NotificationWorkerLeaseSelector,
): Promise<NotificationDeliveryBudgetRecord> {
  try {
    const input = notificationDeliverySourceSelector.parse(immutableJsonCopy(value));
    return await withNotificationDeliveryConfiguration(
      pool,
      kernel,
      socket,
      input,
      async (client, admission, source, configuration) => {
        const execute = async () => {
          assertNotificationDeliveryWorkerAdmission(admission, client, input.worker);
          await client.query('select openpc.assert_notification_delivery_budget_owner()');
          await endpoint(client, source);
          const p = source.claims;
          const keys = [p.participantId, p.privacyDomainId, p.notificationOccurrenceId];
          // The authenticated source owner holds the existing exclusive Evidence
          // lifecycle fence through commit, serializing an absent delivery row as
          // well as initialization. The immutable occurrence needs no UPDATE grant.
          const selected = await client.query(
            `select ${projection} from control.notification_delivery
          where participant_id=$1 and privacy_domain_id=$2 and notification_occurrence_id=$3 for update`,
            keys,
          );
          let result: NotificationDeliveryBudgetRecord;
          if (selected.rowCount === 0) {
            const inserted = await client.query(
              `insert into control.notification_delivery
            (participant_id,privacy_domain_id,notification_occurrence_id,payload_digest,
             delivery_request_event_id,delivery_request_operation_id,budget_environment_id,
             budget_generation_id,budget_effective_digest,budget_configured_limit,budget_worker_installation_digest,
             state,attempt_count,attempt_limit,next_attempt_at_ms,last_started_at_ms,cancel_requested,revision)
            values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,'PENDING',0,least($10,6),
             floor(extract(epoch from statement_timestamp())*1000),null,false,1) returning ${projection}`,
              [
                ...keys,
                p.payloadDigest,
                p.eventId,
                p.operationId,
                p.environmentId,
                configuration.generation_id,
                configuration.effective_digest,
                configuration.configured_limit,
                admission.installation.installationDigest,
              ],
            );
            if (inserted.rowCount !== 1) throw new NotificationDeliveryBudgetError();
            result = notificationDeliveryBudgetRecord.parse(inserted.rows[0]);
          } else {
            if (selected.rowCount !== 1) throw new NotificationDeliveryBudgetError();
            const before = notificationDeliveryBudgetRecord.parse(selected.rows[0]);
            if (
              before.payloadDigest !== p.payloadDigest ||
              before.deliveryRequestEventId !== p.eventId ||
              before.deliveryRequestOperationId !== p.operationId ||
              before.budgetEnvironmentId !== p.environmentId
            )
              throw new NotificationDeliveryBudgetError();
            result = lowerNotificationDeliveryBudget(
              before,
              configuration,
              admission.installation.installationDigest,
            );
            if (result.revision !== before.revision) {
              const updated = await client.query(
                `update control.notification_delivery set attempt_limit=$4,revision=$5,
              budget_generation_id=$6,budget_effective_digest=$7,budget_configured_limit=$8,budget_worker_installation_digest=$9
              where participant_id=$1 and privacy_domain_id=$2 and notification_occurrence_id=$3 and revision=$10
              returning ${projection}`,
                [
                  ...keys,
                  result.attemptLimit,
                  result.revision,
                  result.budgetGenerationId,
                  result.budgetEffectiveDigest,
                  result.budgetConfiguredLimit,
                  result.budgetWorkerInstallationDigest,
                  before.revision,
                ],
              );
              if (updated.rowCount !== 1) throw new NotificationDeliveryBudgetError();
              result = notificationDeliveryBudgetRecord.parse(updated.rows[0]);
            }
          }
          await endpoint(client, source);
          return immutableJsonCopy(result);
        };
        return lease === undefined
          ? execute()
          : withNotificationWorkerLease(client, input, lease, 'PREPARE', async () => {
              return execute();
            });
      },
    );
  } catch {
    throw new NotificationDeliveryBudgetError();
  }
}

/** Leased production entry; original API remains available to existing owners. */
export function synchronizeNotificationDeliveryBudgetLeased(
  lease: unknown,
  pool: Pool,
  kernel: IdentityKernel,
  socket: TLSSocket,
  value: unknown,
) {
  return synchronizeNotificationDeliveryBudget(
    pool,
    kernel,
    socket,
    value,
    notificationWorkerLeaseSelector.parse(immutableJsonCopy(lease)),
  );
}
