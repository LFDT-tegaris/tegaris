import {
  withNotificationWorkerLease,
  notificationWorkerLeaseSelector,
  type NotificationWorkerLeaseSelector,
} from './async-worker-state.js';
import { randomBytes } from 'node:crypto';
import type { Pool, PoolClient } from 'pg';
import type { TLSSocket } from 'node:tls';
import { z } from 'zod';
import type { IdentityKernel } from '../../../identity-service/src/domain/identity-kernel.js';
import { assertNotificationDeliveryWorkerAdmission } from '../../../identity-service/src/domain/notification-worker.js';
import { canonicalJson } from '../configuration/digest.js';
import { immutableJsonCopy } from '../privacy-explorer/immutable.js';
import { withNotificationDeliveryRequest } from './delivery-admission.js';
import { currentNotificationChannel } from './endpoint-admission.js';
import {
  NotificationPayloadReferenceGate,
  assertNotificationDeliveryPayloadReference,
} from './payload-reference.js';
import {
  notificationDeliverySigningSelector,
  type NotificationDeliverySigningSelector,
} from './delivery-signing-contract.js';
import {
  readNotificationSigningRecord,
  withNotificationSigningHistory,
} from './delivery-signing-state.js';
import {
  decodeNotificationDispatchClaim,
  readNotificationDeliveryStartInTransaction,
  type NotificationDeliveryDispatchClaim,
} from './delivery-start-atomic.js';
import type { NotificationDeliveryStartTransition } from './delivery-start-transition.js';

export class NotificationDeliveryDispatchError extends Error {
  constructor() {
    super('Notification delivery dispatch unavailable');
  }
}
export interface NotificationDeliveryDispatchRecord {
  readonly original: NotificationDeliveryStartTransition;
  readonly claim: NotificationDeliveryDispatchClaim;
}
/** Opaque local ownership only. It is not a live material/credential/send grant. */
declare const capabilityBrand: unique symbol;
export interface NotificationDispatchCapability {
  readonly [capabilityBrand]: true;
}
const capabilities = new WeakMap<
  NotificationDispatchCapability,
  { selector: string; record: NotificationDeliveryDispatchRecord }
>();
export type NotificationDeliveryDispatchResult =
  | {
      readonly state: 'CLAIMED';
      readonly record: NotificationDeliveryDispatchRecord;
      readonly capability: NotificationDispatchCapability;
    }
  | { readonly state: 'LOOKUP'; readonly record: NotificationDeliveryDispatchRecord }
  | {
      readonly state: 'WAIT';
      readonly reason: 'ZERO_CAPACITY';
      readonly record: NotificationDeliveryDispatchRecord;
    };
const configuration = z.strictObject({
  generation_id: z.uuidv7(),
  effective_digest: z.string().regex(/^sha256:[0-9a-f]{64}$/u),
  configured_limit: z.number().int().min(0).max(100),
});

async function read(
  client: PoolClient,
  q: NotificationDeliverySigningSelector,
  locked = false,
): Promise<NotificationDeliveryDispatchRecord> {
  const original = await readNotificationDeliveryStartInTransaction(client, q);
  if (!original) throw new NotificationDeliveryDispatchError();
  const rows = await client.query<{
    state: string;
    claim_token: string | null;
    claimed_at_ms: string | null;
  }>(
    `select state,claim_token,claimed_at_ms::text from control.notification_delivery_dispatch_intent
     where participant_id=$1 and privacy_domain_id=$2 and operation_id=$3 ${locked ? 'for update' : ''}`,
    [q.source.worker.participantId, q.source.worker.privacyDomainId, q.operationId],
  );
  if (rows.rowCount !== 1) throw new NotificationDeliveryDispatchError();
  return immutableJsonCopy({ original, claim: decodeNotificationDispatchClaim(rows.rows[0]!) });
}
/** Restart/reconciliation readback. Even PENDING or an expired original never
 * yields a capability from this path. Current generation and KMS are unnecessary. */
export async function readNotificationDeliveryDispatch(
  pool: Pool,
  kernel: IdentityKernel,
  socket: TLSSocket,
  value: unknown,
) {
  try {
    return await withNotificationSigningHistory(pool, kernel, socket, value, (client, q) =>
      read(client, q),
    );
  } catch {
    throw new NotificationDeliveryDispatchError();
  }
}
/** Consume once, inside the later live material owner's independently authorized
 * callback. A copied descriptor, selector mismatch, replay or recovered record
 * cannot be exchanged for local ownership. No network or material access here. */
export function consumeNotificationDispatchCapability(
  capability: NotificationDispatchCapability,
  value: unknown,
): NotificationDeliveryDispatchRecord {
  const saved = capabilities.get(capability);
  capabilities.delete(capability);
  if (!saved || saved.selector !== canonicalJson(notificationDeliverySigningSelector.parse(value)))
    throw new NotificationDeliveryDispatchError();
  return saved.record;
}

/** One real post-STARTED transaction; no signer-current/pre-STARTED admission.
 * Lock order matches preparation: worker/Identity -> lifecycle -> generation ->
 * custody/KMS attempt -> routing/channel -> delivery -> dispatch intent.
 * The return from the peer owner includes COMMIT and its final authority check.
 * Cancellation has no supported mutation owner yet; this is NOT a send entrypoint. */
export async function claimNotificationDeliveryDispatch(
  pool: Pool,
  kernel: IdentityKernel,
  socket: TLSSocket,
  gate: NotificationPayloadReferenceGate,
  value: unknown,
  lease?: NotificationWorkerLeaseSelector,
): Promise<NotificationDeliveryDispatchResult> {
  let q: NotificationDeliverySigningSelector;
  try {
    q = notificationDeliverySigningSelector.parse(immutableJsonCopy(value));
  } catch {
    throw new NotificationDeliveryDispatchError();
  }
  let mutationAttempted = false;
  try {
    const result = await withNotificationDeliveryRequest(
      pool,
      kernel,
      socket,
      q.source,
      async (client, admission, source) => {
        const execute = async () => {
          assertNotificationDeliveryWorkerAdmission(admission, client, q.source.worker);
          await client.query('select openpc.assert_notification_delivery_dispatch_owner()');
          const prior = await read(client, q);
          if (prior.claim.state === 'CLAIMED') return { state: 'LOOKUP' as const, record: prior };
          const signing = await readNotificationSigningRecord(client, q);
          if (!signing?.observation) throw new NotificationDeliveryDispatchError();
          const p = signing.preparation.deliveryPreparation;
          if (
            p.authorityDigest !== admission.authorityDigest ||
            source.sourceReceiptDigest !== p.sourceReceiptDigest ||
            source.sourceOperationId !== p.sourceOperationId
          )
            throw new NotificationDeliveryDispatchError();
          const configs = await client.query(
            'select * from openpc.current_notification_delivery_limit($1)',
            [source.claims.environmentId],
          );
          if (configs.rowCount !== 1) throw new NotificationDeliveryDispatchError();
          const current = configuration.parse(configs.rows[0]);
          if (current.configured_limit === 0)
            return { state: 'WAIT' as const, reason: 'ZERO_CAPACITY' as const, record: prior };
          if (
            current.generation_id !== p.generationId ||
            current.effective_digest !== p.effectiveDigest ||
            current.configured_limit !== p.configuredLimit
          )
            throw new NotificationDeliveryDispatchError();
          return gate.withDeliveryCurrent(client, admission, q.source, async (reference) => {
            assertNotificationDeliveryPayloadReference(reference, client, q.source);
            const channel = await currentNotificationChannel(
              client,
              source.claims,
              p.attempt.credentialRef,
            );
            if (canonicalJson(channel.channel) !== canonicalJson(p.channel))
              throw new NotificationDeliveryDispatchError();
            // SQL rechecks the native retained bindings, current authority and exact
            // post-STARTED projection, taking the delivery row before the intent.
            await client.query('select openpc.check_notification_delivery_dispatch_current($1)', [
              q.operationId,
            ]);
            const original = await read(client, q, true);
            if (original.claim.state === 'CLAIMED')
              return { state: 'LOOKUP' as const, record: original };
            const token = randomBytes(32).toString('hex');
            mutationAttempted = true;
            const changed = await client.query(
              `update control.notification_delivery_dispatch_intent set state='CLAIMED',claim_token=$4,claimed_at_ms=floor(extract(epoch from clock_timestamp())*1000)
          where participant_id=$1 and privacy_domain_id=$2 and operation_id=$3 and state='PENDING' and claim_token is null and claimed_at_ms is null returning operation_id`,
              [
                q.source.worker.participantId,
                q.source.worker.privacyDomainId,
                q.operationId,
                token,
              ],
            );
            if (changed.rowCount !== 1) throw new NotificationDeliveryDispatchError();
            const record = await read(client, q);
            if (record.claim.state !== 'CLAIMED' || record.claim.claimToken !== token)
              throw new NotificationDeliveryDispatchError();
            return { state: 'CLAIMED' as const, record };
          });
        };
        return lease === undefined
          ? execute()
          : withNotificationWorkerLease(client, q.source, lease, 'GATEWAY', async () => {
              return execute();
            });
      },
    );
    if (result.state !== 'CLAIMED') return result;
    // Never move this mint into the callback: COMMIT may fail or lose its ACK.
    const capability = Object.freeze(Object.create(null)) as NotificationDispatchCapability;
    capabilities.set(capability, { selector: canonicalJson(q), record: result.record });
    return { ...result, capability };
  } catch {
    if (mutationAttempted) {
      // This invocation cannot try again, even if readback still says PENDING.
      // A failed readback remains unavailable; it cannot manufacture authority.
      const record = await readNotificationDeliveryDispatch(pool, kernel, socket, q);
      return { state: 'LOOKUP', record };
    }
    throw new NotificationDeliveryDispatchError();
  }
}

/** Leased production entry; original API remains available to existing owners. */
export function claimNotificationDeliveryDispatchLeased(
  lease: unknown,
  pool: Pool,
  kernel: IdentityKernel,
  socket: TLSSocket,
  gate: NotificationPayloadReferenceGate,
  value: unknown,
) {
  return claimNotificationDeliveryDispatch(
    pool,
    kernel,
    socket,
    gate,
    value,
    notificationWorkerLeaseSelector.parse(immutableJsonCopy(lease)),
  );
}
