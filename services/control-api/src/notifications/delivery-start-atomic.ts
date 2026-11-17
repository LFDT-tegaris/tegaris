import { immutableJsonCopy } from '../privacy-explorer/immutable.js';
import {
  withNotificationWorkerLease,
  notificationWorkerLeaseSelector,
  type NotificationWorkerLeaseSelector,
} from './async-worker-state.js';
import { z } from 'zod';
import type { Pool, PoolClient } from 'pg';
import type { TLSSocket } from 'node:tls';
import type { IdentityKernel } from '../../../identity-service/src/domain/identity-kernel.js';
import { canonicalJson } from '../configuration/digest.js';
import type { NotificationPayloadReferenceGate } from './payload-reference.js';
import {
  encodeNotificationDeliveryStartTransition,
  decodeNotificationDeliveryStartTransition,
} from './delivery-start-transition.js';
import {
  notificationSigningTransition,
  NotificationDeliverySigningError,
  type NotificationDeliverySigningSelector,
} from './delivery-signing-contract.js';
import {
  withCurrentNotificationSigning,
  withNotificationSigningHistory,
  readNotificationSigningRecord,
} from './delivery-signing-state.js';
/** Retained claim metadata is historical state, never execution authority. */
export const notificationDeliveryDispatchClaim = z.discriminatedUnion('state', [
  z.strictObject({ state: z.literal('PENDING'), claimToken: z.null(), claimedAtMs: z.null() }),
  z.strictObject({
    state: z.literal('CLAIMED'),
    claimToken: z.string().regex(/^[0-9a-f]{64}$/u),
    claimedAtMs: z.number().int().min(0).max(Number.MAX_SAFE_INTEGER),
  }),
]);
export type NotificationDeliveryDispatchClaim = z.infer<typeof notificationDeliveryDispatchClaim>;
export function decodeNotificationDispatchClaim(row: {
  state: string;
  claim_token: string | null;
  claimed_at_ms: string | null;
}): NotificationDeliveryDispatchClaim {
  if (row.claimed_at_ms !== null && !/^(0|[1-9][0-9]*)$/u.test(row.claimed_at_ms))
    throw new NotificationDeliverySigningError();
  return notificationDeliveryDispatchClaim.parse({
    state: row.state,
    claimToken: row.claim_token,
    claimedAtMs: row.claimed_at_ms === null ? null : Number(row.claimed_at_ms),
  });
}
/** Original same-client readback; callers still own real scoped Identity admission. */
export async function readNotificationDeliveryStartInTransaction(
  client: PoolClient,
  q: NotificationDeliverySigningSelector,
) {
  const rows = await client.query<{
    transition_bytes: Buffer;
    transition_digest: string;
    receipt_payload: Buffer;
    cose_sign1: Buffer;
    receipt_digest: string;
    attempt_number: number;
    worker_credential_id: string;
    worker_credential_epoch: string;
    started_at_ms: string;
    dispatch_revision: string;
    dispatch_receipt_digest: string;
    dispatch_state: string;
    claim_token: string | null;
    claimed_at_ms: string | null;
  }>(
    `select s.transition_bytes,s.transition_digest,s.receipt_payload,s.cose_sign1,s.receipt_digest,
 a.attempt_number,a.worker_credential_id,a.worker_credential_epoch::text,a.started_at_ms::text,i.delivery_revision::text dispatch_revision,i.receipt_digest dispatch_receipt_digest,i.state dispatch_state,i.claim_token,i.claimed_at_ms::text
 from control.notification_delivery_start s join control.notification_delivery_attempt a on a.participant_id=s.participant_id and a.privacy_domain_id=s.privacy_domain_id and a.start_operation_id=s.operation_id and a.attempt_id=s.attempt_id and a.notification_occurrence_id=s.notification_occurrence_id and a.payload_digest=s.payload_digest
 join control.notification_delivery_dispatch_intent i on i.participant_id=s.participant_id and i.privacy_domain_id=s.privacy_domain_id and i.operation_id=s.operation_id and i.attempt_id=s.attempt_id and i.notification_occurrence_id=s.notification_occurrence_id and i.payload_digest=s.payload_digest
 where s.participant_id=$1 and s.privacy_domain_id=$2 and s.operation_id=$3`,
    [q.source.worker.participantId, q.source.worker.privacyDomainId, q.operationId],
  );
  if (!rows.rowCount) {
    const partial = await client.query(
      `select 1 from control.notification_delivery_start where participant_id=$1 and privacy_domain_id=$2 and operation_id=$3`,
      [q.source.worker.participantId, q.source.worker.privacyDomainId, q.operationId],
    );
    if (partial.rowCount) throw new NotificationDeliverySigningError();
    return null;
  }
  if (rows.rowCount !== 1) throw new NotificationDeliverySigningError();
  const signing = await readNotificationSigningRecord(client, q);
  if (!signing?.observation) throw new NotificationDeliverySigningError();
  const expected = notificationSigningTransition(signing.preparation, signing.observation),
    row = rows.rows[0]!,
    actual = decodeNotificationDeliveryStartTransition(row.transition_bytes, row.transition_digest),
    d = signing.preparation.deliveryPreparation;
  const encoded = encodeNotificationDeliveryStartTransition(expected);
  if (
    canonicalJson(actual) !== canonicalJson(expected) ||
    !encoded.receiptPayload.equals(row.receipt_payload) ||
    !encoded.coseSign1.equals(row.cose_sign1) ||
    encoded.receiptDigest !== row.receipt_digest ||
    row.attempt_number !== d.attempt.attemptNumber ||
    row.worker_credential_id !== d.workerCredentialId ||
    row.worker_credential_epoch !== d.workerEpoch ||
    row.started_at_ms !== String(d.attempt.startedAtMs) ||
    row.dispatch_revision !== (BigInt(d.before.revision) + 1n).toString() ||
    row.dispatch_receipt_digest !== row.receipt_digest ||
    canonicalJson(d.source) !== canonicalJson(q.source)
  )
    throw new NotificationDeliverySigningError();
  const claim = decodeNotificationDispatchClaim({
    state: row.dispatch_state,
    claim_token: row.claim_token,
    claimed_at_ms: row.claimed_at_ms,
  });
  if (
    claim.state === 'CLAIMED' &&
    (claim.claimedAtMs < d.attempt.startedAtMs ||
      claim.claimedAtMs >= Math.min(d.attempt.deadlineAtMs, d.authorityValidUntilMs))
  )
    throw new NotificationDeliverySigningError();
  return actual;
}
/** Historical original readback needs no fresh generation or receipt lifetime. */
export function readNotificationDeliveryStart(
  pool: Pool,
  kernel: IdentityKernel,
  socket: TLSSocket,
  value: unknown,
) {
  return withNotificationSigningHistory(
    pool,
    kernel,
    socket,
    value,
    readNotificationDeliveryStartInTransaction,
  );
}
/** One real transaction persists all four owners. Existing budget/attempt gates
 * stay closed until canonical registration explicitly composes the new checks.
 * There is no gateway/provider/material I/O, public event or early completion. */
export async function publishNotificationDeliveryStart(
  pool: Pool,
  kernel: IdentityKernel,
  socket: TLSSocket,
  gate: NotificationPayloadReferenceGate,
  value: unknown,
  lease?: NotificationWorkerLeaseSelector,
) {
  const prior = await readNotificationDeliveryStart(pool, kernel, socket, value);
  if (prior) return prior;
  try {
    return await withCurrentNotificationSigning(
      pool,
      kernel,
      socket,
      gate,
      value,
      async (client, q, p) => {
        const execute = async () => {
          await client.query('select openpc.assert_notification_delivery_start_atomic_owner()');
          const old = await readNotificationDeliveryStartInTransaction(client, q);
          if (old) return old;
          const signing = await readNotificationSigningRecord(client, q, true);
          if (
            !signing?.observation ||
            canonicalJson(signing.preparation.deliveryPreparation) !== canonicalJson(p)
          )
            throw new NotificationDeliverySigningError();
          const transition = notificationSigningTransition(
              signing.preparation,
              signing.observation,
            ),
            e = encodeNotificationDeliveryStartTransition(transition),
            r = transition.receipt;
          await client.query(
            `insert into control.notification_delivery_start(participant_id,privacy_domain_id,operation_id,receipt_id,attempt_id,notification_occurrence_id,payload_digest,delivery_revision,source_operation_id,worker_installation_digest,transition,transition_bytes,transition_digest,receipt_payload,receipt_digest,cose_sign1)
    values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)`,
            [
              r.participantId,
              r.privacyDomainId,
              r.operationId,
              r.receiptId,
              r.attemptId,
              r.notificationOccurrenceId,
              r.payloadDigest,
              r.deliveryRevision,
              p.sourceOperationId,
              p.source.worker.installationDigest,
              transition,
              e.transitionBytes,
              e.transitionDigest,
              e.receiptPayload,
              e.receiptDigest,
              e.coseSign1,
            ],
          );
          await client.query(
            `insert into control.notification_delivery_attempt(participant_id,privacy_domain_id,attempt_id,notification_occurrence_id,payload_digest,attempt_number,started_at_ms,worker_credential_id,worker_credential_epoch,start_operation_id)
    values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
            [
              r.participantId,
              r.privacyDomainId,
              r.attemptId,
              r.notificationOccurrenceId,
              r.payloadDigest,
              r.attemptNumber,
              r.startedAtMs,
              p.workerCredentialId,
              p.workerEpoch,
              r.operationId,
            ],
          );
          const projected = await client.query(
            `update control.notification_delivery set state='STARTED',attempt_count=$4,last_started_at_ms=$5,next_attempt_at_ms=null,revision=revision+1
    where participant_id=$1 and privacy_domain_id=$2 and notification_occurrence_id=$3 and revision=$6 and state=$7 and not cancel_requested returning notification_occurrence_id`,
            [
              r.participantId,
              r.privacyDomainId,
              r.notificationOccurrenceId,
              r.attemptNumber,
              r.startedAtMs,
              r.deliveryRevision,
              p.before.state,
            ],
          );
          if (projected.rowCount !== 1) throw new NotificationDeliverySigningError();
          await client.query(
            `insert into control.notification_delivery_dispatch_intent(participant_id,privacy_domain_id,operation_id,attempt_id,notification_occurrence_id,payload_digest,delivery_revision,receipt_digest)
    values($1,$2,$3,$4,$5,$6,$7,$8)`,
            [
              r.participantId,
              r.privacyDomainId,
              r.operationId,
              r.attemptId,
              r.notificationOccurrenceId,
              r.payloadDigest,
              (BigInt(r.deliveryRevision) + 1n).toString(),
              e.receiptDigest,
            ],
          );
          await client.query('select openpc.check_notification_delivery_start_complete($1)', [
            r.operationId,
          ]);
          return (await readNotificationDeliveryStartInTransaction(client, q))!;
        };
        return lease === undefined
          ? execute()
          : withNotificationWorkerLease(client, q.source, lease, 'STARTED', async () => {
              return execute();
            });
      },
      lease,
    );
  } catch (error) {
    // A competing committed original or uncertain COMMIT is recovered read-only.
    const committed = await readNotificationDeliveryStart(pool, kernel, socket, value);
    if (committed) return committed;
    throw error;
  }
}

/** Leased production entry; original API remains available to existing owners. */
export function publishNotificationDeliveryStartLeased(
  lease: unknown,
  pool: Pool,
  kernel: IdentityKernel,
  socket: TLSSocket,
  gate: NotificationPayloadReferenceGate,
  value: unknown,
) {
  return publishNotificationDeliveryStart(
    pool,
    kernel,
    socket,
    gate,
    value,
    notificationWorkerLeaseSelector.parse(immutableJsonCopy(lease)),
  );
}
