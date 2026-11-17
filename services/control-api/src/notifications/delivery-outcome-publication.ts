import {
  withNotificationWorkerLease,
  notificationWorkerLeaseSelector,
  type NotificationWorkerLeaseSelector,
} from './async-worker-state.js';
import {
  businessSourceSelect,
  verifyBusinessSource,
  type BusinessSourceRow,
} from '../evidence/business-source.js';
import type { Pool, PoolClient } from 'pg';
import type { TLSSocket } from 'node:tls';
import { z } from 'zod';
import type { IdentityKernel } from '../../../identity-service/src/domain/identity-kernel.js';
import {
  withNotificationDeliveryWorkerPeer,
  assertNotificationDeliveryWorkerCurrent,
  type NotificationWorkerAdmission,
} from '../../../identity-service/src/domain/notification-worker.js';
import { lockEvidenceLifecycle } from '../evidence/lifecycle-fence.js';
import { immutableJsonCopy } from '../privacy-explorer/immutable.js';
import { canonicalJson, sha256 } from '../configuration/digest.js';
import { readPublishedNotificationDeliveryRequest } from './delivery-source.js';
import {
  withNotificationDeliveryResultAuthority,
  assertNotificationDeliveryResultAuthority,
} from './delivery-result-admission.js';
import {
  notificationOutcomeSigningSelector,
  readNotificationOutcomeInputInTransaction,
  readNotificationOutcomeSigningInTransaction,
  notificationOutcomeSigningTransition,
  decodeNotificationSignedOutcomeRow,
  type NotificationOutcomeSigningSelector,
  type NotificationOutcomeObservationRow,
  type NotificationSignedOutcomeRow,
} from './delivery-outcome-state.js';
import {
  NotificationDeliveryOutcomeError,
  encodeNotificationOutcomeObservation,
} from './delivery-outcome-contract.js';
import {
  notificationOutcomePublication,
  assertNotificationCompletionRow,
  type NotificationCompletionRow,
} from './delivery-outcome-publication-contract.js';
import { validateNotificationWorkerInstallation } from './worker-installation-contract.js';

export class NotificationOutcomePublicationUnknown extends Error {
  readonly selector: NotificationOutcomeSigningSelector;
  constructor(value: NotificationOutcomeSigningSelector) {
    super('Notification outcome publication requires original readback');
    this.selector = immutableJsonCopy(
      notificationOutcomeSigningSelector.parse(immutableJsonCopy(value)),
    );
  }
}
export const notificationOutcomePublicationScope = z.strictObject({
  participantId: z.uuidv7(),
  privacyDomainId: z.uuidv7(),
  operationId: z.uuidv7(),
});
const outcomeColumns = `participant_id::text,privacy_domain_id::text,operation_id::text,receipt_id::text,attempt_id::text,start_operation_id::text,notification_occurrence_id::text,payload_digest,worker_installation_digest,signer_installation_digest,delivery_revision::text,transition_bytes,transition_digest,receipt_payload,receipt_digest,cose_sign1`;
/** Same-client historical verification for the authorized publication reader and
 * Evidence custody source. SQL completeness is mandatory; no caller boolean can
 * replace actual original signing/observation/event/work/projection provenance. */
export async function readNotificationOutcomePublicationInTransaction(
  client: PoolClient,
  value: NotificationOutcomeSigningSelector,
) {
  const q = notificationOutcomeSigningSelector.parse(immutableJsonCopy(value));
  const args = [q.worker.participantId, q.worker.privacyDomainId, q.operationId];
  const rows = await client.query<NotificationSignedOutcomeRow>(
    `select ${outcomeColumns} from control.notification_delivery_outcome where participant_id=$1 and privacy_domain_id=$2 and operation_id=$3`,
    args,
  );
  if (rows.rowCount === 0) return null;
  if (rows.rowCount !== 1) throw new NotificationDeliveryOutcomeError();
  const row = rows.rows[0]!;
  const signing = await readNotificationOutcomeSigningInTransaction(client, q);
  if (
    !signing?.observation ||
    signing.state !== 'OBSERVED' ||
    signing.observation.outcome !== 'SIGNED'
  )
    throw new NotificationDeliveryOutcomeError();
  const first = await client.query<NotificationOutcomeObservationRow>(
    `select participant_id::text,privacy_domain_id::text,observation_id::text,attempt_id::text,start_operation_id::text,dispatch_claim_token,operation_id::text,outcome,observed_at_ms::text,observation_bytes,observation_digest from control.notification_delivery_observation where participant_id=$1 and privacy_domain_id=$2 and attempt_id=$3`,
    [...args.slice(0, 2), row.attempt_id],
  );
  if (first.rowCount !== 1) throw new NotificationDeliveryOutcomeError();
  // The retained signing reader has already verified the original STARTED and
  // exclusive claim. Historical custody does not lock the current delivery or
  // acquire UPDATE privileges merely to read an immutable result.
  const expected = notificationOutcomePublication(
    notificationOutcomeSigningTransition(signing.preparation, signing.observation),
  );
  const t = decodeNotificationSignedOutcomeRow(
    { original: expected.proposal.original, claim: expected.proposal.claim },
    first.rows[0]!,
    row,
  );
  if (
    canonicalJson(t) !==
    canonicalJson(notificationOutcomeSigningTransition(signing.preparation, signing.observation))
  )
    throw new NotificationDeliveryOutcomeError();
  const publication = notificationOutcomePublication(t);
  const events = await client.query<NotificationCompletionRow>(
    `select participant_id::text,privacy_domain_id::text,event_id::text,event_type,aggregate_type,aggregate_id::text,aggregate_sequence::text,business_sequence::text,proof_kind,sequence_namespace,receipt_id::text,data_schema_uri,source,subject,correlation_id::text,causation_id::text,authority_generation,payload_cbor,payload_digest,cose_sign1,webauthn_assertion_binding_digest,floor(extract(epoch from occurred_at)*1000)::text occurred_at_ms from control.outbox_event where participant_id=$1 and privacy_domain_id=$2 and (event_id=$3 or (sequence_namespace='NOTIFICATION_DELIVERY_COMPLETED_V1' and correlation_id=$4))`,
    [...args.slice(0, 2), t.receipt.receiptId, t.receipt.operationId],
  );
  if (events.rowCount !== (publication.event ? 1 : 0)) throw new NotificationDeliveryOutcomeError();
  assertNotificationCompletionRow(publication, events.rows[0] ?? null);
  if (publication.failureWork) {
    const work = await client.query<{ row_version: string }>(
      'select row_version::text from control.work_item where participant_id=$1 and privacy_domain_id=$2 and work_item_id=$3',
      [q.worker.participantId, q.worker.privacyDomainId, t.receipt.receiptId],
    );
    if (work.rowCount !== 1) throw new NotificationDeliveryOutcomeError();
    if (BigInt(work.rows[0]!.row_version) > 1n) {
      const history = await client.query<BusinessSourceRow & { beforeState: Buffer }>(
        `${businessSourceSelect.replace('select ', 'select a.before_state_preimage as "beforeState", ')} and a.aggregate_type='work-item' and a.aggregate_id=$3 and a.before_revision=1`,
        [q.worker.participantId, q.worker.privacyDomainId, t.receipt.receiptId],
      );
      if (history.rowCount !== 1) throw new NotificationDeliveryOutcomeError();
      const row = history.rows[0]!,
        receipt = verifyBusinessSource(row, q.worker);
      if (
        receipt.aggregateType !== 'work-item' ||
        receipt.aggregateId !== t.receipt.receiptId ||
        receipt.before.existence !== 1 ||
        receipt.before.revision !== 1n ||
        sha256(row.beforeState) !== `sha256:${receipt.before.stateDigest.toString('hex')}`
      )
        throw new NotificationDeliveryOutcomeError();
    }
  }
  await client.query('select openpc.check_notification_outcome_publication_original($1)', [
    q.operationId,
  ]);
  return publication;
}
async function withPublicationPeer<T>(
  pool: Pool,
  kernel: IdentityKernel,
  socket: TLSSocket,
  q: NotificationOutcomeSigningSelector,
  operation: (client: PoolClient, admission: NotificationWorkerAdmission) => Promise<T>,
  lease?: NotificationWorkerLeaseSelector,
) {
  return withNotificationDeliveryWorkerPeer(
    pool,
    kernel,
    socket,
    q.worker,
    async (client, admission) => {
      const executeOwner = async () => {
        await client.query(
          "select set_config('openpc.action_intent_id','ACT-EVIDENCE_EXPORT_RECORDS-V1',true)",
        );
        try {
          await lockEvidenceLifecycle(client, q.worker.participantId, q.worker.privacyDomainId);
          await assertNotificationDeliveryWorkerCurrent(admission, client, q.worker);
          await readPublishedNotificationDeliveryRequest(client, admission, {
            ...q.original.source,
            worker: q.worker,
          });
          const result = await operation(client, admission);
          await assertNotificationDeliveryWorkerCurrent(admission, client, q.worker);
          return result;
        } finally {
          await client.query(
            "select set_config('openpc.action_intent_id','ACT-POLICY_READ_EFFECTIVE_ACCESS-V1',true)",
          );
        }
      };
      if (lease === undefined) return executeOwner();
      await client.query(
        "select set_config('openpc.action_intent_id','ACT-EVIDENCE_EXPORT_RECORDS-V1',true)",
      );
      try {
        return await withNotificationWorkerLease(
          client,
          q.original.source,
          lease,
          'RECOVERY_PUBLICATION',
          async () => {
            await client.query(
              "select set_config('openpc.action_intent_id','ACT-POLICY_READ_EFFECTIVE_ACCESS-V1',true)",
            );
            try {
              return await executeOwner();
            } finally {
              await client.query(
                "select set_config('openpc.action_intent_id','ACT-EVIDENCE_EXPORT_RECORDS-V1',true)",
              );
            }
          },
        );
      } finally {
        await client.query(
          "select set_config('openpc.action_intent_id','ACT-POLICY_READ_EFFECTIVE_ACCESS-V1',true)",
        );
      }
    },
  );
}
/** Readback remains available to a current scoped reader after original signer
 * withdrawal. This is historical publication proof, not renewed signing. */
export function readNotificationDeliveryOutcomePublication(
  pool: Pool,
  kernel: IdentityKernel,
  socket: TLSSocket,
  value: unknown,
) {
  const q = notificationOutcomeSigningSelector.parse(immutableJsonCopy(value));
  return withPublicationPeer(pool, kernel, socket, q, (client) =>
    readNotificationOutcomePublicationInTransaction(client, q),
  );
}
/** No external I/O or retry. Whole publication commits in the actual peer/result
 * transaction. Missing shared admissions fail before writes. Any uncertain write
 * or COMMIT must reconcile this selector; it cannot mint another result. */
export async function publishNotificationDeliveryOutcome(
  pool: Pool,
  kernel: IdentityKernel,
  socket: TLSSocket,
  value: unknown,
  lease?: NotificationWorkerLeaseSelector,
) {
  const q = notificationOutcomeSigningSelector.parse(immutableJsonCopy(value));
  let attempted = false;
  try {
    return await withPublicationPeer(
      pool,
      kernel,
      socket,
      q,
      async (client, admission) => {
        const execute = async () => {
          const original = await readNotificationOutcomePublicationInTransaction(client, q);
          if (original) return original;
          await client.query('select openpc.assert_notification_outcome_publication_owner()');
          const actual = await readNotificationOutcomeInputInTransaction(client, q.original, true);
          const signing = await readNotificationOutcomeSigningInTransaction(client, q, true);
          if (
            !signing?.observation ||
            signing.state !== 'OBSERVED' ||
            signing.observation.outcome !== 'SIGNED' ||
            actual.first !== null
          )
            throw new NotificationDeliveryOutcomeError();
          const p = notificationOutcomePublication(
            notificationOutcomeSigningTransition(signing.preparation, signing.observation),
          );
          if (
            canonicalJson(actual.current) !== canonicalJson(p.proposal.before) ||
            canonicalJson(actual.record.original) !== canonicalJson(p.proposal.original) ||
            canonicalJson(actual.record.claim) !== canonicalJson(p.proposal.claim)
          )
            throw new NotificationDeliveryOutcomeError();
          await client.query(
            "select set_config('openpc.action_intent_id','ACT-POLICY_READ_EFFECTIVE_ACCESS-V1',true)",
          );
          try {
            return await withNotificationDeliveryResultAuthority(
              client,
              admission,
              {
                worker: q.worker,
                signerInstallationDigest: q.signerInstallationDigest,
              },
              async (signer) => {
                const r = p.encoded.transition.receipt;
                assertNotificationDeliveryResultAuthority(
                  client,
                  admission,
                  signer,
                  {
                    worker: q.worker,
                    signerInstallationDigest: q.signerInstallationDigest,
                  },
                  r,
                );
                const native = encodeNotificationOutcomeObservation(
                  p.encoded.transition.input.observation,
                );
                const worker = validateNotificationWorkerInstallation(
                  p.encoded.transition.workerInstallation,
                  r.recordedAtMs,
                );
                attempted = true;
                await client.query(
                  `insert into control.notification_delivery_outcome(participant_id,privacy_domain_id,operation_id,receipt_id,attempt_id,start_operation_id,notification_occurrence_id,payload_digest,worker_installation_digest,signer_installation_digest,delivery_revision,transition,transition_bytes,transition_digest,receipt_payload,receipt_digest,cose_sign1) values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)`,
                  [
                    r.participantId,
                    r.privacyDomainId,
                    r.operationId,
                    r.receiptId,
                    r.attemptId,
                    r.startOperationId,
                    r.notificationOccurrenceId,
                    r.payloadDigest,
                    worker.installationDigest,
                    q.signerInstallationDigest,
                    r.deliveryRevision,
                    p.encoded.transition,
                    p.encoded.transitionBytes,
                    p.encoded.transitionDigest,
                    p.encoded.receiptPayload,
                    p.encoded.receiptDigest,
                    p.encoded.coseSign1,
                  ],
                );
                await client.query(
                  `insert into control.notification_delivery_observation(participant_id,privacy_domain_id,observation_id,attempt_id,start_operation_id,dispatch_claim_token,operation_id,outcome,observed_at_ms,observation_bytes,observation_digest) values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
                  [
                    r.participantId,
                    r.privacyDomainId,
                    native.observation.claims.receiptId,
                    r.attemptId,
                    r.startOperationId,
                    native.claim.claimToken,
                    r.operationId,
                    native.observation.claims.outcome,
                    native.observation.claims.observedAtMs,
                    native.observationBytes,
                    native.observationDigest,
                  ],
                );
                const next = p.proposal.after.snapshot;
                const changed = await client.query(
                  `update control.notification_delivery set state=$4,attempt_limit=$5,next_attempt_at_ms=$6,revision=revision+1 where participant_id=$1 and privacy_domain_id=$2 and notification_occurrence_id=$3 and revision=$7 returning notification_occurrence_id`,
                  [
                    r.participantId,
                    r.privacyDomainId,
                    r.notificationOccurrenceId,
                    next.state,
                    next.attemptLimit,
                    next.nextAttemptAtMs,
                    r.deliveryRevision,
                  ],
                );
                if (changed.rowCount !== 1) throw new NotificationDeliveryOutcomeError();
                if (p.failureWork) {
                  const w = p.failureWork;
                  await client.query(
                    `insert into control.work_item(work_item_id,participant_id,privacy_domain_id,kind,state,resource_ref,payload_digest,reason,created_by_principal_id,assignee_principal_id,claimed_by_principal_id,completed_by_principal_id,row_version) values($1,$2,$3,$4,$5,$6,$7,$8,$9,null,null,null,1)`,
                    [
                      w.workItemId,
                      w.participantId,
                      w.privacyDomainId,
                      w.kind,
                      w.state,
                      w.resourceRef,
                      Buffer.from(w.payloadDigest.slice(7), 'hex'),
                      w.reason,
                      w.createdByPrincipalId,
                    ],
                  );
                }
                if (p.event) {
                  const e = p.event;
                  await client.query(
                    `insert into control.outbox_event(participant_id,privacy_domain_id,event_id,event_type,aggregate_type,aggregate_id,business_sequence,proof_kind,sequence_namespace,data_schema_uri,source,subject,correlation_id,causation_id,payload_cbor,payload_digest,occurred_at) values($1,$2,$3,$4,'notification-occurrence',$5,1,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`,
                    [
                      r.participantId,
                      r.privacyDomainId,
                      e.envelope.id,
                      e.envelope.type,
                      r.notificationOccurrenceId,
                      e.proofKind,
                      e.sequenceNamespace,
                      e.envelope.dataschema,
                      e.envelope.source,
                      e.envelope.subject,
                      e.envelope.correlationid,
                      e.envelope.causationid,
                      e.payloadCbor,
                      e.payloadDigest,
                      e.envelope.time,
                    ],
                  );
                }
                await client.query(
                  'select openpc.check_notification_outcome_publication_complete($1)',
                  [r.operationId],
                );
                const published = await readNotificationOutcomePublicationInTransaction(client, q);
                if (!published || published.encoded.transitionDigest !== p.encoded.transitionDigest)
                  throw new NotificationDeliveryOutcomeError();
                return published;
              },
            );
          } finally {
            await client.query(
              "select set_config('openpc.action_intent_id','ACT-EVIDENCE_EXPORT_RECORDS-V1',true)",
            );
          }
        };
        return lease === undefined
          ? execute()
          : withNotificationWorkerLease(
              client,
              q.original.source,
              lease,
              'RECOVERY_PUBLICATION',
              async () => {
                return execute();
              },
            );
      },
      lease,
    );
  } catch (error) {
    if (attempted) throw new NotificationOutcomePublicationUnknown(q);
    throw error;
  }
}

/** Leased production entry; original API remains available to existing owners. */
export function publishNotificationDeliveryOutcomeLeased(
  lease: unknown,
  pool: Pool,
  kernel: IdentityKernel,
  socket: TLSSocket,
  value: unknown,
) {
  return publishNotificationDeliveryOutcome(
    pool,
    kernel,
    socket,
    value,
    notificationWorkerLeaseSelector.parse(immutableJsonCopy(lease)),
  );
}
