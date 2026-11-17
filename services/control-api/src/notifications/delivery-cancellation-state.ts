import {
  withNotificationWorkerLease,
  notificationWorkerLeaseSelector,
  type NotificationWorkerLeaseSelector,
  type NotificationWorkerLeaseWindow,
  notificationWorkerLeaseSignal,
} from './async-worker-state.js';
import { validateNotificationRetryLineage } from './delivery-cancellation-contract.js';
import { readNotificationOutcomePublicationInTransaction } from './delivery-outcome-publication.js';
import type { Pool, PoolClient } from 'pg';
import type { TLSSocket } from 'node:tls';
import { z } from 'zod';
import {
  businessTransitionProfileForOperation,
  encodeNotificationClaim,
  type NotificationDeliveryCancellationReceiptClaims,
} from '@openpc/security-kernel';
import { decodeCbor } from '../../../../packages/security-kernel/src/canonical-cbor.js';
import type { IdentityKernel } from '../../../identity-service/src/domain/identity-kernel.js';
import { localOperationId } from '../../../identity-service/src/domain/local-operation-id.js';
import {
  createNotificationCancellationReceiptRequest,
  validateNotificationCancellationReceiptRequest,
  validateNotificationCancellationReceiptObservation,
  type NotificationCancellationReceiptRequest,
} from '../../../identity-service/src/domain/notification-cancellation-receipt-provider.js';
import type {
  NotificationReceiptProviderTrust,
  NotificationReceiptProviderObservation,
} from '../../../identity-service/src/domain/notification-receipt-provider.js';
import { createHttpNotificationCancellationReceiptProvider } from '../../../identity-service/src/domain/http-notification-receipt-provider.js';
import {
  withCurrentNotificationCancellationSigner,
  assertNotificationCancellationSigner,
  type NotificationReceiptSigner,
} from './receipt-signer-installation.js';
import {
  withNotificationDeliveryWorkerPeer,
  assertNotificationDeliveryWorkerCurrent,
  type NotificationWorkerAdmission,
} from '../../../identity-service/src/domain/notification-worker.js';
import { canonicalJson, sha256 } from '../configuration/digest.js';
import { immutableJsonCopy } from '../privacy-explorer/immutable.js';
import { lockEvidenceLifecycle } from '../evidence/lifecycle-fence.js';
import {
  businessSourceSelect,
  verifyBusinessSource,
  type BusinessSourceRow,
} from '../evidence/business-source.js';
import {
  bindNotificationEndpointBusinessState,
  parseNotificationEndpointBusinessState,
  assertNotificationEndpointReplacement,
  endpointBinding,
} from './endpoint-business-state.js';
import { notificationRevision } from './endpoint-binding.js';
import { readPublishedNotificationDeliveryRequest } from './delivery-source.js';
import { notificationDeliveryBudgetRecord } from './delivery-start-state.js';
import { notificationDeliverySnapshot } from './delivery-policy.js';
import { notificationDeliveryStateDigest } from './delivery-start-contract.js';
import { decodeNotificationDeliverySigning } from './delivery-signing-contract.js';
import {
  readNotificationDeliveryStartInTransaction,
  decodeNotificationDispatchClaim,
} from './delivery-start-atomic.js';
import {
  notificationCancellationCauseBinding,
  notificationDeliveryCancellationSelector,
  proposeNotificationDeliveryCancellation,
  encodeNotificationDeliveryCancellation,
  decodeNotificationDeliveryCancellation,
  validateNotificationDeliveryCancellationInput,
  type NotificationDeliveryCancellationSelector,
  type NotificationDeliveryCancellationTransition,
} from './delivery-cancellation-contract.js';

export class NotificationDeliveryCancellationError extends Error {
  constructor(
    readonly reason:
      | 'UNAVAILABLE'
      | 'CAUSE'
      | 'LINEAGE'
      | 'OUTCOME_OWNER_UNBOUND'
      | 'SIGNER_OWNER_UNBOUND' = 'UNAVAILABLE',
  ) {
    super(`Notification cancellation ${reason}`);
  }
}
export class NotificationDeliveryCancellationCommitUnknown extends Error {
  constructor(readonly selector: NotificationDeliveryCancellationSelector) {
    super('Notification cancellation commit requires original readback');
  }
}
const hash = (v: Buffer) => `sha256:${v.toString('hex')}`;
const causeSelector = z.strictObject({
  participantId: z.uuidv7(),
  privacyDomainId: z.uuidv7(),
  causeOperationId: z.uuidv7(),
  endpointId: z.uuidv7(),
  endpointRevision: notificationRevision,
});
export interface NotificationCancellationCauseRow extends BusinessSourceRow {
  beforePreimage: Buffer;
  afterPreimage: Buffer;
  authoritySnapshot: Buffer;
  resultPayload: unknown;
  resultDigest: Buffer;
}

function endpointPreimage(
  bytes: Buffer,
  receipt: ReturnType<typeof verifyBusinessSource>,
  which: 'before' | 'after',
) {
  if (!Buffer.isBuffer(bytes) || bytes.length > 65536) throw new Error();
  const value = decodeCbor(bytes);
  if (!Array.isArray(value) || value.length !== 9 || !(value[8] instanceof Map)) throw new Error();
  const fields = value[8];
  const h = (key: number) => {
    const item = fields.get(key);
    if (!Buffer.isBuffer(item) || item.length !== 32) throw new Error();
    return hash(item);
  };
  const presence = fields.get(7);
  if (fields.get(5) !== 0n || (presence !== 0n && presence !== 1n)) throw new Error();
  const scope = {
    participantId: receipt.participantId,
    privacyDomainId: receipt.privacyDomainId,
    aggregateId: receipt.aggregateId,
  };
  const state = parseNotificationEndpointBusinessState(scope, {
    participantId: scope.participantId,
    privacyDomainId: scope.privacyDomainId,
    endpointId: scope.aggregateId,
    revision: receipt[which].revision.toString(),
    channel: fields.get(0),
    state: fields.get(1),
    destinationRef: fields.get(2),
    channelProfileDigest: h(3),
    credentialRef: fields.get(4),
    arbitraryEgress: false,
    candidateDigest: h(6),
    verificationId: presence === 0n ? null : fields.get(8),
  });
  if (!state) throw new Error();
  const bound = bindNotificationEndpointBusinessState(
    {
      ...scope,
      aggregateType: receipt.aggregateType,
      profileDigest: receipt.transitionProfileDigest,
    },
    state,
  );
  if (
    !bound.preimage.equals(bytes) ||
    !bound.reference.stateDigest.equals(receipt[which].stateDigest) ||
    bound.reference.existence !== receipt[which].existence
  )
    throw new Error();
  return state;
}

/** Pure historical verification. Production obtains every row/trust byte from
 * the real scoped business source query below; caller-supplied trust is not an
 * admission. The current endpoint, predecessor credential and current step-up
 * lifetime play no role in reinterpreting this original committed operation. */
export function verifyNotificationDeliveryCancellationCause(
  row: NotificationCancellationCauseRow,
  value: unknown,
) {
  try {
    const q = causeSelector.parse(immutableJsonCopy(value));
    const receipt = verifyBusinessSource(row, q);
    const profile = businessTransitionProfileForOperation('CFG-OP-UPDATE-NOTIFICATION-ENDPOINT');
    const result = immutableJsonCopy(row.resultPayload) as Record<string, unknown>;
    if (
      !profile ||
      receipt.catalogOperationId !== profile.catalogOperationId ||
      receipt.actionIntentId !== profile.actionIntentId ||
      hash(receipt.transitionProfileDigest) !== profile.profileDigest ||
      receipt.operationId !== q.causeOperationId ||
      receipt.aggregateId !== q.endpointId ||
      receipt.before.revision.toString() !== q.endpointRevision ||
      receipt.before.existence !== 1 ||
      receipt.after.existence !== 1 ||
      result.operationId !== receipt.operationId ||
      result.state !== 'SUCCEEDED' ||
      result.truthState !== 'SUCCESS' ||
      result.actionIntentId !== receipt.actionIntentId ||
      result.resourceRef !== `urn:openpc:resource:${receipt.aggregateId}` ||
      result.revision !== receipt.after.revision.toString() ||
      result.intentDigest !== hash(receipt.actionIntentDigest) ||
      sha256(result) !== hash(row.resultDigest) ||
      sha256(row.authoritySnapshot) !== hash(receipt.preCommitAuthorityDigest) ||
      receipt.authorizationEvidence.length !== 2 ||
      receipt.authorizationEvidence[0]?.kind !== 2 ||
      receipt.authorizationEvidence[1]?.kind !== 4 ||
      receipt.authorizationEvidence[0].evidenceId === receipt.authorizationEvidence[1].evidenceId
    )
      throw new Error();
    const before = endpointPreimage(row.beforePreimage, receipt, 'before');
    const after = endpointPreimage(row.afterPreimage, receipt, 'after');
    // The signed after-state binds the resolved replacement digest. The
    // receipt candidate binds the complete UPDATE command, including its
    // action/revision/reason; those independent digests are not interchangeable.
    assertNotificationEndpointReplacement(
      {
        participantId: q.participantId,
        privacyDomainId: q.privacyDomainId,
        aggregateId: q.endpointId,
      },
      before,
      after,
      {
        expectedRevision: q.endpointRevision,
        replacementDigest: after.candidateDigest,
        binding: endpointBinding(after),
      },
    );
    return immutableJsonCopy(
      notificationCancellationCauseBinding.parse({
        participantId: q.participantId,
        privacyDomainId: q.privacyDomainId,
        environmentId: receipt.environmentId,
        operationId: receipt.operationId,
        receiptId: receipt.receiptId,
        endpointId: q.endpointId,
        endpointRevision: before.revision,
        successorRevision: after.revision,
        profileDigest: hash(receipt.transitionProfileDigest),
        receiptDigest: sha256(row.payload),
        beforeStateDigest: hash(receipt.before.stateDigest),
        afterStateDigest: hash(receipt.after.stateDigest),
        recordedAtMs: Number(receipt.recordedAtNs / 1000000n),
      }),
    );
  } catch {
    throw new NotificationDeliveryCancellationError('CAUSE');
  }
}

/** Historical cause reader, not current worker/cancellation authority. Caller
 * retains its same scoped transaction and lifecycle fence. Native SQL reuses the
 * original consumed WebAuthn owner at receipt time, never today's freshness. */
export async function readNotificationDeliveryCancellationCause(
  client: PoolClient,
  value: unknown,
) {
  const q = causeSelector.parse(immutableJsonCopy(value));
  const context = await client.query<{ allowed: boolean }>(
    `select openpc.assert_request_context(true),
    openpc.current_participant_id()=$1::uuid and openpc.current_privacy_domain_id()=$2::uuid
    and current_setting('transaction_isolation')='read committed' and current_setting('row_security')='on'
    and not r.rolsuper and not r.rolbypassrls allowed from pg_roles r where r.rolname=current_user`,
    [q.participantId, q.privacyDomainId],
  );
  if (context.rowCount !== 1 || context.rows[0]?.allowed !== true)
    throw new NotificationDeliveryCancellationError('CAUSE');
  const rows = await client.query<NotificationCancellationCauseRow>(
    `select b.*,a.before_state_preimage as "beforePreimage",
    a.after_state_preimage as "afterPreimage",a.authority_snapshot as "authoritySnapshot",i.result_payload as "resultPayload",i.result_digest as "resultDigest"
    from (${businessSourceSelect} and a.operation_id=$3) b
    join control.audit_occurrence a on a.participant_id=$1 and a.privacy_domain_id=$2 and a.receipt_id=b."receiptId"::uuid and a.operation_id=$3
    join control.idempotency_record i on i.participant_id=a.participant_id and i.privacy_domain_id=a.privacy_domain_id
      and i.operation_id=a.operation_id and i.idempotency_record_id=a.idempotency_record_id
      and i.action_intent_id=a.action_intent_id and i.catalog_operation_id=a.catalog_operation_id and i.input_digest=a.candidate_digest
      and i.terminal_state='COMMITTED' and i.result_aggregate_version=a.after_revision
    where a.aggregate_id=$4 and a.before_revision=$5 and a.catalog_operation_id='CFG-OP-UPDATE-NOTIFICATION-ENDPOINT'
      and a.action_intent_id='ACT-NOTIFICATION_ENDPOINTS_UPDATE_RESOURCE-V1'`,
    [q.participantId, q.privacyDomainId, q.causeOperationId, q.endpointId, q.endpointRevision],
  );
  if (rows.rowCount !== 1) throw new NotificationDeliveryCancellationError('CAUSE');
  const row = rows.rows[0]!;
  const cause = verifyNotificationDeliveryCancellationCause(row, q);
  const receipt = verifyBusinessSource(row, q);
  const admitted = await client.query(
    `select 1 from control.audit_occurrence a
    join control.mutation_evidence e on e.participant_id=a.participant_id and e.privacy_domain_id=a.privacy_domain_id
      and e.operation_id=a.operation_id and e.action_intent_id=a.action_intent_id and e.catalog_operation_id=a.catalog_operation_id
      and e.aggregate_id=a.aggregate_id and e.candidate_digest=a.candidate_digest
    where a.participant_id=$1 and a.privacy_domain_id=$2 and a.operation_id=$3
      and e.mutation_evidence_id=$4 and e.evidence_digest=$5 and e.evidence_digest=sha256(e.evidence_cbor)
      and e.evidence_role='AUTHORIZATION_INPUT' and e.evidence_format='IDENTITY_RUNTIME_ASSERTION_3002_2_13'
      and openpc.configuration_step_up_receipt_input(a,e)=jsonb_build_object('0',4,'1',$6::text,'2',openpc.business_bytes($7::bytea))`,
    [
      q.participantId,
      q.privacyDomainId,
      q.causeOperationId,
      receipt.authorizationEvidence[0]!.evidenceId,
      receipt.authorizationEvidence[0]!.evidenceDigest,
      receipt.authorizationEvidence[1]!.evidenceId,
      receipt.authorizationEvidence[1]!.evidenceDigest,
    ],
  );
  if (admitted.rowCount !== 1) throw new NotificationDeliveryCancellationError('CAUSE');
  const events = await client.query<{
    id: string;
    payload: Buffer;
    digest: Buffer;
    sequence: string;
  }>(
    `select event_id::text id,payload_cbor payload,payload_digest digest,business_sequence::text sequence
    from control.outbox_event where participant_id=$1 and privacy_domain_id=$2 and receipt_id=$3 and proof_kind='BUSINESS_RECEIPT_REFERENCE' order by business_sequence limit 17`,
    [q.participantId, q.privacyDomainId, receipt.receiptId],
  );
  if (
    events.rowCount !== receipt.outboxEvents.length ||
    events.rows.some((event, index) => {
      const bound = receipt.outboxEvents[index]!;
      return (
        event.id !== bound.eventId ||
        event.sequence !== bound.aggregateSequence.toString() ||
        !event.digest.equals(bound.payloadDigest) ||
        sha256(event.payload) !== hash(event.digest)
      );
    })
  )
    throw new NotificationDeliveryCancellationError('CAUSE');
  return cause;
}

const projection = `participant_id::text as "participantId",privacy_domain_id::text as "privacyDomainId",notification_occurrence_id::text as "notificationOccurrenceId",payload_digest as "payloadDigest",state,
 attempt_count as "attemptCount",attempt_limit as "attemptLimit",next_attempt_at_ms::float8 as "nextAttemptAtMs",last_started_at_ms::float8 as "lastStartedAtMs",cancel_requested as "cancelRequested",revision::text,
 delivery_request_event_id::text as "deliveryRequestEventId",delivery_request_operation_id::text as "deliveryRequestOperationId",budget_environment_id as "budgetEnvironmentId",budget_generation_id::text as "budgetGenerationId",budget_effective_digest as "budgetEffectiveDigest",budget_configured_limit as "budgetConfiguredLimit",budget_worker_installation_digest as "budgetWorkerInstallationDigest"`;
async function lineage(
  client: PoolClient,
  q: NotificationDeliveryCancellationSelector,
  before: z.infer<typeof notificationDeliveryBudgetRecord>,
) {
  const scope = [
    q.source.worker.participantId,
    q.source.worker.privacyDomainId,
    q.source.notificationOccurrenceId,
  ];
  const starts = await client.query<{
    operation_id: string;
    preparation_bytes: Buffer;
    preparation_digest: string;
  }>(
    `select s.operation_id,g.preparation_bytes,g.preparation_digest
    from control.notification_delivery_start s join control.notification_delivery_signing g using(participant_id,privacy_domain_id,operation_id)
    where s.participant_id=$1 and s.privacy_domain_id=$2 and s.notification_occurrence_id=$3 order by s.delivery_revision desc limit 7`,
    scope,
  );
  if (before.attemptCount === 0) {
    const attempts = await client.query(
      `select 1 from control.notification_delivery_attempt where participant_id=$1 and privacy_domain_id=$2 and notification_occurrence_id=$3 limit 1`,
      scope,
    );
    if (starts.rowCount !== 0 || attempts.rowCount !== 0)
      throw new NotificationDeliveryCancellationError('LINEAGE');
    return { originalStart: null, originalClaim: null };
  }
  if (starts.rowCount !== before.attemptCount || !starts.rows[0])
    throw new NotificationDeliveryCancellationError('LINEAGE');
  const row = starts.rows[0],
    signing = decodeNotificationDeliverySigning(row.preparation_bytes, row.preparation_digest);
  const originalQ = {
    source: signing.deliveryPreparation.source,
    operationId: row.operation_id,
    signerInstallationDigest: signing.request.signerInstallationDigest,
  };
  const originalStart = await readNotificationDeliveryStartInTransaction(client, originalQ);
  if (
    !originalStart ||
    originalStart.attempt.attemptNumber !== before.attemptCount ||
    originalStart.attempt.startedAtMs !== before.lastStartedAtMs ||
    originalStart.receipt.payloadDigest !== before.payloadDigest ||
    originalStart.receipt.sourceEventId !== q.source.eventId
  )
    throw new NotificationDeliveryCancellationError('LINEAGE');
  const claims = await client.query<{
    state: string;
    claim_token: string | null;
    claimed_at_ms: string | null;
  }>(
    `select state,claim_token,claimed_at_ms::text from control.notification_delivery_dispatch_intent
    where participant_id=$1 and privacy_domain_id=$2 and operation_id=$3 for update`,
    [scope[0], scope[1], row.operation_id],
  );
  if (claims.rowCount !== 1) throw new NotificationDeliveryCancellationError('LINEAGE');
  const originalClaim = decodeNotificationDispatchClaim(claims.rows[0]!);
  if (before.state !== 'RETRY_WAIT') return { originalStart, originalClaim };
  const outcomes = await client.query<{ operation_id: string; signer_installation_digest: string }>(
    `select operation_id::text,signer_installation_digest from control.notification_delivery_outcome
     where participant_id=$1 and privacy_domain_id=$2 and notification_occurrence_id=$3
       and start_operation_id=$4 and attempt_id=$5`,
    [...scope, originalStart.receipt.operationId, originalStart.attempt.attemptId],
  );
  if (outcomes.rowCount !== 1) throw new NotificationDeliveryCancellationError('LINEAGE');
  const outcome = outcomes.rows[0]!;
  const published = await readNotificationOutcomePublicationInTransaction(client, {
    original: originalQ,
    worker: q.source.worker,
    operationId: outcome.operation_id,
    signerInstallationDigest: outcome.signer_installation_digest,
  });
  if (!published) throw new NotificationDeliveryCancellationError('LINEAGE');
  const originalOutcome = validateNotificationRetryLineage(
    published.encoded.transition,
    before,
    originalStart,
    originalClaim,
  );
  return { originalStart, originalClaim, originalOutcome };
}

async function withOwner<T>(
  pool: Pool,
  kernel: IdentityKernel,
  socket: TLSSocket,
  value: unknown,
  operation: (
    client: PoolClient,
    admission: NotificationWorkerAdmission,
    q: NotificationDeliveryCancellationSelector,
    source: Awaited<ReturnType<typeof readPublishedNotificationDeliveryRequest>>,
  ) => Promise<T>,
  lease?: NotificationWorkerLeaseSelector,
) {
  const q = notificationDeliveryCancellationSelector.parse(immutableJsonCopy(value));
  return withNotificationDeliveryWorkerPeer(
    pool,
    kernel,
    socket,
    q.source.worker,
    async (client, admission) => {
      const executeOwner = async () => {
        await client.query(
          "select set_config('openpc.action_intent_id','ACT-EVIDENCE_EXPORT_RECORDS-V1',true)",
        );
        try {
          await lockEvidenceLifecycle(
            client,
            q.source.worker.participantId,
            q.source.worker.privacyDomainId,
          );
          await assertNotificationDeliveryWorkerCurrent(admission, client, q.source.worker);
          const source = await readPublishedNotificationDeliveryRequest(
            client,
            admission,
            q.source,
          );
          const result = await operation(client, admission, q, source);
          await assertNotificationDeliveryWorkerCurrent(admission, client, q.source.worker);
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
        return await withNotificationWorkerLease(client, q.source, lease, 'CANCEL', async () => {
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
        });
      } finally {
        await client.query(
          "select set_config('openpc.action_intent_id','ACT-POLICY_READ_EFFECTIVE_ACCESS-V1',true)",
        );
      }
    },
  );
}

async function current(
  client: PoolClient,
  admission: NotificationWorkerAdmission,
  q: NotificationDeliveryCancellationSelector,
  source: Awaited<ReturnType<typeof readPublishedNotificationDeliveryRequest>>,
) {
  const cause = await readNotificationDeliveryCancellationCause(client, {
    participantId: q.source.worker.participantId,
    privacyDomainId: q.source.worker.privacyDomainId,
    causeOperationId: q.causeOperationId,
    endpointId: source.claims.endpointId,
    endpointRevision: source.claims.endpointRevision,
  });
  const rows = await client.query(
    `select ${projection} from control.notification_delivery where participant_id=$1 and privacy_domain_id=$2 and notification_occurrence_id=$3 for update`,
    [
      q.source.worker.participantId,
      q.source.worker.privacyDomainId,
      q.source.notificationOccurrenceId,
    ],
  );
  if (rows.rowCount !== 1) throw new NotificationDeliveryCancellationError();
  const before = notificationDeliveryBudgetRecord.parse(rows.rows[0]);
  if (
    !['PENDING', 'RETRY_WAIT', 'STARTED', 'AMBIGUOUS'].includes(before.state) ||
    before.cancelRequested ||
    before.deliveryRequestEventId !== source.claims.eventId ||
    before.deliveryRequestOperationId !== source.sourceOperationId
  )
    throw new NotificationDeliveryCancellationError();
  const clock = await client.query<{ now: string }>(
    'select floor(extract(epoch from clock_timestamp())*1000)::text now',
  );
  const nowMs = Number(clock.rows[0]?.now);
  const after = proposeNotificationDeliveryCancellation(
    before,
    {
      participantId: q.source.worker.participantId,
      privacyDomainId: q.source.worker.privacyDomainId,
      notificationOccurrenceId: q.source.notificationOccurrenceId,
      payloadDigest: source.claims.payloadDigest,
      expectedRevision: q.expectedRevision,
    },
    nowMs,
  );
  return immutableJsonCopy({
    selector: q,
    sourceOperationId: source.sourceOperationId,
    sourceReceiptDigest: source.sourceReceiptDigest,
    sourceClaims: source.claims,
    workerInstallation: admission.installation.input,
    workerAuthorityDigest: admission.authorityDigest,
    cause,
    before,
    after,
    ...(await lineage(client, q, before)),
    nowMs,
  });
}

/** Read-only input inspection for the canonical distinct signer owner. Returned
 * inputs escape no live grant; that owner must reread them under its own real
 * transaction, allocate/persist original IDs and commit before provider I/O. */
export function inspectNotificationDeliveryCancellation(
  pool: Pool,
  kernel: IdentityKernel,
  socket: TLSSocket,
  value: unknown,
) {
  return withOwner(pool, kernel, socket, value, current);
}

async function original(
  client: PoolClient,
  q: NotificationDeliveryCancellationSelector,
  source: Awaited<ReturnType<typeof readPublishedNotificationDeliveryRequest>>,
) {
  const rows = await client.query<{
    transition_bytes: Buffer;
    transition_digest: string;
    receipt_payload: Buffer;
    receipt_digest: string;
    cose_sign1: Buffer;
  }>(
    `select transition_bytes,transition_digest,receipt_payload,receipt_digest,cose_sign1 from control.notification_delivery_cancellation
    where participant_id=$1 and privacy_domain_id=$2 and notification_occurrence_id=$3 and cause_operation_id=$4`,
    [
      q.source.worker.participantId,
      q.source.worker.privacyDomainId,
      q.source.notificationOccurrenceId,
      q.causeOperationId,
    ],
  );
  if (rows.rowCount === 0) return null;
  if (rows.rowCount !== 1) throw new NotificationDeliveryCancellationError();
  const row = rows.rows[0]!,
    record = decodeNotificationDeliveryCancellation(row.transition_bytes, row.transition_digest);
  const cause = await readNotificationDeliveryCancellationCause(client, {
    participantId: q.source.worker.participantId,
    privacyDomainId: q.source.worker.privacyDomainId,
    causeOperationId: q.causeOperationId,
    endpointId: source.claims.endpointId,
    endpointRevision: source.claims.endpointRevision,
  });
  if (
    record.sourceOperationId !== source.sourceOperationId ||
    record.sourceReceiptDigest !== source.sourceReceiptDigest ||
    canonicalJson(record.sourceClaims) !== canonicalJson(source.claims) ||
    canonicalJson(record.cause) !== canonicalJson(cause) ||
    record.payloadHex !== row.receipt_payload.toString('hex') ||
    record.coseHex !== row.cose_sign1.toString('hex') ||
    sha256(row.receipt_payload) !== row.receipt_digest
  )
    throw new NotificationDeliveryCancellationError();
  await client.query('select openpc.check_notification_delivery_cancellation_complete($1)', [
    record.receipt.operationId,
  ]);
  return record;
}
/** Exact historical signed readback. No current predecessor credential, KMS,
 * generation or send grant. Gateway outcome remains a separate owner's record. */
export function readOriginalNotificationDeliveryCancellation(
  pool: Pool,
  kernel: IdentityKernel,
  socket: TLSSocket,
  value: unknown,
) {
  return withOwner(pool, kernel, socket, value, (client, _admission, q, source) =>
    original(client, q, source),
  );
}

type CancellationInput = ReturnType<typeof validateNotificationDeliveryCancellationInput>;
export interface NotificationCancellationSigningPreparation {
  readonly input: CancellationInput;
  readonly trust: NotificationReceiptProviderTrust;
  readonly request: NotificationCancellationReceiptRequest;
}
export interface NotificationCancellationSigningRecord {
  readonly preparation: NotificationCancellationSigningPreparation;
  readonly state: 'PREPARED' | 'DISPATCHED' | 'OBSERVED';
  readonly dispatchToken: string | null;
  readonly dispatchedAtMs: number | null;
  readonly observation: NotificationReceiptProviderObservation | null;
}
type SigningRow = {
  preparation_bytes: Buffer;
  preparation_digest: string;
  request_digest: string;
  state: string;
  dispatch_token: string | null;
  dispatched_at_ms: string | null;
  observation_bytes: Buffer | null;
  observation_digest: string | null;
};

/** Pure original decoder. Revalidates the actual committed cancellation
 * protocol, distinct installed purpose and exact first observation. */
export function decodeNotificationCancellationSigningRecord(
  row: SigningRow,
): NotificationCancellationSigningRecord {
  if (
    !Buffer.isBuffer(row.preparation_bytes) ||
    row.preparation_bytes.length > 1048576 ||
    sha256(row.preparation_bytes) !== row.preparation_digest
  )
    throw new NotificationDeliveryCancellationError();
  const text = new TextDecoder('utf-8', { fatal: true }).decode(row.preparation_bytes);
  const raw = z
    .strictObject({
      input: z.unknown(),
      trust: z.strictObject({ worker: z.unknown(), signer: z.unknown() }),
      request: z.unknown(),
    })
    .parse(JSON.parse(text));
  const input = validateNotificationDeliveryCancellationInput(raw.input);
  const trust = raw.trust as NotificationReceiptProviderTrust;
  const bound = validateNotificationCancellationReceiptRequest(raw.request, trust);
  if (
    canonicalJson({ input, trust, request: bound.request }) !== text ||
    bound.requestDigest !== row.request_digest ||
    bound.request.payloadHex !== input.payloadHex ||
    bound.request.cancellationPreparationDigest !== sha256(input) ||
    canonicalJson(trust.worker) !== canonicalJson(input.workerInstallation)
  )
    throw new NotificationDeliveryCancellationError();
  const preparation = immutableJsonCopy({ input, trust, request: bound.request });
  if (
    !['PREPARED', 'DISPATCHED', 'OBSERVED'].includes(row.state) ||
    (row.state === 'PREPARED') !== (row.dispatch_token === null) ||
    (row.state === 'PREPARED') !== (row.dispatched_at_ms === null)
  )
    throw new NotificationDeliveryCancellationError();
  let dispatchedAtMs: number | null = null;
  if (row.dispatch_token !== null) {
    z.uuidv7().parse(row.dispatch_token);
    if (!/^(0|[1-9][0-9]*)$/u.test(row.dispatched_at_ms!))
      throw new NotificationDeliveryCancellationError();
    dispatchedAtMs = Number(row.dispatched_at_ms);
    if (
      !Number.isSafeInteger(dispatchedAtMs) ||
      dispatchedAtMs < bound.notBeforeMs ||
      dispatchedAtMs >= bound.notAfterMs
    )
      throw new NotificationDeliveryCancellationError();
  }
  let observation: NotificationReceiptProviderObservation | null = null;
  if (row.state === 'OBSERVED') {
    if (
      !Buffer.isBuffer(row.observation_bytes) ||
      row.observation_bytes.length > 196608 ||
      sha256(row.observation_bytes) !== row.observation_digest
    )
      throw new NotificationDeliveryCancellationError();
    const original = new TextDecoder('utf-8', { fatal: true }).decode(row.observation_bytes);
    observation = validateNotificationCancellationReceiptObservation(
      bound.request,
      JSON.parse(original),
      trust,
    );
    if (
      canonicalJson(observation) !== original ||
      (observation.outcome === 'SIGNED' && observation.recordedAtMs < dispatchedAtMs!)
    )
      throw new NotificationDeliveryCancellationError();
  } else if (row.observation_bytes !== null || row.observation_digest !== null)
    throw new NotificationDeliveryCancellationError();
  return immutableJsonCopy({
    preparation,
    state: row.state as NotificationCancellationSigningRecord['state'],
    dispatchToken: row.dispatch_token,
    dispatchedAtMs,
    observation,
  });
}
async function signingRecord(
  client: PoolClient,
  q: NotificationDeliveryCancellationSelector,
  locked = false,
) {
  const rows = await client.query<SigningRow>(
    `select preparation_bytes,preparation_digest,request_digest,state,dispatch_token,dispatched_at_ms::text,observation_bytes,observation_digest,openpc.check_notification_cancellation_signing_original(s)
    from control.notification_cancellation_signing s where participant_id=$1 and privacy_domain_id=$2 and notification_occurrence_id=$3 and cause_operation_id=$4 ${locked ? 'for update' : ''}`,
    [
      q.source.worker.participantId,
      q.source.worker.privacyDomainId,
      q.source.notificationOccurrenceId,
      q.causeOperationId,
    ],
  );
  if (rows.rowCount === 0) return null;
  if (rows.rowCount !== 1) throw new NotificationDeliveryCancellationError();
  const result = decodeNotificationCancellationSigningRecord(rows.rows[0]!);
  const original = result.preparation.input.selector;
  if (
    original.source.worker.participantId !== q.source.worker.participantId ||
    original.source.worker.privacyDomainId !== q.source.worker.privacyDomainId ||
    original.source.notificationOccurrenceId !== q.source.notificationOccurrenceId ||
    original.source.eventId !== q.source.eventId ||
    original.causeOperationId !== q.causeOperationId
  )
    throw new NotificationDeliveryCancellationError();
  return result;
}
export function readNotificationCancellationSigning(
  pool: Pool,
  kernel: IdentityKernel,
  socket: TLSSocket,
  value: unknown,
) {
  return withOwner(pool, kernel, socket, value, (client, _admission, q) =>
    signingRecord(client, q),
  );
}
function signingInput(
  binding: Awaited<ReturnType<typeof current>>,
  signer: NotificationReceiptSigner,
) {
  const { nowMs, ...input } = binding,
    source = input.sourceClaims,
    cause = input.cause,
    before = input.before,
    after = input.after;
  const receipt: NotificationDeliveryCancellationReceiptClaims = {
    environmentId: source.environmentId,
    participantId: source.participantId,
    privacyDomainId: source.privacyDomainId,
    operationId: localOperationId(),
    receiptId: localOperationId(),
    notificationOccurrenceId: source.notificationOccurrenceId,
    payloadDigest: source.payloadDigest,
    sourceEventId: source.eventId,
    sourceReceiptDigest: input.sourceReceiptDigest,
    workerProfileDigest: input.workerInstallation.pins.signedProfileDigest,
    routingProfileDigest: source.routingProfileDigest,
    authoritySnapshotDigest: input.workerAuthorityDigest,
    endpointId: source.endpointId,
    endpointRevision: source.endpointRevision,
    causeOperationId: cause.operationId,
    causeAction: 'ACT-NOTIFICATION_ENDPOINTS_UPDATE_RESOURCE-V1',
    causeProfileDigest: cause.profileDigest,
    causeReceiptDigest: cause.receiptDigest,
    causeBeforeStateDigest: cause.beforeStateDigest,
    causeAfterStateDigest: cause.afterStateDigest,
    causeEndpointRevision: cause.successorRevision,
    deliveryRevision: before.revision,
    beforeStateDigest: notificationDeliveryStateDigest(
      notificationDeliverySnapshot.strip().parse(before),
      before.revision,
    ),
    afterStateDigest: notificationDeliveryStateDigest(
      notificationDeliverySnapshot.strip().parse(after),
      after.revision,
    ),
    beforeDeliveryState:
      before.state as NotificationDeliveryCancellationReceiptClaims['beforeDeliveryState'],
    afterDeliveryState:
      after.state as NotificationDeliveryCancellationReceiptClaims['afterDeliveryState'],
    attemptCount: before.attemptCount,
    disposition:
      before.state === 'PENDING'
        ? 'CANCELLED_BEFORE_START'
        : before.state === 'RETRY_WAIT'
          ? 'PREVENT_LATER_ATTEMPTS'
          : 'RECONCILE_ORIGINAL',
    recordedAtMs: nowMs,
    signerKeyId: signer.signerKeyId,
  };
  return validateNotificationDeliveryCancellationInput({
    schema: 'pc.notification.delivery-cancellation-transition.v1',
    ...input,
    receipt,
    payloadHex: encodeNotificationClaim(
      'NotificationDeliveryCancellationReceiptV1',
      receipt,
    ).toString('hex'),
  });
}
async function withSigner<T>(
  client: PoolClient,
  admission: NotificationWorkerAdmission,
  q: NotificationDeliveryCancellationSelector,
  signerInstallationDigest: string,
  operation: (signer: NotificationReceiptSigner) => Promise<T>,
) {
  await client.query(
    "select set_config('openpc.action_intent_id','ACT-POLICY_READ_EFFECTIVE_ACCESS-V1',true)",
  );
  try {
    return await withCurrentNotificationCancellationSigner(
      client,
      admission,
      { worker: q.source.worker, signerInstallationDigest },
      async (signer) => {
        await client.query(
          "select set_config('openpc.action_intent_id','ACT-EVIDENCE_EXPORT_RECORDS-V1',true)",
        );
        try {
          return await operation(signer);
        } finally {
          await client.query(
            "select set_config('openpc.action_intent_id','ACT-POLICY_READ_EFFECTIVE_ACCESS-V1',true)",
          );
        }
      },
    );
  } finally {
    await client.query(
      "select set_config('openpc.action_intent_id','ACT-EVIDENCE_EXPORT_RECORDS-V1',true)",
    );
  }
}
/** Exact durable original. IDs and request bytes are minted once under the real
 * worker/lifecycle/distinct-signer/delivery/claim fences, without provider I/O. */
export async function prepareNotificationCancellationSigning(
  pool: Pool,
  kernel: IdentityKernel,
  socket: TLSSocket,
  value: unknown,
  signerInstallationDigest: string,
  lease?: NotificationWorkerLeaseSelector,
) {
  return withOwner(
    pool,
    kernel,
    socket,
    value,
    async (client, admission, q, source) => {
      const execute = async () => {
        const prior = await signingRecord(client, q);
        if (prior) {
          if (
            prior.preparation.request.signerInstallationDigest !== signerInstallationDigest ||
            prior.preparation.input.selector.expectedRevision !== q.expectedRevision
          )
            throw new NotificationDeliveryCancellationError();
          return prior;
        }
        return withSigner(client, admission, q, signerInstallationDigest, async (signer) => {
          assertNotificationCancellationSigner(signer, client, {
            worker: q.source.worker,
            signerInstallationDigest,
          });
          const binding = await current(client, admission, q, source),
            input = signingInput(binding, signer);
          const trust = { worker: input.workerInstallation, signer: signer.pins };
          const request = createNotificationCancellationReceiptRequest(trust, {
            payloadHex: input.payloadHex,
            cancellationPreparationDigest: sha256(input),
          });
          const checked = validateNotificationCancellationReceiptRequest(request, trust),
            preparation = { input, trust, request };
          const bytes = Buffer.from(canonicalJson(preparation));
          await client.query(
            `insert into control.notification_cancellation_signing(participant_id,privacy_domain_id,operation_id,signing_attempt_id,notification_occurrence_id,cause_operation_id,signer_installation_digest,preparation,preparation_bytes,preparation_digest,request_digest)
        values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
            [
              request.participantId,
              request.privacyDomainId,
              request.operationId,
              request.signingAttemptId,
              q.source.notificationOccurrenceId,
              q.causeOperationId,
              signer.digest,
              preparation,
              bytes,
              sha256(bytes),
              checked.requestDigest,
            ],
          );
          return (await signingRecord(client, q))!;
        });
      };
      return lease === undefined
        ? execute()
        : withNotificationWorkerLease(client, q.source, lease, 'CANCEL', async () => {
            return execute();
          });
    },
    lease,
  );
}
function unchangedInput(input: CancellationInput, binding: Awaited<ReturnType<typeof current>>) {
  const { nowMs, ...actual } = binding;
  const expected = {
    ...actual,
    schema: input.schema,
    receipt: input.receipt,
    payloadHex: input.payloadHex,
  };
  if (canonicalJson(input) !== canonicalJson(expected) || input.receipt.recordedAtMs > nowMs)
    throw new NotificationDeliveryCancellationError();
}
const signingClaims = new WeakMap<object, NotificationCancellationSigningRecord>();
const leasedSigningClaims = new WeakMap<object, NotificationWorkerLeaseWindow>();
async function claimSigning(
  pool: Pool,
  kernel: IdentityKernel,
  socket: TLSSocket,
  value: unknown,
  lease?: NotificationWorkerLeaseSelector,
) {
  let claimedWindow: NotificationWorkerLeaseWindow | undefined;

  const claimed = await withOwner(
    pool,
    kernel,
    socket,
    value,
    async (client, admission, q, source) => {
      const execute = async () => {
        const prior = await signingRecord(client, q);
        if (!prior || prior.state !== 'PREPARED') return null;
        const digest = prior.preparation.request.signerInstallationDigest;
        return withSigner(client, admission, q, digest, async (signer) => {
          assertNotificationCancellationSigner(signer, client, {
            worker: q.source.worker,
            signerInstallationDigest: digest,
          });
          unchangedInput(prior.preparation.input, await current(client, admission, q, source));
          const locked = await signingRecord(client, q, true);
          if (!locked || locked.state !== 'PREPARED') return null;
          const token = localOperationId();
          const changed = await client.query(
            `update control.notification_cancellation_signing set state='DISPATCHED',dispatch_token=$4,dispatched_at_ms=floor(extract(epoch from statement_timestamp())*1000)
        where participant_id=$1 and privacy_domain_id=$2 and operation_id=$3 and state='PREPARED' returning operation_id`,
            [
              q.source.worker.participantId,
              q.source.worker.privacyDomainId,
              locked.preparation.request.operationId,
              token,
            ],
          );
          if (changed.rowCount !== 1) throw new NotificationDeliveryCancellationError();
          return (await signingRecord(client, q))!;
        });
      };
      return lease === undefined
        ? execute()
        : withNotificationWorkerLease(client, q.source, lease, 'CANCEL', async (window) => {
            claimedWindow = window;
            return execute();
          });
    },
    lease,
  );
  if (!claimed) return null;
  // Only the acknowledged COMMIT return can mint this one-use local handle.
  const capability = Object.freeze(Object.create(null)) as object;
  signingClaims.set(capability, claimed);
  if (claimedWindow) leasedSigningClaims.set(capability, claimedWindow);
  return capability;
}
export async function attachNotificationCancellationSigningObservation(
  pool: Pool,
  kernel: IdentityKernel,
  socket: TLSSocket,
  value: unknown,
  observed: unknown,
) {
  return withOwner(pool, kernel, socket, value, async (client, _admission, q) => {
    const prior = await signingRecord(client, q, true);
    if (!prior || prior.state === 'PREPARED') throw new NotificationDeliveryCancellationError();
    const observation = validateNotificationCancellationReceiptObservation(
      prior.preparation.request,
      observed,
      prior.preparation.trust,
      prior.observation ?? undefined,
    );
    if (prior.observation) return prior;
    const bytes = Buffer.from(canonicalJson(observation));
    await client.query(
      `update control.notification_cancellation_signing set state='OBSERVED',observation=$4,observation_bytes=$5,observation_digest=$6
      where participant_id=$1 and privacy_domain_id=$2 and operation_id=$3 and state='DISPATCHED'`,
      [
        q.source.worker.participantId,
        q.source.worker.privacyDomainId,
        prior.preparation.request.operationId,
        observation,
        bytes,
        sha256(bytes),
      ],
    );
    const retained = await signingRecord(client, q);
    if (
      !retained?.observation ||
      canonicalJson(retained.observation) !== canonicalJson(observation)
    )
      throw new NotificationDeliveryCancellationError();
    return retained;
  });
}
export type NotificationCancellationSigningResult =
  | { state: 'OBSERVED'; record: NotificationCancellationSigningRecord }
  | { state: 'UNKNOWN'; selector: NotificationDeliveryCancellationSelector };
/** Actual pinned HTTP/TLS transport only, outside DB transactions. No signer
 * callback/private key. Any uncertain claim/perform/attach is lookup-only. */
export class NotificationCancellationSigningRuntime {
  constructor(
    private readonly pool: Pool,
    private readonly kernel: IdentityKernel,
    private readonly transport: Omit<
      Parameters<typeof createHttpNotificationCancellationReceiptProvider>[0],
      'trust'
    >,
  ) {}
  async dispatchOnce(
    socket: TLSSocket,
    value: unknown,
    lease?: NotificationWorkerLeaseSelector,
  ): Promise<NotificationCancellationSigningResult> {
    const q = notificationDeliveryCancellationSelector.parse(immutableJsonCopy(value));
    let capability: object | null;
    try {
      capability = await claimSigning(this.pool, this.kernel, socket, q, lease);
    } catch {
      return { state: 'UNKNOWN', selector: q };
    }
    if (!capability) return this.reconcile(socket, q);
    const original = signingClaims.get(capability);
    signingClaims.delete(capability);
    const window = leasedSigningClaims.get(capability);
    leasedSigningClaims.delete(capability);
    if (!original) throw new NotificationDeliveryCancellationError();
    let provider: ReturnType<typeof createHttpNotificationCancellationReceiptProvider> | undefined;
    try {
      provider = createHttpNotificationCancellationReceiptProvider({
        ...this.transport,
        trust: original.preparation.trust,
        ...(lease === undefined
          ? {}
          : {
              signal: notificationWorkerLeaseSignal(
                window ??
                  (() => {
                    throw new NotificationDeliveryCancellationError();
                  })(),
                this.transport.signal,
              ),
            }),
      });
      const observed = await provider.perform(original.preparation.request);
      return {
        state: 'OBSERVED',
        record: await attachNotificationCancellationSigningObservation(
          this.pool,
          this.kernel,
          socket,
          q,
          observed,
        ),
      };
    } catch {
      return { state: 'UNKNOWN', selector: q };
    } finally {
      provider?.close();
    }
  }
  dispatchOnceLeased(socket: TLSSocket, value: unknown, lease: unknown) {
    return this.dispatchOnce(
      socket,
      value,
      notificationWorkerLeaseSelector.parse(immutableJsonCopy(lease)),
    );
  }
  async reconcile(
    socket: TLSSocket,
    value: unknown,
  ): Promise<NotificationCancellationSigningResult> {
    const q = notificationDeliveryCancellationSelector.parse(immutableJsonCopy(value));
    const original = await readNotificationCancellationSigning(this.pool, this.kernel, socket, q);
    if (!original || original.state === 'PREPARED') return { state: 'UNKNOWN', selector: q };
    if (original.state === 'OBSERVED') return { state: 'OBSERVED', record: original };
    let provider: ReturnType<typeof createHttpNotificationCancellationReceiptProvider> | undefined;
    try {
      provider = createHttpNotificationCancellationReceiptProvider({
        ...this.transport,
        trust: original.preparation.trust,
      });
      const observed = await provider.lookup(original.preparation.request);
      if (!observed) return { state: 'UNKNOWN', selector: q };
      return {
        state: 'OBSERVED',
        record: await attachNotificationCancellationSigningObservation(
          this.pool,
          this.kernel,
          socket,
          q,
          observed,
        ),
      };
    } catch {
      return { state: 'UNKNOWN', selector: q };
    } finally {
      provider?.close();
    }
  }
}

/** Publish only the retained distinct-purpose request and first signed result.
 * Canonical registration must install both declarations and their SQL guards;
 * missing admission fails closed. No provider I/O or automatic retry follows an
 * unknown COMMIT; the exact occurrence/cause selector owns historical readback. */
export async function publishNotificationDeliveryCancellation(
  pool: Pool,
  kernel: IdentityKernel,
  socket: TLSSocket,
  value: unknown,
  lease?: NotificationWorkerLeaseSelector,
): Promise<NotificationDeliveryCancellationTransition> {
  const q = notificationDeliveryCancellationSelector.parse(immutableJsonCopy(value));
  let mutationAttempted = false;
  try {
    return await withOwner(
      pool,
      kernel,
      socket,
      q,
      async (client, admission, selector, source) => {
        const execute = async () => {
          const signing = await signingRecord(client, selector);
          if (signing?.observation?.outcome !== 'SIGNED' || !signing.observation.coseHex)
            throw new NotificationDeliveryCancellationError();
          const encoded = encodeNotificationDeliveryCancellation({
            ...signing.preparation.input,
            coseHex: signing.observation.coseHex,
          });
          const retained = await original(client, selector, source);
          if (retained) {
            if (canonicalJson(retained) !== canonicalJson(encoded.transition))
              throw new NotificationDeliveryCancellationError();
            return retained;
          }
          const input = await current(client, admission, selector, source);
          unchangedInput(signing.preparation.input, input);
          const installed = await client.query<{ present: boolean }>(
            "select to_regprocedure('openpc.check_notification_delivery_cancellation_signer(uuid,text)') is not null present",
          );
          if (installed.rowCount !== 1 || installed.rows[0]?.present !== true)
            throw new NotificationDeliveryCancellationError('SIGNER_OWNER_UNBOUND');
          await client.query(
            'select openpc.check_notification_delivery_cancellation_signer($1,$2)',
            [encoded.transition.receipt.operationId, encoded.digest],
          );
          const r = encoded.transition.receipt;
          mutationAttempted = true;
          await client.query(
            `insert into control.notification_delivery_cancellation(participant_id,privacy_domain_id,operation_id,receipt_id,notification_occurrence_id,payload_digest,source_operation_id,cause_operation_id,cause_receipt_id,delivery_revision,worker_installation_digest,transition,transition_bytes,transition_digest,receipt_payload,receipt_digest,cose_sign1)
        values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)`,
            [
              r.participantId,
              r.privacyDomainId,
              r.operationId,
              r.receiptId,
              r.notificationOccurrenceId,
              r.payloadDigest,
              source.sourceOperationId,
              r.causeOperationId,
              input.cause.receiptId,
              r.deliveryRevision,
              q.source.worker.installationDigest,
              encoded.transition,
              encoded.bytes,
              encoded.digest,
              encoded.receiptPayload,
              encoded.receiptDigest,
              encoded.coseSign1,
            ],
          );
          const changed = await client.query(
            `update control.notification_delivery set state=$4,cancel_requested=true,next_attempt_at_ms=null,revision=revision+1
        where participant_id=$1 and privacy_domain_id=$2 and notification_occurrence_id=$3 and revision=$5 and not cancel_requested returning notification_occurrence_id`,
            [
              r.participantId,
              r.privacyDomainId,
              r.notificationOccurrenceId,
              r.afterDeliveryState,
              r.deliveryRevision,
            ],
          );
          if (changed.rowCount !== 1) throw new NotificationDeliveryCancellationError();
          await client.query(
            'select openpc.check_notification_delivery_cancellation_complete($1)',
            [r.operationId],
          );
          return encoded.transition;
        };
        return lease === undefined
          ? execute()
          : withNotificationWorkerLease(client, q.source, lease, 'CANCEL', async () => {
              return execute();
            });
      },
      lease,
    );
  } catch (error) {
    if (mutationAttempted) throw new NotificationDeliveryCancellationCommitUnknown(q);
    throw error;
  }
}

/** Leased production entry; original API remains available to existing owners. */
export function prepareNotificationCancellationSigningLeased(
  lease: unknown,
  pool: Pool,
  kernel: IdentityKernel,
  socket: TLSSocket,
  value: unknown,
  signerInstallationDigest: string,
) {
  return prepareNotificationCancellationSigning(
    pool,
    kernel,
    socket,
    value,
    signerInstallationDigest,
    notificationWorkerLeaseSelector.parse(immutableJsonCopy(lease)),
  );
}

/** Leased production entry; original API remains available to existing owners. */
export function publishNotificationDeliveryCancellationLeased(
  lease: unknown,
  pool: Pool,
  kernel: IdentityKernel,
  socket: TLSSocket,
  value: unknown,
) {
  return publishNotificationDeliveryCancellation(
    pool,
    kernel,
    socket,
    value,
    notificationWorkerLeaseSelector.parse(immutableJsonCopy(lease)),
  );
}
