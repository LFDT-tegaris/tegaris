import type { PoolClient } from 'pg';
import { decodeNotificationDeliveryOutcomeTransition } from '../../notifications/delivery-outcome-contract.js';
import {
  qualificationCaseResultSchema,
  qualificationCases,
  qualificationOutcomeSchema,
  qualificationSampleSchema,
  qualificationTime,
  reject,
  type QualificationPeer,
  type NotificationQualificationSelector,
  type QualificationCase,
  type QualificationOutcome,
} from './notification-qualification-contract.js';
import {
  appendQualificationRecord,
  qualificationContext,
  qualificationNow,
  readNotificationQualificationOriginal,
  readQualificationInstallation,
  recordValue,
  withNotificationQualificationRun,
} from './notification-qualification-store.js';
/** Metrics originate in the protected database on this transaction. No request
 * may submit numbers or an attestation and have them retained as measurements. */
export async function sampleNotificationQualification(
  c: PoolClient,
  s: NotificationQualificationSelector,
  peer: QualificationPeer,
) {
  return withNotificationQualificationRun(c, s, peer, async (same) => {
    const original = await readNotificationQualificationOriginal(same, s),
      pins = await readQualificationInstallation(same, s, true);
    const samples = original.records.filter((r) => r.record.kind === 'SAMPLE');
    if (samples.length >= pins.maximumSamples) reject();
    const sourceIds = original.records
      .filter((r) => r.record.kind === 'SOURCE')
      .map((r) => r.record.key);
    // Validating original proof custody precedes all measurements.
    await same.query(
      `select openpc.check_notification_async_work_proof(w.event_id,w.revision) from control.notification_async_work w where participant_id=$1 and privacy_domain_id=$2 and event_id=any($3::uuid[])`,
      [s.participantId, s.privacyDomainId, sourceIds],
    );
    const at = await qualificationNow(same);
    const r = await same.query<{
      leases: string;
      items: string;
      bytes: string;
      age: string;
      batch: string;
      payload: string;
      dispatched: string;
    }>(
      `with work as (select * from control.notification_async_work where participant_id=$1 and privacy_domain_id=$2 and event_id=any($3::uuid[])),
       active as (select * from work where state in ('PENDING','RETRY_WAIT','LEASED','RECONCILING') or charged),
       batches as (select count(*) n from control.notification_async_work_transition t where participant_id=$1 and privacy_domain_id=$2 and event_id=any($3::uuid[]) and transition->'after'->>'state'='LEASED' and (transition->'before'->>'lease_epoch')::numeric<(transition->'after'->>'lease_epoch')::numeric group by operation_id),
       starts as (select st.* from control.notification_delivery_start st join work w using(participant_id,privacy_domain_id,notification_occurrence_id))
       select (select count(*)::text from active where state='LEASED' and lease_until_ms>$4) leases,
       (select count(*)::text from active) items,(select coalesce(sum(payload_bytes),0)::text from active) bytes,
       (select coalesce(max($4-published_at_ms),0)::text from active) age,
       (select coalesce(max(n),0)::text from batches) batch,
       (select coalesce(max((transition->'attempt'->>'payloadBytes')::numeric),0)::text from starts) payload,
       (select count(*)::text from starts) dispatched`,
      [s.participantId, s.privacyDomainId, sourceIds, at],
    );
    if (r.rowCount !== 1) reject('EVIDENCE');
    const row = r.rows[0]!;
    const sample = qualificationSampleSchema.parse({
      atMs: at,
      sourceEventIds: sourceIds,
      activeLeases: Number(row.leases),
      batchSize: Number(row.batch),
      queueItems: Number(row.items),
      queueBytes: Number(row.bytes),
      maximumPayloadBytes: Number(row.payload),
      maximumQueueAgeMs: Number(row.age),
      dispatched: Number(row.dispatched),
    });
    await appendQualificationRecord(
      same,
      s,
      'SAMPLE',
      String(samples.length + 1).padStart(6, '0'),
      sample,
    );
    return sample;
  });
}
/** Called only by the approved native harness after its actual scenario returns
 * or throws. Input contains a closed error classification, never measurements. */
export async function retainNotificationQualificationCase(
  c: PoolClient,
  s: NotificationQualificationSelector,
  peer: QualificationPeer,
  value: unknown,
) {
  return withNotificationQualificationRun(c, s, peer, async (same) => {
    const result = qualificationCaseResultSchema.parse(value),
      original = await readNotificationQualificationOriginal(same, s);
    if (result.sourceEventIds.some((id) => !recordValue(original, 'SOURCE', id)))
      reject('EVIDENCE');
    if ((result.status === 'PASS') !== (result.reason === 'COMPLETE')) reject();
    return appendQualificationRecord(same, s, 'CASE', result.caseId, result);
  });
}
async function originalOutcomes(
  c: PoolClient,
  s: NotificationQualificationSelector,
  sourceIds: string[],
) {
  const pins = await readQualificationInstallation(c, s);
  const size = await c.query<{ bytes: string }>(
    `select coalesce(sum(octet_length(o.transition_bytes)*2+octet_length(o.receipt_payload)*2+octet_length(o.cose_sign1)*2+octet_length(st.receipt_payload)*2+octet_length(st.cose_sign1)*2+1024),0)::text bytes
    from control.outbox_event e join control.notification_delivery_start st on st.participant_id=e.participant_id and st.privacy_domain_id=e.privacy_domain_id and st.notification_occurrence_id=e.aggregate_id
    join control.notification_delivery_outcome o on o.participant_id=st.participant_id and o.privacy_domain_id=st.privacy_domain_id and o.attempt_id=st.attempt_id
    where e.participant_id=$1 and e.privacy_domain_id=$2 and e.event_id=any($3::uuid[])`,
    [s.participantId, s.privacyDomainId, sourceIds],
  );
  if (BigInt(size.rows[0]?.bytes ?? '0') > BigInt(pins.maximumEvidenceBytes)) reject('EVIDENCE');
  const rows = await c.query<{
    event_id: string;
    published: string;
    started: string;
    start_payload: Buffer;
    start_cose: Buffer;
    transition_bytes: Buffer;
    transition_digest: string;
    receipt_payload: Buffer;
    cose_sign1: Buffer;
  }>(
    `select e.event_id,floor(extract(epoch from e.occurred_at)*1000)::text published,
     st.transition->'attempt'->>'startedAtMs' started,st.receipt_payload start_payload,st.cose_sign1 start_cose,o.transition_bytes,o.transition_digest,o.receipt_payload,o.cose_sign1,
     openpc.check_notification_delivery_start_original(st),openpc.check_notification_outcome_publication_original(o.operation_id)
     from control.outbox_event e join control.notification_delivery_start st on st.participant_id=e.participant_id and st.privacy_domain_id=e.privacy_domain_id and st.notification_occurrence_id=e.aggregate_id
     join control.notification_delivery_outcome o on o.participant_id=st.participant_id and o.privacy_domain_id=st.privacy_domain_id and o.attempt_id=st.attempt_id
     where e.participant_id=$1 and e.privacy_domain_id=$2 and e.event_id=any($3::uuid[]) order by st.attempt_id`,
    [s.participantId, s.privacyDomainId, sourceIds],
  );
  const outcomes: QualificationOutcome[] = rows.rows.map((row) => {
    const t = decodeNotificationDeliveryOutcomeTransition(
      row.transition_bytes,
      row.transition_digest,
    );
    if (
      !row.receipt_payload.equals(Buffer.from(t.payloadHex, 'hex')) ||
      !row.cose_sign1.equals(Buffer.from(t.coseHex, 'hex'))
    )
      reject('EVIDENCE');
    return qualificationOutcomeSchema.parse({
      eventId: row.event_id,
      attemptId: t.receipt.attemptId,
      operationId: t.receipt.operationId,
      publishedAtMs: Number(row.published),
      startedAtMs: Number(row.started),
      completedAtMs: t.receipt.recordedAtMs,
      startPayloadHex: row.start_payload.toString('hex'),
      startCoseHex: row.start_cose.toString('hex'),
      outcomePayloadHex: row.receipt_payload.toString('hex'),
      outcomeCoseHex: row.cose_sign1.toString('hex'),
      transitionHex: row.transition_bytes.toString('hex'),
      transitionDigest: row.transition_digest,
    });
  });
  const unresolved = await c.query<{ count: string }>(
    `select count(*)::text count from control.notification_delivery_start st join control.outbox_event e on e.participant_id=st.participant_id and e.privacy_domain_id=st.privacy_domain_id and e.aggregate_id=st.notification_occurrence_id where e.participant_id=$1 and e.privacy_domain_id=$2 and e.event_id=any($3::uuid[]) and not exists(select 1 from control.notification_delivery_outcome o where o.participant_id=st.participant_id and o.privacy_domain_id=st.privacy_domain_id and o.attempt_id=st.attempt_id)`,
    [s.participantId, s.privacyDomainId, sourceIds],
  );
  return {
    outcomes,
    unresolvedAttempts: qualificationTime.parse(Number(unresolved.rows[0]?.count)),
  };
}
/** Original-only recovery can seal interrupted/expired runs as UNKNOWN, never
 * restart an external effect or upgrade missing cases to PASS. This protected
 * root-local retention remains possible after execution authority expires. */
export async function sealNotificationQualification(
  c: PoolClient,
  s: NotificationQualificationSelector,
) {
  const ctx = await qualificationContext(c, s);
  await c.query(
    "select pg_advisory_xact_lock(hashtextextended('notification-qualification-run:'||$1,0))",
    [s.runId],
  );
  let original = await readNotificationQualificationOriginal(c, s);
  if (recordValue(original, 'RESULT')) return original;
  const dispatch = recordValue(original, 'DISPATCH');
  if (!dispatch) reject('UNBOUND');
  for (const caseId of qualificationCases)
    if (!recordValue(original, 'CASE', caseId))
      await appendQualificationRecord(c, s, 'CASE', caseId, {
        caseId,
        status: 'UNKNOWN',
        reason: 'INTERRUPTED',
        sourceEventIds: [],
      });
  original = await readNotificationQualificationOriginal(c, s);
  const sourceIds = original.records
      .filter((r) => r.record.kind === 'SOURCE')
      .map((r) => r.record.key),
    collected = await originalOutcomes(c, s, sourceIds);
  const startedAtMs = qualificationTime.parse(
      (dispatch.record.value as { startedAtMs: unknown }).startedAtMs,
    ),
    completedAtMs = await qualificationNow(c);
  const raw = await appendQualificationRecord(c, s, 'RAW', 'original', {
    startedAtMs,
    completedAtMs,
    samples: original.records
      .filter((r) => r.record.kind === 'SAMPLE')
      .map((r) => qualificationSampleSchema.parse(r.record.value)),
    cases: original.records
      .filter((r) => r.record.kind === 'CASE')
      .map((r) => qualificationCaseResultSchema.parse(r.record.value)),
    unresolvedAttempts: collected.unresolvedAttempts,
  });
  const outcomes = await appendQualificationRecord(c, s, 'OUTCOMES', 'original', {
    outcomes: collected.outcomes,
  });
  await appendQualificationRecord(c, s, 'RESULT', 'original', {
    rawEvidenceDigest: raw.digest,
    originalSignedOutcomesDigest: outcomes.digest,
    completedAtMs,
  });
  await ctx.confirm();
  return readNotificationQualificationOriginal(c, s);
}
export type QualificationHarnessCaseInput = {
  caseId: QualificationCase;
  selector: NotificationQualificationSelector;
};
