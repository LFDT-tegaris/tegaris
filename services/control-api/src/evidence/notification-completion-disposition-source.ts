import type { PoolClient } from 'pg';
import { notificationCoseProfiles } from '../../../../packages/security-kernel/src/notification-gateway/generated.js';
import { sha256, canonicalJson } from '../configuration/digest.js';
import {
  evidenceScope,
  EvidenceCustodyError,
  type EvidenceScope,
  type SourceReceipt,
} from './segment.js';
import { encodeNotificationCompletionDisposition } from '../notifications/completion-disposition-contract.js';
import {
  readNotificationCompletionSigningInTransaction,
  notificationCompletionSigningTransition,
} from '../notifications/completion-disposition-state.js';
export function notificationCompletionDispositionEvidenceFormat() {
  const p = notificationCoseProfiles.NotificationCompletionDispositionReceiptV1;
  if (!p) throw new EvidenceCustodyError('INTEGRITY');
  return `COSE_SIGN1_${p.schemaId}_1_${p.purposeCode}`;
}
/** Independently verifies native signed evidence and scope. Persisted completeness
 * is separately mandatory; this pure projection does not prove an effect. */
export function verifyNotificationCompletionDispositionSource(
  value: unknown,
  scope: Pick<EvidenceScope, 'participantId' | 'privacyDomainId'>,
): SourceReceipt {
  try {
    const e = encodeNotificationCompletionDisposition(value),
      r = e.transition.receipt;
    if (r.participantId !== scope.participantId || r.privacyDomainId !== scope.privacyDomainId)
      throw new Error();
    return {
      recordId: r.receiptId,
      evidenceClass: 'EFFECT',
      sourceFormat: notificationCompletionDispositionEvidenceFormat(),
      occurredAt: new Date(r.recordedAtMs).toISOString().replace(/\.(\d{3})Z$/u, '.$1000Z'),
      receiptDigest: sha256(e.cose),
      receiptBase64: e.cose.toString('base64'),
    };
  } catch {
    throw new EvidenceCustodyError('INTEGRITY');
  }
}
/** Existing custody scope/fence is required. Read every selected record's original
 * signing journal and atomic proof; do not omit malformed/incomplete joins. */
export async function readNotificationCompletionDispositionEvidenceSources(
  client: PoolClient,
  value: EvidenceScope,
): Promise<SourceReceipt[]> {
  const scope = evidenceScope.parse(value),
    format = notificationCompletionDispositionEvidenceFormat();
  const rows = await client.query<{
    event_id: string;
    transition: unknown;
    transition_bytes: Buffer;
    transition_digest: string;
    receipt_payload: Buffer;
    cose_sign1: Buffer;
  }>(
    `
    select event_id::text,transition,transition_bytes,transition_digest,receipt_payload,cose_sign1 from control.notification_completion_disposition d
    where participant_id=$1 and privacy_domain_id=$2 and not exists(select 1 from control.evidence_catalogue c where c.participant_id=d.participant_id and c.privacy_domain_id=d.privacy_domain_id and c.stream_id=$3 and c.record_id=d.receipt_id::text and c.receipt_digest='sha256:'||encode(sha256(d.cose_sign1),'hex') and c.source_format=$4 and c.evidence_class='EFFECT')
    order by (transition->'receipt'->>'recordedAtMs')::numeric,receipt_id limit 8`,
    [scope.participantId, scope.privacyDomainId, scope.streamId, format],
  );
  const results: SourceReceipt[] = [];
  for (const row of rows.rows) {
    const e = encodeNotificationCompletionDisposition(row.transition),
      r = e.transition.receipt;
    if (
      !e.bytes.equals(row.transition_bytes) ||
      e.transitionDigest !== row.transition_digest ||
      !e.payload.equals(row.receipt_payload) ||
      !e.cose.equals(row.cose_sign1) ||
      r.sourceEventId !== row.event_id
    )
      throw new EvidenceCustodyError('INTEGRITY');
    const record = await readNotificationCompletionSigningInTransaction(client, {
      worker: {
        participantId: scope.participantId,
        privacyDomainId: scope.privacyDomainId,
        installationDigest: r.workerInstallationDigest,
      },
      eventId: r.sourceEventId,
      operationId: r.operationId,
    });
    if (
      !record ||
      canonicalJson(notificationCompletionSigningTransition(record).transition) !==
        canonicalJson(e.transition)
    )
      throw new EvidenceCustodyError('INTEGRITY');
    await client.query('select openpc.check_notification_completion_disposition_original($1)', [
      r.sourceEventId,
    ]);
    results.push(verifyNotificationCompletionDispositionSource(e.transition, scope));
  }
  return results;
}
