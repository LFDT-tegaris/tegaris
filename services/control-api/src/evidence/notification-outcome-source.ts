import { validateNotificationWorkerInstallation } from '../notifications/worker-installation-contract.js';
import { validateNotificationOutcomeSignerInstallation } from '../notifications/receipt-signer-installation.js';
import type { PoolClient } from 'pg';
import { sha256 } from '../configuration/digest.js';
import {
  evidenceScope,
  EvidenceCustodyError,
  type EvidenceScope,
  type SourceReceipt,
} from './segment.js';
import {
  notificationOutcomeEvidenceFormat,
  notificationOutcomePublication,
  assertNotificationCompletionRow,
  type NotificationCompletionRow,
} from '../notifications/delivery-outcome-publication-contract.js';
import { readNotificationOutcomePublicationInTransaction } from '../notifications/delivery-outcome-publication.js';
import { decodeNotificationDeliveryOutcomeTransition } from '../notifications/delivery-outcome-contract.js';
import { notificationOutcomeSigningSelector } from '../notifications/delivery-outcome-state.js';

/** Pure independently verified native evidence projection. The source reader
 * separately requires actual SQL publication provenance and current custody scope.
 * No fake audit_occurrence/evidence_record, new signature or success assertion. */
export function verifyNotificationOutcomeSource(
  value: unknown,
  event: NotificationCompletionRow | null,
  scope: Pick<EvidenceScope, 'participantId' | 'privacyDomainId'>,
): SourceReceipt {
  try {
    const p = notificationOutcomePublication(value),
      r = p.encoded.transition.receipt;
    if (r.participantId !== scope.participantId || r.privacyDomainId !== scope.privacyDomainId)
      throw new Error();
    assertNotificationCompletionRow(p, event);
    return {
      recordId: r.receiptId,
      evidenceClass: 'EFFECT',
      sourceFormat: notificationOutcomeEvidenceFormat,
      occurredAt: new Date(r.recordedAtMs).toISOString().replace(/\.(\d{3})Z$/u, '.$1000Z'),
      receiptDigest: sha256(p.encoded.coseSign1),
      receiptBase64: p.encoded.coseSign1.toString('base64'),
    };
  } catch {
    throw new EvidenceCustodyError('INTEGRITY');
  }
}
/** EvidenceCustody calls this under its existing authenticated source scope and
 * lifecycle fence. Every selected row is verified, including incomplete joins;
 * missing signing/outbox/work lineage fails instead of silently disappearing. */
export async function readNotificationOutcomeEvidenceSources(
  client: PoolClient,
  value: EvidenceScope,
): Promise<SourceReceipt[]> {
  const scope = evidenceScope.parse(value);
  const rows = await client.query<{
    transition_bytes: Buffer;
    transition_digest: string;
    start_signer_digest: string | null;
  }>(
    `select o.transition_bytes,o.transition_digest,s.signer_installation_digest start_signer_digest
     from control.notification_delivery_outcome o left join control.notification_delivery_signing s
      on s.participant_id=o.participant_id and s.privacy_domain_id=o.privacy_domain_id and s.operation_id=o.start_operation_id
     where o.participant_id=$1 and o.privacy_domain_id=$2 and not exists(select 1 from control.evidence_catalogue c
      where c.participant_id=o.participant_id and c.privacy_domain_id=o.privacy_domain_id and c.stream_id=$3 and c.record_id=o.receipt_id::text
       and c.receipt_digest='sha256:'||encode(sha256(o.cose_sign1),'hex') and c.source_format='COSE_SIGN1_24029_1_366' and c.evidence_class='EFFECT')
     order by (o.transition->'receipt'->>'recordedAtMs')::numeric,o.receipt_id limit 8`,
    [scope.participantId, scope.privacyDomainId, scope.streamId],
  );
  const records: SourceReceipt[] = [];
  for (const row of rows.rows) {
    const t = decodeNotificationDeliveryOutcomeTransition(
        row.transition_bytes,
        row.transition_digest,
      ),
      original = notificationOutcomePublication(t).proposal.original;
    const selector = notificationOutcomeSigningSelector.parse({
      original: {
        operationId: t.receipt.startOperationId,
        signerInstallationDigest: row.start_signer_digest,
        source: {
          worker: {
            participantId: scope.participantId,
            privacyDomainId: scope.privacyDomainId,
            installationDigest: original.workerInstallationDigest,
          },
          notificationOccurrenceId: t.receipt.notificationOccurrenceId,
          eventId: original.source.eventId,
        },
      },
      worker: {
        participantId: scope.participantId,
        privacyDomainId: scope.privacyDomainId,
        installationDigest: validateNotificationWorkerInstallation(
          t.workerInstallation,
          t.receipt.recordedAtMs,
        ).installationDigest,
      },
      operationId: t.receipt.operationId,
      signerInstallationDigest: validateNotificationOutcomeSignerInstallation(t.signerInstallation)
        .digest,
    });
    const actual = await readNotificationOutcomePublicationInTransaction(client, selector);
    if (!actual || actual.encoded.transitionDigest !== row.transition_digest)
      throw new EvidenceCustodyError('INTEGRITY');
    // The same-client reader verified the exact event row; derive only the
    // independently signed native bytes for the existing custody pipeline.
    const r = actual.encoded.transition.receipt;
    records.push({
      recordId: r.receiptId,
      evidenceClass: 'EFFECT',
      sourceFormat: notificationOutcomeEvidenceFormat,
      occurredAt: new Date(r.recordedAtMs).toISOString().replace(/\.(\d{3})Z$/u, '.$1000Z'),
      receiptDigest: sha256(actual.encoded.coseSign1),
      receiptBase64: actual.encoded.coseSign1.toString('base64'),
    });
  }
  return records;
}
