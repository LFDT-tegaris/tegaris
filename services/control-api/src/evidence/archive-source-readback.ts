import type { PoolClient } from 'pg';
import { LocalEvidenceVault, vaultObject } from './local-vault.js';
import {
  openSegment,
  EvidenceCustodyError,
  type EvidenceScope,
  type SourceReceipt,
  type SegmentHeader,
} from './segment.js';

export type ArchiveKeyResolver = (keyId: string) => Promise<Buffer>;
const values = (scope: EvidenceScope) => [
  scope.participantId,
  scope.privacyDomainId,
  scope.streamId,
];
type OriginalRow = {
  recordId: string;
  evidenceClass: string;
  sourceFormat: string;
  receiptDigest: string;
  occurredAt: string;
  sequence: string;
  header: SegmentHeader;
  objectDigest: string;
  encrypted: Buffer | null;
};
/** No new custody implementation: decode only existing exact-version segments
 * through openSegment. The same function verifies replay and local-vault restore. */
export async function readArchivedSourceRecords(
  client: PoolClient,
  scope: EvidenceScope,
  recordIds: readonly string[],
  resolveKey: ArchiveKeyResolver,
  sink?: LocalEvidenceVault,
) {
  const selected = await client.query<OriginalRow>(
    `select c.record_id as "recordId",c.evidence_class as "evidenceClass",c.source_format as "sourceFormat",
     c.receipt_digest as "receiptDigest",c.sequence::text,
     to_char(c.occurred_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') as "occurredAt",
     jsonb_build_object('version','OPENPC_EVIDENCE_SEGMENT_V1','participantId',s.participant_id::text,
      'privacyDomainId',s.privacy_domain_id::text,'streamId',s.stream_id,'segmentId',s.segment_id::text,
      'firstSequence',s.first_sequence::text,'throughSequence',s.through_sequence::text,
      'previousSegmentDigest',s.previous_segment_digest,'keyId',s.key_id,
      'retentionUntil',to_char(s.retention_until at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')) header,
     s.object_digest as "objectDigest",p.encrypted_segment encrypted
     from control.evidence_catalogue c join control.evidence_segment s using(participant_id,privacy_domain_id,stream_id,segment_id)
     left join control.evidence_segment_payload p using(participant_id,privacy_domain_id,stream_id,segment_id)
     where c.participant_id=$1 and c.privacy_domain_id=$2 and c.stream_id=$3 and c.record_id=any($4::text[])
     order by c.sequence`,
    [...values(scope), recordIds],
  );
  const opened = new Map<string, ReturnType<typeof openSegment>>(),
    records = new Map<string, SourceReceipt>();
  for (const row of selected.rows) {
    if (records.has(row.recordId) || !recordIds.includes(row.recordId))
      throw new EvidenceCustodyError('INTEGRITY');
    let segment = opened.get(row.header.segmentId);
    if (!segment) {
      const bytes = sink
        ? await sink.read(vaultObject(sink.sinkId, row.header, row.objectDigest))
        : row.encrypted;
      if (!bytes) throw new EvidenceCustodyError('UNAVAILABLE');
      segment = openSegment(
        bytes,
        row.objectDigest,
        row.header,
        await resolveKey(row.header.keyId),
      );
      opened.set(row.header.segmentId, segment);
    }
    const record = segment.records.find((item) => item.recordId === row.recordId);
    if (
      !record ||
      record.sequence !== row.sequence ||
      record.evidenceClass !== row.evidenceClass ||
      record.sourceFormat !== row.sourceFormat ||
      record.receiptDigest !== row.receiptDigest ||
      record.occurredAt !== row.occurredAt
    )
      throw new EvidenceCustodyError('INTEGRITY');
    records.set(row.recordId, {
      recordId: record.recordId,
      evidenceClass: record.evidenceClass,
      sourceFormat: record.sourceFormat,
      receiptDigest: record.receiptDigest,
      occurredAt: record.occurredAt,
      receiptBase64: record.receiptBase64,
    });
  }
  return records;
}
