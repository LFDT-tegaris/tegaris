import type { PoolClient } from 'pg';
import { canonicalJson } from '../configuration/digest.js';
import {
  EvidenceCustodyError,
  openSegment,
  type EvidenceScope,
  type SegmentHeader,
  type SourceReceipt,
} from './segment.js';

/** Recover inbox metadata only after the original native-verified COSE matches
 * actual decrypted local custody. A retired projection is never rebuilt here.
 * Missing local bytes or the original key stays blocked for its custody owner. */
export async function uncustodiedFactSources(
  client: PoolClient,
  scope: EvidenceScope,
  entries: readonly { source: SourceReceipt }[],
  encryption: { keyId: string; key: Buffer },
): Promise<SourceReceipt[]> {
  const pending: SourceReceipt[] = [];
  const opened = new Map<string, ReturnType<typeof openSegment>>();
  for (const { source } of entries) {
    const selected = await client.query<{
      segmentId: string;
      firstSequence: string;
      throughSequence: string;
      previousSegmentDigest: string | null;
      objectDigest: string;
      keyId: string;
      retentionUntil: string;
      encrypted: Buffer | null;
    }>(
      `select s.segment_id::text as "segmentId",s.first_sequence::text as "firstSequence",s.through_sequence::text as "throughSequence",
    s.previous_segment_digest as "previousSegmentDigest",s.object_digest as "objectDigest",s.key_id as "keyId",
    to_char(s.retention_until at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') as "retentionUntil",b.encrypted_segment as encrypted
    from control.evidence_catalogue c join control.evidence_segment s using(participant_id,privacy_domain_id,stream_id,segment_id)
    left join control.evidence_segment_payload b using(participant_id,privacy_domain_id,stream_id,segment_id)
    where c.participant_id=$1 and c.privacy_domain_id=$2 and c.stream_id=$3 and c.record_id=$4`,
      [scope.participantId, scope.privacyDomainId, scope.streamId, source.recordId],
    );
    if (selected.rowCount === 0) {
      pending.push(source);
      continue;
    }
    const row = selected.rows[0];
    if (selected.rowCount !== 1 || !row?.encrypted || row.keyId !== encryption.keyId)
      throw new EvidenceCustodyError('INTEGRITY');
    let segment = opened.get(row.segmentId);
    if (!segment) {
      const header: SegmentHeader = {
        ...scope,
        version: 'OPENPC_EVIDENCE_SEGMENT_V1',
        segmentId: row.segmentId,
        firstSequence: row.firstSequence,
        throughSequence: row.throughSequence,
        previousSegmentDigest: row.previousSegmentDigest,
        keyId: row.keyId,
        retentionUntil: row.retentionUntil,
      };
      segment = openSegment(row.encrypted, row.objectDigest, header, encryption.key);
      opened.set(row.segmentId, segment);
    }
    const record = segment.records.find((record) => record.recordId === source.recordId);
    if (
      !record ||
      canonicalJson({
        recordId: record.recordId,
        evidenceClass: record.evidenceClass,
        sourceFormat: record.sourceFormat,
        receiptBase64: record.receiptBase64,
        receiptDigest: record.receiptDigest,
        occurredAt: record.occurredAt,
      }) !== canonicalJson(source)
    )
      throw new EvidenceCustodyError('INTEGRITY');
  }
  return pending;
}
