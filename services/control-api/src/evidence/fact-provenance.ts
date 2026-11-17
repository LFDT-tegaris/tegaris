import type { PoolClient } from 'pg';
import { sha256 } from '../configuration/digest.js';
import type { ProvenanceSource } from './deployment-provenance.js';
import { factProvenance } from './fact-provenance-contract.js';
import { EvidenceCustodyError } from './segment.js';

export function verifyFactProjection(
  record: ProvenanceSource & { sequence: string },
  value: unknown,
  projectionDigest: string,
) {
  const parsed = factProvenance.parse(value);
  if (
    sha256(parsed) !== projectionDigest ||
    parsed.receiptDigest !== record.recordDigest ||
    parsed.admittedAt !== record.occurredAt ||
    parsed.sourceSequence !== record.sequence ||
    record.recordId !==
      `fact:${sha256([record.participantId, record.privacyDomainId, parsed.sourceProfileId]).slice(7)}:${parsed.sourceSequence}`
  )
    throw new EvidenceCustodyError('INTEGRITY');
  return parsed;
}

/** Read only the verified, scoped custody projection. Its original COSE and
 * subject/value remain encrypted; historical integrity grants no readiness. */
export async function readFactProvenance(
  client: PoolClient,
  record: ProvenanceSource & { streamId: string; sequence: string },
) {
  const selected = await client.query<{ projection: unknown; projection_digest: string }>(
    `select projection,projection_digest from control.evidence_fact_provenance
     where participant_id=$1 and privacy_domain_id=$2 and stream_id=$3 and record_id=$4`,
    [record.participantId, record.privacyDomainId, record.streamId, record.recordId],
  );
  if (selected.rowCount === 0) return null;
  if (selected.rowCount !== 1) throw new EvidenceCustodyError('INTEGRITY');
  return verifyFactProjection(
    record,
    selected.rows[0]!.projection,
    selected.rows[0]!.projection_digest,
  );
}
