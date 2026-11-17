import type { PoolClient } from 'pg';
import { sha256 } from '../configuration/digest.js';
import { bindFactAdmissionDelivery, type FactAdmissionDelivery } from './fact-delivery-contract.js';
import type { FactProvenance } from './fact-provenance-contract.js';
import { EvidenceCustodyError, type EvidenceScope, type SourceReceipt } from './segment.js';

/** Called inside the original evidence custody transaction. Missing legacy
 * delivery identity stays unacknowledged; it is never synthesized here. */
export async function retainFactAdmissionDelivery(
  client: PoolClient,
  scope: EvidenceScope,
  entries: readonly {
    source: SourceReceipt;
    provenance: FactProvenance;
    admissionDelivery?: FactAdmissionDelivery;
  }[],
) {
  for (const entry of entries) {
    if (entry.admissionDelivery === undefined) continue;
    const event = bindFactAdmissionDelivery(
      entry.admissionDelivery,
      scope,
      entry.provenance.candidateId,
      entry.provenance.lineage.factId,
    );
    const hash = sha256(event);
    let retained = await client.query(
      `select envelope,envelope_digest,stream_id,record_id,source_receipt_digest
   from control.evidence_fact_admission_inbox where participant_id=$1 and privacy_domain_id=$2 and event_id=$3`,
      [scope.participantId, scope.privacyDomainId, event.id],
    );
    if (retained.rowCount === 0) {
      // Ephemeral proof for retired projections: the SQL guard matches its
      // digest to the immutable successful retirement; no projection is stored.
      await client.query("select set_config('openpc.fact_delivery_source_projection',$1,true)", [
        JSON.stringify(entry.provenance),
      ]);
      await client.query(
        `insert into control.evidence_fact_admission_inbox
   (participant_id,privacy_domain_id,event_id,fact_type,sequence,candidate_id,stream_id,record_id,source_receipt_digest,envelope,envelope_digest)
   values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) on conflict do nothing`,
        [
          scope.participantId,
          scope.privacyDomainId,
          event.id,
          entry.provenance.lineage.factType,
          event.sequence,
          entry.provenance.candidateId,
          scope.streamId,
          entry.source.recordId,
          entry.source.receiptDigest,
          event,
          hash,
        ],
      );
      await client.query("select set_config('openpc.fact_delivery_source_projection','',true)");
      retained = await client.query(
        `select envelope,envelope_digest,stream_id,record_id,source_receipt_digest
   from control.evidence_fact_admission_inbox where participant_id=$1 and privacy_domain_id=$2 and event_id=$3`,
        [scope.participantId, scope.privacyDomainId, event.id],
      );
    }
    const row = retained.rows[0];
    if (
      retained.rowCount !== 1 ||
      row.envelope_digest !== hash ||
      sha256(row.envelope) !== hash ||
      row.stream_id !== scope.streamId ||
      row.record_id !== entry.source.recordId ||
      row.source_receipt_digest !== entry.source.receiptDigest
    )
      throw new EvidenceCustodyError('CONFLICT');
  }
  // An earlier out-of-order effect may become contiguous on a later worker pass.
  // Readback acknowledges only through this cursor, never merely an inbox row.
  for (const kind of ['CONTRACT_STATE_CALL', 'RELATIONSHIP', 'EXTERNAL_DECISION']) {
    const scopeType = [scope.participantId, scope.privacyDomainId, kind];
    await client.query(
      `insert into control.evidence_fact_admission_cursor(participant_id,privacy_domain_id,fact_type)
   values($1,$2,$3) on conflict do nothing`,
      scopeType,
    );
    const head = await client.query<{ sequence: string }>(
      `select sequence::text from control.evidence_fact_admission_cursor
   where participant_id=$1 and privacy_domain_id=$2 and fact_type=$3 for update`,
      scopeType,
    );
    if (head.rowCount !== 1) throw new EvidenceCustodyError('INTEGRITY');
    const current = head.rows[0]!.sequence;
    const contiguous = await client.query<{ sequence: string | null }>(
      `with batch as materialized (
   select sequence from control.evidence_fact_admission_inbox where participant_id=$1 and privacy_domain_id=$2
    and fact_type=$3 and sequence>$4 order by sequence limit 256
  ), ordered as (select sequence,row_number() over(order by sequence) ordinal from batch)
  select max(sequence)::text as sequence from ordered where sequence=$4::numeric+ordinal`,
      [...scopeType, current],
    );
    const next = contiguous.rows[0]?.sequence;
    if (next !== null && next !== undefined)
      await client.query(
        `update control.evidence_fact_admission_cursor set sequence=$4
   where participant_id=$1 and privacy_domain_id=$2 and fact_type=$3`,
        [...scopeType, next],
      );
  }
}
