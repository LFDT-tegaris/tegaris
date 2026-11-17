import type { PoolClient } from 'pg';
import type { EvidenceScope } from './segment.js';
import { LocalEvidenceVault, type VaultObject } from './local-vault.js';
import { vaultHold, type VaultHold } from './hold-vault.js';

/** Caller owns the scope's exclusive lifecycle fence before taking any stream locks. */
export async function coverObjectHolds(
  client: PoolClient,
  object: VaultObject,
  sink: LocalEvidenceVault,
) {
  const selected = await client.query<VaultHold>(
    `select retention_hold_id::text as "holdId",
    selector_digest as "selectorDigest",creation_operation_id::text as "creationOperationId",
    release_operation_id::text as "releaseOperationId",state,revision::text from control.retention_hold h
    where participant_id=$1 and (selector_type='PARTICIPANT' or privacy_domain_id=$2)
    and openpc.evidence_hold_requires_coverage(h,$3,$4)
    and not exists(select 1 from control.evidence_hold_coverage c where c.participant_id=h.participant_id
      and c.privacy_domain_id=$2 and c.retention_hold_id=h.retention_hold_id
      and c.hold_revision=h.revision and c.sink_id=$5 and c.segment_id=$4)
    order by retention_hold_id limit 9`,
    [object.participantId, object.privacyDomainId, object.streamId, object.segmentId, sink.sinkId],
  );
  for (const row of selected.rows.slice(0, 8)) {
    const hold = vaultHold.parse(row);
    const acknowledgement = await sink.acknowledgeHold(object, hold);
    await client.query(
      `insert into control.evidence_hold_coverage(participant_id,privacy_domain_id,retention_hold_id,
      hold_revision,stream_id,segment_id,object_digest,sink_id,receipt,receipt_digest)
      values($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,$10)`,
      [
        object.participantId,
        object.privacyDomainId,
        hold.holdId,
        hold.revision,
        object.streamId,
        object.segmentId,
        object.objectDigest,
        sink.sinkId,
        JSON.stringify(acknowledgement),
        acknowledgement.receiptDigest,
      ],
    );
  }
  return selected.rows.length <= 8;
}

export async function pendingHoldObjects(client: PoolClient, scope: EvidenceScope, sinkId: string) {
  const result = await client.query<{ object: VaultObject }>(
    `select p.receipt->'object' as object
    from control.evidence_checkpoint p where participant_id=$1 and privacy_domain_id=$2 and stream_id=$3 and sink_id=$4
    and exists(select 1 from control.retention_hold h where h.participant_id=p.participant_id
      and (h.selector_type='PARTICIPANT' or h.privacy_domain_id=p.privacy_domain_id)
      and openpc.evidence_hold_requires_coverage(h,p.stream_id,p.segment_id)
      and not exists(select 1 from control.evidence_hold_coverage c where c.participant_id=h.participant_id
       and c.privacy_domain_id=$2 and c.retention_hold_id=h.retention_hold_id
       and c.hold_revision=h.revision and c.sink_id=p.sink_id and c.segment_id=p.segment_id))
    order by through_sequence limit 8`,
    [scope.participantId, scope.privacyDomainId, scope.streamId, sinkId],
  );
  return result.rows.map((row) => row.object);
}
