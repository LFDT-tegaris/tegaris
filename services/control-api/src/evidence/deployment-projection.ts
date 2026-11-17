import type { PoolClient } from 'pg';
import { sha256 } from '../configuration/digest.js';
import { deploymentProvenanceProjection } from './provenance-contracts.js';
import { EvidenceCustodyError, type EvidenceScope, type SourceReceipt } from './segment.js';

/** Called only after the source owner has verified the original target purpose
 * signature. Reconciliation cannot resurrect an intentionally retired view. */
export async function retainDeploymentProjection(
  client: PoolClient,
  scope: EvidenceScope,
  source: SourceReceipt,
) {
  const identity = [scope.participantId, scope.privacyDomainId, scope.streamId, source.recordId];
  const retired = await client.query(
    `select 1 from control.evidence_projection_retirement r
     join control.deletion_job j using(participant_id,privacy_domain_id,deletion_job_id)
     where r.participant_id=$1 and r.privacy_domain_id=$2 and r.stream_id=$3 and r.record_id=$4
      and r.data_class='NORMALIZED_JSON_PROJECTION' and j.state='SUCCEEDED'
      and j.selection->>'sourceKind'='DEPLOYMENT_PROVENANCE'
      and r.source_receipt_digest=$5 and r.retirement_digest=openpc.projection_retirement_digest(r)`,
    [...identity, source.receiptDigest],
  );
  if (retired.rowCount === 1) return;
  const expected = await client.query<{ projection: unknown }>(
    `select openpc.evidence_deployment_projection(c) projection from control.evidence_catalogue c
     where participant_id=$1 and privacy_domain_id=$2 and stream_id=$3 and record_id=$4
      and receipt_digest=$5`,
    [...identity, source.receiptDigest],
  );
  if (expected.rowCount !== 1) throw new EvidenceCustodyError('INTEGRITY');
  const projection = deploymentProvenanceProjection.parse(expected.rows[0]!.projection);
  const digest = sha256(projection);
  await client.query(
    `insert into control.evidence_deployment_provenance
     (participant_id,privacy_domain_id,stream_id,record_id,projection,projection_digest)
     values($1,$2,$3,$4,$5,$6) on conflict do nothing`,
    [...identity, projection, digest],
  );
  const retained = await client.query<{ projection: unknown; projection_digest: string }>(
    `select projection,projection_digest from control.evidence_deployment_provenance
     where participant_id=$1 and privacy_domain_id=$2 and stream_id=$3 and record_id=$4`,
    identity,
  );
  if (
    retained.rowCount !== 1 ||
    retained.rows[0]!.projection_digest !== digest ||
    sha256(retained.rows[0]!.projection) !== digest
  )
    throw new EvidenceCustodyError('INTEGRITY');
}
